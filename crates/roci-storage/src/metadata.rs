//! Derived, rebuildable-from-the-layout metadata index (ARCHITECTURE.md
//! §"Metadata index engine"). The [`MetadataStore`] trait is the read/mutate
//! surface the storage backend resolves tags, manifest media types, and the
//! subject→referrers relation against; the default [`LogMetadataStore`] keeps
//! the state in RAM and durably mirrors every mutation to an append-only,
//! CRC32C-framed `roci-meta.log` so restarts replay in one sequential pass.
//!
//! The on-disk OCI layout (`index.json` + `blobs/`) remains the source of
//! truth (invariant 6); this index is a cache, always reconstructable by
//! replaying the log or, failing that, walking the layout.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A tag/manifest/referrer mutation the store can record and replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaOp {
    /// A manifest was stored: `(repo, digest, media_type, optional tag)`.
    PutManifest {
        repo: String,
        digest: String,
        media_type: String,
        tag: Option<String>,
    },
    /// The reverse edges for a manifest: every `blob` the manifest references
    /// (config + layers) gains `manifest` in its backref set. Recorded after
    /// the manifest is stored so a future GC can reclaim an unreferenced blob.
    PutBackrefs {
        repo: String,
        manifest: String,
        blobs: Vec<String>,
    },
    /// A manifest (and every tag pointing at it) was deleted: `(repo, digest)`.
    DeleteManifest { repo: String, digest: String },
    /// A referrer descriptor was recorded against a subject digest.
    PutReferrer {
        repo: String,
        subject: String,
        referrer: String,
        descriptor: Vec<u8>,
    },
}

/// The read/mutate surface for derived metadata. AuthN/AuthZ is enforced before
/// any call (ARCHITECTURE.md invariant 3), exactly like [`crate::Storage`].
pub trait MetadataStore: Send + Sync + 'static {
    /// Resolve a tag to `(digest, media_type)`, if the tag exists. Both come
    /// from the same locked read, so a resolved tag always carries its media
    /// type (no second lookup, no fallback default).
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)>;
    /// The stored media type for a manifest digest, if known.
    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String>;
    /// One page of `repo`'s tags in lexical order: at most `limit` tags
    /// strictly after `last` (from the start when `None`) — an O(log n) seek,
    /// so the work is bounded by the page, not the repo. `None` when the store
    /// records no tag for `repo` (the caller falls back to the layout).
    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>>;
    /// One page of the referrers recorded for `subject`, ordered by referrer
    /// digest: at most `limit` entries strictly after `last`, restricted to
    /// descriptors whose `artifactType` equals `artifact_type` when given (an
    /// O(log n) seek into a per-type index, never a filtered scan). `None`
    /// when the store records no referrer for `subject` at all.
    fn referrers_page(
        &self,
        repo: &str,
        subject: &str,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Option<Page<Referrer>>;
    /// Whether `referrer` is recorded as a referrer of `subject`.
    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool;
    /// The manifest digests currently recorded as referencing `blob` in `repo`.
    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String>;
    /// Apply and durably record a mutation.
    fn apply(&self, op: MetaOp) -> io::Result<()>;
}

/// In-RAM metadata maps mirrored to an append-only CRC32C-framed log.
///
/// Writes are **group-committed**: the append (buffered `write` + `flush` into
/// the kernel) happens under the fast `inner` lock and bumps `appended`; the
/// durability barrier (`fdatasync`) is coalesced behind a separate `sync` lock,
/// so N appends that pile up while one `fdatasync` is in flight are made
/// durable by that single sync — a caller whose record is already covered
/// (`synced >= my_seq`) returns without its own sync (RESEARCH §8.8, PLAN
/// Phase 2 group-commit).
pub struct LogMetadataStore {
    inner: Mutex<State>,
    /// Records appended to the kernel so far (monotonic; the append seq).
    appended: AtomicU64,
    /// Coalesced durability barrier: the highest `appended` made durable, plus
    /// a `fdatasync`-capable clone of the log handle.
    sync: Mutex<SyncCoord>,
    log_path: PathBuf,
}

/// Durability-barrier state, guarded independently of `inner` so a `fdatasync`
/// never holds the append lock.
#[derive(Default)]
struct SyncCoord {
    /// Highest `appended` seq made durable by a completed `fdatasync`.
    synced: u64,
    /// A clone of the log file used only for `sync_data`; set on first append.
    handle: Option<std::fs::File>,
}

/// A repo-scoped map key: `(repo, name)` so repositories stay isolated.
type RepoKey = (String, String);
/// One referrer: `(referrer_digest, descriptor_bytes)`; the digest de-dups.
pub type Referrer = (String, Vec<u8>);

/// One page of a cursor-paginated listing: at most the requested number of
/// items strictly after the request cursor, in the listing's stable order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// At least one further item follows `items` (→ a `Link: rel="next"`).
    pub more: bool,
}

/// Collect at most `limit` items of `it` and record whether any remain.
pub(crate) fn take_page<T>(mut it: impl Iterator<Item = T>, limit: usize) -> Page<T> {
    let items: Vec<T> = it.by_ref().take(limit).collect();
    let more = it.next().is_some();
    Page { items, more }
}

/// The key range strictly after the cursor `last` (everything when `None`).
fn after(last: Option<&str>) -> (Bound<&str>, Bound<&str>) {
    (
        last.map_or(Bound::Unbounded, Bound::Excluded),
        Bound::Unbounded,
    )
}

/// The referrers of one subject, ordered by referrer digest so a page is an
/// O(log n) seek past the cursor. `by_type` indexes the same digests by their
/// descriptor's `artifactType`, so a filtered page is an equally bounded seek.
#[derive(Default)]
struct SubjectReferrers {
    /// `referrer_digest → (artifactType, descriptor_bytes)`.
    by_digest: BTreeMap<String, (Option<String>, Vec<u8>)>,
    /// `artifactType → {referrer_digest}`; holds exactly the typed entries of
    /// `by_digest`, and a type whose set empties is removed.
    by_type: HashMap<String, BTreeSet<String>>,
}

impl SubjectReferrers {
    /// Record (or replace, de-duplicating by digest) one referrer descriptor.
    fn insert(&mut self, referrer: &str, descriptor: &[u8]) {
        let artifact_type = serde_json::from_slice::<serde_json::Value>(descriptor)
            .ok()
            .and_then(|v| v.get("artifactType")?.as_str().map(str::to_string));
        self.remove(referrer);
        if let Some(t) = &artifact_type {
            self.by_type
                .entry(t.clone())
                .or_default()
                .insert(referrer.to_string());
        }
        self.by_digest
            .insert(referrer.to_string(), (artifact_type, descriptor.to_vec()));
    }

    /// Drop `referrer` from both indexes.
    fn remove(&mut self, referrer: &str) {
        let Some((Some(t), _)) = self.by_digest.remove(referrer) else {
            return;
        };
        if let Some(set) = self.by_type.get_mut(&t) {
            set.remove(referrer);
            if set.is_empty() {
                self.by_type.remove(&t);
            }
        }
    }

    fn page(
        &self,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Page<Referrer> {
        match artifact_type {
            None => take_page(
                self.by_digest
                    .range::<str, _>(after(last))
                    .map(|(d, (_, bytes))| (d.clone(), bytes.clone())),
                limit,
            ),
            Some(t) => match self.by_type.get(t) {
                Some(set) => take_page(
                    set.range::<str, _>(after(last))
                        .map(|d| (d.clone(), self.by_digest[d].1.clone())),
                    limit,
                ),
                None => Page::default(),
            },
        }
    }
}

/// The mutable in-RAM state. Repo-scoped so repositories stay isolated.
#[derive(Default)]
struct State {
    /// `repo → tag → (digest, media_type)` — lexically ordered per repo so a
    /// tag page is a seek; a repo whose last tag goes is removed. The media
    /// type is stored alongside so a tag resolution needs no second lookup.
    tags: HashMap<String, BTreeMap<String, (String, String)>>,
    /// `(repo, digest) → media_type`.
    media_types: HashMap<RepoKey, String>,
    /// `(repo, subject) → referrers`; a subject whose last referrer goes is
    /// removed.
    referrers: HashMap<RepoKey, SubjectReferrers>,
    /// `(repo, blob_digest) → [manifest_digest]`: reverse edges from a blob to
    /// every manifest that references it. Maintained on manifest put/delete for
    /// a future online GC; manifest digests de-dup within a set.
    backrefs: HashMap<RepoKey, Vec<String>>,
    /// Buffered log writer (`None` until a mutation opens/creates the log).
    log: Option<std::fs::File>,
}

impl LogMetadataStore {
    /// Open (replaying) or create the metadata store at `<root>/roci-meta.log`.
    /// A corrupt trailing record (torn write from a crash) is truncated away;
    /// records that fail their CRC are skipped, and the layout can always
    /// rebuild what a damaged log loses.
    pub fn open(root: &Path) -> io::Result<Self> {
        let log_path = root.join("roci-meta.log");
        let mut state = State::default();
        if let Ok(bytes) = std::fs::read(&log_path) {
            replay(&bytes, &mut state);
        }
        Ok(Self {
            inner: Mutex::new(state),
            appended: AtomicU64::new(0),
            sync: Mutex::new(SyncCoord::default()),
            log_path,
        })
    }

    /// Apply a mutation to the in-RAM maps only (used by both `apply`, after it
    /// has framed the record to the log, and by log replay).
    fn apply_in_ram(state: &mut State, op: &MetaOp) {
        match op {
            MetaOp::PutManifest {
                repo,
                digest,
                media_type,
                tag,
            } => {
                state
                    .media_types
                    .insert((repo.clone(), digest.clone()), media_type.clone());
                if let Some(tag) = tag {
                    state
                        .tags
                        .entry(repo.clone())
                        .or_default()
                        .insert(tag.clone(), (digest.clone(), media_type.clone()));
                }
            }
            MetaOp::DeleteManifest { repo, digest } => {
                state.media_types.remove(&(repo.clone(), digest.clone()));
                // Drop every tag pointing at this digest.
                if let Some(tags) = state.tags.get_mut(repo) {
                    tags.retain(|_, (d, _)| d != digest);
                    if tags.is_empty() {
                        state.tags.remove(repo);
                    }
                }
                // Drop the deleted manifest as a referrer of any subject in
                // this repo; a subject left without referrers is removed.
                state.referrers.retain(|(r, _), refs| {
                    if r == repo {
                        refs.remove(digest);
                    }
                    !refs.by_digest.is_empty()
                });
                // Drop the deleted manifest from every blob's backref set in
                // this repo; a set that empties is removed entirely.
                state.backrefs.retain(|(r, _), manifests| {
                    if r == repo {
                        manifests.retain(|m| m != digest);
                    }
                    !manifests.is_empty()
                });
            }
            MetaOp::PutBackrefs {
                repo,
                manifest,
                blobs,
            } => {
                for blob in blobs {
                    let set = state
                        .backrefs
                        .entry((repo.clone(), blob.clone()))
                        .or_default();
                    if !set.iter().any(|m| m == manifest) {
                        set.push(manifest.clone());
                    }
                }
            }
            MetaOp::PutReferrer {
                repo,
                subject,
                referrer,
                descriptor,
            } => {
                state
                    .referrers
                    .entry((repo.clone(), subject.clone()))
                    .or_default()
                    .insert(referrer, descriptor);
            }
        }
    }
}

impl MetadataStore for LogMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state.tags.get(repo)?.get(tag).cloned()
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .media_types
            .get(&(repo.to_string(), digest.to_string()))
            .cloned()
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let tags = state.tags.get(repo)?;
        Some(take_page(
            tags.range::<str, _>(after(last)).map(|(t, _)| t.clone()),
            limit,
        ))
    }

    fn referrers_page(
        &self,
        repo: &str,
        subject: &str,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Option<Page<Referrer>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let refs = state
            .referrers
            .get(&(repo.to_string(), subject.to_string()))?;
        Some(refs.page(artifact_type, last, limit))
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .referrers
            .get(&(repo.to_string(), subject.to_string()))
            .is_some_and(|refs| refs.by_digest.contains_key(referrer))
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .backrefs
            .get(&(repo.to_string(), blob.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        // Append the record and reflect it in RAM under one lock (so the
        // in-memory maps always match log-replay order even under concurrent
        // appends), then coalesce the durability barrier. The in-RAM maps are a
        // rebuildable cache and the log is the source of truth: if the barrier
        // fails, the record is already in the log (replayed on restart) and the
        // in-RAM state already matches that replay — the caller gets the error.
        let my_seq = self.append_record(&op)?;
        self.group_commit_through(my_seq)
    }
}

impl LogMetadataStore {
    /// Phase 1 of a group-committed apply: under the fast `inner` lock, buffer
    /// the record into the kernel (write + flush, no fsync), apply it to the
    /// in-RAM maps **in append order** (same lock → no reordering across
    /// concurrent callers), and return this write's monotonic sequence number.
    /// On the first mutation, open the log and hand a `sync_data`-capable clone
    /// to the durability coordinator.
    fn append_record(&self, op: &MetaOp) -> io::Result<u64> {
        let record = encode(op);
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        if state.log.is_none() {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)?;
            let clone = f.try_clone()?;
            state.log = Some(f);
            self.sync.lock().expect("sync lock poisoned").handle = Some(clone);
        }
        let log = state.log.as_mut().expect("log opened above");
        log.write_all(&record)?;
        log.flush()?;
        let seq = self.appended.fetch_add(1, Ordering::AcqRel) + 1;
        Self::apply_in_ram(&mut state, op);
        Ok(seq)
    }

    /// Phase 2 of a group-committed apply: the coalesced durability barrier.
    /// If a prior `fdatasync` already covered `my_seq` this returns without a
    /// syscall; otherwise one `fdatasync` makes every append up to now durable
    /// (the group-commit win — concurrent appends piled up during an in-flight
    /// sync share it). N appends between two syncs cost one fsync.
    fn group_commit_through(&self, my_seq: u64) -> io::Result<()> {
        let mut sync = self.sync.lock().expect("sync lock poisoned");
        if sync.synced >= my_seq {
            return Ok(());
        }
        // Snapshot the append seq *before* syncing so we only claim durability
        // for records already flushed to the kernel.
        let covered = self.appended.load(Ordering::Acquire);
        // The handle is set on the first append (before any seq is returned), so
        // it is always present by the time a commit runs.
        sync.handle
            .as_ref()
            .expect("log handle set on first append")
            .sync_data()?;
        sync.synced = sync.synced.max(covered);
        Ok(())
    }

    /// Snapshot all manifest digests recorded in `repo` (populated by
    /// [`MetaOp::PutManifest`]).
    pub fn manifests(&self, repo: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .media_types
            .keys()
            .filter(|(r, _)| r == repo)
            .map(|(_, d)| d.clone())
            .collect()
    }

    /// Every repo with at least one manifest or referrer recorded.
    pub fn repos(&self) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let mut repos: Vec<String> = state
            .media_types
            .keys()
            .chain(state.referrers.keys())
            .map(|(r, _)| r.clone())
            .collect();
        repos.sort();
        repos.dedup();
        repos
    }

    /// Snapshot the tags for `repo` as `(tag, digest, media_type)`, sorted by tag.
    pub fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .tags
            .get(repo)
            .map(|tags| {
                tags.iter()
                    .map(|(tag, (digest, media))| (tag.clone(), digest.clone(), media.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Snapshot referrers for `repo` as `(subject_digest, [(referrer_digest, descriptor_bytes)])`.
    pub fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .referrers
            .iter()
            .filter(|((r, _), _)| r == repo)
            .map(|((_, subject), refs)| {
                let refs = refs
                    .by_digest
                    .iter()
                    .map(|(d, (_, bytes))| (d.clone(), bytes.clone()))
                    .collect();
                (subject.clone(), refs)
            })
            .collect()
    }
}

// ---- Log framing -----------------------------------------------------------
//
// Each record is `<u32 LE length><u32 LE crc32c><JSON payload>`. The length lets
// replay find the next record; the CRC lets it reject a torn tail. The payload
// is the `MetaOp` serialized as a small self-describing JSON object.

fn encode(op: &MetaOp) -> Vec<u8> {
    let payload = serialize_op(op);
    let crc = crc32c(&payload);
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Replay a log buffer into `state`, stopping at the first truncated or
/// CRC-failed record (a crash-torn tail).
fn replay(bytes: &[u8], state: &mut State) {
    let mut pos = 0usize;
    while pos + 8 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let crc = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let start = pos + 8;
        let end = start + len;
        if end > bytes.len() {
            break; // truncated tail
        }
        let payload = &bytes[start..end];
        if crc32c(payload) != crc {
            break; // corrupt record; layout rebuild is the recovery path
        }
        if let Some(op) = deserialize_op(payload) {
            LogMetadataStore::apply_in_ram(state, &op);
        }
        pos = end;
    }
}

// ---- MetaOp <-> JSON payload ----------------------------------------------

fn serialize_op(op: &MetaOp) -> Vec<u8> {
    let v = match op {
        MetaOp::PutManifest {
            repo,
            digest,
            media_type,
            tag,
        } => serde_json::json!({
            "op": "put_manifest",
            "repo": repo,
            "digest": digest,
            "media_type": media_type,
            "tag": tag,
        }),
        MetaOp::DeleteManifest { repo, digest } => serde_json::json!({
            "op": "delete_manifest",
            "repo": repo,
            "digest": digest,
        }),
        MetaOp::PutReferrer {
            repo,
            subject,
            referrer,
            descriptor,
        } => serde_json::json!({
            "op": "put_referrer",
            "repo": repo,
            "subject": subject,
            "referrer": referrer,
            // Descriptor bytes are already JSON; embed as a string to keep the
            // record a single flat object and survive any byte content.
            "descriptor": String::from_utf8_lossy(descriptor),
        }),
        MetaOp::PutBackrefs {
            repo,
            manifest,
            blobs,
        } => serde_json::json!({
            "op": "put_backrefs",
            "repo": repo,
            "manifest": manifest,
            "blobs": blobs,
        }),
    };
    serde_json::to_vec(&v).expect("MetaOp serializes")
}

fn deserialize_op(payload: &[u8]) -> Option<MetaOp> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    match v.get("op").and_then(|x| x.as_str())? {
        "put_manifest" => Some(MetaOp::PutManifest {
            repo: s("repo")?,
            digest: s("digest")?,
            media_type: s("media_type")?,
            tag: v.get("tag").and_then(|x| x.as_str()).map(str::to_string),
        }),
        "delete_manifest" => Some(MetaOp::DeleteManifest {
            repo: s("repo")?,
            digest: s("digest")?,
        }),
        "put_referrer" => Some(MetaOp::PutReferrer {
            repo: s("repo")?,
            subject: s("subject")?,
            referrer: s("referrer")?,
            descriptor: s("descriptor")?.into_bytes(),
        }),
        "put_backrefs" => Some(MetaOp::PutBackrefs {
            repo: s("repo")?,
            manifest: s("manifest")?,
            blobs: v
                .get("blobs")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        }),
        _ => None,
    }
}

// ---- CRC32C (Castagnoli, reflected) ---------------------------------------

/// Compute the CRC32C (Castagnoli polynomial `0x1EDC6F41`, reflected) of `data`.
/// A dependency-free, table-free software implementation — corruption detection
/// only, not a cryptographic guarantee (the layout is the real integrity
/// authority). Records are tiny, so the per-bit loop is not a hot path.
fn crc32c(data: &[u8]) -> u32 {
    // Reflected Castagnoli polynomial.
    const POLY: u32 = 0x82F6_3B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(repo: &str, digest: &str, tag: Option<&str>) -> MetaOp {
        MetaOp::PutManifest {
            repo: repo.into(),
            digest: digest.into(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            tag: tag.map(str::to_string),
        }
    }

    #[test]
    fn crc32c_matches_known_vector() {
        // Standard CRC32C check value for the ASCII string "123456789".
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn apply_resolve_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        // Untagged manifest records only its media type.
        s.apply(put("r", "sha256:cc", None)).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(s.resolve_tag("r", "missing"), None);
        assert_eq!(
            s.manifest_media_type("r", "sha256:cc").as_deref(),
            Some("application/vnd.oci.image.manifest.v1+json")
        );
        assert_eq!(s.manifest_media_type("r", "sha256:zz"), None);
        assert_eq!(
            s.tags_page("r", None, usize::MAX).unwrap().items,
            vec!["v1".to_string(), "v2".to_string()]
        );
        assert!(s.tags_page("other", None, usize::MAX).is_none());
    }

    #[test]
    fn delete_removes_tags_media_and_referrers() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1b"))).unwrap();
        // A referrer manifest pointing at subject sha256:aa.
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:aa".into(),
            referrer: "sha256:rr".into(),
            descriptor: br#"{"digest":"sha256:rr"}"#.to_vec(),
        })
        .unwrap();
        assert_eq!(
            s.referrers_page("r", "sha256:aa", None, None, usize::MAX)
                .unwrap()
                .items
                .len(),
            1
        );
        // Deleting the referrer manifest drops it from the subject's set.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:rr".into(),
        })
        .unwrap();
        assert!(s
            .referrers_page("r", "sha256:aa", None, None, usize::MAX)
            .is_none());
        // Deleting the subject manifest drops both its tags and media type.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();
        assert!(s.tags_page("r", None, usize::MAX).is_none());
        assert_eq!(s.manifest_media_type("r", "sha256:aa"), None);
    }

    #[test]
    fn referrer_dedup_replaces_by_digest() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        let mk = |body: &[u8]| MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:rr".into(),
            descriptor: body.to_vec(),
        };
        s.apply(mk(br#"{"v":1}"#)).unwrap();
        s.apply(mk(br#"{"v":2}"#)).unwrap();
        let refs = s
            .referrers_page("r", "sha256:s", None, None, usize::MAX)
            .unwrap()
            .items;
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, br#"{"v":2}"#);
        assert!(s
            .referrers_page("r", "sha256:none", None, None, usize::MAX)
            .is_none());
    }

    #[test]
    fn tags_page_seeks_past_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        for t in ["v4", "v1", "v3", "v2"] {
            s.apply(put("r", "sha256:aa", Some(t))).unwrap();
        }
        s.apply(put("other", "sha256:aa", Some("v0"))).unwrap();
        let page = |last, limit| {
            let p = s.tags_page("r", last, limit).unwrap();
            (p.items, p.more)
        };
        let v = |ts: &[&str]| ts.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(page(None, 2), (v(&["v1", "v2"]), true));
        assert_eq!(page(Some("v2"), 2), (v(&["v3", "v4"]), false), "exact fit");
        // A cursor that is not (or no longer) a tag resumes lexically after it.
        assert_eq!(page(Some("v25"), 1), (v(&["v3"]), true));
        assert_eq!(page(Some("v9"), 5), (v(&[]), false));
        assert_eq!(page(None, 0), (v(&[]), true));
    }

    #[test]
    fn referrers_page_filters_through_type_index() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        let add = |repo: &str, referrer: &str, descriptor: &str| {
            s.apply(MetaOp::PutReferrer {
                repo: repo.into(),
                subject: "sha256:s".into(),
                referrer: referrer.into(),
                descriptor: descriptor.as_bytes().to_vec(),
            })
            .unwrap();
        };
        add("r", "sha256:c", r#"{"artifactType":"sig"}"#);
        add("r", "sha256:a", r#"{"artifactType":"sig"}"#);
        add("r", "sha256:b", r#"{"artifactType":"sbom"}"#);
        add("r", "sha256:d", r#"{}"#);
        add("other", "sha256:a", r#"{"artifactType":"sig"}"#);
        let page = |filter, last, limit| {
            let p = s
                .referrers_page("r", "sha256:s", filter, last, limit)
                .unwrap();
            (
                p.items.into_iter().map(|(d, _)| d).collect::<Vec<_>>(),
                p.more,
            )
        };
        let v = |ds: &[&str]| ds.iter().map(|d| d.to_string()).collect::<Vec<_>>();
        // Digest order, independent of insertion order.
        assert_eq!(
            page(None, None, 9),
            (v(&["sha256:a", "sha256:b", "sha256:c", "sha256:d"]), false)
        );
        assert_eq!(page(Some("sig"), None, 1), (v(&["sha256:a"]), true));
        assert_eq!(
            page(Some("sig"), Some("sha256:a"), 1),
            (v(&["sha256:c"]), false)
        );
        assert_eq!(page(Some("nope"), None, 9), (v(&[]), false));
        // Re-typing a referrer moves it between type indexes.
        add("r", "sha256:c", r#"{"artifactType":"sbom"}"#);
        assert_eq!(page(Some("sig"), None, 9), (v(&["sha256:a"]), false));
        assert_eq!(
            page(Some("sbom"), None, 9),
            (v(&["sha256:b", "sha256:c"]), false)
        );
        // Deleting a manifest drops it from this repo's indexes only.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:a".into(),
        })
        .unwrap();
        assert_eq!(page(Some("sig"), None, 9), (v(&[]), false));
        assert!(s.has_referrer("other", "sha256:s", "sha256:a"));
        assert!(!s.has_referrer("r", "sha256:s", "sha256:a"));
    }

    #[test]
    fn backrefs_apply_query_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = LogMetadataStore::open(dir.path()).unwrap();
            s.apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m".into(),
                blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
            })
            .unwrap();
            // Idempotent: re-recording the same edge does not duplicate it.
            s.apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m".into(),
                blobs: vec!["sha256:b1".into()],
            })
            .unwrap();
            assert_eq!(s.backrefs("r", "sha256:b1"), vec!["sha256:m".to_string()]);
            assert!(s.backrefs("r", "sha256:absent").is_empty());
        }
        // A fresh store replays the log (serialize → deserialize round-trip).
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(s2.backrefs("r", "sha256:b2"), vec!["sha256:m".to_string()]);
        // Deleting the manifest clears its backref edges on replay too.
        s2.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:m".into(),
        })
        .unwrap();
        assert!(s2.backrefs("r", "sha256:b1").is_empty());
    }

    #[test]
    fn log_replays_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = LogMetadataStore::open(dir.path()).unwrap();
            s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
            s.apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:aa".into(),
                referrer: "sha256:rr".into(),
                descriptor: br#"{"digest":"sha256:rr"}"#.to_vec(),
            })
            .unwrap();
            // A second tagged manifest that we then delete, so replay exercises
            // the DeleteManifest record decode + apply.
            s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
            s.apply(MetaOp::DeleteManifest {
                repo: "r".into(),
                digest: "sha256:bb".into(),
            })
            .unwrap();
        }
        // A fresh store over the same dir replays the log.
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s2.referrers_page("r", "sha256:aa", None, None, usize::MAX)
                .unwrap()
                .items
                .len(),
            1
        );
        // The deleted manifest's tag did not survive replay.
        assert_eq!(s2.resolve_tag("r", "v2"), None);
    }

    #[test]
    fn replay_stops_at_torn_tail_and_bad_crc() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);
        let log = dir.path().join("roci-meta.log");
        let good = std::fs::read(&log).unwrap();

        // Case 1: a truncated trailing record is ignored; the good record stays.
        let mut torn = good.clone();
        torn.extend_from_slice(&(999u32).to_le_bytes()); // length far past EOF
        torn.extend_from_slice(&(0u32).to_le_bytes());
        torn.extend_from_slice(b"partial");
        std::fs::write(&log, &torn).unwrap();
        let s1 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s1.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        drop(s1);

        // Case 2: a record with a corrupted CRC halts replay at that point.
        let mut bad = good.clone();
        let payload = b"{\"op\":\"delete_manifest\",\"repo\":\"r\",\"digest\":\"sha256:aa\"}";
        bad.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bad.extend_from_slice(&(0xDEAD_BEEFu32).to_le_bytes()); // wrong crc
        bad.extend_from_slice(payload);
        std::fs::write(&log, &bad).unwrap();
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        // The corrupt delete was skipped, so the tag survives.
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );

        // Case 3: a valid-CRC but unknown-op record is skipped, replay continues.
        let mut unknown = good.clone();
        let up = b"{\"op\":\"nope\"}";
        unknown.extend_from_slice(&(up.len() as u32).to_le_bytes());
        unknown.extend_from_slice(&crc32c(up).to_le_bytes());
        unknown.extend_from_slice(up);
        // Append a real record after the unknown one to prove replay continued.
        unknown.extend_from_slice(&encode(&put("r", "sha256:bb", Some("v2"))));
        std::fs::write(&log, &unknown).unwrap();
        let s3 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s3.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
    }

    #[test]
    fn deserialize_rejects_malformed_payloads() {
        assert!(deserialize_op(b"not json").is_none());
        assert!(deserialize_op(b"{\"no_op_field\":1}").is_none());
    }

    #[test]
    fn group_commit_coalesces_syncs() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        // Append two records without syncing between them (phase 1 only).
        let seq1 = s.append_record(&put("r", "sha256:aa", Some("v1"))).unwrap();
        let seq2 = s.append_record(&put("r", "sha256:bb", Some("v2"))).unwrap();
        assert_eq!((seq1, seq2), (1, 2));
        // One durability barrier covering seq 2 makes both records durable.
        s.group_commit_through(seq2).unwrap();
        // A later barrier for an already-covered seq is a no-op (the coalesced
        // fast path: `synced >= my_seq`, no second fsync).
        s.group_commit_through(seq1).unwrap();
        // Both records survive a reopen (they were flushed + synced).
        drop(s);
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s2.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
        // The public `apply` still works end-to-end (append + immediate sync).
        s2.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
    }
}
