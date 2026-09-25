//! The default metadata engine: in-RAM maps mirrored to an append-only,
//! CRC32C-framed `roci-meta.log`, replayed in one sequential pass on start.
//!
//! ## Compaction (Phase 5)
//!
//! When `roci-meta.log` exceeds `compact_threshold_bytes`, `maintain()` writes
//! a fresh log containing the minimal record set reproducing the current state,
//! atomically swaps it in, and re-opens the append + group-commit handles. The
//! state lock is held for the rewrite (brief pause — typically < 50 ms for
//! multi-MB logs) so concurrent appends are not lost or reordered. A crash at
//! any point leaves either the old or the new complete log.
//!
//! ## rkyv mmap snapshot (Phase 5, `snapshot = true`)
//!
//! When snapshots are enabled, `maintain()` also writes an rkyv archive of the
//! complete state (`roci-meta.snapshot`) with an integrity header (CRC32C or
//! HMAC-SHA256 when a key is configured). On open, the snapshot is mmap'd and
//! verified, then reads are served from the archived base + an in-RAM delta
//! overlay. Cold start is O(1) — mmap + demand-paging, no per-record replay.
//!
//! ## WAL HMAC (Phase 5, `hmac_key_file` set)
//!
//! Every log record carries an HMAC-SHA256 tag (in addition to its CRC32C for
//! torn-tail detection). The first record is a header declaring the framing
//! mode. Opening an existing log with a mismatched framing/key moves it aside
//! and starts fresh — the layout rebuild recovers the state.

use super::snapshot::{self, SnapshotState};
use super::wal_hmac::{self, decode_header, FramingMode, HmacKey};
use super::{after, take_page, BlobChecksum, MetaOp, MetadataStore, Page, Referrer};
use roci_config::MetadataConfig;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// In-RAM metadata maps mirrored to an append-only CRC32C-framed log.
pub struct LogMetadataStore {
    inner: Mutex<State>,
    appended: AtomicU64,
    sync: Mutex<SyncCoord>,
    log_path: PathBuf,
    snapshot_path: PathBuf,
    compact_threshold: u64,
    snapshot_enabled: bool,
    hmac_key: Option<HmacKey>,
    /// The snapshot base. When present, queries merge base + delta.
    snap_base: Mutex<Option<snapshot::VerifiedSnapshot>>,
    generation: Mutex<u64>,
    /// Length of the log image written by the last compaction/snapshot (or
    /// the offset a loaded snapshot covers): upkeep triggers on growth past
    /// it, so a state larger than the threshold is not rewritten every tick.
    image_len: AtomicU64,
}

impl std::fmt::Debug for LogMetadataStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogMetadataStore")
            .field("log_path", &self.log_path)
            .finish()
    }
}

#[derive(Default)]
struct SyncCoord {
    synced: u64,
    handle: Option<std::fs::File>,
}

type RepoKey = (String, String);

#[derive(Default, Clone)]
struct SubjectReferrers {
    by_digest: BTreeMap<String, (Option<String>, Vec<u8>)>,
    by_type: HashMap<String, BTreeSet<String>>,
}

impl SubjectReferrers {
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

/// The mutable in-RAM state (acts as delta overlay when a snapshot base is
/// present).
#[derive(Default)]
struct State {
    tags: HashMap<String, BTreeMap<String, (String, String)>>,
    media_types: HashMap<RepoKey, String>,
    referrers: HashMap<RepoKey, SubjectReferrers>,
    backrefs: HashMap<RepoKey, Vec<String>>,
    checksums: HashMap<RepoKey, BlobChecksum>,
    log: Option<std::fs::File>,
    /// Digests deleted from the base per repo (for DeleteManifest tombstoning).
    deleted_digests: HashMap<String, BTreeSet<String>>,
    /// Individual blob-checksum keys deleted from the base.
    deleted_checksums: BTreeSet<RepoKey>,
}

impl State {
    fn add_backrefs(&mut self, repo: &str, manifest: &str, blobs: &[String]) {
        for blob in blobs {
            let set = self
                .backrefs
                .entry((repo.to_string(), blob.clone()))
                .or_default();
            if !set.iter().any(|m| m == manifest) {
                set.push(manifest.to_string());
            }
        }
    }

    fn add_referrer(&mut self, repo: &str, subject: &str, referrer: &str, descriptor: &[u8]) {
        self.referrers
            .entry((repo.to_string(), subject.to_string()))
            .or_default()
            .insert(referrer, descriptor);
    }

    /// Is `digest` tombstoned in `repo`?
    fn is_digest_deleted(&self, repo: &str, digest: &str) -> bool {
        self.deleted_digests
            .get(repo)
            .is_some_and(|s| s.contains(digest))
    }

    /// Materialize the full in-RAM state from `self` (delta) + snapshot base
    /// into a standalone `State` suitable for compaction/snapshot serialization.
    fn materialize(&self, base: Option<&snapshot::VerifiedSnapshot>) -> State {
        if base.is_none() {
            return State {
                tags: self.tags.clone(),
                media_types: self.media_types.clone(),
                referrers: self.referrers.clone(),
                backrefs: self.backrefs.clone(),
                checksums: self.checksums.clone(),
                log: None,
                deleted_digests: self.deleted_digests.clone(),
                deleted_checksums: self.deleted_checksums.clone(),
            };
        }
        let archived = base.unwrap().archived();
        let mut out = State::default();

        // Tags: base filtered by tombstones, then delta overrides.
        for entry in archived.tags.iter() {
            let repo: String = entry.repo.as_str().into();
            let deleted = self.deleted_digests.get(&repo);
            for tag_entry in entry.tags.iter() {
                let tag: String = tag_entry.tag.as_str().into();
                let digest: String = tag_entry.digest.as_str().into();
                let media: String = tag_entry.media_type.as_str().into();
                if deleted.is_some_and(|s| s.contains(&digest)) {
                    continue;
                }
                out.tags
                    .entry(repo.clone())
                    .or_default()
                    .insert(tag, (digest, media));
            }
        }
        for (repo, delta_tags) in &self.tags {
            let out_tags = out.tags.entry(repo.clone()).or_default();
            for (tag, val) in delta_tags {
                out_tags.insert(tag.clone(), val.clone());
            }
        }

        // Media types: base minus tombstones, then delta.
        for entry in archived.media_types.iter() {
            let repo: String = entry.repo.as_str().into();
            let digest: String = entry.digest.as_str().into();
            let media: String = entry.media_type.as_str().into();
            let key = (repo, digest);
            if self
                .deleted_digests
                .get(&key.0)
                .is_some_and(|s| s.contains(&key.1))
            {
                continue;
            }
            out.media_types.insert(key, media);
        }
        for (k, v) in &self.media_types {
            out.media_types.insert(k.clone(), v.clone());
        }

        // Referrers: base minus tombstones, then delta.
        for entry in archived.referrers.iter() {
            let repo: String = entry.repo.as_str().into();
            let subject: String = entry.subject.as_str().into();
            let key = (repo.clone(), subject);
            let deleted = self.deleted_digests.get(&repo);
            let out_refs = out.referrers.entry(key).or_default();
            for ref_entry in entry.referrers.iter() {
                let referrer: String = ref_entry.referrer_digest.as_str().into();
                if deleted.is_some_and(|s| s.contains(&referrer)) {
                    continue;
                }
                let descriptor: Vec<u8> = ref_entry.descriptor.as_slice().to_vec();
                out_refs.insert(&referrer, &descriptor);
            }
        }
        for (k, v) in &self.referrers {
            let out_refs = out.referrers.entry(k.clone()).or_default();
            for (d, (_, bytes)) in &v.by_digest {
                out_refs.insert(d, bytes);
            }
        }
        out.referrers.retain(|_, v| !v.by_digest.is_empty());

        // Backrefs: base minus tombstones, then delta.
        for entry in archived.backrefs.iter() {
            let repo: String = entry.repo.as_str().into();
            let blob: String = entry.blob.as_str().into();
            let key = (repo.clone(), blob);
            let deleted = self.deleted_digests.get(&repo);
            let mut manifests: Vec<String> = entry
                .manifests
                .iter()
                .map(|s| s.as_str().to_string())
                .filter(|m| !deleted.is_some_and(|s| s.contains(m)))
                .collect();
            if let Some(delta) = self.backrefs.get(&key) {
                for m in delta {
                    if !manifests.contains(m) {
                        manifests.push(m.clone());
                    }
                }
            }
            if !manifests.is_empty() {
                out.backrefs.insert(key, manifests);
            }
        }
        // Delta-only backrefs.
        for (k, v) in &self.backrefs {
            if !out.backrefs.contains_key(k) {
                out.backrefs.insert(k.clone(), v.clone());
            }
        }

        // Checksums: base minus tombstones, then delta.
        for entry in archived.checksums.iter() {
            let repo: String = entry.repo.as_str().into();
            let digest: String = entry.digest.as_str().into();
            let key = (repo, digest);
            if self.deleted_checksums.contains(&key) {
                continue;
            }
            if self
                .deleted_digests
                .get(&key.0)
                .is_some_and(|s| s.contains(&key.1))
            {
                continue;
            }
            out.checksums.insert(
                key,
                BlobChecksum {
                    crc32c: entry.crc32c.into(),
                    size: entry.size.into(),
                },
            );
        }
        for (k, v) in &self.checksums {
            out.checksums.insert(k.clone(), *v);
        }

        out
    }
}

// ============================================================================
// LogMetadataStore: open, apply_in_ram
// ============================================================================

impl LogMetadataStore {
    /// Open with the `[storage.metadata]` policy.
    pub fn open_with(root: &Path, config: &MetadataConfig) -> io::Result<Self> {
        let hmac_key = config
            .hmac_key_file
            .as_ref()
            .map(|p| HmacKey::load(p))
            .transpose()?;
        Self::open_inner(
            root,
            config.compact_threshold_bytes,
            config.snapshot,
            hmac_key,
        )
    }

    /// Open (replaying) or create the metadata store.
    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_inner(root, 0, false, None)
    }

    fn open_inner(
        root: &Path,
        compact_threshold: u64,
        snapshot_enabled: bool,
        hmac_key: Option<HmacKey>,
    ) -> io::Result<Self> {
        let log_path = root.join("roci-meta.log");
        let snapshot_path = root.join("roci-meta.snapshot");
        let mut state = State::default();
        let mut generation = 0u64;
        // `(generation, covered log offset)` of a verified snapshot.
        let mut covered: Option<(u64, u64)> = None;
        let mut snap_base: Option<snapshot::VerifiedSnapshot> = None;

        // Phase 1: Try to load and verify a snapshot.
        if snapshot_enabled {
            match snapshot::VerifiedSnapshot::open(&snapshot_path, hmac_key.as_ref()) {
                Ok(Some(verified)) => {
                    let archived = verified.archived();
                    generation = archived.generation.into();
                    covered = Some((generation, archived.log_offset.into()));
                    snap_base = Some(verified);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "discarding invalid snapshot; falling back to log replay"
                    );
                    let _ = std::fs::remove_file(&snapshot_path);
                }
            }
        }

        // Phase 2: Replay the log.
        if let Ok(bytes) = std::fs::read(&log_path) {
            if !bytes.is_empty() {
                let expected_mode = if hmac_key.is_some() {
                    FramingMode::HmacSha256
                } else {
                    FramingMode::Plain
                };
                match check_log_framing(&bytes, expected_mode, hmac_key.as_ref()) {
                    LogFramingCheck::Compatible => {
                        replay_log(&bytes, &mut state, hmac_key.as_ref(), covered);
                    }
                    LogFramingCheck::Incompatible => {
                        tracing::warn!(
                            "WAL framing/key mismatch; moving log aside and starting fresh"
                        );
                        let _ = wal_hmac::move_aside(&log_path);
                        if snap_base.is_some() {
                            snap_base = None;
                            let _ = std::fs::remove_file(&snapshot_path);
                        }
                    }
                    LogFramingCheck::NoHeader => {
                        // Legacy log without a header — only compatible when
                        // no HMAC key is configured.
                        if hmac_key.is_some() {
                            tracing::warn!(
                                "unauthenticated log found with HMAC key configured; \
                                 moving log aside"
                            );
                            let _ = wal_hmac::move_aside(&log_path);
                            if snap_base.is_some() {
                                snap_base = None;
                                let _ = std::fs::remove_file(&snapshot_path);
                            }
                        } else {
                            replay_legacy(&bytes, &mut state);
                        }
                    }
                }
            }
        }

        Ok(Self {
            inner: Mutex::new(state),
            appended: AtomicU64::new(0),
            sync: Mutex::new(SyncCoord::default()),
            log_path,
            snapshot_path,
            compact_threshold,
            snapshot_enabled,
            hmac_key,
            snap_base: Mutex::new(snap_base),
            generation: Mutex::new(generation),
            image_len: AtomicU64::new(covered.map_or(0, |(_, offset)| offset)),
        })
    }

    fn apply_in_ram(state: &mut State, op: &MetaOp) {
        match op {
            MetaOp::PutManifest {
                repo,
                digest,
                media_type,
                tag,
                references,
                referrer,
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
                state.add_backrefs(repo, digest, references);
                if let Some((subject, descriptor)) = referrer {
                    state.add_referrer(repo, subject, digest, descriptor);
                }
            }
            MetaOp::DeleteManifest { repo, digest } => {
                state.checksums.remove(&(repo.clone(), digest.clone()));
                state
                    .deleted_checksums
                    .insert((repo.clone(), digest.clone()));
                state.media_types.remove(&(repo.clone(), digest.clone()));
                // Tombstone this digest in the base.
                state
                    .deleted_digests
                    .entry(repo.clone())
                    .or_default()
                    .insert(digest.clone());
                // Drop tags pointing at this digest from the delta.
                if let Some(tags) = state.tags.get_mut(repo) {
                    tags.retain(|_, (d, _)| d != digest);
                    if tags.is_empty() {
                        state.tags.remove(repo);
                    }
                }
                // Drop from delta referrers.
                state.referrers.retain(|(r, _), refs| {
                    if r == repo {
                        refs.remove(digest);
                    }
                    !refs.by_digest.is_empty()
                });
                // Drop from delta backrefs.
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
            } => state.add_backrefs(repo, manifest, blobs),
            MetaOp::PutReferrer {
                repo,
                subject,
                referrer,
                descriptor,
            } => state.add_referrer(repo, subject, referrer, descriptor),
            MetaOp::PutChecksum {
                repo,
                digest,
                crc32c,
                size,
            } => {
                let key = (repo.clone(), digest.clone());
                state.deleted_checksums.remove(&key);
                state.checksums.insert(
                    key,
                    BlobChecksum {
                        crc32c: *crc32c,
                        size: *size,
                    },
                );
            }
            MetaOp::DeleteBlob { repo, digest } => {
                let key = (repo.clone(), digest.clone());
                state.checksums.remove(&key);
                state.deleted_checksums.insert(key);
            }
        }
    }
}

// ============================================================================
// MetadataStore trait implementation
// ============================================================================

impl MetadataStore for LogMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        // Check delta first.
        if let Some(tags) = state.tags.get(repo) {
            if let Some(v) = tags.get(tag) {
                return Some(v.clone());
            }
        }
        // Check base.
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a.tags.binary_search_by(|e| e.repo.as_str().cmp(repo)) {
                for entry in a.tags[idx].tags.iter() {
                    if entry.tag.as_str() == tag {
                        let digest: String = entry.digest.as_str().into();
                        if state.is_digest_deleted(repo, &digest) {
                            return None;
                        }
                        return Some((digest, entry.media_type.as_str().into()));
                    }
                }
            }
        }
        None
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        if let Some(v) = state
            .media_types
            .get(&(repo.to_string(), digest.to_string()))
        {
            return Some(v.clone());
        }
        if state.is_digest_deleted(repo, digest) {
            return None;
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .media_types
                .binary_search_by(|e| (e.repo.as_str(), e.digest.as_str()).cmp(&(repo, digest)))
            {
                return Some(a.media_types[idx].media_type.as_str().into());
            }
        }
        None
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");

        if base.is_none() {
            // Fast path: no snapshot, pure delta.
            let tags = state.tags.get(repo)?;
            return Some(take_page(
                tags.range::<str, _>(after(last)).map(|(t, _)| t.clone()),
                limit,
            ));
        }

        // Merge base + delta, filtering tombstones.
        let a = base.as_ref().unwrap().archived();
        let delta_tags = state.tags.get(repo);
        let base_repo = a
            .tags
            .binary_search_by(|e| e.repo.as_str().cmp(repo))
            .ok()
            .map(|i| &a.tags[i].tags);

        if delta_tags.is_none() && base_repo.is_none() {
            return None;
        }

        let mut merged = BTreeMap::new();
        if let Some(base_tags) = base_repo {
            for entry in base_tags.iter() {
                let tag: String = entry.tag.as_str().into();
                let digest: String = entry.digest.as_str().into();
                if !state.is_digest_deleted(repo, &digest) {
                    merged.insert(tag, ());
                }
            }
        }
        if let Some(dt) = delta_tags {
            for t in dt.keys() {
                merged.insert(t.clone(), ());
            }
        }

        if merged.is_empty() {
            return None;
        }

        Some(take_page(
            merged.range::<str, _>(after(last)).map(|(t, _)| t.clone()),
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
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let key = (repo.to_string(), subject.to_string());

        if base.is_none() {
            let refs = state.referrers.get(&key)?;
            return Some(refs.page(artifact_type, last, limit));
        }

        // Merge base + delta referrers into a temporary SubjectReferrers.
        let a = base.as_ref().unwrap().archived();
        let base_refs = a
            .referrers
            .binary_search_by(|e| (e.repo.as_str(), e.subject.as_str()).cmp(&(repo, subject)))
            .ok()
            .map(|i| &a.referrers[i].referrers);
        let delta_refs = state.referrers.get(&key);

        if base_refs.is_none() && delta_refs.is_none() {
            return None;
        }

        let mut merged = SubjectReferrers::default();
        if let Some(br) = base_refs {
            for entry in br.iter() {
                let referrer: String = entry.referrer_digest.as_str().into();
                if state.is_digest_deleted(repo, &referrer) {
                    continue;
                }
                let descriptor: Vec<u8> = entry.descriptor.as_slice().to_vec();
                merged.insert(&referrer, &descriptor);
            }
        }
        if let Some(dr) = delta_refs {
            for (d, (_, bytes)) in &dr.by_digest {
                merged.insert(d, bytes);
            }
        }

        if merged.by_digest.is_empty() {
            return None;
        }

        Some(merged.page(artifact_type, last, limit))
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let key = (repo.to_string(), subject.to_string());
        if let Some(refs) = state.referrers.get(&key) {
            if refs.by_digest.contains_key(referrer) {
                return true;
            }
        }
        if state.is_digest_deleted(repo, referrer) {
            return false;
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .referrers
                .binary_search_by(|e| (e.repo.as_str(), e.subject.as_str()).cmp(&(repo, subject)))
            {
                return a.referrers[idx]
                    .referrers
                    .binary_search_by(|e| e.referrer_digest.as_str().cmp(referrer))
                    .is_ok();
            }
        }
        false
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let key = (repo.to_string(), blob.to_string());
        let base = self.snap_base.lock().expect("snap lock poisoned");

        let mut result: Vec<String> = Vec::new();

        // Base backrefs for this blob.
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .backrefs
                .binary_search_by(|e| (e.repo.as_str(), e.blob.as_str()).cmp(&(repo, blob)))
            {
                for m in a.backrefs[idx].manifests.iter() {
                    let ms: String = m.as_str().into();
                    if !state.is_digest_deleted(repo, &ms) {
                        result.push(ms);
                    }
                }
            }
        }

        // Delta backrefs.
        if let Some(delta) = state.backrefs.get(&key) {
            for m in delta {
                if !result.contains(m) {
                    result.push(m.clone());
                }
            }
        }

        result
    }

    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let key = (repo.to_string(), digest.to_string());
        if let Some(v) = state.checksums.get(&key) {
            return Some(*v);
        }
        if state.deleted_checksums.contains(&key) || state.is_digest_deleted(repo, digest) {
            return None;
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .checksums
                .binary_search_by(|e| (e.repo.as_str(), e.digest.as_str()).cmp(&(repo, digest)))
            {
                return Some(BlobChecksum {
                    crc32c: a.checksums[idx].crc32c.into(),
                    size: a.checksums[idx].size.into(),
                });
            }
        }
        None
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        let my_seq = self.append_record(&op)?;
        self.group_commit_through(my_seq)
    }

    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()> {
        self.append_record(&op).map(drop)
    }

    fn repos(&self) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let mut repos: BTreeSet<String> = state
            .media_types
            .keys()
            .chain(state.referrers.keys())
            .map(|(r, _)| r.clone())
            .collect();
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            for entry in a.media_types.iter() {
                let repo: String = entry.repo.as_str().into();
                let digest: String = entry.digest.as_str().into();
                if !state.is_digest_deleted(&repo, &digest) {
                    repos.insert(repo);
                }
            }
            for entry in a.referrers.iter() {
                let repo: String = entry.repo.as_str().into();
                let has_live = entry
                    .referrers
                    .iter()
                    .any(|r| !state.is_digest_deleted(&repo, r.referrer_digest.as_str()));
                if has_live {
                    repos.insert(repo);
                }
            }
        }
        repos.into_iter().collect()
    }

    fn manifests(&self, repo: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let mut result: Vec<String> = state
            .media_types
            .keys()
            .filter(|(r, _)| r == repo)
            .map(|(_, d)| d.clone())
            .collect();
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            for entry in a.media_types.iter() {
                if entry.repo.as_str() == repo {
                    let digest: String = entry.digest.as_str().into();
                    if !state.is_digest_deleted(repo, &digest) && !result.contains(&digest) {
                        result.push(digest);
                    }
                }
            }
        }
        result
    }

    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");

        let mut merged: BTreeMap<String, (String, String)> = BTreeMap::new();
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a.tags.binary_search_by(|e| e.repo.as_str().cmp(repo)) {
                for entry in a.tags[idx].tags.iter() {
                    let digest: String = entry.digest.as_str().into();
                    if !state.is_digest_deleted(repo, &digest) {
                        merged.insert(
                            entry.tag.as_str().into(),
                            (digest, entry.media_type.as_str().into()),
                        );
                    }
                }
            }
        }
        if let Some(dt) = state.tags.get(repo) {
            for (t, v) in dt {
                merged.insert(t.clone(), v.clone());
            }
        }
        merged.into_iter().map(|(t, (d, m))| (t, d, m)).collect()
    }

    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");

        let mut by_subject: HashMap<String, SubjectReferrers> = HashMap::new();

        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            for entry in a.referrers.iter() {
                if entry.repo.as_str() != repo {
                    continue;
                }
                let subject: String = entry.subject.as_str().into();
                let sr = by_subject.entry(subject).or_default();
                for ref_entry in entry.referrers.iter() {
                    let referrer: String = ref_entry.referrer_digest.as_str().into();
                    if !state.is_digest_deleted(repo, &referrer) {
                        let descriptor: Vec<u8> = ref_entry.descriptor.as_slice().to_vec();
                        sr.insert(&referrer, &descriptor);
                    }
                }
            }
        }

        for ((r, subject), refs) in &state.referrers {
            if r != repo {
                continue;
            }
            let sr = by_subject.entry(subject.clone()).or_default();
            for (d, (_, bytes)) in &refs.by_digest {
                sr.insert(d, bytes);
            }
        }

        by_subject
            .into_iter()
            .filter(|(_, sr)| !sr.by_digest.is_empty())
            .map(|(subject, sr)| {
                let refs = sr
                    .by_digest
                    .into_iter()
                    .map(|(d, (_, bytes))| (d, bytes))
                    .collect();
                (subject, refs)
            })
            .collect()
    }

    fn maintain(&self) -> io::Result<()> {
        self.do_maintain()
    }

    fn generation(&self) -> u64 {
        *self.generation.lock().expect("gen lock poisoned")
    }

    fn log_len(&self) -> u64 {
        std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }
}

// ============================================================================
// Private implementation: append, group-commit, compaction, snapshot
// ============================================================================

impl LogMetadataStore {
    fn append_record(&self, op: &MetaOp) -> io::Result<u64> {
        let record = encode(op, self.hmac_key.as_ref());
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        if state.log.is_none() {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)?;
            let clone = f.try_clone()?;
            // Write header if the file is empty (new log).
            let meta = f.metadata()?;
            if meta.len() == 0 {
                let mode = if self.hmac_key.is_some() {
                    FramingMode::HmacSha256
                } else {
                    FramingMode::Plain
                };
                let header_payload = wal_hmac::encode_header(mode);
                let header_record = encode_raw(&header_payload, self.hmac_key.as_ref());
                // We write header + first record together before setting the
                // file handle, so the header is always the first record.
                let mut combined = header_record;
                combined.extend_from_slice(&record);
                (&f).write_all(&combined)?;
                (&f).flush()?;
            } else {
                (&f).write_all(&record)?;
                (&f).flush()?;
            }
            state.log = Some(f);
            self.sync.lock().expect("sync lock poisoned").handle = Some(clone);
            let seq = self.appended.fetch_add(1, Ordering::AcqRel) + 1;
            Self::apply_in_ram(&mut state, op);
            roci_telemetry::record_meta_wal_append();
            return Ok(seq);
        }
        let log = state.log.as_mut().expect("log opened above");
        log.write_all(&record)?;
        log.flush()?;
        let seq = self.appended.fetch_add(1, Ordering::AcqRel) + 1;
        Self::apply_in_ram(&mut state, op);
        roci_telemetry::record_meta_wal_append();
        Ok(seq)
    }

    fn group_commit_through(&self, my_seq: u64) -> io::Result<()> {
        let mut sync = self.sync.lock().expect("sync lock poisoned");
        if sync.synced >= my_seq {
            return Ok(());
        }
        let covered = self.appended.load(Ordering::Acquire);
        sync.handle
            .as_ref()
            .expect("log handle set on first append")
            .sync_data()?;
        let batch = covered.saturating_sub(sync.synced);
        sync.synced = sync.synced.max(covered);
        roci_telemetry::record_meta_wal_batch_size(batch);
        Ok(())
    }

    /// The maintenance entry point. Nothing happens until the WAL outgrows
    /// `compact_threshold`; then the log is rewritten as the minimal record
    /// image of the current state and — with `snapshot` on — an rkyv snapshot
    /// covering that image is cut, so a cold start maps the snapshot and
    /// replays only the records appended after it.
    ///
    /// The state lock is held for the whole rewrite: appends pause for its
    /// duration (O(state) serialization + two fsyncs) but can never interleave
    /// with, or be lost by, the swap.
    fn do_maintain(&self) -> io::Result<()> {
        let log_size = std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let grown = log_size.saturating_sub(self.image_len.load(Ordering::Acquire));
        if self.compact_threshold == 0 || grown <= self.compact_threshold {
            return Ok(());
        }
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        let mut base = self.snap_base.lock().expect("snap lock poisoned");
        let full = state.materialize(base.as_ref());
        if self.snapshot_enabled {
            let mut gen = self.generation.lock().expect("gen lock poisoned");
            let next = *gen + 1;
            let (tmp, covered) = self.write_log_image(&full, Some(next))?;
            let snap_state = state_to_snapshot(&full, next, covered);
            let body = rkyv::to_bytes::<rkyv::rancor::Error>(&snap_state)
                .map_err(|e| io::Error::other(format!("rkyv: {e}")))?;
            let hdr = snapshot::encode_header(&body, self.hmac_key.as_ref());
            // Snapshot first: a crash before the log swap leaves the new
            // snapshot next to the previous-generation log, which open()
            // ignores — the snapshot already covers every record in it.
            snapshot::write_atomic(&self.snapshot_path, &hdr, &body)?;
            self.install_log(&mut state, &tmp)?;
            self.image_len.store(covered, Ordering::Release);
            *base = snapshot::VerifiedSnapshot::open(&self.snapshot_path, self.hmac_key.as_ref())?;
            *gen = next;
            // The snapshot is the new base; the in-RAM delta starts empty.
            state.tags.clear();
            state.media_types.clear();
            state.referrers.clear();
            state.backrefs.clear();
            state.checksums.clear();
            state.deleted_digests.clear();
            state.deleted_checksums.clear();
            roci_telemetry::record_meta_compaction("ok");
            roci_telemetry::record_meta_snapshot("ok");
        } else {
            let (tmp, len) = self.write_log_image(&full, None)?;
            self.install_log(&mut state, &tmp)?;
            self.image_len.store(len, Ordering::Release);
            roci_telemetry::record_meta_compaction("ok");
        }
        Ok(())
    }

    /// Write the minimal record image reproducing `full` — WAL header, an
    /// optional generation marker binding it to a snapshot, then one record
    /// per tag / untagged manifest / backref edge / referrer / checksum — to a
    /// temp beside the log, fsynced. Returns the temp path and its length
    /// (the offset a snapshot of the same state covers through).
    fn write_log_image(&self, full: &State, gen: Option<u64>) -> io::Result<(PathBuf, u64)> {
        let key = self.hmac_key.as_ref();
        let tmp = self.log_path.with_extension("log.compact.tmp");
        let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        let mode = if key.is_some() {
            FramingMode::HmacSha256
        } else {
            FramingMode::Plain
        };
        f.write_all(&encode_raw(&wal_hmac::encode_header(mode), key))?;
        if let Some(gen) = gen {
            let marker = format!("{{\"op\":\"gen\",\"gen\":{gen}}}");
            f.write_all(&encode_raw(marker.as_bytes(), key))?;
        }
        let mut tagged: BTreeSet<(&str, &str)> = BTreeSet::new();
        for (repo, tags) in &full.tags {
            for (tag, (digest, media_type)) in tags {
                f.write_all(&encode(
                    &MetaOp::PutManifest {
                        repo: repo.clone(),
                        digest: digest.clone(),
                        media_type: media_type.clone(),
                        tag: Some(tag.clone()),
                        references: Vec::new(),
                        referrer: None,
                    },
                    key,
                ))?;
                tagged.insert((repo, digest));
            }
        }
        for ((repo, digest), media_type) in &full.media_types {
            if !tagged.contains(&(repo.as_str(), digest.as_str())) {
                f.write_all(&encode(
                    &MetaOp::PutManifest {
                        repo: repo.clone(),
                        digest: digest.clone(),
                        media_type: media_type.clone(),
                        tag: None,
                        references: Vec::new(),
                        referrer: None,
                    },
                    key,
                ))?;
            }
        }
        for ((repo, blob), manifests) in &full.backrefs {
            for m in manifests {
                f.write_all(&encode(
                    &MetaOp::PutBackrefs {
                        repo: repo.clone(),
                        manifest: m.clone(),
                        blobs: vec![blob.clone()],
                    },
                    key,
                ))?;
            }
        }
        for ((repo, subject), refs) in &full.referrers {
            for (referrer, (_, descriptor)) in &refs.by_digest {
                f.write_all(&encode(
                    &MetaOp::PutReferrer {
                        repo: repo.clone(),
                        subject: subject.clone(),
                        referrer: referrer.clone(),
                        descriptor: descriptor.clone(),
                    },
                    key,
                ))?;
            }
        }
        for ((repo, digest), ck) in &full.checksums {
            f.write_all(&encode(
                &MetaOp::PutChecksum {
                    repo: repo.clone(),
                    digest: digest.clone(),
                    crc32c: ck.crc32c,
                    size: ck.size,
                },
                key,
            ))?;
        }
        let f = f.into_inner().map_err(io::IntoInnerError::into_error)?;
        f.sync_all()?;
        let len = f.metadata()?.len();
        Ok((tmp, len))
    }

    /// Atomically install `tmp` as the WAL (rename + dir fsync) and point the
    /// append and group-commit handles at it. Every record appended so far is
    /// in the image, so the durability watermark moves to the current seq.
    fn install_log(&self, state: &mut State, tmp: &Path) -> io::Result<()> {
        std::fs::rename(tmp, &self.log_path)?;
        if let Some(dir) = self.log_path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.log_path)?;
        let clone = f.try_clone()?;
        state.log = Some(f);
        let mut sync = self.sync.lock().expect("sync lock poisoned");
        sync.handle = Some(clone);
        sync.synced = self.appended.load(Ordering::Acquire);
        Ok(())
    }
}

/// Convert a materialized State into a SnapshotState for rkyv serialization.
fn state_to_snapshot(state: &State, generation: u64, log_offset: u64) -> SnapshotState {
    use snapshot::*;

    let mut tags: Vec<RepoTags> = state
        .tags
        .iter()
        .map(|(repo, btree)| RepoTags {
            repo: repo.clone(),
            tags: btree
                .iter()
                .map(|(tag, (digest, media))| TagEntry {
                    tag: tag.clone(),
                    digest: digest.clone(),
                    media_type: media.clone(),
                })
                .collect(),
        })
        .collect();
    tags.sort_by(|a, b| a.repo.cmp(&b.repo));

    let mut media_types: Vec<MediaTypeEntry> = state
        .media_types
        .iter()
        .map(|((r, d), m)| MediaTypeEntry {
            repo: r.clone(),
            digest: d.clone(),
            media_type: m.clone(),
        })
        .collect();
    media_types.sort_by(|a, b| (&a.repo, &a.digest).cmp(&(&b.repo, &b.digest)));

    let mut referrers: Vec<SubjectReferrers> = state
        .referrers
        .iter()
        .map(|((repo, subject), sr)| {
            let mut entries: Vec<ReferrerEntry> = sr
                .by_digest
                .iter()
                .map(|(d, (at, bytes))| ReferrerEntry {
                    referrer_digest: d.clone(),
                    artifact_type: at.clone().unwrap_or_default(),
                    descriptor: bytes.clone(),
                })
                .collect();
            entries.sort_by(|a, b| a.referrer_digest.cmp(&b.referrer_digest));
            snapshot::SubjectReferrers {
                repo: repo.clone(),
                subject: subject.clone(),
                referrers: entries,
            }
        })
        .collect();
    referrers.sort_by(|a, b| (&a.repo, &a.subject).cmp(&(&b.repo, &b.subject)));

    let mut backrefs: Vec<BackrefEntry> = state
        .backrefs
        .iter()
        .map(|((r, b), ms)| BackrefEntry {
            repo: r.clone(),
            blob: b.clone(),
            manifests: ms.clone(),
        })
        .collect();
    backrefs.sort_by(|a, b| (&a.repo, &a.blob).cmp(&(&b.repo, &b.blob)));

    let mut checksums: Vec<ChecksumEntry> = state
        .checksums
        .iter()
        .map(|((r, d), ck)| ChecksumEntry {
            repo: r.clone(),
            digest: d.clone(),
            crc32c: ck.crc32c,
            size: ck.size,
        })
        .collect();
    checksums.sort_by(|a, b| (&a.repo, &a.digest).cmp(&(&b.repo, &b.digest)));

    SnapshotState {
        tags,
        media_types,
        referrers,
        backrefs,
        checksums,
        generation,
        log_offset,
    }
}

// ============================================================================
// Log framing: encode, replay, compatibility checking
// ============================================================================

/// Encode a MetaOp as a framed record.
fn encode(op: &MetaOp, hmac_key: Option<&HmacKey>) -> Vec<u8> {
    let payload = serialize_op(op);
    encode_raw(&payload, hmac_key)
}

/// Encode raw payload bytes as a framed record.
fn encode_raw(payload: &[u8], hmac_key: Option<&HmacKey>) -> Vec<u8> {
    let crc = crc32c::crc32c(payload);
    let hmac_tag = hmac_key.map(|k| k.tag(payload));
    let total = 8 + payload.len() + if hmac_tag.is_some() { 32 } else { 0 };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(payload);
    if let Some(tag) = hmac_tag {
        out.extend_from_slice(&tag);
    }
    out
}

/// Result of checking the first record of a log for framing compatibility.
enum LogFramingCheck {
    /// The log has a header matching the expected mode.
    Compatible,
    /// The log has a header with a different mode.
    Incompatible,
    /// The log has no WAL header (legacy format).
    NoHeader,
}

/// Check if the log's first record is a WAL header matching `expected`.
fn check_log_framing(
    bytes: &[u8],
    expected: FramingMode,
    hmac_key: Option<&HmacKey>,
) -> LogFramingCheck {
    if bytes.len() < 8 {
        return LogFramingCheck::NoHeader;
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let crc = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let payload_end = 8 + len;
    if payload_end > bytes.len() {
        return LogFramingCheck::NoHeader;
    }
    let payload = &bytes[8..payload_end];
    if crc32c::crc32c(payload) != crc {
        return LogFramingCheck::NoHeader;
    }
    match decode_header(payload) {
        Some(mode) if mode == expected => {
            // If an HMAC key is configured and the mode is HMAC, verify
            // the HMAC tag on the header record to detect a wrong key.
            if let Some(key) = hmac_key {
                let hmac_start = payload_end;
                let hmac_end = hmac_start + 32;
                if hmac_end > bytes.len() {
                    return LogFramingCheck::Incompatible;
                }
                let tag: [u8; 32] = bytes[hmac_start..hmac_end].try_into().expect("32 bytes");
                if !key.verify(payload, &tag) {
                    return LogFramingCheck::Incompatible;
                }
            }
            LogFramingCheck::Compatible
        }
        Some(_) => LogFramingCheck::Incompatible,
        None => LogFramingCheck::NoHeader,
    }
}

/// The generation a `{"op":"gen","gen":N}` marker record binds its log to.
fn generation_marker(payload: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    if v.get("op")?.as_str()? != "gen" {
        return None;
    }
    v.get("gen")?.as_u64()
}

/// Replay a log (with WAL header) into `state`.
/// With a verified snapshot, `covered = Some((generation, offset))`: a log of
/// another generation is ignored entirely (the snapshot covers it), and in the
/// matching log only records starting at or after `offset` — the tail appended
/// since the snapshot — are replayed. Without one, every record is replayed.
fn replay_log(
    bytes: &[u8],
    state: &mut State,
    hmac_key: Option<&HmacKey>,
    covered: Option<(u64, u64)>,
) {
    let mut pos = 0usize;
    let hmac_extra = if hmac_key.is_some() { 32 } else { 0 };
    // Records 0 and 1 may be the WAL header and a generation marker.
    let mut index = 0usize;
    let mut log_generation = 0u64;

    while pos + 8 <= bytes.len() {
        let record_start = pos;
        let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let crc = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let payload_start = pos + 8;
        let payload_end = payload_start + len;
        let record_end = payload_end + hmac_extra;
        if record_end > bytes.len() {
            break; // truncated tail
        }
        let payload = &bytes[payload_start..payload_end];
        if crc32c::crc32c(payload) != crc {
            break; // corrupt record
        }
        // Verify HMAC if configured.
        if let Some(key) = hmac_key {
            let tag: [u8; 32] = bytes[payload_end..record_end].try_into().expect("32 bytes");
            if !key.verify(payload, &tag) {
                break; // HMAC verification failed
            }
        }
        pos = record_end;
        index += 1;

        if index == 1 && decode_header(payload).is_some() {
            continue;
        }
        if index <= 2 {
            if let Some(g) = generation_marker(payload) {
                log_generation = g;
                continue;
            }
        }
        if let Some((snap_generation, offset)) = covered {
            // A log of another generation is fully covered by the snapshot;
            // in the matching one, skip the image the snapshot was cut from.
            if log_generation != snap_generation {
                return;
            }
            if (record_start as u64) < offset {
                continue;
            }
        }

        if let Some(op) = deserialize_op(payload) {
            LogMetadataStore::apply_in_ram(state, &op);
        }
    }
}

/// Replay a legacy log (no WAL header) into `state`.
fn replay_legacy(bytes: &[u8], state: &mut State) {
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
            break;
        }
        let payload = &bytes[start..end];
        if crc32c::crc32c(payload) != crc {
            break;
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
            references,
            referrer,
        } => {
            let mut v = serde_json::json!({
                "op": "put_manifest",
                "repo": repo,
                "digest": digest,
                "media_type": media_type,
                "tag": tag,
            });
            if !references.is_empty() {
                v["references"] = serde_json::json!(references);
            }
            if let Some((subject, descriptor)) = referrer {
                v["subject"] = serde_json::json!(subject);
                v["descriptor"] = serde_json::json!(String::from_utf8_lossy(descriptor));
            }
            v
        }
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
        MetaOp::PutChecksum {
            repo,
            digest,
            crc32c,
            size,
        } => serde_json::json!({
            "op": "put_checksum",
            "repo": repo,
            "digest": digest,
            "crc32c": crc32c,
            "size": size,
        }),
        MetaOp::DeleteBlob { repo, digest } => serde_json::json!({
            "op": "delete_blob",
            "repo": repo,
            "digest": digest,
        }),
    };
    serde_json::to_vec(&v).expect("MetaOp serializes")
}

fn deserialize_op(payload: &[u8]) -> Option<MetaOp> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let strings = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    match v.get("op").and_then(|x| x.as_str())? {
        "put_manifest" => Some(MetaOp::PutManifest {
            repo: s("repo")?,
            digest: s("digest")?,
            media_type: s("media_type")?,
            tag: s("tag"),
            references: strings("references"),
            referrer: s("subject").zip(s("descriptor").map(String::into_bytes)),
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
            blobs: strings("blobs"),
        }),
        "put_checksum" => Some(MetaOp::PutChecksum {
            repo: s("repo")?,
            digest: s("digest")?,
            crc32c: u32::try_from(v.get("crc32c")?.as_u64()?).ok()?,
            size: v.get("size")?.as_u64()?,
        }),
        "delete_blob" => Some(MetaOp::DeleteBlob {
            repo: s("repo")?,
            digest: s("digest")?,
        }),
        _ => None,
    }
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
            references: Vec::new(),
            referrer: None,
        }
    }

    fn make_key(dir: &Path) -> PathBuf {
        let p = dir.join("hmac.key");
        std::fs::write(&p, [0xABu8; 64]).unwrap();
        p
    }

    #[test]
    fn apply_resolve_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
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
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:rr".into(),
        })
        .unwrap();
        assert!(s
            .referrers_page("r", "sha256:aa", None, None, usize::MAX)
            .is_none());
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
        assert_eq!(page(Some("v2"), 2), (v(&["v3", "v4"]), false));
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
        add("r", "sha256:c", r#"{"artifactType":"sbom"}"#);
        assert_eq!(page(Some("sig"), None, 9), (v(&["sha256:a"]), false));
        assert_eq!(
            page(Some("sbom"), None, 9),
            (v(&["sha256:b", "sha256:c"]), false)
        );
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
            s.apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m".into(),
                blobs: vec!["sha256:b1".into()],
            })
            .unwrap();
            assert_eq!(s.backrefs("r", "sha256:b1"), vec!["sha256:m".to_string()]);
            assert!(s.backrefs("r", "sha256:absent").is_empty());
        }
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(s2.backrefs("r", "sha256:b2"), vec!["sha256:m".to_string()]);
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
            s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
            s.apply(MetaOp::DeleteManifest {
                repo: "r".into(),
                digest: "sha256:bb".into(),
            })
            .unwrap();
        }
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

        // Case 1: truncated trailing record.
        let mut torn = good.clone();
        torn.extend_from_slice(&(999u32).to_le_bytes());
        torn.extend_from_slice(&(0u32).to_le_bytes());
        torn.extend_from_slice(b"partial");
        std::fs::write(&log, &torn).unwrap();
        let s1 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s1.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        drop(s1);

        // Case 2: bad CRC.
        let mut bad = good.clone();
        let payload = b"{\"op\":\"delete_manifest\",\"repo\":\"r\",\"digest\":\"sha256:aa\"}";
        bad.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bad.extend_from_slice(&(0xDEAD_BEEFu32).to_le_bytes());
        bad.extend_from_slice(payload);
        std::fs::write(&log, &bad).unwrap();
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );

        // Case 3: unknown op is skipped, replay continues.
        let mut unknown = good.clone();
        let up = b"{\"op\":\"nope\"}";
        unknown.extend_from_slice(&(up.len() as u32).to_le_bytes());
        unknown.extend_from_slice(&crc32c::crc32c(up).to_le_bytes());
        unknown.extend_from_slice(up);
        unknown.extend_from_slice(&encode(&put("r", "sha256:bb", Some("v2")), None));
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
        let seq1 = s.append_record(&put("r", "sha256:aa", Some("v1"))).unwrap();
        let seq2 = s.append_record(&put("r", "sha256:bb", Some("v2"))).unwrap();
        assert_eq!((seq1, seq2), (1, 2));
        s.group_commit_through(seq2).unwrap();
        s.group_commit_through(seq1).unwrap();
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
        s2.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
    }

    // ---- Compaction tests ------------------------------------------------

    #[test]
    fn compaction_preserves_all_queries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            compact_threshold_bytes: 1, // compact on every maintain
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        // Build up state: tags, referrers, backrefs, checksums, media types.
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(put("r", "sha256:cc", None)).unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:aa".into(),
            referrer: "sha256:ref1".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:ref1"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:aa".into(),
            blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0x12345678,
            size: 1024,
        })
        .unwrap();

        // Snapshot state before compaction.
        let tags_before = s.tags_snapshot("r");
        let refs_before = s.referrers_snapshot("r");
        let backrefs_before = s.backrefs("r", "sha256:b1");
        let ck_before = s.checksum("r", "sha256:b1");
        let mt_before = s.manifest_media_type("r", "sha256:cc");
        let repos_before = s.repos();
        let manifests_before = s.manifests("r");

        // Compact.
        s.maintain().unwrap();

        // All queries must be identical.
        assert_eq!(s.tags_snapshot("r"), tags_before);
        assert_eq!(s.referrers_snapshot("r"), refs_before);
        assert_eq!(s.backrefs("r", "sha256:b1"), backrefs_before);
        assert_eq!(s.checksum("r", "sha256:b1"), ck_before);
        assert_eq!(s.manifest_media_type("r", "sha256:cc"), mt_before);
        assert_eq!(s.repos(), repos_before);
        assert_eq!(s.manifests("r"), manifests_before);

        // Appends after compaction still work.
        s.apply(put("r", "sha256:dd", Some("v3"))).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:dd")
        );

        // Reopen and verify.
        drop(s);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.tags_snapshot("r"), {
            let mut t = tags_before.clone();
            t.push((
                "v3".into(),
                "sha256:dd".into(),
                "application/vnd.oci.image.manifest.v1+json".into(),
            ));
            t.sort();
            t
        });
    }

    #[test]
    fn compaction_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
    }

    #[test]
    fn torn_tail_after_compaction_handled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        drop(s);

        // Append garbage to simulate a torn tail.
        let log = dir.path().join("roci-meta.log");
        let mut data = std::fs::read(&log).unwrap();
        data.extend_from_slice(&(999u32).to_le_bytes());
        data.extend_from_slice(b"garbage");
        std::fs::write(&log, &data).unwrap();

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s2.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
    }

    // ---- HMAC tests -------------------------------------------------------

    #[test]
    fn hmac_tampered_payload_stops_replay() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let cfg = MetadataConfig {
            hmac_key_file: Some(key_path.clone()),
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        drop(s);

        // Tamper with a byte in the second record's payload.
        let log = dir.path().join("roci-meta.log");
        let mut data = std::fs::read(&log).unwrap();
        // The log has: header_record, rec1, rec2. Flip a byte in the middle.
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&log, &data).unwrap();

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        // The first record (v1) may or may not survive depending on where
        // the flip landed. The tampered record and everything after must stop.
        // We just verify that v2 is gone (replay stopped).
        assert_eq!(s2.resolve_tag("r", "v2"), None);
    }

    #[test]
    fn hmac_wrong_key_moves_log_aside() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let cfg1 = MetadataConfig {
            hmac_key_file: Some(key_path),
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg1).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);

        // Open with a different key.
        let key2_path = dir.path().join("hmac2.key");
        std::fs::write(&key2_path, [0xCDu8; 64]).unwrap();
        let cfg2 = MetadataConfig {
            hmac_key_file: Some(key2_path),
            ..Default::default()
        };
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg2).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);

        // Original log was moved aside.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("untrusted"))
            .collect();
        assert!(!entries.is_empty(), "log should be moved aside");
    }

    #[test]
    fn hmac_unauthenticated_with_key_moves_aside() {
        let dir = tempfile::tempdir().unwrap();
        // Write a plain log.
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);

        // Open with an HMAC key.
        let key_path = make_key(dir.path());
        let cfg = MetadataConfig {
            hmac_key_file: Some(key_path),
            ..Default::default()
        };
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
    }

    #[test]
    fn hmac_key_too_short_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("short.key");
        std::fs::write(&key_path, [0u8; 31]).unwrap();
        let cfg = MetadataConfig {
            hmac_key_file: Some(key_path),
            ..Default::default()
        };
        let err = LogMetadataStore::open_with(dir.path(), &cfg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // ---- Snapshot tests ---------------------------------------------------

    #[test]
    fn snapshot_reopen_identical_queries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xABCD,
            size: 512,
        })
        .unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:aa".into(),
            referrer: "sha256:ref1".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:ref1"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:aa".into(),
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();

        let tags_before = s.tags_snapshot("r");
        let refs_before = s.referrers_page("r", "sha256:aa", None, None, usize::MAX);
        let ck_before = s.checksum("r", "sha256:b1");
        let br_before = s.backrefs("r", "sha256:b1");

        s.maintain().unwrap();
        drop(s);

        // Reopen from snapshot.
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.tags_snapshot("r"), tags_before);
        assert_eq!(
            s2.referrers_page("r", "sha256:aa", None, None, usize::MAX),
            refs_before
        );
        assert_eq!(s2.checksum("r", "sha256:b1"), ck_before);
        assert_eq!(s2.backrefs("r", "sha256:b1"), br_before);
    }

    #[test]
    fn snapshot_delta_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.maintain().unwrap();

        // Add more after snapshot.
        s.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        // Delete one from the snapshot base.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();

        assert_eq!(s.resolve_tag("r", "v1"), None);
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
        assert_eq!(s.manifest_media_type("r", "sha256:aa"), None);

        // Re-add the same digest.
        s.apply(put("r", "sha256:aa", Some("v1-new"))).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1-new").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );

        // Snapshot again and reopen.
        s.maintain().unwrap();
        drop(s);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
        assert_eq!(
            s2.resolve_tag("r", "v1-new").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
    }

    #[test]
    fn snapshot_page_merge_across_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        // Put tags v1, v3 in the snapshot base.
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        s.maintain().unwrap();

        // Add v2 and v4 in the delta.
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(put("r", "sha256:dd", Some("v4"))).unwrap();

        // Page across boundaries.
        let page = |last, limit| {
            let p = s.tags_page("r", last, limit).unwrap();
            (p.items, p.more)
        };
        let v = |ts: &[&str]| ts.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(page(None, 2), (v(&["v1", "v2"]), true));
        assert_eq!(page(Some("v2"), 2), (v(&["v3", "v4"]), false));
        assert_eq!(page(None, 4), (v(&["v1", "v2", "v3", "v4"]), false));
    }

    #[test]
    fn snapshot_corrupted_byte_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        // Corrupt the snapshot.
        let snap_path = dir.path().join("roci-meta.snapshot");
        let mut data = std::fs::read(&snap_path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&snap_path, &data).unwrap();

        // Reopen: should fall back to log replay.
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
    }

    #[test]
    fn snapshot_wrong_hmac_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            hmac_key_file: Some(key_path),
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        // Open with a different key.
        let key2_path = dir.path().join("hmac2.key");
        std::fs::write(&key2_path, [0xCDu8; 64]).unwrap();
        let cfg2 = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            hmac_key_file: Some(key2_path),
            ..Default::default()
        };
        // The snapshot has wrong HMAC, log has wrong HMAC framing too.
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg2).unwrap();
        // Both snapshot and log are discarded.
        assert_eq!(s2.resolve_tag("r", "v1"), None);
    }

    #[test]
    fn snapshot_stale_log_tail_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        // The maintain cut a snapshot (gen 1) and wrote a fresh log (gen 1).
        // Now add more.
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        drop(s);

        // Save the current log (gen 1, with v2).
        let log_path = dir.path().join("roci-meta.log");
        let saved_log = std::fs::read(&log_path).unwrap();

        // Re-open and maintain again to get gen 2.
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s2.maintain().unwrap();
        drop(s2);

        // Replace the log with the saved gen-1 log (stale).
        std::fs::write(&log_path, &saved_log).unwrap();

        // Reopen: the stale log tail (gen 1) should be ignored because
        // the snapshot is now gen 2.
        let s3 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s3.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s3.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
        // v2 is in the snapshot (gen 2), not from the stale log.
    }

    #[test]
    fn snapshot_is_cut_only_past_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = |threshold| MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: threshold,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg(1 << 20)).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        assert!(!dir.path().join("roci-meta.snapshot").exists());
        drop(s);
        let s = LogMetadataStore::open_with(dir.path(), &cfg(1)).unwrap();
        s.maintain().unwrap();
        let first = std::fs::metadata(dir.path().join("roci-meta.snapshot")).unwrap();
        // Upkeep triggers on growth past the last image, not on the image's
        // own size: with nothing appended since, a tick rewrites nothing.
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.maintain().unwrap();
        let again = std::fs::metadata(dir.path().join("roci-meta.snapshot")).unwrap();
        assert_eq!(first.modified().unwrap(), again.modified().unwrap());
        // Reopening from the snapshot replays nothing into the heap delta.
        drop(s);
        let s = LogMetadataStore::open_with(dir.path(), &cfg(1)).unwrap();
        assert!(s.inner.lock().unwrap().tags.is_empty());
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
    }

    #[test]
    fn snapshot_reopen_replays_only_the_tail_but_falls_back_to_the_image() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        for i in 0..20 {
            s.apply(put(
                "r",
                &format!("sha256:{i:02}"),
                Some(&format!("t{i:02}")),
            ))
            .unwrap();
        }
        s.maintain().unwrap();
        s.apply(put("r", "sha256:ff", Some("tail"))).unwrap();
        drop(s);
        // Cold start: the snapshot is the base; only the one tail record is
        // replayed into the heap delta.
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s.inner.lock().unwrap().tags["r"].len(), 1);
        assert_eq!(s.tags_page("r", None, 100).unwrap().items.len(), 21);
        drop(s);
        // A rejected snapshot falls back to the full log: the image the
        // snapshot was cut from plus the tail.
        std::fs::write(dir.path().join("roci-meta.snapshot"), b"garbage").unwrap();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s.tags_page("r", None, 100).unwrap().items.len(), 21);
    }

    #[test]
    fn debug_impl() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("LogMetadataStore"), "got: {dbg}");
        assert!(dbg.contains("log_path"), "got: {dbg}");
    }

    #[test]
    fn subject_referrers_remove_cleans_type_index() {
        let mut sr = SubjectReferrers::default();
        sr.insert("sha256:r1", br#"{"artifactType":"sig"}"#);
        sr.insert("sha256:r2", br#"{"artifactType":"sig"}"#);
        assert_eq!(sr.by_type.get("sig").map(|s| s.len()), Some(2));
        // Remove one: type entry is pruned from the set.
        sr.remove("sha256:r1");
        assert_eq!(sr.by_type.get("sig").map(|s| s.len()), Some(1));
        // Remove the other: the type key is deleted entirely.
        sr.remove("sha256:r2");
        assert!(!sr.by_type.contains_key("sig"));
        // Remove non-existent is a no-op.
        sr.remove("sha256:r99");
    }

    // ---- Legacy log (no header) ----------------------------------------

    #[test]
    fn legacy_log_replays_without_header() {
        // Build a legacy log (no WAL header, no generation marker) by
        // directly encoding records.
        let mut bytes = Vec::new();
        let payload1 = serialize_op(&put("r", "sha256:aa", Some("v1")));
        let crc1 = crc32c::crc32c(&payload1);
        bytes.extend_from_slice(&(payload1.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc1.to_le_bytes());
        bytes.extend_from_slice(&payload1);

        let payload2 = serialize_op(&MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0x1111,
            size: 256,
        });
        let crc2 = crc32c::crc32c(&payload2);
        bytes.extend_from_slice(&(payload2.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc2.to_le_bytes());
        bytes.extend_from_slice(&payload2);

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("roci-meta.log");
        std::fs::write(&log_path, &bytes).unwrap();

        let s = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s.checksum("r", "sha256:b1"),
            Some(BlobChecksum {
                crc32c: 0x1111,
                size: 256
            })
        );
    }

    #[test]
    fn legacy_log_truncated_stops_gracefully() {
        // Build a legacy log with a truncated trailing record.
        let mut bytes = Vec::new();
        let payload1 = serialize_op(&put("r", "sha256:aa", Some("v1")));
        let crc1 = crc32c::crc32c(&payload1);
        bytes.extend_from_slice(&(payload1.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc1.to_le_bytes());
        bytes.extend_from_slice(&payload1);
        // Truncated record: declared length exceeds remaining bytes.
        bytes.extend_from_slice(&(9999u32).to_le_bytes());
        bytes.extend_from_slice(&(0u32).to_le_bytes());
        bytes.extend_from_slice(b"short");

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("roci-meta.log");
        std::fs::write(&log_path, &bytes).unwrap();

        let s = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "should replay the valid record before the torn tail"
        );
    }

    #[test]
    fn legacy_log_bad_crc_stops_replay() {
        let mut bytes = Vec::new();
        let payload1 = serialize_op(&put("r", "sha256:aa", Some("v1")));
        let crc1 = crc32c::crc32c(&payload1);
        bytes.extend_from_slice(&(payload1.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc1.to_le_bytes());
        bytes.extend_from_slice(&payload1);
        // Record with bad CRC.
        let payload2 = serialize_op(&put("r", "sha256:bb", Some("v2")));
        bytes.extend_from_slice(&(payload2.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(0xDEAD_BEEFu32).to_le_bytes()); // wrong CRC
        bytes.extend_from_slice(&payload2);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("roci-meta.log"), &bytes).unwrap();

        let s = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(s.resolve_tag("r", "v2"), None);
    }

    // ---- Framing edge cases -------------------------------------------

    #[test]
    fn check_framing_short_bytes() {
        // < 8 bytes ⇒ NoHeader (line 1284)
        assert!(matches!(
            check_log_framing(b"short", FramingMode::Plain, None),
            LogFramingCheck::NoHeader
        ));
    }

    #[test]
    fn check_framing_truncated_payload() {
        // Declared payload length exceeds remaining bytes (line 1290)
        let mut buf = Vec::new();
        buf.extend_from_slice(&(999u32).to_le_bytes());
        buf.extend_from_slice(&(0u32).to_le_bytes());
        buf.extend_from_slice(b"x");
        assert!(matches!(
            check_log_framing(&buf, FramingMode::Plain, None),
            LogFramingCheck::NoHeader
        ));
    }

    #[test]
    fn check_framing_bad_crc() {
        // Payload CRC mismatch (line 1294)
        let payload = wal_hmac::encode_header(FramingMode::Plain);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(0xBAAD_F00Du32).to_le_bytes());
        buf.extend_from_slice(&payload);
        assert!(matches!(
            check_log_framing(&buf, FramingMode::Plain, None),
            LogFramingCheck::NoHeader
        ));
    }

    #[test]
    fn check_framing_hmac_truncated_tag() {
        // HMAC mode but tag bytes missing (line 1304)
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let key = HmacKey::load(&key_path).unwrap();
        let payload = wal_hmac::encode_header(FramingMode::HmacSha256);
        let crc = crc32c::crc32c(&payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&payload);
        // No HMAC tag appended → Incompatible
        assert!(matches!(
            check_log_framing(&buf, FramingMode::HmacSha256, Some(&key)),
            LogFramingCheck::Incompatible
        ));
    }

    #[test]
    fn check_framing_hmac_wrong_tag() {
        // Valid framing but HMAC tag is wrong → Incompatible (line 1308)
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let key = HmacKey::load(&key_path).unwrap();
        let payload = wal_hmac::encode_header(FramingMode::HmacSha256);
        let crc = crc32c::crc32c(&payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(&[0xFFu8; 32]); // wrong HMAC
        assert!(matches!(
            check_log_framing(&buf, FramingMode::HmacSha256, Some(&key)),
            LogFramingCheck::Incompatible
        ));
    }

    #[test]
    fn check_framing_mode_mismatch() {
        // Plain header but expecting HmacSha256 → Incompatible (line 1314)
        let payload = wal_hmac::encode_header(FramingMode::Plain);
        let crc = crc32c::crc32c(&payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&payload);
        assert!(matches!(
            check_log_framing(&buf, FramingMode::HmacSha256, None),
            LogFramingCheck::Incompatible
        ));
    }

    #[test]
    fn check_framing_non_header_payload() {
        // Valid CRC but payload isn't a header → NoHeader (line 1314)
        let payload = b"not_a_header_record";
        let crc = crc32c::crc32c(payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(payload);
        assert!(matches!(
            check_log_framing(&buf, FramingMode::Plain, None),
            LogFramingCheck::NoHeader
        ));
    }

    // ---- deserialize_op: DeleteBlob (lines 1548-1549) --------------------

    #[test]
    fn deserialize_delete_blob() {
        let op = MetaOp::DeleteBlob {
            repo: "r".into(),
            digest: "sha256:xx".into(),
        };
        let bytes = serialize_op(&op);
        let round = deserialize_op(&bytes).expect("should parse DeleteBlob");
        assert_eq!(round, op);
    }

    // ---- Incompatible framing with snapshot discards both ----------------

    #[test]
    fn incompatible_framing_discards_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            hmac_key_file: Some(key_path),
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        assert!(dir.path().join("roci-meta.snapshot").exists());

        // Now open without HMAC — the log's HMAC header is "Incompatible"
        // with Plain. Snapshot and log should both be discarded (lines 397-400).
        let cfg2 = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg2).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
    }

    #[test]
    fn noheader_with_hmac_key_discards_snapshot() {
        // Write a plain log (no HMAC) then open with HMAC key + snapshot.
        // The legacy log triggers NoHeader+hmac_key.is_some() path
        // (lines 405-414).
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);

        // Also create a dummy snapshot file to test cleanup
        let snap_path = dir.path().join("roci-meta.snapshot");
        std::fs::write(&snap_path, b"dummy-snapshot").unwrap();

        let key_path = make_key(dir.path());
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            hmac_key_file: Some(key_path),
            ..Default::default()
        };
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        // Everything is discarded because the existing log has no header
        // and an HMAC key is configured.
        assert_eq!(s2.resolve_tag("r", "v1"), None);
        assert!(!snap_path.exists(), "snapshot should be removed");
    }

    #[test]
    fn legacy_replay_path_no_hmac() {
        // Legacy log without header, no HMAC key → replay_legacy (line 416).
        let mut bytes = Vec::new();
        let p = serialize_op(&put("r", "sha256:aa", Some("v1")));
        let crc = crc32c::crc32c(&p);
        bytes.extend_from_slice(&(p.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&p);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("roci-meta.log"), &bytes).unwrap();

        let s = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
    }

    // ---- Snapshot base+delta merge for ALL query methods ----------------
    // These tests create state → snapshot → delta modifications, then
    // exercise every MetadataStore method to cover the base+delta merge
    // paths (lines 238-310, 560, 578-584, 612-689, 708-717, 742, 777,
    // 801-817, 833-840, 863, 880-892, 899).

    #[test]
    fn snapshot_base_delta_tags_and_media_types() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        // Base: two tags and their media types.
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(put("r2", "sha256:cc", Some("latest"))).unwrap();
        s.maintain().unwrap();

        // Delta: add a tag, delete one from base.
        s.apply(put("r", "sha256:dd", Some("v3"))).unwrap();
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();

        // resolve_tag: v1 deleted from base, v2 from base, v3 from delta.
        assert_eq!(s.resolve_tag("r", "v1"), None);
        assert_eq!(
            s.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:dd")
        );
        // resolve_tag miss in base (line 560)
        assert_eq!(s.resolve_tag("r", "v_missing"), None);

        // manifest_media_type: deleted from base, present in base, delta.
        assert_eq!(s.manifest_media_type("r", "sha256:aa"), None);
        assert!(s.manifest_media_type("r", "sha256:bb").is_some()); // base
        assert!(s.manifest_media_type("r", "sha256:dd").is_some()); // delta
                                                                    // Missing entirely from both.
        assert_eq!(s.manifest_media_type("r", "sha256:zz"), None);

        // tags_page: merged from base+delta, tombstones excluded.
        let page = s.tags_page("r", None, usize::MAX).unwrap();
        assert_eq!(page.items, vec!["v2".to_string(), "v3".to_string()]);

        // tags_page paging across base+delta.
        let p1 = s.tags_page("r", None, 1).unwrap();
        assert_eq!(p1.items, vec!["v2".to_string()]);
        assert!(p1.more);
        let p2 = s.tags_page("r", Some("v2"), 1).unwrap();
        assert_eq!(p2.items, vec!["v3".to_string()]);
        assert!(!p2.more);

        // tags_page for repo with nothing left after tombstones.
        // Delete the only tag in r2 from base.
        s.apply(MetaOp::DeleteManifest {
            repo: "r2".into(),
            digest: "sha256:cc".into(),
        })
        .unwrap();
        assert!(s.tags_page("r2", None, usize::MAX).is_none());

        // tags_page for missing repo (both base and delta have nothing).
        assert!(s.tags_page("no_repo", None, usize::MAX).is_none());

        // tags_snapshot merges base+delta.
        let snap = s.tags_snapshot("r");
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|(t, _, _)| t == "v2"));
        assert!(snap.iter().any(|(t, _, _)| t == "v3"));

        // repos: merges base+delta, excludes repos with only tombstoned entries.
        let repos = s.repos();
        assert!(repos.contains(&"r".to_string()));
        assert!(!repos.contains(&"r2".to_string()));

        // manifests: merges base (not tombstoned) + delta.
        let mf = s.manifests("r");
        assert!(!mf.contains(&"sha256:aa".to_string()), "aa is tombstoned");
        assert!(mf.contains(&"sha256:bb".to_string()), "bb from base");
        assert!(mf.contains(&"sha256:dd".to_string()), "dd from delta");
    }

    #[test]
    fn snapshot_base_delta_referrers() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        // Base referrers.
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r1".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:r1"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r2".into(),
            descriptor: br#"{"artifactType":"sbom","digest":"sha256:r2"}"#.to_vec(),
        })
        .unwrap();
        // Also add a second subject for referrers_snapshot coverage.
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s2".into(),
            referrer: "sha256:r3".into(),
            descriptor: br#"{"digest":"sha256:r3"}"#.to_vec(),
        })
        .unwrap();
        s.maintain().unwrap();

        // Delta: delete r1 from base, add r4 in delta.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:r1".into(),
        })
        .unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r4".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:r4"}"#.to_vec(),
        })
        .unwrap();

        // referrers_page: base minus tombstones + delta.
        let page = s
            .referrers_page("r", "sha256:s", None, None, usize::MAX)
            .unwrap();
        let digests: Vec<_> = page.items.iter().map(|(d, _)| d.as_str()).collect();
        assert!(!digests.contains(&"sha256:r1"), "r1 is tombstoned");
        assert!(digests.contains(&"sha256:r2"), "r2 from base");
        assert!(digests.contains(&"sha256:r4"), "r4 from delta");

        // referrers_page: empty after all deleted from a subject.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:r3".into(),
        })
        .unwrap();
        assert!(s
            .referrers_page("r", "sha256:s2", None, None, usize::MAX)
            .is_none());

        // referrers_page: no referrers at all for a subject.
        assert!(s
            .referrers_page("r", "sha256:none", None, None, usize::MAX)
            .is_none());

        // has_referrer: from base, from delta, tombstoned.
        assert!(!s.has_referrer("r", "sha256:s", "sha256:r1"), "tombstoned");
        assert!(s.has_referrer("r", "sha256:s", "sha256:r2"), "from base");
        assert!(s.has_referrer("r", "sha256:s", "sha256:r4"), "from delta");

        // referrers_snapshot: covers base+delta per subject.
        let rs = s.referrers_snapshot("r");
        // Subject s should have r2 + r4; s2 should have nothing.
        let s_entry = rs.iter().find(|(sub, _)| sub == "sha256:s");
        assert!(s_entry.is_some());
        let (_, refs) = s_entry.unwrap();
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn snapshot_base_delta_backrefs() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        // Base backrefs.
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:m1".into(),
            blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:m2".into(),
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
        s.maintain().unwrap();

        // Delta: delete m1 from base, add m3 referencing b1.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:m1".into(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:m3".into(),
            blobs: vec!["sha256:b1".into(), "sha256:b3".into()],
        })
        .unwrap();

        // backrefs: b1 should have m2 (base, not tombstoned) + m3 (delta).
        let br = s.backrefs("r", "sha256:b1");
        assert!(!br.contains(&"sha256:m1".to_string()), "m1 is tombstoned");
        assert!(br.contains(&"sha256:m2".to_string()), "m2 from base");
        assert!(br.contains(&"sha256:m3".to_string()), "m3 from delta");

        // b2 had m1 as only backref → m1 tombstoned → empty.
        assert!(s.backrefs("r", "sha256:b2").is_empty());

        // b3 is delta-only.
        assert_eq!(s.backrefs("r", "sha256:b3"), vec!["sha256:m3".to_string()]);
    }

    #[test]
    fn snapshot_base_delta_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        // Base checksums.
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:c1".into(),
            crc32c: 0x1111,
            size: 100,
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:c2".into(),
            crc32c: 0x2222,
            size: 200,
        })
        .unwrap();
        s.maintain().unwrap();

        // Delta: delete c1 via DeleteBlob, add c3.
        s.apply(MetaOp::DeleteBlob {
            repo: "r".into(),
            digest: "sha256:c1".into(),
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:c3".into(),
            crc32c: 0x3333,
            size: 300,
        })
        .unwrap();

        // checksum: c1 deleted, c2 from base, c3 from delta.
        assert_eq!(s.checksum("r", "sha256:c1"), None);
        assert_eq!(
            s.checksum("r", "sha256:c2"),
            Some(BlobChecksum {
                crc32c: 0x2222,
                size: 200
            })
        );
        assert_eq!(
            s.checksum("r", "sha256:c3"),
            Some(BlobChecksum {
                crc32c: 0x3333,
                size: 300
            })
        );
        // Missing entirely.
        assert_eq!(s.checksum("r", "sha256:c99"), None);
    }

    #[test]
    fn snapshot_materialize_full_round_trip() {
        // Build a snapshot base with everything, apply deltas including
        // tombstones, then compact (which calls materialize) and verify
        // the new compacted state is correct.
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        // Build base state.
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:aa".into(),
            referrer: "sha256:ref1".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:ref1"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:aa".into(),
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xABCD,
            size: 512,
        })
        .unwrap();
        s.maintain().unwrap(); // snapshot1

        // Delta: delete aa and ref1 (tags, referrers, backrefs tombstoned), add new.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();
        // Delete ref1 to tombstone it as a referrer of aa.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:ref1".into(),
        })
        .unwrap();
        s.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:cc".into(),
            referrer: "sha256:ref2".into(),
            descriptor: br#"{"digest":"sha256:ref2"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:cc".into(),
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b2".into(),
            crc32c: 0x1234,
            size: 64,
        })
        .unwrap();

        // Compact again — this calls materialize(base) on the delta.
        s.maintain().unwrap();

        // Verify final state after re-compaction.
        assert_eq!(s.resolve_tag("r", "v1"), None);
        assert_eq!(
            s.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
        assert!(!s.has_referrer("r", "sha256:aa", "sha256:ref1"));
        assert!(s.has_referrer("r", "sha256:cc", "sha256:ref2"));
        assert_eq!(s.backrefs("r", "sha256:b1"), vec!["sha256:cc".to_string()]);
        // Reopen and verify again.
        drop(s);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
        assert_eq!(
            s2.checksum("r", "sha256:b2"),
            Some(BlobChecksum {
                crc32c: 0x1234,
                size: 64
            })
        );
    }

    #[test]
    fn snapshot_repos_from_base_with_referrers() {
        // Cover line 809-817: repos() iterates base referrers to find
        // repos with live referrer entries.
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        // Put only a referrer (no PutManifest with media_type for this repo).
        s.apply(MetaOp::PutReferrer {
            repo: "ref-only".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r1".into(),
            descriptor: br#"{"digest":"sha256:r1"}"#.to_vec(),
        })
        .unwrap();
        s.maintain().unwrap();

        // repos() should find "ref-only" from the base referrers.
        let repos = s.repos();
        assert!(
            repos.contains(&"ref-only".to_string()),
            "repos should include ref-only from base referrers"
        );

        // Now delete the referrer → repo should disappear.
        s.apply(MetaOp::DeleteManifest {
            repo: "ref-only".into(),
            digest: "sha256:r1".into(),
        })
        .unwrap();
        let repos2 = s.repos();
        assert!(
            !repos2.contains(&"ref-only".to_string()),
            "tombstoned referrer should hide the repo"
        );
    }

    // ---- DeleteBlob round-trip through log replay ----------------------

    #[test]
    fn delete_blob_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xAAAA,
            size: 128,
        })
        .unwrap();
        assert!(s.checksum("r", "sha256:b1").is_some());
        s.apply(MetaOp::DeleteBlob {
            repo: "r".into(),
            digest: "sha256:b1".into(),
        })
        .unwrap();
        assert!(s.checksum("r", "sha256:b1").is_none());
        // Replay verifies deserialization of DeleteBlob.
        drop(s);
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert!(s2.checksum("r", "sha256:b1").is_none());
    }

    // ---- apply_relaxed covers relaxed-commit path ----------------------

    #[test]
    fn apply_relaxed_does_not_sync() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply_relaxed(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xBBBB,
            size: 99,
        })
        .unwrap();
        assert_eq!(
            s.checksum("r", "sha256:b1"),
            Some(BlobChecksum {
                crc32c: 0xBBBB,
                size: 99
            })
        );
    }
}
