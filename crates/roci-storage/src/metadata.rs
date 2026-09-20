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

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
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
    /// All tags in a repo, sorted lexically.
    fn list_tags(&self, repo: &str) -> Vec<String>;
    /// The referrer descriptors recorded for a subject digest, as raw JSON.
    fn referrers(&self, repo: &str, subject: &str) -> Vec<Vec<u8>>;
    /// Apply and durably record a mutation.
    fn apply(&self, op: MetaOp) -> io::Result<()>;
}

/// In-RAM metadata maps mirrored to an append-only CRC32C-framed log.
pub struct LogMetadataStore {
    inner: Mutex<State>,
    log_path: PathBuf,
}

/// A repo-scoped map key: `(repo, name)` so repositories stay isolated.
type RepoKey = (String, String);
/// One referrer: `(referrer_digest, descriptor_bytes)`; the digest de-dups.
type Referrer = (String, Vec<u8>);

/// The mutable in-RAM state. Keyed by `(repo, key)` so repos stay isolated.
#[derive(Default)]
struct State {
    /// `(repo, tag) → (digest, media_type)` — media type stored alongside so a
    /// tag resolution needs no second lookup and carries no fallback default.
    tags: HashMap<RepoKey, (String, String)>,
    /// `(repo, digest) → media_type`.
    media_types: HashMap<RepoKey, String>,
    /// `(repo, subject) → [(referrer_digest, descriptor_bytes)]`. The referrer
    /// digest keys de-dup so a re-push replaces rather than appends.
    referrers: HashMap<RepoKey, Vec<Referrer>>,
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
                    state.tags.insert(
                        (repo.clone(), tag.clone()),
                        (digest.clone(), media_type.clone()),
                    );
                }
            }
            MetaOp::DeleteManifest { repo, digest } => {
                state.media_types.remove(&(repo.clone(), digest.clone()));
                // Drop every tag pointing at this digest.
                state
                    .tags
                    .retain(|(r, _), (d, _)| !(r == repo && d == digest));
                // Drop the deleted manifest as a referrer of any subject.
                for refs in state.referrers.values_mut() {
                    refs.retain(|(rd, _)| rd != digest);
                }
            }
            MetaOp::PutReferrer {
                repo,
                subject,
                referrer,
                descriptor,
            } => {
                let entry = state
                    .referrers
                    .entry((repo.clone(), subject.clone()))
                    .or_default();
                // De-dup by referrer digest: replace an existing descriptor.
                if let Some(slot) = entry.iter_mut().find(|(rd, _)| rd == referrer) {
                    slot.1 = descriptor.clone();
                } else {
                    entry.push((referrer.clone(), descriptor.clone()));
                }
            }
        }
    }
}

impl MetadataStore for LogMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .tags
            .get(&(repo.to_string(), tag.to_string()))
            .cloned()
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .media_types
            .get(&(repo.to_string(), digest.to_string()))
            .cloned()
    }

    fn list_tags(&self, repo: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let mut tags: Vec<String> = state
            .tags
            .keys()
            .filter(|(r, _)| r == repo)
            .map(|(_, t)| t.clone())
            .collect();
        tags.sort();
        tags
    }

    fn referrers(&self, repo: &str, subject: &str) -> Vec<Vec<u8>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .referrers
            .get(&(repo.to_string(), subject.to_string()))
            .map(|v| v.iter().map(|(_, d)| d.clone()).collect())
            .unwrap_or_default()
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        let record = encode(&op);
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        // Open the log lazily on first mutation (append + create).
        if state.log.is_none() {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)?;
            state.log = Some(f);
        }
        let log = state.log.as_mut().expect("log opened above");
        log.write_all(&record)?;
        log.flush()?;
        Self::apply_in_ram(&mut state, &op);
        Ok(())
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
        assert_eq!(s.list_tags("r"), vec!["v1".to_string(), "v2".to_string()]);
        assert!(s.list_tags("other").is_empty());
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
        assert_eq!(s.referrers("r", "sha256:aa").len(), 1);
        // Deleting the referrer manifest drops it from the subject's set.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:rr".into(),
        })
        .unwrap();
        assert!(s.referrers("r", "sha256:aa").is_empty());
        // Deleting the subject manifest drops both its tags and media type.
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();
        assert!(s.list_tags("r").is_empty());
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
        let refs = s.referrers("r", "sha256:s");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], br#"{"v":2}"#);
        assert!(s.referrers("r", "sha256:none").is_empty());
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
        assert_eq!(s2.referrers("r", "sha256:aa").len(), 1);
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
}
