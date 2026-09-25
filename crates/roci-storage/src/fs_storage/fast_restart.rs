//! zot-style `fastRestart`: write a stamp file on graceful shutdown, consume
//! it at startup to skip the CAS walk (blob-presence, dedupe, quota, GC
//! candidate seeding). Any mismatch (binary version, config hash, metadata
//! identity, integrity failure) falls back to the full walk — never data loss.
//!
//! The stamp is **consumed** (removed + dir fsync) before the stored state is
//! applied, so a crash between read and completion forces a full walk on the
//! next start (identical to zot's model). Out-of-band edits to the layout
//! while roci is stopped are not observed on a fast restart — the same caveat
//! as zot; the presence filter is a *definite-miss* filter only for data roci
//! itself wrote.
//!
//! **S3 backend:** not applicable. S3's recovery lists remote objects
//! asynchronously; there is no local CAS walk to skip.

use super::super::FsStorage;
use crate::metadata::wal_hmac::HmacKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Name of the stamp file under the store root.
const STAMP_FILE: &str = ".roci-fast-restart";

/// Current stamp format version. Bump when the schema changes.
const FORMAT_VERSION: u32 = 1;

/// Build-time binary version baked into the stamp.
const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── stamp schema ──────────────────────────────────────────────────────

/// The fast-restart stamp file payload (before integrity wrapping).
#[derive(Debug, Serialize, Deserialize)]
struct Stamp {
    /// Format version (for forward compatibility).
    format_version: u32,
    /// `CARGO_PKG_VERSION` of the binary that wrote the stamp.
    binary_version: String,
    /// SHA-256 hex of the TOML-serialised storage-relevant config (the
    /// `StorageConfig` struct minus the `fast_restart` flag itself, since
    /// toggling the flag shouldn't invalidate the stamp).
    config_hash: String,
    /// Metadata WAL generation (snapshot identity).
    metadata_generation: u64,
    /// Size in bytes of the metadata WAL file at the time the stamp was
    /// written. On open, the replayed log must have the same size; any
    /// in-between mutation (or compaction) invalidates the stamp.
    metadata_log_len: u64,
    /// `(repo, digest)` entries for the blob-presence filter.
    presence: Vec<(String, String)>,
    /// `(digest, repo)` entries for the dedupe index.
    dedupe: Vec<(String, String)>,
    /// Per-repo quota byte usage.
    quota_per_repo: Vec<(String, u64)>,
    /// Registry-wide total byte usage.
    quota_total: u64,
    /// Upload sessions counted at shutdown.
    quota_sessions: usize,
    /// GC candidates: `(repo, digest)`. Restored with a fresh timestamp
    /// (worst case: delays collection by one grace period — never data loss).
    gc_candidates: Vec<(String, String)>,
    /// GC root manifests: `(repo, digest)`.
    gc_roots: Vec<(String, String)>,
    /// Repos marked GC-unsafe.
    gc_unsafe_repos: Vec<String>,
}

// ── integrity wrapper ────────────────────────────────────────────────

/// Wire format: `[4-byte LE body_len][body][32-byte integrity]`.
/// Integrity = HMAC-SHA256 when a key is configured, else CRC32C zero-padded.
fn wrap(body: &[u8], key: Option<&HmacKey>) -> Vec<u8> {
    let len = (body.len() as u32).to_le_bytes();
    let integrity = match key {
        Some(k) => k.tag(body),
        None => {
            let crc = crc32c::crc32c(body);
            let mut buf = [0u8; 32];
            buf[..4].copy_from_slice(&crc.to_le_bytes());
            buf
        }
    };
    let mut out = Vec::with_capacity(4 + body.len() + 32);
    out.extend_from_slice(&len);
    out.extend_from_slice(body);
    out.extend_from_slice(&integrity);
    out
}

/// Unwrap and verify the integrity. Returns the body on success.
fn unwrap<'a>(data: &'a [u8], key: Option<&HmacKey>) -> Result<&'a [u8], &'static str> {
    if data.len() < 4 + 32 {
        return Err("stamp too small");
    }
    let body_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if data.len() != 4 + body_len + 32 {
        return Err("stamp length mismatch");
    }
    let body = &data[4..4 + body_len];
    let stored: [u8; 32] = data[4 + body_len..].try_into().unwrap();
    match key {
        Some(k) => {
            if !k.verify(body, &stored) {
                return Err("HMAC verification failed");
            }
        }
        None => {
            let crc = crc32c::crc32c(body);
            let mut expected = [0u8; 32];
            expected[..4].copy_from_slice(&crc.to_le_bytes());
            if stored != expected {
                return Err("CRC32C verification failed");
            }
        }
    }
    Ok(body)
}

// ── config hash ───────────────────────────────────────────────────────

/// Hash the storage-relevant config fields (everything except `fast_restart`
/// and `root`, which don't affect derived in-memory state).
fn config_hash(config: &roci_config::StorageConfig) -> String {
    // We hash the TOML serialization of the config with fast_restart forced
    // false so toggling it alone doesn't invalidate the stamp.
    let mut normalized = config.clone();
    normalized.fast_restart = false;
    // Root path doesn't affect derived state (presence/dedupe/quota are
    // relative); however, changing root means a different CAS, so include it.
    let text = toml::to_string(&normalized).unwrap_or_default();
    let hash = Sha256::digest(text.as_bytes());
    hex::encode(hash)
}

// ── public API ────────────────────────────────────────────────────────

fn stamp_path(root: &Path) -> PathBuf {
    root.join(STAMP_FILE)
}

/// Atomic write: temp + fsync + rename + dir fsync.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(path);
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Dir fsync so the rename is durable.
    let d = std::fs::File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

/// Consume (remove + dir fsync) the stamp file so a crash in this run forces
/// a full walk next time.
fn consume_stamp(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)?;
    let dir = path.parent().unwrap_or(path);
    let d = std::fs::File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

/// Why a fast-restart stamp was rejected (logged at info/warn).
#[derive(Debug)]
pub(crate) enum StampReject {
    Absent,
    Io(io::Error),
    Integrity(&'static str),
    FormatVersion { got: u32, expected: u32 },
    BinaryVersion { got: String, expected: String },
    ConfigMismatch,
    Parse(String),
    Consumed(io::Error),
}

impl std::fmt::Display for StampReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => write!(f, "no stamp file"),
            Self::Io(e) => write!(f, "reading stamp: {e}"),
            Self::Integrity(reason) => write!(f, "integrity: {reason}"),
            Self::FormatVersion { got, expected } => {
                write!(f, "format version {got}, expected {expected}")
            }
            Self::BinaryVersion { got, expected } => {
                write!(f, "binary version {got}, expected {expected}")
            }
            Self::ConfigMismatch => write!(f, "config hash mismatch"),
            Self::Parse(e) => write!(f, "parsing stamp: {e}"),
            Self::Consumed(e) => write!(f, "consuming stamp: {e}"),
        }
    }
}

/// A validated stamp ready to be applied.
pub(crate) struct ValidStamp {
    pub(crate) presence: Vec<(String, String)>,
    pub(crate) dedupe: Vec<(String, String)>,
    pub(crate) quota_per_repo: Vec<(String, u64)>,
    pub(crate) quota_sessions: usize,
    pub(crate) gc_candidates: Vec<(String, String)>,
    pub(crate) gc_roots: Vec<(String, String)>,
    pub(crate) gc_unsafe_repos: Vec<String>,
}

impl FsStorage {
    /// Attempt to read, validate and consume the fast-restart stamp. On
    /// success, returns the validated stamp data to apply. On any failure,
    /// returns the reason (the caller falls back to the full CAS walk).
    pub(crate) fn try_consume_stamp(
        root: &Path,
        config: &roci_config::StorageConfig,
        hmac_key: Option<&HmacKey>,
        metadata_generation: u64,
        metadata_log_len: u64,
    ) -> Result<ValidStamp, StampReject> {
        let path = stamp_path(root);

        // 1. Read the stamp file.
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StampReject::Absent),
            Err(e) => return Err(StampReject::Io(e)),
        };

        // 2. IMMEDIATELY consume (remove + dir fsync) so a crash from here on
        //    forces a full walk next time.
        if let Err(e) = consume_stamp(&path) {
            return Err(StampReject::Consumed(e));
        }

        // 3. Verify integrity.
        let body = unwrap(&data, hmac_key).map_err(StampReject::Integrity)?;

        // 4. Deserialize.
        let stamp: Stamp =
            serde_json::from_slice(body).map_err(|e| StampReject::Parse(e.to_string()))?;

        // 5. Validate fields.
        if stamp.format_version != FORMAT_VERSION {
            return Err(StampReject::FormatVersion {
                got: stamp.format_version,
                expected: FORMAT_VERSION,
            });
        }
        if stamp.binary_version != BINARY_VERSION {
            return Err(StampReject::BinaryVersion {
                got: stamp.binary_version,
                expected: BINARY_VERSION.to_string(),
            });
        }
        if stamp.config_hash != config_hash(config) {
            return Err(StampReject::ConfigMismatch);
        }
        // Metadata identity: the WAL generation and file length must match.
        // A compaction or any append between runs changes one or both.
        if stamp.metadata_generation != metadata_generation
            || stamp.metadata_log_len != metadata_log_len
        {
            return Err(StampReject::ConfigMismatch);
        }

        Ok(ValidStamp {
            presence: stamp.presence,
            dedupe: stamp.dedupe,
            quota_per_repo: stamp.quota_per_repo,
            quota_sessions: stamp.quota_sessions,
            gc_candidates: stamp.gc_candidates,
            gc_roots: stamp.gc_roots,
            gc_unsafe_repos: stamp.gc_unsafe_repos,
        })
    }

    /// Write the fast-restart stamp file atomically. Called on graceful
    /// shutdown.
    pub(crate) fn write_fast_restart_stamp(&self) -> io::Result<()> {
        let hmac_key = self
            .config
            .metadata
            .hmac_key_file
            .as_ref()
            .map(|p| HmacKey::load(p))
            .transpose()?;

        // Walk the CAS to collect (repo, digest) pairs — the cuckoo filter
        // does not support enumeration, so we re-derive the set from disk.
        // This walk happens after the server has stopped accepting requests,
        // so it is uncontended.
        let mut presence = Vec::new();
        crate::layout::for_each_cas_blob(&self.root, |repo, digest, _entry| {
            presence.push((repo.to_string(), digest.as_string()));
        });

        let stamp = Stamp {
            format_version: FORMAT_VERSION,
            binary_version: BINARY_VERSION.to_string(),
            config_hash: config_hash(&self.config),
            metadata_generation: self.meta.generation(),
            metadata_log_len: self.meta.log_len(),
            presence,
            dedupe: self.dedupe.entries(),
            quota_per_repo: self.quota.per_repo_bytes(),
            quota_total: self.quota.total_bytes(),
            quota_sessions: self.quota.sessions(),
            gc_candidates: self.gc.candidate_keys(),
            gc_roots: self.gc.root_keys(),
            gc_unsafe_repos: self.gc.unsafe_repo_names(),
        };

        let body = serde_json::to_vec(&stamp).map_err(io::Error::other)?;
        let wire = wrap(&body, hmac_key.as_ref());
        write_atomic(&stamp_path(&self.root), &wire)
    }

    /// Apply a validated stamp: seed presence, dedupe, quota and GC state.
    pub(crate) fn apply_stamp(&self, stamp: ValidStamp) {
        for (repo, digest) in &stamp.presence {
            self.presence.insert(repo, digest);
        }
        for (digest, repo) in &stamp.dedupe {
            self.dedupe.insert(repo, digest);
        }
        for (repo, bytes) in &stamp.quota_per_repo {
            self.quota.seed(repo, *bytes);
        }
        self.quota.seed_sessions(stamp.quota_sessions);
        let now = Instant::now();
        for (repo, digest) in &stamp.gc_candidates {
            self.gc.mark_at(repo, digest, now);
        }
        for (repo, digest) in &stamp.gc_roots {
            self.gc.add_root(repo, digest);
        }
        for repo in &stamp.gc_unsafe_repos {
            self.gc.mark_unsafe(repo);
        }
        // Mark GC ready immediately — the stamp carries the consistency-check
        // result, so the background GC task can skip the check and start
        // sweeping right away.
        if self.gc.enabled() {
            self.gc.set_ready();
        }
    }
}

// ── unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip_crc() {
        let body = b"hello fast restart";
        let wire = wrap(body, None);
        let got = unwrap(&wire, None).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn wrap_unwrap_roundtrip_hmac() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, [0xABu8; 64]).unwrap();
        let key = HmacKey::load(&key_path).unwrap();

        let body = b"hello fast restart hmac";
        let wire = wrap(body, Some(&key));
        let got = unwrap(&wire, Some(&key)).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn crc_detects_tampering() {
        let body = b"payload";
        let mut wire = wrap(body, None);
        wire[6] ^= 0xFF; // flip a byte in the body
        assert!(unwrap(&wire, None).is_err());
    }

    #[test]
    fn hmac_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, [0xABu8; 64]).unwrap();
        let key = HmacKey::load(&key_path).unwrap();

        let body = b"payload";
        let mut wire = wrap(body, Some(&key));
        wire[6] ^= 0xFF;
        assert!(unwrap(&wire, Some(&key)).is_err());
    }

    #[test]
    fn wrong_hmac_key_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let k1_path = dir.path().join("k1");
        std::fs::write(&k1_path, [0xAAu8; 64]).unwrap();
        let k1 = HmacKey::load(&k1_path).unwrap();
        let k2_path = dir.path().join("k2");
        std::fs::write(&k2_path, [0xBBu8; 64]).unwrap();
        let k2 = HmacKey::load(&k2_path).unwrap();

        let wire = wrap(b"data", Some(&k1));
        assert!(unwrap(&wire, Some(&k2)).is_err());
    }

    #[test]
    fn config_hash_excludes_fast_restart_flag() {
        let c1 = roci_config::StorageConfig {
            fast_restart: false,
            ..Default::default()
        };
        let c2 = roci_config::StorageConfig {
            fast_restart: true,
            ..Default::default()
        };
        assert_eq!(config_hash(&c1), config_hash(&c2));
    }

    #[test]
    fn config_hash_changes_on_field_change() {
        let c1 = roci_config::StorageConfig::default();
        let mut c2 = roci_config::StorageConfig::default();
        c2.dedupe = !c2.dedupe;
        assert_ne!(config_hash(&c1), config_hash(&c2));
    }

    #[test]
    fn stamp_serde_roundtrip() {
        let stamp = Stamp {
            format_version: FORMAT_VERSION,
            binary_version: BINARY_VERSION.to_string(),
            config_hash: "abc123".to_string(),
            metadata_generation: 5,
            metadata_log_len: 4096,
            presence: vec![("r".into(), "sha256:aa".into())],
            dedupe: vec![("sha256:aa".into(), "r".into())],
            quota_per_repo: vec![("r".into(), 1024)],
            quota_total: 1024,
            quota_sessions: 3,
            gc_candidates: vec![("r".into(), "sha256:bb".into())],
            gc_roots: vec![("r".into(), "sha256:cc".into())],
            gc_unsafe_repos: vec!["broken".into()],
        };
        let json = serde_json::to_vec(&stamp).unwrap();
        let back: Stamp = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.format_version, stamp.format_version);
        assert_eq!(back.presence, stamp.presence);
        assert_eq!(back.gc_candidates, stamp.gc_candidates);
    }
}
