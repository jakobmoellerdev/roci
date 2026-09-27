//! Fast-restart stamp: skip the CAS walk on startup when a valid stamp exists.
//! The stamp is consumed before applying so a crash forces a full walk.

use super::super::FsStorage;
use crate::metadata::wal_hmac::HmacKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const STAMP_FILE: &str = ".roci-fast-restart";
const FORMAT_VERSION: u32 = 1;
const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stamp payload (before integrity wrapping).
#[derive(Debug, Serialize, Deserialize)]
struct Stamp {
    format_version: u32,
    binary_version: String,
    /// SHA-256 hex of config (minus `fast_restart` and `root`).
    config_hash: String,
    metadata_generation: u64,
    metadata_log_len: u64,
    presence: Vec<(String, String)>,
    dedupe: Vec<(String, String)>,
    quota_per_repo: Vec<(String, u64)>,
    quota_sessions: usize,
    /// GC candidates (restored with a fresh timestamp).
    gc_candidates: Vec<(String, String)>,
    gc_roots: Vec<(String, String)>,
    gc_unsafe_repos: Vec<String>,
}

/// Wire: `[4-byte LE body_len][body][32-byte HMAC-SHA256 or CRC32C]`.
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

/// Hash config fields that affect derived in-memory state.
fn config_hash(config: &roci_config::StorageConfig) -> String {
    let mut normalized = config.clone();
    normalized.fast_restart = false;
    let text = toml::to_string(&normalized).unwrap_or_default();
    let hash = Sha256::digest(text.as_bytes());
    hex::encode(hash)
}

fn stamp_path(root: &Path) -> PathBuf {
    root.join(STAMP_FILE)
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(path);
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    let d = std::fs::File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

/// Consume the stamp so a crash forces a full walk.
fn consume_stamp(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)?;
    let dir = path.parent().unwrap_or(path);
    let d = std::fs::File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

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
    /// Read, validate and consume the stamp; `Err` falls back to full walk.
    pub(crate) fn try_consume_stamp(
        root: &Path,
        config: &roci_config::StorageConfig,
        hmac_key: Option<&HmacKey>,
        metadata_generation: u64,
        metadata_log_len: u64,
    ) -> Result<ValidStamp, StampReject> {
        let path = stamp_path(root);

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StampReject::Absent),
            Err(e) => return Err(StampReject::Io(e)),
        };

        if let Err(e) = consume_stamp(&path) {
            return Err(StampReject::Consumed(e));
        }

        let body = unwrap(&data, hmac_key).map_err(StampReject::Integrity)?;

        let stamp: Stamp =
            serde_json::from_slice(body).map_err(|e| StampReject::Parse(e.to_string()))?;

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

    /// Write the stamp atomically on graceful shutdown.
    pub(crate) fn write_fast_restart_stamp(&self) -> io::Result<()> {
        let hmac_key = self
            .config
            .metadata
            .hmac_key_file
            .as_ref()
            .map(|p| HmacKey::load(p))
            .transpose()?;

        // Re-derive presence from disk (cuckoo filter is not enumerable).
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
            quota_sessions: self.quota.sessions(),
            gc_candidates: self.gc.candidate_keys(),
            gc_roots: self.gc.root_keys(),
            gc_unsafe_repos: self.gc.unsafe_repo_names(),
        };

        let body = serde_json::to_vec(&stamp).map_err(io::Error::other)?;
        let wire = wrap(&body, hmac_key.as_ref());
        write_atomic(&stamp_path(&self.root), &wire)
    }

    /// Seed in-memory state from a validated stamp.
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
        // Stamp includes the GC consistency-check result.
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
