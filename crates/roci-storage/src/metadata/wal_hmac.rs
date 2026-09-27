//! WAL + snapshot HMAC authentication (SECURITY §Storage boundary).
//! CRC detects torn tails; HMAC authenticates against compromised storage.
//! Key ≥ 32 bytes; framing/key mismatch → log moved aside, rebuilt from layout.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// A loaded, validated HMAC key (≥ 32 bytes).
#[derive(Clone, Debug)]
pub(crate) struct HmacKey(Vec<u8>);

impl HmacKey {
    /// Load and validate the HMAC key from `path`. Rejects keys < 32 bytes.
    pub(crate) fn load(path: &Path) -> io::Result<Self> {
        let raw = std::fs::read(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "storage.metadata.hmac_key_file: cannot read {}: {e}",
                    path.display()
                ),
            )
        })?;
        if raw.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "storage.metadata.hmac_key_file: key in {} is {} bytes, minimum is 32",
                    path.display(),
                    raw.len()
                ),
            ));
        }
        Ok(Self(raw))
    }

    /// Compute the HMAC-SHA256 tag.
    pub(crate) fn tag(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length ≥ 1");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify an HMAC-SHA256 tag.
    pub(crate) fn verify(&self, data: &[u8], tag: &[u8; 32]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length ≥ 1");
        mac.update(data);
        mac.verify_slice(tag).is_ok()
    }
}

/// The framing mode declared by the header record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FramingMode {
    Plain,
    HmacSha256,
}

const HEADER_MAGIC: &[u8] = b"roci-wal\x00";

/// Encode a WAL header declaring the framing mode.
pub(crate) fn encode_header(mode: FramingMode) -> Vec<u8> {
    let mode_byte = match mode {
        FramingMode::Plain => 0u8,
        FramingMode::HmacSha256 => 1u8,
    };
    let mut payload = Vec::with_capacity(HEADER_MAGIC.len() + 1);
    payload.extend_from_slice(HEADER_MAGIC);
    payload.push(mode_byte);
    payload
}

/// Decode a WAL header from a first-record payload.
pub(crate) fn decode_header(payload: &[u8]) -> Option<FramingMode> {
    if payload.len() < HEADER_MAGIC.len() + 1 {
        return None;
    }
    if &payload[..HEADER_MAGIC.len()] != HEADER_MAGIC {
        return None;
    }
    match payload[HEADER_MAGIC.len()] {
        0 => Some(FramingMode::Plain),
        1 => Some(FramingMode::HmacSha256),
        _ => None,
    }
}

/// Move a log aside when framing/key doesn't match.
pub(crate) fn move_aside(log_path: &Path) -> io::Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let aside = log_path.with_extension(format!("log.untrusted-{ts}"));
    std::fs::rename(log_path, &aside)?;
    Ok(aside)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_rejects_short() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("short.key");
        std::fs::write(&p, [0u8; 31]).unwrap();
        let err = HmacKey::load(&p).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("31 bytes"), "msg: {}", err);
    }

    #[test]
    fn key_accepts_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok.key");
        std::fs::write(&p, [0xABu8; 32]).unwrap();
        let key = HmacKey::load(&p).unwrap();
        let tag = key.tag(b"hello");
        assert!(key.verify(b"hello", &tag));
        assert!(!key.verify(b"world", &tag));
    }

    #[test]
    fn header_roundtrip() {
        for mode in [FramingMode::Plain, FramingMode::HmacSha256] {
            let payload = encode_header(mode);
            assert_eq!(decode_header(&payload), Some(mode));
        }
        assert_eq!(decode_header(b"garbage"), None);
        assert_eq!(decode_header(b"roci-wal\x00\x09"), None); // unknown mode
    }

    #[test]
    fn move_aside_renames() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("roci-meta.log");
        std::fs::write(&p, b"data").unwrap();
        let aside = move_aside(&p).unwrap();
        assert!(!p.exists());
        assert!(aside.exists());
        assert_eq!(std::fs::read(&aside).unwrap(), b"data");
    }

    #[test]
    fn key_load_missing_file() {
        let err = HmacKey::load(Path::new("/nonexistent/path/to/hmac.key")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("hmac_key_file"), "msg: {}", err);
    }
}
