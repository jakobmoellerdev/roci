//! rkyv zero-copy mmap snapshot for O(1) cold start (ARCHITECTURE §Hyper-
//! optimized OCI-layout ↔ index interaction, RESEARCH §9.4).

use super::wal_hmac::HmacKey;
use rkyv::{Archive, Deserialize, Serialize};
use std::io::{self, Write};
use std::path::Path;

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct TagEntry {
    pub(crate) tag: String,
    pub(crate) digest: String,
    pub(crate) media_type: String,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct RepoTags {
    pub(crate) repo: String,
    pub(crate) tags: Vec<TagEntry>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct MediaTypeEntry {
    pub(crate) repo: String,
    pub(crate) digest: String,
    pub(crate) media_type: String,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct ReferrerEntry {
    pub(crate) referrer_digest: String,
    pub(crate) artifact_type: String,
    pub(crate) descriptor: Vec<u8>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct SubjectReferrers {
    pub(crate) repo: String,
    pub(crate) subject: String,
    pub(crate) referrers: Vec<ReferrerEntry>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct BackrefEntry {
    pub(crate) repo: String,
    pub(crate) blob: String,
    pub(crate) manifests: Vec<String>,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct ChecksumEntry {
    pub(crate) repo: String,
    pub(crate) digest: String,
    pub(crate) crc32c: u32,
    pub(crate) size: u64,
}

#[derive(Archive, Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct SnapshotState {
    pub(crate) tags: Vec<RepoTags>,
    pub(crate) media_types: Vec<MediaTypeEntry>,
    pub(crate) referrers: Vec<SubjectReferrers>,
    pub(crate) backrefs: Vec<BackrefEntry>,
    pub(crate) checksums: Vec<ChecksumEntry>,
    /// Monotonic generation; mismatched-generation log tails are stale.
    pub(crate) generation: u64,
    /// WAL byte offset this snapshot covers through.
    pub(crate) log_offset: u64,
}

const MAGIC: &[u8; 8] = b"rocisnap";
const VERSION: u32 = 1;
/// Header size (8-byte aligned for rkyv body).
const HEADER_SIZE: usize = 56;

pub(crate) fn encode_header(body: &[u8], hmac_key: Option<&HmacKey>) -> [u8; HEADER_SIZE] {
    let mut hdr = [0u8; HEADER_SIZE];
    hdr[..8].copy_from_slice(MAGIC);
    hdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
    hdr[12..20].copy_from_slice(&(body.len() as u64).to_le_bytes());
    let integrity = integrity_of(body, hmac_key);
    hdr[20..52].copy_from_slice(&integrity);
    hdr
}

fn integrity_of(body: &[u8], hmac_key: Option<&HmacKey>) -> [u8; 32] {
    match hmac_key {
        Some(key) => key.tag(body),
        None => {
            let crc = crc32c::crc32c(body);
            let mut out = [0u8; 32];
            out[..4].copy_from_slice(&crc.to_le_bytes());
            out
        }
    }
}

fn verify_header<'a>(data: &'a [u8], hmac_key: Option<&HmacKey>) -> Result<&'a [u8], &'static str> {
    if data.len() < HEADER_SIZE {
        return Err("snapshot too small for header");
    }
    if &data[..8] != MAGIC {
        return Err("bad snapshot magic");
    }
    let ver = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if ver != VERSION {
        return Err("unsupported snapshot version");
    }
    let body_len = u64::from_le_bytes([
        data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
    ]) as usize;
    if HEADER_SIZE + body_len > data.len() {
        return Err("snapshot body truncated");
    }
    let body = &data[HEADER_SIZE..HEADER_SIZE + body_len];
    let stored: &[u8; 32] = data[20..52].try_into().expect("32 bytes");
    let expected = integrity_of(body, hmac_key);
    if *stored != expected {
        return Err("snapshot integrity check failed");
    }
    Ok(body)
}

pub(crate) fn write_atomic(path: &Path, header: &[u8; HEADER_SIZE], body: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = path.with_extension("snap.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(header)?;
        f.write_all(body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    let d = std::fs::File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

/// A verified, mmap'd snapshot.
pub(crate) struct VerifiedSnapshot {
    mmap: memmap2::Mmap,
    body_offset: usize,
    body_len: usize,
}

impl std::fmt::Debug for VerifiedSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSnapshot")
            .field("body_len", &self.body_len)
            .finish()
    }
}

impl VerifiedSnapshot {
    pub(crate) fn open(path: &Path, hmac_key: Option<&HmacKey>) -> io::Result<Option<Self>> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        // SAFETY: The snapshot file is written via atomic rename (never
        // modified in place). An external actor truncating/overwriting
        // the file after our open is a documented SIGBUS risk (same
        // risk profile as LMDB). The file descriptor is read-only.
        #[allow(unsafe_code)]
        let mmap = unsafe { memmap2::Mmap::map(&file)? };

        let body = verify_header(&mmap, hmac_key)
            .map_err(|msg| io::Error::new(io::ErrorKind::InvalidData, msg))?;
        let body_len = body.len();

        rkyv::access::<ArchivedSnapshotState, rkyv::rancor::Error>(body).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snapshot rkyv validation failed: {e}"),
            )
        })?;

        Ok(Some(Self {
            mmap,
            body_offset: HEADER_SIZE,
            body_len,
        }))
    }

    pub(crate) fn archived(&self) -> &ArchivedSnapshotState {
        let body = &self.mmap[self.body_offset..self.body_offset + self.body_len];
        // SAFETY: The archive was fully validated by `rkyv::access` (with
        // bytecheck) during `open()`. The underlying mmap is read-only and the
        // file was written via atomic rename, so the bytes have not changed
        // (barring SIGBUS-class interference, which is documented).
        #[allow(unsafe_code)]
        unsafe {
            rkyv::access_unchecked::<ArchivedSnapshotState>(body)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> SnapshotState {
        SnapshotState {
            tags: vec![RepoTags {
                repo: "repo".into(),
                tags: vec![TagEntry {
                    tag: "v1".into(),
                    digest: "sha256:aa".into(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                }],
            }],
            media_types: vec![MediaTypeEntry {
                repo: "repo".into(),
                digest: "sha256:aa".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            }],
            referrers: vec![],
            backrefs: vec![],
            checksums: vec![ChecksumEntry {
                repo: "repo".into(),
                digest: "sha256:bb".into(),
                crc32c: 0x12345678,
                size: 1024,
            }],
            generation: 1,
            log_offset: 0,
        }
    }

    #[test]
    fn snapshot_roundtrip() {
        let state = sample_state();
        let body = rkyv::to_bytes::<rkyv::rancor::Error>(&state).unwrap();

        for (label, key) in [
            ("no_hmac", None),
            ("with_hmac", Some([0xABu8; 64].as_slice())),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("roci-meta.snapshot");
            let hmac_key = key.map(|k| {
                let p = dir.path().join("hmac.key");
                std::fs::write(&p, k).unwrap();
                HmacKey::load(&p).unwrap()
            });
            let hdr = encode_header(&body, hmac_key.as_ref());
            write_atomic(&path, &hdr, &body).unwrap();

            let snap = VerifiedSnapshot::open(&path, hmac_key.as_ref())
                .unwrap()
                .unwrap();
            let archived = snap.archived();
            assert_eq!(archived.tags.len(), 1, "{label}");
            assert_eq!(archived.generation, 1, "{label}");
            assert_eq!(archived.checksums.len(), 1, "{label}");
        }
    }

    #[test]
    fn snapshot_integrity_rejected() {
        let state = sample_state();
        let body = rkyv::to_bytes::<rkyv::rancor::Error>(&state).unwrap();

        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("roci-meta.snapshot");
            let hdr = encode_header(&body, None);
            write_atomic(&path, &hdr, &body).unwrap();
            let mut data = std::fs::read(&path).unwrap();
            let idx = HEADER_SIZE + 2;
            if idx < data.len() {
                data[idx] ^= 0xFF;
            }
            std::fs::write(&path, &data).unwrap();
            let err = VerifiedSnapshot::open(&path, None).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "corrupted_body"
            );
        }

        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("roci-meta.snapshot");
            let key_path = dir.path().join("hmac.key");
            std::fs::write(&key_path, [0xABu8; 64]).unwrap();
            let key = HmacKey::load(&key_path).unwrap();
            let hdr = encode_header(&body, Some(&key));
            write_atomic(&path, &hdr, &body).unwrap();
            let key2_path = dir.path().join("hmac2.key");
            std::fs::write(&key2_path, [0xCDu8; 64]).unwrap();
            let key2 = HmacKey::load(&key2_path).unwrap();
            let err = VerifiedSnapshot::open(&path, Some(&key2)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "wrong_hmac");
        }

        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("roci-meta.snapshot");
            let key_path = dir.path().join("hmac3.key");
            std::fs::write(&key_path, [0xABu8; 64]).unwrap();
            let key = HmacKey::load(&key_path).unwrap();
            let hdr = encode_header(&body, Some(&key));
            write_atomic(&path, &hdr, &body).unwrap();
            let err = VerifiedSnapshot::open(&path, None).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "hmac_when_no_key"
            );
        }
    }

    #[test]
    fn verify_header_edge_cases() {
        let state = sample_state();
        let body = rkyv::to_bytes::<rkyv::rancor::Error>(&state).unwrap();

        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("too_small", vec![0u8; 10], "snapshot too small for header"),
            (
                "bad_magic",
                {
                    let mut data = vec![0u8; HEADER_SIZE + 8];
                    data[..8].copy_from_slice(b"BADMAGIC");
                    data
                },
                "bad snapshot magic",
            ),
            (
                "bad_version",
                {
                    let mut data = vec![0u8; HEADER_SIZE + 8];
                    data[..8].copy_from_slice(MAGIC);
                    data[8..12].copy_from_slice(&99u32.to_le_bytes());
                    data
                },
                "unsupported snapshot version",
            ),
            (
                "truncated_body",
                {
                    let mut data = vec![0u8; HEADER_SIZE];
                    data[..8].copy_from_slice(MAGIC);
                    data[8..12].copy_from_slice(&VERSION.to_le_bytes());
                    data[12..20].copy_from_slice(&999u64.to_le_bytes());
                    data
                },
                "snapshot body truncated",
            ),
            (
                "integrity_mismatch",
                {
                    let hdr = encode_header(&body, None);
                    let mut data = Vec::new();
                    data.extend_from_slice(&hdr);
                    data.extend_from_slice(&body);
                    data[20] ^= 0xFF;
                    data
                },
                "snapshot integrity check failed",
            ),
        ];

        for (label, data, expected) in &cases {
            let result = verify_header(data, None);
            assert_eq!(result.unwrap_err(), *expected, "{label}");
        }
    }

    #[test]
    fn verified_snapshot_debug() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roci-meta.snapshot");
        let state = sample_state();
        let body = rkyv::to_bytes::<rkyv::rancor::Error>(&state).unwrap();
        let hdr = encode_header(&body, None);
        write_atomic(&path, &hdr, &body).unwrap();
        let snap = VerifiedSnapshot::open(&path, None).unwrap().unwrap();
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("VerifiedSnapshot"), "got: {dbg}");
        assert!(dbg.contains("body_len"), "got: {dbg}");
    }

    #[test]
    fn snapshot_rejects_invalid_rkyv_archive() {
        let garbage_body = vec![0xFFu8; 128];
        let hdr = encode_header(&garbage_body, None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roci-meta.snapshot");
        write_atomic(&path, &hdr, &garbage_body).unwrap();
        let err = VerifiedSnapshot::open(&path, None).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("rkyv"),
            "error should mention rkyv: {}",
            err
        );
    }

    #[test]
    fn snapshot_open_io_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roci-meta.snapshot");
        std::fs::create_dir(&path).unwrap();
        let err = VerifiedSnapshot::open(&path, None).unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
