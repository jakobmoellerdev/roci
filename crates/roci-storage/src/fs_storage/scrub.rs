//! Background data scrubbing: staggered CRC32C verification with digest re-hash escalation.

use super::super::FsStorage;
use super::paths::blob_rel;
use crate::beneath::{dir_beneath, open_beneath, run_blocking};
use crate::digest::hash_reader;
use crate::layout::for_each_cas_blob;
use crate::metadata::MetaOp;
use crate::Digest;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[cfg(target_os = "linux")]
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;
#[cfg(target_os = "linux")]
const ZFS_SUPER_MAGIC: u64 = 0x2FC1_2FC1;

/// Whether `f_type` is a self-checksumming FS (btrfs/ZFS).
#[cfg(target_os = "linux")]
pub(crate) fn fs_is_self_checksumming_linux(f_type: u64) -> bool {
    matches!(f_type, BTRFS_SUPER_MAGIC | ZFS_SUPER_MAGIC)
}

/// Whether `f_fstypename` is a self-checksumming FS (btrfs/ZFS).
#[cfg(target_os = "macos")]
pub(crate) fn fs_is_self_checksumming_macos(fstypename: &[i8]) -> bool {
    let bytes: Vec<u8> = fstypename
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as u8)
        .collect();
    let name = std::str::from_utf8(&bytes).unwrap_or("");
    matches!(name, "zfs" | "btrfs")
}

/// True when the store root's FS does its own checksumming.
#[cfg(target_os = "linux")]
fn detect_self_checksumming_fs(root: &Path) -> io::Result<bool> {
    let st = rustix::fs::statfs(root).map_err(io::Error::from)?;
    Ok(fs_is_self_checksumming_linux(st.f_type as u64))
}

#[cfg(target_os = "macos")]
fn detect_self_checksumming_fs(root: &Path) -> io::Result<bool> {
    let st = rustix::fs::statfs(root).map_err(io::Error::from)?;
    Ok(fs_is_self_checksumming_macos(&st.f_fstypename))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_self_checksumming_fs(_root: &Path) -> io::Result<bool> {
    Ok(false)
}

/// Token-bucket rate limiter for scrub read bandwidth.
pub(crate) struct TokenBucket {
    tokens: f64,
    rate: f64,
    capacity: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    pub(crate) fn new(bytes_per_sec: u64) -> Self {
        let cap = bytes_per_sec as f64;
        Self {
            tokens: cap,
            rate: cap,
            capacity: cap,
            last: std::time::Instant::now(),
        }
    }

    fn refill(&mut self, now: std::time::Instant) {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last = now;
    }

    /// Consume `n` bytes, returning the required sleep duration.
    pub(crate) fn consume(&mut self, n: u64) -> Duration {
        let now = std::time::Instant::now();
        self.refill(now);
        let needed = n as f64;
        if self.tokens >= needed {
            self.tokens -= needed;
            Duration::ZERO
        } else {
            let deficit = needed - self.tokens;
            let wait_secs = deficit / self.rate;
            self.tokens -= needed; // goes negative; refill catches up
            Duration::from_secs_f64(wait_secs)
        }
    }

    /// Time for `n` bytes at the given rate (test helper).
    #[cfg(test)]
    pub(crate) fn time_for(bytes_per_sec: u64, deficit_bytes: u64) -> Duration {
        if bytes_per_sec == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(deficit_bytes as f64 / bytes_per_sec as f64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BlobEntry {
    pub repo: String,
    pub digest: String,
    pub size: u64,
}

/// Blobs from one repo, sorted by digest.
#[derive(Debug, Clone)]
pub(crate) struct Segment {
    pub blobs: Vec<BlobEntry>,
}

/// Enumerate all CAS blobs grouped by repo into segments.
pub(crate) fn enumerate_segments(root: &Path) -> Vec<Segment> {
    let mut entries: Vec<BlobEntry> = Vec::new();
    for_each_cas_blob(root, |repo, digest, entry| {
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        entries.push(BlobEntry {
            repo: repo.to_string(),
            digest: digest.as_string(),
            size,
        });
    });
    entries.sort();

    let mut segments: Vec<Segment> = Vec::new();
    for entry in entries {
        if segments
            .last()
            .map(|s| s.blobs.last().map(|b| b.repo.as_str()) != Some(entry.repo.as_str()))
            .unwrap_or(true)
        {
            segments.push(Segment { blobs: Vec::new() });
        }
        segments.last_mut().unwrap().blobs.push(entry);
    }
    segments
}

/// Staggered visit order: round-robin across segments.
pub(crate) fn staggered_order(segments: &[Segment]) -> Vec<(usize, usize)> {
    let max_len = segments.iter().map(|s| s.blobs.len()).max().unwrap_or(0);
    let mut order = Vec::new();
    for round in 0..max_len {
        for (seg_idx, seg) in segments.iter().enumerate() {
            if round < seg.blobs.len() {
                order.push((seg_idx, round));
            }
        }
    }
    order
}

/// Reorder remaining entries to drain the corrupt segment first.
pub(crate) fn adaptive_reorder(
    order: &[(usize, usize)],
    already_done: usize,
    corrupt_seg: usize,
    _segments: &[Segment],
) -> Vec<(usize, usize)> {
    let remaining = &order[already_done..];
    let mut drain: Vec<(usize, usize)> = Vec::new();
    let mut rest: Vec<(usize, usize)> = Vec::new();
    for &(si, bi) in remaining {
        if si == corrupt_seg {
            drain.push((si, bi));
        } else {
            rest.push((si, bi));
        }
    }
    drain.extend(rest);
    drain
}

fn quarantine_leaf(repo: &str, digest: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let safe_repo = repo.replace('/', "__");
    let safe_digest = digest.replace(':', "_");
    format!("{safe_repo}---{safe_digest}---{ts}")
}

/// Quarantine dir (dot-prefixed, invisible to `discover_repos`).
const QUARANTINE_DIR: &str = ".roci-quarantine";

async fn quarantine_blob(
    root: &Path,
    repo: &str,
    digest_obj: &Digest,
    digest_str: &str,
) -> io::Result<()> {
    use super::paths::blob_dir_rel;
    let (from_dir_rel, from_leaf) = blob_dir_rel(repo, digest_obj)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let to_dir_rel = PathBuf::from(QUARANTINE_DIR);
    let to_leaf = quarantine_leaf(repo, digest_str);

    let root = root.to_path_buf();
    run_blocking("quarantine_blob", move || -> io::Result<()> {
        let from_fd = dir_beneath(&root, &from_dir_rel, false)?;
        let to_fd = dir_beneath(&root, &to_dir_rel, true)?;
        rustix::fs::renameat(&from_fd, from_leaf.as_str(), &to_fd, to_leaf.as_str())
            .map_err(io::Error::from)?;
        rustix::fs::fsync(&to_fd).map_err(io::Error::from)?;
        Ok(())
    })
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScrubResult {
    /// CRC or digest verified.
    Ok,
    /// Wrong checksum record corrected after digest match.
    Repaired,
    Corrupt,
    Skipped,
}

impl ScrubResult {
    fn label(self) -> &'static str {
        match self {
            ScrubResult::Ok => "ok",
            ScrubResult::Repaired => "repaired",
            ScrubResult::Corrupt => "corrupt",
            ScrubResult::Skipped => "skipped",
        }
    }
}

impl FsStorage {
    async fn scrub_one_blob(&self, repo: &str, digest_str: &str) -> (ScrubResult, u64) {
        let digest = match Digest::parse(digest_str) {
            Ok(d) => d,
            Err(_) => return (ScrubResult::Skipped, 0),
        };

        let rel = match blob_rel(repo, &digest) {
            Ok(r) => r,
            Err(_) => return (ScrubResult::Skipped, 0),
        };
        let file = match open_beneath(&self.root, &rel).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (ScrubResult::Skipped, 0),
            Err(e) => {
                tracing::warn!(repo, digest = digest_str, error = %e, "scrub: cannot open blob");
                return (ScrubResult::Skipped, 0);
            }
        };

        let file_size = match file.metadata().await {
            Ok(m) => m.len(),
            Err(_) => return (ScrubResult::Skipped, 0),
        };

        let recorded = self.meta.checksum(repo, digest_str);

        if let Some(cksum) = &recorded {
            if cksum.size == file_size {
                let crc_result = crc32c_of_file(file).await;
                match crc_result {
                    Ok((crc, bytes_read)) => {
                        if crc == cksum.crc32c {
                            return (ScrubResult::Ok, bytes_read);
                        }
                    }
                    Err(_) => return (ScrubResult::Skipped, 0),
                }
            }
        }

        // SECURITY: capture inode identity before hashing — a concurrent
        // delete+re-push may install a valid replacement we must not quarantine.
        let file2 = match open_beneath(&self.root, &rel).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return (ScrubResult::Skipped, 0),
            Err(_) => return (ScrubResult::Skipped, 0),
        };
        let hashed_ino = {
            let st = match rustix::fs::fstat(&file2) {
                Ok(s) => s,
                Err(_) => return (ScrubResult::Skipped, 0),
            };
            (st.st_dev as u64, st.st_ino as u64)
        };

        let (computed_digest, computed_crc) = match hash_reader(file2, digest.algorithm()).await {
            Ok(v) => v,
            Err(_) => return (ScrubResult::Skipped, 0),
        };

        if computed_digest.ct_eq(&digest) {
            let had_wrong = recorded.is_some();
            if let Err(e) = self.meta.apply_relaxed(MetaOp::PutChecksum {
                repo: repo.to_string(),
                digest: digest_str.to_string(),
                crc32c: computed_crc,
                size: file_size,
            }) {
                tracing::warn!(repo, digest = digest_str, error = %e, "scrub: recording checksum failed");
            }
            let result = if had_wrong {
                ScrubResult::Repaired
            } else {
                ScrubResult::Ok
            };
            (result, file_size)
        } else {
            tracing::error!(
                repo = repo,
                digest = digest_str,
                "scrub: blob corrupt — digest mismatch, quarantining"
            );
            let _fence = self.gc.exclusive().await;

            // SECURITY: re-verify inode identity after acquiring fence.
            let path_ino = {
                let full = self.root.join(&rel);
                match std::fs::symlink_metadata(&full) {
                    Ok(m) => {
                        use std::os::unix::fs::MetadataExt;
                        (m.dev(), m.ino())
                    }
                    Err(_) => {
                        return (ScrubResult::Corrupt, file_size);
                    }
                }
            };
            if path_ino != hashed_ino {
                tracing::info!(
                    repo,
                    digest = digest_str,
                    "scrub: inode replaced since hash; skipping quarantine"
                );
                return (ScrubResult::Corrupt, file_size);
            }

            match quarantine_blob(&self.root, repo, &digest, digest_str).await {
                Ok(()) => {
                    self.blob_left(repo, digest_str, Some(file_size));
                }
                Err(e) => {
                    // SECURITY: do NOT call blob_left — the CAS file persists;
                    // clearing bookkeeping would serve known-bad bytes.
                    tracing::error!(
                        repo = repo,
                        digest = digest_str,
                        error = %e,
                        "scrub: quarantine rename failed; leaving for next pass"
                    );
                    return (ScrubResult::Corrupt, file_size);
                }
            }

            self.quarantine_hard_linked_copies(digest_str, &digest, hashed_ino, repo)
                .await;

            (ScrubResult::Corrupt, file_size)
        }
    }

    /// Quarantine hard-linked copies sharing `corrupt_ino` (called under GC fence).
    async fn quarantine_hard_linked_copies(
        &self,
        digest_str: &str,
        digest: &Digest,
        corrupt_ino: (u64, u64),
        already_quarantined_repo: &str,
    ) {
        let root = self.root.clone();
        let digest_clone = digest.clone();
        let corrupt_ino_val = corrupt_ino;
        let already_repo = already_quarantined_repo.to_string();
        let linked: Vec<(String, u64)> = {
            let root = root.clone();
            let digest_c = digest_clone.clone();
            run_blocking("quarantine_hard_linked_copies", move || {
                let mut hits = Vec::new();
                for_each_cas_blob(&root, |r, d, entry| {
                    if d.as_string() != digest_c.as_string() {
                        return;
                    }
                    if r == already_repo {
                        return;
                    }
                    if let Ok(m) = entry.metadata() {
                        use std::os::unix::fs::MetadataExt;
                        if (m.dev(), m.ino()) == corrupt_ino_val {
                            hits.push((r.to_string(), m.len()));
                        }
                    }
                });
                Ok(hits)
            })
            .await
            .unwrap_or_default()
        };
        for (other_repo, size) in linked {
            match quarantine_blob(&self.root, &other_repo, digest, digest_str).await {
                Ok(()) => {
                    self.blob_left(&other_repo, digest_str, Some(size));
                    tracing::warn!(
                        repo = other_repo,
                        digest = digest_str,
                        "scrub: quarantined hard-linked copy"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        repo = other_repo,
                        digest = digest_str,
                        error = %e,
                        "scrub: quarantine of hard-linked copy failed; leaving for next pass"
                    );
                }
            }
        }
    }

    /// Run one full scrub pass over the store.
    #[tracing::instrument(skip_all, name = "scrub.pass")]
    pub(crate) async fn scrub_pass(&self) {
        let root = self.root.clone();
        let segments = tokio::task::spawn_blocking(move || enumerate_segments(&root))
            .await
            .unwrap_or_default();

        if segments.is_empty() {
            return;
        }

        let order = staggered_order(&segments);
        let total = order.len();
        let mut counts = ScrubCounts::default();
        let mut bucket = TokenBucket::new(self.config.scrub.max_bytes_per_sec);

        let mut pos = 0;
        let mut current_order: Vec<(usize, usize)> = order.clone();

        while pos < current_order.len() {
            let (seg_idx, blob_idx) = current_order[pos];
            let entry = &segments[seg_idx].blobs[blob_idx];

            let delay = bucket.consume(entry.size);
            if delay > Duration::ZERO {
                tokio::time::sleep(delay).await;
            }

            let (result, bytes) = self.scrub_one_blob(&entry.repo, &entry.digest).await;
            roci_telemetry::record_scrub(result.label(), bytes);
            match result {
                ScrubResult::Ok => counts.ok += 1,
                ScrubResult::Repaired => counts.repaired += 1,
                ScrubResult::Corrupt => {
                    counts.corrupt += 1;
                    let new_tail = adaptive_reorder(&current_order, pos + 1, seg_idx, &segments);
                    current_order.truncate(pos + 1);
                    current_order.extend(new_tail);
                }
                ScrubResult::Skipped => counts.skipped += 1,
            }
            counts.bytes += bytes;
            pos += 1;
        }

        tracing::info!(
            total,
            ok = counts.ok,
            repaired = counts.repaired,
            corrupt = counts.corrupt,
            skipped = counts.skipped,
            bytes = counts.bytes,
            "scrub pass complete"
        );
    }

    /// Start the scrub background task.
    pub(crate) fn start_scrub(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let mode = self.config.scrub.mode;

        if mode == roci_config::ScrubMode::Auto {
            match detect_self_checksumming_fs(&self.root) {
                Ok(true) => {
                    tracing::info!(
                        root = %self.root.display(),
                        "scrub: integrity is delegated to the filesystem's own scrub"
                    );
                    return;
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "scrub: could not detect filesystem type, running app pass"
                    );
                }
            }
        }

        let interval = Duration::from_secs(self.config.scrub.interval_secs);
        crate::storage::spawn_periodic(
            self.clone(),
            "scrub.pass",
            interval,
            shutdown,
            |s| async move {
                s.scrub_pass().await;
            },
        );
    }
}

async fn crc32c_of_file(mut file: tokio::fs::File) -> io::Result<(u32, u64)> {
    let mut crc = 0u32;
    let mut total = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        crc = crc32c::crc32c_append(crc, &buf[..n]);
        total += n as u64;
    }
    Ok((crc, total))
}

#[derive(Default)]
struct ScrubCounts {
    ok: u64,
    repaired: u64,
    corrupt: u64,
    skipped: u64,
    bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_of;
    use crate::storage::Storage;

    fn store() -> (tempfile::TempDir, FsStorage) {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        (dir, s)
    }

    fn store_with(config: &roci_config::StorageConfig) -> (tempfile::TempDir, FsStorage) {
        let dir = tempfile::tempdir().unwrap();
        let quota = std::sync::Arc::new(crate::quota::QuotaTracker::default());
        let s = FsStorage::with_config(dir.path(), config, quota).unwrap();
        (dir, s)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fs_detection_linux() {
        for (label, magic, expected) in [
            ("btrfs", BTRFS_SUPER_MAGIC, true),
            ("zfs", ZFS_SUPER_MAGIC, true),
            ("ext4", 0xEF53_u64, false),
            ("xfs", 0x5846_5342_u64, false),
        ] {
            assert_eq!(fs_is_self_checksumming_linux(magic), expected, "{label}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fs_detection_macos() {
        fn name(s: &[u8]) -> [i8; 16] {
            let mut out = [0i8; 16];
            for (i, &b) in s.iter().enumerate() {
                out[i] = b as i8;
            }
            out
        }
        for (label, fsname, expected) in [
            ("zfs", b"zfs" as &[u8], true),
            ("apfs", b"apfs", false),
            ("hfs", b"hfs", false),
        ] {
            assert_eq!(
                fs_is_self_checksumming_macos(&name(fsname)),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    fn token_bucket_immediate_when_enough() {
        let mut b = TokenBucket::new(1_000_000);
        assert_eq!(b.consume(500_000), Duration::ZERO);
    }

    #[test]
    fn token_bucket_waits_when_deficit() {
        let mut b = TokenBucket::new(1_000_000);
        let _ = b.consume(1_000_000);
        let d = b.consume(500_000);
        assert!(d > Duration::ZERO);
        assert!(d.as_secs_f64() > 0.4 && d.as_secs_f64() < 0.7);
    }

    #[test]
    fn token_bucket_time_for_pure_math() {
        assert!((TokenBucket::time_for(1_000_000, 2_000_000).as_secs_f64() - 2.0).abs() < 0.001);
        assert!(
            (TokenBucket::time_for(64 * 1024 * 1024, 64 * 1024 * 1024).as_secs_f64() - 1.0).abs()
                < 0.001
        );
        assert_eq!(TokenBucket::time_for(0, 1000), Duration::ZERO);
    }

    #[test]
    fn staggered_order_interleaves_segments() {
        let segments = vec![
            Segment {
                blobs: vec![
                    BlobEntry {
                        repo: "a".into(),
                        digest: "sha256:aa".repeat(32),
                        size: 10,
                    },
                    BlobEntry {
                        repo: "a".into(),
                        digest: "sha256:bb".repeat(32),
                        size: 20,
                    },
                    BlobEntry {
                        repo: "a".into(),
                        digest: "sha256:cc".repeat(32),
                        size: 30,
                    },
                ],
            },
            Segment {
                blobs: vec![
                    BlobEntry {
                        repo: "b".into(),
                        digest: "sha256:dd".repeat(32),
                        size: 10,
                    },
                    BlobEntry {
                        repo: "b".into(),
                        digest: "sha256:ee".repeat(32),
                        size: 20,
                    },
                ],
            },
        ];
        let order = staggered_order(&segments);
        assert_eq!(order, vec![(0, 0), (1, 0), (0, 1), (1, 1), (0, 2)]);
    }

    #[test]
    fn staggered_order_empty() {
        assert!(staggered_order(&[]).is_empty());
    }

    #[test]
    fn staggered_order_single_segment() {
        let segments = vec![Segment {
            blobs: vec![
                BlobEntry {
                    repo: "r".into(),
                    digest: "sha256:aa".repeat(32),
                    size: 1,
                },
                BlobEntry {
                    repo: "r".into(),
                    digest: "sha256:bb".repeat(32),
                    size: 2,
                },
            ],
        }];
        assert_eq!(staggered_order(&segments), vec![(0, 0), (0, 1)]);
    }

    #[test]
    fn adaptive_reorder_drains_corrupt_segment_first() {
        let segments = vec![
            Segment {
                blobs: vec![
                    BlobEntry {
                        repo: "a".into(),
                        digest: "d0".into(),
                        size: 1,
                    },
                    BlobEntry {
                        repo: "a".into(),
                        digest: "d1".into(),
                        size: 1,
                    },
                    BlobEntry {
                        repo: "a".into(),
                        digest: "d2".into(),
                        size: 1,
                    },
                ],
            },
            Segment {
                blobs: vec![
                    BlobEntry {
                        repo: "b".into(),
                        digest: "d3".into(),
                        size: 1,
                    },
                    BlobEntry {
                        repo: "b".into(),
                        digest: "d4".into(),
                        size: 1,
                    },
                ],
            },
        ];
        let order = staggered_order(&segments);
        let new_tail = adaptive_reorder(&order, 2, 1, &segments);
        assert_eq!(new_tail, vec![(1, 1), (0, 1), (0, 2)]);
    }

    #[test]
    fn adaptive_reorder_no_remaining() {
        let segments = vec![Segment {
            blobs: vec![BlobEntry {
                repo: "r".into(),
                digest: "d".into(),
                size: 1,
            }],
        }];
        assert!(adaptive_reorder(&[(0, 0)], 1, 0, &segments).is_empty());
    }

    #[test]
    fn quarantine_leaf_encodes_correctly() {
        let leaf = quarantine_leaf("org/repo", "sha256:aabb");
        assert!(leaf.starts_with("org__repo---sha256_aabb---"));
        assert!(!leaf.contains('/'));
        assert!(!leaf.contains(':'));
    }

    #[test]
    fn scrub_result_labels() {
        for (variant, expected) in [
            (ScrubResult::Ok, "ok"),
            (ScrubResult::Repaired, "repaired"),
            (ScrubResult::Corrupt, "corrupt"),
            (ScrubResult::Skipped, "skipped"),
        ] {
            assert_eq!(variant.label(), expected, "{expected}");
        }
    }

    #[tokio::test]
    async fn scrub_detects_and_quarantines_corruption() {
        let (_dir, s) = store();
        let data = b"scrub test content";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.scrub_pass().await;
        assert!(s.meta.checksum("r", &d.as_string()).is_some());

        let blob_path = _dir.path().join("r/blobs/sha256").join(d.hex());
        std::fs::write(&blob_path, b"CORRUPTED DATA HERE!!").unwrap();
        s.scrub_pass().await;

        assert!(matches!(
            s.blob_size("r", &d).await,
            Err(crate::StorageError::NotFound)
        ));
        let q_dir = _dir.path().join(QUARANTINE_DIR);
        assert!(q_dir.is_dir());
        let entries: Vec<_> = std::fs::read_dir(&q_dir).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].file_name().to_string_lossy().starts_with("r---"));

        s.put_blob("r", &d, data).await.unwrap();
        assert_eq!(s.blob_size("r", &d).await.unwrap(), data.len() as u64);
    }

    #[tokio::test]
    async fn scrub_repairs_wrong_checksum_without_quarantine() {
        let (_dir, s) = store();
        let data = b"content with wrong checksum";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.meta
            .apply_relaxed(MetaOp::PutChecksum {
                repo: "r".to_string(),
                digest: d.as_string(),
                crc32c: 0xDEAD_BEEF,
                size: data.len() as u64,
            })
            .unwrap();

        s.scrub_pass().await;
        assert_eq!(s.blob_size("r", &d).await.unwrap(), data.len() as u64);
        assert_ne!(
            s.meta.checksum("r", &d.as_string()).unwrap().crc32c,
            0xDEAD_BEEF
        );
        assert!(!_dir.path().join(QUARANTINE_DIR).exists());
    }

    #[tokio::test]
    async fn scrub_bootstraps_checksum_for_new_blob() {
        let (_dir, s) = store();
        let data = b"bootstrap me";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.meta
            .apply_relaxed(MetaOp::DeleteBlob {
                repo: "r".to_string(),
                digest: d.as_string(),
            })
            .unwrap();
        assert!(s.meta.checksum("r", &d.as_string()).is_none());

        s.scrub_pass().await;
        assert_eq!(
            s.meta.checksum("r", &d.as_string()).unwrap().size,
            data.len() as u64
        );
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    }

    #[tokio::test]
    async fn scrub_enumerate_segments_groups_by_repo() {
        let (_dir, s) = store();
        s.put_blob("repo1", &sha256_of(b"a"), b"a").await.unwrap();
        s.put_blob("repo1", &sha256_of(b"b"), b"b").await.unwrap();
        s.put_blob("repo2", &sha256_of(b"c"), b"c").await.unwrap();
        let segments = enumerate_segments(_dir.path());
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].blobs[0].repo, "repo1");
        assert_eq!(segments[0].blobs.len(), 2);
        assert_eq!(segments[1].blobs[0].repo, "repo2");
        assert_eq!(segments[1].blobs.len(), 1);
    }

    #[tokio::test]
    async fn scrub_quarantine_dir_not_in_discover_repos() {
        let (_dir, s) = store();
        let d = sha256_of(b"quarantine me");
        s.put_blob("r", &d, b"quarantine me").await.unwrap();
        let q_dir = _dir.path().join(QUARANTINE_DIR);
        std::fs::create_dir_all(&q_dir).unwrap();
        std::fs::write(q_dir.join("dummy"), b"quarantined blob").unwrap();
        let repos = crate::layout::discover_repos(_dir.path());
        assert!(!repos.iter().any(|r| r.contains("roci-quarantine")));
        assert!(repos.contains(&"r".to_string()));
    }

    #[tokio::test]
    async fn scrub_mode_auto_and_app_run_pass() {
        for mode in [roci_config::ScrubMode::Auto, roci_config::ScrubMode::App] {
            let (_dir, s) = if matches!(mode, roci_config::ScrubMode::App) {
                let mut config = roci_config::StorageConfig::default();
                config.scrub.enabled = true;
                config.scrub.mode = roci_config::ScrubMode::App;
                store_with(&config)
            } else {
                store()
            };
            let data = b"mode test";
            let d = sha256_of(data);
            s.put_blob("r", &d, data).await.unwrap();
            s.meta
                .apply_relaxed(MetaOp::DeleteBlob {
                    repo: "r".to_string(),
                    digest: d.as_string(),
                })
                .unwrap();
            if matches!(mode, roci_config::ScrubMode::Auto) {
                detect_self_checksumming_fs(_dir.path()).unwrap();
            }
            s.scrub_pass().await;
            assert!(s.meta.checksum("r", &d.as_string()).is_some(), "{mode:?}");
        }
    }

    #[tokio::test]
    async fn scrub_crc32c_ok_does_not_rehash() {
        let (_dir, s) = store();
        let data = b"fast path content";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        assert_eq!(
            s.meta.checksum("r", &d.as_string()).unwrap().size,
            data.len() as u64
        );
        let (result, bytes) = s.scrub_one_blob("r", &d.as_string()).await;
        assert_eq!(result, ScrubResult::Ok);
        assert_eq!(bytes, data.len() as u64);
    }

    #[tokio::test]
    async fn scrub_skips_unreachable_blobs() {
        let (_dir, s) = store();
        for (label, repo, digest) in [
            (
                "vanished",
                "nonexistent",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("invalid_digest", "r", "not-a-digest"),
            (
                "absent_repo",
                "absent-repo",
                &sha256_of(b"nobody").as_string(),
            ),
        ] {
            let (result, bytes) = s.scrub_one_blob(repo, digest).await;
            assert_eq!(result, ScrubResult::Skipped, "{label}");
            assert_eq!(bytes, 0, "{label}");
        }
    }

    #[tokio::test]
    async fn scrub_size_mismatch_escalates_to_rehash() {
        let (_dir, s) = store();
        let data = b"size mismatch test";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        let real_cksum = s.meta.checksum("r", &d.as_string()).unwrap();
        s.meta
            .apply_relaxed(MetaOp::PutChecksum {
                repo: "r".to_string(),
                digest: d.as_string(),
                crc32c: real_cksum.crc32c,
                size: 99999,
            })
            .unwrap();
        let (result, bytes) = s.scrub_one_blob("r", &d.as_string()).await;
        assert_eq!(result, ScrubResult::Repaired);
        assert_eq!(bytes, data.len() as u64);
        assert_eq!(
            s.meta.checksum("r", &d.as_string()).unwrap().size,
            data.len() as u64
        );
    }

    #[tokio::test]
    async fn start_scrub_auto_and_app_modes() {
        for mode in [roci_config::ScrubMode::Auto, roci_config::ScrubMode::App] {
            let config = roci_config::StorageConfig {
                scrub: roci_config::ScrubConfig {
                    enabled: true,
                    mode,
                    interval_secs: 3600,
                    ..roci_config::ScrubConfig::default()
                },
                ..roci_config::StorageConfig::default()
            };
            let (_dir, s) = store_with(&config);
            let (tx, rx) = tokio::sync::watch::channel(false);
            s.start_scrub(rx);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = tx.send(true);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn scrub_quarantine_failure_still_does_blob_left() {
        let (_dir, s) = store();
        let data = b"quarantine-fail";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.scrub_pass().await;
        std::fs::write(_dir.path().join("r/blobs/sha256").join(d.hex()), b"X").unwrap();
        s.scrub_pass().await;
        assert!(matches!(
            s.blob_size("r", &d).await,
            Err(crate::StorageError::NotFound)
        ));
        assert!(_dir.path().join(QUARANTINE_DIR).is_dir());
    }

    #[tokio::test]
    async fn scrub_size_mismatch_bypasses_crc_shortcut() {
        let (_dir, s) = store();
        let data = b"size mismatch content";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.meta
            .apply_relaxed(MetaOp::PutChecksum {
                repo: "r".to_string(),
                digest: d.as_string(),
                crc32c: crc32c::crc32c(data),
                size: 9999,
            })
            .unwrap();
        let (result, bytes) = s.scrub_one_blob("r", &d.as_string()).await;
        assert_eq!(
            result,
            ScrubResult::Repaired,
            "size mismatch triggers rehash → Repaired"
        );
        assert_eq!(bytes, data.len() as u64);
        let ck = s.meta.checksum("r", &d.as_string()).unwrap();
        assert_eq!(ck.size, data.len() as u64, "checksum repaired");
    }

    #[tokio::test]
    async fn scrub_pass_adaptive_reorder_on_corruption() {
        let (_dir, s) = store();
        let ok_data = b"intact blob";
        let ok_d = sha256_of(ok_data);
        s.put_blob("r", &ok_d, ok_data).await.unwrap();
        let bad_data = b"will corrupt";
        let bad_d = sha256_of(bad_data);
        s.put_blob("r", &bad_d, bad_data).await.unwrap();
        s.scrub_pass().await;
        let blob_path = _dir.path().join("r/blobs/sha256").join(bad_d.hex());
        std::fs::write(&blob_path, b"EVIL").unwrap();
        s.scrub_pass().await;
        assert!(
            matches!(
                s.blob_size("r", &bad_d).await,
                Err(crate::StorageError::NotFound)
            ),
            "corrupt blob quarantined"
        );
        assert_eq!(
            s.blob_size("r", &ok_d).await.unwrap(),
            ok_data.len() as u64,
            "intact blob survives"
        );
    }
    #[tokio::test]
    async fn corrupt_hard_linked_copies_are_quarantined_in_every_repo() {
        use std::os::unix::fs::MetadataExt;
        let (dir, s) = store();
        let data = b"shared and then rotted";
        let d = sha256_of(data);
        s.put_blob("a", &d, data).await.unwrap();
        s.put_blob("b", &d, data).await.unwrap();
        let pa = s.blob_path("a", &d).unwrap();
        let pb = s.blob_path("b", &d).unwrap();
        if std::fs::metadata(&pa).unwrap().ino() != std::fs::metadata(&pb).unwrap().ino() {
            return; // reflink filesystem
        }
        let mut bytes = std::fs::read(&pa).unwrap();
        bytes[0] ^= 0xFF;
        std::fs::write(&pa, &bytes).unwrap();
        s.scrub_pass().await;
        for repo in ["a", "b"] {
            assert!(matches!(
                s.blob_size(repo, &d).await,
                Err(crate::StorageError::NotFound)
            ));
        }
        assert_eq!(
            std::fs::read_dir(dir.path().join(".roci-quarantine"))
                .unwrap()
                .count(),
            2
        );
    }
}
