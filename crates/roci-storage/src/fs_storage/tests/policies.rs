//! Storage policies wired into the blob lifecycle: quotas, the upload-session
//! cap, cross-repo dedupe on upload, and the scrub checksum recorded at write.

use super::*;
use crate::quota::{QuotaLimits, QuotaTracker};
use crate::storage::Storage;
use roci_config::StorageConfig;
use std::sync::Arc;

fn store_with(limits: QuotaLimits, dedupe: bool) -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StorageConfig {
        dedupe,
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &cfg, Arc::new(QuotaTracker::new(limits))).unwrap();
    (dir, s)
}

fn repo_cap(bytes: u64) -> QuotaLimits {
    QuotaLimits {
        max_repo_bytes: bytes,
        ..QuotaLimits::default()
    }
}

async fn chunked(s: &FsStorage, repo: &str, data: &[u8]) -> Result<(), StorageError> {
    let id = s.begin_upload(repo).await?;
    s.append_upload(repo, &id, data, None).await?;
    s.finish_upload(repo, &id, &sha256_of(data), u64::MAX, &[])
        .await
}

#[tokio::test]
async fn repository_quota_rejects_at_finalize_and_frees_on_delete() {
    let (_dir, s) = store_with(repo_cap(10), false);
    let a = b"12345678";
    s.put_blob("r", &sha256_of(a), a).await.unwrap();
    // Re-storing a present blob adds no bytes, so it is admitted at the cap.
    s.put_blob("r", &sha256_of(a), a).await.unwrap();
    let b = b"abcde";
    assert!(matches!(
        s.put_blob("r", &sha256_of(b), b).await,
        Err(StorageError::QuotaExceeded {
            scope: QuotaScope::Repository,
            limit: 10,
            requested: 5
        })
    ));
    // A chunked upload over the cap fails at finalize and its session is gone.
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, b, None).await.unwrap();
    assert!(matches!(
        s.finish_upload("r", &id, &sha256_of(b), u64::MAX, &[])
            .await,
        Err(StorageError::QuotaExceeded { .. })
    ));
    assert!(matches!(
        s.upload_size("r", &id).await,
        Err(StorageError::NotFound)
    ));
    assert!(!s.blob_exists("r", &sha256_of(b)).await.unwrap());
    // Another repository has its own budget.
    chunked(&s, "other", b).await.unwrap();
    // Deleting returns the bytes: the rejected blob now fits.
    s.delete_blob("r", &sha256_of(a)).await.unwrap();
    chunked(&s, "r", b).await.unwrap();
    assert_eq!(s.quota.repo_bytes("r"), 5);
}

#[tokio::test]
async fn total_quota_spans_repositories_and_mounts() {
    let (_dir, s) = store_with(
        QuotaLimits {
            max_total_bytes: 12,
            ..QuotaLimits::default()
        },
        false,
    );
    let a = b"123456";
    s.put_blob("a", &sha256_of(a), a).await.unwrap();
    s.put_blob("b", &sha256_of(b"654321"), b"654321")
        .await
        .unwrap();
    // A mount is a logical copy and is charged to the destination.
    assert!(matches!(
        s.mount_blob("a", "c", &sha256_of(a)).await,
        Err(StorageError::QuotaExceeded {
            scope: QuotaScope::Total,
            ..
        })
    ));
    assert!(!s.blob_exists("c", &sha256_of(a)).await.unwrap());
    s.delete_blob("b", &sha256_of(b"654321")).await.unwrap();
    assert!(s.mount_blob("a", "c", &sha256_of(a)).await.unwrap());
    assert_eq!(s.quota.total_bytes(), 12);
}

#[tokio::test]
async fn quota_usage_is_seeded_from_the_cas_on_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let s = FsStorage::new(dir.path()).unwrap();
        s.put_blob("r", &sha256_of(b"1234"), b"1234").await.unwrap();
    }
    let s = FsStorage::with_config(
        dir.path(),
        &StorageConfig::default(),
        Arc::new(QuotaTracker::new(repo_cap(6))),
    )
    .unwrap();
    assert_eq!(s.quota.repo_bytes("r"), 4);
    assert!(matches!(
        s.put_blob("r", &sha256_of(b"xyz"), b"xyz").await,
        Err(StorageError::QuotaExceeded { .. })
    ));
}

#[tokio::test]
async fn upload_session_cap_counts_open_sessions_across_restart() {
    let limits = QuotaLimits {
        max_upload_sessions: 2,
        ..QuotaLimits::default()
    };
    let (dir, s) = store_with(limits, false);
    let first = s.begin_upload("r").await.unwrap();
    let second = s.begin_upload("r").await.unwrap();
    assert!(matches!(
        s.begin_upload("r").await,
        Err(StorageError::TooManySessions { limit: 2 })
    ));
    // Abort and a completed finalize both release their slot.
    assert!(s.abort_upload("r", &first).await.unwrap());
    let third = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &third, b"x", None).await.unwrap();
    s.finish_upload("r", &third, &sha256_of(b"x"), u64::MAX, &[])
        .await
        .unwrap();
    // A rejected finalize (digest mismatch) drops the session too.
    let fourth = s.begin_upload("r").await.unwrap();
    assert!(s
        .finish_upload("r", &fourth, &sha256_of(b"y"), u64::MAX, b"z")
        .await
        .is_err());
    assert_eq!(s.quota.sessions(), 1);
    drop(s);
    // Staged sessions survive a restart and still count against the cap.
    let s = FsStorage::with_config(
        dir.path(),
        &StorageConfig::default(),
        Arc::new(QuotaTracker::new(limits)),
    )
    .unwrap();
    assert_eq!(s.quota.sessions(), 1);
    s.begin_upload("r").await.unwrap();
    assert!(s.begin_upload("r").await.is_err());
    assert!(s.abort_upload("r", &second).await.unwrap());
}

#[cfg(unix)]
fn link_count(s: &FsStorage, repo: &str, d: &Digest) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(s.blob_path(repo, d).unwrap())
        .unwrap()
        .nlink()
}

#[tokio::test]
async fn dedupe_links_a_blob_another_repo_holds_and_deletion_stays_independent() {
    #[cfg(target_os = "linux")]
    let _serialize = FAULT_TEST_LOCK.lock().await;
    let (_dir, s) = store_with(QuotaLimits::default(), true);
    let data = b"shared layer bytes";
    let d = sha256_of(data);
    s.put_blob("a", &d, data).await.unwrap();
    // Chunked finalize and monolithic put both link instead of copying.
    chunked(&s, "b", data).await.unwrap();
    s.put_blob("c", &d, data).await.unwrap();
    for repo in ["a", "b", "c"] {
        assert_eq!(s.read_blob(repo, &d).await.unwrap(), data);
    }
    // On a filesystem without reflink (CI ext4, APFS via this API) the
    // fallback is a hard link: one inode, three names.
    #[cfg(unix)]
    if link_count(&s, "a", &d) > 1 {
        assert_eq!(link_count(&s, "a", &d), 3);
    }
    // Deleting the canonical copy leaves the others intact; with no known
    // location left, the next arrival keeps its own copy.
    s.delete_blob("a", &d).await.unwrap();
    assert_eq!(s.read_blob("b", &d).await.unwrap(), data);
    s.put_blob("d", &d, data).await.unwrap();
    assert_eq!(s.read_blob("d", &d).await.unwrap(), data);
}

#[cfg(unix)]
#[tokio::test]
async fn dedupe_disabled_keeps_independent_copies() {
    let (_dir, s) = store_with(QuotaLimits::default(), false);
    let data = b"not shared";
    let d = sha256_of(data);
    s.put_blob("a", &d, data).await.unwrap();
    chunked(&s, "b", data).await.unwrap();
    assert_eq!(link_count(&s, "a", &d), 1);
    assert_eq!(link_count(&s, "b", &d), 1);
}

#[tokio::test]
async fn dedupe_falls_back_to_a_copy_when_the_located_blob_vanished() {
    let (dir, s) = store_with(QuotaLimits::default(), true);
    let data = b"stale location";
    let d = sha256_of(data);
    s.put_blob("a", &d, data).await.unwrap();
    // Remove the canonical copy behind roci's back: the index is stale.
    std::fs::remove_file(dir.path().join("a/blobs/sha256").join(d.hex())).unwrap();
    chunked(&s, "b", data).await.unwrap();
    assert_eq!(s.read_blob("b", &d).await.unwrap(), data);
    // The stale location was forgotten; "b" is now the canonical holder.
    assert_eq!(s.dedupe.locate(&d.as_string(), "z").as_deref(), Some("b"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dedupe_keeps_its_own_copy_when_linking_is_impossible() {
    let _serialize = FAULT_TEST_LOCK.lock().await;
    let (_dir, s) = store_with(QuotaLimits::default(), true);
    let data = b"cross-device";
    let d = sha256_of(data);
    s.put_blob("a", &d, data).await.unwrap();
    FORCE_COPY_FALLBACK.store(true, std::sync::atomic::Ordering::Relaxed);
    let staged = chunked(&s, "b", data).await;
    let put = s.put_blob("c", &d, data).await;
    FORCE_COPY_FALLBACK.store(false, std::sync::atomic::Ordering::Relaxed);
    staged.unwrap();
    put.unwrap();
    assert_eq!(link_count(&s, "b", &d), 1);
    assert_eq!(s.read_blob("c", &d).await.unwrap(), data);
}

#[tokio::test]
async fn checksum_is_recorded_at_write_carried_by_mount_and_dropped_on_delete() {
    let (_dir, s) = store_with(QuotaLimits::default(), false);
    let data = b"checksummed";
    let d = sha256_of(data);
    let expected = BlobChecksum {
        crc32c: crc32c::crc32c(data),
        size: data.len() as u64,
    };
    chunked(&s, "a", data).await.unwrap();
    assert_eq!(s.meta.checksum("a", &d.as_string()), Some(expected));
    s.put_blob("b", &d, data).await.unwrap();
    assert_eq!(s.meta.checksum("b", &d.as_string()), Some(expected));
    assert!(s.mount_blob("a", "c", &d).await.unwrap());
    assert_eq!(s.meta.checksum("c", &d.as_string()), Some(expected));
    s.delete_blob("a", &d).await.unwrap();
    assert_eq!(s.meta.checksum("a", &d.as_string()), None);
    assert_eq!(s.meta.checksum("b", &d.as_string()), Some(expected));
}

#[tokio::test]
async fn manifest_links_commit_atomically_and_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let layer = sha256_of(b"layer");
    let subject = sha256_of(b"subject");
    let body = br#"{"schemaVersion":2}"#;
    let m = sha256_of(body);
    {
        let s = FsStorage::new(dir.path()).unwrap();
        s.put_manifest(
            "r",
            Some("v1"),
            &m,
            "application/vnd.oci.image.manifest.v1+json",
            body,
            ManifestLinks {
                references: &[layer.clone(), subject.clone()],
                subject: Some((&subject, br#"{"artifactType":"a/b"}"#)),
            },
        )
        .await
        .unwrap();
    }
    let s = FsStorage::new(dir.path()).unwrap();
    assert_eq!(s.backrefs("r", &layer), vec![m.as_string()]);
    assert_eq!(s.backrefs("r", &subject), vec![m.as_string()]);
    let page = s
        .list_referrers("r", &subject, Some("a/b"), None, 10)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].0, m.as_string());
    // A malformed referrer descriptor is rejected before anything is stored.
    let other = br#"{"schemaVersion":2,"x":1}"#;
    assert!(matches!(
        s.put_manifest(
            "r",
            None,
            &sha256_of(other),
            "application/json",
            other,
            ManifestLinks {
                references: &[],
                subject: Some((&subject, b"not json")),
            },
        )
        .await,
        Err(StorageError::Io(_))
    ));
    assert!(!s.blob_exists("r", &sha256_of(other)).await.unwrap());
}
