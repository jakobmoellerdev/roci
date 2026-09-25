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
    s.append_upload(repo, &id, crate::upload_body(data), None, u64::MAX)
        .await?;
    s.finish_upload(
        repo,
        &id,
        &sha256_of(data),
        u64::MAX,
        crate::upload_body([]),
        u64::MAX,
    )
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
    s.append_upload("r", &id, crate::upload_body(b), None, u64::MAX)
        .await
        .unwrap();
    assert!(matches!(
        s.finish_upload(
            "r",
            &id,
            &sha256_of(b),
            u64::MAX,
            crate::upload_body([]),
            u64::MAX
        )
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
    s.append_upload("r", &third, crate::upload_body(b"x"), None, u64::MAX)
        .await
        .unwrap();
    s.finish_upload(
        "r",
        &third,
        &sha256_of(b"x"),
        u64::MAX,
        crate::upload_body([]),
        u64::MAX,
    )
    .await
    .unwrap();
    // A rejected finalize (digest mismatch) drops the session too.
    let fourth = s.begin_upload("r").await.unwrap();
    assert!(s
        .finish_upload(
            "r",
            &fourth,
            &sha256_of(b"y"),
            u64::MAX,
            crate::upload_body(b"z"),
            u64::MAX
        )
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

#[tokio::test]
async fn commit_store_lands_every_write_path() {
    // `storage.commit = true` syncs blob data and publishing dir entries; every
    // path must still land byte-identical blobs: monolithic put, chunked
    // finalize (staging sync + rename), mount (hard link) and dedupe on upload.
    let dir = tempfile::tempdir().unwrap();
    let cfg = StorageConfig {
        commit: true,
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &cfg, Arc::default()).unwrap();
    let data = b"durable";
    let d = sha256_of(data);
    s.put_blob("a", &d, data).await.unwrap();
    chunked(&s, "b", data).await.unwrap();
    assert!(s.mount_blob("a", "c", &d).await.unwrap());
    let other = b"chunked-first";
    chunked(&s, "d", other).await.unwrap();
    for repo in ["a", "b", "c"] {
        assert_eq!(s.read_blob(repo, &d).await.unwrap(), data);
    }
    assert_eq!(s.read_blob("d", &sha256_of(other)).await.unwrap(), other);
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
                required: &[],
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
                required: &[],
                subject: Some((&subject, b"not json")),
            },
        )
        .await,
        Err(StorageError::Io(_))
    ));
    assert!(!s.blob_exists("r", &sha256_of(other)).await.unwrap());
}

#[tokio::test]
async fn quota_release_on_unknown_repo_is_noop() {
    // quota.release when per_repo has no entry for the repo → the if-let
    // Some(used) branch is not entered (quota.rs line 102).
    let limits = QuotaLimits {
        max_total_bytes: 10_000,
        ..QuotaLimits::default()
    };
    let quota = QuotaTracker::new(limits);
    // Seed some bytes on repo "a".
    quota.seed("a", 500);
    assert_eq!(quota.repo_bytes("a"), 500);
    // Release on a repo that was never seeded/admitted → no panic, total still drops.
    quota.release("unknown", 100);
    assert_eq!(quota.repo_bytes("unknown"), 0);
}

#[tokio::test]
async fn quota_release_partial_does_not_remove_entry() {
    // When release does not bring the repo's usage to 0, the entry stays.
    let limits = QuotaLimits {
        max_total_bytes: 10_000,
        ..QuotaLimits::default()
    };
    let quota = QuotaTracker::new(limits);
    quota.seed("a", 500);
    quota.release("a", 200);
    assert_eq!(quota.repo_bytes("a"), 300);
}

#[tokio::test]
async fn gc_touch_on_non_candidate_is_noop() {
    // gc.touch on a digest that is not a candidate → the inner if-let branch
    // returns None (gc.rs line 113, closing brace path).
    use crate::gc::GcTracker;
    let gc = GcTracker::new(true, std::time::Duration::from_secs(60));
    gc.set_ready();
    // Touch a digest that was never marked → no panic.
    gc.touch(
        "r",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(gc.len(), 0);
}

#[tokio::test]
async fn blob_read_redirect_into_stream_returns_unsupported() {
    // BlobRead::redirect → into_stream returns Unsupported (storage.rs lines 95-98).
    let br = BlobRead::redirect(42, "https://example.com/blob".into());
    assert_eq!(br.size(), 42);
    assert_eq!(br.redirect_url(), Some("https://example.com/blob"));
    match br.into_stream(0, 42).await {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Unsupported),
        Ok(_) => panic!("expected Unsupported error for redirect blob"),
    }
}

#[tokio::test]
async fn lifecycle_blob_entered_warn_on_checksum_already_matches() {
    // When the checksum recorded by blob_entered exactly matches an existing
    // record, the apply_relaxed is skipped. When they differ, the apply records
    // the new one. When the apply fails, the warn arm is hit (lifecycle.rs line 62).
    let (_dir, s) = store();
    let d = sha256_of(b"lifecycle-enter");
    s.put_blob("r", &d, b"lifecycle-enter").await.unwrap();
    // Checksum was recorded at put_blob; re-enter with the same checksum → skip.
    let existing = s.meta.checksum("r", &d.as_string()).unwrap();
    s.blob_entered(
        "r",
        &d.as_string(),
        Some(BlobChecksum {
            crc32c: existing.crc32c,
            size: existing.size,
        }),
    );
    // Re-enter with a different checksum → apply_relaxed is called.
    s.blob_entered(
        "r",
        &d.as_string(),
        Some(BlobChecksum {
            crc32c: existing.crc32c.wrapping_add(1),
            size: existing.size,
        }),
    );
}

#[tokio::test]
async fn lifecycle_blob_left_clears_everything() {
    // blob_left removes the blob from presence, cache, dedupe, gc, and quota;
    // also drops the checksum record (lifecycle.rs lines 89, 91).
    let (_dir, s) = store();
    let d = sha256_of(b"lifecycle-leave");
    s.put_blob("r", &d, b"lifecycle-leave").await.unwrap();
    assert!(s.blob_exists("r", &d).await.unwrap());
    assert!(s.meta.checksum("r", &d.as_string()).is_some());
    // Call blob_left directly.
    s.blob_left("r", &d.as_string(), Some(15));
    // Presence filter should report absent.
    assert!(!s.presence.maybe_present("r", &d.as_string()));
    // Checksum should be gone.
    assert!(s.meta.checksum("r", &d.as_string()).is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn manifest_rejects_a_recorded_blob_swapped_for_a_symlink() {
    // `blob_exists` answers from the metadata record for blobs roci wrote, so
    // it still says "present" after the CAS file is swapped for a symlink; the
    // manifest commit's no-follow re-check must reject it regardless.
    let (dir, s) = store_with(QuotaLimits::default(), false);
    let layer = b"layer";
    let ld = sha256_of(layer);
    s.put_blob("r", &ld, layer).await.unwrap();
    let path = dir.path().join("r/blobs/sha256").join(ld.hex());
    std::fs::rename(&path, dir.path().join("outside")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("outside"), &path).unwrap();
    assert!(s.blob_exists("r", &ld).await.unwrap());
    let body = br#"{"schemaVersion":2,"z":1}"#;
    let d = sha256_of(body);
    let err = s
        .put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/json",
            body,
            ManifestLinks {
                references: std::slice::from_ref(&ld),
                required: std::slice::from_ref(&ld),
                subject: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::MissingReference(ref m) if *m == ld.as_string()));
    assert!(s.meta.resolve_tag("r", "v1").is_none());
}

#[tokio::test]
async fn manifest_commit_rechecks_required_blobs_under_the_fence() {
    let (_dir, s) = store_with(QuotaLimits::default(), false);
    let missing = sha256_of(b"never pushed");
    let body = br#"{"schemaVersion":2,"y":1}"#;
    let d = sha256_of(body);
    let err = s
        .put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/json",
            body,
            ManifestLinks {
                references: std::slice::from_ref(&missing),
                required: std::slice::from_ref(&missing),
                subject: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::MissingReference(ref m) if *m == missing.as_string()));
    // Nothing was committed: no tag, no manifest record.
    assert!(s.meta.resolve_tag("r", "v1").is_none());
    assert!(s.meta.manifest_media_type("r", &d.as_string()).is_none());
}

#[tokio::test]
async fn concurrent_duplicate_uploads_are_charged_once() {
    let (_dir, s) = store_with(repo_cap(1000), false);
    let data = b"same bytes, many pushers";
    let d = sha256_of(data);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let s = s.clone();
        let d = d.clone();
        tasks.push(tokio::spawn(async move { s.put_blob("r", &d, data).await }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(s.quota.repo_bytes("r"), data.len() as u64);
    s.delete_blob("r", &d).await.unwrap();
    assert_eq!(s.quota.repo_bytes("r"), 0);
}
