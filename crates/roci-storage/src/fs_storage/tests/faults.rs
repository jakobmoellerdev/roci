use super::*;

#[tokio::test]
async fn mount_blob_promotes_and_reports_absence() {
    // Serialize against the fault-injection test so a forced fallback cannot
    // change the promotion mechanism mid-assertion and flake it.
    #[cfg(target_os = "linux")]
    let _serialize = FAULT_TEST_LOCK.lock().await;
    let (_dir, s) = store();
    let data = b"shared-layer";
    let d = sha256_of(data);
    s.put_blob("src", &d, data).await.unwrap();
    // Present source → mount promotes it into `dst` (reflink on
    // btrfs/XFS/APFS, else a hard link, else a streaming copy — all share
    // storage or copy the exact bytes). Assert the observable contract, not
    // the mechanism (which is filesystem-dependent): the mount succeeds and
    // the blob is byte-identical in the destination repo.
    assert!(s.mount_blob("src", "dst", &d).await.unwrap());
    assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
    // Both repos hold a real, independently-openable regular file for the
    // digest (reflink gives distinct inodes; a hard link shares one — either
    // way both paths resolve to a regular CAS blob with the right bytes).
    #[cfg(unix)]
    {
        for repo in ["src", "dst"] {
            let meta = std::fs::symlink_metadata(s.blob_path(repo, &d).unwrap()).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.len(), data.len() as u64);
        }
    }
    // Re-mounting an already-present destination is idempotent success (the
    // existing regular-file blob is validated no-follow, never re-copied).
    assert!(s.mount_blob("src", "dst", &d).await.unwrap());
    assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
    // Absent source → Ok(false) (caller falls back to a session).
    let absent = sha256_of(b"never-stored");
    assert!(!s.mount_blob("src", "dst", &absent).await.unwrap());
    // Idempotent re-mount stays correct.
    assert!(s.mount_blob("src", "dst", &d).await.unwrap());
    assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
}

#[cfg(unix)]
#[tokio::test]
async fn mount_hard_link_failure_falls_back_to_copy() {
    // A hard-link failure that is not AlreadyExists (here: a read-only
    // destination alg dir → EACCES) dispatches to the crash-atomic copy
    // fallback. In this fixture the copy's temp create also fails (the dir
    // is read-only), so the error propagates — exercising the fallback
    // dispatch without needing a second filesystem.
    use std::os::unix::fs::PermissionsExt;
    let (dir, s) = store();
    let data = b"mountable";
    let d = sha256_of(data);
    s.put_blob("src", &d, data).await.unwrap();
    s.ensure_layout("dst").await.unwrap();
    let alg = dir.path().join("dst").join("blobs").join("sha256");
    std::fs::create_dir_all(&alg).unwrap();
    std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(s.mount_blob("src", "dst", &d).await.is_err());
    // Restore perms so the tempdir cleans up.
    std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// Drive the reflink / hard-link / copy fallbacks of mount_promote_beneath and
// publish_bytes deterministically on a single filesystem via the FORCE_*
// seams — the branches CI's one filesystem cannot otherwise reach. Serialized
// so a forced fallback cannot flake a parallel mount test.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn mount_and_put_fallback_paths() {
    use std::sync::atomic::Ordering;
    let _serialize = FAULT_TEST_LOCK.lock().await;
    let data = b"fallback-blob";
    let d = sha256_of(data);
    // Every fallback lands the same bytes whether or not blob writes are
    // synced (`storage.commit`).
    for commit in [false, true] {
        let store = |dir: &tempfile::TempDir| {
            let cfg = roci_config::StorageConfig {
                commit,
                ..Default::default()
            };
            FsStorage::with_config(dir.path(), &cfg, Default::default()).unwrap()
        };

        // (1) Reflink + hard link forced off → mount takes the streaming copy.
        FORCE_COPY_FALLBACK.store(true, Ordering::Relaxed);
        let d1 = tempfile::tempdir().unwrap();
        let s1 = store(&d1);
        s1.put_blob("srcrepo", &d, data).await.unwrap();
        assert!(s1.mount_blob("srcrepo", "dstrepo", &d).await.unwrap());
        assert_eq!(s1.read_blob("dstrepo", &d).await.unwrap(), data);
        FORCE_COPY_FALLBACK.store(false, Ordering::Relaxed);

        // (2) Reflink forced to succeed → mount takes the reflink primary.
        FORCE_REFLINK_OK.store(true, Ordering::Relaxed);
        let d2 = tempfile::tempdir().unwrap();
        let s2 = store(&d2);
        s2.put_blob("srcrepo", &d, data).await.unwrap();
        assert!(s2.mount_blob("srcrepo", "dstrepo", &d).await.unwrap());
        assert_eq!(s2.read_blob("dstrepo", &d).await.unwrap(), data);
        FORCE_REFLINK_OK.store(false, Ordering::Relaxed);

        // (3) O_TMPFILE unsupported → put_blob takes the temp+rename fallback.
        FORCE_TMPFILE_UNSUPPORTED.store(true, Ordering::Relaxed);
        let d3 = tempfile::tempdir().unwrap();
        let s3 = store(&d3);
        let td = sha256_of(b"no-tmpfile-here");
        s3.put_blob("r", &td, b"no-tmpfile-here").await.unwrap();
        assert_eq!(s3.read_blob("r", &td).await.unwrap(), b"no-tmpfile-here");
        FORCE_TMPFILE_UNSUPPORTED.store(false, Ordering::Relaxed);
    }
}

// stat_beneath propagates a genuine leaf-stat IO error (not NOENT) as an
// error, exercised deterministically via the FORCE_STAT_ERROR seam.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn stat_beneath_propagates_io_error() {
    use std::sync::atomic::Ordering;
    let _serialize = FAULT_TEST_LOCK.lock().await;
    let (_dir, s) = store();
    let data = b"present-blob";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    FORCE_STAT_ERROR.store(true, Ordering::Relaxed);
    let res = s.blob_exists("r", &d).await;
    FORCE_STAT_ERROR.store(false, Ordering::Relaxed);
    assert!(matches!(res, Err(StorageError::Io(_))));
}

// dir_beneath propagates a genuine openat syscall error (not a symlink/
// NotFound) from its walk, exercised via the FORCE_SYSCALL_ERROR seam.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn dir_beneath_propagates_syscall_error() {
    use std::sync::atomic::Ordering;
    let _serialize = FAULT_TEST_LOCK.lock().await;
    let (_dir, s) = store();
    let d = sha256_of(b"blocked-write");
    FORCE_SYSCALL_ERROR.store(true, Ordering::Relaxed);
    let res = s.put_blob("r", &d, b"blocked-write").await;
    FORCE_SYSCALL_ERROR.store(false, Ordering::Relaxed);
    assert!(matches!(res, Err(StorageError::Io(_))));
}

// stream_copy is the portable fallback the in-kernel copy path uses on a
// cross-device/unsupported-fs mount. Exercise it directly: it rewinds and
// truncates the destination (dropping any partial kernel copy) and streams
// the full source across.
#[cfg(target_os = "linux")]
#[test]
fn stream_copy_rewinds_truncates_and_copies() {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let dir = tempfile::tempdir().unwrap();
    let src_path = dir.path().join("src");
    let dst_path = dir.path().join("dst");
    let payload = vec![0x42u8; 70000];
    std::fs::write(&src_path, &payload).unwrap();
    // Pre-seed the destination with stale bytes + a stale cursor to prove
    // stream_copy truncates and rewinds rather than appending.
    let mut dst = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dst_path)
        .unwrap();
    dst.write_all(b"stale-tail-that-must-be-dropped").unwrap();
    dst.seek(SeekFrom::End(0)).unwrap();
    let mut src = std::fs::File::open(&src_path).unwrap();
    stream_copy(&mut src, &mut dst).unwrap();
    let mut out = Vec::new();
    let mut check = std::fs::File::open(&dst_path).unwrap();
    check.read_to_end(&mut out).unwrap();
    assert_eq!(out, payload);
}

// Without `openat2` (pre-5.6 kernels, seccomp, non-Linux) every beneath-root
// open falls back to the per-component walk: the full blob lifecycle — and the
// symlink refusal — must behave identically on it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn beneath_walk_fallback_serves_the_full_lifecycle() {
    use std::sync::atomic::Ordering;
    let _serialize = FAULT_TEST_LOCK.lock().await;
    FORCE_NO_OPENAT2.store(true, Ordering::Relaxed);
    let (dir, s) = store();
    let data = b"walked";
    let d = sha256_of(data);
    let put = s.put_blob("team/r", &d, data).await;
    let read = s.read_blob("team/r", &d).await;
    let size = s.blob_size("team/r", &d).await;
    let alg = dir.path().join("team/r/blobs/sha256");
    std::fs::rename(&alg, dir.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("moved"), &alg).unwrap();
    let via_symlink = s.open_blob("team/r", &d).await.map(|_| ());
    FORCE_NO_OPENAT2.store(false, Ordering::Relaxed);
    put.unwrap();
    assert_eq!(read.unwrap(), data);
    assert_eq!(size.unwrap(), data.len() as u64);
    assert!(matches!(via_symlink, Err(StorageError::NotFound)));
}
