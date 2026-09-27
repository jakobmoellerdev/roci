#[cfg(target_os = "linux")]
use super::super::paths::blob_dir_rel;
use super::*;

// SECURITY: planted CAS symlink → no-follow rejects it as absent.
#[cfg(unix)]
#[tokio::test]
async fn planted_cas_symlink_is_not_present() {
    let (dir, s) = store();
    let secret = dir.path().join("outside-secret");
    std::fs::write(&secret, b"outside").unwrap();
    let d = sha256_of(b"outside");
    s.presence.insert("r", &d.as_string());
    let cas = s.blob_path("r", &d).unwrap();
    std::fs::create_dir_all(cas.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, &cas).unwrap();
    assert!(!s.blob_exists("r", &d).await.unwrap());
    assert!(matches!(
        s.blob_size("r", &d).await,
        Err(StorageError::NotFound)
    ));
    // Mounted destination is the symlink → rejected.
    s.put_blob("src", &d, b"outside").await.unwrap();
    assert!(matches!(
        s.mount_blob("src", "r", &d).await,
        Err(StorageError::BadPath(_))
    ));
}

// SECURITY: symlinked `blobs` parent → reads refuse to traverse.
#[cfg(unix)]
#[tokio::test]
async fn planted_parent_symlink_is_not_traversed() {
    let (dir, s) = store();
    let d = sha256_of(b"outside-bytes");
    let outside = dir.path().join("outside");
    let outside_blob = outside.join("blobs").join(d.algorithm()).join(d.hex());
    std::fs::create_dir_all(outside_blob.parent().unwrap()).unwrap();
    std::fs::write(&outside_blob, b"outside-bytes").unwrap();
    let repo_dir = s.repo_dir("r").unwrap();
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::os::unix::fs::symlink(outside.join("blobs"), repo_dir.join("blobs")).unwrap();
    s.presence.insert("r", &d.as_string());
    assert!(!s.blob_exists("r", &d).await.unwrap());
    assert!(matches!(
        s.blob_size("r", &d).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        s.read_blob("r", &d).await,
        Err(StorageError::NotFound)
    ));
    assert!(s.open_blob("r", &d).await.is_err());
}

// SECURITY: symlinked `blobs` parent → writes refuse to escape.
#[cfg(unix)]
#[tokio::test]
async fn put_blob_refuses_symlinked_parent() {
    let (dir, s) = store();
    let data = b"write-escape-attempt";
    let d = sha256_of(data);
    let outside = dir.path().join("outside-blobs");
    std::fs::create_dir_all(&outside).unwrap();
    let repo_dir = s.repo_dir("r").unwrap();
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::os::unix::fs::symlink(&outside, repo_dir.join("blobs")).unwrap();
    assert!(s.put_blob("r", &d, data).await.is_err());
    assert!(!outside.join(d.algorithm()).join(d.hex()).exists());
}

// SECURITY: O_NOFOLLOW on staging file prevents symlink redirect.
#[cfg(unix)]
#[tokio::test]
async fn append_refuses_symlinked_session() {
    let (dir, s) = store();
    let target = dir.path().join("append-target");
    std::fs::write(&target, b"").unwrap();
    let uploads = s.repo_dir("r").unwrap().join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    std::os::unix::fs::symlink(&target, uploads.join("evil")).unwrap();
    // ELOOP and redirect target untouched.
    assert!(s
        .append_upload("r", "evil", crate::upload_body(b"x"), None, u64::MAX)
        .await
        .is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"");
}

// SECURITY: EEXIST from linkat + non-regular file → rejected.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn put_blob_rejects_non_regular_eexist_destination() {
    let (dir, s) = store();
    let data = b"collide";
    let d = sha256_of(data);
    let dest = s.blob_path("r", &d).unwrap();
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, b"x").unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dest).unwrap();
    let err = s.put_blob("r", &d, data).await.unwrap_err();
    assert!(matches!(err, StorageError::Io(_)));
}

// Missing leaf in existing dir → absent (NOENT arm).
#[cfg(unix)]
#[tokio::test]
async fn stat_beneath_missing_leaf_in_existing_dir_is_absent() {
    let (_dir, s) = store();
    let present = sha256_of(b"present");
    s.put_blob("r", &present, b"present").await.unwrap();
    let absent = sha256_of(b"absent");
    s.presence.insert("r", &absent.as_string());
    assert!(!s.blob_exists("r", &absent).await.unwrap());
}

// SECURITY: symlinked source blob → mount refuses (no-follow fstat).
#[cfg(unix)]
#[tokio::test]
async fn mount_refuses_non_regular_source() {
    let (dir, s) = store();
    let d = sha256_of(b"src-bytes");
    // Plant a symlink at the source CAS path.
    s.presence.insert("src", &d.as_string());
    let src = s.blob_path("src", &d).unwrap();
    std::fs::create_dir_all(src.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), &src).unwrap();
    // Not a regular file → no blob promoted.
    let _ = s.mount_blob("src", "dst", &d).await;
    assert!(!std::fs::symlink_metadata(s.blob_path("dst", &d).unwrap())
        .map(|m| m.is_file())
        .unwrap_or(false));
}

// EACCES on read-only CAS parent → Io error, not false 404.
#[cfg(unix)]
#[tokio::test]
async fn write_through_readonly_parent_is_io_error() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, s) = store();
    let blobs = s.repo_dir("r").unwrap().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o500)).unwrap();
    let d = sha256_of(b"blocked");
    let res = s.put_blob("r", &d, b"blocked").await;
    let _ = std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755));
    // Root bypasses mode bits; unprivileged gets Io error.
    if let Err(e) = res {
        assert!(matches!(e, StorageError::Io(_)));
    }
}

// EACCES on unsearchable alg dir → Io error, not false 404.
#[cfg(unix)]
#[tokio::test]
async fn read_through_unsearchable_parent_is_io_error() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, s) = store();
    let d = sha256_of(b"present");
    s.put_blob("r", &d, b"present").await.unwrap();
    let alg = s.repo_dir("r").unwrap().join("blobs").join(d.algorithm());
    std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o000)).unwrap();
    let read = s.read_blob("r", &d).await;
    let sized = s.blob_size("r", &d).await;
    let _ = std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755));
    // Unprivileged: EACCES → Io. Root: succeeds.
    for r in [read.map(|_| ()), sized.map(|_| ())] {
        if let Err(e) = r {
            assert!(matches!(e, StorageError::Io(_)));
        }
    }
}

// FIFO at blob leaf → rejected (NotFound), never blocks.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn read_beneath_rejects_fifo_leaf() {
    let (_dir, s) = store();
    let d = sha256_of(b"fifo-victim");
    let leaf_path = s.blob_path("r", &d).unwrap();
    std::fs::create_dir_all(leaf_path.parent().unwrap()).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &leaf_path,
        rustix::fs::Mode::from_raw_mode(0o644),
    )
    .unwrap();
    s.presence.insert("r", &d.as_string());
    assert!(matches!(
        s.read_blob("r", &d).await,
        Err(StorageError::NotFound)
    ));
    assert!(s.open_blob("r", &d).await.is_err());
}

// Empty relative path → absent (no-op guard).
#[cfg(unix)]
#[tokio::test]
async fn stat_beneath_empty_rel_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(stat_beneath(dir.path(), Path::new(""))
        .await
        .unwrap()
        .is_none());
}

// SECURITY: EEXIST + symlink at digest leaf → publish_bytes rejects.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn publish_bytes_rejects_non_regular_eexist() {
    let (dir, s) = store();
    let data = b"collide";
    let d = sha256_of(data);
    let (alg_rel, leaf) = blob_dir_rel("r", &d).unwrap();
    let alg_abs = dir.path().join(&alg_rel);
    std::fs::create_dir_all(&alg_abs).unwrap();
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), alg_abs.join(&leaf)).unwrap();
    let err = publish_bytes(&s.root, &alg_rel, &leaf, data, true)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

// Mismatched inode → rename_beneath returns NotFound.
#[cfg(unix)]
#[tokio::test]
async fn rename_beneath_rejects_inode_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("from")).unwrap();
    std::fs::write(root.join("from/leaf"), b"data").unwrap();
    let err = crate::beneath::rename_beneath_sync(
        root.to_path_buf(),
        "from".into(),
        "leaf".into(),
        "to".into(),
        "leaf".into(),
        (0, 0), // wrong inode
        true,
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(unix)]
fn plant_rename_pair(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("dst")).unwrap();
    std::fs::write(root.join("src/blob"), b"content").unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn rename_beneath_eexist_regular_file_is_idempotent() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    plant_rename_pair(dir.path());
    std::fs::write(dir.path().join("dst/blob"), b"content").unwrap();
    let st = std::fs::metadata(dir.path().join("src/blob")).unwrap();
    let ino = (st.dev(), st.ino());
    crate::beneath::rename_beneath_sync(
        dir.path().to_path_buf(),
        "src".into(),
        "blob".into(),
        "dst".into(),
        "blob".into(),
        ino,
        true,
    )
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn rename_beneath_eexist_symlink_is_rejected() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    plant_rename_pair(dir.path());
    std::os::unix::fs::symlink(dir.path().join("outside"), dir.path().join("dst/blob")).unwrap();
    let st = std::fs::metadata(dir.path().join("src/blob")).unwrap();
    let ino = (st.dev(), st.ino());
    let err = crate::beneath::rename_beneath_sync(
        dir.path().to_path_buf(),
        "src".into(),
        "blob".into(),
        "dst".into(),
        "blob".into(),
        ino,
        true,
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

// Non-regular oci-layout → AlreadyExists error.
#[cfg(unix)]
#[tokio::test]
async fn ensure_layout_beneath_rejects_non_regular_oci_layout() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let repo_dir = root.join("evil");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::fs::create_dir_all(repo_dir.join("oci-layout")).unwrap();
    let err = crate::beneath::ensure_layout_beneath(
        root,
        Path::new("evil"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

// dir_beneath race: symlink replaces dir → LOOP → NotFound.
#[cfg(unix)]
#[tokio::test]
async fn dir_beneath_race_replace_with_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::os::unix::fs::symlink(root.join("outside"), root.join("link")).unwrap();
    let err = crate::beneath::dir_beneath(root, Path::new("link/sub"), true).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

// blob_size returns NotFound when CAS entry is a directory (not a regular file).
#[cfg(unix)]
#[tokio::test]
async fn blob_size_returns_not_found_for_directory_at_blob_path() {
    let (_dir, s) = store();
    let data = b"will-be-replaced-by-dir";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    // Remove the checksum so blob_size falls through to stat_beneath.
    s.meta
        .apply_relaxed(crate::MetaOp::DeleteBlob {
            repo: "r".to_string(),
            digest: d.as_string(),
        })
        .unwrap();
    // Replace the blob file with a directory.
    let blob_path = s.blob_path("r", &d).unwrap();
    std::fs::remove_file(&blob_path).unwrap();
    std::fs::create_dir(&blob_path).unwrap();
    assert!(matches!(
        s.blob_size("r", &d).await,
        Err(StorageError::NotFound)
    ));
}

// stat_beneath with missing parent directory → Ok(None).
#[cfg(unix)]
#[tokio::test]
async fn stat_beneath_missing_parent_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Path with missing parent: "no_such_parent/leaf"
    let rel = std::path::PathBuf::from("no_such_parent/leaf");
    let result = crate::beneath::stat_beneath(root, &rel).await.unwrap();
    assert_eq!(result, None, "missing parent → None");
}
