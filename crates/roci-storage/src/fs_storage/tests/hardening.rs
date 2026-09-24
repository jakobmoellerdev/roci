#[cfg(target_os = "linux")]
use super::super::paths::blob_dir_rel;
use super::*;

// A planted symlink under the CAS name is not a valid blob: blob_exists and
// blob_size report it absent (no-follow), so it can never satisfy a
// manifest's referenced-blob check nor be served as a repo's content.
#[cfg(unix)]
#[tokio::test]
async fn planted_cas_symlink_is_not_present() {
    let (dir, s) = store();
    let secret = dir.path().join("outside-secret");
    std::fs::write(&secret, b"outside").unwrap();
    let d = sha256_of(b"outside");
    // Force the presence filter to say "maybe" so the stat path runs.
    s.presence.insert("r", &d.as_string());
    let cas = s.blob_path("r", &d).unwrap();
    std::fs::create_dir_all(cas.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&secret, &cas).unwrap();
    assert!(!s.blob_exists("r", &d).await.unwrap());
    assert!(matches!(
        s.blob_size("r", &d).await,
        Err(StorageError::NotFound)
    ));
    // A mount whose destination is the planted symlink is rejected, not a
    // false 201.
    s.put_blob("src", &d, b"outside").await.unwrap();
    assert!(matches!(
        s.mount_blob("src", "r", &d).await,
        Err(StorageError::BadPath(_))
    ));
}

// A symlinked *parent* directory (not just the leaf) must not let an external
// file be seen/served as a CAS blob: the beneath-root resolver opens every
// component no-follow, so a `blobs` symlink pointing outside the store is
// rejected by blob_exists / blob_size / read_blob alike.
#[cfg(unix)]
#[tokio::test]
async fn planted_parent_symlink_is_not_traversed() {
    let (dir, s) = store();
    // An outside tree holding a file at the exact CAS-relative sub-path.
    let d = sha256_of(b"outside-bytes");
    let outside = dir.path().join("outside");
    let outside_blob = outside.join("blobs").join(d.algorithm()).join(d.hex());
    std::fs::create_dir_all(outside_blob.parent().unwrap()).unwrap();
    std::fs::write(&outside_blob, b"outside-bytes").unwrap();
    // Repo dir exists but its `blobs` is a symlink to the outside tree.
    let repo_dir = s.repo_dir("r").unwrap();
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::os::unix::fs::symlink(outside.join("blobs"), repo_dir.join("blobs")).unwrap();
    s.presence.insert("r", &d.as_string());
    // Every read surface refuses to traverse the symlinked `blobs` parent.
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

// The *write* side is beneath-root too: a symlinked `blobs` parent must not
// let put_blob create the blob outside the store, and delete_blob must not
// follow it. The dirfd walk refuses to descend a symlinked component, so the
// write fails rather than escaping.
#[cfg(unix)]
#[tokio::test]
async fn put_blob_refuses_symlinked_parent() {
    let (dir, s) = store();
    let data = b"write-escape-attempt";
    let d = sha256_of(data);
    // Point the repo's `blobs` at an outside directory via a symlink.
    let outside = dir.path().join("outside-blobs");
    std::fs::create_dir_all(&outside).unwrap();
    let repo_dir = s.repo_dir("r").unwrap();
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::os::unix::fs::symlink(&outside, repo_dir.join("blobs")).unwrap();
    // put_blob must refuse to write through the symlinked `blobs` parent.
    assert!(s.put_blob("r", &d, data).await.is_err());
    // Nothing was created under the outside target.
    assert!(!outside.join(d.algorithm()).join(d.hex()).exists());
}

// A PATCH append opens the staging file O_NOFOLLOW: a symlink planted at
// `uploads/<id>` cannot redirect the append to an arbitrary target.
#[cfg(unix)]
#[tokio::test]
async fn append_refuses_symlinked_session() {
    let (dir, s) = store();
    let target = dir.path().join("append-target");
    std::fs::write(&target, b"").unwrap();
    let uploads = s.repo_dir("r").unwrap().join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    std::os::unix::fs::symlink(&target, uploads.join("evil")).unwrap();
    // Appending to the symlinked session fails (O_NOFOLLOW → ELOOP), and the
    // redirect target is left untouched.
    assert!(s.append_upload("r", "evil", b"x", None).await.is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"");
}

// put_blob's O_TMPFILE+linkat hits EEXIST when the digest name already
// exists, but if that entry is NOT a regular file (a planted symlink) it is
// rejected, never reported as dedup success.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn put_blob_rejects_non_regular_eexist_destination() {
    let (dir, s) = store();
    let data = b"collide";
    let d = sha256_of(data);
    // Pre-plant a symlink at the exact CAS destination so linkat → EEXIST.
    let dest = s.blob_path("r", &d).unwrap();
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, b"x").unwrap();
    std::os::unix::fs::symlink(&elsewhere, &dest).unwrap();
    let err = s.put_blob("r", &d, data).await.unwrap_err();
    assert!(matches!(err, StorageError::Io(_)));
}

// stat_beneath returns absent for a leaf whose parent dir exists but the
// leaf itself is missing (exercises the leaf openat/statat NOENT arm).
#[cfg(unix)]
#[tokio::test]
async fn stat_beneath_missing_leaf_in_existing_dir_is_absent() {
    let (_dir, s) = store();
    // Materialise `r/blobs/sha256` by storing one blob, then stat a
    // *different* sha256 digest (same alg dir, absent leaf).
    let present = sha256_of(b"present");
    s.put_blob("r", &present, b"present").await.unwrap();
    let absent = sha256_of(b"absent");
    s.presence.insert("r", &absent.as_string());
    assert!(!s.blob_exists("r", &absent).await.unwrap());
}

// A non-regular *source* blob (a planted symlink) is refused by mount: the
// source is opened no-follow and fstat-checked for a regular file.
#[cfg(unix)]
#[tokio::test]
async fn mount_refuses_non_regular_source() {
    let (dir, s) = store();
    let d = sha256_of(b"src-bytes");
    // Force the presence filter to admit the source, then plant a symlink at
    // the source CAS path so mount's no-follow source open/ fstat rejects it.
    s.presence.insert("src", &d.as_string());
    let src = s.blob_path("src", &d).unwrap();
    std::fs::create_dir_all(src.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), &src).unwrap();
    // Source "exists" per the filter but is not a regular file → the mount's
    // source resolution reports it absent (Ok(false)) or errors; either way
    // no blob is promoted into `dst`.
    let _ = s.mount_blob("src", "dst", &d).await;
    assert!(!std::fs::symlink_metadata(s.blob_path("dst", &d).unwrap())
        .map(|m| m.is_file())
        .unwrap_or(false));
}

// A read-only CAS parent makes the beneath-root dirfd operations fail with a
// genuine EACCES (not NotFound), which surfaces as an IO error rather than a
// false 404 — exercising the `Err(e)` syscall-error arms of the dirfd walk
// and promotion. Runs as the unprivileged test user (root bypasses mode bits).
#[cfg(unix)]
#[tokio::test]
async fn write_through_readonly_parent_is_io_error() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, s) = store();
    // Create `r/blobs` read-only so creating `<alg>` under it fails EACCES.
    let blobs = s.repo_dir("r").unwrap().join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o500)).unwrap();
    let d = sha256_of(b"blocked");
    let res = s.put_blob("r", &d, b"blocked").await;
    // Restore perms so the tempdir can be cleaned up.
    let _ = std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755));
    // Root (if the suite runs privileged) bypasses mode bits and succeeds;
    // the unprivileged CI/test user gets an IO error. Accept either, but a
    // failure must be an Io error, never a spurious NotFound.
    if let Err(e) = res {
        assert!(matches!(e, StorageError::Io(_)));
    }
}

// A read through an unsearchable intermediate CAS dir (mode 0o000) hits a
// genuine EACCES in the beneath-root open/stat walk (not NotFound) — an IO
// error, never a false 404. Unprivileged test user only (root bypasses).
#[cfg(unix)]
#[tokio::test]
async fn read_through_unsearchable_parent_is_io_error() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, s) = store();
    let d = sha256_of(b"present");
    s.put_blob("r", &d, b"present").await.unwrap();
    // Make the `<alg>` dir unsearchable so opening/stat-ing the leaf EACCES.
    let alg = s.repo_dir("r").unwrap().join("blobs").join(d.algorithm());
    std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o000)).unwrap();
    let read = s.read_blob("r", &d).await;
    let sized = s.blob_size("r", &d).await;
    let _ = std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755));
    // Unprivileged: EACCES → Io. Privileged (root): succeeds. Never a false
    // NotFound on a genuine permission error.
    for r in [read.map(|_| ()), sized.map(|_| ())] {
        if let Err(e) = r {
            assert!(matches!(e, StorageError::Io(_)));
        }
    }
}

// open_beneath rejects a non-regular final entry: a FIFO planted at a blob
// leaf must not be opened (a read would block / return non-CAS bytes).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn read_beneath_rejects_fifo_leaf() {
    let (_dir, s) = store();
    let d = sha256_of(b"fifo-victim");
    let leaf_path = s.blob_path("r", &d).unwrap();
    std::fs::create_dir_all(leaf_path.parent().unwrap()).unwrap();
    // Plant a FIFO at the digest leaf (rustix mkfifoat, CWD + absolute path).
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &leaf_path,
        rustix::fs::Mode::from_raw_mode(0o644),
    )
    .unwrap();
    s.presence.insert("r", &d.as_string());
    // Reads refuse the non-regular entry (NotFound), never blocking.
    assert!(matches!(
        s.read_blob("r", &d).await,
        Err(StorageError::NotFound)
    ));
    assert!(s.open_blob("r", &d).await.is_err());
}

// stat_beneath on an empty relative path is a no-op absent (defensive guard
// for a path with no components).
#[cfg(unix)]
#[tokio::test]
async fn stat_beneath_empty_rel_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(stat_beneath(dir.path(), Path::new(""))
        .await
        .unwrap()
        .is_none());
}

// publish_bytes rejects an EEXIST destination that is not a regular file:
// a symlink planted at the digest leaf (inside a valid, beneath-root alg
// dir) makes `linkat` return EEXIST, and the no-follow fstat then refuses it
// rather than reporting false dedup success.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn publish_bytes_rejects_non_regular_eexist() {
    let (dir, s) = store();
    let data = b"collide";
    let d = sha256_of(data);
    let (alg_rel, leaf) = blob_dir_rel("r", &d).unwrap();
    // Materialise the alg dir and plant a symlink at the digest leaf.
    let alg_abs = dir.path().join(&alg_rel);
    std::fs::create_dir_all(&alg_abs).unwrap();
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), alg_abs.join(&leaf)).unwrap();
    let err = publish_bytes(&s.root, &alg_rel, &leaf, data)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

// rename_beneath rejects a mismatched inode: calling it with a wrong
// expected_ino reports NotFound (beneath.rs line 206).
#[cfg(unix)]
#[tokio::test]
async fn rename_beneath_rejects_inode_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("from")).unwrap();
    std::fs::write(root.join("from/leaf"), b"data").unwrap();
    let err = crate::beneath::rename_beneath(
        root,
        Path::new("from"),
        "leaf",
        Path::new("to"),
        "leaf",
        (0, 0), // wrong inode
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

// rename_beneath with a pre-existing regular-file destination: EEXIST → Ok
// (idempotent dedup, beneath.rs lines 225-229).
#[cfg(unix)]
#[tokio::test]
async fn rename_beneath_eexist_regular_file_is_idempotent() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("dst")).unwrap();
    std::fs::write(root.join("src/blob"), b"content").unwrap();
    std::fs::write(root.join("dst/blob"), b"content").unwrap();
    let st = std::fs::metadata(root.join("src/blob")).unwrap();
    let ino = (st.dev(), st.ino());
    // Destination already exists as a regular file → Ok (idempotent).
    crate::beneath::rename_beneath(
        root,
        Path::new("src"),
        "blob",
        Path::new("dst"),
        "blob",
        ino,
    )
    .await
    .unwrap();
}

// rename_beneath with a pre-existing non-regular destination (symlink):
// EEXIST + stat shows not a file → AlreadyExists error (beneath.rs lines 231-234).
#[cfg(unix)]
#[tokio::test]
async fn rename_beneath_eexist_symlink_is_rejected() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("dst")).unwrap();
    std::fs::write(root.join("src/blob"), b"data").unwrap();
    // Plant a symlink at the destination.
    std::os::unix::fs::symlink(root.join("outside"), root.join("dst/blob")).unwrap();
    let st = std::fs::metadata(root.join("src/blob")).unwrap();
    let ino = (st.dev(), st.ino());
    let err = crate::beneath::rename_beneath(
        root,
        Path::new("src"),
        "blob",
        Path::new("dst"),
        "blob",
        ino,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

// ensure_layout_beneath with a non-regular oci-layout (e.g. a directory):
// returns AlreadyExists error (beneath.rs lines 313-316).
#[cfg(unix)]
#[tokio::test]
async fn ensure_layout_beneath_rejects_non_regular_oci_layout() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let repo_dir = root.join("evil");
    std::fs::create_dir_all(&repo_dir).unwrap();
    // Plant a directory named `oci-layout`.
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

// dir_beneath with create=true, when a racer replaces a just-created dir with
// a symlink: the re-open yields LOOP/NOTDIR → NotFound (beneath.rs lines 153-154).
#[cfg(unix)]
#[tokio::test]
async fn dir_beneath_race_replace_with_symlink() {
    // Simulate the race by creating a symlink at a component before calling
    // dir_beneath (the mkdir finds EEXIST, then re-open hits LOOP).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::os::unix::fs::symlink(root.join("outside"), root.join("link")).unwrap();
    // dir_beneath with create=true tries mkdir("link") → EEXIST, then re-opens → LOOP → NotFound.
    let err = crate::beneath::dir_beneath(root, Path::new("link/sub"), true).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
