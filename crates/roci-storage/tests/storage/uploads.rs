use super::common::store;
use roci_storage::*;

#[tokio::test]
async fn upload_session_finalizes_into_cas() {
    let (_dir, s) = store();
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, b"chunk1", None).await.unwrap();
    let total = s.append_upload("r", &id, b"chunk2", None).await.unwrap();
    assert_eq!(total, 12);
    let d = sha256_of(b"chunk1chunk2");
    s.finish_upload("r", &id, &d, u64::MAX, b"").await.unwrap();
    assert_eq!(s.read_blob("r", &d).await.unwrap(), b"chunk1chunk2");
}

#[tokio::test]
async fn blob_delete_and_finish_upload_mismatch() {
    let (_dir, s) = store();
    let data = b"deleteme";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    s.delete_blob("r", &d).await.unwrap();
    assert!(matches!(
        s.delete_blob("r", &d).await,
        Err(StorageError::NotFound)
    ));

    // finish_upload with a wrong expected digest is rejected.
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, b"abc", None).await.unwrap();
    let wrong = sha256_of(b"xyz");
    assert!(matches!(
        s.finish_upload("r", &id, &wrong, u64::MAX, b"").await,
        Err(StorageError::DigestMismatch { .. })
    ));
    // Missing upload session size / append errors are NotFound.
    assert!(matches!(
        s.upload_size("r", "nope").await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        s.append_upload("r", "nope", b"x", None).await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn upload_size_errors_when_session_path_is_a_dir() {
    let (dir, s) = store();
    // Create an "upload" that is actually a directory; finish_upload's
    // non-regular-file guard rejects it as a bad path before hashing.
    let up = dir.path().join("r").join("uploads").join("dir-session");
    std::fs::create_dir_all(&up).unwrap();
    let d = sha256_of(b"x");
    assert!(matches!(
        s.finish_upload("r", "dir-session", &d, u64::MAX, b"").await,
        Err(StorageError::BadPath(_))
    ));
}

#[tokio::test]
async fn begin_upload_ids_are_distinct_random_hex() {
    let (_dir, s) = store();
    let a = s.begin_upload("r").await.unwrap();
    let b = s.begin_upload("r").await.unwrap();
    assert_ne!(a, b);
    // 128 random bits → 32 lowercase hex chars.
    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
}

// finish_upload re-checks the per-session cap under the lock: a staging file
// that grew past the cap is rejected (413/SIZE_INVALID → TooLarge) and
// dropped, so a racing empty-body PUT cannot promote an oversized blob.
#[tokio::test]
async fn finish_upload_rejects_over_cap_staging() {
    let (_dir, s) = store();
    let data = b"0123456789";
    let d = sha256_of(data);
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, data, None).await.unwrap();
    // Cap below the staged size → finalize rejects and drops the session.
    assert!(matches!(
        s.finish_upload("r", &id, &d, 4, b"").await,
        Err(StorageError::TooLarge {
            limit: 4,
            actual: 10
        })
    ));
    assert!(matches!(
        s.upload_size("r", &id).await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn abort_upload_is_idempotent() {
    let (dir, s) = store();
    let id = s.begin_upload("r").await.unwrap();
    // First abort removes the staging file; a second is a no-op Ok(false).
    assert!(s.abort_upload("r", &id).await.unwrap());
    assert!(!s.abort_upload("r", &id).await.unwrap());
    // A session id that names a directory yields a non-NotFound IO error.
    let uploads = dir.path().join("r").join("uploads");
    tokio::fs::create_dir_all(uploads.join("dirsess"))
        .await
        .unwrap();
    assert!(matches!(
        s.abort_upload("r", "dirsess").await,
        Err(StorageError::Io(_))
    ));
}

#[tokio::test]
async fn finish_upload_honors_sha512_digest() {
    let (_dir, s) = store();
    let data = b"sha512-streamed-blob";
    // A sha512 upload exercises the sha512 branch of the streaming hasher.
    let d = digest_of(data, "sha512");
    assert_eq!(d.algorithm(), "sha512");
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, data, None).await.unwrap();
    s.finish_upload("r", &id, &d, u64::MAX, b"").await.unwrap();
    assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    // A sha512 mismatch is rejected by the streamed verify.
    let id2 = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id2, b"different", None)
        .await
        .unwrap();
    assert!(matches!(
        s.finish_upload("r", &id2, &d, u64::MAX, b"").await,
        Err(StorageError::DigestMismatch { .. })
    ));
}

#[tokio::test]
async fn append_upload_enforces_content_range_offset() {
    let (_dir, s) = store();
    let id = s.begin_upload("r").await.unwrap();
    // First chunk at offset 0 is accepted.
    assert_eq!(s.append_upload("r", &id, b"abc", Some(0)).await.unwrap(), 3);
    // A chunk whose declared offset does not match the current size (3) is
    // rejected under the lock.
    assert!(matches!(
        s.append_upload("r", &id, b"de", Some(0)).await,
        Err(StorageError::RangeNotSatisfiable {
            expected: 3,
            got: 0
        })
    ));
    // The correct offset (3) is accepted.
    assert_eq!(s.append_upload("r", &id, b"de", Some(3)).await.unwrap(), 5);
}

// finish_upload on an id that was never begun (no staging file) resolves to
// absent beneath the root → NotFound, and drops the session lock.
#[tokio::test]
async fn finish_upload_missing_session_is_not_found() {
    let (_dir, s) = store();
    let d = sha256_of(b"never-staged");
    assert!(matches!(
        s.finish_upload("r", "ghost", &d, u64::MAX, b"").await,
        Err(StorageError::NotFound)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn finish_rejects_non_regular_staging_file() {
    // A staging entry that is a symlink (not a regular file) is rejected by
    // finish_upload's no-follow guard, never hashed-through and promoted.
    use std::os::unix::fs::symlink;
    let (dir, s) = store();
    let uploads = dir.path().join("r").join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    let target = dir.path().join("outside-secret");
    std::fs::write(&target, b"secret").unwrap();
    symlink(&target, uploads.join("linksess")).unwrap();
    let d = sha256_of(b"secret");
    assert!(matches!(
        s.finish_upload("r", "linksess", &d, u64::MAX, b"").await,
        Err(StorageError::BadPath(_))
    ));
}
