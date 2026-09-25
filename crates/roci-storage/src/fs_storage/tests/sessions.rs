use super::super::paths::blob_dir_rel;
use super::*;

#[tokio::test]
async fn finish_upload_promotes_staging_without_leftover() {
    let (_dir, s) = store();
    // A ~1 MiB blob pushed in two chunks, then finished.
    let data = vec![0x5au8; 1024 * 1024];
    let d = sha256_of(&data);
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload(
        "r",
        &id,
        crate::upload_body(&data[..512 * 1024]),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    s.append_upload(
        "r",
        &id,
        crate::upload_body(&data[512 * 1024..]),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    s.finish_upload("r", &id, &d, u64::MAX, crate::upload_body(b""), u64::MAX)
        .await
        .unwrap();
    // Content is retrievable byte-identical, the staging file is gone, and
    // the CAS file exists (promotion happened in place, no buffering leak).
    assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    assert!(!tokio::fs::try_exists(s.upload_path("r", &id).unwrap())
        .await
        .unwrap());
    assert!(tokio::fs::try_exists(s.blob_path("r", &d).unwrap())
        .await
        .unwrap());
    // A finish whose bytes do not hash to the declared digest is rejected
    // and drops the staging file.
    let id2 = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id2, crate::upload_body(b"mismatch"), None, u64::MAX)
        .await
        .unwrap();
    assert!(matches!(
        s.finish_upload("r", &id2, &d, u64::MAX, crate::upload_body(b""), u64::MAX)
            .await,
        Err(StorageError::DigestMismatch { .. })
    ));
    assert!(!tokio::fs::try_exists(s.upload_path("r", &id2).unwrap())
        .await
        .unwrap());
}

#[tokio::test]
async fn upload_ops_reject_invalid_id_and_do_not_leak_locks() {
    let (_dir, s) = store();
    // A traversal id is rejected by session_lock's validation on every op,
    // before any lock-map entry is created.
    assert!(matches!(
        s.append_upload("r", "../evil", crate::upload_body(b"x"), None, u64::MAX)
            .await,
        Err(StorageError::BadPath(_))
    ));
    let d = sha256_of(b"x");
    assert!(matches!(
        s.finish_upload(
            "r",
            "../evil",
            &d,
            u64::MAX,
            crate::upload_body(b""),
            u64::MAX
        )
        .await,
        Err(StorageError::BadPath(_))
    ));
    assert!(matches!(
        s.abort_upload("r", "../evil").await,
        Err(StorageError::BadPath(_))
    ));
    // A valid-but-unknown session id: append errors NotFound and drops the
    // lock entry it created, so the map does not grow per unknown id.
    assert!(matches!(
        s.append_upload("r", "deadbeef", crate::upload_body(b"x"), None, u64::MAX)
            .await,
        Err(StorageError::NotFound)
    ));
    assert!(s
        .upload_locks
        .lock()
        .unwrap()
        .get(&("r".to_string(), "deadbeef".to_string()))
        .is_none());
}

// Directly exercise the best-effort cache warm: an absent blob path is a
// no-op (open fails → skipped), and a present small blob is cached.
#[cfg(unix)]
#[tokio::test]
async fn warm_small_blob_cache_open_error_is_noop_and_small_blob_caches() {
    let (_dir, s) = store();
    let d = sha256_of(b"warmable");
    let (alg_rel, hex) = blob_dir_rel("r", &d).unwrap();
    let mut rel = alg_rel.clone();
    rel.push(&hex);
    // (a) No blob at rel yet → open fails → warm is a no-op (nothing cached).
    s.warm_small_blob_cache("r", &rel, &d.as_string()).await;
    assert!(s.cache.get("r", &d.as_string()).is_none());
    // (b) Materialise the blob, then warm → it is read back and cached.
    s.put_blob("r", &d, b"warmable").await.unwrap();
    s.cache.invalidate("r", &d.as_string());
    s.warm_small_blob_cache("r", &rel, &d.as_string()).await;
    assert_eq!(
        s.cache.get("r", &d.as_string()).map(|b| b.to_vec()),
        Some(b"warmable".to_vec())
    );
}
