use super::*;

#[tokio::test]
async fn finish_upload_promotes_staging_without_leftover() {
    let (_dir, s) = store();
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
    assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    assert!(!tokio::fs::try_exists(s.upload_path("r", &id).unwrap())
        .await
        .unwrap());
    assert!(tokio::fs::try_exists(s.blob_path("r", &d).unwrap())
        .await
        .unwrap());
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
    // Traversal id rejected before any lock-map entry.
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
    // Unknown id: NotFound + lock entry dropped.
    assert!(matches!(
        s.append_upload("r", "deadbeef", crate::upload_body(b"x"), None, u64::MAX)
            .await,
        Err(StorageError::NotFound)
    ));
    assert!(!s.upload_locks.contains("r", "deadbeef"));
}

// Small blobs cached on finalize; large blobs are not.
#[tokio::test]
async fn finalize_warms_cache_for_small_blobs_only() {
    let (_dir, s) = store();
    for (data, cached) in [
        (b"warmable".to_vec(), true),
        (
            vec![9u8; crate::cache::DEFAULT_SMALL_BLOB_THRESHOLD + 1],
            false,
        ),
    ] {
        let d = sha256_of(&data);
        let id = s.begin_upload("r").await.unwrap();
        s.finish_upload("r", &id, &d, u64::MAX, crate::upload_body(&data), u64::MAX)
            .await
            .unwrap();
        assert_eq!(s.cache.get("r", &d.as_string()).is_some(), cached);
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    }
}

/// Custom `small_blob_threshold` controls cache eligibility.
#[cfg(unix)]
#[tokio::test]
async fn custom_small_blob_threshold_controls_caching() {
    use crate::quota::QuotaTracker;
    use roci_config::StorageConfig;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let cfg = StorageConfig {
        small_blob_threshold: 16,
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &cfg, Arc::new(QuotaTracker::default())).unwrap();

    let big_data = b"0123456789abcdefX"; // 17 bytes
    let big_d = sha256_of(big_data);
    s.put_blob("r", &big_d, big_data).await.unwrap();
    assert!(
        s.cache.get("r", &big_d.as_string()).is_none(),
        "17-byte blob should not be cached with threshold=16"
    );

    let small_data = b"0123456789abcdef"; // 16 bytes
    let small_d = sha256_of(small_data);
    s.put_blob("r", &small_d, small_data).await.unwrap();
    assert_eq!(
        s.cache.get("r", &small_d.as_string()).map(|b| b.to_vec()),
        Some(small_data.to_vec()),
        "16-byte blob should be cached with threshold=16"
    );
}
