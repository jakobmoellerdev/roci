use super::common::store;
use roci_storage::*;

#[tokio::test]
async fn path_backstop_rejects_traversal_components() {
    let (_dir, s) = store();
    let d = sha256_of(b"x");
    // A `..` repo component is rejected before any filesystem access.
    assert!(matches!(
        s.blob_size("a/../b", &d).await,
        Err(StorageError::BadPath(_))
    ));
    // A `..` tag resolves through index.json; traversal is simply not found.
    assert!(matches!(
        s.get_manifest("r", "..").await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        s.append_upload(
            "r",
            "../evil",
            roci_storage::upload_body(b"x"),
            None,
            u64::MAX
        )
        .await,
        Err(StorageError::BadPath(_))
    ));
    assert_eq!(
        StorageError::BadPath("..".into()).to_string(),
        "unsafe path component: .."
    );
}

#[tokio::test]
async fn open_blob_streams_ranges_across_chunk_boundaries() {
    use futures::TryStreamExt;
    let (_dir, s) = store();
    let data: Vec<u8> = (0..600 * 1024u32).map(|i| (i % 251) as u8).collect();
    let d = sha256_of(&data);
    s.put_blob("r", &d, &data).await.unwrap();
    for (start, len) in [(0, data.len()), (1, data.len() - 2), (262_143, 262_146)] {
        let blob = s.open_blob("r", &d).await.unwrap();
        let chunks: Vec<_> = blob
            .into_stream(start as u64, len as u64)
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();
        assert_eq!(
            chunks.concat(),
            &data[start..start + len],
            "range {start}+{len}"
        );
    }
}

#[tokio::test]
async fn open_blob_stream_errors_when_file_is_shorter_than_its_size() {
    use futures::TryStreamExt;
    let (dir, s) = store();
    let data = vec![7u8; 300 * 1024];
    let d = sha256_of(&data);
    s.put_blob("r", &d, &data).await.unwrap();
    let blob = s.open_blob("r", &d).await.unwrap();
    // Truncated read must fail, not silently end short.
    let path = dir.path().join("r/blobs/sha256").join(d.hex());
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(1024)
        .unwrap();
    let err = blob
        .into_stream(0, data.len() as u64)
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn open_blob_streams_and_missing_is_not_found() {
    use futures::TryStreamExt;
    let (_dir, s) = store();
    let data = b"streamed";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    let blob = s.open_blob("r", &d).await.unwrap();
    assert_eq!(blob.size(), data.len() as u64);
    assert!(blob.redirect_url().is_none());
    let chunks: Vec<_> = blob
        .into_stream(0, 8)
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(chunks.concat(), data);
    let blob = s.open_blob("r", &d).await.unwrap();
    let chunks: Vec<_> = blob
        .into_stream(2, 3)
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(chunks.concat(), b"rea");
    let absent = sha256_of(b"absent");
    assert!(matches!(
        s.open_blob("r", &absent).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        s.blob_size("r", &absent).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        s.read_blob("r", &absent).await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn blob_only_repo_is_seeded_after_restart() {
    // Blob-only repo (no index.json) must seed presence filter on restart.
    let dir = tempfile::tempdir().unwrap();
    let data = b"blob-only-layer";
    let d = sha256_of(data);
    {
        let s = FsStorage::new(dir.path()).unwrap();
        s.put_blob("blobonly", &d, data).await.unwrap();
        assert!(!dir.path().join("blobonly").join("index.json").exists());
        assert!(dir.path().join("blobonly").join("oci-layout").exists());
    }
    let s2 = FsStorage::new(dir.path()).unwrap();
    assert!(s2.blob_exists("blobonly", &d).await.unwrap());
    assert_eq!(
        s2.blob_size("blobonly", &d).await.unwrap(),
        data.len() as u64
    );
}

#[tokio::test]
async fn seed_presence_and_discover_repos_edge_cases() {
    // Exercises every branch of seed_presence_from_cas and discover_repos.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let good = sha256_of(b"good-blob");
    let a_alg = root.join("a").join("blobs").join("sha256");
    std::fs::create_dir_all(&a_alg).unwrap();
    std::fs::write(a_alg.join(good.hex()), b"good-blob").unwrap();
    std::fs::write(a_alg.join("deadbeef.tmp"), b"partial").unwrap();
    std::fs::write(root.join("a").join("index.json"), b"{}").unwrap();
    std::fs::write(root.join("a").join("blobs").join("notadir"), b"x").unwrap();

    std::fs::create_dir_all(root.join("b")).unwrap();
    std::fs::write(root.join("b").join("index.json"), b"{}").unwrap();

    let mut deep = root.to_path_buf();
    for i in 0..20 {
        deep = deep.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("index.json"), b"{}").unwrap();

    let s = FsStorage::new(root).unwrap();
    assert_eq!(s.read_blob("a", &good).await.unwrap(), b"good-blob");
    let never = sha256_of(b"never");
    assert!(matches!(
        s.blob_size("a", &never).await,
        Err(StorageError::NotFound)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = dir.path().join("locked");
        std::fs::create_dir_all(locked.join("sub")).unwrap();
        std::fs::write(locked.join("sub").join("index.json"), b"{}").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let _ = FsStorage::new(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

// Idempotent dedup: on Linux linkat EEXIST is treated as success.
#[tokio::test]
async fn put_blob_same_digest_twice_is_idempotent() {
    let (_dir, s) = store();
    let data = b"dedup-me";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    s.put_blob("r", &d, data).await.unwrap();
    assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
}

#[tokio::test]
async fn backrefs_track_referenced_blobs_across_delete() {
    let (_dir, s) = store();
    let b1 = sha256_of(b"blob-1");
    let b2 = sha256_of(b"blob-2");
    let manifest = sha256_of(b"the-manifest");
    for repo in ["r", "other"] {
        s.put_manifest(
            repo,
            None,
            &manifest,
            "application/vnd.oci.image.manifest.v1+json",
            b"the-manifest",
            ManifestLinks {
                references: &[b1.clone(), b2.clone()],
                required: &[],
                subject: None,
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(s.backrefs("r", &b1), vec![manifest.as_string()]);
    assert_eq!(s.backrefs("r", &b2), vec![manifest.as_string()]);
    // Delete clears this repo's edges; other repo's stay intact.
    s.delete_manifest("r", &manifest).await.unwrap();
    assert!(s.backrefs("r", &b1).is_empty());
    assert!(s.backrefs("r", &b2).is_empty());
    assert_eq!(s.backrefs("other", &b1), vec![manifest.as_string()]);
}

#[tokio::test]
async fn generic_blob_cases() {
    let (_dir, s) = store();
    super::suite::case_put_and_read_blob(&s).await;
    super::suite::case_blob_exists_and_size(&s).await;
    super::suite::case_blob_not_found_cross_repo(&s).await;
    super::suite::case_put_blob_digest_mismatch(&s).await;
    super::suite::case_delete_blob(&s).await;
    super::suite::case_mount_blob_cross_repo(&s).await;
    super::suite::case_mount_blob_absent_source(&s).await;
    super::suite::case_mount_same_repo_noop(&s).await;
    super::suite::case_rejects_traversal_in_repo(&s).await;
}
