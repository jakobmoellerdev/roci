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
    // A `..` reference resolves through index.json, never a path built from
    // the tag, so traversal is impossible: it is simply not found.
    assert!(matches!(
        s.get_manifest("r", "..").await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        s.append_upload("r", "../evil", b"x", None).await,
        Err(StorageError::BadPath(_))
    ));
    // BadPath renders a message.
    assert_eq!(
        StorageError::BadPath("..".into()).to_string(),
        "unsafe path component: .."
    );
}

#[tokio::test]
async fn blob_roundtrip_and_digest_verify() {
    let (_dir, s) = store();
    let data = b"hello roci";
    let d = sha256_of(data);
    s.put_blob("repo/a", &d, data).await.unwrap();
    assert_eq!(s.blob_size("repo/a", &d).await.unwrap(), data.len() as u64);
    assert_eq!(s.read_blob("repo/a", &d).await.unwrap(), data);

    // Wrong digest is rejected.
    let wrong = sha256_of(b"other");
    assert!(matches!(
        s.put_blob("repo/a", &wrong, data).await,
        Err(StorageError::DigestMismatch { .. })
    ));
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
    // A range streams exactly its window.
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
    // A repo that received only a blob push (no manifest) has an oci-layout
    // marker + blobs/ but no index.json. After a restart the presence filter
    // must still be seeded from it, or a valid blob would be reported absent
    // (and a later manifest push would 404 MANIFEST_BLOB_UNKNOWN).
    let dir = tempfile::tempdir().unwrap();
    let data = b"blob-only-layer";
    let d = sha256_of(data);
    {
        let s = FsStorage::new(dir.path()).unwrap();
        s.put_blob("blobonly", &d, data).await.unwrap();
        // Sanity: no index.json exists for this repo (blob-only).
        assert!(!dir.path().join("blobonly").join("index.json").exists());
        assert!(dir.path().join("blobonly").join("oci-layout").exists());
    }
    // Reopen: the seed walk must discover the blob-only repo via its marker.
    let s2 = FsStorage::new(dir.path()).unwrap();
    assert!(s2.blob_exists("blobonly", &d).await.unwrap());
    assert_eq!(
        s2.blob_size("blobonly", &d).await.unwrap(),
        data.len() as u64
    );
}

#[tokio::test]
async fn seed_presence_and_discover_repos_edge_cases() {
    // Build a root that exercises every branch of seed_presence_from_cas and
    // discover_repos, then construct FsStorage to run the seed walk.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // repo "a": a proper CAS blob (happy path — inserted into the filter)
    // plus a `.tmp` staging file that must be skipped.
    let good = sha256_of(b"good-blob");
    let a_alg = root.join("a").join("blobs").join("sha256");
    std::fs::create_dir_all(&a_alg).unwrap();
    std::fs::write(a_alg.join(good.hex()), b"good-blob").unwrap();
    std::fs::write(a_alg.join("deadbeef.tmp"), b"partial").unwrap();
    std::fs::write(root.join("a").join("index.json"), b"{}").unwrap();
    // A regular file where an algorithm dir is expected → read_dir(alg) fails.
    std::fs::write(root.join("a").join("blobs").join("notadir"), b"x").unwrap();

    // repo "b": has index.json but NO blobs/ dir → read_dir(blobs) fails.
    std::fs::create_dir_all(root.join("b")).unwrap();
    std::fs::write(root.join("b").join("index.json"), b"{}").unwrap();

    // A directory nested deeper than the discover_repos depth bound carries
    // an index.json that must NOT be discovered (depth cutoff).
    let mut deep = root.to_path_buf();
    for i in 0..20 {
        deep = deep.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("index.json"), b"{}").unwrap();

    let s = FsStorage::new(root).unwrap();
    // The real blob is present (filter seeded); the tmp file was skipped, so
    // reading it back would 404 — but the good blob reads fine.
    assert_eq!(s.read_blob("a", &good).await.unwrap(), b"good-blob");
    // A blob never stored is absent (filter authoritative after a complete seed).
    let never = sha256_of(b"never");
    assert!(matches!(
        s.blob_size("a", &never).await,
        Err(StorageError::NotFound)
    ));

    // discover_repos read_dir-failure branch: point a fresh store at a path
    // whose root cannot be read (unix perms) — the walk returns nothing and
    // construction still succeeds.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = dir.path().join("locked");
        std::fs::create_dir_all(locked.join("sub")).unwrap();
        std::fs::write(locked.join("sub").join("index.json"), b"{}").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Seeding walks `locked` but read_dir fails → skipped, no panic.
        let _ = FsStorage::new(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

// A same-repo mount (src == dest) short-circuits: the blob is already
// present and must not be copied onto itself (which would truncate it).
#[tokio::test]
async fn mount_blob_same_repo_is_idempotent_noop() {
    let (_dir, s) = store();
    let data = b"self-mount";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    assert!(s.mount_blob("r", "r", &d).await.unwrap());
    // Content is intact (not truncated by a copy-onto-self).
    assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
}

// Pushing the identical blob twice is idempotent dedup: on Linux the second
// put's `linkat` hits `EEXIST` (the content-addressed name already exists)
// and is treated as success; the bytes remain correct.
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
    // The manifest commits its backref edges atomically with itself.
    for repo in ["r", "other"] {
        s.put_manifest(
            repo,
            None,
            &manifest,
            "application/vnd.oci.image.manifest.v1+json",
            b"the-manifest",
            ManifestLinks {
                references: &[b1.clone(), b2.clone()],
                subject: None,
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(s.backrefs("r", &b1), vec![manifest.as_string()]);
    assert_eq!(s.backrefs("r", &b2), vec![manifest.as_string()]);
    // Deleting the manifest clears its edges from every referenced blob in
    // this repo, but leaves the other repo's edges intact.
    s.delete_manifest("r", &manifest).await.unwrap();
    assert!(s.backrefs("r", &b1).is_empty());
    assert!(s.backrefs("r", &b2).is_empty());
    assert_eq!(s.backrefs("other", &b1), vec![manifest.as_string()]);
}
