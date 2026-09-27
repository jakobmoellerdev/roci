use super::*;

#[tokio::test]
async fn put_errors_when_parent_path_is_a_file() {
    let (dir, s) = store();
    let repo_dir = dir.path().join("r");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::fs::write(repo_dir.join("blobs"), b"file").unwrap();
    let data = b"x";
    let d = sha256_of(data);
    assert!(matches!(
        s.put_blob("r", &d, data).await,
        Err(StorageError::Io(_))
    ));

    assert!(matches!(
        s.put_manifest(
            "r",
            None,
            &d,
            "application/json",
            data,
            ManifestLinks::default()
        )
        .await,
        Err(StorageError::Io(_))
    ));

    let body = br#"{"schemaVersion":2}"#;
    let bd = sha256_of(body);
    std::fs::create_dir_all(dir.path().join("r2").join("index.json")).unwrap();
    s.put_manifest(
        "r2",
        Some("v1"),
        &bd,
        "application/json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    assert!(matches!(s.read_index("r2").await, Err(StorageError::Io(_))));
}

#[tokio::test]
async fn non_notfound_io_error_surfaces() {
    let (dir, s) = store();
    let repo_dir = dir.path().join("r");
    std::fs::create_dir_all(repo_dir.join("index.json")).unwrap();
    assert!(matches!(
        s.list_tags("r", None, usize::MAX).await,
        Err(StorageError::Io(_))
    ));
    let subject = sha256_of(b"s");
    assert!(matches!(
        s.list_referrers("r", &subject, None, None, usize::MAX)
            .await,
        Err(StorageError::Io(_))
    ));
    let repo2 = dir.path().join("r2");
    std::fs::create_dir_all(&repo2).unwrap();
    std::fs::write(repo2.join("index.json"), b"{ not json").unwrap();
    assert!(matches!(
        s.list_tags("r2", None, usize::MAX).await,
        Err(StorageError::Io(_))
    ));
}

#[tokio::test]
async fn index_preserves_foreign_entries_and_referrer_append() {
    let (_dir, s) = store();
    // Foreign descriptor + non-array manifests sibling.
    let subject = sha256_of(b"subject");
    let referrer = sha256_of(b"referrer");
    s.ensure_layout("r").await.unwrap();
    let seeded = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"mediaType": "application/xml", "digest": "sha256:dead", "size": 3}
        ]
    });
    FsStorage::write_index_at_root(&s.root, "r", &seeded)
        .await
        .unwrap();
    assert!(s
        .list_tags("r", None, usize::MAX)
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items
        .is_empty());
    // Referrer with no pre-existing manifest entry → append branch.
    s.put_manifest(
        "r",
        None,
        &referrer,
        "application/json",
        b"referrer",
        ManifestLinks {
            references: &[],
            required: &[],
            subject: Some((&subject, br#"{"digest":"x","artifactType":"a/b"}"#)),
        },
    )
    .await
    .unwrap();
    let listed = s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items;
    assert_eq!(listed.len(), 1);
    let parsed: serde_json::Value = serde_json::from_slice(&listed[0].1).unwrap();
    assert_eq!(
        parsed
            .get("subject")
            .and_then(|v| v.get("digest"))
            .and_then(|v| v.as_str()),
        Some(subject.as_string().as_str())
    );
    let idx = s.read_index("r").await.unwrap();
    assert_eq!(idx["manifests"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn upgrade_semantics_preexisting_subjects() {
    let dir = tempfile::tempdir().unwrap();
    let subject = sha256_of(b"subject");
    let referrer = sha256_of(b"preexisting-referrer");
    // Pre-existing layout with `subject` descriptor roci has never seen.
    let repo = dir.path().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        repo.join("index.json"),
        serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": referrer.as_string(), "size": 5,
                "artifactType": "a/sig",
                "subject": {"digest": subject.as_string()}
            }]
        })
        .to_string(),
    )
    .unwrap();
    let s = FsStorage::new(dir.path()).unwrap();
    s.warm_referrers_from_layout().await;
    let page = |s: &FsStorage| {
        s.meta
            .referrers_page("r", &subject.as_string(), None, None, usize::MAX)
            .unwrap()
            .items
    };
    let from_meta = page(&s);
    assert_eq!(from_meta.len(), 1);
    s.warm_referrers_from_layout().await;
    assert_eq!(page(&s).len(), 1);
    assert_eq!(from_meta[0].0, referrer.as_string());
}

#[tokio::test]
async fn layout_fallback_pages_like_the_store() {
    // Out-of-band layout served from index.json.
    let dir = tempfile::tempdir().unwrap();
    let subject = sha256_of(b"subject");
    let mut refs: Vec<(String, &str)> = (0..3u8)
        .map(|i| {
            (
                sha256_of(&[i]).as_string(),
                ["a/sig", "a/sbom"][usize::from(i % 2)],
            )
        })
        .collect();
    let tagged = |tag: &str, d: &str| serde_json::json!({"digest": d, "annotations": {(REF_NAME_ANNOTATION): tag}});
    let mut manifests: Vec<serde_json::Value> = refs
        .iter()
        .map(|(d, at)| {
            serde_json::json!({"digest": d, "artifactType": at,
                                   "subject": {"digest": subject.as_string()}})
        })
        .collect();
    for t in ["c", "a", "b", "a"] {
        manifests.push(tagged(t, &refs[0].0));
    }
    let repo = dir.path().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("index.json"),
        serde_json::json!({"schemaVersion": 2, "manifests": manifests}).to_string(),
    )
    .unwrap();
    let s = FsStorage::new(dir.path()).unwrap();

    let p = s.list_tags("r", None, 2).await.unwrap();
    assert_eq!((p.items, p.more), (vec!["a".into(), "b".into()], true));
    let p = s.list_tags("r", Some("b"), 2).await.unwrap();
    assert_eq!((p.items, p.more), (vec!["c".to_string()], false));

    refs.sort();
    let sigs: Vec<&String> = refs
        .iter()
        .filter(|(_, at)| *at == "a/sig")
        .map(|(d, _)| d)
        .collect();
    let p = s
        .list_referrers("r", &subject, Some("a/sig"), None, 1)
        .await
        .unwrap();
    assert_eq!((&p.items[0].0, p.more), (sigs[0], true));
    let p = s
        .list_referrers("r", &subject, Some("a/sig"), Some(sigs[0]), 1)
        .await
        .unwrap();
    assert_eq!((&p.items[0].0, p.more), (sigs[1], false));
    let all = s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items;
    let digests: Vec<&String> = all.iter().map(|(d, _)| d).collect();
    assert_eq!(digests, refs.iter().map(|(d, _)| d).collect::<Vec<_>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn index_write_behind_eventual() {
    let (dir, s) = store();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    s.put_manifest(
        "r",
        Some("v1"),
        &d,
        "application/json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        s.list_tags("r", None, usize::MAX).await.unwrap().items,
        ["v1"]
    );
    let path = dir.path().join("r").join("index.json");
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
    loop {
        if let Ok(b) = std::fs::read(&path) {
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            if v["manifests"]
                .as_array()
                .is_some_and(|m| m.iter().any(|e| descriptor_tag(e) == Some("v1")))
            {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "index.json never written"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
    while s.index_dirty.lock().unwrap().contains_key("r") {
        assert!(
            std::time::Instant::now() < deadline,
            "repo never became clean"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("r"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty());
    s.delete_manifest("r", &d).await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
    loop {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if v["manifests"].as_array().unwrap().is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "delete never persisted"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

#[test]
fn new_outside_runtime_does_not_panic_and_reconcile_persists() {
    // No Tokio runtime needed at construction time.
    let (dir, s) = store();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        s.put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/json",
            body,
            ManifestLinks::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            s.list_tags("r", None, usize::MAX).await.unwrap().items,
            ["v1"]
        );
        s.reconcile_index_json().await;
    });
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r/index.json")).unwrap()).unwrap();
    assert!(v["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| descriptor_tag(e) == Some("v1")));
}

#[tokio::test]
async fn reconcile_recovers_wal_ahead_of_index() {
    // Simulate crash after WAL append but before background rename.
    let dir = tempfile::tempdir().unwrap();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    {
        let s = FsStorage::new(dir.path()).unwrap();
        s.put_blob("r", &d, body).await.unwrap();
        s.meta
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: d.as_string(),
                media_type: "application/json".into(),
                tag: Some("v1".into()),
                references: Vec::new(),
                referrer: None,
            })
            .unwrap();
    }
    assert!(!dir.path().join("r/index.json").exists());
    let s = FsStorage::new(dir.path()).unwrap();
    s.reconcile_index_json().await;
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("r/index.json")).unwrap()).unwrap();
    let e = &v["manifests"][0];
    assert_eq!(descriptor_tag(e), Some("v1"));
    assert_eq!(e["size"], body.len());
}

#[tokio::test]
async fn rebuild_preserves_preexisting_foreign_tags() {
    let dir = tempfile::tempdir().unwrap();
    let foreign_body = br#"{"schemaVersion":2,"x":1}"#;
    let fd = sha256_of(foreign_body);
    {
        let s = FsStorage::new(dir.path()).unwrap();
        s.put_blob("r", &fd, foreign_body).await.unwrap();
    }
    std::fs::remove_file(dir.path().join("roci-meta.log")).ok();
    std::fs::write(
        dir.path().join("r/index.json"),
        serde_json::json!({"schemaVersion": 2, "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": fd.as_string(), "size": foreign_body.len(),
            "annotations": {REF_NAME_ANNOTATION: "legacy"}
        }]})
        .to_string(),
    )
    .unwrap();
    let s = FsStorage::new(dir.path()).unwrap();
    s.reconcile_index_json().await;
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    s.put_manifest(
        "r",
        Some("new"),
        &d,
        "application/json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    let idx = s.read_index("r").await.unwrap();
    let tags: Vec<_> = idx["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(descriptor_tag)
        .collect();
    assert!(
        tags.contains(&"legacy") && tags.contains(&"new"),
        "{tags:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn index_write_refuses_symlinked_repo_and_bad_repo_name() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("evil")).unwrap();
    let idx = serde_json::json!({"schemaVersion": 2, "manifests": []});
    assert!(FsStorage::write_index_at_root(dir.path(), "evil", &idx)
        .await
        .is_err());
    assert!(!outside.path().join("index.json").exists());
    let s = FsStorage::new(dir.path()).unwrap();
    let sub = sha256_of(b"s");
    assert!(matches!(
        s.put_manifest(
            "../x",
            None,
            &sub,
            "application/json",
            b"s",
            ManifestLinks {
                references: &[],
                required: &[],
                subject: Some((&sub, b"{}")),
            },
        )
        .await,
        Err(StorageError::BadPath(_))
    ));
}

#[tokio::test]
async fn rebuild_keeps_top_level_fields_and_skips_unreadable_index() {
    let (dir, s) = store();
    s.ensure_layout("r").await.unwrap();
    let seeded = serde_json::json!({
        "schemaVersion": 2,
        "annotations": {"org.example": "keep"},
        "manifests": [],
    });
    FsStorage::write_index_at_root(&s.root, "r", &seeded)
        .await
        .unwrap();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    s.put_manifest(
        "r",
        Some("v1"),
        &d,
        "application/json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    let idx = s.read_index("r").await.unwrap();
    assert_eq!(idx["annotations"]["org.example"], "keep");
    // Unreadable index → never overwritten from metadata; stays dirty.
    let dirty = StdMutex::new(HashMap::from([("q".to_string(), 1u64)]));
    std::fs::create_dir_all(dir.path().join("q/index.json")).unwrap();
    FsStorage::flush_dirty(&s.root, &*s.meta, &dirty).await;
    assert!(dirty.lock().unwrap().contains_key("q"));
    assert!(dir.path().join("q/index.json").is_dir());
}

#[cfg(unix)]
#[tokio::test]
async fn warm_referrers_ignores_symlinked_index() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let subject = sha256_of(b"s");
    let r = sha256_of(b"r");
    std::fs::write(
        outside.path().join("index.json"),
        serde_json::json!({"manifests": [{"digest": r.as_string(),
                "subject": {"digest": subject.as_string()}}]})
        .to_string(),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("repo")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("index.json"),
        dir.path().join("repo/index.json"),
    )
    .unwrap();
    let s = FsStorage::new(dir.path()).unwrap();
    s.warm_referrers_from_layout().await;
    assert!(!s
        .meta
        .has_referrer("repo", &subject.as_string(), &r.as_string()));
}

#[tokio::test]
async fn serves_external_oci_layout() {
    // Hand-built OCI layout serves tagged manifest and config blob.
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("app");
    let config = br#"{"architecture":"amd64","os":"linux"}"#;
    let config_d = sha256_of(config);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":{}}},"layers":[]}}"#,
        config_d.as_string(),
        config.len()
    );
    let manifest_d = sha256_of(manifest.as_bytes());
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("oci-layout"), OCI_LAYOUT_MARKER).unwrap();
    let blobs = repo.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(config_d.hex()), config).unwrap();
    std::fs::write(blobs.join(manifest_d.hex()), manifest.as_bytes()).unwrap();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_d.as_string(),
            "size": manifest.len(),
            "annotations": {"org.opencontainers.image.ref.name": "v1"}
        }]
    });
    std::fs::write(repo.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();

    let s = FsStorage::new(dir.path()).unwrap();
    let by_tag = s.get_manifest("app", "v1").await.unwrap();
    assert_eq!(by_tag.digest, manifest_d);
    assert_eq!(
        by_tag.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(by_tag.bytes, manifest.as_bytes());
    assert_eq!(
        s.list_tags("app", None, usize::MAX).await.unwrap().items,
        vec!["v1".to_string()]
    );
    assert_eq!(s.read_blob("app", &config_d).await.unwrap(), config);
    // By-digest blob not in index.json → image-manifest media type.
    let extra = br#"{"schemaVersion":2}"#;
    let extra_d = sha256_of(extra);
    std::fs::write(blobs.join(extra_d.hex()), extra).unwrap();
    let by_digest = s.get_manifest("app", &extra_d.as_string()).await.unwrap();
    assert_eq!(
        by_digest.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(by_digest.bytes, extra);
    let absent = sha256_of(b"absent");
    assert!(matches!(
        s.get_manifest("app", &absent.as_string()).await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn referrer_merges_into_annotated_entry() {
    // Existing annotations survive add_referrer merge.
    let (_dir, s) = store();
    let body = br#"{"schemaVersion":2}"#;
    let referrer = sha256_of(body);
    let subject = sha256_of(b"subject");
    // Entry's annotations win over referrer descriptor's.
    s.put_manifest(
        "r",
        Some("v1"),
        &referrer,
        "application/json",
        body,
        ManifestLinks {
            references: &[],
            required: &[],
            subject: Some((
                &subject,
                br#"{"mediaType":"application/json","digest":"x","annotations":{"other":"1"},"artifactType":"a/b"}"#,
            )),
        },
    )
    .await
    .unwrap();
    let listed = s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items;
    assert_eq!(listed.len(), 1);
    let d: serde_json::Value = serde_json::from_slice(&listed[0].1).unwrap();
    // Referrer descriptor carries subject link and artifactType.
    assert_eq!(
        d.get("subject")
            .and_then(|v| v.get("digest"))
            .and_then(|v| v.as_str()),
        Some(subject.as_string().as_str())
    );
    assert_eq!(d.get("artifactType").and_then(|v| v.as_str()), Some("a/b"));
    // Tag annotation preserved (k=="annotations" skip).
    let index = s.read_index("r").await.unwrap();
    let entry = index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| descriptor_digest(e) == Some(referrer.as_string().as_str()))
        .unwrap()
        .clone();
    assert_eq!(
        entry
            .get("annotations")
            .and_then(|a| a.get("org.opencontainers.image.ref.name"))
            .and_then(|v| v.as_str()),
        Some("v1")
    );
    assert_eq!(
        entry
            .get("subject")
            .and_then(|v| v.get("digest"))
            .and_then(|v| v.as_str()),
        Some(subject.as_string().as_str())
    );
}

#[tokio::test]
async fn write_index_no_tmp_leftovers() {
    #[cfg(target_os = "linux")]
    let _serialize = FAULT_TEST_LOCK.lock().await;

    async fn assert_no_tmp_leftovers(s: &FsStorage, dir: &std::path::Path) {
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        s.put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/json",
            body,
            ManifestLinks::default(),
        )
        .await
        .unwrap();
        s.reconcile_index_json().await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
        while s.index_dirty.lock().unwrap().contains_key("r") {
            assert!(
                std::time::Instant::now() < deadline,
                "repo never became clean"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let index_bytes = std::fs::read(dir.join("r/index.json")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
        assert!(v["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| descriptor_tag(e) == Some("v1")));
        let leftovers: Vec<_> = std::fs::read_dir(dir.join("r"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");
    }

    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::Ordering;
        for force in [true, false] {
            crate::fault::FORCE_TMPFILE_UNSUPPORTED.store(force, Ordering::Relaxed);
            let (dir, s) = store();
            assert_no_tmp_leftovers(&s, dir.path()).await;
        }
        crate::fault::FORCE_TMPFILE_UNSUPPORTED.store(false, Ordering::Relaxed);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (dir, s) = store();
        assert_no_tmp_leftovers(&s, dir.path()).await;
    }
}

/// Stale `.index.json.*.tmp` regular files swept; symlinks/dirs not.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_sweeps_stale_tmp_but_not_symlinks_or_dirs() {
    let (dir, s) = store();
    let repo_dir = dir.path().join("r");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::fs::write(
        repo_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        repo_dir.join("index.json"),
        r#"{"schemaVersion":2,"manifests":[]}"#,
    )
    .unwrap();

    let orphan_path = repo_dir.join(".index.json.deadbeef01234567.tmp");
    std::fs::write(&orphan_path, b"stale leftover").unwrap();

    let symlink_path = repo_dir.join(".index.json.cafebabe00000000.tmp");
    std::os::unix::fs::symlink("/dev/null", &symlink_path).unwrap();

    let dir_path = repo_dir.join(".index.json.0000000000000000.tmp");
    std::fs::create_dir(&dir_path).unwrap();

    s.reconcile_index_json().await;

    assert!(
        !orphan_path.exists(),
        "stale regular-file .tmp should be removed"
    );
    assert!(
        std::fs::symlink_metadata(&symlink_path).is_ok(),
        "symlink matching .tmp pattern should NOT be removed"
    );
    assert!(
        dir_path.is_dir(),
        "directory matching .tmp pattern should NOT be removed"
    );
}
