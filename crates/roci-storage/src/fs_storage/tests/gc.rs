use super::*;
use crate::quota::QuotaLimits;
use std::time::{Duration, Instant};

#[tokio::test]
async fn unreferenced_blob_collected_only_after_delay() {
    let (_dir, s) = gc_store_cfg(60, None);
    let blob_data = b"garbage layer";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    assert!(!s.gc.is_empty());

    let now = Instant::now();
    s.sweep_at(now).await;
    assert!(s.blob_exists("r", &blob_d).await.unwrap());

    let later = now + Duration::from_secs(61);
    s.sweep_at(later).await;
    assert!(!s.blob_exists("r", &blob_d).await.unwrap());
    assert_eq!(s.gc.len(), 0);
}

#[tokio::test]
async fn referenced_blob_survives_sweep() {
    let (_dir, s) = gc_store_cfg(60, None);
    let config_data = b"config";
    let config_d = sha256_of(config_data);
    let layer_data = b"layer data";
    let layer_d = sha256_of(layer_data);

    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer_d, layer_data).await.unwrap();

    let manifest_body = make_manifest(&config_d, &[&layer_d]);
    let manifest_d = sha256_of(&manifest_body);
    let refs = manifest_references(&serde_json::from_slice(&manifest_body).unwrap());
    s.put_manifest(
        "r",
        Some("v1"),
        &manifest_d,
        MEDIA_TYPE_IMAGE_MANIFEST,
        &manifest_body,
        ManifestLinks {
            references: &refs,
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    assert_eq!(s.gc.len(), 0);

    let later = Instant::now() + Duration::from_secs(3600);
    s.sweep_at(later).await;
    assert!(s.blob_exists("r", &config_d).await.unwrap());
    assert!(s.blob_exists("r", &layer_d).await.unwrap());
}

#[tokio::test]
async fn deleting_manifest_makes_blobs_collectable_but_shared_blobs_survive() {
    let (_dir, s) = gc_store_cfg(60, None);
    let config_data = b"shared-config";
    let config_d = sha256_of(config_data);
    let layer1_data = b"layer for manifest A only";
    let layer1_d = sha256_of(layer1_data);
    let layer2_data = b"shared layer";
    let layer2_d = sha256_of(layer2_data);

    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer1_d, layer1_data).await.unwrap();
    s.put_blob("r", &layer2_d, layer2_data).await.unwrap();

    let ma_body = make_manifest(&config_d, &[&layer1_d, &layer2_d]);
    let ma_d = sha256_of(&ma_body);
    let ma_refs = manifest_references(&serde_json::from_slice(&ma_body).unwrap());
    s.put_manifest(
        "r",
        Some("a"),
        &ma_d,
        MEDIA_TYPE_IMAGE_MANIFEST,
        &ma_body,
        ManifestLinks {
            references: &ma_refs,
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    let mb_body = make_manifest(&config_d, &[&layer2_d]);
    let mb_d = sha256_of(&mb_body);
    let mb_refs = manifest_references(&serde_json::from_slice(&mb_body).unwrap());
    s.put_manifest(
        "r",
        Some("b"),
        &mb_d,
        MEDIA_TYPE_IMAGE_MANIFEST,
        &mb_body,
        ManifestLinks {
            references: &mb_refs,
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    s.delete_manifest("r", &ma_d).await.unwrap();

    assert!(!s.gc.is_empty());

    let later = Instant::now() + Duration::from_secs(120);
    s.sweep_at(later).await;
    assert!(
        !s.blob_exists("r", &layer1_d).await.unwrap(),
        "layer1 should be collected"
    );
    assert!(
        s.blob_exists("r", &config_d).await.unwrap(),
        "shared config should survive"
    );
    assert!(
        s.blob_exists("r", &layer2_d).await.unwrap(),
        "shared layer2 should survive"
    );
}

#[tokio::test]
async fn head_touch_postpones_collection() {
    let (_dir, s) = gc_store_cfg(60, None);
    let blob_data = b"touchable";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    let past = Instant::now() - Duration::from_secs(120);
    s.gc.mark_at("r", &blob_d.as_string(), past);

    assert!(s.blob_exists("r", &blob_d).await.unwrap());

    let now = Instant::now();
    s.sweep_at(now).await;
    assert!(
        s.blob_exists("r", &blob_d).await.unwrap(),
        "touch should postpone collection"
    );

    let much_later = Instant::now() + Duration::from_secs(120);
    s.sweep_at(much_later).await;
    assert!(
        !s.blob_exists("r", &blob_d).await.unwrap(),
        "eventually collected"
    );
}

#[tokio::test]
async fn reupload_of_due_candidate_survives() {
    let (_dir, s) = gc_store_cfg(60, None);
    let blob_data = b"reupload me";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    let past = Instant::now() - Duration::from_secs(120);
    s.gc.mark_at("r", &blob_d.as_string(), past);

    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    let now = Instant::now();
    s.sweep_at(now).await;
    assert!(
        s.blob_exists("r", &blob_d).await.unwrap(),
        "reupload must survive the sweep"
    );
}

#[tokio::test]
async fn layout_only_manifests_survive_after_consistency_check() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let layer_data = b"external layer";
    let layer_d = sha256_of(layer_data);
    let config_data = b"external config";
    let config_d = sha256_of(config_data);
    let manifest_body = make_manifest(&config_d, &[&layer_d]);
    let manifest_d = sha256_of(&manifest_body);
    plant_layout(
        root,
        "ext",
        &[&manifest_body, config_data, layer_data],
        &[serde_json::json!({
            "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
            "digest": manifest_d.as_string(),
            "size": manifest_body.len(),
            "annotations": { "org.opencontainers.image.ref.name": "latest" }
        })],
    );
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 1,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        root,
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();
    assert!(
        s.gc.is_root("ext", &manifest_d.as_string()),
        "layout-only manifest should be a root"
    );
    assert!(
        s.backrefs("ext", &config_d)
            .contains(&manifest_d.as_string()),
        "config backref rebuilt"
    );
    assert!(
        s.backrefs("ext", &layer_d)
            .contains(&manifest_d.as_string()),
        "layer backref rebuilt"
    );
    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    assert!(s.blob_exists("ext", &manifest_d).await.unwrap());
    assert!(s.blob_exists("ext", &config_d).await.unwrap());
    assert!(s.blob_exists("ext", &layer_d).await.unwrap());
}

#[tokio::test]
async fn missing_backrefs_are_rebuilt() {
    let (_dir, s) = gc_store_cfg(60, None);
    let config_data = b"cfg";
    let config_d = sha256_of(config_data);
    let layer_data = b"lyr";
    let layer_d = sha256_of(layer_data);

    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer_d, layer_data).await.unwrap();

    // Empty references simulate missing edges from an old log.
    let manifest_body = make_manifest(&config_d, &[&layer_d]);
    let manifest_d = sha256_of(&manifest_body);
    s.put_manifest(
        "r",
        Some("v1"),
        &manifest_d,
        MEDIA_TYPE_IMAGE_MANIFEST,
        &manifest_body,
        ManifestLinks {
            references: &[], // empty! simulating missing edges
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    assert!(s.backrefs("r", &config_d).is_empty());
    assert!(s.backrefs("r", &layer_d).is_empty());

    s.gc_consistency_check().await;

    assert!(
        s.backrefs("r", &config_d).contains(&manifest_d.as_string()),
        "config backref rebuilt by consistency check"
    );
    assert!(
        s.backrefs("r", &layer_d).contains(&manifest_d.as_string()),
        "layer backref rebuilt by consistency check"
    );

    s.sweep_at(Instant::now() + Duration::from_secs(120)).await;
    assert!(s.blob_exists("r", &config_d).await.unwrap());
    assert!(s.blob_exists("r", &layer_d).await.unwrap());
}

#[tokio::test]
async fn unparseable_root_manifest_makes_repo_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    let bad_manifest_data = b"this is not json{{{";
    let bad_d = sha256_of(bad_manifest_data);
    let blob_data = b"innocent";
    let blob_d = sha256_of(blob_data);
    plant_layout(
        dir.path(),
        "bad",
        &[bad_manifest_data.as_slice(), blob_data],
        &[serde_json::json!({
            "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
            "digest": bad_d.as_string(),
            "size": bad_manifest_data.len()
        })],
    );
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 1,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        dir.path(),
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();
    assert!(s.gc.is_unsafe("bad"), "repo should be GC-unsafe");
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(dir
        .path()
        .join("bad/blobs/sha256")
        .join(blob_d.hex())
        .exists());
}

#[tokio::test]
async fn stale_uploads_expire() {
    let (_dir, s) = gc_store_cfg(
        2,
        Some(QuotaLimits {
            max_upload_sessions: 100,
            ..QuotaLimits::default()
        }),
    );

    // Blob ensures repo is visible to discover_repos.
    let blob = sha256_of(b"anchor");
    s.put_blob("r", &blob, b"anchor").await.unwrap();

    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, crate::upload_body(b"x"), None, u64::MAX)
        .await
        .unwrap();
    s.upload_locks.remove("r", &id);
    assert_eq!(s.quota.sessions(), 1);

    let upload_path = _dir.path().join("r").join("uploads").join(&id);
    assert!(upload_path.exists());
    let past = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(&upload_path, past).unwrap();

    s.sweep_at(Instant::now()).await;
    assert!(!upload_path.exists(), "stale upload should be removed");
    assert_eq!(s.quota.sessions(), 0, "session count should drop");
}

#[tokio::test]
async fn never_written_sessions_expire_and_release_their_slot() {
    // A session with no staging file expires and releases its slot.
    let (_dir, s) = gc_store_cfg(
        0,
        Some(QuotaLimits {
            max_upload_sessions: 100,
            ..QuotaLimits::default()
        }),
    );
    s.put_blob("r", &sha256_of(b"anchor"), b"anchor")
        .await
        .unwrap();
    let id = s.begin_upload("r").await.unwrap();
    assert_eq!(s.quota.sessions(), 1);
    assert_eq!(s.upload_size("r", &id).await.unwrap(), 0);
    s.sweep_at(Instant::now()).await;
    assert_eq!(s.quota.sessions(), 0);
    assert!(matches!(
        s.append_upload("r", &id, crate::upload_body(b"x"), None, u64::MAX)
            .await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn sweeps_do_nothing_before_set_ready() {
    let dir = tempfile::tempdir().unwrap();
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 0,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        dir.path(),
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    let blob_data = b"before ready";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    assert!(
        s.blob_exists("r", &blob_d).await.unwrap(),
        "blob should survive because GC is not ready"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_push_delete_preserves_reachable_set() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 1,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        dir.path(),
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    s.gc.set_ready();
    let store = std::sync::Arc::new(s);
    let counter = std::sync::Arc::new(AtomicU64::new(0));
    let iterations = 50;
    let mut handles = Vec::new();

    for _ in 0..4 {
        let st = store.clone();
        let ctr = counter.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..iterations {
                let i = ctr.fetch_add(1, Ordering::Relaxed);
                let layer_data = format!("layer-{i}");
                let layer_d = sha256_of(layer_data.as_bytes());
                let config_data = format!("config-{i}");
                let config_d = sha256_of(config_data.as_bytes());

                st.put_blob("c", &layer_d, layer_data.as_bytes())
                    .await
                    .unwrap();
                st.put_blob("c", &config_d, config_data.as_bytes())
                    .await
                    .unwrap();

                assert!(st.blob_exists("c", &layer_d).await.unwrap());
                assert!(st.blob_exists("c", &config_d).await.unwrap());
                let manifest_body = make_manifest(&config_d, &[&layer_d]);
                let manifest_d = sha256_of(&manifest_body);
                let refs = manifest_references(&serde_json::from_slice(&manifest_body).unwrap());
                let tag = format!("t{i}");
                st.put_manifest(
                    "c",
                    Some(&tag),
                    &manifest_d,
                    MEDIA_TYPE_IMAGE_MANIFEST,
                    &manifest_body,
                    ManifestLinks {
                        references: &refs,
                        required: &[],
                        subject: None,
                    },
                )
                .await
                .unwrap();

                if i.is_multiple_of(2) {
                    let _ = st.delete_manifest("c", &manifest_d).await;
                }
            }
        }));
    }

    for _ in 0..2 {
        let st = store.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..(iterations * 2) {
                st.sweep_at(Instant::now()).await;
                tokio::task::yield_now().await;
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Reachable blobs must still exist.
    let total = counter.load(Ordering::Relaxed);
    for i in 0..total {
        if !i.is_multiple_of(2) {
            let layer_data = format!("layer-{i}");
            let layer_d = sha256_of(layer_data.as_bytes());
            let config_data = format!("config-{i}");
            let config_d = sha256_of(config_data.as_bytes());

            assert!(
                store.blob_exists("c", &layer_d).await.unwrap(),
                "layer of committed manifest {i} must exist"
            );
            assert!(
                store.blob_exists("c", &config_d).await.unwrap(),
                "config of committed manifest {i} must exist"
            );
        }
    }

    store
        .sweep_at(Instant::now() + Duration::from_secs(100))
        .await;
    let mut collected = 0u64;
    for i in 0..total {
        if i.is_multiple_of(2) {
            let layer_data = format!("layer-{i}");
            let layer_d = sha256_of(layer_data.as_bytes());
            if !store.blob_exists("c", &layer_d).await.unwrap() {
                collected += 1;
            }
        }
    }
    assert!(
        collected > 0,
        "GC should eventually collect blobs of deleted manifests"
    );
}

#[tokio::test]
async fn image_index_children_are_protected_as_roots() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let child_config = b"child-config-bytes";
    let child_config_d = sha256_of(child_config);
    let child_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
        "config": { "digest": child_config_d.as_string(), "mediaType": "application/vnd.oci.image.config.v1+json", "size": child_config.len() },
        "layers": []
    })).unwrap();
    let child_d = sha256_of(&child_bytes);
    let index_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{ "mediaType": MEDIA_TYPE_IMAGE_MANIFEST, "digest": child_d.as_string(), "size": child_bytes.len() }]
    })).unwrap();
    let index_d = sha256_of(&index_bytes);
    let garbage = b"garbage-multi";
    let garbage_d = sha256_of(garbage);
    plant_layout(
        root,
        "multi",
        &[child_config, &child_bytes, &index_bytes, garbage],
        &[serde_json::json!({
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": index_d.as_string(),
            "size": index_bytes.len()
        })],
    );
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 0,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        root,
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();
    assert!(
        s.gc.is_root("multi", &index_d.as_string())
            || s.meta
                .manifest_media_type("multi", &index_d.as_string())
                .is_some()
    );
    assert!(
        s.gc.is_root("multi", &child_d.as_string())
            || s.meta
                .manifest_media_type("multi", &child_d.as_string())
                .is_some()
    );
    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    let blobs = root.join("multi/blobs/sha256");
    assert!(blobs.join(child_d.hex()).exists());
    assert!(blobs.join(index_d.hex()).exists());
    assert!(!blobs.join(garbage_d.hex()).exists());
}

#[tokio::test]
async fn missing_cas_root_makes_repo_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    let phantom_d = sha256_of(b"phantom-manifest");
    let blob_data = b"should-survive-unsafe";
    let blob_d = sha256_of(blob_data);
    plant_layout(
        dir.path(),
        "ghost",
        &[blob_data],
        &[serde_json::json!({
            "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
            "digest": phantom_d.as_string(),
            "size": 16
        })],
    );
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 0,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        dir.path(),
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();
    assert!(s.gc.is_unsafe("ghost"));
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(dir
        .path()
        .join("ghost/blobs/sha256")
        .join(blob_d.hex())
        .exists());
}

#[tokio::test]
async fn stale_upload_locked_session_survives_sweep() {
    let (_dir, s) = gc_store_cfg(
        0,
        Some(QuotaLimits {
            max_upload_sessions: 100,
            ..QuotaLimits::default()
        }),
    );
    let blob = sha256_of(b"anchor-lock");
    s.put_blob("r", &blob, b"anchor-lock").await.unwrap();

    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, crate::upload_body(b"partial"), None, u64::MAX)
        .await
        .unwrap();

    let upload_path = _dir.path().join("r").join("uploads").join(&id);
    assert!(upload_path.exists());
    let past = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(&upload_path, past).unwrap();

    // Held session survives sweep despite stale mtime.
    let lock = s.session_lock("r", &id).unwrap();
    let held = lock.lock().await;
    s.sweep_at(Instant::now()).await;
    assert!(
        upload_path.exists(),
        "locked upload session should survive sweep"
    );
    drop(held);

    let before = s.quota.sessions();
    s.sweep_at(Instant::now()).await;
    assert!(!upload_path.exists(), "idle stale session is expired");
    assert_eq!(s.quota.sessions(), before - 1);
}

#[tokio::test]
async fn sweep_handles_already_deleted_blob() {
    // Externally removed blob: sweep clears the candidate.
    let (_dir, s) = gc_store_cfg(0, None);
    let data = b"will-vanish";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    assert!(!s.gc.is_empty());

    let blob_path = s.blob_path("r", &d).unwrap();
    std::fs::remove_file(&blob_path).unwrap();

    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    assert_eq!(s.gc.len(), 0, "candidate should be cleared");
}

#[tokio::test]
async fn start_maintenance_runs_a_tick_and_shuts_down() {
    // spawn_periodic runs at least one tick and shuts down cleanly.
    let dir = tempfile::tempdir().unwrap();
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 1,
        },
        scrub: roci_config::ScrubConfig {
            enabled: true,
            interval_secs: 1,
            ..roci_config::ScrubConfig::default()
        },
        ..roci_config::StorageConfig::default()
    };
    let s = FsStorage::with_config(
        dir.path(),
        &config,
        std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    )
    .unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    crate::storage::StorageBackend::start_maintenance(&s, rx);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = tx.send(true);
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn malformed_index_json_makes_repo_unsafe() {
    // Unparseable index.json → repo is GC-unsafe; blobs survive.
    let (dir, s) = gc_store_cfg(0, None);
    let blob = sha256_of(b"live-but-unindexed");
    s.put_blob("r", &blob, b"live-but-unindexed").await.unwrap();
    std::fs::write(dir.path().join("r/index.json"), b"{not json").unwrap();
    s.gc_consistency_check().await;
    assert!(s.gc.is_unsafe("r"));
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(s.blob_exists("r", &blob).await.unwrap());
}

#[tokio::test]
async fn oversized_root_manifest_makes_repo_unsafe_without_buffering_it() {
    let (dir, s) = gc_store_cfg(0, None);
    let big = vec![b' '; 4 * 1024 * 1024 + 1];
    let big_d = sha256_of(&big);
    s.put_blob("r", &big_d, &big).await.unwrap();
    let layer = sha256_of(b"layer-of-big");
    s.put_blob("r", &layer, b"layer-of-big").await.unwrap();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{"mediaType": MEDIA_TYPE_IMAGE_MANIFEST, "digest": big_d.as_string(), "size": big.len()}]
    });
    std::fs::write(
        dir.path().join("r/index.json"),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();
    s.gc_consistency_check().await;
    assert!(s.gc.is_unsafe("r"));
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(s.blob_exists("r", &layer).await.unwrap());
}

#[tokio::test]
async fn sweep_skips_root_blob_and_clears_candidate() {
    let (_dir, s) = gc_store_cfg(0, None);
    let data = b"root-blob";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    s.gc.add_root("r", &d.as_string());
    s.gc.set_ready();
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(s.blob_exists("r", &d).await.unwrap(), "root blob survives");
    assert!(!s.gc.is_due(
        "r",
        &d.as_string(),
        Instant::now() + Duration::from_secs(100)
    ));
}

#[tokio::test]
async fn sweep_skips_unsafe_repo() {
    let (_dir, s) = gc_store_cfg(0, None);
    let data = b"unsafe-repo-blob";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    s.gc.mark_unsafe("r");
    s.gc.set_ready();
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(
        s.blob_exists("r", &d).await.unwrap(),
        "blob in unsafe repo survives"
    );
}

#[tokio::test]
async fn sweep_skips_blob_with_backrefs() {
    let (_dir, s) = gc_store_cfg(0, None);
    let config_data = b"cfg-for-backref-test";
    let config_d = sha256_of(config_data);
    let layer_data = b"lyr-for-backref-test";
    let layer_d = sha256_of(layer_data);
    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer_d, layer_data).await.unwrap();
    let manifest_body = make_manifest(&config_d, &[&layer_d]);
    let manifest_d = sha256_of(&manifest_body);
    let refs = manifest_references(&serde_json::from_slice(&manifest_body).unwrap());
    s.put_manifest(
        "r",
        Some("v1"),
        &manifest_d,
        MEDIA_TYPE_IMAGE_MANIFEST,
        &manifest_body,
        ManifestLinks {
            references: &refs,
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();
    // Manually mark config as GC candidate even though it has backrefs.
    s.gc.mark("r", &config_d.as_string());
    s.gc.set_ready();
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(
        s.blob_exists("r", &config_d).await.unwrap(),
        "blob with backrefs survives"
    );
}

#[tokio::test]
async fn sweep_skips_blob_that_is_a_manifest() {
    let (_dir, s) = gc_store_cfg(0, None);
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
    // The manifest blob is also stored, manually mark it as candidate.
    s.gc.mark("r", &d.as_string());
    s.gc.set_ready();
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(
        s.blob_exists("r", &d).await.unwrap(),
        "manifest blob survives sweep"
    );
}

#[tokio::test]
async fn consistency_check_adds_meta_only_repos() {
    let (_dir, s) = gc_store_cfg(0, None);
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    // Put manifest in "r" → metadata has "r"
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
    // Delete the repo dir (metadata still has "r")
    let _ = std::fs::remove_dir_all(_dir.path().join("r"));
    // Consistency check should not panic on metadata-only repos.
    s.gc_consistency_check().await;
}
