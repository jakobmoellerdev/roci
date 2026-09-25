//! GC tests: deterministic sweep timing via `sweep_at`, backref rebuild,
//! stale upload cleanup, and the concurrency property test.

use super::*;
use crate::quota::{QuotaLimits, QuotaTracker};
use roci_config::{GcConfig, StorageConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Create a store with GC enabled and the given delay (seconds).
fn gc_store(delay_secs: u64) -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs,
            interval_secs: 3600, // won't fire in tests
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    s.gc.set_ready(); // tests do their own consistency check or skip it
    (dir, s)
}

/// Create a store with GC enabled, quotas, and the given delay.
fn gc_store_with_quota(delay_secs: u64) -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let quota = Arc::new(QuotaTracker::new(QuotaLimits {
        max_upload_sessions: 100,
        ..QuotaLimits::default()
    }));
    let s = FsStorage::with_config(dir.path(), &config, quota).unwrap();
    s.gc.set_ready();
    (dir, s)
}

/// Build a minimal OCI image manifest referencing the given blob digests.
fn make_manifest(config_digest: &Digest, layer_digests: &[&Digest]) -> Vec<u8> {
    let layers: Vec<serde_json::Value> = layer_digests
        .iter()
        .map(|d| {
            serde_json::json!({
                "digest": d.as_string(),
                "mediaType": "application/octet-stream",
                "size": 0
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "digest": config_digest.as_string(),
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 0
        },
        "layers": layers
    });
    serde_json::to_vec(&manifest).unwrap()
}

// -----------------------------------------------------------------------
// Deterministic tests via sweep_at
// -----------------------------------------------------------------------

#[tokio::test]
async fn unreferenced_blob_collected_only_after_delay() {
    let (_dir, s) = gc_store(60);
    let blob_data = b"garbage layer";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    // The blob has no manifest referencing it → it's a candidate.
    assert!(!s.gc.is_empty());

    // Sweep before the delay: nothing collected.
    let now = Instant::now();
    s.sweep_at(now).await;
    assert!(s.blob_exists("r", &blob_d).await.unwrap());

    // Sweep after the delay: collected.
    let later = now + Duration::from_secs(61);
    s.sweep_at(later).await;
    assert!(!s.blob_exists("r", &blob_d).await.unwrap());
    assert_eq!(s.gc.len(), 0);
}

#[tokio::test]
async fn referenced_blob_survives_sweep() {
    let (_dir, s) = gc_store(60);
    let config_data = b"config";
    let config_d = sha256_of(config_data);
    let layer_data = b"layer data";
    let layer_d = sha256_of(layer_data);

    // Put blobs first (they become candidates).
    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer_d, layer_data).await.unwrap();

    // Put manifest referencing them (clears candidates).
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

    // They should no longer be candidates.
    assert_eq!(s.gc.len(), 0);

    // Sweep way after the delay: referenced blobs survive.
    let later = Instant::now() + Duration::from_secs(3600);
    s.sweep_at(later).await;
    assert!(s.blob_exists("r", &config_d).await.unwrap());
    assert!(s.blob_exists("r", &layer_d).await.unwrap());
}

#[tokio::test]
async fn deleting_manifest_makes_blobs_collectable_but_shared_blobs_survive() {
    let (_dir, s) = gc_store(60);
    let config_data = b"shared-config";
    let config_d = sha256_of(config_data);
    let layer1_data = b"layer for manifest A only";
    let layer1_d = sha256_of(layer1_data);
    let layer2_data = b"shared layer";
    let layer2_d = sha256_of(layer2_data);

    // Blobs.
    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer1_d, layer1_data).await.unwrap();
    s.put_blob("r", &layer2_d, layer2_data).await.unwrap();

    // Manifest A references config + layer1 + layer2.
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

    // Manifest B references config + layer2 (shares them with A).
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

    // Delete manifest A: layer1 becomes unreferenced, shared blobs keep backrefs.
    s.delete_manifest("r", &ma_d).await.unwrap();

    // layer1 should be a candidate now.
    assert!(!s.gc.is_empty());

    // Sweep after delay: layer1 collected, shared blobs survive.
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
    let (_dir, s) = gc_store(60);
    let blob_data = b"touchable";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    // Manually stamp the candidate far in the past so it's due now.
    let past = Instant::now() - Duration::from_secs(120);
    s.gc.mark_at("r", &blob_d.as_string(), past);

    // A HEAD/blob_exists "touches" the blob via want_blob, restamping it to now.
    assert!(s.blob_exists("r", &blob_d).await.unwrap());

    // Sweep at now: the touch restamped it, so despite the old mark it's not due.
    let now = Instant::now();
    s.sweep_at(now).await;
    assert!(
        s.blob_exists("r", &blob_d).await.unwrap(),
        "touch should postpone collection"
    );

    // Sweep well past the restamped time: now it's collected.
    let much_later = Instant::now() + Duration::from_secs(120);
    s.sweep_at(much_later).await;
    assert!(
        !s.blob_exists("r", &blob_d).await.unwrap(),
        "eventually collected"
    );
}

#[tokio::test]
async fn reupload_of_due_candidate_survives() {
    let (_dir, s) = gc_store(60);
    let blob_data = b"reupload me";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    // Manually stamp candidate far in the past so it's immediately due.
    let past = Instant::now() - Duration::from_secs(120);
    s.gc.mark_at("r", &blob_d.as_string(), past);

    // Re-upload the blob: put_blob → blob_entered → gc.mark restamps at now.
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    // Sweep at now: the re-upload restamped, so it's not due.
    let now = Instant::now();
    s.sweep_at(now).await;
    assert!(
        s.blob_exists("r", &blob_d).await.unwrap(),
        "reupload must survive the sweep"
    );
}

#[tokio::test]
async fn layout_only_manifests_survive_after_consistency_check() {
    // Create a store, manually write an index.json with a manifest the metadata
    // log has never seen, then run the consistency check and verify the manifest
    // and its blobs survive.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Prepare on-disk layout: repo "ext" with one manifest and one layer.
    let layer_data = b"external layer";
    let layer_d = sha256_of(layer_data);
    let config_data = b"external config";
    let config_d = sha256_of(config_data);
    let manifest_body = make_manifest(&config_d, &[&layer_d]);
    let manifest_d = sha256_of(&manifest_body);

    // Write OCI layout on disk.
    let repo_dir = root.join("ext");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::fs::write(
        repo_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let blobs_dir = repo_dir.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs_dir).unwrap();
    std::fs::write(blobs_dir.join(manifest_d.hex()), &manifest_body).unwrap();
    std::fs::write(blobs_dir.join(config_d.hex()), config_data).unwrap();
    std::fs::write(blobs_dir.join(layer_d.hex()), layer_data).unwrap();

    // Write index.json referencing the manifest.
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": manifest_d.as_string(),
            "size": manifest_body.len(),
            "annotations": { "org.opencontainers.image.ref.name": "latest" }
        }]
    });
    std::fs::write(
        repo_dir.join("index.json"),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();

    // Open the store (log has never seen this manifest).
    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs: 1,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(root, &config, Arc::new(QuotaTracker::default())).unwrap();

    // Run the consistency check (normally done by start_gc).
    s.gc_consistency_check().await;
    s.gc.set_ready();

    // The manifest should be a root.
    assert!(
        s.gc.is_root("ext", &manifest_d.as_string()),
        "layout-only manifest should be a root"
    );

    // Blobs should have their backrefs rebuilt.
    let config_backrefs = s.backrefs("ext", &config_d);
    assert!(
        config_backrefs.contains(&manifest_d.as_string()),
        "config backref should be rebuilt"
    );
    let layer_backrefs = s.backrefs("ext", &layer_d);
    assert!(
        layer_backrefs.contains(&manifest_d.as_string()),
        "layer backref should be rebuilt"
    );

    // Sweep after the delay: everything should survive.
    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    assert!(s.blob_exists("ext", &manifest_d).await.unwrap());
    assert!(s.blob_exists("ext", &config_d).await.unwrap());
    assert!(s.blob_exists("ext", &layer_d).await.unwrap());
}

#[tokio::test]
async fn missing_backrefs_are_rebuilt() {
    let (_dir, s) = gc_store(60);
    let config_data = b"cfg";
    let config_d = sha256_of(config_data);
    let layer_data = b"lyr";
    let layer_d = sha256_of(layer_data);

    // Put blobs.
    s.put_blob("r", &config_d, config_data).await.unwrap();
    s.put_blob("r", &layer_d, layer_data).await.unwrap();

    // Put manifest with EMPTY references (simulating an old log missing edges).
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

    // Backrefs should be empty for the blobs (since we passed empty references).
    assert!(s.backrefs("r", &config_d).is_empty());
    assert!(s.backrefs("r", &layer_d).is_empty());

    // Run the consistency check — it should rebuild the missing edges.
    s.gc_consistency_check().await;

    // Now backrefs should exist.
    assert!(
        s.backrefs("r", &config_d).contains(&manifest_d.as_string()),
        "config backref rebuilt by consistency check"
    );
    assert!(
        s.backrefs("r", &layer_d).contains(&manifest_d.as_string()),
        "layer backref rebuilt by consistency check"
    );

    // The blobs should survive a sweep (they're referenced now).
    s.sweep_at(Instant::now() + Duration::from_secs(120)).await;
    assert!(s.blob_exists("r", &config_d).await.unwrap());
    assert!(s.blob_exists("r", &layer_d).await.unwrap());
}

#[tokio::test]
async fn unparseable_root_manifest_makes_repo_unsafe() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Write an OCI layout with an unparseable manifest.
    let repo_dir = root.join("bad");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::fs::write(
        repo_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let bad_manifest_data = b"this is not json{{{";
    let bad_d = sha256_of(bad_manifest_data);
    let blobs_dir = repo_dir.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs_dir).unwrap();
    std::fs::write(blobs_dir.join(bad_d.hex()), bad_manifest_data).unwrap();

    // Also add an unreferenced blob that should NOT be collected.
    let blob_data = b"innocent";
    let blob_d = sha256_of(blob_data);
    std::fs::write(blobs_dir.join(blob_d.hex()), blob_data).unwrap();

    // index.json references the bad manifest.
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": bad_d.as_string(),
            "size": bad_manifest_data.len()
        }]
    });
    std::fs::write(
        repo_dir.join("index.json"),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();

    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs: 1,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(root, &config, Arc::new(QuotaTracker::default())).unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();

    assert!(s.gc.is_unsafe("bad"), "repo should be GC-unsafe");

    // Sweep: nothing in the unsafe repo should be collected.
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(std::fs::metadata(blobs_dir.join(blob_d.hex())).is_ok());
}

#[tokio::test]
async fn stale_uploads_expire() {
    let (_dir, s) = gc_store_with_quota(2);

    // Put a blob to ensure the repo has an oci-layout marker, so discover_repos
    // finds it. Without this, a repo with only uploads/ is invisible.
    let blob = sha256_of(b"anchor");
    s.put_blob("r", &blob, b"anchor").await.unwrap();

    // Begin an upload, write to it (creating its staging file) and abandon it.
    let id = s.begin_upload("r").await.unwrap();
    s.append_upload("r", &id, crate::upload_body(b"x"), None, u64::MAX)
        .await
        .unwrap();
    s.drop_session_lock("r", &id);
    assert_eq!(s.quota.sessions(), 1);

    // Touch the staging file mtime to the past to make it stale.
    let upload_path = _dir.path().join("r").join("uploads").join(&id);
    assert!(upload_path.exists());
    let past = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(&upload_path, past).unwrap();

    // Sweep: the stale upload should be cleaned up.
    s.sweep_at(Instant::now()).await;
    assert!(!upload_path.exists(), "stale upload should be removed");
    assert_eq!(s.quota.sessions(), 0, "session count should drop");
}

#[tokio::test]
async fn never_written_sessions_expire_and_release_their_slot() {
    // A begun session with no data has no staging file; the sweep expires it
    // after the delay and frees its upload-session slot. Afterwards the id is
    // unknown (a later PATCH is BLOB_UPLOAD_UNKNOWN).
    let (_dir, s) = gc_store_with_quota(0);
    s.put_blob("r", &sha256_of(b"anchor"), b"anchor").await.unwrap();
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
    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs: 0,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    // Do NOT set_ready.
    let blob_data = b"before ready";
    let blob_d = sha256_of(blob_data);
    s.put_blob("r", &blob_d, blob_data).await.unwrap();

    // Sweep: should do nothing.
    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    assert!(
        s.blob_exists("r", &blob_d).await.unwrap(),
        "blob should survive because GC is not ready"
    );
}

// -----------------------------------------------------------------------
// Concurrency/property test
// -----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_push_delete_preserves_reachable_set() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            // The grace period the design relies on: far longer than one
            // push, far shorter than the test.
            delay_secs: 1,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    s.gc.set_ready();

    let store = Arc::new(s);
    let counter = Arc::new(AtomicU64::new(0));
    let iterations = 50;
    let mut handles = Vec::new();

    // Spawn pusher tasks: each pushes a unique blob+manifest pair.
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

                // Like the manifest-push handler: check referenced blobs first
                // (refreshing their GC stamp), then commit the manifest.
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

                // Delete every other manifest (their blobs become candidates).
                if i.is_multiple_of(2) {
                    let _ = st.delete_manifest("c", &manifest_d).await;
                }
            }
        }));
    }

    // Spawn sweeper tasks: repeatedly sweep.
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

    // After quiescence: every committed (non-deleted) manifest's referenced blobs
    // must be present.
    let total = counter.load(Ordering::Relaxed);
    for i in 0..total {
        // Odd-numbered manifests were NOT deleted.
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

    // Eventually-collected: run a final sweep and check deleted manifests' blobs.
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
    // At least some deleted manifests' blobs should be collected.
    assert!(
        collected > 0,
        "GC should eventually collect blobs of deleted manifests"
    );
}

#[tokio::test]
async fn image_index_children_are_protected_as_roots() {
    // A multi-platform manifest list (image index) whose child manifests
    // are CAS blobs; GC must protect both the index and every child.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let repo_dir = root.join("multi");
    std::fs::create_dir_all(repo_dir.join("blobs").join("sha256")).unwrap();
    std::fs::write(
        repo_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();

    // A child manifest (a real image manifest).
    let child_config = b"child-config-bytes";
    let child_config_d = sha256_of(child_config);
    std::fs::write(
        repo_dir.join("blobs/sha256").join(child_config_d.hex()),
        child_config,
    )
    .unwrap();
    let child_manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "digest": child_config_d.as_string(),
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": child_config.len()
        },
        "layers": []
    });
    let child_bytes = serde_json::to_vec(&child_manifest).unwrap();
    let child_d = sha256_of(&child_bytes);
    std::fs::write(
        repo_dir.join("blobs/sha256").join(child_d.hex()),
        &child_bytes,
    )
    .unwrap();

    // The image index referencing the child.
    let index_manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": child_d.as_string(),
            "size": child_bytes.len()
        }]
    });
    let index_bytes = serde_json::to_vec(&index_manifest).unwrap();
    let index_d = sha256_of(&index_bytes);
    std::fs::write(
        repo_dir.join("blobs/sha256").join(index_d.hex()),
        &index_bytes,
    )
    .unwrap();

    // An unreferenced blob that should be collected.
    let garbage = b"garbage-multi";
    let garbage_d = sha256_of(garbage);
    std::fs::write(repo_dir.join("blobs/sha256").join(garbage_d.hex()), garbage).unwrap();

    // On-disk index.json
    let on_disk_index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": index_d.as_string(),
            "size": index_bytes.len()
        }]
    });
    std::fs::write(
        repo_dir.join("index.json"),
        serde_json::to_vec(&on_disk_index).unwrap(),
    )
    .unwrap();

    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs: 0,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(root, &config, Arc::new(QuotaTracker::default())).unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();

    // The child manifest and the index are roots — neither should be a candidate.
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

    // Sweep should collect only the garbage blob.
    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    // Child and index still exist.
    assert!(repo_dir.join("blobs/sha256").join(child_d.hex()).exists());
    assert!(repo_dir.join("blobs/sha256").join(index_d.hex()).exists());
    // Garbage should be gone.
    assert!(!repo_dir.join("blobs/sha256").join(garbage_d.hex()).exists());
}

#[tokio::test]
async fn missing_cas_root_makes_repo_unsafe() {
    // A root manifest that appears in the on-disk index but is absent from
    // the CAS: the repo must be marked GC-unsafe so nothing is collected.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let repo_dir = root.join("ghost");
    std::fs::create_dir_all(repo_dir.join("blobs").join("sha256")).unwrap();
    std::fs::write(
        repo_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();

    // Index references a digest that has no CAS blob.
    let phantom_data = b"phantom-manifest";
    let phantom_d = sha256_of(phantom_data);
    let on_disk = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": phantom_d.as_string(),
            "size": phantom_data.len()
        }]
    });
    std::fs::write(
        repo_dir.join("index.json"),
        serde_json::to_vec(&on_disk).unwrap(),
    )
    .unwrap();

    // An unreferenced blob.
    let blob_data = b"should-survive-unsafe";
    let blob_d = sha256_of(blob_data);
    std::fs::write(repo_dir.join("blobs/sha256").join(blob_d.hex()), blob_data).unwrap();

    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs: 0,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(root, &config, Arc::new(QuotaTracker::default())).unwrap();
    s.gc_consistency_check().await;
    s.gc.set_ready();

    assert!(s.gc.is_unsafe("ghost"));
    // Sweep: unsafe repo → nothing collected.
    s.sweep_at(Instant::now() + Duration::from_secs(10)).await;
    assert!(repo_dir.join("blobs/sha256").join(blob_d.hex()).exists());
}

#[tokio::test]
async fn stale_upload_locked_session_survives_sweep() {
    // A stale upload whose session is currently locked should not be cleaned up.
    let (_dir, s) = gc_store_with_quota(0);
    let blob = sha256_of(b"anchor-lock");
    s.put_blob("r", &blob, b"anchor-lock").await.unwrap();

    let id = s.begin_upload("r").await.unwrap();
    // Append some data to create a lock entry (session_lock is called).
    s.append_upload("r", &id, crate::upload_body(b"partial"), None, u64::MAX)
        .await
        .unwrap();

    // Touch the staging file mtime to the past.
    let upload_path = _dir.path().join("r").join("uploads").join(&id);
    assert!(upload_path.exists());
    let past = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(&upload_path, past).unwrap();

    // Sweep while an append/finalize holds the session: stale by mtime, but
    // a held session is in use and survives.
    let lock = s.session_lock("r", &id).unwrap();
    let held = lock.lock().await;
    s.sweep_at(Instant::now()).await;
    assert!(
        upload_path.exists(),
        "locked upload session should survive sweep"
    );
    drop(held);

    // Released and still stale: the next sweep expires it and frees the slot.
    let before = s.quota.sessions();
    s.sweep_at(Instant::now()).await;
    assert!(!upload_path.exists(), "idle stale session is expired");
    assert_eq!(s.quota.sessions(), before - 1);
}

#[tokio::test]
async fn sweep_handles_already_deleted_blob() {
    // A candidate whose file was already externally removed: sweep should
    // clear it without error.
    let (_dir, s) = gc_store(0);
    let data = b"will-vanish";
    let d = sha256_of(data);
    s.put_blob("r", &d, data).await.unwrap();
    assert!(!s.gc.is_empty());

    // Externally remove the blob file.
    let blob_path = s.blob_path("r", &d).unwrap();
    std::fs::remove_file(&blob_path).unwrap();

    // Sweep: the stat sees NotFound → blob is cleared from candidates.
    let later = Instant::now() + Duration::from_secs(10);
    s.sweep_at(later).await;
    assert_eq!(s.gc.len(), 0, "candidate should be cleared");
}

#[tokio::test]
async fn start_maintenance_runs_a_tick_and_shuts_down() {
    // Exercises start_maintenance → spawn_periodic running at least one
    // tick (covering maintenance.rs lines 39-42, 49-54, 56, 62, 85-87, 92).
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig {
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 1,
        },
        scrub: roci_config::ScrubConfig {
            enabled: true,
            interval_secs: 1,
            ..roci_config::ScrubConfig::default()
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    crate::storage::StorageBackend::start_maintenance(&s, rx);
    // Wait for spawned tasks to run consistency check + at least one tick.
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Signal shutdown (the `break` on maintenance.rs line 92).
    let _ = tx.send(true);
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn malformed_index_json_makes_repo_unsafe() {
    // An index.json that exists but cannot be parsed hides the repo's roots:
    // GC must not treat its blobs as garbage.
    let (dir, s) = gc_store(0);
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
    let (dir, s) = gc_store(0);
    // A layout-listed "manifest" larger than the 4 MiB root cap.
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
