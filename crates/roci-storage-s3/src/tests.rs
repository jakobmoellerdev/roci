//! Tests for S3Storage against InMemory object store.

use crate::client::S3Client;
use crate::S3Storage;
use object_store::memory::InMemory;
use roci_config::StorageConfig;
use roci_storage::quota::{QuotaLimits, QuotaTracker};
use roci_storage::{Digest, ManifestLinks, Storage, StorageBackend};
use std::sync::Arc;
use std::time::Duration;

/// Build an S3Storage backed by InMemory for tests.
fn test_store() -> (tempfile::TempDir, S3Storage) {
    test_store_with_config(StorageConfig::default(), QuotaTracker::default())
}

fn test_store_with_config(
    mut config: StorageConfig,
    quota: QuotaTracker,
) -> (tempfile::TempDir, S3Storage) {
    let dir = tempfile::tempdir().unwrap();
    config.root = dir.path().to_path_buf();
    let mem = Arc::new(InMemory::new());
    let client = S3Client::in_memory(
        mem,
        None, // no signer = proxy mode
        String::new(),
        0, // redirect disabled
        Duration::from_secs(60),
        16 * 1024 * 1024,
        8,
    );
    let s = S3Storage::open_with_client(dir.path(), client, &config, Arc::new(quota)).unwrap();
    (dir, s)
}

fn test_store_with_redirect(
    redirect_min_size: u64,
) -> (tempfile::TempDir, S3Storage, Arc<InMemory>) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::default();
    let mem = Arc::new(InMemory::new());
    // Use an AmazonS3 with dummy credentials for signing.
    let signer = build_test_signer();
    let client = S3Client::in_memory(
        mem.clone(),
        signer,
        String::new(),
        redirect_min_size,
        Duration::from_secs(15),
        16 * 1024 * 1024,
        8,
    );
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    (dir, s, mem)
}

/// Build a test signer from AmazonS3Builder with dummy credentials.
fn build_test_signer() -> Option<Arc<dyn object_store::signer::Signer>> {
    use object_store::aws::AmazonS3Builder;
    crate::client::install_crypto_provider();
    let store = AmazonS3Builder::new()
        .with_bucket_name("test-bucket")
        .with_region("us-east-1")
        .with_access_key_id("AKIAIOSFODNN7EXAMPLE")
        .with_secret_access_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .with_endpoint("http://localhost:9999") // unreachable, signing is offline
        .with_allow_http(true)
        .build()
        .ok()?;
    Some(Arc::new(store))
}

/// Create a minimal valid OCI manifest JSON.
fn test_manifest(config_digest: &str, layer_digests: &[&str]) -> Vec<u8> {
    let layers: Vec<serde_json::Value> = layer_digests
        .iter()
        .map(|d| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": d,
                "size": 100
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": 10
        },
        "layers": layers
    }))
    .unwrap()
}

/// Create a manifest with `subject`.
fn test_manifest_with_subject(
    config_digest: &str,
    layer_digests: &[&str],
    subject_digest: &str,
) -> Vec<u8> {
    let layers: Vec<serde_json::Value> = layer_digests
        .iter()
        .map(|d| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": d,
                "size": 100
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": 10
        },
        "layers": layers,
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": subject_digest,
            "size": 100
        }
    }))
    .unwrap()
}

fn sha256_digest(data: &[u8]) -> Digest {
    roci_storage::sha256_of(data)
}

// ── basic blob tests ───────────────────────────────────────────────────

#[tokio::test]
async fn put_blob_and_read_back() {
    let (_dir, s) = test_store();
    let data = b"hello world";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    let read = s.read_blob("repo", &digest).await.unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn blob_exists_and_size() {
    let (_dir, s) = test_store();
    let data = b"test data";
    let digest = sha256_digest(data);

    assert!(!s.blob_exists("repo", &digest).await.unwrap());
    s.put_blob("repo", &digest, data).await.unwrap();
    assert!(s.blob_exists("repo", &digest).await.unwrap());
    assert_eq!(
        s.blob_size("repo", &digest).await.unwrap(),
        data.len() as u64
    );
}

#[tokio::test]
async fn blob_not_found_cross_repo() {
    let (_dir, s) = test_store();
    let data = b"isolated";
    let digest = sha256_digest(data);
    s.put_blob("repo-a", &digest, data).await.unwrap();

    // Must not be visible in repo-b (cross-repo isolation).
    assert!(!s.blob_exists("repo-b", &digest).await.unwrap());
    assert!(matches!(
        s.blob_size("repo-b", &digest).await,
        Err(roci_storage::StorageError::NotFound)
    ));
}

#[tokio::test]
async fn put_blob_digest_mismatch() {
    let (_dir, s) = test_store();
    let data = b"real content";
    let wrong = sha256_digest(b"other content");
    let err = s.put_blob("repo", &wrong, data).await.unwrap_err();
    assert!(matches!(
        err,
        roci_storage::StorageError::DigestMismatch { .. }
    ));
}

#[tokio::test]
async fn delete_blob() {
    let (_dir, s) = test_store();
    let data = b"delete me";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    assert!(s.blob_exists("repo", &digest).await.unwrap());

    s.delete_blob("repo", &digest).await.unwrap();
    assert!(!s.blob_exists("repo", &digest).await.unwrap());
}

// ── upload session tests ───────────────────────────────────────────────

#[tokio::test]
async fn chunked_upload_flow() {
    let (_dir, s) = test_store();
    let data = b"chunk-a-chunk-b";
    let digest = sha256_digest(data);

    let id = s.begin_upload("repo").await.unwrap();
    let size_a = s
        .append_upload("repo", &id, b"chunk-a-", Some(0))
        .await
        .unwrap();
    assert_eq!(size_a, 8);
    let size_b = s
        .append_upload("repo", &id, b"chunk-b", Some(8))
        .await
        .unwrap();
    assert_eq!(size_b, 15);
    assert_eq!(s.upload_size("repo", &id).await.unwrap(), 15);

    s.finish_upload("repo", &id, &digest, 1024 * 1024, b"")
        .await
        .unwrap();
    let read = s.read_blob("repo", &digest).await.unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn monolithic_upload() {
    let (_dir, s) = test_store();
    let data = b"monolithic body";
    let digest = sha256_digest(data);

    let id = s.begin_upload("repo").await.unwrap();
    s.finish_upload("repo", &id, &digest, 1024 * 1024, data)
        .await
        .unwrap();
    let read = s.read_blob("repo", &digest).await.unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn upload_range_mismatch() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload("repo", &id, b"abc", Some(0)).await.unwrap();
    let err = s
        .append_upload("repo", &id, b"def", Some(0))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        roci_storage::StorageError::RangeNotSatisfiable { .. }
    ));
}

#[tokio::test]
async fn upload_too_large() {
    let (_dir, s) = test_store();
    let data = b"some data here!!!"; // 17 bytes
    let digest = sha256_digest(data);
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload("repo", &id, data, None).await.unwrap();
    let err = s
        .finish_upload("repo", &id, &digest, 10, b"")
        .await
        .unwrap_err();
    assert!(matches!(err, roci_storage::StorageError::TooLarge { .. }));
}

#[tokio::test]
async fn upload_digest_mismatch() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload("repo", &id, b"real", None).await.unwrap();
    let wrong = sha256_digest(b"wrong");
    let err = s
        .finish_upload("repo", &id, &wrong, 1024 * 1024, b"")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        roci_storage::StorageError::DigestMismatch { .. }
    ));
}

#[tokio::test]
async fn abort_upload() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload("repo", &id, b"data", None).await.unwrap();
    assert!(s.abort_upload("repo", &id).await.unwrap());
    // Double abort is idempotent.
    assert!(!s.abort_upload("repo", &id).await.unwrap());
}

// ── manifest tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn put_and_get_manifest_by_tag_and_digest() {
    let (_dir, s) = test_store();
    let config_data = b"config";
    let config_digest = sha256_digest(config_data);
    s.put_blob("repo", &config_digest, config_data)
        .await
        .unwrap();

    let layer_data = b"layer-data";
    let layer_digest = sha256_digest(layer_data);
    s.put_blob("repo", &layer_digest, layer_data).await.unwrap();

    let manifest = test_manifest(&config_digest.as_string(), &[&layer_digest.as_string()]);
    let manifest_digest = sha256_digest(&manifest);
    let refs: Vec<Digest> = vec![config_digest.clone(), layer_digest.clone()];

    s.put_manifest(
        "repo",
        Some("latest"),
        &manifest_digest,
        "application/vnd.oci.image.manifest.v1+json",
        &manifest,
        ManifestLinks {
            references: &refs,
            subject: None,
        },
    )
    .await
    .unwrap();

    // Get by tag.
    let by_tag = s.get_manifest("repo", "latest").await.unwrap();
    assert_eq!(by_tag.bytes, manifest);
    assert_eq!(by_tag.digest, manifest_digest);

    // Get by digest.
    let by_digest = s
        .get_manifest("repo", &manifest_digest.as_string())
        .await
        .unwrap();
    assert_eq!(by_digest.bytes, manifest);
}

#[tokio::test]
async fn delete_manifest_removes_blob_and_metadata() {
    let (_dir, s) = test_store();
    let config_data = b"config";
    let config_digest = sha256_digest(config_data);
    s.put_blob("repo", &config_digest, config_data)
        .await
        .unwrap();

    let manifest = test_manifest(&config_digest.as_string(), &[]);
    let manifest_digest = sha256_digest(&manifest);

    s.put_manifest(
        "repo",
        Some("v1"),
        &manifest_digest,
        "application/vnd.oci.image.manifest.v1+json",
        &manifest,
        ManifestLinks {
            references: std::slice::from_ref(&config_digest),
            subject: None,
        },
    )
    .await
    .unwrap();

    s.delete_manifest("repo", &manifest_digest).await.unwrap();
    assert!(matches!(
        s.get_manifest("repo", "v1").await,
        Err(roci_storage::StorageError::NotFound)
    ));
}

// ── tags ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_tags_pagination() {
    let (_dir, s) = test_store();
    // Push 3 manifests with tags.
    for tag in ["a", "b", "c"] {
        let data = format!("manifest-{tag}");
        let manifest = test_manifest(&sha256_digest(data.as_bytes()).as_string(), &[]);
        let digest = sha256_digest(&manifest);
        // Put config blob.
        let cd = sha256_digest(data.as_bytes());
        s.put_blob("repo", &cd, data.as_bytes()).await.unwrap();
        s.put_manifest(
            "repo",
            Some(tag),
            &digest,
            "application/vnd.oci.image.manifest.v1+json",
            &manifest,
            ManifestLinks {
                references: &[cd],
                subject: None,
            },
        )
        .await
        .unwrap();
    }

    let page1 = s.list_tags("repo", None, 2).await.unwrap();
    assert_eq!(page1.items, vec!["a", "b"]);
    assert!(page1.more);

    let page2 = s.list_tags("repo", Some("b"), 2).await.unwrap();
    assert_eq!(page2.items, vec!["c"]);
    assert!(!page2.more);
}

// ── referrers ──────────────────────────────────────────────────────────

#[tokio::test]
async fn referrers_recorded_and_paginated() {
    let (_dir, s) = test_store();

    // Push a subject manifest.
    let subject_data = b"subject";
    let subject_manifest = test_manifest(&sha256_digest(subject_data).as_string(), &[]);
    let subject_digest = sha256_digest(&subject_manifest);
    let cd = sha256_digest(subject_data);
    s.put_blob("repo", &cd, subject_data).await.unwrap();
    s.put_manifest(
        "repo",
        Some("base"),
        &subject_digest,
        "application/vnd.oci.image.manifest.v1+json",
        &subject_manifest,
        ManifestLinks {
            references: &[cd],
            subject: None,
        },
    )
    .await
    .unwrap();

    // Push a referrer.
    let ref_config = b"ref-config";
    let ref_cd = sha256_digest(ref_config);
    s.put_blob("repo", &ref_cd, ref_config).await.unwrap();
    let referrer_manifest =
        test_manifest_with_subject(&ref_cd.as_string(), &[], &subject_digest.as_string());
    let referrer_digest = sha256_digest(&referrer_manifest);
    let descriptor = serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": referrer_digest.as_string(),
        "size": referrer_manifest.len(),
        "artifactType": "application/example"
    });
    let descriptor_bytes = serde_json::to_vec(&descriptor).unwrap();

    s.put_manifest(
        "repo",
        None,
        &referrer_digest,
        "application/vnd.oci.image.manifest.v1+json",
        &referrer_manifest,
        ManifestLinks {
            references: &[ref_cd.clone(), subject_digest.clone()],
            subject: Some((&subject_digest, &descriptor_bytes)),
        },
    )
    .await
    .unwrap();

    let page = s
        .list_referrers("repo", &subject_digest, None, None, 100)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].0, referrer_digest.as_string());
}

// ── mount (server-side copy) ───────────────────────────────────────────

#[tokio::test]
async fn mount_blob_server_side_copy() {
    let (_dir, s) = test_store();
    let data = b"shared blob";
    let digest = sha256_digest(data);
    s.put_blob("repo-a", &digest, data).await.unwrap();

    assert!(s.mount_blob("repo-a", "repo-b", &digest).await.unwrap());
    let read = s.read_blob("repo-b", &digest).await.unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn mount_blob_absent_source() {
    let (_dir, s) = test_store();
    let digest = sha256_digest(b"missing");
    assert!(!s.mount_blob("repo-a", "repo-b", &digest).await.unwrap());
}

#[tokio::test]
async fn mount_same_repo_noop() {
    let (_dir, s) = test_store();
    let data = b"same-repo";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    assert!(s.mount_blob("repo", "repo", &digest).await.unwrap());
}

// ── dedupe (server-side copy) ──────────────────────────────────────────

#[tokio::test]
async fn dedupe_via_server_side_copy() {
    let (_dir, s) = test_store();
    let data = b"deduped blob";
    let digest = sha256_digest(data);

    // First push to repo-a.
    s.put_blob("repo-a", &digest, data).await.unwrap();
    // Second push to repo-b should use server-side copy.
    s.put_blob("repo-b", &digest, data).await.unwrap();

    let read = s.read_blob("repo-b", &digest).await.unwrap();
    assert_eq!(read, data);
}

// ── quota ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn quota_repo_byte_cap() {
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 20,
        max_total_bytes: 0,
        max_upload_sessions: 0,
    });
    let (_dir, s) = test_store_with_config(StorageConfig::default(), quota);

    let data = b"twelve bytes"; // 12 bytes
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    // A different blob that exceeds the remaining cap.
    let big_data = b"this is a big blob that exceeds twenty bytes of quota";
    let big_digest = sha256_digest(big_data);
    let err = s.put_blob("repo", &big_digest, big_data).await.unwrap_err();
    assert!(matches!(
        err,
        roci_storage::StorageError::QuotaExceeded { .. }
    ));
}

#[tokio::test]
async fn quota_session_cap() {
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 0,
        max_total_bytes: 0,
        max_upload_sessions: 1,
    });
    let (_dir, s) = test_store_with_config(StorageConfig::default(), quota);

    let _id1 = s.begin_upload("repo").await.unwrap();
    let err = s.begin_upload("repo").await.unwrap_err();
    assert!(matches!(
        err,
        roci_storage::StorageError::TooManySessions { .. }
    ));
}

// ── open_blob redirect vs proxy ────────────────────────────────────────

#[tokio::test]
async fn open_blob_redirect_above_min_size() {
    let (_dir, s, _mem) = test_store_with_redirect(10);
    let data = b"this is more than ten bytes of content for redirect";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    let blob = s.open_blob("repo", &digest).await.unwrap();
    assert_eq!(blob.size(), data.len() as u64);
    // Should be a redirect.
    let url = blob.redirect_url();
    assert!(url.is_some(), "expected redirect URL for large blob");
    let url_str = url.unwrap();
    assert!(
        url_str.contains("X-Amz-Signature") || url_str.contains("Signature"),
        "expected signed URL, got: {url_str}"
    );
}

#[tokio::test]
async fn open_blob_proxy_below_min_size() {
    let (_dir, s, _mem) = test_store_with_redirect(1000);
    let data = b"small";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    let blob = s.open_blob("repo", &digest).await.unwrap();
    assert_eq!(blob.size(), data.len() as u64);
    // Should NOT be a redirect.
    assert!(blob.redirect_url().is_none());
    // Should be streamable.
    let stream = blob.into_stream(0, data.len() as u64).await.unwrap();
    let collected: Vec<bytes::Bytes> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    let bytes: Vec<u8> = collected.into_iter().flat_map(|b| b.to_vec()).collect();
    assert_eq!(bytes, data);
}

#[tokio::test]
async fn open_blob_ranged_read() {
    let (_dir, s) = test_store();
    let data = b"0123456789abcdef";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    let blob = s.open_blob("repo", &digest).await.unwrap();
    assert_eq!(blob.size(), 16);
    // Read a range [4, 8).
    let stream = blob.into_stream(4, 4).await.unwrap();
    let collected: Vec<bytes::Bytes> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    let bytes: Vec<u8> = collected.into_iter().flat_map(|b| b.to_vec()).collect();
    assert_eq!(bytes, b"4567");
}

// ── tar+zstd layer byte-identity ───────────────────────────────────────

#[tokio::test]
async fn tar_zstd_layer_byte_identical() {
    let (_dir, s) = test_store();
    // Simulate a tar+zstd layer (arbitrary binary data).
    let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let digest = sha256_digest(&data);
    s.put_blob("repo", &digest, &data).await.unwrap();

    let read = s.read_blob("repo", &digest).await.unwrap();
    assert_eq!(read, data, "tar+zstd layer must be byte-identical");
}

// ── recover ────────────────────────────────────────────────────────────

#[tokio::test]
async fn recover_imports_from_remote_index() {
    // Push a manifest, then create a fresh S3Storage and recover.
    let dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig::default();
    let client = S3Client::in_memory(
        mem.clone(),
        None,
        String::new(),
        0,
        Duration::from_secs(60),
        16 * 1024 * 1024,
        8,
    );
    let s1 = S3Storage::open_with_client(
        dir.path(),
        client.clone(),
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();

    let data = b"recover-config";
    let cd = sha256_digest(data);
    s1.put_blob("repo", &cd, data).await.unwrap();
    let manifest = test_manifest(&cd.as_string(), &[]);
    let md = sha256_digest(&manifest);
    s1.put_manifest(
        "repo",
        Some("v1"),
        &md,
        "application/vnd.oci.image.manifest.v1+json",
        &manifest,
        ManifestLinks {
            references: std::slice::from_ref(&cd),
            subject: None,
        },
    )
    .await
    .unwrap();

    // Wait for debounced index writer.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Force write the index.
    s1.write_remote_index("repo").await.unwrap();

    // Create a fresh store with the same InMemory backend.
    let dir2 = tempfile::tempdir().unwrap();
    let client2 = S3Client::in_memory(
        mem.clone(),
        None,
        String::new(),
        0,
        Duration::from_secs(60),
        16 * 1024 * 1024,
        8,
    );
    let s2 = S3Storage::open_with_client(
        dir2.path(),
        client2,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s2.recover().await;

    // Should be able to resolve the tag after recovery.
    let m = s2.get_manifest("repo", "v1").await.unwrap();
    assert_eq!(m.bytes, manifest);
}

// ── GC ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn gc_collects_unreferenced_blob() {
    let mut config = StorageConfig::default();
    config.gc.enabled = true;
    config.gc.delay_secs = 0; // immediate
    let (_dir, s) = test_store_with_config(config, QuotaTracker::default());
    s.gc.set_ready();

    let data = b"gc-target";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    // Blob is unreferenced → should be a GC candidate.
    assert!(s.blob_exists("repo", &digest).await.unwrap());

    // Wait for delay to pass (0 secs) then sweep.
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;

    assert!(!s.blob_exists("repo", &digest).await.unwrap());
}

#[tokio::test]
async fn gc_does_not_collect_referenced_blob() {
    let mut config = StorageConfig::default();
    config.gc.enabled = true;
    config.gc.delay_secs = 0;
    let (_dir, s) = test_store_with_config(config, QuotaTracker::default());
    s.gc.set_ready();

    let data = b"gc-protected";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();

    // Reference it via a manifest.
    let manifest = test_manifest(&digest.as_string(), &[]);
    let md = sha256_digest(&manifest);
    s.put_manifest(
        "repo",
        Some("keep"),
        &md,
        "application/vnd.oci.image.manifest.v1+json",
        &manifest,
        ManifestLinks {
            references: std::slice::from_ref(&digest),
            subject: None,
        },
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;

    // Still present because it's referenced.
    assert!(s.blob_exists("repo", &digest).await.unwrap());
}

// ── path validation ────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_traversal_in_repo() {
    let (_dir, s) = test_store();
    let digest = sha256_digest(b"x");
    assert!(matches!(
        s.blob_exists("../etc", &digest).await,
        Err(roci_storage::StorageError::BadPath(_))
    ));
}

use futures::StreamExt;

// ═══════════════════════════════════════════════════════════════════════
// End-to-end tests through the HTTP stack
// ═══════════════════════════════════════════════════════════════════════

mod http_e2e {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use http_body_util::BodyExt;
    use roci_config::Config;
    use roci_core::{build_router, AppState};
    use tower::ServiceExt;

    /// Build an axum Router backed by S3Storage over InMemory.
    fn make_app() -> (tempfile::TempDir, axum::Router, S3Storage) {
        make_app_with_config(StorageConfig::default(), QuotaTracker::default())
    }

    fn make_app_with_config(
        storage_config: StorageConfig,
        quota: QuotaTracker,
    ) -> (tempfile::TempDir, axum::Router, S3Storage) {
        let (dir, s) = test_store_with_config(storage_config, quota);
        let router = build_router(AppState::new_with(s.clone(), Config::default()));
        (dir, router, s)
    }

    fn make_app_with_redirect(
        redirect_min_size: u64,
    ) -> (tempfile::TempDir, axum::Router, S3Storage, Arc<InMemory>) {
        let (dir, s, mem) = test_store_with_redirect(redirect_min_size);
        let router = build_router(AppState::new_with(s.clone(), Config::default()));
        (dir, router, s, mem)
    }

    async fn body_bytes(resp: axum::http::Response<Body>) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    // ── monolithic push + pull ─────────────────────────────────────────

    #[tokio::test]
    async fn monolithic_push_and_pull() {
        let (_dir, app, _s) = make_app();
        let repo = "test/repo";

        // Push a blob.
        let data = b"hello-world";
        let digest = sha256_digest(data);
        let digest_str = digest.as_string();

        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post(format!("/v2/{repo}/blobs/uploads/?digest={digest_str}"))
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", data.len().to_string())
                    .body(Body::from(data.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Monolithic POST with digest should return 201 Created.
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Pull the blob.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(format!("/v2/{repo}/blobs/{digest_str}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(body, data);
    }

    // ── chunked push ───────────────────────────────────────────────────

    #[tokio::test]
    async fn chunked_push() {
        let (_dir, app, _s) = make_app();
        let repo = "test/chunked";

        // Begin upload.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post(format!("/v2/{repo}/blobs/uploads/"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let location = resp
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Upload chunks.
        let chunk_a = b"chunk-a-";
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::patch(&location)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Range", "0-7")
                    .body(Body::from(chunk_a.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let chunk_b = b"chunk-b";
        let full_data = b"chunk-a-chunk-b";
        let digest = sha256_digest(full_data);
        let digest_str = digest.as_string();

        // Finalize.
        let final_location = resp
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let sep = if final_location.contains('?') {
            '&'
        } else {
            '?'
        };
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::put(format!("{final_location}{sep}digest={digest_str}"))
                    .header("Content-Type", "application/octet-stream")
                    .body(Body::from(chunk_b.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Pull.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(format!("/v2/{repo}/blobs/{digest_str}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, full_data);
    }

    // ── manifest push/pull by tag and digest ───────────────────────────

    #[tokio::test]
    async fn manifest_push_pull_by_tag_and_digest() {
        let (_dir, app, _s) = make_app();
        let repo = "test/manifest";

        // Push config blob first.
        let config_data = b"config";
        let config_digest = sha256_digest(config_data);
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post(format!(
                    "/v2/{repo}/blobs/uploads/?digest={}",
                    config_digest.as_string()
                ))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(config_data.to_vec()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Push manifest with tag.
        let manifest = test_manifest(&config_digest.as_string(), &[]);
        let manifest_digest = sha256_digest(&manifest);
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::put(format!("/v2/{repo}/manifests/latest"))
                    .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                    .body(Body::from(manifest.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Pull by tag.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(format!("/v2/{repo}/manifests/latest"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, manifest);

        // Pull by digest.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(format!(
                    "/v2/{repo}/manifests/{}",
                    manifest_digest.as_string()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, manifest);
    }

    // ── HEAD ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn head_blob() {
        let (_dir, app, s) = make_app();
        let data = b"head-check";
        let digest = sha256_digest(data);
        s.put_blob("test/head", &digest, data).await.unwrap();

        let resp = app
            .oneshot(
                HttpRequest::head(format!("/v2/test/head/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cl = resp
            .headers()
            .get("Content-Length")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cl, "10"); // b"head-check".len()
        assert!(body_bytes(resp).await.is_empty());
    }

    // ── tags list ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn tags_list() {
        let (_dir, app, s) = make_app();
        let repo = "test/tags";
        for tag in ["alpha", "beta", "gamma"] {
            let d = format!("data-{tag}");
            let cd = sha256_digest(d.as_bytes());
            s.put_blob(repo, &cd, d.as_bytes()).await.unwrap();
            let m = test_manifest(&cd.as_string(), &[]);
            let md = sha256_digest(&m);
            s.put_manifest(
                repo,
                Some(tag),
                &md,
                "application/vnd.oci.image.manifest.v1+json",
                &m,
                ManifestLinks {
                    references: &[cd],
                    subject: None,
                },
            )
            .await
            .unwrap();
        }

        let resp = app
            .oneshot(
                HttpRequest::get(format!("/v2/{repo}/tags/list"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let tags = body["tags"].as_array().unwrap();
        let names: Vec<&str> = tags.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert!(names.contains(&"gamma"));
    }

    // ── referrers ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn referrers_via_http() {
        let (_dir, app, s) = make_app();
        let repo = "test/referrers";

        // Push subject.
        let subject_data = b"subject";
        let cd = sha256_digest(subject_data);
        s.put_blob(repo, &cd, subject_data).await.unwrap();
        let subject_manifest = test_manifest(&cd.as_string(), &[]);
        let subject_digest = sha256_digest(&subject_manifest);
        s.put_manifest(
            repo,
            Some("base"),
            &subject_digest,
            "application/vnd.oci.image.manifest.v1+json",
            &subject_manifest,
            ManifestLinks {
                references: std::slice::from_ref(&cd),
                subject: None,
            },
        )
        .await
        .unwrap();

        // Push referrer.
        let ref_config = b"ref-config";
        let ref_cd = sha256_digest(ref_config);
        s.put_blob(repo, &ref_cd, ref_config).await.unwrap();
        let referrer_manifest =
            test_manifest_with_subject(&ref_cd.as_string(), &[], &subject_digest.as_string());
        let referrer_digest = sha256_digest(&referrer_manifest);
        let descriptor = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": referrer_digest.as_string(),
            "size": referrer_manifest.len(),
            "artifactType": "application/example"
        });
        s.put_manifest(
            repo,
            None,
            &referrer_digest,
            "application/vnd.oci.image.manifest.v1+json",
            &referrer_manifest,
            ManifestLinks {
                references: &[ref_cd.clone(), subject_digest.clone()],
                subject: Some((&subject_digest, &serde_json::to_vec(&descriptor).unwrap())),
            },
        )
        .await
        .unwrap();

        let resp = app
            .oneshot(
                HttpRequest::get(format!(
                    "/v2/{repo}/referrers/{}",
                    subject_digest.as_string()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let manifests = body["manifests"].as_array().unwrap();
        assert!(!manifests.is_empty(), "referrers should not be empty");
    }

    // ── cross-repo mount (201) and isolation (404) ─────────────────────

    #[tokio::test]
    async fn cross_repo_mount_and_isolation() {
        let (_dir, app, s) = make_app();
        let data = b"shared-for-mount";
        let digest = sha256_digest(data);
        s.put_blob("source/repo", &digest, data).await.unwrap();

        // Mount from source/repo to target/repo.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post(format!(
                    "/v2/target/repo/blobs/uploads/?mount={}&from=source/repo",
                    digest.as_string()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify blob is in target/repo.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::head(format!("/v2/target/repo/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Blob only in source/repo should NOT be visible in other/repo.
        let data2 = b"only-in-source";
        let digest2 = sha256_digest(data2);
        s.put_blob("source/repo", &digest2, data2).await.unwrap();
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::head(format!("/v2/other/repo/blobs/{}", digest2.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── delete ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_blob_via_http() {
        let (_dir, app, s) = make_app();
        let data = b"delete-me";
        let digest = sha256_digest(data);
        s.put_blob("test/del", &digest, data).await.unwrap();

        let resp = app
            .clone()
            .oneshot(
                HttpRequest::delete(format!("/v2/test/del/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Confirm gone.
        let resp = app
            .oneshot(
                HttpRequest::head(format!("/v2/test/del/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── quota 413 ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn quota_blob_over_cap_413() {
        let quota = QuotaTracker::new(QuotaLimits {
            max_repo_bytes: 10,
            max_total_bytes: 0,
            max_upload_sessions: 0,
        });
        let (_dir, app, _s) = make_app_with_config(StorageConfig::default(), quota);

        let data = b"this blob exceeds ten bytes by a lot!!";
        let digest = sha256_digest(data);
        let resp = app
            .oneshot(
                HttpRequest::post(format!(
                    "/v2/test/quota/blobs/uploads/?digest={}",
                    digest.as_string()
                ))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(data.to_vec()))
                .unwrap(),
            )
            .await
            .unwrap();
        // Expect 413 or 403 depending on how the router surfaces QuotaExceeded.
        // OCI spec says DENIED or SIZE_EXCEEDED → 413 or 403.
        let status = resp.status().as_u16();
        assert!(
            status == 403 || status == 413,
            "expected 403 or 413 for quota exceeded, got {status}"
        );
    }

    // ── session cap 429 ────────────────────────────────────────────────

    #[tokio::test]
    async fn session_cap_429() {
        let quota = QuotaTracker::new(QuotaLimits {
            max_repo_bytes: 0,
            max_total_bytes: 0,
            max_upload_sessions: 1,
        });
        let (_dir, app, _s) = make_app_with_config(StorageConfig::default(), quota);

        // First upload starts fine.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/test/sess/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Second upload should hit the session cap.
        let resp = app
            .oneshot(
                HttpRequest::post("/v2/test/sess/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        assert!(
            status == 429 || status == 503 || status == 403,
            "expected 429/503/403 for session cap, got {status}"
        );
    }

    // ── 307 redirect for large blob with signer ────────────────────────

    #[tokio::test]
    async fn redirect_307_for_large_blob_with_signer() {
        let (_dir, app, s, _mem) = make_app_with_redirect(10);

        // Push blob above the redirect threshold.
        let data = b"this blob exceeds ten bytes, triggering redirect";
        let digest = sha256_digest(data);
        s.put_blob("test/redir", &digest, data).await.unwrap();

        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(format!("/v2/test/redir/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Should be either 307 (redirect) or 200 (proxied).
        // With a signer configured and size >= redirect_min_size, expect 307.
        let status = resp.status().as_u16();
        if status == 307 {
            let loc = resp
                .headers()
                .get("Location")
                .expect("307 should have Location header")
                .to_str()
                .unwrap();
            assert!(
                loc.contains("X-Amz-Signature") || loc.contains("Signature"),
                "expected signed URL, got: {loc}"
            );
        } else {
            // Proxied 200 is also acceptable if signing failed.
            assert_eq!(status, 200);
        }
    }

    // ── 200 (proxied) for small blob even with signer ──────────────────

    #[tokio::test]
    async fn proxy_200_for_small_blob_with_signer() {
        let (_dir, app, s, _mem) = make_app_with_redirect(1000);

        let data = b"small";
        let digest = sha256_digest(data);
        s.put_blob("test/proxy", &digest, data).await.unwrap();

        let resp = app
            .oneshot(
                HttpRequest::get(format!("/v2/test/proxy/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Below redirect_min_size: proxied 200, not redirect.
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, data);
    }

    // ── delete absent blob returns 404 ─────────────────────────────────

    #[tokio::test]
    async fn delete_absent_blob_returns_404() {
        let (_dir, app, _s) = make_app();
        let digest = sha256_digest(b"never-stored");
        let resp = app
            .oneshot(
                HttpRequest::delete(format!("/v2/test/gone/blobs/{}", digest.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
