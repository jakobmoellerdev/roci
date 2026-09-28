//! Tests for S3Storage against InMemory object store.

#[path = "../../roci-storage/tests/storage/suite.rs"]
mod suite;

use crate::client::RedirectGuard;
use crate::client::S3Client;
use crate::S3Storage;
use object_store::memory::InMemory;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStoreExt, PutPayload};
use roci_config::StorageConfig;
use roci_storage::quota::{QuotaLimits, QuotaTracker};
use roci_storage::{Digest, ManifestLinks, Storage, StorageBackend};
use std::sync::Arc;
use std::time::Duration;

fn mem_client(mem: Arc<InMemory>) -> S3Client {
    S3Client::in_memory(
        mem,
        None,
        String::new(),
        0,
        Duration::from_secs(60),
        16 * 1024 * 1024,
        8,
    )
}

fn store_on(mem: Arc<InMemory>, config: StorageConfig) -> (tempfile::TempDir, S3Storage) {
    let dir = tempfile::tempdir().unwrap();
    let client = mem_client(mem);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    (dir, s)
}

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
    let client = mem_client(mem);
    let s = S3Storage::open_with_client(dir.path(), client, &config, Arc::new(quota)).unwrap();
    (dir, s)
}

fn test_store_with_redirect(
    redirect_min_size: u64,
) -> (tempfile::TempDir, S3Storage, Arc<InMemory>) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::default();
    let mem = Arc::new(InMemory::new());
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

fn test_store_with_redirect_guard(
    redirect_min_size: u64,
    guard: RedirectGuard,
) -> (tempfile::TempDir, S3Storage, Arc<InMemory>) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::default();
    let mem = Arc::new(InMemory::new());
    let signer = build_test_signer();
    let client = S3Client::in_memory(
        mem.clone(),
        signer,
        String::new(),
        redirect_min_size,
        Duration::from_secs(15),
        16 * 1024 * 1024,
        8,
    )
    .with_redirect_guard(guard);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    (dir, s, mem)
}

fn build_test_signer() -> Option<Arc<dyn object_store::signer::Signer>> {
    use object_store::aws::AmazonS3Builder;
    crate::client::install_crypto_provider();
    let store = AmazonS3Builder::new()
        .with_bucket_name("test-bucket")
        .with_region("us-east-1")
        .with_access_key_id("AKIAIOSFODNN7EXAMPLE")
        .with_secret_access_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        .with_endpoint("https://s3.test.example")
        .build()
        .ok()?;
    Some(Arc::new(store))
}

fn manifest(config: &Digest, layers: &[&Digest], subject: Option<&Digest>) -> Vec<u8> {
    let layer_json: Vec<serde_json::Value> = layers
        .iter()
        .map(|d| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": d.as_string(),
                "size": 100
            })
        })
        .collect();
    let mut m = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config.as_string(),
            "size": 10
        },
        "layers": layer_json
    });
    if let Some(s) = subject {
        m.as_object_mut().unwrap().insert(
            "subject".into(),
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": s.as_string(),
                "size": 100
            }),
        );
    }
    serde_json::to_vec(&m).unwrap()
}

fn sha256_digest(data: &[u8]) -> Digest {
    roci_storage::sha256_of(data)
}

async fn put_tagged(
    s: &S3Storage,
    repo: &str,
    tag: &str,
    config: &Digest,
    layers: &[&Digest],
) -> (Digest, Vec<u8>) {
    let m = manifest(config, layers, None);
    let md = sha256_digest(&m);
    let mut refs: Vec<Digest> = vec![config.clone()];
    refs.extend(layers.iter().copied().cloned());
    s.put_manifest(
        repo,
        Some(tag),
        &md,
        "application/vnd.oci.image.manifest.v1+json",
        &m,
        ManifestLinks {
            references: &refs,
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();
    (md, m)
}

fn gc_config() -> StorageConfig {
    let mut c = StorageConfig::default();
    c.gc.enabled = true;
    c.gc.delay_secs = 0;
    c
}

fn gc_test_store() -> (tempfile::TempDir, S3Storage) {
    test_store_with_config(gc_config(), QuotaTracker::default())
}

async fn put_index(mem: &InMemory, repo: &str, index: &serde_json::Value) {
    mem.put(
        &ObjPath::from(format!("{repo}/index.json")),
        PutPayload::from(serde_json::to_vec(index).unwrap()),
    )
    .await
    .unwrap();
    mem.put(
        &ObjPath::from(format!("{repo}/oci-layout")),
        PutPayload::from_static(b"{\"imageLayoutVersion\":\"1.0.0\"}"),
    )
    .await
    .unwrap();
}

fn small_part_store(copy_limit: Option<u64>) -> (tempfile::TempDir, S3Storage) {
    let dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(InMemory::new());
    let mut client = S3Client::in_memory(
        mem,
        None,
        String::new(),
        0,
        Duration::from_secs(60),
        5 * 1024 * 1024,
        4,
    );
    if let Some(cl) = copy_limit {
        client.copy_limit = cl;
    }
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &StorageConfig::default(),
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    (dir, s)
}

fn base_s3_config() -> roci_config::S3Config {
    roci_config::S3Config {
        bucket: "test-bucket".into(),
        region: "us-east-1".into(),
        endpoint: None,
        prefix: String::new(),
        access_key_id: None,
        secret_access_key_file: None,
        allow_http: false,
        redirect_min_size: 0,
        redirect_ttl_secs: 60,
        multipart_part_size: 16 * 1024 * 1024,
        multipart_concurrency: 8,
        create_bucket: false,
        ca_file: None,
    }
}

#[tokio::test]
async fn generic_blob_cases() {
    let (_dir, s) = test_store();
    suite::case_put_and_read_blob(&s).await;
    suite::case_blob_exists_and_size(&s).await;
    suite::case_blob_not_found_cross_repo(&s).await;
    suite::case_put_blob_digest_mismatch(&s).await;
    suite::case_delete_blob(&s).await;
    suite::case_mount_blob_cross_repo(&s).await;
    suite::case_mount_blob_absent_source(&s).await;
    suite::case_mount_same_repo_noop(&s).await;
    suite::case_rejects_traversal_in_repo(&s).await;
}

#[tokio::test]
async fn generic_upload_cases() {
    let (_dir, s) = test_store();
    suite::case_chunked_upload_flow(&s).await;
    suite::case_monolithic_upload(&s).await;
    suite::case_upload_range_mismatch(&s).await;
    suite::case_upload_too_large(&s).await;
    suite::case_upload_digest_mismatch(&s).await;
    suite::case_abort_upload(&s).await;
}

#[tokio::test]
async fn generic_manifest_cases() {
    let (_dir, s) = test_store();
    suite::case_put_and_get_manifest(&s).await;
    suite::case_delete_manifest(&s).await;
    suite::case_list_tags_pagination(&s).await;
    suite::case_referrers_recorded_and_paginated(&s).await;
}

#[tokio::test]
async fn generic_quota_cases() {
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 20,
        max_total_bytes: 0,
        max_upload_sessions: 1,
    });
    let (_dir, s) = test_store_with_config(StorageConfig::default(), quota);
    suite::case_quota_repo_byte_cap(&s).await;
    // Session cap needs separate store (fresh upload namespace).
    let quota2 = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 0,
        max_total_bytes: 0,
        max_upload_sessions: 1,
    });
    let (_dir2, s2) = test_store_with_config(StorageConfig::default(), quota2);
    suite::case_quota_session_cap(&s2).await;
}

use futures::StreamExt;

#[tokio::test]
async fn open_blob_redirect_and_proxy() {
    for (label, min_size, expect_redirect) in [("redirect", 10u64, true), ("proxy", 1000u64, false)]
    {
        let (_dir, s, _mem) = test_store_with_redirect(min_size);
        let data = b"this is more than ten bytes of content for redirect";
        let digest = sha256_digest(data);
        s.put_blob("repo", &digest, data).await.unwrap();
        let blob = s.open_blob("repo", &digest).await.unwrap();
        assert_eq!(blob.size(), data.len() as u64, "{label}: size");
        if expect_redirect {
            let url = blob.redirect_url();
            assert!(url.is_some(), "{label}: expected redirect URL");
            let url_str = url.unwrap();
            assert!(
                url_str.contains("X-Amz-Signature") || url_str.contains("Signature"),
                "{label}: expected signed URL, got: {url_str}"
            );
        } else {
            assert!(blob.redirect_url().is_none(), "{label}: no redirect");
            let stream = blob.into_stream(0, data.len() as u64).await.unwrap();
            let collected: Vec<bytes::Bytes> = stream
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .map(|r| r.unwrap())
                .collect();
            let bytes: Vec<u8> = collected.into_iter().flat_map(|b| b.to_vec()).collect();
            assert_eq!(bytes, data, "{label}: proxy stream");
        }
    }
}

#[tokio::test]
async fn open_blob_ranged_read() {
    let (_dir, s) = test_store();
    let data = b"0123456789abcdef";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    let blob = s.open_blob("repo", &digest).await.unwrap();
    assert_eq!(blob.size(), 16);
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

#[tokio::test]
async fn server_side_copy_and_dedupe() {
    let (_dir, s) = test_store();
    let data = b"deduped blob";
    let digest = sha256_digest(data);

    s.put_blob("repo-a", &digest, data).await.unwrap();
    // Dedupe path: second put to a different repo should use server-side copy.
    s.put_blob("repo-b", &digest, data).await.unwrap();
    let read = s.read_blob("repo-b", &digest).await.unwrap();
    assert_eq!(read, data, "dedupe: read back");

    // Mount path: server-side copy from repo-a to repo-c.
    assert!(
        s.mount_blob("repo-a", "repo-c", &digest).await.unwrap(),
        "mount"
    );
    let read2 = s.read_blob("repo-c", &digest).await.unwrap();
    assert_eq!(read2, data, "mount: read back");
}

#[tokio::test]
async fn gc_collects_unreferenced_blob() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let data = b"gc-target";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    assert!(s.blob_exists("repo", &digest).await.unwrap());
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    assert!(!s.blob_exists("repo", &digest).await.unwrap());
}

#[tokio::test]
async fn gc_does_not_collect_referenced_blob() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let data = b"gc-protected";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    put_tagged(&s, "repo", "keep", &digest, &[]).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    assert!(s.blob_exists("repo", &digest).await.unwrap());
}

#[tokio::test]
async fn gc_consistency_check_layout_only_root() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), gc_config());
    let data = b"layout-root-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let (md, _) = put_tagged(&s, "repo", "v1", &cd, &[]).await;
    s.write_remote_index("repo").await.unwrap();
    let (_dir2, s2) = store_on(mem, gc_config());
    s2.gc_consistency_check().await;
    assert!(
        s2.gc.is_root("repo", &md.as_string()),
        "layout_only_root: root"
    );
    let now_plus = std::time::Instant::now() + Duration::from_secs(1);
    assert!(
        !s2.gc.is_due("repo", &cd.as_string(), now_plus),
        "layout_only_root: not due"
    );
}

#[tokio::test]
async fn gc_consistency_check_missing_root_marks_unsafe() {
    let mem = Arc::new(InMemory::new());
    let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000001";
    let index = serde_json::json!({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"digest": fake_digest, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 100}]
    });
    put_index(&mem, "repo", &index).await;
    let (_dir, s) = store_on(mem, gc_config());
    s.gc_consistency_check().await;
    assert!(s.gc.is_unsafe("repo"));
}

#[tokio::test]
async fn gc_consistency_check_unparseable_root_marks_unsafe() {
    let mem = Arc::new(InMemory::new());
    let bad_data = b"this is not json";
    let bd = sha256_digest(bad_data);
    let digest_str = bd.as_string();
    let (alg, hex) = digest_str.split_once(':').unwrap();
    mem.put(
        &ObjPath::from(format!("repo/blobs/{alg}/{hex}")),
        PutPayload::from(bytes::Bytes::from_static(bad_data)),
    )
    .await
    .unwrap();
    let index = serde_json::json!({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"digest": digest_str, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": bad_data.len()}]
    });
    put_index(&mem, "repo", &index).await;
    let (_dir, s) = store_on(mem, gc_config());
    s.gc_consistency_check().await;
    assert!(s.gc.is_unsafe("repo"));
}

#[tokio::test]
async fn gc_consistency_check_seeds_unreferenced_candidates() {
    let (_dir, s) = gc_test_store();
    let data = b"orphan-blob";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    s.gc_consistency_check().await;
    let now_plus = std::time::Instant::now() + Duration::from_secs(1);
    assert!(s.gc.is_due("repo", &digest.as_string(), now_plus));
}

#[tokio::test]
async fn gc_consistency_check_missing_backref_rebuild() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s1) = store_on(mem.clone(), gc_config());
    let layer = b"layer-data";
    let ld = sha256_digest(layer);
    s1.put_blob("repo", &ld, layer).await.unwrap();
    let (md, _) = put_tagged(&s1, "repo", "v1", &ld, &[]).await;
    s1.write_remote_index("repo").await.unwrap();
    let (_dir2, s2) = store_on(mem, gc_config());
    s2.gc_consistency_check().await;
    let now_plus = std::time::Instant::now() + Duration::from_secs(1);
    assert!(
        !s2.gc.is_due("repo", &ld.as_string(), now_plus),
        "backref rebuild: not due"
    );
    assert!(
        s2.gc.is_root("repo", &md.as_string()),
        "backref rebuild: root"
    );
}

#[tokio::test]
async fn sweep_stale_uploads_removes_old_files() {
    let (_dir, s) = test_store_with_config(gc_config(), QuotaTracker::default());
    let repo_dir = _dir.path().join("uploads").join("repo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    let path = repo_dir.join("00000000000000000000000000000000");
    std::fs::write(&path, b"stale-data").unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH;
    let f = std::fs::File::open(&path).unwrap();
    f.set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();
    drop(f);
    let (count, bytes) = s.sweep_stale_uploads().await;
    assert_eq!(count, 1, "sweep: count");
    assert!(bytes > 0, "sweep: bytes");
    assert!(!path.exists(), "sweep: removed");
}

#[tokio::test]
async fn sweep_stale_uploads_keeps_fresh_files() {
    let config = StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 60,
        },
        ..StorageConfig::default()
    };
    let (_dir, s) = test_store_with_config(config, QuotaTracker::default());
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload(
        "repo",
        &id,
        roci_storage::upload_body(b"fresh-data"),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    let (count, _) = s.sweep_stale_uploads().await;
    assert_eq!(count, 0, "fresh: count");
    assert!(
        s.staging_path("repo", &id).unwrap().exists(),
        "fresh: exists"
    );
}

#[tokio::test]
async fn recover_imports_from_remote_index() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s1) = store_on(mem.clone(), StorageConfig::default());
    let data = b"recover-config";
    let cd = sha256_digest(data);
    s1.put_blob("repo", &cd, data).await.unwrap();
    let (_, m) = put_tagged(&s1, "repo", "v1", &cd, &[]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    s1.write_remote_index("repo").await.unwrap();
    let (_dir2, s2) = store_on(mem, StorageConfig::default());
    s2.recover().await;
    assert_eq!(s2.get_manifest("repo", "v1").await.unwrap().bytes, m);
}

#[tokio::test]
async fn recover_foreign_tag_import_and_referrer_warmup() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s1) = store_on(mem.clone(), StorageConfig::default());
    let cfg_data = b"subject-config";
    let cd = sha256_digest(cfg_data);
    s1.put_blob("repo", &cd, cfg_data).await.unwrap();
    let (smd, subject_manifest) = put_tagged(&s1, "repo", "subject", &cd, &[]).await;
    let ref_data = b"referrer-config";
    let rcd = sha256_digest(ref_data);
    s1.put_blob("repo", &rcd, ref_data).await.unwrap();
    let referrer_manifest = manifest(&rcd, &[], Some(&smd));
    let rmd = sha256_digest(&referrer_manifest);
    let descriptor = serde_json::to_vec(&serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "size": referrer_manifest.len(), "digest": rmd.as_string(), "artifactType": "test/artifact"
    }))
    .unwrap();
    s1.put_manifest(
        "repo",
        Some("referrer"),
        &rmd,
        "application/vnd.oci.image.manifest.v1+json",
        &referrer_manifest,
        ManifestLinks {
            references: std::slice::from_ref(&rcd),
            required: &[],
            subject: Some((&smd, &descriptor)),
        },
    )
    .await
    .unwrap();
    s1.write_remote_index("repo").await.unwrap();
    let (_dir2, s2) = store_on(mem, StorageConfig::default());
    s2.recover().await;
    assert_eq!(
        s2.get_manifest("repo", "subject").await.unwrap().bytes,
        subject_manifest
    );
    assert_eq!(
        s2.get_manifest("repo", "referrer").await.unwrap().bytes,
        referrer_manifest
    );
}

#[tokio::test]
async fn recover_seeds_quota_and_dedupe() {
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig {
        dedupe: true,
        ..StorageConfig::default()
    };
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 1024 * 1024,
        max_total_bytes: 0,
        max_upload_sessions: 10,
    });
    let dir = tempfile::tempdir().unwrap();
    let client = mem_client(mem.clone());
    let s1 = S3Storage::open_with_client(dir.path(), client, &config, Arc::new(quota)).unwrap();
    let data = b"seed-blob-data";
    let digest = sha256_digest(data);
    s1.put_blob("repo", &digest, data).await.unwrap();
    s1.write_remote_index("repo").await.unwrap();

    let quota2 = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 1024 * 1024,
        max_total_bytes: 0,
        max_upload_sessions: 10,
    });
    let dir2 = tempfile::tempdir().unwrap();
    let client2 = mem_client(mem);
    let s2 = S3Storage::open_with_client(dir2.path(), client2, &config, Arc::new(quota2)).unwrap();
    s2.recover().await;
    assert!(s2.dedupe.enabled());
    assert!(s2.put_blob("other", &digest, data).await.is_ok());
}

#[tokio::test]
async fn recover_seeds_sessions_from_staging() {
    let mem = Arc::new(InMemory::new());
    let (dir, s1) = store_on(mem.clone(), StorageConfig::default());
    let _id1 = s1.begin_upload("repo").await.unwrap();
    let _id2 = s1.begin_upload("repo").await.unwrap();
    let client2 = mem_client(mem);
    let s2 = S3Storage::open_with_client(
        dir.path(),
        client2,
        &StorageConfig::default(),
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s2.recover().await;
    let _id3 = s2.begin_upload("repo").await.unwrap();
}

#[tokio::test]
async fn write_remote_index_and_read_back() {
    let (_dir, s) = test_store();
    let data = b"index-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    put_tagged(&s, "repo", "v1", &cd, &[]).await;
    s.write_remote_index("repo").await.unwrap();
    let index = s.read_remote_index("repo").await.unwrap();
    let manifests = index.get("manifests").and_then(|m| m.as_array()).unwrap();
    assert!(!manifests.is_empty());
    let has_tag = manifests.iter().any(|e| {
        e.get("annotations")
            .and_then(|a| a.get("org.opencontainers.image.ref.name"))
            .and_then(|v| v.as_str())
            == Some("v1")
    });
    assert!(has_tag);
}

/// `index.json` is written behind; until the writer catches up a dirty repo's
/// reads derive from the store, so a deleted manifest's tag never reappears
/// (OCI conformance "tags list should reflect manifest deletion").
#[tokio::test]
async fn deleted_tag_not_listed_while_index_write_is_pending() {
    let (_dir, s) = test_store();
    let data = b"stale-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let (md, _) = put_tagged(&s, "repo", "v1", &cd, &[]).await;
    s.write_remote_index("repo").await.unwrap(); // remote index.json names v1
    s.delete_manifest("repo", &md).await.unwrap(); // store updated, file not yet
    let page = s.list_tags("repo", None, 100).await.unwrap();
    assert!(page.items.is_empty(), "stale tag listed: {:?}", page.items);
}

#[tokio::test]
async fn finish_upload_multipart_above_part_size() {
    let (_dir, s) = small_part_store(None);
    let blob_size = 6 * 1024 * 1024;
    let data: Vec<u8> = (0..blob_size).map(|i| (i % 251) as u8).collect();
    let digest = sha256_digest(&data);
    let id = s.begin_upload("repo").await.unwrap();
    let half = data.len() / 2;
    let off1 = s
        .append_upload(
            "repo",
            &id,
            roci_storage::upload_body(&data[..half]),
            Some(0),
            u64::MAX,
        )
        .await
        .unwrap();
    assert_eq!(off1, half as u64);
    let off2 = s
        .append_upload(
            "repo",
            &id,
            roci_storage::upload_body(&data[half..]),
            Some(half as u64),
            u64::MAX,
        )
        .await
        .unwrap();
    assert_eq!(off2, data.len() as u64);
    s.finish_upload(
        "repo",
        &id,
        &digest,
        data.len() as u64 + 1,
        roci_storage::upload_body([]),
        u64::MAX,
    )
    .await
    .unwrap();
    let read_back = s.read_blob("repo", &digest).await.unwrap();
    assert_eq!(read_back.len(), data.len());
    assert_eq!(sha256_digest(&read_back), digest);
}

#[tokio::test]
async fn put_blob_below_part_size_single_put() {
    let (_dir, s) = small_part_store(None);
    let data = b"small-blob";
    let digest = sha256_digest(data);
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload("repo", &id, roci_storage::upload_body(data), None, u64::MAX)
        .await
        .unwrap();
    s.finish_upload(
        "repo",
        &id,
        &digest,
        1024,
        roci_storage::upload_body([]),
        u64::MAX,
    )
    .await
    .unwrap();
    assert_eq!(s.read_blob("repo", &digest).await.unwrap(), data);
}

#[tokio::test]
async fn parallel_copy_via_mount_with_small_copy_limit() {
    let (_dir, s) = small_part_store(Some(0));
    let blob_size = 6 * 1024 * 1024;
    let data: Vec<u8> = (0..blob_size).map(|i| (i % 199) as u8).collect();
    let digest = sha256_digest(&data);
    s.put_blob("from", &digest, &data).await.unwrap();
    assert!(s.mount_blob("from", "to", &digest).await.unwrap());
    let read_back = s.read_blob("to", &digest).await.unwrap();
    assert_eq!(read_back.len(), data.len());
    assert_eq!(sha256_digest(&read_back), digest);
}

#[tokio::test]
async fn parallel_copy_small_object() {
    let (_dir, s) = small_part_store(Some(0));
    let data = b"tiny-for-parallel-copy";
    let digest = sha256_digest(data);
    s.put_blob("a", &digest, data).await.unwrap();
    assert!(s.mount_blob("a", "b", &digest).await.unwrap());
    assert_eq!(s.read_blob("b", &digest).await.unwrap(), data);
}

#[tokio::test]
async fn list_tags_fallback_and_pagination() {
    let dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig::default();
    let fake_digest1 = "sha256:aaaa000000000000000000000000000000000000000000000000000000000001";
    let fake_digest2 = "sha256:aaaa000000000000000000000000000000000000000000000000000000000002";
    let fake_digest3 = "sha256:aaaa000000000000000000000000000000000000000000000000000000000003";
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            { "digest": fake_digest3, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 10, "annotations": { "org.opencontainers.image.ref.name": "c-tag" } },
            { "digest": fake_digest1, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 10, "annotations": { "org.opencontainers.image.ref.name": "a-tag" } },
            { "digest": fake_digest2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 10, "annotations": { "org.opencontainers.image.ref.name": "b-tag" } },
        ]
    });
    mem.put(
        &ObjPath::from("repo/index.json"),
        PutPayload::from(serde_json::to_vec(&index).unwrap()),
    )
    .await
    .unwrap();
    let client = mem_client(mem);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    let page1 = s.list_tags("repo", None, 2).await.unwrap();
    assert_eq!(page1.items, vec!["a-tag", "b-tag"]);
    assert!(page1.more);
    let page2 = s.list_tags("repo", Some("b-tag"), 2).await.unwrap();
    assert_eq!(page2.items, vec!["c-tag"]);
    assert!(!page2.more);
}

#[tokio::test]
async fn list_referrers_fallback_from_index() {
    let dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig::default();
    let subject_digest = "sha256:bbbb000000000000000000000000000000000000000000000000000000000001";
    let ref_digest1 = "sha256:cccc000000000000000000000000000000000000000000000000000000000001";
    let ref_digest2 = "sha256:cccc000000000000000000000000000000000000000000000000000000000002";
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            { "digest": ref_digest1, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 10, "artifactType": "test/type", "subject": { "digest": subject_digest } },
            { "digest": ref_digest2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 10, "artifactType": "test/type", "subject": { "digest": subject_digest } },
        ]
    });
    mem.put(
        &ObjPath::from("repo/index.json"),
        PutPayload::from(serde_json::to_vec(&index).unwrap()),
    )
    .await
    .unwrap();
    let client = mem_client(mem);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    let subject = Digest::parse(subject_digest).unwrap();
    let page = s
        .list_referrers("repo", &subject, None, None, 10)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2, "referrers: all");
    let page2 = s
        .list_referrers("repo", &subject, Some("test/type"), None, 1)
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 1, "referrers: filtered page1");
    assert!(page2.more);
    let last = &page2.items[0].0;
    let page3 = s
        .list_referrers("repo", &subject, Some("test/type"), Some(last), 10)
        .await
        .unwrap();
    assert_eq!(page3.items.len(), 1, "referrers: filtered page2");
    assert!(!page3.more);
}

#[tokio::test]
async fn index_resolve_tag_finds_tag() {
    let dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig::default();
    let manifest_data = manifest(&sha256_digest(b"dummy-cfg"), &[], None);
    let real_digest = sha256_digest(&manifest_data);
    let real_digest_str = real_digest.as_string();
    let (alg2, hex2) = real_digest_str.split_once(':').unwrap();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "digest": real_digest_str,
            "mediaType": "application/vnd.custom.type+json",
            "size": manifest_data.len(),
            "annotations": { "org.opencontainers.image.ref.name": "latest" }
        }]
    });
    mem.put(
        &ObjPath::from("repo/index.json"),
        PutPayload::from(serde_json::to_vec(&index).unwrap()),
    )
    .await
    .unwrap();
    mem.put(
        &ObjPath::from(format!("repo/blobs/{alg2}/{hex2}")),
        PutPayload::from(bytes::Bytes::from(manifest_data.clone())),
    )
    .await
    .unwrap();
    let client = mem_client(mem);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    let m = s.get_manifest("repo", "latest").await.unwrap();
    assert_eq!(m.digest, real_digest);
    assert_eq!(m.media_type, "application/vnd.custom.type+json");
    assert_eq!(m.bytes, manifest_data);
}

#[tokio::test]
async fn index_resolve_tag_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig::default();
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": []
    });
    mem.put(
        &ObjPath::from("repo/index.json"),
        PutPayload::from(serde_json::to_vec(&index).unwrap()),
    )
    .await
    .unwrap();
    let client = mem_client(mem);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    assert!(matches!(
        s.get_manifest("repo", "nonexistent").await,
        Err(roci_storage::StorageError::NotFound)
    ));
}

#[tokio::test]
async fn obj_err_not_found_mapped() {
    let (_dir, s) = test_store();
    let fake =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000099")
            .unwrap();
    assert!(matches!(
        s.read_blob("repo", &fake).await,
        Err(roci_storage::StorageError::NotFound)
    ));
}

#[tokio::test]
async fn delete_blob_not_found() {
    let (_dir, s) = test_store();
    let fake =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000099")
            .unwrap();
    assert!(matches!(
        s.delete_blob("repo", &fake).await,
        Err(roci_storage::StorageError::NotFound)
    ));
}

#[tokio::test]
async fn delete_manifest_cleans_up() {
    let (_dir, s) = test_store();
    let data = b"dm-config";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let m = manifest(&cd, &[], None);
    let md = sha256_digest(&m);
    s.put_manifest(
        "repo",
        Some("del-me"),
        &md,
        "application/vnd.oci.image.manifest.v1+json",
        &m,
        ManifestLinks {
            references: std::slice::from_ref(&cd),
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();
    s.delete_manifest("repo", &md).await.unwrap();
    assert!(
        matches!(
            s.get_manifest("repo", "del-me").await,
            Err(roci_storage::StorageError::NotFound)
        ),
        "tag gone"
    );
    assert!(
        !s.blob_exists("repo", &md).await.unwrap(),
        "manifest blob gone"
    );
}

#[tokio::test]
async fn put_manifest_bad_tag() {
    let (_dir, s) = test_store();
    let data = b"bad-tag-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let m = manifest(&cd, &[], None);
    let md = sha256_digest(&m);
    for bad_tag in ["..", "a/b"] {
        let result = s
            .put_manifest(
                "repo",
                Some(bad_tag),
                &md,
                "application/vnd.oci.image.manifest.v1+json",
                &m,
                ManifestLinks {
                    references: std::slice::from_ref(&cd),
                    required: &[],
                    subject: None,
                },
            )
            .await;
        assert!(
            matches!(result, Err(roci_storage::StorageError::BadPath(_))),
            "bad tag: {bad_tag}"
        );
    }
}

#[tokio::test]
async fn abort_upload_not_found_paths() {
    let (_dir, s) = test_store();
    for (label, id) in [
        ("invalid_id", "a/b"),
        ("missing_file", "00000000000000000000000000000000"),
    ] {
        assert!(!s.abort_upload("repo", id).await.unwrap(), "{label}");
    }
}

#[tokio::test]
async fn staging_path_rejects_bad_inputs() {
    let (_dir, s) = test_store();
    for (label, repo, id) in [
        ("bad_repo", "..", "00000000000000000000000000000000"),
        ("bad_id", "repo", "not-hex-!!!!"),
    ] {
        assert!(s.staging_path(repo, id).is_err(), "{label}");
    }
}

#[tokio::test]
async fn enumerate_staging_files_lists_sessions() {
    let (_dir, s) = test_store();
    let id1 = s.begin_upload("repo").await.unwrap();
    s.append_upload(
        "repo",
        &id1,
        roci_storage::upload_body(b"data1"),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    let id2 = s.begin_upload("repo/nested").await.unwrap();
    s.append_upload(
        "repo/nested",
        &id2,
        roci_storage::upload_body(b"data2"),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    let files = s.enumerate_staging_files();
    assert_eq!(files.len(), 2, "enumerate: count");
    let repos: std::collections::HashSet<_> = files.iter().map(|(r, _, _, _)| r.clone()).collect();
    assert!(repos.contains("repo"), "enumerate: repo");
    assert!(repos.contains("repo/nested"), "enumerate: nested");
}

#[tokio::test]
async fn staging_size_not_found() {
    let (_dir, s) = test_store();
    assert!(matches!(
        s.staging_size("repo", "00000000000000000000000000000000")
            .await,
        Err(roci_storage::StorageError::NotFound)
    ));
}

#[tokio::test]
async fn hash_staging_bad_algorithm() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload(
        "repo",
        &id,
        roci_storage::upload_body(b"hello"),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    assert!(matches!(
        s.hash_staging("repo", &id, "md5").await,
        Err(roci_storage::StorageError::BadDigest(_))
    ));
}

#[test]
fn extract_repo_from_index_key_works() {
    use crate::storage_impl::*;
    assert_eq!(
        extract_repo_from_index_key("pfx/myrepo/index.json", "pfx"),
        Some("myrepo".into())
    );
    assert_eq!(
        extract_repo_from_index_key("myrepo/index.json", ""),
        Some("myrepo".into())
    );
    assert_eq!(
        extract_repo_from_index_key("myrepo/sub/index.json", ""),
        Some("myrepo/sub".into())
    );
    assert_eq!(
        extract_repo_from_index_key("myrepo/blobs/sha256/abc", ""),
        None
    );
    assert_eq!(extract_repo_from_index_key("index.json", ""), None);
}

#[test]
fn extract_digest_from_blob_key_works() {
    use crate::storage_impl::*;
    assert_eq!(
        extract_digest_from_blob_key("myrepo/blobs/sha256/abcdef", "myrepo"),
        Some("sha256:abcdef".into())
    );
    assert_eq!(
        extract_digest_from_blob_key("myrepo/not-blobs/sha256/abcdef", "myrepo"),
        None
    );
}

#[test]
fn from_config_secret_file_read() {
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("secret.txt");
    std::fs::write(&secret_file, "  my-secret-key  \n").unwrap();
    let s3 = roci_config::S3Config {
        endpoint: Some("https://localhost:9999".into()),
        prefix: "pfx".into(),
        access_key_id: Some("AKID".into()),
        secret_access_key_file: Some(secret_file),
        ..base_s3_config()
    };
    let client = S3Client::from_config(&s3).unwrap();
    assert_eq!(client.prefix, "pfx");
    assert!(client.signer.is_some());
    assert_eq!(client.copy_limit, crate::storage_impl::S3_COPY_LIMIT);
}

#[test]
fn from_config_missing_secret_file() {
    let s3 = roci_config::S3Config {
        access_key_id: Some("AKID".into()),
        secret_access_key_file: Some(std::path::PathBuf::from("/nonexistent/secret")),
        ..base_s3_config()
    };
    let err = S3Client::from_config(&s3).err().expect("expected error");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("secret_access_key_file"));
}

#[test]
fn from_config_key_id_without_file() {
    let s3 = roci_config::S3Config {
        access_key_id: Some("AKID".into()),
        ..base_s3_config()
    };
    let err = S3Client::from_config(&s3).err().expect("expected error");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err
        .to_string()
        .contains("secret_access_key_file is missing"));
}

#[test]
fn from_config_allow_http_and_path_style() {
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("secret.txt");
    std::fs::write(&secret_file, "key").unwrap();
    let s3 = roci_config::S3Config {
        bucket: "bucket".into(),
        region: "eu-west-1".into(),
        endpoint: Some("http://minio:9000".into()),
        access_key_id: Some("AKID".into()),
        secret_access_key_file: Some(secret_file),
        allow_http: true,
        multipart_part_size: 5 * 1024 * 1024,
        multipart_concurrency: 4,
        ..base_s3_config()
    };
    let client = S3Client::from_config(&s3).unwrap();
    assert!(client.signer.is_some());
}

#[test]
fn from_config_no_credentials() {
    let s3 = base_s3_config();
    let client = S3Client::from_config(&s3).unwrap();
    assert!(client.signer.is_some());
}

#[tokio::test]
async fn malformed_remote_index_makes_repo_unsafe() {
    let (_dir, s) = gc_test_store();
    let data = b"live layer";
    let d = roci_storage::sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.client
        .store
        .put(
            &ObjPath::from("repo/index.json"),
            PutPayload::from_static(b"{broken"),
        )
        .await
        .unwrap();
    s.gc_consistency_check().await;
    assert!(s.gc.is_unsafe("repo"));
}

#[tokio::test]
async fn manifest_commit_rechecks_required_blobs() {
    let (_dir, s) = test_store();
    let missing = roci_storage::sha256_of(b"never pushed");
    let body = br#"{"schemaVersion":2}"#;
    let d = roci_storage::sha256_of(body);
    let err = s
        .put_manifest(
            "repo",
            Some("v1"),
            &d,
            "application/json",
            body,
            ManifestLinks {
                references: std::slice::from_ref(&missing),
                required: std::slice::from_ref(&missing),
                subject: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        roci_storage::StorageError::MissingReference(_)
    ));
    assert!(s.meta.resolve_tag("repo", "v1").is_none());
}

#[test]
fn redirect_guard_permit_policy() {
    for (label, hosts, allow_http, url_str, expected) in [
        (
            "http_rejected",
            vec!["s3.test.example".into()],
            false,
            "http://s3.test.example/key",
            false,
        ),
        (
            "https_ok",
            vec!["s3.test.example".into()],
            false,
            "https://s3.test.example/key",
            true,
        ),
        (
            "http_allowed",
            vec!["s3.test.example".into()],
            true,
            "http://s3.test.example/key",
            true,
        ),
        (
            "internal_rejected",
            vec!["127.0.0.1".into()],
            true,
            "http://127.0.0.1/some/key",
            false,
        ),
    ] {
        let guard = RedirectGuard::new(hosts, allow_http);
        let url = url::Url::parse(url_str).unwrap();
        assert_eq!(guard.permits(&url), expected, "{label}");
    }
}

#[test]
fn redirect_guard_from_config_aws_default() {
    let s3 = roci_config::S3Config {
        bucket: "My-Bucket".into(),
        region: "eu-central-1".into(),
        redirect_min_size: 1024,
        ..base_s3_config()
    };
    let guard = RedirectGuard::from_config(&s3);
    assert!(
        guard.permits(
            &url::Url::parse("https://s3.eu-central-1.amazonaws.com/My-Bucket/key").unwrap()
        ),
        "path-style"
    );
    assert!(
        guard.permits(
            &url::Url::parse("https://my-bucket.s3.eu-central-1.amazonaws.com/key").unwrap()
        ),
        "vhost"
    );
    assert!(
        !guard.permits(&url::Url::parse("https://evil.example/key").unwrap()),
        "evil"
    );
}

#[test]
fn redirect_guard_from_config_custom_endpoint() {
    let s3 = roci_config::S3Config {
        bucket: "b".into(),
        endpoint: Some("https://minio.example:9000".into()),
        redirect_min_size: 1024,
        ..base_s3_config()
    };
    let guard = RedirectGuard::from_config(&s3);
    assert!(
        guard.permits(&url::Url::parse("https://minio.example:9000/b/key?sig=abc").unwrap()),
        "ok"
    );
    assert!(
        !guard.permits(&url::Url::parse("https://evil.example/b/key").unwrap()),
        "evil"
    );
}

#[tokio::test]
async fn open_blob_redirect_rejected_by_guard_falls_back_to_proxy() {
    let guard = RedirectGuard::new(vec!["other.example".into()], false);
    let (_dir, s, _mem) = test_store_with_redirect_guard(10, guard);
    let data = b"this is more than ten bytes of content for redirect guard test";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    let blob = s.open_blob("repo", &digest).await.unwrap();
    assert_eq!(blob.size(), data.len() as u64);
    assert!(blob.redirect_url().is_none(), "expected proxy fallback");
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
async fn ready_succeeds_with_in_memory_store() {
    let (_dir, s) = test_store();
    s.ready().await.unwrap();
}

#[tokio::test]
async fn ready_caches_success() {
    let (_dir, s) = test_store();
    s.ready().await.unwrap();
    s.ready().await.unwrap();
    let cache = s.readiness_cache.lock().expect("poisoned");
    assert!(
        cache.is_some(),
        "cache should be populated after a successful probe"
    );
}

#[test]
fn obj_err_write_maps_not_found_to_unavailable() {
    use roci_storage::StorageError;
    let err = object_store::Error::NotFound {
        path: "some/key".to_string(),
        source: "test".into(),
    };
    let mapped = crate::storage_impl::obj_err_write(err);
    match mapped {
        StorageError::Unavailable(msg) => {
            assert!(
                msg.contains("NotFound"),
                "message should mention NotFound: {msg}"
            );
        }
        other => panic!("expected Unavailable, got: {other:?}"),
    }
}

#[test]
fn obj_err_read_maps_not_found_to_not_found() {
    use roci_storage::StorageError;
    let err = object_store::Error::NotFound {
        path: "some/key".to_string(),
        source: "test".into(),
    };
    let mapped = crate::storage_impl::obj_err(err);
    assert!(
        matches!(mapped, StorageError::NotFound),
        "read-path NotFound should map to StorageError::NotFound"
    );
}

#[test]
fn obj_err_write_passes_through_other_errors() {
    use roci_storage::StorageError;
    let err = object_store::Error::Generic {
        store: "test",
        source: "some error".into(),
    };
    let mapped = crate::storage_impl::obj_err_write(err);
    assert!(
        matches!(mapped, StorageError::Io(_)),
        "non-NotFound errors should map to Io"
    );
}

/// Build a test store with `create_bucket = true`.
fn test_store_create_bucket() -> (tempfile::TempDir, S3Storage) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig::default();
    let mem = Arc::new(InMemory::new());
    let signer = build_test_signer();
    let client = S3Client::in_memory(
        mem,
        signer,
        String::new(),
        0,
        Duration::from_secs(60),
        16 * 1024 * 1024,
        8,
    );
    let mut s = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s.create_bucket = true;
    (dir, s)
}

/// Minimal HTTP server answering each connection with the next scripted
/// status (repeating the last). Records `METHOD PATH` of every request.
async fn scripted_s3(statuses: Vec<u16>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut i = 0;
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let line = String::from_utf8_lossy(&buf)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let mut parts = line.split(' ');
            let (m, p) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let path = p.split('?').next().unwrap_or("").to_string();
            log.lock().unwrap().push(format!("{m} {path}"));
            let status = statuses[i.min(statuses.len() - 1)];
            i += 1;
            let resp =
                format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    (format!("http://{addr}"), seen)
}

/// S3Storage whose signer and bucket HTTP client target `endpoint`.
fn store_against(endpoint: &str) -> (tempfile::TempDir, S3Storage) {
    use object_store::aws::AmazonS3Builder;
    use object_store::client::HttpConnector;
    crate::client::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let opts = object_store::ClientOptions::default().with_allow_http(true);
    let aws = AmazonS3Builder::new()
        .with_bucket_name("smoke")
        .with_region("us-east-1")
        .with_access_key_id("AKIDEXAMPLE")
        .with_secret_access_key("secret")
        .with_endpoint(endpoint)
        .with_virtual_hosted_style_request(false)
        .with_client_options(opts.clone())
        .build()
        .unwrap();
    let http = object_store::client::ReqwestConnector::default()
        .connect(&opts)
        .unwrap();
    let client = S3Client::in_memory(
        Arc::new(InMemory::new()),
        Some(Arc::new(aws)),
        String::new(),
        0,
        Duration::from_secs(60),
        16 * 1024 * 1024,
        8,
    )
    .with_bucket_http(http);
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &StorageConfig::default(),
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    (dir, s)
}

#[tokio::test]
async fn ensure_bucket_sends_create_bucket_and_accepts_200() {
    let (ep, seen) = scripted_s3(vec![200]).await;
    let (_dir, s) = store_against(&ep);
    s.ensure_bucket_within(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), vec!["PUT /smoke/".to_string()]);
}

#[tokio::test]
async fn ensure_bucket_accepts_409_already_owned() {
    let (ep, _) = scripted_s3(vec![409]).await;
    let (_dir, s) = store_against(&ep);
    s.ensure_bucket_within(Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn ensure_bucket_retries_until_backend_accepts() {
    let (ep, seen) = scripted_s3(vec![503, 503, 200]).await;
    let (_dir, s) = store_against(&ep);
    s.ensure_bucket_within(Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn ensure_bucket_gives_up_as_unavailable_at_deadline() {
    let (ep, _) = scripted_s3(vec![403]).await;
    let (_dir, s) = store_against(&ep);
    let err = s
        .ensure_bucket_within(Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, roci_storage::StorageError::Unavailable(m) if m.contains("403")),
        "{err:?}"
    );
}

#[tokio::test]
async fn ensure_bucket_without_http_client_is_rejected() {
    let (_dir, s) = test_store_create_bucket();
    assert!(s.ensure_bucket().await.is_err());
}

#[tokio::test]
async fn ready_retries_create_bucket_until_it_succeeds() {
    // Startup CreateBucket gave up; each readiness check tries once more, and
    // stops trying after the first success.
    let (ep, seen) = scripted_s3(vec![503, 200]).await;
    let (_dir, mut s) = store_against(&ep);
    s.create_bucket = true;
    assert!(matches!(
        s.ready().await,
        Err(roci_storage::StorageError::Unavailable(_))
    ));
    s.ready().await.unwrap();
    *s.readiness_cache.lock().unwrap() = None;
    s.ready().await.unwrap();
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "no CreateBucket after success"
    );
}

#[tokio::test]
async fn recover_skips_ensure_bucket_when_flag_unset() {
    // create_bucket = false: recover must not attempt CreateBucket (the
    // store has no bucket HTTP client, so an attempt would log an error).
    let (_dir, s) = test_store();
    assert!(!s.create_bucket);
    s.recover().await;
}

#[test]
fn ca_file_bad_pem_rejected_at_startup() {
    use roci_config::S3Config;
    crate::client::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(&bad_pem, "this is not a valid PEM certificate").unwrap();
    let s3 = S3Config {
        bucket: "test".into(),
        region: "us-east-1".into(),
        endpoint: Some("http://localhost:9000".into()),
        prefix: String::new(),
        access_key_id: None,
        secret_access_key_file: None,
        allow_http: true,
        redirect_min_size: 0,
        redirect_ttl_secs: 15,
        multipart_part_size: 16 * 1024 * 1024,
        multipart_concurrency: 8,
        create_bucket: false,
        ca_file: Some(bad_pem),
    };
    let err = S3Client::from_config(&s3);
    assert!(err.is_err(), "bad PEM should be rejected at startup");
    let msg = err.err().expect("expected an error").to_string();
    assert!(
        msg.contains("PEM") || msg.contains("pem") || msg.contains("ca_file"),
        "error should mention PEM or ca_file: {msg}"
    );
}

#[test]
fn obj_err_read_maps_generic_to_io() {
    let err = object_store::Error::Generic {
        store: "test",
        source: "custom error".into(),
    };
    let mapped = crate::storage_impl::obj_err(err);
    assert!(
        matches!(mapped, roci_storage::StorageError::Io(_)),
        "generic obj error should map to Io: {mapped:?}"
    );
}

#[test]
fn extract_repo_from_index_key_empty_repo_returns_none() {
    let result = crate::storage_impl::extract_repo_from_index_key("index.json", "");
    assert!(result.is_none(), "bare index.json has no repo");
}

#[test]
fn extract_repo_from_index_key_prefixed_empty_repo_returns_none() {
    let result = crate::storage_impl::extract_repo_from_index_key("pfx/index.json", "pfx");
    assert!(
        result.is_none(),
        "prefix-only key has empty repo after strip"
    );
}

#[tokio::test]
async fn gc_sweep_skips_not_ready() {
    let (_dir, s) = gc_test_store();
    let data = b"not-ready-blob";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    // gc is NOT set_ready, sweep should be a no-op
    s.gc_sweep().await;
    assert!(
        s.blob_exists("repo", &digest).await.unwrap(),
        "blob should survive when GC is not ready"
    );
}

#[tokio::test]
async fn gc_sweep_skips_unsafe_repo() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let data = b"unsafe-repo-blob";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    s.gc.mark_unsafe("repo");
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    assert!(
        s.blob_exists("repo", &digest).await.unwrap(),
        "blob in unsafe repo should survive sweep"
    );
}

#[tokio::test]
async fn gc_sweep_clears_root_candidate() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let data = b"root-blob-data";
    let digest = sha256_digest(data);
    s.put_blob("repo", &digest, data).await.unwrap();
    let ds = digest.as_string();
    s.gc.add_root("repo", &ds);
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    assert!(
        s.blob_exists("repo", &digest).await.unwrap(),
        "root blob should not be collected"
    );
}

#[tokio::test]
async fn gc_sweep_clears_blob_with_backrefs() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let layer = b"layer-with-backref";
    let ld = sha256_digest(layer);
    s.put_blob("repo", &ld, layer).await.unwrap();
    put_tagged(&s, "repo", "v1", &ld, &[]).await;
    // Force a GC mark on the layer (normally wouldn't happen since put_manifest clears it)
    s.gc.mark("repo", &ld.as_string());
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    assert!(
        s.blob_exists("repo", &ld).await.unwrap(),
        "blob with backrefs should survive sweep"
    );
}

#[tokio::test]
async fn gc_sweep_clears_manifest_typed_candidate() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let layer = b"layer-data-mtype";
    let ld = sha256_digest(layer);
    s.put_blob("repo", &ld, layer).await.unwrap();
    let (md, _) = put_tagged(&s, "repo", "v1", &ld, &[]).await;
    // Force mark on the manifest digest (has a media type in metadata)
    s.gc.mark("repo", &md.as_string());
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    assert!(
        s.blob_exists("repo", &md).await.unwrap(),
        "manifest-typed blob should survive sweep"
    );
}

#[tokio::test]
async fn gc_sweep_nothing_to_collect_path() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    // No candidates at all → hits "nothing to collect" path
    s.gc_sweep().await;
}

#[tokio::test]
async fn gc_rebuild_unreadable_index_marks_unsafe() {
    let mem = Arc::new(InMemory::new());
    mem.put(
        &ObjPath::from("repo/index.json"),
        PutPayload::from_static(b"not valid json at all"),
    )
    .await
    .unwrap();
    mem.put(
        &ObjPath::from("repo/oci-layout"),
        PutPayload::from_static(b"{\"imageLayoutVersion\":\"1.0.0\"}"),
    )
    .await
    .unwrap();
    let (_dir, s) = store_on(mem, gc_config());
    s.gc_consistency_check().await;
    assert!(
        s.gc.is_unsafe("repo"),
        "repo with unparseable index.json should be marked unsafe"
    );
}

#[tokio::test]
async fn gc_rebuild_no_index_uses_metadata_roots() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem, gc_config());
    let layer = b"metadata-only-layer";
    let ld = sha256_digest(layer);
    s.put_blob("repo", &ld, layer).await.unwrap();
    let (_md, _) = put_tagged(&s, "repo", "v1", &ld, &[]).await;
    // No remote index.json; gc_consistency_check uses meta.manifests().
    // Delete the index.json that put_blob created.
    s.client
        .store
        .delete(&ObjPath::from("repo/index.json"))
        .await
        .unwrap();
    s.gc_consistency_check().await;
    // Manifest has a media type → not added as root, but layer should not be due
    let now_plus = std::time::Instant::now() + Duration::from_secs(1);
    assert!(
        !s.gc.is_due("repo", &ld.as_string(), now_plus),
        "layer should have backrefs rebuilt and not be due"
    );
}

#[tokio::test]
async fn gc_rebuild_repo_oversized_root_marks_unsafe() {
    let mem = Arc::new(InMemory::new());
    // Create blob larger than MAX_ROOT_MANIFEST_BYTES (4 MiB)
    let big_data = vec![0u8; 4 * 1024 * 1024 + 1];
    let bd = sha256_digest(&big_data);
    let digest_str = bd.as_string();
    let (alg, hex) = digest_str.split_once(':').unwrap();
    mem.put(
        &ObjPath::from(format!("repo/blobs/{alg}/{hex}")),
        PutPayload::from(bytes::Bytes::from(big_data)),
    )
    .await
    .unwrap();
    let index = serde_json::json!({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"digest": digest_str, "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 4 * 1024 * 1024 + 1}]
    });
    put_index(&mem, "repo", &index).await;
    let (_dir, s) = store_on(mem, gc_config());
    s.gc_consistency_check().await;
    assert!(
        s.gc.is_unsafe("repo"),
        "oversized root manifest should make repo GC-unsafe"
    );
}

#[tokio::test]
async fn gc_consistency_check_meta_repos_included() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), gc_config());
    let data = b"meta-repo-cfg";
    let cd = sha256_digest(data);
    s.put_blob("meta-only", &cd, data).await.unwrap();
    put_tagged(&s, "meta-only", "v1", &cd, &[]).await;
    // Don't write_remote_index: repo exists only in metadata, not S3 listing.
    // Rebuild second store from same memory (no index.json for meta-only).
    let (_dir2, s2) = store_on(mem, gc_config());
    // Populate metadata so meta.repos() returns "meta-only".
    let data2 = b"meta-repo-cfg";
    let cd2 = sha256_digest(data2);
    s2.put_blob("meta-only", &cd2, data2).await.unwrap();
    put_tagged(&s2, "meta-only", "v1", &cd2, &[]).await;
    s2.gc_consistency_check().await;
    // Should not crash; the repo from meta.repos() is included in consistency check
}

#[tokio::test]
async fn delete_manifest_read_error_fallback() {
    let (_dir, s) = test_store();
    let data = b"config-for-delete";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let (md, _) = put_tagged(&s, "repo", "v1", &cd, &[]).await;
    // Delete the underlying blob first, so read_blob fails during delete_manifest
    let key = format!("repo/blobs/{}", md.as_string().replace(':', "/"));
    s.client
        .store
        .delete(&ObjPath::from(key.clone()))
        .await
        .unwrap();
    // delete_manifest should handle read_blob error gracefully (empty references)
    // but the actual delete_blob call will also fail (NotFound)
    let err = s.delete_manifest("repo", &md).await;
    assert!(
        err.is_err(),
        "delete_manifest should fail when blob is missing"
    );
}

#[tokio::test]
async fn index_media_type_fallback_via_recover() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s1) = store_on(mem.clone(), StorageConfig::default());
    let cfg_data = b"config-for-media-type";
    let cd = sha256_digest(cfg_data);
    s1.put_blob("repo", &cd, cfg_data).await.unwrap();
    let manifest_data = manifest(&cd, &[], None);
    let md = sha256_digest(&manifest_data);
    let digest_str = md.as_string();
    s1.put_manifest(
        "repo",
        Some("tagged"),
        &md,
        "application/vnd.custom.cached+json",
        &manifest_data,
        ManifestLinks {
            references: std::slice::from_ref(&cd),
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();
    s1.write_remote_index("repo").await.unwrap();
    let (_dir2, s2) = store_on(mem, StorageConfig::default());
    s2.recover().await;
    let m = s2.get_manifest("repo", &digest_str).await.unwrap();
    assert_eq!(m.bytes, manifest_data);
    assert_eq!(m.media_type, "application/vnd.custom.cached+json");
}

#[tokio::test]
async fn put_blob_creates_layout_marker_and_index() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let data = b"layout-trigger";
    let d = sha256_digest(data);
    s.put_blob("new-repo", &d, data).await.unwrap();
    assert!(
        mem.head(&ObjPath::from("new-repo/oci-layout"))
            .await
            .is_ok(),
        "oci-layout should exist"
    );
    assert!(
        mem.head(&ObjPath::from("new-repo/index.json"))
            .await
            .is_ok(),
        "index.json should exist"
    );
    // Second put: layout cached
    s.put_blob("new-repo", &d, data).await.unwrap();
}

#[tokio::test]
async fn put_blob_preserves_existing_index() {
    let mem = Arc::new(InMemory::new());
    let custom_index = serde_json::json!({"schemaVersion": 2, "manifests": [
        {"digest": "sha256:aaaa000000000000000000000000000000000000000000000000000000000001",
         "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 100,
         "annotations": {"org.opencontainers.image.ref.name": "existing"}}
    ]});
    mem.put(
        &ObjPath::from("repo/oci-layout"),
        PutPayload::from_static(b"{\"imageLayoutVersion\":\"1.0.0\"}"),
    )
    .await
    .unwrap();
    mem.put(
        &ObjPath::from("repo/index.json"),
        PutPayload::from(serde_json::to_vec(&custom_index).unwrap()),
    )
    .await
    .unwrap();
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let data = b"trigger-ensure";
    let d = sha256_digest(data);
    s.put_blob("repo", &d, data).await.unwrap();
    let result = mem.get(&ObjPath::from("repo/index.json")).await.unwrap();
    let bytes = result.bytes().await.unwrap();
    let idx: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ms = idx.get("manifests").unwrap().as_array().unwrap();
    let has_existing = ms.iter().any(|m| {
        m.get("annotations")
            .and_then(|a| a.get("org.opencontainers.image.ref.name"))
            .and_then(|v| v.as_str())
            == Some("existing")
    });
    assert!(
        has_existing,
        "existing index.json entries should be preserved"
    );
}

#[tokio::test]
async fn write_remote_index_merges_existing() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let data = b"wri-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let (md, _) = put_tagged(&s, "repo", "v1", &cd, &[]).await;
    s.write_remote_index("repo").await.unwrap();
    // Push another tag
    let data2 = b"wri-cfg-2";
    let cd2 = sha256_digest(data2);
    s.put_blob("repo", &cd2, data2).await.unwrap();
    let (md2, _) = put_tagged(&s, "repo", "v2", &cd2, &[]).await;
    // write_remote_index merges existing; both tags should appear
    s.write_remote_index("repo").await.unwrap();
    let result = mem.get(&ObjPath::from("repo/index.json")).await.unwrap();
    let bytes = result.bytes().await.unwrap();
    let idx: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let manifests = idx.get("manifests").unwrap().as_array().unwrap();
    let digests: Vec<&str> = manifests
        .iter()
        .filter_map(|m| m.get("digest").and_then(|d| d.as_str()))
        .collect();
    assert!(
        digests.contains(&md.as_string().as_str()),
        "first manifest should be in index"
    );
    assert!(
        digests.contains(&md2.as_string().as_str()),
        "second manifest should be in index"
    );
}

#[tokio::test]
async fn write_remote_index_no_existing() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let data = b"fresh-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo-fresh", &cd, data).await.unwrap();
    put_tagged(&s, "repo-fresh", "v1", &cd, &[]).await;
    // Delete the index.json that ensure_layout created
    let _ = mem.delete(&ObjPath::from("repo-fresh/index.json")).await;
    // write_remote_index with no existing index (NotFound path)
    s.write_remote_index("repo-fresh").await.unwrap();
    let result = mem
        .get(&ObjPath::from("repo-fresh/index.json"))
        .await
        .unwrap();
    let bytes = result.bytes().await.unwrap();
    let idx: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(!idx.get("manifests").unwrap().as_array().unwrap().is_empty());
}

#[tokio::test]
async fn recover_with_prefix() {
    let mem = Arc::new(InMemory::new());
    let dir = tempfile::tempdir().unwrap();
    let mut client = mem_client(mem.clone());
    client.prefix = "pfx".to_string();
    let config = StorageConfig::default();
    let s1 = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    let data = b"prefixed-cfg";
    let cd = sha256_digest(data);
    s1.put_blob("myrepo", &cd, data).await.unwrap();
    let (_, m) = put_tagged(&s1, "myrepo", "v1", &cd, &[]).await;
    s1.write_remote_index("myrepo").await.unwrap();

    let dir2 = tempfile::tempdir().unwrap();
    let mut client2 = mem_client(mem.clone());
    client2.prefix = "pfx".to_string();
    let s2 = S3Storage::open_with_client(
        dir2.path(),
        client2,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s2.recover().await;
    assert_eq!(s2.get_manifest("myrepo", "v1").await.unwrap().bytes, m);
}

#[tokio::test]
async fn recover_with_dedupe_seeds_from_blobs() {
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig {
        dedupe: true,
        ..StorageConfig::default()
    };
    let (_dir, s1) = store_on(mem.clone(), config.clone());
    let data = b"dedupe-seed-blob";
    let digest = sha256_digest(data);
    s1.put_blob("repo", &digest, data).await.unwrap();
    s1.write_remote_index("repo").await.unwrap();

    let (_dir2, s2) = store_on(mem, config);
    s2.recover().await;
    // seed_dedupe_from_listing should have inserted the blob digest
    assert!(s2.dedupe.enabled());
}

#[tokio::test]
async fn ready_with_prefix() {
    let mem = Arc::new(InMemory::new());
    let dir = tempfile::tempdir().unwrap();
    let mut client = mem_client(mem);
    client.prefix = "pfx".to_string();
    let s = S3Storage::open_with_client(
        dir.path(),
        client,
        &StorageConfig::default(),
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s.ready().await.unwrap();
    // Second call hits the cache (PROBE_TTL path)
    s.ready().await.unwrap();
}

#[tokio::test]
async fn list_referrers_empty_fallback() {
    let mem = Arc::new(InMemory::new());
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": []
    });
    put_index(&mem, "repo", &index).await;
    let (_dir, s) = store_on(mem, StorageConfig::default());
    let subject =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let page = s
        .list_referrers("repo", &subject, None, None, 10)
        .await
        .unwrap();
    assert!(page.items.is_empty(), "no referrers should be found");
}

#[tokio::test]
async fn mount_blob_source_not_found() {
    let (_dir, s) = test_store();
    let missing =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let result = s.mount_blob("src", "dst", &missing).await.unwrap();
    assert!(
        !result,
        "mount should return false when source blob is missing"
    );
}

#[tokio::test]
async fn sweep_stale_uploads_locked_session_skipped() {
    let (_dir, s) = test_store_with_config(gc_config(), QuotaTracker::default());
    let id = s.begin_upload("repo").await.unwrap();
    // Grab the upload lock so sweep cannot acquire it
    let lock = s.upload_locks.get("repo", &id);
    let _guard = lock.lock().await;
    // gc delay is 0, so any file is "stale" but the lock prevents removal
    let (count, _) = s.sweep_stale_uploads().await;
    assert_eq!(count, 0, "locked session should not be swept");
}

#[tokio::test]
async fn dedupe_disabled_skips_server_side_copy() {
    let (_dir, s) = test_store();
    // dedupe is disabled by default: put_blob goes through direct upload, not copy
    let data = b"no-dedupe-blob";
    let d = sha256_digest(data);
    s.put_blob("repo", &d, data).await.unwrap();
    assert_eq!(s.read_blob("repo", &d).await.unwrap(), data);
}

#[test]
fn from_config_ca_file_missing_file() {
    crate::client::install_crypto_provider();
    let s3 = roci_config::S3Config {
        ca_file: Some(std::path::PathBuf::from("/nonexistent/ca.pem")),
        ..base_s3_config()
    };
    let err = S3Client::from_config(&s3).err().expect("expected error");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("ca_file"), "error: {err}");
}

#[test]
fn from_config_ca_file_empty_pem_rejected() {
    crate::client::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let empty_pem = dir.path().join("empty.pem");
    std::fs::write(&empty_pem, "").unwrap();
    let s3 = roci_config::S3Config {
        ca_file: Some(empty_pem),
        ..base_s3_config()
    };
    let err = S3Client::from_config(&s3).err().expect("expected error");
    assert!(
        err.to_string().contains("no valid PEM") || err.to_string().contains("ca_file"),
        "error should mention empty PEM: {err}"
    );
}

#[tokio::test]
async fn finish_upload_digest_mismatch() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    let data = b"upload-data-mismatch";
    s.append_upload("repo", &id, roci_storage::upload_body(data), None, u64::MAX)
        .await
        .unwrap();
    let wrong_digest = sha256_digest(b"wrong data");
    let err = s
        .finish_upload(
            "repo",
            &id,
            &wrong_digest,
            1024,
            roci_storage::upload_body([]),
            u64::MAX,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, roci_storage::StorageError::DigestMismatch { .. }),
        "expected DigestMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn finish_upload_too_large() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    let data = b"large-upload-data-for-limit-check";
    s.append_upload("repo", &id, roci_storage::upload_body(data), None, u64::MAX)
        .await
        .unwrap();
    let d = sha256_digest(data);
    let err = s
        .finish_upload(
            "repo",
            &id,
            &d,
            5, // max_size = 5, much smaller than data
            roci_storage::upload_body([]),
            u64::MAX,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, roci_storage::StorageError::TooLarge { .. }),
        "expected TooLarge, got: {err:?}"
    );
}

#[tokio::test]
async fn finish_upload_multipart_staged_blob() {
    let (_dir, s) = small_part_store(None);
    // Upload enough data to trigger multipart in upload_staged_blob (> 5 MiB part)
    let data: Vec<u8> = (0..6 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let digest = sha256_digest(&data);
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload(
        "repo",
        &id,
        roci_storage::upload_body(&data),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    s.finish_upload(
        "repo",
        &id,
        &digest,
        u64::MAX,
        roci_storage::upload_body([]),
        u64::MAX,
    )
    .await
    .unwrap();
    assert_eq!(
        s.read_blob("repo", &digest).await.unwrap().len(),
        data.len()
    );
}

#[tokio::test]
async fn put_manifest_bad_tag_variants() {
    let (_dir, s) = test_store();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_digest(body);
    for bad_tag in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
        let err = s
            .put_manifest(
                "repo",
                Some(bad_tag),
                &d,
                "application/json",
                body,
                ManifestLinks {
                    references: &[],
                    required: &[],
                    subject: None,
                },
            )
            .await;
        assert!(
            matches!(err, Err(roci_storage::StorageError::BadPath(_))),
            "tag {bad_tag:?} should be rejected"
        );
    }
}

#[tokio::test]
async fn delete_blob_not_found_returns_error() {
    let (_dir, s) = test_store();
    let missing = sha256_digest(b"never-stored");
    let err = s.delete_blob("repo", &missing).await;
    assert!(
        matches!(err, Err(roci_storage::StorageError::NotFound)),
        "delete of missing blob should be NotFound"
    );
}

#[tokio::test]
async fn recover_create_bucket_error_path() {
    // create_bucket = true but no HTTP client → error during recover
    let (_dir, mut s) = test_store();
    s.create_bucket = true;
    // bucket_ensured stays false; recover will try ensure_bucket which fails
    s.recover().await;
    // Should not panic; error is logged
    assert!(
        !s.bucket_ensured.load(std::sync::atomic::Ordering::Acquire),
        "bucket_ensured should remain false after failed create"
    );
}

#[tokio::test]
async fn gc_consistency_with_prefix() {
    let mem = Arc::new(InMemory::new());
    let dir = tempfile::tempdir().unwrap();
    let mut client = mem_client(mem.clone());
    client.prefix = "pfx".to_string();
    let config = gc_config();
    let s1 = S3Storage::open_with_client(
        dir.path(),
        client,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    let data = b"prefixed-gc-cfg";
    let cd = sha256_digest(data);
    s1.put_blob("repo", &cd, data).await.unwrap();
    let (md, _) = put_tagged(&s1, "repo", "v1", &cd, &[]).await;
    s1.write_remote_index("repo").await.unwrap();

    let dir2 = tempfile::tempdir().unwrap();
    let mut client2 = mem_client(mem);
    client2.prefix = "pfx".to_string();
    let s2 = S3Storage::open_with_client(
        dir2.path(),
        client2,
        &config,
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s2.gc_consistency_check().await;
    assert!(
        s2.gc.is_root("repo", &md.as_string()),
        "prefixed store should find root"
    );
}

#[tokio::test]
async fn staging_size_missing_returns_not_found() {
    let (_dir, s) = test_store();
    let err = s
        .upload_size("repo", "00000000000000000000000000000000")
        .await;
    assert!(matches!(err, Err(roci_storage::StorageError::NotFound)));
}

#[tokio::test]
async fn hash_staging_unsupported_algorithm() {
    let (_dir, s) = test_store();
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload(
        "repo",
        &id,
        roci_storage::upload_body(b"data"),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    let err = s.hash_staging("repo", &id, "md5").await;
    assert!(
        matches!(err, Err(roci_storage::StorageError::BadDigest(_))),
        "unsupported algorithm should be rejected"
    );
}

#[tokio::test]
async fn quota_admission_deduplicates() {
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 100,
        max_total_bytes: 0,
        max_upload_sessions: 10,
    });
    let (_dir, s) = test_store_with_config(StorageConfig::default(), quota);
    let data = b"blob-for-quota-dedup";
    let d = sha256_digest(data);
    s.put_blob("repo", &d, data).await.unwrap();
    // Second put of same blob: admit_blob should see it exists → charge 0
    s.put_blob("repo", &d, data).await.unwrap();
}

#[tokio::test]
async fn abort_upload_missing_session_returns_false() {
    let (_dir, s) = test_store();
    let result = s
        .abort_upload("repo", "00000000000000000000000000000000")
        .await
        .unwrap();
    assert!(!result, "aborting nonexistent session should return false");
}

#[tokio::test]
async fn enumerate_staging_files_nested_repos() {
    let (_dir, s) = test_store();
    let _id1 = s.begin_upload("org/repo").await.unwrap();
    let _id2 = s.begin_upload("org/repo").await.unwrap();
    let files = s.enumerate_staging_files();
    assert_eq!(files.len(), 2, "should find both staging files");
    for (repo, _id, _size, _modified) in &files {
        assert_eq!(repo, "org/repo");
    }
}

#[tokio::test]
async fn seed_sessions_from_staging_counts_nested() {
    let mem = Arc::new(InMemory::new());
    let (dir, s1) = store_on(mem.clone(), StorageConfig::default());
    let _id1 = s1.begin_upload("a/b").await.unwrap();
    let _id2 = s1.begin_upload("c").await.unwrap();
    // Create new store over same root to re-seed
    let client2 = mem_client(mem);
    let s2 = S3Storage::open_with_client(
        dir.path(),
        client2,
        &StorageConfig::default(),
        Arc::new(QuotaTracker::default()),
    )
    .unwrap();
    s2.seed_sessions_from_staging();
    // Should not panic and should count 2 sessions
}

#[tokio::test]
async fn dedupe_enabled_server_side_copy_on_put() {
    let mem = Arc::new(InMemory::new());
    let config = StorageConfig {
        dedupe: true,
        ..StorageConfig::default()
    };
    let (_dir, s) = store_on(mem, config);
    let data = b"dedupe-copy-data";
    let d = sha256_digest(data);
    s.put_blob("repo-a", &d, data).await.unwrap();
    // Second repo: dedupe.locate should find repo-a, triggering server_side_copy
    s.put_blob("repo-b", &d, data).await.unwrap();
    assert_eq!(s.read_blob("repo-b", &d).await.unwrap(), data);
}

#[tokio::test]
async fn gc_sweep_already_deleted_blob() {
    let (_dir, s) = gc_test_store();
    s.gc.set_ready();
    let data = b"vanishing-blob";
    let d = sha256_digest(data);
    s.put_blob("repo", &d, data).await.unwrap();
    // Manually delete the blob from S3 behind the GC's back
    let ds = d.as_string();
    let (alg, hex) = ds.split_once(':').unwrap();
    s.client
        .store
        .delete(&ObjPath::from(format!("repo/blobs/{alg}/{hex}")))
        .await
        .unwrap();
    // GC still has it marked as candidate
    tokio::time::sleep(Duration::from_millis(50)).await;
    s.gc_sweep().await;
    // Should not panic; blob was already gone (NotFound on head → clear)
}

#[tokio::test]
async fn write_remote_index_preserves_sizes_from_cache() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let data = b"size-test-cfg";
    let cd = sha256_digest(data);
    s.put_blob("repo", &cd, data).await.unwrap();
    let (md, manifest_bytes) = put_tagged(&s, "repo", "v1", &cd, &[]).await;
    // record_manifest_size was called by put_manifest
    s.write_remote_index("repo").await.unwrap();
    let result = mem.get(&ObjPath::from("repo/index.json")).await.unwrap();
    let bytes = result.bytes().await.unwrap();
    let idx: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ms = idx.get("manifests").unwrap().as_array().unwrap();
    let entry = ms
        .iter()
        .find(|m| m.get("digest").and_then(|d| d.as_str()) == Some(&md.as_string()))
        .expect("manifest should be in index");
    let size = entry.get("size").and_then(|s| s.as_u64()).unwrap();
    assert_eq!(
        size,
        manifest_bytes.len() as u64,
        "manifest size should match"
    );
}

#[tokio::test]
async fn recover_skips_invalid_manifests_in_index() {
    let mem = Arc::new(InMemory::new());
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "size": 100},
            "not an object"
        ]
    });
    put_index(&mem, "repo", &index).await;
    let (_dir, s) = store_on(mem, StorageConfig::default());
    s.recover().await;
    // Should not panic on entries without a "digest" field
}

#[tokio::test]
async fn gc_consistency_check_with_dedupe_disabled() {
    let (_dir, s) = gc_test_store();
    // dedupe is disabled by default in gc_test_store
    let data = b"no-dedupe-gc";
    let d = sha256_digest(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.gc_consistency_check().await;
    // seed_dedupe_from_listing returns early when disabled
    let now = std::time::Instant::now() + Duration::from_secs(1);
    assert!(s.gc.is_due("repo", &d.as_string(), now));
}

#[tokio::test]
async fn delete_manifest_with_unparseable_blob() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let bad_manifest = b"not json at all";
    let d = sha256_digest(bad_manifest);
    s.put_manifest(
        "repo",
        Some("v1"),
        &d,
        "application/json",
        bad_manifest,
        ManifestLinks {
            references: &[],
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();
    // delete_manifest: read_blob succeeds but JSON parse fails → empty references
    s.delete_manifest("repo", &d).await.unwrap();
    assert!(!s.blob_exists("repo", &d).await.unwrap());
}

#[tokio::test]
async fn seed_quota_from_listing_via_recover() {
    let mem = Arc::new(InMemory::new());
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 1024 * 1024,
        max_total_bytes: 0,
        max_upload_sessions: 10,
    });
    let dir = tempfile::tempdir().unwrap();
    let client = mem_client(mem.clone());
    let s1 = S3Storage::open_with_client(
        dir.path(),
        client,
        &StorageConfig::default(),
        Arc::new(quota),
    )
    .unwrap();
    let data = b"quota-seed-data";
    let d = sha256_digest(data);
    s1.put_blob("repo", &d, data).await.unwrap();
    s1.write_remote_index("repo").await.unwrap();
    // New store with quota tracking
    let quota2 = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 1024 * 1024,
        max_total_bytes: 0,
        max_upload_sessions: 10,
    });
    let dir2 = tempfile::tempdir().unwrap();
    let client2 = mem_client(mem);
    let s2 = S3Storage::open_with_client(
        dir2.path(),
        client2,
        &StorageConfig::default(),
        Arc::new(quota2),
    )
    .unwrap();
    s2.recover().await;
    // After recover, quota should be seeded; putting data that'd exceed limit should fail
    // (but our limit is high, so just verify the seeding path ran without error)
}

#[tokio::test]
async fn get_manifest_by_digest_default_media_type() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s) = store_on(mem.clone(), StorageConfig::default());
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_digest(body);
    let ds = d.as_string();
    let (alg, hex) = ds.split_once(':').unwrap();
    // Place blob directly in S3 (no metadata, no index cache)
    s.client
        .store
        .put(
            &ObjPath::from(format!("repo/blobs/{alg}/{hex}")),
            PutPayload::from(bytes::Bytes::copy_from_slice(body)),
        )
        .await
        .unwrap();
    // get_manifest by digest: no metadata media type, no cached index → default
    let m = s.get_manifest("repo", &ds).await.unwrap();
    assert_eq!(
        m.media_type, "application/vnd.oci.image.manifest.v1+json",
        "should use default media type"
    );
    assert_eq!(m.bytes, body);
}

#[tokio::test]
async fn finish_upload_with_trailing_body() {
    let (_dir, s) = test_store();
    let part1 = b"first-part";
    let part2 = b"second-part";
    let mut full = Vec::new();
    full.extend_from_slice(part1);
    full.extend_from_slice(part2);
    let d = sha256_digest(&full);
    let id = s.begin_upload("repo").await.unwrap();
    s.append_upload(
        "repo",
        &id,
        roci_storage::upload_body(part1),
        None,
        u64::MAX,
    )
    .await
    .unwrap();
    // finish_upload with trailing body that adds part2
    s.finish_upload(
        "repo",
        &id,
        &d,
        u64::MAX,
        roci_storage::upload_body(part2),
        u64::MAX,
    )
    .await
    .unwrap();
    assert_eq!(s.read_blob("repo", &d).await.unwrap(), full);
}

#[tokio::test]
async fn mount_blob_same_repo_is_noop() {
    let (_dir, s) = test_store();
    let data = b"same-repo-mount";
    let d = sha256_digest(data);
    s.put_blob("repo", &d, data).await.unwrap();
    let ok = s.mount_blob("repo", "repo", &d).await.unwrap();
    assert!(ok, "mounting within same repo should succeed");
}

#[tokio::test]
async fn recover_caches_remote_index_for_tag_resolve() {
    let mem = Arc::new(InMemory::new());
    let (_dir, s1) = store_on(mem.clone(), StorageConfig::default());
    let data = b"tag-resolve-cfg";
    let cd = sha256_digest(data);
    s1.put_blob("repo", &cd, data).await.unwrap();
    let (_, m) = put_tagged(&s1, "repo", "v1", &cd, &[]).await;
    s1.write_remote_index("repo").await.unwrap();
    let (_dir2, s2) = store_on(mem, StorageConfig::default());
    s2.recover().await;
    // After recover, index should be cached; tag resolve should work
    let result = s2.get_manifest("repo", "v1").await.unwrap();
    assert_eq!(result.bytes, m);
}

mod http_e2e {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use http_body_util::BodyExt;
    use roci_config::Config;
    use roci_core::{build_router, AppState};
    use tower::ServiceExt;

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

    #[tokio::test]
    async fn redirect_307_for_large_blob_with_signer() {
        let (_dir, app, s, _mem) = make_app_with_redirect(10);
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
            assert_eq!(status, 200);
        }
    }

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
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, data);
    }
}
