//! Unit tests for filesystem storage internals.

mod fast_restart;
mod faults;
mod gc;
mod hardening;
mod index;
mod policies;
mod sessions;

pub(crate) use crate::beneath::*;
pub(crate) use crate::digest::*;
pub(crate) use crate::error::*;
#[cfg(target_os = "linux")]
pub(crate) use crate::fault::*;
pub(crate) use crate::layout::*;
pub(crate) use crate::metadata::*;
#[cfg(target_os = "linux")]
pub(crate) use crate::publish::*;
pub(crate) use crate::storage::*;
pub(crate) use crate::FsStorage;
pub(crate) use std::collections::HashMap;
pub(crate) use std::path::Path;
pub(crate) use std::sync::Mutex as StdMutex;

pub(crate) fn store() -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let s = FsStorage::new(dir.path()).unwrap();
    (dir, s)
}

#[allow(dead_code)]
pub(crate) fn store_with(config: &roci_config::StorageConfig) -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let quota = std::sync::Arc::new(crate::quota::QuotaTracker::default());
    let s = FsStorage::with_config(dir.path(), config, quota).unwrap();
    (dir, s)
}

pub(crate) fn gc_store_cfg(
    delay_secs: u64,
    quota: Option<crate::quota::QuotaLimits>,
) -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let config = roci_config::StorageConfig {
        gc: roci_config::GcConfig {
            enabled: true,
            delay_secs,
            interval_secs: 3600,
        },
        ..roci_config::StorageConfig::default()
    };
    let qt = match quota {
        Some(limits) => std::sync::Arc::new(crate::quota::QuotaTracker::new(limits)),
        None => std::sync::Arc::new(crate::quota::QuotaTracker::default()),
    };
    let s = FsStorage::with_config(dir.path(), &config, qt).unwrap();
    s.gc.set_ready();
    (dir, s)
}

pub(crate) fn make_manifest(config: &Digest, layers: &[&Digest]) -> Vec<u8> {
    let layers_json: Vec<serde_json::Value> = layers
        .iter()
        .map(|d| {
            serde_json::json!({
                "digest": d.as_string(),
                "mediaType": "application/octet-stream",
                "size": 0
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
        "config": {
            "digest": config.as_string(),
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 0
        },
        "layers": layers_json
    }))
    .unwrap()
}

#[allow(dead_code)]
pub(crate) async fn push_image(
    s: &FsStorage,
    repo: &str,
    tag: &str,
    config: &[u8],
    layer: &[u8],
) -> (Digest, Digest, Digest) {
    let config_d = crate::digest::sha256_of(config);
    let layer_d = crate::digest::sha256_of(layer);
    s.put_blob(repo, &config_d, config).await.unwrap();
    s.put_blob(repo, &layer_d, layer).await.unwrap();
    let manifest_body = make_manifest(&config_d, &[&layer_d]);
    let manifest_d = crate::digest::sha256_of(&manifest_body);
    let refs = manifest_references(&serde_json::from_slice(&manifest_body).unwrap());
    s.put_manifest(
        repo,
        Some(tag),
        &manifest_d,
        MEDIA_TYPE_IMAGE_MANIFEST,
        &manifest_body,
        ManifestLinks {
            references: &refs,
            required: &[config_d.clone(), layer_d.clone()],
            subject: None,
        },
    )
    .await
    .unwrap();
    (manifest_d, config_d, layer_d)
}

pub(crate) fn plant_layout(
    root: &std::path::Path,
    repo: &str,
    blobs: &[&[u8]],
    index_manifests: &[serde_json::Value],
) {
    let repo_dir = root.join(repo);
    std::fs::create_dir_all(repo_dir.join("blobs/sha256")).unwrap();
    std::fs::write(
        repo_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    for blob in blobs {
        let d = crate::digest::sha256_of(blob);
        std::fs::write(repo_dir.join("blobs/sha256").join(d.hex()), blob).unwrap();
    }
    if !index_manifests.is_empty() {
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": index_manifests
        });
        std::fs::write(
            repo_dir.join("index.json"),
            serde_json::to_vec(&index).unwrap(),
        )
        .unwrap();
    }
}
