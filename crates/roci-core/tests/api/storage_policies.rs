//! Storage policies as clients see them: quota and session-cap rejections on
//! the wire, and foreign layer media types (`tar+zstd`) served untouched.

use axum::http::{header, Method, StatusCode};
use axum::Router;
use roci_config::{Config, StorageConfig};
use roci_core::{build_router, AppState};
use roci_storage::quota::{QuotaLimits, QuotaTracker};
use roci_storage::*;
use std::sync::Arc;
use tempfile::TempDir;

use super::common::*;

fn app_with_quota(limits: QuotaLimits) -> (Router, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::with_config(
        dir.path(),
        &StorageConfig::default(),
        Arc::new(QuotaTracker::new(limits)),
    )
    .unwrap();
    (
        build_router(AppState::new_with(storage, Config::default())),
        dir,
    )
}

async fn monolithic(app: &Router, repo: &str, data: &[u8]) -> axum::response::Response {
    let d = sha256_of(data);
    send(
        app,
        post(
            format!("/v2/{repo}/blobs/uploads/?digest={d}"),
            data.to_vec(),
        ),
    )
    .await
}

#[tokio::test]
async fn repository_quota_is_413_and_registry_quota_is_507() {
    let (app, _d) = app_with_quota(QuotaLimits {
        max_repo_bytes: 8,
        max_total_bytes: 12,
        ..QuotaLimits::default()
    });
    assert_eq!(
        monolithic(&app, "a", b"12345678").await.status(),
        StatusCode::CREATED
    );
    let over_repo = monolithic(&app, "a", b"9").await;
    assert_eq!(over_repo.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        json_body(over_repo).await["errors"][0]["code"],
        "SIZE_INVALID"
    );
    assert_eq!(
        monolithic(&app, "b", b"1234").await.status(),
        StatusCode::CREATED
    );
    let over_total = monolithic(&app, "c", b"x").await;
    assert_eq!(over_total.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(json_body(over_total).await["errors"][0]["code"], "DENIED");
}

#[tokio::test]
async fn upload_session_cap_is_429_until_a_session_ends() {
    let (app, _d) = app_with_quota(QuotaLimits {
        max_upload_sessions: 1,
        ..QuotaLimits::default()
    });
    let first = start_session(&app, "r").await;
    let refused = send(
        &app,
        post("/v2/r/blobs/uploads/", axum::body::Body::empty()),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(refused).await["errors"][0]["code"],
        "TOOMANYREQUESTS"
    );
    // Completing the session frees its slot.
    let d = sha256_of(b"done");
    let sep = if first.contains('?') { '&' } else { '?' };
    assert_eq!(
        status_of(
            &app,
            put(format!("{first}{sep}digest={d}"), b"done".to_vec())
        )
        .await,
        StatusCode::CREATED
    );
    start_session(&app, "r").await;
}

#[tokio::test]
async fn tar_zstd_layers_are_accepted_and_served_byte_identical() {
    let (app, _d) = app();
    // A zstd frame (magic 28 b5 2f fd) — roci never inspects layer bytes.
    let layer: Vec<u8> = [0x28, 0xb5, 0x2f, 0xfd]
        .into_iter()
        .chain((0..4096u32).map(|i| (i * 31 % 251) as u8))
        .collect();
    let layer_digest = push_blob(&app, "r", &layer).await;
    let config = push_blob(&app, "r", b"{}").await;
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config.as_string(), "size": 2},
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
            "digest": layer_digest.as_string(),
            "size": layer.len(),
        }],
    });
    let body = serde_json::to_vec(&manifest).unwrap();
    push_manifest(
        &app,
        "r",
        "zstd",
        "application/vnd.oci.image.manifest.v1+json",
        &body,
    )
    .await;
    let pulled = send(&app, get("/v2/r/manifests/zstd")).await;
    assert_eq!(body_bytes(pulled).await, body);
    let blob = send(&app, get(format!("/v2/r/blobs/{layer_digest}"))).await;
    assert_eq!(blob.status(), StatusCode::OK);
    assert_eq!(
        hv(&blob, header::CONTENT_TYPE),
        Some("application/octet-stream")
    );
    assert_eq!(body_bytes(blob).await.as_ref(), layer.as_slice());
    // Ranged reads of the compressed layer are served as stored.
    let ranged = send(
        &app,
        request(
            Method::GET,
            format!("/v2/r/blobs/{layer_digest}"),
            &[(header::RANGE, "bytes=0-3")],
            axum::body::Body::empty(),
        ),
    )
    .await;
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(ranged).await.as_ref(), &[0x28, 0xb5, 0x2f, 0xfd]);
}
