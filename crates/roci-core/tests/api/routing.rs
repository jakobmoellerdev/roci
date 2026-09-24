use axum::body::Body;
use axum::http::{Method, StatusCode};
use roci_config::Config;
use roci_core::{build_router, AppState};
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn base_endpoint_ok() {
    let (app, _d) = app();
    assert_eq!(status_of(&app, get("/v2/")).await, StatusCode::OK);
}

#[tokio::test]
async fn unsupported_paths_for_every_method() {
    let (app, _d) = app();
    // parse_path → Unknown: too few segments, and an unknown verb.
    for path in ["/v2/onlyone", "/v2/repo/bogusverb/x"] {
        for method in [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            assert_eq!(
                status_of(&app, request(method, path, &[], Body::empty())).await,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
    }
}

#[tokio::test]
async fn malformed_name_and_reference_rejected_before_handler() {
    let (app, _d) = app();
    // Uppercase repo name → NAME_INVALID (400), before any storage access.
    let v = body_json_of(&app, get("/v2/Foo/manifests/tag")).await;
    assert_eq!(v["errors"][0]["code"], "NAME_INVALID");
    // Path-traversal repo component → NAME_INVALID.
    assert_eq!(
        status_of(&app, get("/v2/a/../b/manifests/t")).await,
        StatusCode::BAD_REQUEST
    );
    // A syntactically-invalid manifest reference is NOT a 400 — per the
    // dist-spec conformance suite it resolves to 404 MANIFEST_UNKNOWN
    // (matches the suite's `.INVALID_MANIFEST_NAME` nonexistent-manifest
    // case). Only the repository name is grammar-rejected (above).
    let v = body_json_of(&app, get("/v2/ok/manifests/.INVALID_MANIFEST_NAME")).await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn put_and_patch_to_invalid_name_rejected() {
    let (app, _d) = app();
    assert_eq!(
        status_of(&app, put("/v2/BAD/manifests/t", Body::empty())).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status_of(&app, patch("/v2/BAD/blobs/uploads/x", Body::empty())).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn head_and_post_to_invalid_name_rejected() {
    let (app, _d) = app();
    assert_eq!(
        status_of(&app, head("/v2/BAD/manifests/t")).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status_of(&app, post("/v2/BAD/blobs/uploads/", Body::empty())).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn delete_disabled_returns_405() {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let m = br#"{"schemaVersion":2}"#;
    let md = sha256_of(m);
    storage
        .put_manifest(
            "r",
            Some("v1"),
            &md,
            "application/json",
            m,
            ManifestLinks::default(),
        )
        .await
        .unwrap();
    let mut config = Config::default();
    config.delete.enabled = false;
    let app = build_router(AppState::new_with(storage.clone(), config));
    for path in [
        format!("/v2/r/manifests/{md}"),
        "/v2/r/manifests/v1".to_string(),
        format!("/v2/r/blobs/{md}"),
    ] {
        let v = body_json_of(&app, delete(&path)).await;
        assert_eq!(v["errors"][0]["code"], "UNSUPPORTED", "{path}");
        assert_eq!(
            status_of(&app, delete(&path)).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    // Nothing was deleted.
    assert!(storage.get_manifest("r", "v1").await.is_ok());
}
