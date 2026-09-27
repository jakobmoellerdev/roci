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
    let v = body_json_of(&app, get("/v2/Foo/manifests/tag")).await;
    assert_eq!(v["errors"][0]["code"], "NAME_INVALID");
    assert_eq!(
        status_of(&app, get("/v2/a/../b/manifests/t")).await,
        StatusCode::BAD_REQUEST
    );
    let v = body_json_of(&app, get("/v2/ok/manifests/.INVALID_MANIFEST_NAME")).await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn invalid_name_rejected_for_all_methods() {
    let (app, _d) = app();
    for (label, req) in [
        ("PUT", put("/v2/BAD/manifests/t", Body::empty())),
        ("PATCH", patch("/v2/BAD/blobs/uploads/x", Body::empty())),
        ("HEAD", head("/v2/BAD/manifests/t")),
        ("POST", post("/v2/BAD/blobs/uploads/", Body::empty())),
    ] {
        assert_eq!(
            status_of(&app, req).await,
            StatusCode::BAD_REQUEST,
            "{label}"
        );
    }
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
    assert!(storage.get_manifest("r", "v1").await.is_ok());
}
