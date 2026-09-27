//! Tests for the `/readyz` and `/livez` health endpoints.

use crate::common::{send, status_of};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use roci_config::Config;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;

/// Build an app whose `recovered` flag is still `false`, returning both the
/// router and the state so the test can toggle recovery.
fn app_unrecovered() -> (axum::Router, AppState<FsStorage>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let state = AppState::new_with(storage, Config::default());
    let router = build_router(state.clone());
    (router, state, dir)
}

#[tokio::test]
async fn livez_always_200() {
    let (app, _state, _dir) = app_unrecovered();
    let resp = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/livez")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn livez_head_200() {
    let (app, _state, _dir) = app_unrecovered();
    let resp = send(
        &app,
        Request::builder()
            .method(Method::HEAD)
            .uri("/livez")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn readyz_503_before_recovery() {
    let (app, _state, _dir) = app_unrecovered();
    let status = status_of(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn readyz_head_503_before_recovery() {
    let (app, _state, _dir) = app_unrecovered();
    let status = status_of(
        &app,
        Request::builder()
            .method(Method::HEAD)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn readyz_200_after_recovery() {
    let (app, state, _dir) = app_unrecovered();
    // Before recovery.
    let status = status_of(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Mark recovery complete.
    state.set_recovered();

    // After recovery: FsStorage is always-ready, so readyz should return 200.
    let status = status_of(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn readyz_body_content() {
    let (app, state, _dir) = app_unrecovered();

    // Not ready: body should contain "not ready:".
    let resp = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("not ready:"),
        "503 body should contain 'not ready:'"
    );

    state.set_recovered();

    // Ready: body should be "ok".
    let resp = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"ok");
}

async fn readyz(app: &axum::Router) -> (StatusCode, String) {
    let resp = send(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn readyz_503_when_storage_not_ready_without_leaking_detail() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new_with(FsStorage::new(dir.path()).unwrap(), Config::default())
        .with_ready_check(|| async {
            Err(roci_storage::StorageError::Unavailable(
                "NoSuchBucket at http://secret-host/bucket".into(),
            ))
        });
    state.set_recovered();
    let (status, body) = readyz(&build_router(state)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, "not ready: storage unavailable");
}

#[tokio::test(start_paused = true)]
async fn readyz_503_when_storage_check_hangs() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new_with(FsStorage::new(dir.path()).unwrap(), Config::default())
        .with_ready_check(std::future::pending::<Result<(), roci_storage::StorageError>>);
    state.set_recovered();
    let (status, _) = readyz(&build_router(state)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn readyz_bypasses_auth() {
    // Configure auth; readyz must still be accessible without credentials.
    use roci_core::auth::Auth;

    let mut config = Config::default();
    // Enable htpasswd auth.
    config.auth.htpasswd = Some(roci_config::HtpasswdConfig {
        path: std::path::PathBuf::from("/dev/null"),
    });
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let auth = Auth::from_config(&config).ok().flatten();
    let state = AppState::new_with(storage, config).with_auth(auth);
    state.set_recovered();
    let app = build_router(state);

    // /readyz without any auth header → 200 (not 401).
    let status = status_of(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // /livez also bypasses auth.
    let status = status_of(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/livez")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
