use std::path::{Path, PathBuf};

use axum::body::{Body, Bytes};
use axum::http::{header, HeaderName, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use http_body_util::BodyExt;
use roci_config::Config;
use roci_core::auth::Auth;
use roci_core::{build_router, AppState};
use roci_storage::{sha256_of, Digest, FsStorage, ManifestLinks, Storage};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

/// App over a fresh store.
pub fn app() -> (Router, TempDir) {
    app_with_config(Config::default())
}

pub fn app_with_config(config: Config) -> (Router, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    (build_router(AppState::new_with(storage, config)), dir)
}

/// App with auth engine from `config`.
pub fn app_with_auth(config: Config) -> (Router, Arc<Auth>, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let auth = Auth::from_config(&config)
        .unwrap()
        .expect("auth configured");
    let state = AppState::new_with(storage, config).with_auth(Some(Arc::clone(&auth)));
    (build_router(state), auth, dir)
}

pub fn app_with_storage() -> (Router, FsStorage, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    (build_router(AppState::new(storage.clone())), storage, dir)
}

/// App whose `r/index.json` is a directory (→ 500).
pub fn app_with_broken_repo() -> (Router, TempDir) {
    let (app, dir) = app();
    std::fs::create_dir_all(dir.path().join("r").join("index.json")).unwrap();
    (app, dir)
}

pub fn app_broken_uploads() -> (Router, TempDir) {
    let (app, dir) = app();
    std::fs::create_dir_all(dir.path().join("r")).unwrap();
    std::fs::write(dir.path().join("r").join("uploads"), b"file").unwrap();
    (app, dir)
}

pub fn request(
    method: Method,
    uri: impl AsRef<str>,
    headers: &[(HeaderName, &str)],
    body: impl Into<Body>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri.as_ref());
    for (name, value) in headers {
        b = b.header(name, *value);
    }
    b.body(body.into()).unwrap()
}

pub fn get(uri: impl AsRef<str>) -> Request<Body> {
    request(Method::GET, uri, &[], Body::empty())
}

pub fn head(uri: impl AsRef<str>) -> Request<Body> {
    request(Method::HEAD, uri, &[], Body::empty())
}

pub fn delete(uri: impl AsRef<str>) -> Request<Body> {
    request(Method::DELETE, uri, &[], Body::empty())
}

pub fn post(uri: impl AsRef<str>, body: impl Into<Body>) -> Request<Body> {
    request(Method::POST, uri, &[], body)
}

pub fn put(uri: impl AsRef<str>, body: impl Into<Body>) -> Request<Body> {
    request(Method::PUT, uri, &[], body)
}

pub fn patch(uri: impl AsRef<str>, body: impl Into<Body>) -> Request<Body> {
    request(Method::PATCH, uri, &[], body)
}

pub async fn send(app: &Router, req: Request<Body>) -> Response {
    app.clone().oneshot(req).await.unwrap()
}

pub async fn status_of(app: &Router, req: Request<Body>) -> StatusCode {
    send(app, req).await.status()
}

pub async fn body_json_of(app: &Router, req: Request<Body>) -> serde_json::Value {
    let bytes = body_bytes(send(app, req).await).await;
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

pub async fn json_body(resp: Response) -> serde_json::Value {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

pub async fn body_bytes(resp: Response) -> Bytes {
    resp.into_body().collect().await.unwrap().to_bytes()
}

pub fn hv(resp: &Response, name: HeaderName) -> Option<&str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

pub fn location(resp: &Response) -> String {
    hv(resp, header::LOCATION).unwrap().to_string()
}

/// Monolithic blob push; asserts 201.
pub async fn push_blob(app: &Router, repo: &str, data: &[u8]) -> Digest {
    let d = sha256_of(data);
    let uri = format!("/v2/{repo}/blobs/uploads/?digest={d}");
    assert_eq!(
        status_of(app, post(uri, data.to_vec())).await,
        StatusCode::CREATED
    );
    d
}

/// PUT manifest; asserts 201.
pub async fn push_manifest(
    app: &Router,
    repo: &str,
    reference: &str,
    media_type: &str,
    body: &[u8],
) {
    let req = request(
        Method::PUT,
        format!("/v2/{repo}/manifests/{reference}"),
        &[(header::CONTENT_TYPE, media_type)],
        body.to_vec(),
    );
    assert_eq!(status_of(app, req).await, StatusCode::CREATED);
}

pub async fn start_session(app: &Router, repo: &str) -> String {
    let resp = send(
        app,
        post(format!("/v2/{repo}/blobs/uploads/"), Body::empty()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    location(&resp)
}

pub const ROCI_BASIC: &str = "Basic realm=\"roci\"";

pub fn basic(user: &str, pw: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pw}")))
}

pub fn as_user(
    method: Method,
    uri: impl AsRef<str>,
    auth: &str,
    body: impl Into<Body>,
) -> Request<Body> {
    request(method, uri, &[(header::AUTHORIZATION, auth)], body)
}

pub fn htpasswd(dir: &Path, users: &[(&str, &str)]) -> PathBuf {
    let path = dir.join("htpasswd");
    let lines: Vec<String> = users
        .iter()
        .map(|(u, p)| format!("{u}:{}", bcrypt::hash(p, 4).unwrap()))
        .collect();
    std::fs::write(&path, lines.join("\n")).unwrap();
    path
}

pub async fn error_code(resp: Response) -> (String, String) {
    let v = json_body(resp).await;
    (
        v["errors"][0]["code"].as_str().unwrap().to_string(),
        v["errors"][0]["message"].as_str().unwrap().to_string(),
    )
}

pub fn manifest_put(uri: impl AsRef<str>, ct: &str, body: impl Into<Body>) -> Request<Body> {
    request(Method::PUT, uri, &[(header::CONTENT_TYPE, ct)], body)
}

pub async fn seed_tags(storage: &FsStorage, repo: &str, tags: &[&str]) {
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    for t in tags {
        storage
            .put_manifest(
                repo,
                Some(t),
                &d,
                "application/json",
                body,
                ManifestLinks::default(),
            )
            .await
            .unwrap();
    }
}
