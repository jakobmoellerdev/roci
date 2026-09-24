use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use roci_config::{Bucket, Config, RateLimitConfig};
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use tempfile::TempDir;
use tower::ServiceExt;

fn bucket(rate: u32, burst: u32) -> Bucket {
    Bucket { rate, burst }
}

/// Build a router with the given rate-limit config.
fn app_with_rl(rl: RateLimitConfig) -> (axum::Router, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let mut config = Config::default();
    config.http.rate_limit = rl;
    let state = AppState::new_with(storage, config);
    (build_router(state), dir)
}

fn get_v2() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/v2/")
        .body(Body::empty())
        .unwrap()
}

fn put_v2() -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
        .uri("/v2/repo/manifests/tag")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn burst_n_pass_then_429() {
    let rl = RateLimitConfig {
        enabled: true,
        default: Some(bucket(1, 3)),
        per_method: BTreeMap::new(),
    };
    let (app, _d) = app_with_rl(rl);

    // First 3 (burst) should succeed
    for i in 0..3 {
        let resp = app.clone().oneshot(get_v2()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
    }

    // 4th should be 429
    let resp = app.clone().oneshot(get_v2()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // Check TOOMANYREQUESTS error body
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["errors"][0]["code"], "TOOMANYREQUESTS");

    // Check Retry-After header is present
    let resp = app.clone().oneshot(get_v2()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After header missing");
    let secs: u64 = retry_after.to_str().unwrap().parse().unwrap();
    assert!(secs >= 1, "Retry-After should be at least 1 second");
}

#[tokio::test(start_paused = true)]
async fn tokens_refill_after_time_advance() {
    let rl = RateLimitConfig {
        enabled: true,
        default: Some(bucket(1, 1)),
        per_method: BTreeMap::new(),
    };
    let (app, _d) = app_with_rl(rl);

    // Consume the one token
    let resp = app.clone().oneshot(get_v2()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Exhausted
    let resp = app.clone().oneshot(get_v2()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // Advance time by 1 second, token refills
    tokio::time::advance(std::time::Duration::from_secs(1)).await;

    let resp = app.clone().oneshot(get_v2()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn per_method_independent_of_default() {
    let mut per_method = BTreeMap::new();
    per_method.insert("PUT".to_string(), bucket(1, 1));
    let rl = RateLimitConfig {
        enabled: true,
        default: Some(bucket(100, 100)),
        per_method,
    };
    let (app, _d) = app_with_rl(rl);

    // Exhaust PUT bucket
    let resp = app.clone().oneshot(put_v2()).await.unwrap();
    // PUT to manifests without content → could be 4xx from handler, but rate
    // limit only fires on *exhausted* bucket. The first PUT consumes a token,
    // let's check the second is 429.
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "first PUT should pass"
    );

    let resp = app.clone().oneshot(put_v2()).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second PUT should be rate-limited"
    );

    // GET still works (uses default bucket with burst=100)
    let resp = app.clone().oneshot(get_v2()).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET should use default bucket"
    );
}

#[tokio::test(start_paused = true)]
async fn unlisted_method_no_default_unlimited() {
    let mut per_method = BTreeMap::new();
    per_method.insert("PUT".to_string(), bucket(1, 1));
    let rl = RateLimitConfig {
        enabled: true,
        default: None,
        per_method,
    };
    let (app, _d) = app_with_rl(rl);

    // GET has no per-method entry and no default → unlimited
    for _ in 0..50 {
        let resp = app.clone().oneshot(get_v2()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test(start_paused = true)]
async fn disabled_config_never_429s() {
    let rl = RateLimitConfig {
        enabled: false,
        default: Some(bucket(1, 1)),
        per_method: BTreeMap::new(),
    };
    let (app, _d) = app_with_rl(rl);

    // Even with burst=1, disabled means no rate limiting
    for _ in 0..50 {
        let resp = app.clone().oneshot(get_v2()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
