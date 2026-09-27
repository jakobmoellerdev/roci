use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::StatusCode;
use roci_config::{Bucket, Config, RateLimitConfig};
use tempfile::TempDir;

use super::common::*;

fn bucket(rate: u32, burst: u32) -> Bucket {
    Bucket { rate, burst }
}

fn app_with_rl(rl: RateLimitConfig) -> (axum::Router, TempDir) {
    let mut config = Config::default();
    config.http.rate_limit = rl;
    app_with_config(config)
}

fn get_v2_with_peer(ip: std::net::IpAddr) -> axum::http::Request<Body> {
    let mut req = get("/v2/");
    req.extensions_mut().insert(roci_core::PeerAddr(ip));
    req
}

#[tokio::test(start_paused = true)]
async fn burst_n_pass_then_429() {
    let rl = RateLimitConfig {
        enabled: true,
        default: Some(bucket(1, 3)),
        per_method: BTreeMap::new(),
        per_client: None,
    };
    let (app, _d) = app_with_rl(rl);

    for i in 0..3 {
        let resp = send(&app, get("/v2/")).await;
        assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
    }

    let resp = send(&app, get("/v2/")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = json_body(resp).await;
    assert_eq!(body["errors"][0]["code"], "TOOMANYREQUESTS");

    let resp = send(&app, get("/v2/")).await;
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
        per_client: None,
    };
    let (app, _d) = app_with_rl(rl);

    let resp = send(&app, get("/v2/")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = send(&app, get("/v2/")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    tokio::time::advance(std::time::Duration::from_secs(1)).await;

    let resp = send(&app, get("/v2/")).await;
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
        per_client: None,
    };
    let (app, _d) = app_with_rl(rl);

    let resp = send(&app, put("/v2/repo/manifests/tag", Body::empty())).await;
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "first PUT should pass"
    );

    let resp = send(&app, put("/v2/repo/manifests/tag", Body::empty())).await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second PUT should be rate-limited"
    );

    let resp = send(&app, get("/v2/")).await;
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
        per_client: None,
    };
    let (app, _d) = app_with_rl(rl);

    for _ in 0..50 {
        let resp = send(&app, get("/v2/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test(start_paused = true)]
async fn disabled_config_never_429s() {
    let rl = RateLimitConfig {
        enabled: false,
        default: Some(bucket(1, 1)),
        per_method: BTreeMap::new(),
        per_client: None,
    };
    let (app, _d) = app_with_rl(rl);

    for _ in 0..50 {
        let resp = send(&app, get("/v2/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test(start_paused = true)]
async fn per_client_independent_buckets() {
    let rl = RateLimitConfig {
        enabled: true,
        default: None,
        per_method: BTreeMap::new(),
        per_client: Some(roci_config::PerClientConfig {
            rate: 1,
            burst: 1,
            max_clients: 100,
        }),
    };
    let (app, _d) = app_with_rl(rl);
    let ip_a: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let ip_b: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    let resp = send(&app, get_v2_with_peer(ip_a)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&app, get_v2_with_peer(ip_a)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let resp = send(&app, get_v2_with_peer(ip_b)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn per_client_lru_eviction_resets_bucket() {
    let rl = RateLimitConfig {
        enabled: true,
        default: None,
        per_method: BTreeMap::new(),
        per_client: Some(roci_config::PerClientConfig {
            rate: 1,
            burst: 1,
            max_clients: 2,
        }),
    };
    let (app, _d) = app_with_rl(rl);
    let ip_a: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let ip_b: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let ip_c: std::net::IpAddr = "10.0.0.3".parse().unwrap();

    let resp = send(&app, get_v2_with_peer(ip_a)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&app, get_v2_with_peer(ip_a)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let resp = send(&app, get_v2_with_peer(ip_b)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = send(&app, get_v2_with_peer(ip_c)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = send(&app, get_v2_with_peer(ip_a)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn per_client_absent_means_no_per_client_limiting() {
    let rl = RateLimitConfig {
        enabled: true,
        default: None,
        per_method: BTreeMap::new(),
        per_client: None,
    };
    let (app, _d) = app_with_rl(rl);
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    for _ in 0..50 {
        let resp = send(&app, get_v2_with_peer(ip)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
