//! Test: metrics_router returns empty router when metrics.enabled=false.
#![cfg(feature = "otel")]

use roci_config::Config;

#[tokio::test]
async fn metrics_router_disabled() {
    let mut config = Config::default();
    config.telemetry.metrics.enabled = false;

    // Don't need init for this — just test the router selection.
    let router = roci_telemetry::metrics_router(&config);
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let resp = router
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();

    // Empty router → 404.
    assert_eq!(resp.status(), 404);
}
