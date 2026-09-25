//! Test: OTel metrics recording + Prometheus handler + metrics_router.
//! Exercises metrics::install, record_request (all status classes),
//! record_error, prometheus_handler (both 503-before-init and 200-after-init),
//! and metrics_router(enabled=true).
#![cfg(feature = "otel")]

use roci_config::Config;

/// Single test that exercises both the uninitialised and initialised handler
/// paths in one process, avoiding llvm-cov profdata merge issues.
#[tokio::test]
async fn metrics_full_lifecycle() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let mut config = Config::default();
    config.telemetry.metrics.enabled = true;
    config.telemetry.metrics.path = "/metrics".into();

    // ── Before init: handler returns 503 ────────────────────────────
    let router = roci_telemetry::metrics_router(&config);
    let resp = router
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        503,
        "should be SERVICE_UNAVAILABLE without init"
    );

    // ── After init: handler returns 200 with Prometheus text ────────
    let _guard = roci_telemetry::init(&config).expect("init for metrics test");

    // Exercise all status_class branches and record_error.
    use std::time::Duration;
    roci_telemetry::record_request("blobs", "GET", 200, Duration::from_millis(10));
    roci_telemetry::record_request("manifests", "GET", 304, Duration::from_millis(5));
    roci_telemetry::record_request("uploads", "PUT", 404, Duration::from_millis(2));
    roci_telemetry::record_request("other", "POST", 500, Duration::from_millis(100));
    roci_telemetry::record_error("BLOB_UNKNOWN");
    // Storage-subsystem counters.
    roci_telemetry::record_gc_collected("blob", 4096);
    roci_telemetry::record_scrub("corrupt", 512);
    roci_telemetry::record_dedupe_link("dedupe", "hardlink");
    roci_telemetry::record_quota_rejection("total");
    roci_telemetry::record_auth_decision("htpasswd", "denied");

    let router = roci_telemetry::metrics_router(&config);
    let resp = router
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    // Verify histogram and counter appear in Prometheus text.
    assert!(
        text.contains("http_server_request_duration"),
        "should contain request duration histogram: {text}"
    );
    assert!(
        text.contains("registry_request_errors"),
        "should contain error counter: {text}"
    );
    assert!(
        text.contains("BLOB_UNKNOWN"),
        "should contain BLOB_UNKNOWN label: {text}"
    );
    // Storage counters are exported with their bounded labels and values.
    for series in [
        "registry_gc_collected_total{kind=\"blob\"} 1",
        "registry_gc_collected_bytes_total{kind=\"blob\"} 4096",
        "registry_scrub_checked_total{result=\"corrupt\"} 1",
        "registry_scrub_bytes_total{} 512",
        "registry_quota_rejections_total{scope=\"total\"} 1",
    ] {
        assert!(text.contains(series), "missing `{series}` in: {text}");
    }
    assert!(
        text.contains("registry_dedupe_links_total{") && text.contains("mechanism=\"hardlink\""),
        "missing dedupe link series in: {text}"
    );
    assert!(
        text.contains("registry_auth_decisions_total{")
            && text.contains("method=\"htpasswd\"")
            && text.contains("result=\"denied\""),
        "missing auth decision series in: {text}"
    );
}
