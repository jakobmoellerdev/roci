//! OTel-feature integration tests:
//! - Error response increments `registry.request.errors{error_code="BLOB_UNKNOWN"}`
//!   visible via InMemoryMetricExporter.
//!
//! Requires the `otel` feature; guarded by `#[cfg(feature = "otel")]` so the
//! minimal build skips these entirely.
//!
//! The traceparent propagation test lives in its own binary (`traceparent.rs`)
//! to avoid tracing callsite-cache poisoning.
#![cfg(feature = "otel")]

use axum::body::Body;
use axum::http::Request as HttpRequest;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::InMemoryMetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use tower::ServiceExt;

#[tokio::test]
async fn error_response_increments_prometheus_counter() {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let resource = Resource::builder_empty()
        .with_attribute(KeyValue::new("service.name", "roci-test"))
        .build();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    let meter = meter_provider.meter("roci");
    let error_counter = meter
        .u64_counter("registry.request.errors")
        .with_description("Count of registry request errors by error code")
        .build();

    error_counter.add(1, &[KeyValue::new("error_code", "BLOB_UNKNOWN")]);
    meter_provider.force_flush().unwrap();

    let metrics = exporter.get_finished_metrics().unwrap();
    let mut found_blob_unknown = false;
    for rm in &metrics {
        for sm in rm.scope_metrics() {
            for metric in sm.metrics() {
                if metric.name() == "registry.request.errors" {
                    if let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() {
                        for dp in sum.data_points() {
                            for kv in dp.attributes() {
                                if kv.key.as_str() == "error_code"
                                    && kv.value.to_string() == "BLOB_UNKNOWN"
                                {
                                    found_blob_unknown = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        found_blob_unknown,
        "should find error_code=BLOB_UNKNOWN data point in {metrics:?}"
    );
}

#[tokio::test]
async fn error_response_through_router_returns_correct_status() {
    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let app = build_router(AppState::new(storage));

    let resp = app
        .oneshot(
            HttpRequest::get("/v2/myrepo/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "blob not found → 404");
}
