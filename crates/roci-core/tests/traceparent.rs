//! OTel traceparent propagation test.
//!
//! This test lives in its own binary so its global tracing subscriber is not
//! poisoned by another test's NoSubscriber (tracing callsite caching).
#![cfg(feature = "otel")]

use axum::body::Body;
use axum::http::Request as HttpRequest;
use opentelemetry::trace::{TraceId, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_sdk::testing::trace::new_tokio_test_exporter;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use tower::ServiceExt;
use tracing_subscriber::prelude::*;

#[tokio::test(flavor = "current_thread")]
async fn traceparent_header_propagates_trace_id() {
    let resource = Resource::builder_empty()
        .with_attribute(KeyValue::new("service.name", "roci-test"))
        .build();

    let (span_exporter, mut rx_export, _rx_shutdown) = new_tokio_test_exporter();
    let trace_provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_simple_exporter(span_exporter)
        .build();
    let tracer = trace_provider.tracer("roci-test");

    // Register W3C propagator.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    // Set up tracing subscriber with OTel layer as the global default.
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = tracing_subscriber::registry().with(otel_layer);
    tracing::subscriber::set_global_default(subscriber).expect("set global subscriber");

    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let app = build_router(AppState::new(storage));

    // Craft a request with a W3C traceparent header.
    let expected_trace_id = "0af7651916cd43dd8448eb211c80319c";
    let traceparent = format!("00-{expected_trace_id}-b7ad6b7169203331-01");

    let resp = app
        .oneshot(
            HttpRequest::get("/v2/r/manifests/missing")
                .header("traceparent", &traceparent)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Flush to make sure spans are exported.
    let _ = trace_provider.force_flush();

    // The exported root span continues the caller's trace and carries the
    // dist-spec error as OTel span status ERROR + `error.type`.
    let expected = TraceId::from_hex(expected_trace_id).unwrap();
    let root = std::iter::from_fn(|| rx_export.try_recv().ok())
        .find(|s| s.name == "http.request")
        .expect("root span exported");
    assert_eq!(root.span_context.trace_id(), expected);
    assert!(matches!(
        root.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    assert!(root
        .attributes
        .iter()
        .any(|kv| kv.key.as_str() == "error.type" && kv.value.as_str() == "MANIFEST_UNKNOWN"));
}
