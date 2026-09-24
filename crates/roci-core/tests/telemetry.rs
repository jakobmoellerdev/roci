//! Integration tests verifying the telemetry spine emits expected span
//! attributes (semconv) and metrics (Prometheus text).
//!
//! Each test installs its own global subscriber and lives in its own binary,
//! so there is no cross-test poisoning of the global state.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request as HttpRequest;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::{Id, Subscriber};

/// Collected span data from a custom subscriber.
#[derive(Default)]
struct Collected {
    spans: AtomicUsize,
    has_method: AtomicUsize,
    has_url_path: AtomicUsize,
    has_route: AtomicUsize,
    status: AtomicU64,
    events: AtomicUsize,
}

struct SpanVisitor<'a>(&'a Collected);

impl Visit for SpanVisitor<'_> {
    fn record_debug(&mut self, field: &Field, _v: &dyn std::fmt::Debug) {
        match field.name() {
            "http.request.method" => {
                self.0.has_method.fetch_add(1, Ordering::SeqCst);
            }
            "url.path" => {
                self.0.has_url_path.fetch_add(1, Ordering::SeqCst);
            }
            "http.route" => {
                self.0.has_route.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

struct EventVisitor<'a>(&'a Collected);

impl Visit for EventVisitor<'_> {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "http.response.status_code" {
            self.0.status.store(value, Ordering::SeqCst);
            self.0.events.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "http.response.status_code" {
            self.0.status.store(value as u64, Ordering::SeqCst);
            self.0.events.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn record_debug(&mut self, _f: &Field, _v: &dyn std::fmt::Debug) {}
}

struct AttrCollector(Arc<Collected>);

impl Subscriber for AttrCollector {
    fn enabled(&self, _m: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        if attrs.metadata().name() == "http.request" {
            self.0.spans.fetch_add(1, Ordering::SeqCst);
            let mut v = SpanVisitor(&self.0);
            attrs.record(&mut v);
        }
        Id::from_u64(1)
    }
    fn record(&self, _s: &Id, _v: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _s: &Id, _f: &Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut v = EventVisitor(&self.0);
        event.record(&mut v);
    }
    fn enter(&self, _s: &Id) {}
    fn exit(&self, _s: &Id) {}
}

#[tokio::test]
async fn request_span_has_semconv_attributes() {
    let collected = Arc::new(Collected::default());
    tracing::subscriber::set_global_default(AttrCollector(Arc::clone(&collected)))
        .expect("set global subscriber");

    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let app = build_router(AppState::new(storage));

    let resp = app
        .oneshot(HttpRequest::get("/v2/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The span must carry semconv attributes.
    assert_eq!(
        collected.spans.load(Ordering::SeqCst),
        1,
        "one http.request span"
    );
    assert_eq!(
        collected.has_method.load(Ordering::SeqCst),
        1,
        "http.request.method present"
    );
    assert_eq!(
        collected.has_url_path.load(Ordering::SeqCst),
        1,
        "url.path present"
    );
    assert_eq!(
        collected.has_route.load(Ordering::SeqCst),
        1,
        "http.route present"
    );
    // Completion event recorded the status.
    assert_eq!(
        collected.events.load(Ordering::SeqCst),
        1,
        "one completion event"
    );
    assert_eq!(collected.status.load(Ordering::SeqCst), 200, "status 200");
}
