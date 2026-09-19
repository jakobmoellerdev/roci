//! Integration test for the per-request tracing span spine (Phase 0
//! observability gate). Runs in its own process so it can install a **global**
//! `tracing` subscriber without racing the library's unit-test binary — the
//! `http.request` callsite is first evaluated against this subscriber, so its
//! interest is not poisoned by a `NoSubscriber` default.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request as HttpRequest;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::{Event, Id, Subscriber};

#[derive(Default)]
struct Collected {
    spans: AtomicUsize,
    status: AtomicU64,
    events: AtomicUsize,
}

struct Collector(Arc<Collected>);
struct StatusVisitor<'a>(&'a Collected);

impl Visit for StatusVisitor<'_> {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "http.status" {
            self.0.status.store(value, Ordering::SeqCst);
            self.0.events.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "http.status" {
            self.0.status.store(value as u64, Ordering::SeqCst);
            self.0.events.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn record_debug(&mut self, _f: &Field, _v: &dyn std::fmt::Debug) {}
}

impl Subscriber for Collector {
    fn enabled(&self, _m: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        if attrs.metadata().name() == "http.request" {
            self.0.spans.fetch_add(1, Ordering::SeqCst);
        }
        Id::from_u64(1)
    }
    fn record(&self, _s: &Id, _v: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _s: &Id, _f: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut v = StatusVisitor(&self.0);
        event.record(&mut v);
    }
    fn enter(&self, _s: &Id) {}
    fn exit(&self, _s: &Id) {}
}

#[tokio::test]
async fn request_emits_one_span_with_completion_event() {
    let collected = Arc::new(Collected::default());
    tracing::subscriber::set_global_default(Collector(Arc::clone(&collected)))
        .expect("set global subscriber");

    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let app = build_router(AppState::new(storage));
    let resp = app
        .oneshot(HttpRequest::get("/v2/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    assert_eq!(
        collected.spans.load(Ordering::SeqCst),
        1,
        "one request span"
    );
    assert_eq!(
        collected.events.load(Ordering::SeqCst),
        1,
        "one completion event"
    );
    assert_eq!(collected.status.load(Ordering::SeqCst), 200, "status 200");
}
