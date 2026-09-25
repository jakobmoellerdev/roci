//! Integration test for storage-internal span propagation: `blob.stream` and
//! `cas.link` must appear as children of the request `http.request` span.
//! Runs in its own binary so it can install a global subscriber.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use roci_core::{build_router, AppState};
use roci_storage::{sha256_of, FsStorage};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::{Id, Subscriber};

// ── Span-collecting subscriber ──────────────────────────────────────────

/// Tracks span creation and parent relationships.
#[derive(Default)]
struct Collected {
    next_id: AtomicU64,
    /// span_id → (name, parent_id)
    spans: Mutex<HashMap<u64, (String, Option<u64>)>>,
    /// span_id of the entered span (last entered).
    current: Mutex<Option<u64>>,
    /// span_id → recorded mechanism field value
    mechanisms: Mutex<HashMap<u64, String>>,
}

struct Collector(Arc<Collected>);

struct FieldVisitor {
    mechanism: Option<String>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "mechanism" {
            self.mechanism = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, _f: &Field, _v: &dyn std::fmt::Debug) {}
}

impl Subscriber for Collector {
    fn enabled(&self, _m: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let id = self.0.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let parent = attrs.parent().map(|p| p.into_u64()).or_else(|| {
            if attrs.is_contextual() {
                *self.0.current.lock().unwrap()
            } else {
                None
            }
        });
        let name = attrs.metadata().name().to_string();
        self.0.spans.lock().unwrap().insert(id, (name, parent));
        // Record mechanism if set at creation.
        let mut fv = FieldVisitor { mechanism: None };
        attrs.record(&mut fv);
        if let Some(m) = fv.mechanism {
            self.0.mechanisms.lock().unwrap().insert(id, m);
        }
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &tracing::span::Record<'_>) {
        let mut fv = FieldVisitor { mechanism: None };
        values.record(&mut fv);
        if let Some(m) = fv.mechanism {
            self.0.mechanisms.lock().unwrap().insert(span.into_u64(), m);
        }
    }

    fn record_follows_from(&self, _s: &Id, _f: &Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, span: &Id) {
        *self.0.current.lock().unwrap() = Some(span.into_u64());
    }

    fn exit(&self, _s: &Id) {}
}

impl Collected {
    /// Returns true if there is a span with `name` that is a descendant of a
    /// span with `ancestor_name`.
    fn has_descendant(&self, ancestor_name: &str, name: &str) -> bool {
        let spans = self.spans.lock().unwrap();
        // Find spans with the given name.
        for (id, (n, _)) in spans.iter() {
            if n == name {
                // Walk up the parent chain.
                let mut cur = spans.get(id).and_then(|(_, p)| *p);
                while let Some(pid) = cur {
                    if let Some((pn, pp)) = spans.get(&pid) {
                        if pn == ancestor_name {
                            return true;
                        }
                        cur = *pp;
                    } else {
                        break;
                    }
                }
            }
        }
        false
    }

    /// Return the mechanism value recorded on any `cas.link` span.
    fn cas_link_mechanism(&self) -> Option<String> {
        let spans = self.spans.lock().unwrap();
        let mechs = self.mechanisms.lock().unwrap();
        for (id, (name, _)) in spans.iter() {
            if name == "cas.link" {
                if let Some(m) = mechs.get(id) {
                    return Some(m.clone());
                }
            }
        }
        None
    }
}

// ── Test ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn blob_stream_and_cas_link_spans_are_request_children() {
    let collected = Arc::new(Collected::default());
    tracing::subscriber::set_global_default(Collector(Arc::clone(&collected)))
        .expect("set global subscriber");

    let dir = tempfile::tempdir().unwrap();
    let storage = FsStorage::new(dir.path()).unwrap();
    let app = build_router(AppState::new(storage));

    // Push a blob into repo "a" so we can GET it (exercises blob.stream).
    let blob = b"stream-test-blob-data-payload-that-is-non-trivial";
    let d = sha256_of(blob);
    let push_uri = format!("/v2/a/blobs/uploads/?digest={d}");
    let push_req = Request::builder()
        .method(Method::POST)
        .uri(&push_uri)
        .body(Body::from(blob.to_vec()))
        .unwrap();
    let resp = app.clone().oneshot(push_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "blob push");

    // GET the blob — this exercises into_stream → file_stream → blob.stream
    let get_req = Request::get(format!("/v2/a/blobs/{d}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(get_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Consume the body to drive the stream (and its spans).
    let _ = resp.into_body().collect().await.unwrap().to_bytes();

    // Verify blob.stream is a descendant of http.request.
    assert!(
        collected.has_descendant("http.request", "blob.stream"),
        "blob.stream should be a child of http.request: {:?}",
        collected.spans.lock().unwrap()
    );

    // Cross-repo mount: push the same blob to repo "b" via a mount from "a".
    // The distribution spec mount is POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<other>
    let mount_uri = format!("/v2/b/blobs/uploads/?mount={d}&from=a");
    let mount_req = Request::builder()
        .method(Method::POST)
        .uri(&mount_uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(mount_req).await.unwrap();
    // Mount succeeds: 201 Created.
    assert_eq!(resp.status(), StatusCode::CREATED, "cross-repo mount");

    // Verify cas.link is a descendant of http.request.
    assert!(
        collected.has_descendant("http.request", "cas.link"),
        "cas.link should be a child of http.request: {:?}",
        collected.spans.lock().unwrap()
    );

    // Verify the mechanism field was recorded on the cas.link span.
    let mechanism = collected.cas_link_mechanism();
    assert!(
        mechanism.is_some(),
        "cas.link should have a mechanism field: {:?}",
        collected.mechanisms.lock().unwrap()
    );
    // The mechanism should be one of the valid bounded values.
    let m = mechanism.unwrap();
    assert!(
        ["existing", "reflink", "hardlink", "copy"].contains(&m.as_str()),
        "mechanism should be a valid value, got: {m}"
    );
}
