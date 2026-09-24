//! roci-core: the OCI Distribution Spec v1.1.1 HTTP surface.
//!
//! Implements the dist-spec endpoint groups end-1 .. end-13 against the
//! [`roci_storage::Storage`] trait. AuthN/AuthZ (when added) is evaluated in a
//! layer *before* these handlers touch storage (ARCHITECTURE.md invariant 3).
#![forbid(unsafe_code)]

mod blobs;
mod error;
mod http_util;
mod listing;
mod manifests;
mod names;
mod ratelimit;
mod routes;
mod uploads;

use axum::extract::Request;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
pub use error::{ApiError, ErrorCode};
pub use names::RepositoryName;
use roci_config::Config;
use roci_storage::Storage;
use std::sync::Arc;

/// Shared handler state.
pub struct AppState<S: Storage> {
    storage: Arc<S>,
    /// Effective runtime configuration.
    pub config: Config,
}

// Manual Clone: `Arc<S>` + `Config` are both cloneable regardless of whether
// `S` is.
impl<S: Storage> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            config: self.config.clone(),
        }
    }
}

impl<S: Storage> AppState<S> {
    /// Wrap a storage backend with default size limits and a default config.
    pub fn new(storage: S) -> Self {
        Self::new_with(storage, Config::default())
    }

    /// Wrap a storage backend with an explicit config.
    pub fn new_with(storage: S, config: Config) -> Self {
        Self {
            storage: Arc::new(storage),
            config,
        }
    }

    /// Maximum accepted request-body size (from `config.limits.max_body`).
    pub(crate) fn max_body(&self) -> usize {
        self.config.limits.max_body
    }

    /// Maximum cumulative upload-session size (from `config.limits.max_upload`).
    pub(crate) fn max_upload(&self) -> u64 {
        self.config.limits.max_upload
    }

    /// Maximum manifest size (from `config.limits.max_manifest`).
    pub(crate) fn max_manifest(&self) -> usize {
        self.config.limits.max_manifest
    }

    /// Maximum page size for list endpoints (from `config.limits.max_page`).
    pub(crate) fn max_page(&self) -> usize {
        self.config.limits.max_page
    }

    /// Whether deletion is enabled in the effective configuration.
    pub fn can_delete(&self) -> bool {
        self.config.delete.enabled
    }
}

/// Build the registry [`Router`] for the given storage backend.
pub fn build_router<S: Storage>(state: AppState<S>) -> Router {
    let limiter = ratelimit::RateLimiter::from_config(&state.config.http.rate_limit);

    let mut router = Router::new()
        .route("/v2/", get(routes::get_base))
        // Repo names may contain slashes; capture the remainder with `*rest`
        // and dispatch on the trailing path grammar.
        .route(
            "/v2/{*rest}",
            get(routes::dispatch::<S>)
                .head(routes::dispatch::<S>)
                .post(routes::dispatch::<S>)
                .put(routes::dispatch::<S>)
                .patch(routes::dispatch::<S>)
                .delete(routes::dispatch::<S>),
        );

    // Rate-limit layer: only installed when enabled (zero overhead otherwise).
    if let Some(rl) = limiter {
        router = router.layer(axum::middleware::from_fn_with_state(
            Arc::new(rl),
            ratelimit::rate_limit_middleware,
        ));
    }

    router
        // One root span per request; every handler's structured events attach
        // to it (Phase 0 observability spine). OTLP export lands in Phase 4.
        .layer(axum::middleware::from_fn(request_span))
        .with_state(state)
}
/// Classify a request path into a low-cardinality endpoint label for metrics.
/// Never the raw path (cardinality discipline — ARCHITECTURE.md §Observability).
fn classify_endpoint(path: &str) -> &'static str {
    // /v2/ base, /v2/<name>/blobs/*, /v2/<name>/manifests/*, etc.
    if path == "/v2/" || path == "/v2" {
        return "base";
    }
    // Walk backwards through segments to find the dist-spec verb.
    if let Some(rest) = path.strip_prefix("/v2/") {
        let segs: Vec<&str> = rest.split('/').collect();
        let n = segs.len();
        if n >= 3
            && segs.get(n.wrapping_sub(3)) == Some(&"blobs")
            && segs.get(n.wrapping_sub(2)) == Some(&"uploads")
        {
            return "uploads";
        }
        if n >= 2
            && segs.get(n.wrapping_sub(2)) == Some(&"blobs")
            && segs.get(n.wrapping_sub(1)) == Some(&"uploads")
        {
            return "uploads";
        }
        if n >= 2 {
            match segs.get(n.wrapping_sub(2)).copied() {
                Some("blobs") => return "blobs",
                Some("manifests") => return "manifests",
                Some("tags") => return "tags",
                Some("referrers") => return "referrers",
                _ => {}
            }
        }
    }
    "other"
}

/// Middleware: wrap each request in a `tracing` span carrying semconv
/// attributes, classify the endpoint for metrics, record duration + errors,
/// and (with `otel`) extract W3C `traceparent` as span parent.
async fn request_span(req: Request, next: axum::middleware::Next) -> Response {
    use tracing::Instrument as _;

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let endpoint = classify_endpoint(&path);

    // With OTel: extract traceparent from request headers and set as parent.
    #[cfg(feature = "otel")]
    let parent_cx = {
        let mut carrier = std::collections::HashMap::new();
        for (k, v) in req.headers() {
            if let Ok(val) = v.to_str() {
                carrier.insert(k.as_str().to_string(), val.to_string());
            }
        }
        opentelemetry::global::get_text_map_propagator(|p| p.extract(&carrier))
    };

    let span = tracing::info_span!(
        "http.request",
        otel.kind = "server",
        http.request.method = %method,
        url.path = %path,
        http.route = %endpoint,
        http.response.status_code = tracing::field::Empty,
        error.r#type = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    );

    #[cfg(feature = "otel")]
    {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        let _ = span.set_parent(parent_cx);
    }

    let start = std::time::Instant::now();
    let method_str = method.as_str().to_string();

    async move {
        let response = next.run(req).await;
        let status = response.status().as_u16();
        let duration = start.elapsed();

        tracing::Span::current().record("http.response.status_code", status);

        // Log + span status based on status class.
        if status >= 500 {
            tracing::error!(http.response.status_code = status, "request failed");
        } else if status >= 400 {
            tracing::info!(http.response.status_code = status, "client error");
        } else {
            tracing::info!(http.response.status_code = status, "request completed");
        }

        // Record RED metrics (no-op in minimal builds).
        roci_telemetry::record_request(endpoint, &method_str, status, duration);

        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_endpoint_base() {
        assert_eq!(classify_endpoint("/v2/"), "base");
        assert_eq!(classify_endpoint("/v2"), "base");
    }

    #[test]
    fn classify_endpoint_known_verbs() {
        assert_eq!(classify_endpoint("/v2/myrepo/blobs/sha256:abc"), "blobs");
        assert_eq!(
            classify_endpoint("/v2/myrepo/manifests/latest"),
            "manifests"
        );
        assert_eq!(classify_endpoint("/v2/myrepo/tags/list"), "tags");
        assert_eq!(
            classify_endpoint("/v2/myrepo/referrers/sha256:abc"),
            "referrers"
        );
    }

    #[test]
    fn classify_endpoint_uploads() {
        assert_eq!(classify_endpoint("/v2/myrepo/blobs/uploads/"), "uploads");
        assert_eq!(
            classify_endpoint("/v2/myrepo/blobs/uploads/some-uuid"),
            "uploads"
        );
    }

    #[test]
    fn classify_endpoint_other() {
        // Non-v2 paths.
        assert_eq!(classify_endpoint("/healthz"), "other");
        assert_eq!(classify_endpoint("/metrics"), "other");
        // v2 with too few segments to match any verb (line 150 branch).
        assert_eq!(classify_endpoint("/v2/foo"), "other");
        // v2 with unknown verb.
        assert_eq!(classify_endpoint("/v2/myrepo/unknown/thing"), "other");
    }
}
