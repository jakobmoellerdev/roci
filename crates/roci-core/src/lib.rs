//! OCI Distribution Spec HTTP surface (ARCHITECTURE inv. 3, SECURITY inv. 1).
#![forbid(unsafe_code)]

pub mod auth;
mod blobs;
mod conn_close;
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
pub use ratelimit::PeerAddr;
use roci_config::Config;
use roci_storage::{Storage, StorageBackend, StorageError};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Type-erased async readiness check, populated by `build_router` from a
/// concrete `StorageBackend`. The `/readyz` handler calls this.
type ReadyFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), StorageError>> + Send>> + Send + Sync>;

/// Shared handler state.
pub struct AppState<S: Storage> {
    storage: Arc<S>,
    pub config: Config,
    auth: Option<Arc<auth::Auth>>,
    /// Flipped to `true` after startup recovery (`recover()`) completes.
    recovered: Arc<std::sync::atomic::AtomicBool>,
    /// Type-erased storage readiness probe (from StorageBackend::ready).
    ready_fn: ReadyFn,
}

impl<S: Storage> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            config: self.config.clone(),
            auth: self.auth.clone(),
            recovered: Arc::clone(&self.recovered),
            ready_fn: Arc::clone(&self.ready_fn),
        }
    }
}

impl<S: Storage> AppState<S> {
    /// Wrap a storage backend with default size limits and a default config.
    pub fn new(storage: S) -> Self
    where
        S: StorageBackend,
    {
        Self::new_with(storage, Config::default())
    }

    /// Wrap a storage backend with an explicit config.
    pub fn new_with(storage: S, config: Config) -> Self
    where
        S: StorageBackend,
    {
        let st = Arc::new(storage);
        let st2 = Arc::clone(&st);
        Self {
            storage: st,
            config,
            auth: None,
            recovered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ready_fn: Arc::new(move || {
                let s = Arc::clone(&st2);
                Box::pin(async move { s.ready().await })
            }),
        }
    }

    /// Install the auth engine built by [`auth::Auth::from_config`].
    pub fn with_auth(mut self, auth: Option<Arc<auth::Auth>>) -> Self {
        self.auth = auth;
        self
    }

    /// Mark recovery as complete (called after `recover()` finishes).
    pub fn set_recovered(&self) {
        self.recovered
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Replace the `/readyz` storage check (default: `StorageBackend::ready`),
    /// e.g. to gate readiness on a dependency the backend cannot see.
    pub fn with_ready_check<F, Fut>(mut self, check: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), StorageError>> + Send + 'static,
    {
        self.ready_fn = Arc::new(move || Box::pin(check()));
        self
    }

    pub fn auth(&self) -> Option<&Arc<auth::Auth>> {
        self.auth.as_ref()
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
    let per_client = ratelimit::PerClientLimiter::from_config(&state.config.http.rate_limit);

    let mut router = Router::new().route("/v2/", get(routes::get_base)).route(
        "/v2/{*rest}",
        get(routes::dispatch::<S>)
            .head(routes::dispatch::<S>)
            .post(routes::dispatch::<S>)
            .put(routes::dispatch::<S>)
            .patch(routes::dispatch::<S>)
            .delete(routes::dispatch::<S>),
    );

    if let Some(pcl) = per_client {
        router = router.layer(axum::middleware::from_fn_with_state(
            Arc::new(pcl),
            ratelimit::per_client_rate_limit_middleware,
        ));
    }

    if let Some(auth) = state.auth.clone() {
        router = router.layer(axum::middleware::from_fn_with_state(
            auth,
            auth::middleware::authn_middleware,
        ));
    }

    if let Some(rl) = limiter {
        router = router.layer(axum::middleware::from_fn_with_state(
            Arc::new(rl),
            ratelimit::rate_limit_middleware,
        ));
    }

    // Health probes bypass auth/rate-limit layers (merged after them).
    let health_routes = Router::new()
        .route("/livez", get(livez).head(livez))
        .route("/readyz", get(readyz::<S>).head(readyz::<S>))
        .with_state(state.clone());

    router
        .merge(health_routes)
        .layer(axum::middleware::from_fn(
            auth::middleware::early_data_middleware,
        ))
        .layer(axum::middleware::from_fn(request_span))
        .layer(axum::middleware::from_fn(conn_close::close_on_unread_body))
        .with_state(state)
}

/// `GET /livez`: always `200 ok` once the server is listening.
async fn livez() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

/// `GET /readyz`: `200 ok` when startup recovery is done AND the storage
/// backend reports ready; `503 not ready: <reason>` otherwise.
async fn readyz<S: Storage>(
    axum::extract::State(st): axum::extract::State<AppState<S>>,
) -> Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    if !st.recovered.load(std::sync::atomic::Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready: recovery in progress",
        )
            .into_response();
    }
    // Bounded below the kubelet's 3 s probe timeout: a hung backend must read
    // as 503, not as a timed-out probe.
    match tokio::time::timeout(READYZ_PROBE_TIMEOUT, (st.ready_fn)()).await {
        Ok(Ok(())) => (StatusCode::OK, "ok").into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "readiness probe: storage not ready");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "not ready: storage unavailable",
            )
                .into_response()
        }
        Err(_) => {
            tracing::warn!("readiness probe: storage check timed out");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "not ready: storage unavailable",
            )
                .into_response()
        }
    }
}

/// Upper bound on one `/readyz` storage check.
const READYZ_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Classify a request path into a low-cardinality endpoint label for metrics.
fn classify_endpoint(path: &str) -> &'static str {
    if path == "/livez" || path == "/readyz" {
        return "health";
    }
    if path == "/v2/" || path == "/v2" {
        return "base";
    }
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

/// Per-request tracing span with semconv attributes and RED metrics.
async fn request_span(req: Request, next: axum::middleware::Next) -> Response {
    use tracing::Instrument as _;

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let endpoint = classify_endpoint(&path);

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

        if status >= 500 {
            tracing::error!(http.response.status_code = status, "request failed");
        } else if status >= 400 {
            tracing::info!(http.response.status_code = status, "client error");
        } else {
            tracing::info!(http.response.status_code = status, "request completed");
        }

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
        assert_eq!(classify_endpoint("/v2/"), "base", "base /v2/");
        assert_eq!(classify_endpoint("/v2"), "base", "base /v2");
        assert_eq!(classify_endpoint("/healthz"), "other", "healthz");
        assert_eq!(classify_endpoint("/metrics"), "other", "metrics");
        assert_eq!(classify_endpoint("/v2/foo"), "other", "too few segments");
        assert_eq!(
            classify_endpoint("/v2/myrepo/unknown/thing"),
            "other",
            "unknown verb"
        );
    }
}
