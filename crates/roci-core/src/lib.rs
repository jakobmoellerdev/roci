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
    /// Maximum accepted request-body size; bodies larger are rejected with 413.
    max_body: usize,
    /// Maximum cumulative size of one upload session; exceeding it is 413.
    max_upload: u64,
    /// Effective runtime configuration.
    config: Config,
}

// Manual Clone: `Arc<S>` + `Config` are both cloneable regardless of whether
// `S` is.
impl<S: Storage> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            max_body: self.max_body,
            max_upload: self.max_upload,
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
            max_body: MAX_BODY,
            max_upload: MAX_UPLOAD,
            config,
        }
    }

    /// Override the maximum accepted request-body size (bytes).
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// Override the maximum cumulative upload-session size (bytes).
    pub fn with_max_upload(mut self, max_upload: u64) -> Self {
        self.max_upload = max_upload;
        self
    }

    /// Whether deletion is enabled in the effective configuration.
    pub fn can_delete(&self) -> bool {
        self.config.delete.enabled
    }
}

/// Maximum accepted body size (256 MiB). Chunked uploads split larger blobs.
const MAX_BODY: usize = 256 * 1024 * 1024;

/// Maximum cumulative size of a single blob upload session (5 GiB). A session
/// (chunked or monolithic) exceeding this is rejected with 413 / SIZE_INVALID
/// and dropped, so a client cannot exhaust disk with one open upload.
const MAX_UPLOAD: u64 = 5 * 1024 * 1024 * 1024;

/// Build the registry [`Router`] for the given storage backend.
pub fn build_router<S: Storage>(state: AppState<S>) -> Router {
    Router::new()
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
        )
        // One root span per request; every handler's structured events attach
        // to it (Phase 0 observability spine). OTLP export lands in Phase 4.
        .layer(axum::middleware::from_fn(request_span))
        .with_state(state)
}

/// Middleware: wrap each request in a `tracing` span carrying `method`, `path`,
/// and `otel.kind=server`, then emit one structured completion event with the
/// response `status` on that span.
async fn request_span(req: Request, next: axum::middleware::Next) -> Response {
    use tracing::Instrument as _;
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let span = tracing::info_span!(
        "http.request",
        otel.kind = "server",
        http.method = %method,
        http.path = %path,
    );
    async move {
        let response = next.run(req).await;
        let status = response.status().as_u16();
        tracing::info!(http.status = status, "request completed");
        response
    }
    .instrument(span)
    .await
}
