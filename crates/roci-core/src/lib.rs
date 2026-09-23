//! roci-core: the OCI Distribution Spec v1.1.1 HTTP surface.
//!
//! Implements the dist-spec endpoint groups end-1 .. end-13 against the
//! [`roci_storage::Storage`] trait. AuthN/AuthZ (when added) is evaluated in a
//! layer *before* these handlers touch storage (ARCHITECTURE.md invariant 3).
#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use roci_config::Config;
use roci_storage::{digest_of, sha256_of, Digest, Storage, StorageError};

mod error;
mod names;

pub use error::{ApiError, ErrorCode};
pub use names::RepositoryName;

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

/// Build the registry [`Router`] for the given storage backend.
pub fn build_router<S: Storage>(state: AppState<S>) -> Router {
    Router::new()
        .route("/v2/", get(get_base))
        // Repo names may contain slashes; capture the remainder with `*rest`
        // and dispatch on the trailing path grammar.
        .route(
            "/v2/{*rest}",
            get(route_get)
                .head(route_head)
                .post(route_post)
                .put(route_put)
                .patch(route_patch)
                .delete(route_delete),
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

// ---- OCI error envelope --------------------------------------------------

/// Map a storage-layer error to the spec JSON envelope.
fn map_storage_err(e: StorageError) -> Response {
    ApiError::from(e).into_response()
}

// ---- Path parsing --------------------------------------------------------

/// The parsed grammar of a `/v2/<name>/<verb>...` path.
enum Parsed {
    Blob { repo: String, digest: Digest },
    ManifestRef { repo: String, reference: String },
    UploadStart { repo: String },
    UploadSession { repo: String, id: String },
    TagsList { repo: String },
    Referrers { repo: String, digest: Digest },
    Unknown,
}

/// Split `<name>/<tail...>` where the last one or two segments form the verb,
/// **validating** the repository name (and the reference/digest, where the verb
/// carries one) against the dist-spec grammar before any handler runs. An
/// unrecognized path shape yields `Ok(Parsed::Unknown)` (→ 404); a recognized
/// shape with a malformed name/reference/digest yields `Err(ApiError)`.
fn parse_path(rest: &str) -> Result<Parsed, ApiError> {
    let segments: Vec<&str> = rest.split('/').collect();
    let n = segments.len();
    if n < 2 {
        return Ok(Parsed::Unknown);
    }
    // Validate a repository name, surfacing NAME_INVALID.
    let checked_repo = |repo: String| -> Result<String, ApiError> {
        RepositoryName::parse(&repo)?;
        Ok(repo)
    };
    // blobs/uploads/<id?>
    if n >= 3 && segments[n - 3] == "blobs" && segments[n - 2] == "uploads" {
        let repo = checked_repo(segments[..n - 3].join("/"))?;
        let id = segments[n - 1];
        return Ok(if id.is_empty() {
            Parsed::UploadStart { repo }
        } else {
            Parsed::UploadSession {
                repo,
                id: id.to_string(),
            }
        });
    }
    if n >= 2 && segments[n - 2] == "blobs" && segments[n - 1] == "uploads" {
        // trailing slash omitted: `.../blobs/uploads`
        let repo = checked_repo(segments[..n - 2].join("/"))?;
        return Ok(Parsed::UploadStart { repo });
    }
    Ok(match segments[n - 2] {
        "blobs" => {
            let repo = checked_repo(segments[..n - 2].join("/"))?;
            let digest = Digest::parse(segments[n - 1]).map_err(ApiError::from)?;
            Parsed::Blob { repo, digest }
        }
        "manifests" => {
            // The repo name is validated (400 NAME_INVALID); the manifest
            // reference is NOT grammar-rejected here. Per the dist-spec
            // conformance suite, a syntactically-invalid or unknown manifest
            // reference must resolve to 404 MANIFEST_UNKNOWN, not 400 — so the
            // reference flows through and the storage lookup decides.
            let repo = checked_repo(segments[..n - 2].join("/"))?;
            Parsed::ManifestRef {
                repo,
                reference: segments[n - 1].to_string(),
            }
        }
        "tags" if segments[n - 1] == "list" => Parsed::TagsList {
            repo: checked_repo(segments[..n - 2].join("/"))?,
        },
        "referrers" => {
            let repo = checked_repo(segments[..n - 2].join("/"))?;
            let digest = Digest::parse(segments[n - 1]).map_err(ApiError::from)?;
            Parsed::Referrers { repo, digest }
        }
        _ => Parsed::Unknown,
    })
}

// ---- Query params --------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct UploadQuery {
    digest: Option<String>,
    mount: Option<String>,
    from: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct TagsQuery {
    n: Option<usize>,
    last: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ReferrersQuery {
    #[serde(rename = "artifactType")]
    artifact_type: Option<String>,
    n: Option<usize>,
    last: Option<String>,
}

// ---- end-1: base ---------------------------------------------------------

async fn get_base() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        "{}",
    )
        .into_response()
}

// ---- GET dispatch --------------------------------------------------------

async fn route_get<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let parsed = match parse_path(&rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let headers = req.headers();
    match parsed {
        Parsed::Blob { repo, digest } => get_blob(&st, &repo, &digest, false, headers).await,
        Parsed::ManifestRef { repo, reference } => {
            get_manifest(&st, &repo, &reference, false, headers).await
        }
        Parsed::TagsList { repo } => {
            let q: TagsQuery =
                serde_urlencoded::from_str(req.uri().query().unwrap_or("")).unwrap_or_default();
            list_tags(&st, &repo, q).await
        }
        Parsed::Referrers { repo, digest } => {
            let q: ReferrersQuery =
                serde_urlencoded::from_str(req.uri().query().unwrap_or("")).unwrap_or_default();
            referrers(&st, &repo, &digest, q).await
        }
        Parsed::UploadSession { repo, id } => upload_status(&st, &repo, &id).await,
        _ => ApiError::name_unknown().into_response(),
    }
}

async fn route_head<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let parsed = match parse_path(&rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let headers = req.headers();
    match parsed {
        Parsed::Blob { repo, digest } => get_blob(&st, &repo, &digest, true, headers).await,
        Parsed::ManifestRef { repo, reference } => {
            get_manifest(&st, &repo, &reference, true, headers).await
        }
        _ => ApiError::name_unknown().into_response(),
    }
}

async fn route_post<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let query = req.uri().query().unwrap_or("").to_string();
    let parsed = match parse_path(&rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match parsed {
        Parsed::UploadStart { repo } => {
            let q: UploadQuery = serde_urlencoded::from_str(&query).unwrap_or_default();
            start_upload(&st, &repo, q, req).await
        }
        _ => ApiError::name_unknown().into_response(),
    }
}

async fn route_put<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let query = req.uri().query().unwrap_or("").to_string();
    let parsed = match parse_path(&rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match parsed {
        Parsed::UploadSession { repo, id } => {
            let q: UploadQuery = serde_urlencoded::from_str(&query).unwrap_or_default();
            finish_upload(&st, &repo, &id, q, req).await
        }
        Parsed::ManifestRef { repo, reference } => put_manifest(&st, &repo, &reference, req).await,
        _ => ApiError::name_unknown().into_response(),
    }
}

async fn route_patch<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let parsed = match parse_path(&rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match parsed {
        Parsed::UploadSession { repo, id } => patch_upload(&st, &repo, &id, req).await,
        _ => ApiError::name_unknown().into_response(),
    }
}

async fn route_delete<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
) -> Response {
    let parsed = match parse_path(&rest) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    match parsed {
        Parsed::Blob { repo, digest } => delete_blob(&st, &repo, &digest).await,
        Parsed::ManifestRef { repo, reference } => delete_manifest(&st, &repo, &reference).await,
        _ => ApiError::name_unknown().into_response(),
    }
}

// ---- end-2 / end-10: blobs ----------------------------------------------

/// Parsed outcome of a `Range` header against a known content `size`.
enum RangeOutcome {
    /// No usable range: serve the full entity (200).
    Full,
    /// A satisfiable inclusive byte range `[start, end]`.
    Partial { start: u64, end: u64 },
    /// A syntactically valid but unsatisfiable range: 416.
    Unsatisfiable,
}

/// Parse a single-range `bytes=` header (RFC 9110 §14.1.2) against `size`.
/// Multi-range, malformed, or absent headers yield [`RangeOutcome::Full`] so
/// the caller serves the whole entity with 200 (RFC 9110 §14.2).
fn parse_byte_range(headers: &HeaderMap, size: u64) -> RangeOutcome {
    let Some(raw) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return RangeOutcome::Full;
    };
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    // Only single-range requests are supported; a comma (multi-range) or any
    // parse failure falls back to a full response.
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (start, end) = match (start_s.trim(), end_s.trim()) {
        // Suffix range: last N bytes.
        ("", suffix) => {
            let Ok(n) = suffix.parse::<u64>() else {
                return RangeOutcome::Full;
            };
            if n == 0 {
                return RangeOutcome::Unsatisfiable;
            }
            let start = size.saturating_sub(n);
            (start, size - 1)
        }
        // Open-ended: start to end of entity.
        (start, "") => {
            let Ok(start) = start.parse::<u64>() else {
                return RangeOutcome::Full;
            };
            (start, size.saturating_sub(1))
        }
        // Closed range.
        (start, end) => {
            let (Ok(start), Ok(end)) = (start.parse::<u64>(), end.parse::<u64>()) else {
                return RangeOutcome::Full;
            };
            if end < start {
                return RangeOutcome::Full;
            }
            (start, end.min(size.saturating_sub(1)))
        }
    };
    if size == 0 || start >= size {
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Partial { start, end }
}

/// Whether an `If-None-Match` header matches the blob/manifest ETag (the
/// quoted digest). Compares tolerant of surrounding quotes and the `W/` weak
/// prefix, and honors `*` (any current representation).
fn if_none_match_hit(headers: &HeaderMap, digest: &str) -> bool {
    let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    inm.split(',').any(|tag| {
        let tag = tag.trim();
        if tag == "*" {
            return true;
        }
        let tag = tag.strip_prefix("W/").unwrap_or(tag);
        tag.trim_matches('"') == digest
    })
}

async fn get_blob<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    d: &Digest,
    head: bool,
    headers: &HeaderMap,
) -> Response {
    let digest_str = d.as_string();
    // Blobs are content-addressed and therefore immutable; a client holding the
    // digest ETag needs no body (304).
    if if_none_match_hit(headers, &digest_str) {
        return blob_not_modified(&digest_str);
    }
    if head {
        let size = match st.storage.blob_size(repo, d).await {
            Ok(s) => s,
            Err(StorageError::NotFound) => return ApiError::blob_unknown().into_response(),
            Err(e) => return map_storage_err(e),
        };
        let mut resp_headers = blob_headers(&digest_str);
        resp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
        return (StatusCode::OK, resp_headers).into_response();
    }
    // GET: build the (possibly ranged) streamed body. Every IO step funnels its
    // error through `?` into the single match below, so there are no separate
    // unreachable error arms for the infallible-on-a-regular-file seek/stat.
    match blob_get_body(st, repo, d, &digest_str, headers).await {
        Ok(resp) => resp,
        Err(StorageError::NotFound) => ApiError::blob_unknown().into_response(),
        Err(e) => map_storage_err(e),
    }
}

/// Open the blob and produce its GET response — full `200`, ranged `206`, or
/// `416` — streaming the file. All IO errors propagate to the caller's single
/// error mapping (a missing blob is `NotFound`).
async fn blob_get_body<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    d: &Digest,
    digest_str: &str,
    headers: &HeaderMap,
) -> Result<Response, StorageError> {
    let mut file = st.storage.open_blob(repo, d).await?;
    let size = file.metadata().await?.len();
    match parse_byte_range(headers, size) {
        RangeOutcome::Full => {
            let mut resp_headers = blob_headers(digest_str);
            resp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
            let body = Body::from_stream(ReaderStream::new(file));
            Ok((StatusCode::OK, resp_headers, body).into_response())
        }
        RangeOutcome::Partial { start, end } => {
            file.seek(std::io::SeekFrom::Start(start)).await?;
            let len = end - start + 1;
            let mut resp_headers = blob_headers(digest_str);
            resp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            resp_headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{size}")).unwrap(),
            );
            let body = Body::from_stream(ReaderStream::new(file.take(len)));
            Ok((StatusCode::PARTIAL_CONTENT, resp_headers, body).into_response())
        }
        RangeOutcome::Unsatisfiable => {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            resp_headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{size}")).unwrap(),
            );
            Ok((StatusCode::RANGE_NOT_SATISFIABLE, resp_headers).into_response())
        }
    }
}

/// Common headers for a blob GET/HEAD 200/206 response: digest, octet-stream
/// content type, range support, and immutable-cache validators.
fn blob_headers(digest_str: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "docker-content-digest",
        HeaderValue::from_str(digest_str).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{digest_str}\"")).unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=31536000, immutable"),
    );
    headers
}

/// A `304 Not Modified` for an immutable blob, carrying its cache validators.
fn blob_not_modified(digest_str: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{digest_str}\"")).unwrap(),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=31536000, immutable"),
    );
    (StatusCode::NOT_MODIFIED, headers).into_response()
}

async fn delete_blob<S: Storage>(st: &AppState<S>, repo: &str, d: &Digest) -> Response {
    if !st.can_delete() {
        return ApiError::unsupported().into_response();
    }
    match st.storage.delete_blob(repo, d).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(StorageError::NotFound) => ApiError::blob_unknown().into_response(),
        Err(e) => map_storage_err(e),
    }
}

// ---- end-3 / end-7 / end-9: manifests ------------------------------------

async fn get_manifest<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    reference: &str,
    head: bool,
    headers: &HeaderMap,
) -> Response {
    // A digest reference names immutable content; a tag can be repointed. The
    // `Accept` header is advisory — the stored media type is always returned
    // (dist-spec: the registry serves the manifest's real Content-Type).
    let by_digest = reference.contains(':');
    match st.storage.get_manifest(repo, reference).await {
        Ok(m) => {
            let digest_str = m.digest.as_string();
            // Conditional request: the ETag is the manifest digest. For a tag,
            // a matching digest means the tag still resolves to the same content.
            if if_none_match_hit(headers, &digest_str) {
                return manifest_not_modified(&digest_str, by_digest);
            }
            let mut resp = HeaderMap::new();
            resp.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&m.media_type).unwrap(),
            );
            resp.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(m.bytes.len() as u64),
            );
            resp.insert(
                "docker-content-digest",
                HeaderValue::from_str(&digest_str).unwrap(),
            );
            resp.insert(
                header::ETAG,
                HeaderValue::from_str(&format!("\"{digest_str}\"")).unwrap(),
            );
            resp.insert(header::CACHE_CONTROL, manifest_cache_control(by_digest));
            if head {
                (StatusCode::OK, resp).into_response()
            } else {
                (StatusCode::OK, resp, m.bytes).into_response()
            }
        }
        Err(StorageError::NotFound) => ApiError::manifest_unknown().into_response(),
        Err(e) => map_storage_err(e),
    }
}

/// Cache-Control for a manifest read: by-digest is immutable; by-tag must be
/// revalidated (`no-cache`) since a tag can be repointed.
fn manifest_cache_control(by_digest: bool) -> HeaderValue {
    if by_digest {
        HeaderValue::from_static("max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("no-cache")
    }
}

/// A `304 Not Modified` for a manifest, carrying its ETag and the cache-control
/// appropriate to how it was addressed.
fn manifest_not_modified(digest_str: &str, by_digest: bool) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{digest_str}\"")).unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, manifest_cache_control(by_digest));
    (StatusCode::NOT_MODIFIED, headers).into_response()
}

async fn put_manifest<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    reference: &str,
    req: Request,
) -> Response {
    let media_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();
    // Bound the manifest body by the smaller of the configured request-body
    // limit and the fixed 4 MiB manifest cap. Exceeding the configured limit is
    // a 413 (payload too large); exceeding only the fixed cap is MANIFEST_INVALID.
    let manifest_limit = st.max_body.min(MAX_MANIFEST);
    let body = match read_body_limited(req, manifest_limit).await {
        Ok(b) => b,
        Err(resp) if st.max_body <= MAX_MANIFEST => return *resp,
        Err(_) => {
            return ApiError::manifest_invalid("manifest exceeds 4 MiB size cap").into_response()
        }
    };
    // Reject pathologically nested JSON before handing bytes to serde_json
    // (bounded-input guard; SECURITY.md inv. 14). A non-JSON body has depth 0.
    if json_depth_exceeds(&body, MAX_JSON_DEPTH) {
        return ApiError::manifest_invalid("manifest JSON nesting too deep").into_response();
    }
    // A digest reference must match the content. Compute the content digest
    // with the *reference's* algorithm (sha256/sha512) so a sha512 reference is
    // honored; a tagged push defaults to sha256. Compare constant-time and
    // parse the reference so uppercase hex still matches.
    let (digest, tag) = if reference.contains(':') {
        match Digest::parse(reference) {
            Ok(ref_digest) => {
                let content = digest_of(&body, ref_digest.algorithm());
                if content.ct_eq(&ref_digest) {
                    (content, None)
                } else {
                    return ApiError::digest_invalid("manifest digest does not match reference")
                        .into_response();
                }
            }
            Err(e) => return map_storage_err(e),
        }
    } else {
        (sha256_of(&body), Some(reference))
    };
    // Parse the manifest to extract subject/artifactType/annotations for the
    // referrers index (best-effort; a non-JSON body simply has no subject).
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let subject_digest = parsed
        .get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|d| d.as_str())
        .and_then(|d| Digest::parse(d).ok());

    // Content-Type ↔ manifest `mediaType` agreement (CVE-2021-41190): when the
    // body carries a top-level string `mediaType`, it MUST equal the request
    // Content-Type (compared on the bare type, `;`-params stripped). A body with
    // no `mediaType` (image index / some artifacts) skips the check — never
    // inferred. A mismatch is a malformed manifest.
    if let Some(mt) = parsed.get("mediaType") {
        // A present `mediaType` must be a string; a non-string is malformed and
        // must not silently bypass the agreement check (CVE-2021-41190).
        let Some(body_mt) = mt.as_str() else {
            return ApiError::manifest_invalid("manifest mediaType is not a string")
                .into_response();
        };
        let bare = |s: &str| s.split(';').next().unwrap_or(s).trim().to_string();
        if bare(&media_type) != bare(body_mt) {
            return ApiError::manifest_invalid("Content-Type does not match manifest mediaType")
                .into_response();
        }
    }

    // Referenced-blob existence (MANIFEST_BLOB_UNKNOWN): for an image manifest,
    // every blob it references (its `config` and each `layers` entry) MUST be
    // present. A descriptor that is present but malformed (not an object, or no
    // string `digest`) is a bad manifest → MANIFEST_INVALID.
    let mut referenced: Vec<Digest> = Vec::new();
    // `config`, when present, must be an object carrying a valid string digest.
    if let Some(cfg) = parsed.get("config") {
        match descriptor_digest_str(cfg) {
            Some(s) => match Digest::parse(s) {
                Ok(d) => referenced.push(d),
                Err(_) => {
                    return ApiError::manifest_invalid("config digest is malformed").into_response()
                }
            },
            None => {
                return ApiError::manifest_invalid("config descriptor is malformed").into_response()
            }
        }
    }
    // A present `layers` must be an array; a non-array is a malformed manifest
    // (not silently skipped). Each entry must be a descriptor with a digest.
    if let Some(layers) = parsed.get("layers") {
        let Some(layers) = layers.as_array() else {
            return ApiError::manifest_invalid("manifest layers is not an array").into_response();
        };
        for layer in layers {
            match descriptor_digest_str(layer) {
                Some(s) => match Digest::parse(s) {
                    Ok(d) => referenced.push(d),
                    Err(_) => {
                        return ApiError::manifest_invalid("layer digest is malformed")
                            .into_response()
                    }
                },
                None => {
                    return ApiError::manifest_invalid("layer descriptor is malformed")
                        .into_response()
                }
            }
        }
    }
    for d in &referenced {
        match st.storage.blob_exists(repo, d).await {
            Ok(true) => {}
            Ok(false) => {
                return ApiError::manifest_blob_unknown(format!(
                    "referenced blob {} is not present",
                    d.as_string()
                ))
                .into_response()
            }
            Err(e) => return map_storage_err(e),
        }
    }

    if let Err(e) = st
        .storage
        .put_manifest(repo, tag, &digest, &media_type, &body)
        .await
    {
        return map_storage_err(e);
    }

    // Record the reverse edges blob→manifest so a future GC (Phase 3) can
    // reclaim an object once its last referencing manifest is deleted. Beyond
    // the config+layers checked above, also record an image index's child
    // `manifests[*]` and a `subject` descriptor — those are CAS objects a GC
    // must treat as reachable (their existence is NOT enforced here: a subject
    // may reference an absent manifest per spec, and an index child may be
    // pushed later). The backref index is a derived, rebuildable-from-the-layout
    // cache (never the source of truth), so a failed append must not fail an
    // otherwise-valid push; Phase 3 GC rebuilds/verifies before consuming it.
    let mut edges = referenced.clone();
    if let Some(children) = parsed.get("manifests").and_then(|v| v.as_array()) {
        for child in children {
            if let Some(d) = descriptor_digest_str(child).and_then(|s| Digest::parse(s).ok()) {
                edges.push(d);
            }
        }
    }
    if let Some(subject) = subject_digest.as_ref() {
        edges.push(subject.clone());
    }
    if !edges.is_empty() {
        let _ = st.storage.record_backrefs(repo, &digest, &edges).await;
    }

    if let Some(subject) = subject_digest.as_ref() {
        // Build the referrer descriptor per the referrers-index shape: the
        // referring manifest's descriptor, carrying its artifactType and
        // top-level annotations.
        let mut descriptor = serde_json::Map::new();
        descriptor.insert(
            "mediaType".into(),
            serde_json::Value::String(media_type.clone()),
        );
        descriptor.insert(
            "digest".into(),
            serde_json::Value::String(digest.as_string()),
        );
        descriptor.insert("size".into(), serde_json::Value::Number(body.len().into()));
        // artifactType falls back to the config mediaType when absent (OCI rule).
        let artifact_type = parsed
            .get("artifactType")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                parsed
                    .get("config")
                    .and_then(|c| c.get("mediaType"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            });
        if let Some(at) = artifact_type {
            descriptor.insert("artifactType".into(), serde_json::Value::String(at));
        }
        if let Some(ann) = parsed.get("annotations") {
            descriptor.insert("annotations".into(), ann.clone());
        }
        let descriptor_bytes =
            serde_json::to_vec(&serde_json::Value::Object(descriptor)).unwrap_or_default();
        let _ = st
            .storage
            .add_referrer(repo, subject, &digest, &descriptor_bytes)
            .await;
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/v2/{repo}/manifests/{}", digest.as_string())).unwrap(),
    );
    headers.insert(
        "docker-content-digest",
        HeaderValue::from_str(&digest.as_string()).unwrap(),
    );
    if let Some(subject) = subject_digest.as_ref() {
        headers.insert(
            "oci-subject",
            HeaderValue::from_str(&subject.as_string()).unwrap(),
        );
    }
    (StatusCode::CREATED, headers).into_response()
}

async fn delete_manifest<S: Storage>(st: &AppState<S>, repo: &str, reference: &str) -> Response {
    if !st.can_delete() {
        return ApiError::unsupported().into_response();
    }
    // Resolve tag → digest first so tag deletions work too. A `:`-form
    // reference is a digest (grammar checked by Digest::parse → 400 on a
    // malformed digest); otherwise it is a tag resolved via storage.
    let d = if reference.contains(':') {
        match Digest::parse(reference) {
            Ok(d) => d,
            Err(e) => return map_storage_err(e),
        }
    } else {
        match st.storage.get_manifest(repo, reference).await {
            Ok(m) => m.digest,
            Err(StorageError::NotFound) => return ApiError::manifest_unknown().into_response(),
            Err(e) => return map_storage_err(e),
        }
    };
    match st.storage.delete_manifest(repo, &d).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(StorageError::NotFound) => ApiError::manifest_unknown().into_response(),
        Err(e) => map_storage_err(e),
    }
}

// ---- end-4 / end-5 / end-6 / end-11 / end-13: uploads --------------------

fn upload_location(repo: &str, id: &str) -> String {
    format!("/v2/{repo}/blobs/uploads/{id}")
}

async fn start_upload<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    q: UploadQuery,
    req: Request,
) -> Response {
    // end-11: cross-repository mount.
    if let (Some(mount), Some(from)) = (q.mount.as_ref(), q.from.as_ref()) {
        if let Ok(d) = Digest::parse(mount) {
            // Promote via a filesystem link (copy-free on one filesystem); no
            // blob bytes pass through memory. `Ok(false)` (source absent) or an
            // error falls through to a normal upload session.
            if let Ok(true) = st.storage.mount_blob(from, repo, &d).await {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::LOCATION,
                    HeaderValue::from_str(&format!("/v2/{repo}/blobs/{}", d.as_string())).unwrap(),
                );
                headers.insert(
                    "docker-content-digest",
                    HeaderValue::from_str(&d.as_string()).unwrap(),
                );
                return (StatusCode::CREATED, headers).into_response();
            }
        }
        // Fall through to a normal upload session if the mount source is absent.
    }

    // end-4b: monolithic upload — the whole blob is in this request, so store it
    // directly (put_blob verifies the digest); no session is needed.
    if let Some(digest) = q.digest {
        let d = match Digest::parse(&digest) {
            Ok(d) => d,
            Err(e) => return map_storage_err(e),
        };
        let body = match read_body_limited(req, st.max_body).await {
            Ok(b) => b,
            Err(resp) => return *resp,
        };
        // A monolithic body is a complete upload, so the per-session cap applies
        // here too (e.g. when max_upload is configured below max_body).
        if body.len() as u64 > st.max_upload {
            return ApiError::payload_too_large("upload exceeds maximum blob size").into_response();
        }
        return match st.storage.put_blob(repo, &d, &body).await {
            Ok(()) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::LOCATION,
                    HeaderValue::from_str(&format!("/v2/{repo}/blobs/{}", d.as_string())).unwrap(),
                );
                headers.insert(
                    "docker-content-digest",
                    HeaderValue::from_str(&d.as_string()).unwrap(),
                );
                (StatusCode::CREATED, headers).into_response()
            }
            Err(e) => map_storage_err(e),
        };
    }

    // end-4a: begin a chunked session.
    let id = match st.storage.begin_upload(repo).await {
        Ok(id) => id,
        Err(e) => return map_storage_err(e),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&upload_location(repo, &id)).unwrap(),
    );
    headers.insert("range", HeaderValue::from_static("0-0"));
    headers.insert("docker-upload-uuid", HeaderValue::from_str(&id).unwrap());
    (StatusCode::ACCEPTED, headers).into_response()
}

async fn patch_upload<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    id: &str,
    req: Request,
) -> Response {
    // Parse a Content-Range start offset, if supplied; the storage layer
    // enforces it against the current size *atomically under the session lock*
    // (a pre-check here would race two concurrent PATCHes with the same range).
    let range_start = req
        .headers()
        .get(header::CONTENT_RANGE)
        .or_else(|| req.headers().get("content-range"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split('-').next())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let body = match read_body_limited(req, st.max_body).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    let total = match st.storage.append_upload(repo, id, &body, range_start).await {
        Ok(t) => t,
        // The atomic under-lock offset check rejects a concurrent/duplicate
        // chunk the pre-check above raced past → 416 with the current range.
        Err(StorageError::RangeNotSatisfiable { expected, .. }) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::LOCATION,
                HeaderValue::from_str(&upload_location(repo, id)).unwrap(),
            );
            headers.insert(
                "range",
                HeaderValue::from_str(&format!("0-{}", expected.saturating_sub(1))).unwrap(),
            );
            return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
        }
        Err(e) => return map_storage_err(e),
    };
    // Reject a session whose cumulative size exceeds the per-upload cap: drop
    // the staging file and return 413 / SIZE_INVALID so a client cannot exhaust
    // disk with one open upload.
    if total > st.max_upload {
        let _ = st.storage.abort_upload(repo, id).await;
        return ApiError::payload_too_large("upload exceeds maximum blob size").into_response();
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&upload_location(repo, id)).unwrap(),
    );
    headers.insert(
        "range",
        HeaderValue::from_str(&format!("0-{}", total.saturating_sub(1))).unwrap(),
    );
    headers.insert("docker-upload-uuid", HeaderValue::from_str(id).unwrap());
    (StatusCode::ACCEPTED, headers).into_response()
}

async fn finish_upload<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    id: &str,
    q: UploadQuery,
    req: Request,
) -> Response {
    let digest = match q.digest {
        Some(d) => d,
        None => {
            return ApiError::digest_invalid("missing digest on upload completion").into_response()
        }
    };
    let d = match Digest::parse(&digest) {
        Ok(d) => d,
        Err(e) => return map_storage_err(e),
    };
    let body = match read_body_limited(req, st.max_body).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    // Hand the trailing body to finish_upload so the append and the
    // verify+promote happen under one session-lock hold — a concurrent PATCH
    // cannot inject bytes between them. The per-session cap is enforced there.
    match st
        .storage
        .finish_upload(repo, id, &d, st.max_upload, &body)
        .await
    {
        Ok(()) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::LOCATION,
                HeaderValue::from_str(&format!("/v2/{repo}/blobs/{}", d.as_string())).unwrap(),
            );
            headers.insert(
                "docker-content-digest",
                HeaderValue::from_str(&d.as_string()).unwrap(),
            );
            (StatusCode::CREATED, headers).into_response()
        }
        Err(e) => map_storage_err(e),
    }
}

async fn upload_status<S: Storage>(st: &AppState<S>, repo: &str, id: &str) -> Response {
    match st.storage.upload_size(repo, id).await {
        Ok(total) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::LOCATION,
                HeaderValue::from_str(&upload_location(repo, id)).unwrap(),
            );
            headers.insert(
                "range",
                HeaderValue::from_str(&format!("0-{}", total.saturating_sub(1))).unwrap(),
            );
            headers.insert("docker-upload-uuid", HeaderValue::from_str(id).unwrap());
            (StatusCode::NO_CONTENT, headers).into_response()
        }
        Err(e) => map_storage_err(e),
    }
}

// ---- end-8: tag listing --------------------------------------------------

async fn list_tags<S: Storage>(st: &AppState<S>, repo: &str, q: TagsQuery) -> Response {
    let mut tags = match st.storage.list_tags(repo).await {
        Ok(t) => t,
        Err(e) => return map_storage_err(e),
    };
    if let Some(last) = q.last.as_ref() {
        if let Some(pos) = tags.iter().position(|t| t == last) {
            tags = tags.split_off(pos + 1);
        }
    }
    // Clamp the requested page size to the server-side cap (SECURITY inv. 14).
    let limit = q.n.map(|n| n.min(MAX_PAGE)).unwrap_or(MAX_PAGE);
    let total_len = tags.len();
    tags.truncate(limit);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // Pagination (dist-spec end-8): when tags remain past this page, advertise
    // the next page with an RFC 5988 `Link` whose cursor is the last tag served.
    if total_len > tags.len() && limit > 0 {
        let cursor = tags.last().cloned().unwrap_or_default();
        let link = format!(
            "</v2/{}/tags/list?n={}&last={}>; rel=\"next\"",
            repo, limit, cursor
        );
        headers.insert(header::LINK, HeaderValue::from_str(&link).unwrap());
    }
    let body = serde_json::json!({ "name": repo, "tags": tags });
    (StatusCode::OK, headers, body.to_string()).into_response()
}

// ---- end-12: referrers ---------------------------------------------------

async fn referrers<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    subject: &Digest,
    q: ReferrersQuery,
) -> Response {
    // Referrers for a subject are returned even if the subject manifest itself
    // is absent; a missing index is simply an empty list.
    let raw = st
        .storage
        .list_referrers(repo, subject)
        .await
        .unwrap_or_default();
    let limit = q.n.map(|n| n.min(MAX_PAGE)).unwrap_or(MAX_PAGE);
    let filter = q.artifact_type.as_deref();
    // Stream the (stable, insertion-ordered) referrer list: skip through the
    // `last` cursor, apply the artifactType filter, and stop after `limit + 1`
    // matches — so parse work is bounded by the page, never by the whole
    // referrer set (GHSA-259w-8hf6-59bj amplification class), and every page
    // stays reachable via the cursor.
    let mut past_cursor = q.last.is_none();
    let mut manifests: Vec<serde_json::Value> = Vec::with_capacity(limit.min(64) + 1);
    for bytes in raw {
        let Ok(m) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let digest = m.get("digest").and_then(|v| v.as_str());
        if !past_cursor {
            past_cursor = digest == q.last.as_deref();
            continue;
        }
        if let Some(f) = filter {
            if m.get("artifactType").and_then(|v| v.as_str()) != Some(f) {
                continue;
            }
        }
        manifests.push(m);
        if manifests.len() > limit {
            break;
        }
    }
    let had_more = manifests.len() > limit;
    manifests.truncate(limit);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );
    // end-12b: advertise the applied filter; the response varies by query.
    if filter.is_some() {
        headers.insert(
            "oci-filters-applied",
            HeaderValue::from_static("artifactType"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Accept"));
    }
    // RFC 5988 `Link` to the next page when this one is truncated.
    if had_more && limit > 0 {
        let last_digest = manifests
            .last()
            .and_then(|m| m.get("digest").and_then(|v| v.as_str()))
            .unwrap_or_default();
        let mut link = format!(
            "</v2/{}/referrers/{}?n={}&last={}",
            repo,
            subject.as_string(),
            limit,
            last_digest
        );
        if let Some(f) = filter {
            link.push_str("&artifactType=");
            link.push_str(&f.replace('+', "%2B"));
        }
        link.push_str(">; rel=\"next\"");
        if let Ok(v) = HeaderValue::from_str(&link) {
            headers.insert(header::LINK, v);
        }
    }

    let body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests
    });
    (StatusCode::OK, headers, body.to_string()).into_response()
}

// ---- body helper ---------------------------------------------------------

/// Read a request body, rejecting anything larger than `limit`.
async fn read_body_limited(req: Request, limit: usize) -> Result<Vec<u8>, Box<Response>> {
    use axum::body::to_bytes;
    let body = req.into_body();
    match to_bytes(body, limit).await {
        Ok(b) => Ok(b.to_vec()),
        Err(_) => Err(Box::new(
            ApiError::payload_too_large("request body too large").into_response(),
        )),
    }
}

/// Maximum accepted body size (256 MiB). Chunked uploads split larger blobs.
const MAX_BODY: usize = 256 * 1024 * 1024;

/// Maximum accepted manifest size (4 MiB) — bounded-input guard (PLAN Phase 0).
const MAX_MANIFEST: usize = 4 * 1024 * 1024;

/// Maximum cumulative size of a single blob upload session (5 GiB). A session
/// (chunked or monolithic) exceeding this is rejected with 413 / SIZE_INVALID
/// and dropped, so a client cannot exhaust disk with one open upload.
const MAX_UPLOAD: u64 = 5 * 1024 * 1024 * 1024;

/// Maximum JSON nesting depth accepted in a manifest body.
const MAX_JSON_DEPTH: usize = 32;

/// Maximum page size for list endpoints (tags/referrers); server-side cap.
const MAX_PAGE: usize = 1000;

/// The `digest` string of an OCI descriptor: `Some(&str)` only when `value` is
/// a JSON object carrying a string `digest`. A non-object descriptor, or one
/// missing a string `digest`, yields `None` — the caller treats that as a
/// malformed descriptor. A descriptor field that is entirely absent is handled
/// by the caller before calling this (an omitted `config`/`layers` is legal).
fn descriptor_digest_str(value: &serde_json::Value) -> Option<&str> {
    value.as_object()?.get("digest")?.as_str()
}

/// Returns true if `bytes` contains JSON bracket/brace nesting deeper than
/// `max`. A cheap, allocation-free pre-scan that treats string literals
/// (skipping escaped quotes) as opaque so `{`/`[` inside strings don't count.
/// Non-JSON input never exceeds the limit.
fn json_depth_exceeds(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use http_body_util::BodyExt;
    use roci_storage::FsStorage;
    use tower::ServiceExt;

    fn app() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        (build_router(AppState::new(storage)), dir)
    }

    #[tokio::test]
    async fn base_endpoint_ok() {
        let (app, _d) = app();
        let resp = app
            .oneshot(HttpRequest::get("/v2/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn monolithic_push_then_pull_blob() {
        let (app, _d) = app();
        let data = b"layer-bytes";
        let d = sha256_of(data);
        // end-4b monolithic upload.
        let uri = format!("/v2/myorg/app/blobs/uploads/?digest={}", d.as_string());
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post(&uri)
                    .body(Body::from(data.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        // end-2 pull.
        let get = format!("/v2/myorg/app/blobs/{}", d.as_string());
        let resp = app
            .oneshot(HttpRequest::get(&get).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], data);
    }

    #[tokio::test]
    async fn chunked_upload_and_manifest_tag_flow() {
        let (app, _d) = app();
        // Begin session (end-4a).
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // PATCH a chunk (end-5).
        let resp = app
            .clone()
            .oneshot(HttpRequest::patch(&loc).body(Body::from("hello")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // PUT to finalize (end-6).
        let d = sha256_of(b"hello");
        let put_uri = format!("{loc}?digest={}", d.as_string());
        let resp = app
            .clone()
            .oneshot(HttpRequest::put(&put_uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // PUT a manifest by tag (end-7), then resolve + list (end-3, end-8).
        let manifest =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        let mdigest = sha256_of(manifest);
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::put("/v2/r/manifests/v1")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(manifest.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers()
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            mdigest.as_string()
        );

        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/v2/r/tags/list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["tags"], serde_json::json!(["v1"]));

        // DELETE the manifest (end-9).
        let resp = app
            .oneshot(
                HttpRequest::delete("/v2/r/manifests/v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn unknown_blob_is_404() {
        let (app, _d) = app();
        let d = sha256_of(b"absent");
        let uri = format!("/v2/r/blobs/{}", d.as_string());
        let resp = app
            .oneshot(HttpRequest::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn out_of_order_chunk_is_416() {
        let (app, _d) = app();
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // A chunk claiming to start at offset 5 while the session is empty is rejected.
        let resp = app
            .oneshot(
                HttpRequest::patch(&loc)
                    .header(header::CONTENT_RANGE, "5-9")
                    .body(Body::from("hello"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[tokio::test]
    async fn subject_manifest_appears_in_referrers() {
        let (app, _d) = app();
        let subject = sha256_of(b"the-subject");
        // A referring manifest carrying a `subject` and `artifactType`.
        let referrer = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.example.sig",
            "subject": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": subject.as_string(), "size": 11 },
            "annotations": { "org.opencontainers.image.title": "sig" }
        });
        let body = serde_json::to_vec(&referrer).unwrap();
        let rdigest = sha256_of(&body);
        let put = app
            .clone()
            .oneshot(
                HttpRequest::put(format!("/v2/r/manifests/{}", rdigest.as_string()))
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::CREATED);
        assert_eq!(
            put.headers().get("oci-subject").unwrap().to_str().unwrap(),
            subject.as_string()
        );

        // The referrers index for the subject lists exactly this manifest.
        let get = app
            .clone()
            .oneshot(
                HttpRequest::get(format!("/v2/r/referrers/{}", subject.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            get.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/vnd.oci.image.index.v1+json"
        );
        let idx: serde_json::Value =
            serde_json::from_slice(&get.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(idx["manifests"].as_array().unwrap().len(), 1);
        assert_eq!(idx["manifests"][0]["digest"], rdigest.as_string());
        assert_eq!(
            idx["manifests"][0]["artifactType"],
            "application/vnd.example.sig"
        );

        // Filtering by a non-matching artifactType yields an empty, filter-applied index.
        let filtered = app
            .oneshot(
                HttpRequest::get(format!(
                    "/v2/r/referrers/{}?artifactType=application/vnd.other",
                    subject.as_string()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            filtered
                .headers()
                .get("oci-filters-applied")
                .unwrap()
                .to_str()
                .unwrap(),
            "artifactType"
        );
        let idx: serde_json::Value =
            serde_json::from_slice(&filtered.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(idx["manifests"].as_array().unwrap().len(), 0);
    }

    // Helper returning the storage handle too, for direct seeding / IO-error injection.
    fn app_with_storage() -> (Router, FsStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        (build_router(AppState::new(storage.clone())), storage, dir)
    }

    async fn status_of(app: &Router, req: HttpRequest<Body>) -> StatusCode {
        app.clone().oneshot(req).await.unwrap().status()
    }

    /// Read a response body as a JSON value (for asserting the error envelope).
    async fn body_json_of(app: &Router, req: HttpRequest<Body>) -> serde_json::Value {
        let resp = app.clone().oneshot(req).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn malformed_name_and_reference_rejected_before_handler() {
        let (app, _d) = app();
        // Uppercase repo name → NAME_INVALID (400), before any storage access.
        let v = body_json_of(
            &app,
            HttpRequest::get("/v2/Foo/manifests/tag")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "NAME_INVALID");
        // Path-traversal repo component → NAME_INVALID.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::get("/v2/a/../b/manifests/t")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        // A syntactically-invalid manifest reference is NOT a 400 — per the
        // dist-spec conformance suite it resolves to 404 MANIFEST_UNKNOWN
        // (matches the suite's `.INVALID_MANIFEST_NAME` nonexistent-manifest
        // case). Only the repository name is grammar-rejected (above).
        let v = body_json_of(
            &app,
            HttpRequest::get("/v2/ok/manifests/.INVALID_MANIFEST_NAME")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    #[tokio::test]
    async fn non_allowlisted_digest_rejected() {
        let (app, _d) = app();
        let v = body_json_of(
            &app,
            HttpRequest::get("/v2/ok/blobs/sha1:deadbeef")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "DIGEST_INVALID");
    }

    #[tokio::test]
    async fn manifest_over_fixed_cap_is_manifest_invalid() {
        // Default app (256 MiB body limit); a manifest larger than the fixed
        // 4 MiB cap → 400 MANIFEST_INVALID (distinct from the configured-limit
        // 413 path).
        let (app, _d) = app();
        let over = Body::from(vec![b'x'; MAX_MANIFEST + 1]);
        let resp = app
            .oneshot(
                HttpRequest::put("/v2/r/manifests/t")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(over)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn sha512_blob_and_manifest_roundtrip() {
        // The wire allowlist advertises sha512; a sha512 monolithic blob push
        // and a sha512-referenced manifest push must both succeed (regression
        // for the sha256-only hashing bug).
        let (app, _d) = app();
        let blob = b"sha512-payload";
        let bd = roci_storage::digest_of(blob, "sha512");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", bd.as_string()))
                    .body(Body::from(blob.to_vec()))
                    .unwrap()
            )
            .await,
            StatusCode::CREATED
        );
        let m = br#"{"schemaVersion":2}"#;
        let md = roci_storage::digest_of(m, "sha512");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put(format!("/v2/r/manifests/{}", md.as_string()))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(m.to_vec()))
                    .unwrap()
            )
            .await,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn manifest_json_depth_capped() {
        let (app, _d) = app();
        // 40 levels of nested arrays exceeds MAX_JSON_DEPTH (32) → MANIFEST_INVALID.
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/ok/manifests/t")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(deep))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    }

    #[tokio::test]
    async fn missing_blob_is_blob_unknown() {
        let (app, _d) = app();
        let d = sha256_of(b"absent");
        let v = body_json_of(
            &app,
            HttpRequest::get(format!("/v2/ok/blobs/{}", d.as_string()))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    #[tokio::test]
    async fn tags_list_page_size_is_capped() {
        let (app, storage, _d) = app_with_storage();
        // Push more tags than a small requested `n`; the response honors `n`
        // up to the server cap.
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        for t in ["a", "b", "c", "d"] {
            storage
                .put_manifest("r", Some(t), &d, "application/json", body)
                .await
                .unwrap();
        }
        let v = body_json_of(
            &app,
            HttpRequest::get("/v2/r/tags/list?n=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(v["tags"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn delete_manifest_by_tag_io_error_maps_to_500() {
        // `<repo>/index.json` as a directory makes tag→digest resolution fail
        // with a non-NotFound IO error (read_index), exercising the Io arm on
        // the delete-by-tag path.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("r").join("index.json")).unwrap();
        let app = build_router(AppState::new(storage));
        let resp = app
            .oneshot(
                HttpRequest::delete("/v2/r/manifests/t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn put_and_patch_to_invalid_name_rejected() {
        // route_put / route_patch validate the name before dispatch.
        let (app, _d) = app();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put("/v2/BAD/manifests/t")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(
                &app,
                HttpRequest::patch("/v2/BAD/blobs/uploads/x")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn delete_blob_io_error_maps_to_500() {
        // Make `<repo>/blobs/<alg>/<hex>` a directory so remove_file yields a
        // non-NotFound IO error, exercising delete_blob's Io → 500 arm.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"x");
        let blob_dir = dir
            .path()
            .join("r")
            .join("blobs")
            .join("sha256")
            .join(hex_of(&d));
        std::fs::create_dir_all(&blob_dir).unwrap();
        let app = build_router(AppState::new(storage));
        let resp = app
            .oneshot(
                HttpRequest::delete(format!("/v2/r/blobs/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn manifest_with_escaped_quote_accepted() {
        // A backslash-escaped quote inside a JSON string exercises the escape
        // branch of json_depth_exceeds; the manifest is well-formed and stored.
        let (app, _d) = app();
        let body = br#"{"schemaVersion":2,"annotations":{"k":"a\"b"}}"#;
        let d = sha256_of(body);
        let resp = app
            .oneshot(
                HttpRequest::put("/v2/ok/manifests/t")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let _ = d;
    }

    #[tokio::test]
    async fn head_blob_and_manifest() {
        let (app, storage, _d) = app_with_storage();
        let data = b"blobdata";
        let d = sha256_of(data);
        storage.put_blob("r", &d, data).await.unwrap();
        // HEAD blob → 200 with content-length + digest, no body.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::head(format!("/v2/r/blobs/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            d.as_string()
        );
        // HEAD manifest.
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        storage
            .put_manifest(
                "r",
                Some("t"),
                &md,
                "application/vnd.oci.image.manifest.v1+json",
                m,
            )
            .await
            .unwrap();
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::head("/v2/r/manifests/t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // HEAD absent blob/manifest → 404.
        let absent = sha256_of(b"absent");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::head(format!("/v2/r/blobs/{}", absent.as_string()))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_of(
                &app,
                HttpRequest::head("/v2/r/manifests/nope")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn unsupported_paths_for_every_method() {
        let (app, _d) = app();
        // parse_path → Unknown: too few segments, and an unknown verb.
        for path in ["/v2/onlyone", "/v2/repo/bogusverb/x"] {
            assert_eq!(
                status_of(&app, HttpRequest::get(path).body(Body::empty()).unwrap()).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&app, HttpRequest::head(path).body(Body::empty()).unwrap()).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&app, HttpRequest::post(path).body(Body::empty()).unwrap()).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&app, HttpRequest::put(path).body(Body::empty()).unwrap()).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&app, HttpRequest::patch(path).body(Body::empty()).unwrap()).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&app, HttpRequest::delete(path).body(Body::empty()).unwrap()).await,
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn delete_blob_success_and_absent() {
        let (app, storage, _d) = app_with_storage();
        let data = b"todelete";
        let d = sha256_of(data);
        storage.put_blob("r", &d, data).await.unwrap();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete(format!("/v2/r/blobs/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );
        // Deleting again → 404. Also a malformed digest → 400.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete(format!("/v2/r/blobs/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete("/v2/r/blobs/notadigest")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn delete_manifest_by_tag_and_digest_and_errors() {
        let (app, storage, _d) = app_with_storage();
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        storage
            .put_manifest("r", Some("v1"), &md, "application/json", m)
            .await
            .unwrap();
        // Delete by tag.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete("/v2/r/manifests/v1")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );
        // Re-store and delete by digest.
        storage
            .put_manifest("r", Some("v1"), &md, "application/json", m)
            .await
            .unwrap();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete(format!("/v2/r/manifests/{}", md.as_string()))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::ACCEPTED
        );
        // Delete by an invalid digest reference → 400.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete("/v2/r/manifests/sha256:short")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        // Delete a nonexistent manifest *by digest* → 404 MANIFEST_UNKNOWN
        // (not NAME_UNKNOWN).
        let ghost = sha256_of(b"ghost-manifest");
        let v = body_json_of(
            &app,
            HttpRequest::delete(format!("/v2/r/manifests/{}", ghost.as_string()))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
        // Delete an absent tag → 404.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete("/v2/r/manifests/ghost")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn put_manifest_by_digest_match_and_mismatch() {
        let (app, _d) = app();
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        // Matching digest reference → 201.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put(format!("/v2/r/manifests/{}", md.as_string()))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(m.to_vec()))
                    .unwrap()
            )
            .await,
            StatusCode::CREATED
        );
        // Uppercase-hex digest reference still matches (Digest canonicalizes to
        // lowercase; the compare parses both) → 201.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put(format!("/v2/r/manifests/sha256:{}", md_hex_upper(&md)))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(m.to_vec()))
                    .unwrap()
            )
            .await,
            StatusCode::CREATED
        );
        // Mismatched digest reference → 400.
        let wrong = sha256_of(b"other");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put(format!("/v2/r/manifests/{}", wrong.as_string()))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(m.to_vec()))
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        // A `:`-form reference that is a *malformed* digest → 400 DIGEST_INVALID.
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/sha256:short")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(m.to_vec()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "DIGEST_INVALID");
    }

    #[tokio::test]
    async fn delete_manifest_non_directory_cas_parent_is_404() {
        // `<repo>/blobs/sha256` as a regular file makes the beneath-root dirfd
        // walk refuse to descend into it (ENOTDIR → treated as absent), so a
        // delete of `.../sha256/<hex>` reports the manifest simply not found
        // (404 MANIFEST_UNKNOWN) rather than a 500 — a symlinked/broken CAS
        // parent can never redirect the deletion outside the store. A genuine IO
        // error (e.g. EACCES) still surfaces as 500 via unlink_beneath.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let b_dir = dir.path().join("r").join("blobs");
        std::fs::create_dir_all(&b_dir).unwrap();
        std::fs::write(b_dir.join("sha256"), b"not a dir").unwrap();
        let app = build_router(AppState::new(storage));
        let d = sha256_of(b"x");
        let resp = app
            .oneshot(
                HttpRequest::delete(format!("/v2/r/manifests/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delete_manifest_readonly_parent_is_500() {
        // A genuine IO error (EACCES from a read-only CAS `<alg>` parent, not a
        // symlink/broken-parent NotFound) on the unlink surfaces as 500, not a
        // false 404. Runs as the unprivileged test user (root bypasses modes).
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"present-manifest");
        // Put the manifest, then make its `<alg>` dir read-only so unlink fails.
        storage
            .put_blob("r", &d, b"present-manifest")
            .await
            .unwrap();
        let alg = dir.path().join("r").join("blobs").join("sha256");
        std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o500)).unwrap();
        let app = build_router(AppState::new(storage));
        let resp = app
            .oneshot(
                HttpRequest::delete(format!("/v2/r/manifests/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let _ = std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755));
        // Unprivileged: EACCES → 500. Privileged (root): unlink succeeds → 202.
        assert!(matches!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR | StatusCode::ACCEPTED
        ));
    }

    // Uppercase the hex of a digest for the case-insensitive match test.
    fn md_hex_upper(d: &Digest) -> String {
        d.as_string()
            .split_once(':')
            .unwrap()
            .1
            .to_ascii_uppercase()
    }

    #[tokio::test]
    async fn cross_mount_present_and_absent() {
        let (app, storage, _d) = app_with_storage();
        let data = b"mountable";
        let d = sha256_of(data);
        storage.put_blob("src", &d, data).await.unwrap();
        // Mount from src → 201 at dest.
        let uri = format!("/v2/dest/blobs/uploads/?mount={}&from=src", d.as_string());
        let resp = app
            .clone()
            .oneshot(HttpRequest::post(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            resp.headers()
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            d.as_string()
        );
        // Mount source absent → falls through to a normal upload session (202).
        let absent = sha256_of(b"nope");
        let uri = format!(
            "/v2/dest/blobs/uploads/?mount={}&from=elsewhere",
            absent.as_string()
        );
        let resp = app
            .oneshot(HttpRequest::post(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert!(resp.headers().get("docker-upload-uuid").is_some());
    }

    #[tokio::test]
    async fn upload_status_and_finish_errors() {
        let (app, _d) = app();
        // Begin a session.
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // GET status → 204 with Range + Location + uuid.
        let resp = app
            .clone()
            .oneshot(HttpRequest::get(&loc).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp.headers().get("range").is_some());
        // Finish without a digest query → 400.
        assert_eq!(
            status_of(&app, HttpRequest::put(&loc).body(Body::empty()).unwrap()).await,
            StatusCode::BAD_REQUEST
        );
        // Finish with an invalid digest → 400.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put(format!("{loc}?digest=notadigest"))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        // GET status on an unknown session → 404.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::get("/v2/r/blobs/uploads/ghost")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn monolithic_upload_with_bad_digest() {
        let (app, _d) = app();
        // Invalid digest string on the monolithic POST → 400.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::post("/v2/r/blobs/uploads/?digest=notadigest")
                    .body(Body::from("x"))
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        // Well-formed digest that does not match the body → 400 (mismatch).
        let wrong = sha256_of(b"other");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", wrong.as_string()))
                    .body(Body::from("x"))
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn head_and_post_to_invalid_name_rejected() {
        // route_head / route_post validate the name before dispatch.
        let (app, _d) = app();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::head("/v2/BAD/manifests/t")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(
                &app,
                HttpRequest::post("/v2/BAD/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn blob_and_manifest_io_errors_map_to_500() {
        // A *present* blob (recorded in the presence filter) whose CAS directory
        // is made unreadable yields a non-NotFound IO error (EACCES) on both the
        // HEAD stat and GET open paths, exercising get_blob's Io → 500 arms. The
        // filter guards *absence*, so the blob must actually exist for the read
        // to reach the filesystem.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let data = b"present";
        let d = sha256_of(data);
        storage.put_blob("r", &d, data).await.unwrap();
        let app = build_router(AppState::new(storage));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let alg_dir = dir.path().join("r").join("blobs").join("sha256");
            std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
            for req in [
                HttpRequest::get(format!("/v2/r/blobs/{}", d.as_string())),
                HttpRequest::head(format!("/v2/r/blobs/{}", d.as_string())),
            ] {
                assert_eq!(
                    status_of(&app, req.body(Body::empty()).unwrap()).await,
                    StatusCode::INTERNAL_SERVER_ERROR
                );
            }
            // Restore perms so the tempdir cleans up.
            std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // `<repo2>/index.json` as a directory makes get_manifest by digest fail
        // with a non-NotFound Io error (read_index), exercising its Io arm.
        std::fs::create_dir_all(dir.path().join("r2").join("index.json")).unwrap();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::get(format!("/v2/r2/manifests/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn tags_list_pagination() {
        let (app, storage, _d) = app_with_storage();
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        for t in ["a", "b", "c", "d"] {
            storage
                .put_manifest("r", Some(t), &md, "application/json", m)
                .await
                .unwrap();
        }
        // n truncates.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/v2/r/tags/list?n=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["tags"], serde_json::json!(["a", "b"]));
        // last offsets past the named tag.
        let resp = app
            .oneshot(
                HttpRequest::get("/v2/r/tags/list?last=b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["tags"], serde_json::json!(["c", "d"]));
    }

    #[tokio::test]
    async fn delete_disabled_returns_405() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        storage
            .put_manifest("r", Some("v1"), &md, "application/json", m)
            .await
            .unwrap();
        let mut config = Config::default();
        config.delete.enabled = false;
        let app = build_router(AppState::new_with(storage.clone(), config));
        for path in [
            format!("/v2/r/manifests/{}", md.as_string()),
            "/v2/r/manifests/v1".to_string(),
            format!("/v2/r/blobs/{}", md.as_string()),
        ] {
            let v = body_json_of(
                &app,
                HttpRequest::delete(&path).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(v["errors"][0]["code"], "UNSUPPORTED", "{path}");
            assert_eq!(
                status_of(
                    &app,
                    HttpRequest::delete(&path).body(Body::empty()).unwrap()
                )
                .await,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        // Nothing was deleted.
        assert!(storage.get_manifest("r", "v1").await.is_ok());
    }

    #[tokio::test]
    async fn tags_list_link_header_walks_all_pages() {
        let (app, storage, _d) = app_with_storage();
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        for t in ["a", "b", "c", "d", "e"] {
            storage
                .put_manifest("r", Some(t), &md, "application/json", m)
                .await
                .unwrap();
        }
        let mut url = "/v2/r/tags/list?n=2".to_string();
        let mut seen = Vec::new();
        loop {
            let resp = app
                .clone()
                .oneshot(HttpRequest::get(&url).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let link = resp
                .headers()
                .get(header::LINK)
                .map(|v| v.to_str().unwrap().to_string());
            let v: serde_json::Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            for t in v["tags"].as_array().unwrap() {
                seen.push(t.as_str().unwrap().to_string());
            }
            match link {
                Some(l) => {
                    assert!(l.ends_with("; rel=\"next\""), "{l}");
                    url = l[1..l.find('>').unwrap()].to_string();
                }
                None => break,
            }
        }
        assert_eq!(seen, ["a", "b", "c", "d", "e"]);
    }

    #[tokio::test]
    async fn referrers_pagination_filter_link_and_vary() {
        let (app, storage, _d) = app_with_storage();
        let subject = sha256_of(b"subject");
        let mut sigs = Vec::new();
        for i in 0..5u8 {
            let r = sha256_of(&[i]);
            let at = if i % 2 == 0 {
                "application/sig"
            } else {
                "application/sbom"
            };
            if at == "application/sig" {
                sigs.push(r.as_string());
            }
            let desc = serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": r.as_string(),
                "size": 1,
                "artifactType": at,
            });
            storage
                .add_referrer("r", &subject, &r, desc.to_string().as_bytes())
                .await
                .unwrap();
        }
        // Unfiltered: no Vary, no filter header, full list.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(format!("/v2/r/referrers/{}", subject.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.headers().get(header::VARY).is_none());
        assert!(resp.headers().get(header::LINK).is_none());
        // Filtered + paged: walk every page via Link; collect only sigs.
        let mut url = format!(
            "/v2/r/referrers/{}?artifactType=application/sig&n=2",
            subject.as_string()
        );
        let mut seen = Vec::new();
        loop {
            let resp = app
                .clone()
                .oneshot(HttpRequest::get(&url).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.headers().get(header::VARY).unwrap(), "Accept");
            assert_eq!(
                resp.headers().get("oci-filters-applied").unwrap(),
                "artifactType"
            );
            let link = resp
                .headers()
                .get(header::LINK)
                .map(|v| v.to_str().unwrap().to_string());
            let v: serde_json::Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            let page = v["manifests"].as_array().unwrap();
            assert!(page.len() <= 2);
            for m in page {
                seen.push(m["digest"].as_str().unwrap().to_string());
            }
            match link {
                Some(l) => url = l[1..l.find('>').unwrap()].to_string(),
                None => break,
            }
        }
        assert_eq!(seen, sigs);
    }

    #[tokio::test]
    async fn referrers_bad_digest_is_400() {
        let (app, _d) = app();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::get("/v2/r/referrers/notadigest")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn absent_blob_is_404_even_with_malformed_cas() {
        // The presence filter answers a definite absence without touching the
        // filesystem, so a blob the registry never stored is a clean 404 even
        // when the CAS path underneath is malformed (here `<repo>/blobs/sha256`
        // is a file). This pins the filter's absence guarantee.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let alg_dir = dir.path().join("r").join("blobs");
        std::fs::create_dir_all(&alg_dir).unwrap();
        std::fs::write(alg_dir.join("sha256"), b"not a dir").unwrap();
        let d = sha256_of(b"x");
        let app = build_router(AppState::new(storage));
        let resp = app
            .oneshot(
                HttpRequest::get(format!("/v2/r/blobs/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Extract the hex part of a digest for path construction in the IO-error test.
    fn hex_of(d: &Digest) -> String {
        d.as_string().split_once(':').unwrap().1.to_string()
    }

    #[tokio::test]
    async fn upload_start_without_trailing_slash() {
        let (app, _d) = app();
        let resp = app
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert!(resp.headers().get("docker-upload-uuid").is_some());
    }

    #[tokio::test]
    async fn get_manifest_returns_body() {
        let (app, storage, _d) = app_with_storage();
        let m = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        let md = sha256_of(m);
        storage
            .put_manifest(
                "r",
                Some("t"),
                &md,
                "application/vnd.oci.image.manifest.v1+json",
                m,
            )
            .await
            .unwrap();
        let resp = app
            .oneshot(
                HttpRequest::get("/v2/r/manifests/t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], m);
    }

    #[tokio::test]
    async fn get_blob_with_bad_digest_is_400() {
        let (app, _d) = app();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::get("/v2/r/blobs/notadigest")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn delete_manifest_by_absent_digest_is_404() {
        let (app, _d) = app();
        let absent = sha256_of(b"absent-manifest");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::delete(format!("/v2/r/manifests/{}", absent.as_string()))
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn referrer_artifact_type_falls_back_to_config_media_type() {
        let (app, _d) = app();
        let subject = sha256_of(b"sub");
        let referrer = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.example.config", "digest": sha256_of(b"c").as_string(), "size": 1 },
            "subject": { "digest": subject.as_string() }
        });
        let body = serde_json::to_vec(&referrer).unwrap();
        let rd = sha256_of(&body);
        // The config blob the manifest references must exist (referenced-blob
        // existence is enforced on push); upload it monolithically first.
        let cfg = sha256_of(b"c");
        app.clone()
            .oneshot(
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", cfg.as_string()))
                    .body(Body::from(b"c".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                HttpRequest::put(format!("/v2/r/manifests/{}", rd.as_string()))
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = app
            .oneshot(
                HttpRequest::get(format!("/v2/r/referrers/{}", subject.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let idx: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(
            idx["manifests"][0]["artifactType"],
            "application/vnd.example.config"
        );
    }

    // Build an app whose repo `r` has `index.json` as a directory, so read_index
    // fails with a non-NotFound IO error and the handler maps it to 500.
    fn app_with_broken_repo() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("r").join("index.json")).unwrap();
        (build_router(AppState::new(storage)), dir)
    }

    #[tokio::test]
    async fn tags_list_storage_error_is_500() {
        let (app, _d) = app_with_broken_repo();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::get("/v2/r/tags/list")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn patch_and_finish_on_directory_session_error() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let session = dir.path().join("r").join("uploads").join("dirsess");
        std::fs::create_dir_all(&session).unwrap();
        let app = build_router(AppState::new(storage));
        let patch = app
            .clone()
            .oneshot(
                HttpRequest::patch("/v2/r/blobs/uploads/dirsess")
                    .body(Body::from("data"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patch.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let d = sha256_of(b"data");
        let put = app
            .oneshot(
                HttpRequest::put(format!(
                    "/v2/r/blobs/uploads/dirsess?digest={}",
                    d.as_string()
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        // finish_upload's non-regular-file guard rejects a directory session as
        // a bad path (400 NAME_INVALID) before hashing, rather than a generic 500.
        assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn patch_with_valid_content_range_appends() {
        let (app, _d) = app();
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // A Content-Range whose start equals the current offset (0) is accepted.
        let resp = app
            .oneshot(
                HttpRequest::patch(&loc)
                    .header(header::CONTENT_RANGE, "0-4")
                    .body(Body::from("hello"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(
            resp.headers().get("range").unwrap().to_str().unwrap(),
            "0-4"
        );
    }

    #[tokio::test]
    async fn finish_upload_append_error_on_directory_session() {
        // Drive the finish (PUT) path with a body against a directory session so
        // the append inside finish_upload errors (covers that error arm).
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let session = dir.path().join("r").join("uploads").join("dsess");
        std::fs::create_dir_all(&session).unwrap();
        let app = build_router(AppState::new(storage));
        let d = sha256_of(b"payload");
        let resp = app
            .oneshot(
                HttpRequest::put(format!(
                    "/v2/r/blobs/uploads/dsess?digest={}",
                    d.as_string()
                ))
                .body(Body::from("payload"))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // App whose handlers reject bodies larger than `limit` bytes, so the
    // oversized-body (413) error arms are reachable without huge allocations.
    fn app_tiny_body(limit: usize) -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        (
            build_router(AppState::new(storage).with_max_body(limit)),
            dir,
        )
    }

    #[tokio::test]
    async fn oversized_bodies_are_413() {
        let (app, _d) = app_tiny_body(4);
        // A manifest over the configured request-body limit (4 bytes here) →
        // 413 (payload too large), since the effective cap is the smaller of
        // the configured limit and the fixed 4 MiB manifest cap.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put("/v2/r/manifests/t")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("way too many bytes"))
                    .unwrap()
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // monolithic upload oversized.
        let d = sha256_of(b"way too many bytes");
        assert_eq!(
            status_of(
                &app,
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", d.as_string()))
                    .body(Body::from("way too many bytes"))
                    .unwrap()
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // chunked PATCH oversized.
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::patch(&loc)
                    .body(Body::from("way too many bytes"))
                    .unwrap()
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // finish (PUT) oversized body.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put(format!("{loc}?digest={}", d.as_string()))
                    .body(Body::from("way too many bytes"))
                    .unwrap()
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    // App whose `<repo>/uploads` path is a file, so begin_upload / upload_size
    // fail with a non-NotFound IO error → handlers map to 500.
    fn app_broken_uploads() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let repo = dir.path().join("r");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("uploads"), b"file").unwrap();
        (build_router(AppState::new(storage)), dir)
    }

    #[tokio::test]
    async fn begin_upload_storage_error_is_500() {
        let (app, _d) = app_broken_uploads();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn patch_upload_missing_session_is_404() {
        // `<repo>/uploads` is a regular file, so the no-follow beneath-root
        // resolver cannot open a staging file under it (`ENOTDIR`) — the session
        // does not exist, which is a 404 (BLOB_UPLOAD_UNKNOWN), not a 500. The
        // resolver refuses to distinguish a broken store from a symlink attack:
        // both mean "no valid session here".
        let (app, _d) = app_broken_uploads();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::patch("/v2/r/blobs/uploads/sess")
                    .body(Body::from("x"))
                    .unwrap()
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn put_manifest_storage_error_is_500() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let repo = dir.path().join("r");
        std::fs::create_dir_all(&repo).unwrap();
        // put_manifest writes the manifest to the CAS first; `<repo>/blobs` as a
        // file makes that write fail, exercising the handler's 500 mapping.
        std::fs::write(repo.join("blobs"), b"file").unwrap();
        let app = build_router(AppState::new(storage));
        let m = br#"{"schemaVersion":2}"#;
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put("/v2/r/manifests/t")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(m.to_vec()))
                    .unwrap()
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn mount_put_blob_failure_falls_through() {
        // Source has the blob, but the destination repo's `blobs` path is a file
        // so the mount put_blob fails; start_upload falls through to a normal
        // session (202) rather than 201.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let data = b"mountme";
        let d = sha256_of(data);
        storage.put_blob("src", &d, data).await.unwrap();
        let dest = dir.path().join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("blobs"), b"file").unwrap();
        let app = build_router(AppState::new(storage));
        let uri = format!("/v2/dest/blobs/uploads/?mount={}&from=src", d.as_string());
        let resp = app
            .oneshot(HttpRequest::post(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn monolithic_finish_error_is_500() {
        // `<repo>/blobs` is a file so finish_upload's put into the CAS fails
        // after the body is appended, covering the monolithic error arms.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let repo = dir.path().join("r");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("blobs"), b"file").unwrap();
        let app = build_router(AppState::new(storage));
        let data = b"payload";
        let d = sha256_of(data);
        let uri = format!("/v2/r/blobs/uploads/?digest={}", d.as_string());
        let resp = app
            .oneshot(
                HttpRequest::post(&uri)
                    .body(Body::from(data.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn mount_with_malformed_digest_falls_through() {
        let (app, _d) = app();
        let resp = app
            .oneshot(
                HttpRequest::post("/v2/dest/blobs/uploads/?mount=notadigest&from=src")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn chunked_finish_with_trailing_body_appends_then_completes() {
        let (app, _d) = app();
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let d = sha256_of(b"trailing");
        let resp = app
            .oneshot(
                HttpRequest::put(format!("{loc}?digest={}", d.as_string()))
                    .body(Body::from("trailing"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn monolithic_with_body_appends_and_completes() {
        let (app, _d) = app();
        let data = b"mono-body";
        let d = sha256_of(data);
        let resp = app
            .oneshot(
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", d.as_string()))
                    .body(Body::from(data.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn monolithic_empty_body_upload() {
        // A monolithic POST with an empty body and the digest of empty content:
        // the append is skipped (body is empty) and finish stores the empty blob.
        let (app, _d) = app();
        let d = sha256_of(b"");
        let resp = app
            .oneshot(
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn referrer_without_artifact_type_or_config() {
        let (app, _d) = app();
        let subject = sha256_of(b"s2");
        let referrer = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "subject": { "digest": subject.as_string() }
        });
        let body = serde_json::to_vec(&referrer).unwrap();
        let rd = sha256_of(&body);
        app.clone()
            .oneshot(
                HttpRequest::put(format!("/v2/r/manifests/{}", rd.as_string()))
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = app
            .oneshot(
                HttpRequest::get(format!("/v2/r/referrers/{}", subject.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let idx: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert!(idx["manifests"][0].get("artifactType").is_none());
    }

    #[tokio::test]
    async fn tags_list_last_not_in_list() {
        let (app, storage, _d) = app_with_storage();
        let m = br#"{"schemaVersion":2}"#;
        let md = sha256_of(m);
        storage
            .put_manifest("r", Some("a"), &md, "application/json", m)
            .await
            .unwrap();
        let resp = app
            .oneshot(
                HttpRequest::get("/v2/r/tags/list?last=zzz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["tags"], serde_json::json!(["a"]));
    }

    // ---- Phase 1: streaming Range + cache-control read-path tests ----------

    /// Header value as a str for assertions.
    fn hv(resp: &Response, name: header::HeaderName) -> Option<&str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn blob_range_requests() {
        let (app, storage, _d) = app_with_storage();
        let data = b"0123456789"; // 10 bytes
        let d = sha256_of(data);
        storage.put_blob("r", &d, data).await.unwrap();
        let uri = format!("/v2/r/blobs/{}", d.as_string());

        // Closed range 2-5 → 206, 4 bytes "2345".
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::RANGE, "bytes=2-5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 2-5/10"));
        assert_eq!(hv(&resp, header::CONTENT_LENGTH), Some("4"));
        assert_eq!(hv(&resp, header::ACCEPT_RANGES), Some("bytes"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"2345");

        // Suffix range -3 → last 3 bytes "789".
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::RANGE, "bytes=-3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 7-9/10"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"789");

        // Open-ended range 7- → bytes 7..9, clamped to end.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::RANGE, "bytes=7-")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 7-9/10"));

        // Overlong end clamps to the last byte.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::RANGE, "bytes=8-99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 8-9/10"));

        // Unsatisfiable (start ≥ size) → 416 + Content-Range: bytes */10.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::RANGE, "bytes=10-20")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes */10"));

        // A zero-length suffix is unsatisfiable.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::RANGE, "bytes=-0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[tokio::test]
    async fn blob_ignored_ranges_serve_full() {
        let (app, storage, _d) = app_with_storage();
        let data = b"0123456789";
        let d = sha256_of(data);
        storage.put_blob("r", &d, data).await.unwrap();
        let uri = format!("/v2/r/blobs/{}", d.as_string());
        // Each of these is ignored (malformed/multi/reversed/non-bytes-unit) →
        // full 200 with the whole body and Accept-Ranges advertised.
        for range in [
            "items=0-1",
            "bytes=1-0",
            "bytes=2-5,7-8",
            "bytes=abc",
            "bytes=-xy",
            "bytes=xy-",
            "bytes=a-b",
        ] {
            let resp = app
                .clone()
                .oneshot(
                    HttpRequest::get(&uri)
                        .header(header::RANGE, range)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "range {range}");
            assert_eq!(hv(&resp, header::ACCEPT_RANGES), Some("bytes"));
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], data, "range {range}");
        }
        // No Range header at all → full 200 with immutable cache validators.
        let resp = app
            .oneshot(HttpRequest::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            hv(&resp, header::CACHE_CONTROL),
            Some("max-age=31536000, immutable")
        );
        assert_eq!(
            hv(&resp, header::ETAG),
            Some(format!("\"{}\"", d.as_string()).as_str())
        );
    }

    #[tokio::test]
    async fn blob_conditional_get_and_head() {
        let (app, storage, _d) = app_with_storage();
        let data = b"cacheable";
        let d = sha256_of(data);
        storage.put_blob("r", &d, data).await.unwrap();
        let uri = format!("/v2/r/blobs/{}", d.as_string());
        let etag = format!("\"{}\"", d.as_string());

        // HEAD advertises ranges + immutable cache + ETag.
        let resp = app
            .clone()
            .oneshot(HttpRequest::head(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hv(&resp, header::ACCEPT_RANGES), Some("bytes"));
        assert_eq!(hv(&resp, header::CONTENT_LENGTH), Some("9"));
        assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));

        // If-None-Match matching the digest ETag → 304 (GET and HEAD).
        for method in ["GET", "HEAD"] {
            let req = HttpRequest::builder()
                .method(method)
                .uri(&uri)
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_MODIFIED, "{method}");
            assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(body.is_empty(), "304 has no body ({method})");
        }
        // A `*` If-None-Match also short-circuits to 304.
        let resp = app
            .oneshot(
                HttpRequest::get(&uri)
                    .header(header::IF_NONE_MATCH, "*")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn manifest_cache_control_and_conditional() {
        let (app, storage, _d) = app_with_storage();
        let body =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        let d = sha256_of(body);
        storage
            .put_manifest(
                "r",
                Some("v1"),
                &d,
                "application/vnd.oci.image.manifest.v1+json",
                body,
            )
            .await
            .unwrap();
        let etag = format!("\"{}\"", d.as_string());

        // By-digest GET → immutable cache + ETag.
        let by_digest = format!("/v2/r/manifests/{}", d.as_string());
        let resp = app
            .clone()
            .oneshot(HttpRequest::get(&by_digest).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            hv(&resp, header::CACHE_CONTROL),
            Some("max-age=31536000, immutable")
        );
        assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));

        // By-digest If-None-Match → 304.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get(&by_digest)
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            hv(&resp, header::CACHE_CONTROL),
            Some("max-age=31536000, immutable")
        );

        // By-tag GET → no-cache (revalidate), but still carries an ETag.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/v2/r/manifests/v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(hv(&resp, header::CACHE_CONTROL), Some("no-cache"));
        assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));
        // Accept mismatch is advisory: still 200 with the stored Content-Type.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/v2/r/manifests/v1")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            hv(&resp, header::CONTENT_TYPE),
            Some("application/vnd.oci.image.manifest.v1+json")
        );

        // By-tag If-None-Match with the current digest → 304 + no-cache (HEAD).
        let resp = app
            .oneshot(
                HttpRequest::head("/v2/r/manifests/v1")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(hv(&resp, header::CACHE_CONTROL), Some("no-cache"));
    }

    #[tokio::test]
    async fn manifest_content_type_must_match_media_type() {
        let (app, _d) = app();
        // Body declares an image-manifest mediaType; request Content-Type is an
        // index — the CVE-2021-41190 disagreement → 400 MANIFEST_INVALID.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json"
        });
        let body = serde_json::to_vec(&manifest).unwrap();
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v1")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.index.v1+json",
                )
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
        // Matching Content-Type (params tolerated) → accepted (201).
        let resp = app
            .oneshot(
                HttpRequest::put("/v2/r/manifests/v1")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json; charset=utf-8",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn manifest_referencing_absent_blob_is_manifest_blob_unknown() {
        let (app, _d) = app();
        let cfg = sha256_of(b"cfg");
        let layer = sha256_of(b"layer");
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg.as_string(), "size": 3 },
            "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer.as_string(), "size": 5 } ]
        });
        let body = serde_json::to_vec(&manifest).unwrap();
        // The config/layer blobs were never uploaded → 400 MANIFEST_BLOB_UNKNOWN.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::put("/v2/r/manifests/v1")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
        // Upload the referenced blobs, then the same manifest is accepted.
        for (data, d) in [(&b"cfg"[..], &cfg), (&b"layer"[..], &layer)] {
            app.clone()
                .oneshot(
                    HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", d.as_string()))
                        .body(Body::from(data.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        let resp = app
            .oneshot(
                HttpRequest::put("/v2/r/manifests/v1")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // App whose upload sessions are capped at `limit` bytes so the over-cap
    // (413/SIZE_INVALID) path is reachable without a multi-GiB fixture.
    fn app_tiny_upload(limit: u64) -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        (
            build_router(AppState::new(storage).with_max_upload(limit)),
            dir,
        )
    }

    #[tokio::test]
    async fn chunked_upload_over_session_cap_is_413_and_drops_session() {
        let (app, _d) = app_tiny_upload(4);
        // Open a session.
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::ACCEPTED);
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // A PATCH exceeding the 4-byte session cap → 413 SIZE_INVALID.
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::patch(&loc)
                    .body(Body::from("too many bytes"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["errors"][0]["code"], "SIZE_INVALID");
        // The session was dropped: a status GET now 404s (BLOB_UPLOAD_UNKNOWN).
        let status = app
            .oneshot(HttpRequest::get(&loc).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn finish_upload_over_session_cap_is_413() {
        let (app, _d) = app_tiny_upload(4);
        // Open a session, then a monolithic PUT whose trailing body exceeds the
        // 4-byte session cap → 413 SIZE_INVALID (the finish-path cap branch).
        let start = app
            .clone()
            .oneshot(
                HttpRequest::post("/v2/r/blobs/uploads/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let loc = start
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let d = sha256_of(b"too many bytes");
        let resp = app
            .oneshot(
                HttpRequest::put(format!("{loc}?digest={}", d.as_string()))
                    .body(Body::from("too many bytes"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["errors"][0]["code"], "SIZE_INVALID");
    }

    #[tokio::test]
    async fn manifest_malformed_referenced_digests_are_manifest_invalid() {
        let (app, _d) = app();
        // A malformed config digest → MANIFEST_INVALID.
        let bad_config = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:notavaliddigest", "size": 1 }
        });
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v1")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&bad_config).unwrap()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
        // A malformed layer digest → MANIFEST_INVALID.
        let bad_layer = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:zzzz", "size": 1 } ]
        });
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v2")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&bad_layer).unwrap()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
        // A layer descriptor with no `digest` is malformed → MANIFEST_INVALID.
        let no_digest_layer = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": 0 } ]
        });
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v3")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&no_digest_layer).unwrap()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
        // A non-object config descriptor is likewise malformed → MANIFEST_INVALID.
        let bad_config_shape = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": "not-a-descriptor"
        });
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v4")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&bad_config_shape).unwrap()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
        // A present but non-string `mediaType` must not bypass the CVE-2021-41190
        // agreement check → MANIFEST_INVALID.
        let non_string_mt = serde_json::json!({ "schemaVersion": 2, "mediaType": 123 });
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v5")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&non_string_mt).unwrap()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
        // A present but non-array `layers` is malformed → MANIFEST_INVALID.
        let non_array_layers = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": "not-an-array"
        });
        let v = body_json_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v6")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&non_array_layers).unwrap()))
                .unwrap(),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn manifest_blob_existence_io_error_is_500() {
        // A referenced blob that is present (so the presence filter waves it
        // through to the filesystem) but whose CAS directory is unreadable
        // yields a non-NotFound IO error from blob_exists → 500.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let cfg_data = b"cfg";
        let cfg = sha256_of(cfg_data);
        storage.put_blob("r", &cfg, cfg_data).await.unwrap();
        let app = build_router(AppState::new(storage));
        let alg_dir = dir.path().join("r").join("blobs").join("sha256");
        std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg.as_string(), "size": 3 }
        });
        let status = status_of(
            &app,
            HttpRequest::put("/v2/r/manifests/v1")
                .header(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json",
                )
                .body(Body::from(serde_json::to_vec(&manifest).unwrap()))
                .unwrap(),
        )
        .await;
        // Restore perms so the tempdir cleans up.
        std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn monolithic_upload_over_session_cap_is_413() {
        // A monolithic POST ?digest= whose body exceeds max_upload → 413, even
        // though it is under max_body (the cap applies to monolithic too).
        let (app, _d) = app_tiny_upload(4);
        let data = b"way over the four byte cap";
        let d = sha256_of(data);
        let resp = app
            .oneshot(
                HttpRequest::post(format!("/v2/r/blobs/uploads/?digest={}", d.as_string()))
                    .body(Body::from(data.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["errors"][0]["code"], "SIZE_INVALID");
    }

    #[tokio::test]
    async fn image_index_records_child_and_subject_backrefs() {
        // Pushing an image index records a backref edge from each child manifest
        // digest to the index; a manifest with a subject records the subject
        // edge. Neither child nor subject existence is enforced (they may be
        // pushed later / a subject may be absent per spec).
        let (app, storage, _d) = app_with_storage();
        let child_a = sha256_of(b"child-a");
        let child_b = sha256_of(b"child-b");
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": child_a.as_string(), "size": 1 },
                { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": child_b.as_string(), "size": 1 }
            ]
        });
        let body = serde_json::to_vec(&index).unwrap();
        let idx_digest = sha256_of(&body);
        let resp = app
            .oneshot(
                HttpRequest::put("/v2/r/manifests/idx")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.index.v1+json",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        // Each child carries a backref to the index manifest.
        assert_eq!(
            storage.backrefs("r", &child_a).await.unwrap(),
            vec![idx_digest.as_string()]
        );
        assert_eq!(
            storage.backrefs("r", &child_b).await.unwrap(),
            vec![idx_digest.as_string()]
        );
    }

    #[tokio::test]
    async fn manifest_subject_is_recorded_as_backref() {
        let (app, storage, _d) = app_with_storage();
        let subject = sha256_of(b"the-subject");
        // An artifact-style manifest with no config/layers but a subject.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "subject": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": subject.as_string(), "size": 2 }
        });
        let body = serde_json::to_vec(&manifest).unwrap();
        let m_digest = sha256_of(&body);
        let resp = app
            .oneshot(
                HttpRequest::put("/v2/r/manifests/art")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            storage.backrefs("r", &subject).await.unwrap(),
            vec![m_digest.as_string()]
        );
    }
}
