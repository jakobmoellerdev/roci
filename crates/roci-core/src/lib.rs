//! roci-core: the OCI Distribution Spec v1.1.1 HTTP surface.
//!
//! Implements the dist-spec endpoint groups end-1 .. end-13 against the
//! [`roci_storage::Storage`] trait. AuthN/AuthZ (when added) is evaluated in a
//! layer *before* these handlers touch storage (ARCHITECTURE.md invariant 3).
#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use roci_storage::{sha256_of, Digest, Storage, StorageError};

/// Shared handler state.
pub struct AppState<S: Storage> {
    storage: Arc<S>,
    /// Maximum accepted request-body size; bodies larger are rejected with 413.
    max_body: usize,
}

// Manual Clone: `Arc<S>` is always cloneable regardless of whether `S` is.
impl<S: Storage> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            max_body: self.max_body,
        }
    }
}

impl<S: Storage> AppState<S> {
    /// Wrap a storage backend, accepting bodies up to [`MAX_BODY`] (256 MiB).
    pub fn new(storage: S) -> Self {
        Self {
            storage: Arc::new(storage),
            max_body: MAX_BODY,
        }
    }

    /// Override the maximum accepted request-body size (bytes).
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
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
        .with_state(state)
}

// ---- OCI error envelope --------------------------------------------------

fn oci_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "errors": [{ "code": code, "message": message }]
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn map_storage_err(e: StorageError) -> Response {
    match e {
        StorageError::NotFound => {
            oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "resource not found")
        }
        StorageError::BadDigest(d) => oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("invalid digest: {d}"),
        ),
        StorageError::DigestMismatch { expected, actual } => oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("digest mismatch: expected {expected}, got {actual}"),
        ),
        StorageError::Io(_) => oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            "internal error",
        ),
    }
}

// ---- Path parsing --------------------------------------------------------

/// The parsed grammar of a `/v2/<name>/<verb>...` path.
enum Parsed {
    Blob { repo: String, digest: String },
    ManifestRef { repo: String, reference: String },
    UploadStart { repo: String },
    UploadSession { repo: String, id: String },
    TagsList { repo: String },
    Referrers { repo: String, digest: String },
    Unknown,
}

/// Split `<name>/<tail...>` where the last one or two segments form the verb.
fn parse_path(rest: &str) -> Parsed {
    let segments: Vec<&str> = rest.split('/').collect();
    let n = segments.len();
    if n < 2 {
        return Parsed::Unknown;
    }
    // blobs/uploads/<id?>
    if n >= 3 && segments[n - 3] == "blobs" && segments[n - 2] == "uploads" {
        let repo = segments[..n - 3].join("/");
        let id = segments[n - 1];
        return if id.is_empty() {
            Parsed::UploadStart { repo }
        } else {
            Parsed::UploadSession {
                repo,
                id: id.to_string(),
            }
        };
    }
    if n >= 2 && segments[n - 2] == "blobs" && segments[n - 1] == "uploads" {
        // trailing slash omitted: `.../blobs/uploads`
        let repo = segments[..n - 2].join("/");
        return Parsed::UploadStart { repo };
    }
    match segments[n - 2] {
        "blobs" => Parsed::Blob {
            repo: segments[..n - 2].join("/"),
            digest: segments[n - 1].to_string(),
        },
        "manifests" => Parsed::ManifestRef {
            repo: segments[..n - 2].join("/"),
            reference: segments[n - 1].to_string(),
        },
        "tags" if segments[n - 1] == "list" => Parsed::TagsList {
            repo: segments[..n - 2].join("/"),
        },
        "referrers" => Parsed::Referrers {
            repo: segments[..n - 2].join("/"),
            digest: segments[n - 1].to_string(),
        },
        _ => Parsed::Unknown,
    }
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
    match parse_path(&rest) {
        Parsed::Blob { repo, digest } => get_blob(&st, &repo, &digest, false).await,
        Parsed::ManifestRef { repo, reference } => {
            get_manifest(&st, &repo, &reference, false).await
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
        _ => oci_error(StatusCode::NOT_FOUND, "UNSUPPORTED", "unsupported path"),
    }
}

async fn route_head<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
) -> Response {
    match parse_path(&rest) {
        Parsed::Blob { repo, digest } => get_blob(&st, &repo, &digest, true).await,
        Parsed::ManifestRef { repo, reference } => get_manifest(&st, &repo, &reference, true).await,
        _ => oci_error(StatusCode::NOT_FOUND, "UNSUPPORTED", "unsupported path"),
    }
}

async fn route_post<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let query = req.uri().query().unwrap_or("").to_string();
    match parse_path(&rest) {
        Parsed::UploadStart { repo } => {
            let q: UploadQuery = serde_urlencoded::from_str(&query).unwrap_or_default();
            start_upload(&st, &repo, q, req).await
        }
        _ => oci_error(StatusCode::NOT_FOUND, "UNSUPPORTED", "unsupported path"),
    }
}

async fn route_put<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    let query = req.uri().query().unwrap_or("").to_string();
    match parse_path(&rest) {
        Parsed::UploadSession { repo, id } => {
            let q: UploadQuery = serde_urlencoded::from_str(&query).unwrap_or_default();
            finish_upload(&st, &repo, &id, q, req).await
        }
        Parsed::ManifestRef { repo, reference } => put_manifest(&st, &repo, &reference, req).await,
        _ => oci_error(StatusCode::NOT_FOUND, "UNSUPPORTED", "unsupported path"),
    }
}

async fn route_patch<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    match parse_path(&rest) {
        Parsed::UploadSession { repo, id } => patch_upload(&st, &repo, &id, req).await,
        _ => oci_error(StatusCode::NOT_FOUND, "UNSUPPORTED", "unsupported path"),
    }
}

async fn route_delete<S: Storage>(
    State(st): State<AppState<S>>,
    Path(rest): Path<String>,
) -> Response {
    match parse_path(&rest) {
        Parsed::Blob { repo, digest } => delete_blob(&st, &repo, &digest).await,
        Parsed::ManifestRef { repo, reference } => delete_manifest(&st, &repo, &reference).await,
        _ => oci_error(StatusCode::NOT_FOUND, "UNSUPPORTED", "unsupported path"),
    }
}

// ---- end-2 / end-10: blobs ----------------------------------------------

async fn get_blob<S: Storage>(st: &AppState<S>, repo: &str, digest: &str, head: bool) -> Response {
    let d = match Digest::parse(digest) {
        Ok(d) => d,
        Err(e) => return map_storage_err(e),
    };
    let size = match st.storage.blob_size(repo, &d).await {
        Ok(s) => s,
        Err(e) => return map_storage_err(e),
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    headers.insert(
        "docker-content-digest",
        HeaderValue::from_str(&d.as_string()).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if head {
        return (StatusCode::OK, headers).into_response();
    }
    match st.storage.read_blob(repo, &d).await {
        Ok(bytes) => (StatusCode::OK, headers, bytes).into_response(),
        Err(e) => map_storage_err(e),
    }
}

async fn delete_blob<S: Storage>(st: &AppState<S>, repo: &str, digest: &str) -> Response {
    let d = match Digest::parse(digest) {
        Ok(d) => d,
        Err(e) => return map_storage_err(e),
    };
    match st.storage.delete_blob(repo, &d).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(e) => map_storage_err(e),
    }
}

// ---- end-3 / end-7 / end-9: manifests ------------------------------------

async fn get_manifest<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    reference: &str,
    head: bool,
) -> Response {
    match st.storage.get_manifest(repo, reference).await {
        Ok(m) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(&m.media_type).unwrap(),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(m.bytes.len() as u64),
            );
            headers.insert(
                "docker-content-digest",
                HeaderValue::from_str(&m.digest.as_string()).unwrap(),
            );
            if head {
                (StatusCode::OK, headers).into_response()
            } else {
                (StatusCode::OK, headers, m.bytes).into_response()
            }
        }
        Err(e) => map_storage_err(e),
    }
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
    let body = match read_body_limited(req, st.max_body).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    let digest = sha256_of(&body);
    // A digest reference must match the content; a tag is associated as-is.
    let tag = if reference.contains(':') {
        if reference != digest.as_string() {
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "manifest digest does not match reference",
            );
        }
        None
    } else {
        Some(reference)
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

    if let Err(e) = st
        .storage
        .put_manifest(repo, tag, &digest, &media_type, &body)
        .await
    {
        return map_storage_err(e);
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
    // Resolve tag → digest first so tag deletions work too.
    let d = if reference.contains(':') {
        match Digest::parse(reference) {
            Ok(d) => d,
            Err(e) => return map_storage_err(e),
        }
    } else {
        match st.storage.get_manifest(repo, reference).await {
            Ok(m) => m.digest,
            Err(e) => return map_storage_err(e),
        }
    };
    match st.storage.delete_manifest(repo, &d).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
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
            if let Ok(data) = st.storage.read_blob(from, &d).await {
                if st.storage.put_blob(repo, &d, &data).await.is_ok() {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::LOCATION,
                        HeaderValue::from_str(&format!("/v2/{repo}/blobs/{}", d.as_string()))
                            .unwrap(),
                    );
                    headers.insert(
                        "docker-content-digest",
                        HeaderValue::from_str(&d.as_string()).unwrap(),
                    );
                    return (StatusCode::CREATED, headers).into_response();
                }
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
    // Current committed size of the session.
    let current = match st.storage.upload_size(repo, id).await {
        Ok(s) => s,
        Err(e) => return map_storage_err(e),
    };
    // If the client supplied a Content-Range, its start MUST equal the current
    // offset; out-of-order or retried chunks are rejected with 416.
    let range_start = req
        .headers()
        .get(header::CONTENT_RANGE)
        .or_else(|| req.headers().get("content-range"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split('-').next())
        .and_then(|s| s.trim().parse::<u64>().ok());
    if let Some(start) = range_start {
        if start != current {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::LOCATION,
                HeaderValue::from_str(&upload_location(repo, id)).unwrap(),
            );
            headers.insert(
                "range",
                HeaderValue::from_str(&format!("0-{}", current.saturating_sub(1))).unwrap(),
            );
            return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
        }
    }
    let body = match read_body_limited(req, st.max_body).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    let total = match st.storage.append_upload(repo, id, &body).await {
        Ok(t) => t,
        Err(e) => return map_storage_err(e),
    };
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
            return oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "missing digest on upload completion",
            )
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
    if !body.is_empty() {
        if let Err(e) = st.storage.append_upload(repo, id, &body).await {
            return map_storage_err(e);
        }
    }
    match st.storage.finish_upload(repo, id, &d).await {
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
    if let Some(n) = q.n {
        tags.truncate(n);
    }
    let body = serde_json::json!({ "name": repo, "tags": tags });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

// ---- end-12: referrers ---------------------------------------------------

async fn referrers<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    digest: &str,
    q: ReferrersQuery,
) -> Response {
    let subject = match Digest::parse(digest) {
        Ok(d) => d,
        Err(_) => return oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "invalid digest"),
    };
    // Referrers for a subject are returned even if the subject manifest itself
    // is absent; a missing index is simply an empty list.
    let raw = st
        .storage
        .list_referrers(repo, &subject)
        .await
        .unwrap_or_default();
    let mut manifests: Vec<serde_json::Value> = raw
        .into_iter()
        .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .collect();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );
    // end-12b: filter by artifactType and advertise the applied filter.
    if let Some(filter) = q.artifact_type.as_ref() {
        manifests
            .retain(|m| m.get("artifactType").and_then(|v| v.as_str()) == Some(filter.as_str()));
        headers.insert(
            "oci-filters-applied",
            HeaderValue::from_static("artifactType"),
        );
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
        Err(_) => Err(Box::new(oci_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SIZE_INVALID",
            "request body too large",
        ))),
    }
}

/// Maximum accepted body size (256 MiB). Chunked uploads split larger blobs.
const MAX_BODY: usize = 256 * 1024 * 1024;

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
    async fn storage_io_error_maps_to_500() {
        // Make a repo's blobs path a file so blob_size/read fails with a non-NotFound
        // IO error, exercising the StorageError::Io → 500 mapping arm.
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let repo_dir = dir.path().join("r").join("blobs").join("sha256");
        std::fs::create_dir_all(&repo_dir).unwrap();
        // Put a directory where the blob file should be so open/read yields EISDIR.
        let d = sha256_of(b"x");
        std::fs::create_dir_all(repo_dir.join(hex_of(&d))).unwrap();
        let app = build_router(AppState::new(storage));
        let resp = app
            .oneshot(
                HttpRequest::get(format!("/v2/r/blobs/{}", d.as_string()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
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

    // Build an app whose repo `r` has `tags` as a file, so list_tags fails with a
    // non-NotFound IO error and the handler maps it to 500.
    fn app_with_broken_repo() -> (Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let repo = dir.path().join("r");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("tags"), b"file").unwrap();
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
        assert_eq!(put.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
        let big = Body::from("way too many bytes");
        // put_manifest oversized.
        assert_eq!(
            status_of(
                &app,
                HttpRequest::put("/v2/r/manifests/t")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(big)
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
    async fn patch_upload_size_error_is_500() {
        // `<repo>/uploads` is a file, so upload_size for any session id errors
        // (NotADirectory) rather than NotFound → 500.
        let (app, _d) = app_broken_uploads();
        assert_eq!(
            status_of(
                &app,
                HttpRequest::patch("/v2/r/blobs/uploads/sess")
                    .body(Body::from("x"))
                    .unwrap()
            )
            .await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn put_manifest_storage_error_is_500() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path()).unwrap();
        let repo = dir.path().join("r");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("manifests"), b"file").unwrap();
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
}
