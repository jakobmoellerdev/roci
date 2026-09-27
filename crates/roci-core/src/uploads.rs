//! Upload-session endpoints: start, PATCH, PUT, status.

use crate::auth::principal_of;
use crate::error::ApiError;
use crate::http_util::{blob_location, created};
use crate::names::RepositoryName;
use crate::AppState;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use roci_storage::{upload_body, Digest, Storage, StorageError, UploadBody};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub(crate) struct UploadQuery {
    digest: Option<String>,
    mount: Option<String>,
    from: Option<String>,
}

pub(crate) fn upload_location(repo: &str, id: &str) -> String {
    format!("/v2/{repo}/blobs/uploads/{id}")
}

/// Common headers for an in-progress upload session.
fn upload_headers(repo: &str, id: &str, received: u64) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&upload_location(repo, id)).unwrap(),
    );
    headers.insert(
        "range",
        HeaderValue::from_str(&format!("0-{}", received.saturating_sub(1))).unwrap(),
    );
    headers
}

/// Upload-progress response with the given status code.
fn upload_progress(status: StatusCode, repo: &str, id: &str, received: u64) -> Response {
    let mut headers = upload_headers(repo, id, received);
    headers.insert("docker-upload-uuid", HeaderValue::from_str(id).unwrap());
    (status, headers).into_response()
}

/// Request body as a stream (never buffered whole, inv. 4).
fn body_stream(req: Request) -> UploadBody {
    Box::pin(
        req.into_body()
            .into_data_stream()
            .map_err(std::io::Error::other),
    )
}

#[tracing::instrument(skip_all, name = "upload.session")]
pub(crate) async fn start<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    q: UploadQuery,
    req: Request,
) -> Result<Response, ApiError> {
    // Cross-repo mount: source needs pull (no existence oracle on
    // repos the caller cannot read).
    if let (Some(mount), Some(from)) = (q.mount.as_ref(), q.from.as_ref()) {
        let source_readable = RepositoryName::parse(from).is_ok()
            && st.auth().is_none_or(|auth| {
                auth.allows(
                    principal_of(req.extensions()),
                    from,
                    roci_config::Action::Pull,
                )
            });
        if let (true, Ok(d)) = (source_readable, Digest::parse(mount)) {
            if let Ok(true) = st.storage.mount_blob(from, repo, &d).await {
                return Ok(created(&blob_location(repo, &d), &d));
            }
        }
    }

    // Monolithic upload: stream through a short-lived session.
    if let Some(digest) = q.digest {
        let d = Digest::parse(&digest)?;
        let id = st.storage.begin_upload(repo).await?;
        let limit = (st.max_body() as u64).min(st.max_upload());
        let stored = async {
            st.storage
                .append_upload(repo, &id, body_stream(req), None, limit)
                .await?;
            st.storage
                .finish_upload(repo, &id, &d, st.max_upload(), upload_body([]), 0)
                .await
        }
        .await;
        if let Err(e) = stored {
            let _ = st.storage.abort_upload(repo, &id).await;
            return Err(e.into());
        }
        return Ok(created(&blob_location(repo, &d), &d));
    }

    let id = st.storage.begin_upload(repo).await?;
    Ok(upload_progress(StatusCode::ACCEPTED, repo, &id, 0))
}

pub(crate) async fn patch<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    id: &str,
    req: Request,
) -> Result<Response, ApiError> {
    // Content-Range start offset; storage enforces atomically.
    let range_start = req
        .headers()
        .get(header::CONTENT_RANGE)
        .or_else(|| req.headers().get("content-range"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split('-').next())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let limit = st.max_body() as u64;
    let total = match st
        .storage
        .append_upload(repo, id, body_stream(req), range_start, limit)
        .await
    {
        Ok(t) => t,
        Err(StorageError::RangeNotSatisfiable { expected, .. }) => {
            return Ok((
                StatusCode::RANGE_NOT_SATISFIABLE,
                upload_headers(repo, id, expected),
            )
                .into_response());
        }
        Err(e) => return Err(ApiError::from(e)),
    };
    // Reject oversized sessions: drop staging, return 413.
    if total > st.max_upload() {
        let _ = st.storage.abort_upload(repo, id).await;
        return Err(ApiError::payload_too_large(
            "upload exceeds maximum blob size",
        ));
    }
    Ok(upload_progress(StatusCode::ACCEPTED, repo, id, total))
}

#[tracing::instrument(skip_all, name = "digest.verify")]
pub(crate) async fn finish<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    id: &str,
    q: UploadQuery,
    req: Request,
) -> Result<Response, ApiError> {
    let digest = q
        .digest
        .ok_or_else(|| ApiError::digest_invalid("missing digest on upload completion"))?;
    let d = Digest::parse(&digest)?;
    // Trailing body appended+verified under one session-lock hold.
    st.storage
        .finish_upload(
            repo,
            id,
            &d,
            st.max_upload(),
            body_stream(req),
            st.max_body() as u64,
        )
        .await?;
    Ok(created(&blob_location(repo, &d), &d))
}

pub(crate) async fn status<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    id: &str,
) -> Result<Response, ApiError> {
    let total = st.storage.upload_size(repo, id).await?;
    Ok(upload_progress(StatusCode::NO_CONTENT, repo, id, total))
}
