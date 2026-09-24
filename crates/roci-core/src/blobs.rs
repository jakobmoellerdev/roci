//! Blob endpoints: GET/HEAD (with Range + conditional requests), and DELETE.

use crate::error::{not_found_as, ApiError};
use crate::http_util::{
    etag_value, if_none_match_hit, not_modified, parse_byte_range, RangeOutcome, CACHE_IMMUTABLE,
    DOCKER_CONTENT_DIGEST,
};
use crate::AppState;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use roci_storage::{Digest, Storage, StorageError};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

pub(crate) async fn get<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    d: &Digest,
    head: bool,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let digest_str = d.as_string();
    // Blobs are content-addressed and therefore immutable; a client holding the
    // digest ETag needs no body (304).
    if if_none_match_hit(headers, &digest_str) {
        return Ok(not_modified(
            &digest_str,
            HeaderValue::from_static(CACHE_IMMUTABLE),
        ));
    }
    if head {
        let size = st
            .storage
            .blob_size(repo, d)
            .await
            .map_err(not_found_as(ApiError::blob_unknown))?;
        let mut resp_headers = blob_headers(&digest_str);
        resp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
        return Ok((StatusCode::OK, resp_headers).into_response());
    }
    // GET: build the (possibly ranged) streamed body. Every IO step funnels its
    // error through `?` into the single match below, so there are no separate
    // unreachable error arms for the infallible-on-a-regular-file seek/stat.
    get_body(st, repo, d, &digest_str, headers)
        .await
        .map_err(not_found_as(ApiError::blob_unknown))
}

/// Open the blob and produce its GET response — full `200`, ranged `206`, or
/// `416` — streaming the file. All IO errors propagate to the caller's single
/// error mapping (a missing blob is `NotFound`).
#[tracing::instrument(skip_all, name = "blob.open")]
async fn get_body<S: Storage>(
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
pub(crate) fn blob_headers(digest_str: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        DOCKER_CONTENT_DIGEST,
        HeaderValue::from_str(digest_str).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(header::ETAG, etag_value(digest_str));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_IMMUTABLE),
    );
    headers
}

pub(crate) async fn delete<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    d: &Digest,
) -> Result<Response, ApiError> {
    if !st.can_delete() {
        return Err(ApiError::unsupported());
    }
    st.storage
        .delete_blob(repo, d)
        .await
        .map_err(not_found_as(ApiError::blob_unknown))?;
    Ok(StatusCode::ACCEPTED.into_response())
}
