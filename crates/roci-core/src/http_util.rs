//! HTTP helpers: Range parsing, conditional requests, bounded body reads.
use crate::error::ApiError;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use roci_storage::Digest;

/// Parsed outcome of a `Range` header against a known content `size`.
pub(crate) enum RangeOutcome {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
}

/// Parse a single-range `bytes=` header (RFC 9110) against `size`.
pub(crate) fn parse_byte_range(headers: &HeaderMap, size: u64) -> RangeOutcome {
    let Some(raw) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return RangeOutcome::Full;
    };
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (start, end) = match (start_s.trim(), end_s.trim()) {
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
        (start, "") => {
            let Ok(start) = start.parse::<u64>() else {
                return RangeOutcome::Full;
            };
            (start, size.saturating_sub(1))
        }
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

/// Whether `If-None-Match` matches the ETag.
pub(crate) fn if_none_match_hit(headers: &HeaderMap, digest: &str) -> bool {
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

pub(crate) const DOCKER_CONTENT_DIGEST: &str = "docker-content-digest";

pub(crate) const CACHE_IMMUTABLE: &str = "max-age=31536000, immutable";

pub(crate) fn digest_value(digest: &str) -> HeaderValue {
    HeaderValue::from_str(digest).unwrap()
}

pub(crate) fn etag_value(digest: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{digest}\"")).unwrap()
}

pub(crate) fn not_modified(digest: &str, cache_control: HeaderValue) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, etag_value(digest));
    headers.insert(header::CACHE_CONTROL, cache_control);
    (StatusCode::NOT_MODIFIED, headers).into_response()
}

pub(crate) fn created(location: &str, digest: &Digest) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_str(location).unwrap());
    headers.insert(DOCKER_CONTENT_DIGEST, digest_value(&digest.as_string()));
    (StatusCode::CREATED, headers).into_response()
}

pub(crate) fn blob_location(repo: &str, d: &Digest) -> String {
    format!("/v2/{repo}/blobs/{d}")
}

pub(crate) async fn read_body_limited(req: Request, limit: usize) -> Result<Vec<u8>, ApiError> {
    use axum::body::to_bytes;
    let body = req.into_body();
    match to_bytes(body, limit).await {
        Ok(b) => Ok(b.to_vec()),
        Err(_) => Err(ApiError::payload_too_large("request body too large")),
    }
}
