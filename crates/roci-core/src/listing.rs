//! Listing endpoints: tag list and the referrers API, both paginated with a
//! server-side cap and `Link` next-page headers.

use crate::error::ApiError;
use crate::AppState;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use roci_storage::{Digest, Storage, MEDIA_TYPE_IMAGE_INDEX};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub(crate) struct TagsQuery {
    n: Option<usize>,
    last: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct ReferrersQuery {
    #[serde(rename = "artifactType")]
    artifact_type: Option<String>,
    n: Option<usize>,
    last: Option<String>,
}

/// Maximum page size for list endpoints (tags/referrers); server-side cap.
pub(crate) const MAX_PAGE: usize = 1000;

/// Clamp an optional page-size request to the server-side cap.
fn page_limit(n: Option<usize>) -> usize {
    n.map_or(MAX_PAGE, |n| n.min(MAX_PAGE))
}

pub(crate) async fn tags<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    q: TagsQuery,
) -> Result<Response, ApiError> {
    // Clamp the requested page size to the server-side cap (SECURITY inv. 14);
    // storage seeks past `last` and returns only this page.
    let limit = page_limit(q.n);
    let page = st.storage.list_tags(repo, q.last.as_deref(), limit).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // Pagination (dist-spec end-8): when tags remain past this page, advertise
    // the next page with an RFC 5988 `Link` whose cursor is the last tag served.
    if page.more && limit > 0 {
        let cursor = page.items.last().map(String::as_str).unwrap_or_default();
        insert_next_link(
            &mut headers,
            &format!("/v2/{repo}/tags/list"),
            &[("n", &limit.to_string()), ("last", cursor)],
        );
    }
    let body = serde_json::json!({ "name": repo, "tags": page.items });
    Ok((StatusCode::OK, headers, body.to_string()).into_response())
}

pub(crate) async fn referrers<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    subject: &Digest,
    q: ReferrersQuery,
) -> Response {
    // Referrers for a subject are returned even if the subject manifest itself
    // is absent; a missing index is simply an empty list. Storage seeks past
    // the `last` cursor and applies the artifactType filter itself, so both
    // lookup and parse work are bounded by the page, never by the whole
    // referrer set (GHSA-259w-8hf6-59bj amplification class).
    let limit = page_limit(q.n);
    let filter = q.artifact_type.as_deref();
    let page = st
        .storage
        .list_referrers(repo, subject, filter, q.last.as_deref(), limit)
        .await
        .unwrap_or_default();
    let manifests: Vec<serde_json::Value> = page
        .items
        .iter()
        .filter_map(|(_, bytes)| serde_json::from_slice(bytes).ok())
        .collect();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MEDIA_TYPE_IMAGE_INDEX),
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
    if page.more && limit > 0 {
        let last_digest = page
            .items
            .last()
            .map(|(d, _)| d.as_str())
            .unwrap_or_default();
        let n = limit.to_string();
        let mut query: Vec<(&str, &str)> = vec![("n", &n), ("last", last_digest)];
        if let Some(f) = filter {
            query.push(("artifactType", f));
        }
        insert_next_link(
            &mut headers,
            &format!("/v2/{repo}/referrers/{}", subject.as_string()),
            &query,
        );
    }

    let body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_IMAGE_INDEX,
        "manifests": manifests
    });
    (StatusCode::OK, headers, body.to_string()).into_response()
}

/// Insert an RFC 5988 `Link: <path?query>; rel="next"` header. Query values are
/// form-urlencoded so cursor/filter values containing `&`, `#`, `%`, `+` or
/// spaces round-trip through the next request; a value that still cannot form
/// a header (control bytes) omits the link rather than panicking.
pub(crate) fn insert_next_link(headers: &mut HeaderMap, path: &str, query: &[(&str, &str)]) {
    let Ok(qs) = serde_urlencoded::to_string(query) else {
        return;
    };
    if let Ok(v) = HeaderValue::from_str(&format!("<{path}?{qs}>; rel=\"next\"")) {
        headers.insert(header::LINK, v);
    }
}
