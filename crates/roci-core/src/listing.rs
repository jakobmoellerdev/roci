//! Tag list and referrers API, paginated with server-side cap.

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

fn page_limit(n: Option<usize>, max_page: usize) -> usize {
    n.map_or(max_page, |n| n.min(max_page))
}

pub(crate) async fn tags<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    q: TagsQuery,
) -> Result<Response, ApiError> {
    let limit = page_limit(q.n, st.max_page());
    let page = st.storage.list_tags(repo, q.last.as_deref(), limit).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // Advertise next page with RFC 5988 `Link`.
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
    // Return referrers even if subject is absent; bounded by page size.
    let limit = page_limit(q.n, st.max_page());
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
    if filter.is_some() {
        headers.insert(
            "oci-filters-applied",
            HeaderValue::from_static("artifactType"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Accept"));
    }
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

/// Insert an RFC 5988 `Link: <path?query>; rel="next"` header.
pub(crate) fn insert_next_link(headers: &mut HeaderMap, path: &str, query: &[(&str, &str)]) {
    let qs = serde_urlencoded::to_string(query).expect("str pairs always serialize");
    if let Ok(v) = HeaderValue::from_str(&format!("<{path}?{qs}>; rel=\"next\"")) {
        headers.insert(header::LINK, v);
    }
}
