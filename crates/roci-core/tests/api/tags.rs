use axum::http::{header, StatusCode};
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn tags_list_page_size_is_capped() {
    let (app, storage, _d) = app_with_storage();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    for t in ["a", "b", "c", "d"] {
        storage
            .put_manifest("r", Some(t), &d, "application/json", body)
            .await
            .unwrap();
    }
    let v = body_json_of(&app, get("/v2/r/tags/list?n=2")).await;
    assert_eq!(v["tags"].as_array().unwrap().len(), 2);
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
    let resp = send(&app, get("/v2/r/tags/list?n=2")).await;
    let v = json_body(resp).await;
    assert_eq!(v["tags"], serde_json::json!(["a", "b"]));
    // last offsets past the named tag.
    let resp = send(&app, get("/v2/r/tags/list?last=b")).await;
    let v = json_body(resp).await;
    assert_eq!(v["tags"], serde_json::json!(["c", "d"]));
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
        let resp = send(&app, get(&url)).await;
        let link = hv(&resp, header::LINK).map(str::to_string);
        let v = json_body(resp).await;
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
async fn tags_list_storage_error_is_500() {
    let (app, _d) = app_with_broken_repo();
    assert_eq!(
        status_of(&app, get("/v2/r/tags/list")).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn tags_list_last_not_in_list() {
    let (app, storage, _d) = app_with_storage();
    let m = br#"{"schemaVersion":2}"#;
    let md = sha256_of(m);
    for t in ["a", "c"] {
        storage
            .put_manifest("r", Some(t), &md, "application/json", m)
            .await
            .unwrap();
    }
    // A cursor that no longer names a tag (e.g. deleted between pages)
    // still resumes lexically after it (dist-spec end-8b), never restarts.
    for (last, want) in [
        ("b", serde_json::json!(["c"])),
        ("zzz", serde_json::json!([])),
    ] {
        let resp = send(&app, get(format!("/v2/r/tags/list?last={last}"))).await;
        let v = json_body(resp).await;
        assert_eq!(v["tags"], want, "last={last}");
    }
}
