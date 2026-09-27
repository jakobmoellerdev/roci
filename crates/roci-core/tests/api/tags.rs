use axum::http::{header, StatusCode};

use super::common::*;

#[tokio::test]
async fn tags_list_pagination() {
    let (app, storage, _d) = app_with_storage();
    seed_tags(&storage, "r", &["a", "b", "c", "d"]).await;
    let resp = send(&app, get("/v2/r/tags/list?n=2")).await;
    let v = json_body(resp).await;
    assert_eq!(v["tags"], serde_json::json!(["a", "b"]));
    let resp = send(&app, get("/v2/r/tags/list?last=b")).await;
    let v = json_body(resp).await;
    assert_eq!(v["tags"], serde_json::json!(["c", "d"]));
}

#[tokio::test]
async fn tags_list_link_header_walks_all_pages() {
    let (app, storage, _d) = app_with_storage();
    seed_tags(&storage, "r", &["a", "b", "c", "d", "e"]).await;
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
    seed_tags(&storage, "r", &["a", "c"]).await;
    for (last, want) in [
        ("b", serde_json::json!(["c"])),
        ("zzz", serde_json::json!([])),
    ] {
        let resp = send(&app, get(format!("/v2/r/tags/list?last={last}"))).await;
        let v = json_body(resp).await;
        assert_eq!(v["tags"], want, "last={last}");
    }
}
