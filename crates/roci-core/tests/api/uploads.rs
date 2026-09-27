use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use roci_config::Config;
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn chunked_upload_and_manifest_tag_flow() {
    let (app, _d) = app();
    let loc = start_session(&app, "r").await;

    let resp = send(&app, patch(&loc, "hello")).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let d = sha256_of(b"hello");
    let put_uri = format!("{loc}?digest={}", d.as_string());
    let resp = send(&app, put(&put_uri, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
    let mdigest = sha256_of(manifest);
    let resp = send(
        &app,
        request(
            Method::PUT,
            "/v2/r/manifests/v1",
            &[(
                header::CONTENT_TYPE,
                "application/vnd.oci.image.manifest.v1+json",
            )],
            manifest.to_vec(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        hv(&resp, "docker-content-digest".parse().unwrap()).unwrap(),
        mdigest.as_string()
    );

    let resp = send(&app, get("/v2/r/tags/list")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["tags"], serde_json::json!(["v1"]));

    let resp = send(&app, delete("/v2/r/manifests/v1")).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn out_of_order_chunk_is_416() {
    let (app, _d) = app();
    let loc = start_session(&app, "r").await;
    let resp = send(
        &app,
        request(
            Method::PATCH,
            &loc,
            &[(header::CONTENT_RANGE, "5-9")],
            "hello",
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
}

#[tokio::test]
async fn cross_mount_present_and_absent() {
    let (app, storage, _d) = app_with_storage();
    let data = b"mountable";
    let d = sha256_of(data);
    storage.put_blob("src", &d, data).await.unwrap();
    let uri = format!("/v2/dest/blobs/uploads/?mount={d}&from=src");
    let resp = send(&app, post(&uri, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        hv(&resp, "docker-content-digest".parse().unwrap()).unwrap(),
        d.as_string()
    );
    let absent = sha256_of(b"nope");
    let uri = format!(
        "/v2/dest/blobs/uploads/?mount={}&from=elsewhere",
        absent.as_string()
    );
    let resp = send(&app, post(&uri, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert!(resp.headers().get("docker-upload-uuid").is_some());
}

#[tokio::test]
async fn upload_status_and_finish_errors() {
    let (app, _d) = app();
    let loc = start_session(&app, "r").await;
    let resp = send(&app, get(&loc)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.headers().get("range").is_some());
    assert_eq!(
        status_of(&app, put(&loc, Body::empty())).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status_of(&app, put(format!("{loc}?digest=notadigest"), Body::empty())).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status_of(&app, get("/v2/r/blobs/uploads/ghost")).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn monolithic_upload_with_bad_digest() {
    let (app, _d) = app();
    assert_eq!(
        status_of(&app, post("/v2/r/blobs/uploads/?digest=notadigest", "x")).await,
        StatusCode::BAD_REQUEST
    );
    let wrong = sha256_of(b"other");
    assert_eq!(
        status_of(
            &app,
            post(format!("/v2/r/blobs/uploads/?digest={wrong}"), "x")
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn upload_start_without_trailing_slash() {
    let (app, _d) = app();
    let resp = send(&app, post("/v2/r/blobs/uploads", Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert!(resp.headers().get("docker-upload-uuid").is_some());
}

#[tokio::test]
async fn patch_and_finish_on_directory_session_error() {
    let (app, dir) = app();
    let session = dir.path().join("r").join("uploads").join("dirsess");
    std::fs::create_dir_all(&session).unwrap();
    let resp = send(&app, patch("/v2/r/blobs/uploads/dirsess", "data")).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let d = sha256_of(b"data");
    let resp = send(
        &app,
        put(
            format!("/v2/r/blobs/uploads/dirsess?digest={d}"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_with_valid_content_range_appends() {
    let (app, _d) = app();
    let loc = start_session(&app, "r").await;
    let resp = send(
        &app,
        request(
            Method::PATCH,
            &loc,
            &[(header::CONTENT_RANGE, "0-4")],
            "hello",
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(hv(&resp, header::RANGE).unwrap(), "0-4");
}

#[tokio::test]
async fn oversized_bodies_are_413() {
    let mut cfg = Config::default();
    cfg.limits.max_body = 4;
    cfg.limits.max_manifest = 4;
    let (app, _d) = app_with_config(cfg);
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                "/v2/r/manifests/t",
                &[(header::CONTENT_TYPE, "application/json")],
                "way too many bytes"
            )
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let d = sha256_of(b"way too many bytes");
    assert_eq!(
        status_of(
            &app,
            post(
                format!("/v2/r/blobs/uploads/?digest={d}"),
                "way too many bytes"
            )
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let loc = start_session(&app, "r").await;
    assert_eq!(
        status_of(&app, patch(&loc, "way too many bytes")).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        status_of(
            &app,
            put(
                format!("{loc}?digest={}", d.as_string()),
                "way too many bytes"
            )
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn broken_uploads_dir_surfaces_on_first_write() {
    let (app, _d) = app_broken_uploads();
    let resp = send(&app, post("/v2/r/blobs/uploads/", Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        status_of(&app, patch(&loc, "x")).await,
        StatusCode::NOT_FOUND
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
        status_of(&app, patch("/v2/r/blobs/uploads/sess", "x")).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn monolithic_finish_error_is_404_and_leaves_no_session() {
    let (app, dir) = app();
    let repo = dir.path().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("blobs"), b"file").unwrap();
    let data = b"payload";
    let d = sha256_of(data);
    let uri = format!("/v2/r/blobs/uploads/?digest={d}");
    let resp = send(&app, post(&uri, data.to_vec())).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let uploads = repo.join("uploads");
    let left = std::fs::read_dir(&uploads).map(|d| d.count()).unwrap_or(0);
    assert_eq!(left, 0, "aborted monolithic session must not linger");
}

#[tokio::test]
async fn mount_put_blob_failure_falls_through() {
    let (app, storage, dir) = app_with_storage();
    let data = b"mountme";
    let d = sha256_of(data);
    storage.put_blob("src", &d, data).await.unwrap();
    let dest = dir.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("blobs"), b"file").unwrap();
    let uri = format!("/v2/dest/blobs/uploads/?mount={d}&from=src");
    let resp = send(&app, post(&uri, Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn mount_with_malformed_digest_falls_through() {
    let (app, _d) = app();
    let resp = send(
        &app,
        post(
            "/v2/dest/blobs/uploads/?mount=notadigest&from=src",
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn finish_upload_variants() {
    let (app, _d) = app();
    for (label, req) in [
        ("chunked finish with trailing body", {
            let loc = start_session(&app, "r").await;
            let d = sha256_of(b"trailing");
            put(format!("{loc}?digest={}", d.as_string()), "trailing")
        }),
        ("monolithic with body", {
            let data = b"mono-body";
            let d = sha256_of(data);
            post(format!("/v2/r/blobs/uploads/?digest={d}"), data.to_vec())
        }),
        ("monolithic empty body", {
            let d = sha256_of(b"");
            post(format!("/v2/r/blobs/uploads/?digest={d}"), Body::empty())
        }),
    ] {
        let resp = send(&app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{label}");
    }
}

#[tokio::test]
async fn session_cap_exceeded_is_413_on_all_upload_paths() {
    let mut cfg = Config::default();
    cfg.limits.max_upload = 4;
    let (app, _d) = app_with_config(cfg);

    // Chunked PATCH exceeding the cap.
    let loc = start_session(&app, "r").await;
    let resp = send(&app, patch(&loc, "too many bytes")).await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "chunked patch"
    );
    let v = json_body(resp).await;
    assert_eq!(v["errors"][0]["code"], "SIZE_INVALID", "chunked patch");
    // The session was dropped.
    assert_eq!(
        status_of(&app, get(&loc)).await,
        StatusCode::NOT_FOUND,
        "session dropped"
    );

    let loc2 = start_session(&app, "r").await;
    let d = sha256_of(b"too many bytes");
    let resp = send(
        &app,
        put(format!("{loc2}?digest={}", d.as_string()), "too many bytes"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE, "finish put");
    let v = json_body(resp).await;
    assert_eq!(v["errors"][0]["code"], "SIZE_INVALID", "finish put");

    let data = b"way over the four byte cap";
    let d = sha256_of(data);
    let resp = send(
        &app,
        post(format!("/v2/r/blobs/uploads/?digest={d}"), data.to_vec()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "monolithic post"
    );
    let v = json_body(resp).await;
    assert_eq!(v["errors"][0]["code"], "SIZE_INVALID", "monolithic post");
}
