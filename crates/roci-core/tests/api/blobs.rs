use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn monolithic_push_then_pull_blob() {
    let (app, _d) = app();
    let data = b"layer-bytes";
    let d = push_blob(&app, "myorg/app", data).await;
    let resp = send(&app, get(format!("/v2/myorg/app/blobs/{d}"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(&body[..], data);
}

#[tokio::test]
async fn unknown_blob_is_404() {
    let (app, _d) = app();
    let d = sha256_of(b"absent");
    assert_eq!(
        status_of(&app, get(format!("/v2/r/blobs/{d}"))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn missing_blob_is_blob_unknown() {
    let (app, _d) = app();
    let d = sha256_of(b"absent");
    let v = body_json_of(&app, get(format!("/v2/ok/blobs/{d}"))).await;
    assert_eq!(v["errors"][0]["code"], "BLOB_UNKNOWN");
}

#[tokio::test]
async fn non_allowlisted_digest_rejected() {
    let (app, _d) = app();
    let v = body_json_of(&app, get("/v2/ok/blobs/sha1:deadbeef")).await;
    assert_eq!(v["errors"][0]["code"], "DIGEST_INVALID");
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
            post(format!("/v2/r/blobs/uploads/?digest={bd}"), blob.to_vec()),
        )
        .await,
        StatusCode::CREATED
    );
    let m = br#"{"schemaVersion":2}"#;
    let md = roci_storage::digest_of(m, "sha512");
    push_manifest(&app, "r", &md.to_string(), "application/json", m).await;
}

#[tokio::test]
async fn head_blob_and_manifest() {
    let (app, storage, _d) = app_with_storage();
    let data = b"blobdata";
    let d = sha256_of(data);
    storage.put_blob("r", &d, data).await.unwrap();
    // HEAD blob → 200 with content-length + digest, no body.
    let resp = send(&app, head(format!("/v2/r/blobs/{d}"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ds = d.to_string();
    assert_eq!(
        hv(
            &resp,
            header::HeaderName::from_static("docker-content-digest")
        ),
        Some(ds.as_str())
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
            ManifestLinks::default(),
        )
        .await
        .unwrap();
    let resp = send(&app, head("/v2/r/manifests/t")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // HEAD absent blob/manifest → 404.
    let absent = sha256_of(b"absent");
    assert_eq!(
        status_of(&app, head(format!("/v2/r/blobs/{absent}"))).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_of(&app, head("/v2/r/manifests/nope")).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn delete_blob_success_and_absent() {
    let (app, storage, _d) = app_with_storage();
    let data = b"todelete";
    let d = sha256_of(data);
    storage.put_blob("r", &d, data).await.unwrap();
    assert_eq!(
        status_of(&app, delete(format!("/v2/r/blobs/{d}"))).await,
        StatusCode::ACCEPTED
    );
    // Deleting again → 404. Also a malformed digest → 400.
    assert_eq!(
        status_of(&app, delete(format!("/v2/r/blobs/{d}"))).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_of(&app, delete("/v2/r/blobs/notadigest")).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn delete_blob_io_error_maps_to_500() {
    // Make `<repo>/blobs/<alg>/<hex>` a directory so remove_file yields a
    // non-NotFound IO error, exercising delete_blob's Io → 500 arm.
    let (app, dir) = app();
    let d = sha256_of(b"x");
    let blob_dir = dir
        .path()
        .join("r")
        .join("blobs")
        .join("sha256")
        .join(d.hex());
    std::fs::create_dir_all(&blob_dir).unwrap();
    let resp = send(&app, delete(format!("/v2/r/blobs/{d}"))).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn blob_and_manifest_io_errors_map_to_500() {
    // A *present* blob (recorded in the presence filter) whose CAS directory
    // is made unreadable yields a non-NotFound IO error (EACCES) on both the
    // HEAD stat and GET open paths, exercising get_blob's Io → 500 arms. The
    // filter guards *absence*, so the blob must actually exist for the read
    // to reach the filesystem.
    let (app, storage, dir) = app_with_storage();
    let data = b"present";
    let d = sha256_of(data);
    storage.put_blob("r", &d, data).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let alg_dir = dir.path().join("r").join("blobs").join("sha256");
        std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let uri = format!("/v2/r/blobs/{d}");
        for req in [get(&uri), head(&uri)] {
            assert_eq!(
                status_of(&app, req).await,
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
        status_of(&app, get(format!("/v2/r2/manifests/{d}"))).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn absent_blob_is_404_even_with_malformed_cas() {
    // The presence filter answers a definite absence without touching the
    // filesystem, so a blob the registry never stored is a clean 404 even
    // when the CAS path underneath is malformed (here `<repo>/blobs/sha256`
    // is a file). This pins the filter's absence guarantee.
    let (app, dir) = app();
    let alg_dir = dir.path().join("r").join("blobs");
    std::fs::create_dir_all(&alg_dir).unwrap();
    std::fs::write(alg_dir.join("sha256"), b"not a dir").unwrap();
    let d = sha256_of(b"x");
    assert_eq!(
        status_of(&app, get(format!("/v2/r/blobs/{d}"))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn get_blob_with_bad_digest_is_400() {
    let (app, _d) = app();
    assert_eq!(
        status_of(&app, get("/v2/r/blobs/notadigest")).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn blob_range_requests() {
    let (app, storage, _d) = app_with_storage();
    let data = b"0123456789"; // 10 bytes
    let d = sha256_of(data);
    storage.put_blob("r", &d, data).await.unwrap();
    let uri = format!("/v2/r/blobs/{d}");

    // Closed range 2-5 → 206, 4 bytes "2345".
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::RANGE, "bytes=2-5")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 2-5/10"));
    assert_eq!(hv(&resp, header::CONTENT_LENGTH), Some("4"));
    assert_eq!(hv(&resp, header::ACCEPT_RANGES), Some("bytes"));
    let body = body_bytes(resp).await;
    assert_eq!(&body[..], b"2345");

    // Suffix range -3 → last 3 bytes "789".
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::RANGE, "bytes=-3")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 7-9/10"));
    let body = body_bytes(resp).await;
    assert_eq!(&body[..], b"789");

    // Open-ended range 7- → bytes 7..9, clamped to end.
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::RANGE, "bytes=7-")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 7-9/10"));

    // Overlong end clamps to the last byte.
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::RANGE, "bytes=8-99")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes 8-9/10"));

    // Unsatisfiable (start ≥ size) → 416 + Content-Range: bytes */10.
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::RANGE, "bytes=10-20")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(hv(&resp, header::CONTENT_RANGE), Some("bytes */10"));

    // A zero-length suffix is unsatisfiable.
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::RANGE, "bytes=-0")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
}

#[tokio::test]
async fn blob_ignored_ranges_serve_full() {
    let (app, storage, _d) = app_with_storage();
    let data = b"0123456789";
    let d = sha256_of(data);
    storage.put_blob("r", &d, data).await.unwrap();
    let uri = format!("/v2/r/blobs/{d}");
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
        let resp = send(
            &app,
            request(Method::GET, &uri, &[(header::RANGE, range)], Body::empty()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "range {range}");
        assert_eq!(hv(&resp, header::ACCEPT_RANGES), Some("bytes"));
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], data, "range {range}");
    }
    // No Range header at all → full 200 with immutable cache validators.
    let resp = send(&app, get(&uri)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        hv(&resp, header::CACHE_CONTROL),
        Some("max-age=31536000, immutable")
    );
    assert_eq!(hv(&resp, header::ETAG), Some(format!("\"{d}\"").as_str()));
}

#[tokio::test]
async fn blob_conditional_get_and_head() {
    let (app, storage, _d) = app_with_storage();
    let data = b"cacheable";
    let d = sha256_of(data);
    storage.put_blob("r", &d, data).await.unwrap();
    let uri = format!("/v2/r/blobs/{d}");
    let etag = format!("\"{d}\"");

    // HEAD advertises ranges + immutable cache + ETag.
    let resp = send(&app, head(&uri)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hv(&resp, header::ACCEPT_RANGES), Some("bytes"));
    assert_eq!(hv(&resp, header::CONTENT_LENGTH), Some("9"));
    assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));

    // If-None-Match matching the digest ETag → 304 (GET and HEAD).
    for method in [Method::GET, Method::HEAD] {
        let req = request(
            method.clone(),
            &uri,
            &[(header::IF_NONE_MATCH, etag.as_str())],
            Body::empty(),
        );
        let resp = send(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED, "{method}");
        assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));
        let body = body_bytes(resp).await;
        assert!(body.is_empty(), "304 has no body ({method})");
    }
    // A `*` If-None-Match also short-circuits to 304.
    let resp = send(
        &app,
        request(
            Method::GET,
            &uri,
            &[(header::IF_NONE_MATCH, "*")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
}
