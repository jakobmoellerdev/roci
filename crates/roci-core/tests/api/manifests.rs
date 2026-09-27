use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn put_manifest_by_digest_match_and_mismatch() {
    let (app, _d) = app();
    let m = br#"{"schemaVersion":2}"#;
    let md = sha256_of(m);
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                format!("/v2/r/manifests/{md}"),
                &[(header::CONTENT_TYPE, "application/json")],
                m.to_vec(),
            ),
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                format!("/v2/r/manifests/sha256:{}", md.hex().to_ascii_uppercase()),
                &[(header::CONTENT_TYPE, "application/json")],
                m.to_vec(),
            ),
        )
        .await,
        StatusCode::CREATED
    );
    let wrong = sha256_of(b"other");
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                format!("/v2/r/manifests/{wrong}"),
                &[(header::CONTENT_TYPE, "application/json")],
                m.to_vec(),
            ),
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    let v = body_json_of(
        &app,
        request(
            Method::PUT,
            "/v2/r/manifests/sha256:short",
            &[(header::CONTENT_TYPE, "application/json")],
            m.to_vec(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "DIGEST_INVALID");
}

#[tokio::test]
async fn manifest_over_fixed_cap_is_manifest_invalid() {
    let (app, _d) = app();
    let over = vec![b'x'; 4 * 1024 * 1024 + 1 /* MAX_MANIFEST (4 MiB) + 1 */];
    let resp = send(
        &app,
        request(
            Method::PUT,
            "/v2/r/manifests/t",
            &[(header::CONTENT_TYPE, "application/json")],
            over,
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn manifest_json_depth_capped() {
    let (app, _d) = app();
    let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
    let v = body_json_of(
        &app,
        request(
            Method::PUT,
            "/v2/ok/manifests/t",
            &[(header::CONTENT_TYPE, "application/json")],
            deep,
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
}

#[tokio::test]
async fn manifest_with_escaped_quote_accepted() {
    let (app, _d) = app();
    let body = br#"{"schemaVersion":2,"annotations":{"k":"a\"b"}}"#;
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                "/v2/ok/manifests/t",
                &[(header::CONTENT_TYPE, "application/json")],
                body.to_vec(),
            ),
        )
        .await,
        StatusCode::CREATED
    );
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
            ManifestLinks::default(),
        )
        .await
        .unwrap();
    let resp = send(&app, get("/v2/r/manifests/t")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(&body[..], m);
}

#[tokio::test]
async fn manifest_cache_control_and_conditional() {
    let (app, storage, _d) = app_with_storage();
    let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
    let d = sha256_of(body);
    storage
        .put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/vnd.oci.image.manifest.v1+json",
            body,
            ManifestLinks::default(),
        )
        .await
        .unwrap();
    let etag = format!("\"{d}\"");

    let by_digest = format!("/v2/r/manifests/{d}");
    let resp = send(&app, get(&by_digest)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        hv(&resp, header::CACHE_CONTROL),
        Some("max-age=31536000, immutable")
    );
    assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));

    let resp = send(
        &app,
        request(
            Method::GET,
            &by_digest,
            &[(header::IF_NONE_MATCH, &etag)],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        hv(&resp, header::CACHE_CONTROL),
        Some("max-age=31536000, immutable")
    );

    let resp = send(&app, get("/v2/r/manifests/v1")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hv(&resp, header::CACHE_CONTROL), Some("no-cache"));
    assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));
    let resp = send(
        &app,
        request(
            Method::GET,
            "/v2/r/manifests/v1",
            &[(header::ACCEPT, "application/json")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        hv(&resp, header::CONTENT_TYPE),
        Some("application/vnd.oci.image.manifest.v1+json")
    );

    let resp = send(
        &app,
        request(
            Method::HEAD,
            "/v2/r/manifests/v1",
            &[(header::IF_NONE_MATCH, &etag)],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(hv(&resp, header::CACHE_CONTROL), Some("no-cache"));
}

#[tokio::test]
async fn manifest_content_type_must_match_media_type() {
    let (app, _d) = app();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json"
    });
    let body = serde_json::to_vec(&manifest).unwrap();
    let v = body_json_of(
        &app,
        request(
            Method::PUT,
            "/v2/r/manifests/v1",
            &[(
                header::CONTENT_TYPE,
                "application/vnd.oci.image.index.v1+json",
            )],
            body.clone(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                "/v2/r/manifests/v1",
                &[(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json; charset=utf-8"
                )],
                body,
            ),
        )
        .await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn manifest_referencing_absent_blob_is_manifest_blob_unknown() {
    let (app, _d) = app();
    let cfg = sha256_of(b"cfg");
    let layer = sha256_of(b"layer");
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg.as_string(), "size": 3 },
        "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer.as_string(), "size": 5 } ]
    });
    let body = serde_json::to_vec(&manifest).unwrap();
    let resp = send(
        &app,
        request(
            Method::PUT,
            "/v2/r/manifests/v1",
            &[(
                header::CONTENT_TYPE,
                "application/vnd.oci.image.manifest.v1+json",
            )],
            body.clone(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
    push_blob(&app, "r", b"cfg").await;
    push_blob(&app, "r", b"layer").await;
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                "/v2/r/manifests/v1",
                &[(
                    header::CONTENT_TYPE,
                    "application/vnd.oci.image.manifest.v1+json"
                )],
                body,
            ),
        )
        .await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn manifest_malformed_referenced_digests_are_manifest_invalid() {
    let (app, _d) = app();
    let ct = "application/vnd.oci.image.manifest.v1+json";
    let cases: &[(&str, serde_json::Value)] = &[
        (
            "bad config digest",
            serde_json::json!({
                "schemaVersion": 2, "mediaType": ct,
                "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:notavaliddigest", "size": 1 }
            }),
        ),
        (
            "bad layer digest",
            serde_json::json!({
                "schemaVersion": 2, "mediaType": ct,
                "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:zzzz", "size": 1 }]
            }),
        ),
        (
            "layer missing digest",
            serde_json::json!({
                "schemaVersion": 2, "mediaType": ct,
                "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": 0 }]
            }),
        ),
        (
            "config not an object",
            serde_json::json!({
                "schemaVersion": 2, "mediaType": ct, "config": "not-a-descriptor"
            }),
        ),
        (
            "non-string mediaType",
            serde_json::json!({ "schemaVersion": 2, "mediaType": 123 }),
        ),
        (
            "non-array layers",
            serde_json::json!({
                "schemaVersion": 2, "mediaType": ct, "layers": "not-an-array"
            }),
        ),
    ];
    for (i, (label, body)) in cases.iter().enumerate() {
        let tag = format!("v{}", i + 1);
        let v = body_json_of(
            &app,
            manifest_put(
                format!("/v2/r/manifests/{tag}"),
                ct,
                serde_json::to_vec(body).unwrap(),
            ),
        )
        .await;
        assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID", "{label}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn manifest_blob_existence_io_error_is_500() {
    use std::os::unix::fs::PermissionsExt;
    let (app, storage, dir) = app_with_storage();
    let cfg_data = b"cfg";
    let cfg = sha256_of(cfg_data);
    storage.put_blob("r", &cfg, cfg_data).await.unwrap();
    let alg_dir = dir.path().join("r").join("blobs").join("sha256");
    std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg.as_string(), "size": 3 }
    });
    let status = status_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v1",
            "application/vnd.oci.image.manifest.v1+json",
            serde_json::to_vec(&manifest).unwrap(),
        ),
    )
    .await;
    std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_manifest_by_tag_and_digest_and_errors() {
    let (app, storage, _d) = app_with_storage();
    let m = br#"{"schemaVersion":2}"#;
    let md = sha256_of(m);
    storage
        .put_manifest(
            "r",
            Some("v1"),
            &md,
            "application/json",
            m,
            ManifestLinks::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        status_of(&app, delete("/v2/r/manifests/v1")).await,
        StatusCode::ACCEPTED
    );
    storage
        .put_manifest(
            "r",
            Some("v1"),
            &md,
            "application/json",
            m,
            ManifestLinks::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        status_of(&app, delete(format!("/v2/r/manifests/{md}"))).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        status_of(&app, delete("/v2/r/manifests/sha256:short")).await,
        StatusCode::BAD_REQUEST
    );
    let ghost = sha256_of(b"ghost-manifest");
    let v = body_json_of(&app, delete(format!("/v2/r/manifests/{ghost}"))).await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
    assert_eq!(
        status_of(&app, delete("/v2/r/manifests/ghost")).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn delete_manifest_by_tag_io_error_maps_to_500() {
    let (app, dir) = app();
    std::fs::create_dir_all(dir.path().join("r").join("index.json")).unwrap();
    let resp = send(&app, delete("/v2/r/manifests/t")).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_manifest_non_directory_cas_parent_is_404() {
    let (app, dir) = app();
    let b_dir = dir.path().join("r").join("blobs");
    std::fs::create_dir_all(&b_dir).unwrap();
    std::fs::write(b_dir.join("sha256"), b"not a dir").unwrap();
    let d = sha256_of(b"x");
    let resp = send(&app, delete(format!("/v2/r/manifests/{d}"))).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[cfg(unix)]
#[tokio::test]
async fn delete_manifest_readonly_parent_is_500() {
    use std::os::unix::fs::PermissionsExt as _;
    let (app, storage, dir) = app_with_storage();
    let d = sha256_of(b"present-manifest");
    storage
        .put_blob("r", &d, b"present-manifest")
        .await
        .unwrap();
    let alg = dir.path().join("r").join("blobs").join("sha256");
    std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o500)).unwrap();
    let resp = send(&app, delete(format!("/v2/r/manifests/{d}"))).await;
    let _ = std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755));
    assert!(matches!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR | StatusCode::ACCEPTED
    ));
}

#[tokio::test]
async fn put_manifest_storage_error_is_500() {
    let (app, dir) = app();
    let repo = dir.path().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("blobs"), b"file").unwrap();
    let m = br#"{"schemaVersion":2}"#;
    assert_eq!(
        status_of(
            &app,
            request(
                Method::PUT,
                "/v2/r/manifests/t",
                &[(header::CONTENT_TYPE, "application/json")],
                m.to_vec(),
            ),
        )
        .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn image_index_records_child_and_subject_backrefs() {
    let (app, storage, _d) = app_with_storage();
    let child_a = sha256_of(b"child-a");
    let child_b = sha256_of(b"child-b");
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": child_a.as_string(), "size": 1 },
            { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": child_b.as_string(), "size": 1 }
        ]
    });
    let body = serde_json::to_vec(&index).unwrap();
    let idx_digest = sha256_of(&body);
    push_manifest(
        &app,
        "r",
        "idx",
        "application/vnd.oci.image.index.v1+json",
        &body,
    )
    .await;
    assert_eq!(
        storage.backrefs("r", &child_a),
        vec![idx_digest.as_string()]
    );
    assert_eq!(
        storage.backrefs("r", &child_b),
        vec![idx_digest.as_string()]
    );
}

#[tokio::test]
async fn manifest_subject_is_recorded_as_backref() {
    let (app, storage, _d) = app_with_storage();
    let subject = sha256_of(b"the-subject");
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "subject": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": subject.as_string(), "size": 2 }
    });
    let body = serde_json::to_vec(&manifest).unwrap();
    let m_digest = sha256_of(&body);
    push_manifest(
        &app,
        "r",
        "art",
        "application/vnd.oci.image.manifest.v1+json",
        &body,
    )
    .await;
    assert_eq!(storage.backrefs("r", &subject), vec![m_digest.as_string()]);
}
