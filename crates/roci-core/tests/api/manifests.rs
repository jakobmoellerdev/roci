use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn put_manifest_by_digest_match_and_mismatch() {
    let (app, _d) = app();
    let m = br#"{"schemaVersion":2}"#;
    let md = sha256_of(m);
    // Matching digest reference → 201.
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
    // Uppercase-hex digest reference still matches (Digest canonicalizes to
    // lowercase; the compare parses both) → 201.
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
    // Mismatched digest reference → 400.
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
    // A `:`-form reference that is a *malformed* digest → 400 DIGEST_INVALID.
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
    // Default app (256 MiB body limit); a manifest larger than the fixed
    // 4 MiB cap → 400 MANIFEST_INVALID (distinct from the configured-limit
    // 413 path).
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
    // 40 levels of nested arrays exceeds MAX_JSON_DEPTH (32) → MANIFEST_INVALID.
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
    // A backslash-escaped quote inside a JSON string exercises the escape
    // branch of json_depth_exceeds; the manifest is well-formed and stored.
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
        )
        .await
        .unwrap();
    let etag = format!("\"{d}\"");

    // By-digest GET → immutable cache + ETag.
    let by_digest = format!("/v2/r/manifests/{d}");
    let resp = send(&app, get(&by_digest)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        hv(&resp, header::CACHE_CONTROL),
        Some("max-age=31536000, immutable")
    );
    assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));

    // By-digest If-None-Match → 304.
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

    // By-tag GET → no-cache (revalidate), but still carries an ETag.
    let resp = send(&app, get("/v2/r/manifests/v1")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hv(&resp, header::CACHE_CONTROL), Some("no-cache"));
    assert_eq!(hv(&resp, header::ETAG), Some(etag.as_str()));
    // Accept mismatch is advisory: still 200 with the stored Content-Type.
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

    // By-tag If-None-Match with the current digest → 304 + no-cache (HEAD).
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
    // Body declares an image-manifest mediaType; request Content-Type is an
    // index — the CVE-2021-41190 disagreement → 400 MANIFEST_INVALID.
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
    // Matching Content-Type (params tolerated) → accepted (201).
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
    // The config/layer blobs were never uploaded → 400 MANIFEST_BLOB_UNKNOWN.
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
    // Upload the referenced blobs, then the same manifest is accepted.
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

fn manifest_put(
    uri: impl AsRef<str>,
    ct: &str,
    body: impl Into<Body>,
) -> axum::http::Request<Body> {
    request(Method::PUT, uri, &[(header::CONTENT_TYPE, ct)], body)
}

#[tokio::test]
async fn manifest_malformed_referenced_digests_are_manifest_invalid() {
    let (app, _d) = app();
    let ct = "application/vnd.oci.image.manifest.v1+json";
    // A malformed config digest → MANIFEST_INVALID.
    let bad_config = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": ct,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:notavaliddigest", "size": 1 }
    });
    let v = body_json_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v1",
            ct,
            serde_json::to_vec(&bad_config).unwrap(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    // A malformed layer digest → MANIFEST_INVALID.
    let bad_layer = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": ct,
        "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:zzzz", "size": 1 } ]
    });
    let v = body_json_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v2",
            ct,
            serde_json::to_vec(&bad_layer).unwrap(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    // A layer descriptor with no `digest` is malformed → MANIFEST_INVALID.
    let no_digest_layer = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": ct,
        "layers": [ { "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": 0 } ]
    });
    let v = body_json_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v3",
            ct,
            serde_json::to_vec(&no_digest_layer).unwrap(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    // A non-object config descriptor is likewise malformed → MANIFEST_INVALID.
    let bad_config_shape = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": ct,
        "config": "not-a-descriptor"
    });
    let v = body_json_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v4",
            ct,
            serde_json::to_vec(&bad_config_shape).unwrap(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    // A present but non-string `mediaType` must not bypass the CVE-2021-41190
    // agreement check → MANIFEST_INVALID.
    let non_string_mt = serde_json::json!({ "schemaVersion": 2, "mediaType": 123 });
    let v = body_json_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v5",
            ct,
            serde_json::to_vec(&non_string_mt).unwrap(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
    // A present but non-array `layers` is malformed → MANIFEST_INVALID.
    let non_array_layers = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": ct,
        "layers": "not-an-array"
    });
    let v = body_json_of(
        &app,
        manifest_put(
            "/v2/r/manifests/v6",
            ct,
            serde_json::to_vec(&non_array_layers).unwrap(),
        ),
    )
    .await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_INVALID");
}

#[cfg(unix)]
#[tokio::test]
async fn manifest_blob_existence_io_error_is_500() {
    // A referenced blob that is present (so the presence filter waves it
    // through to the filesystem) but whose CAS directory is unreadable
    // yields a non-NotFound IO error from blob_exists → 500.
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
    // Restore perms so the tempdir cleans up.
    std::fs::set_permissions(&alg_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_manifest_by_tag_and_digest_and_errors() {
    let (app, storage, _d) = app_with_storage();
    let m = br#"{"schemaVersion":2}"#;
    let md = sha256_of(m);
    storage
        .put_manifest("r", Some("v1"), &md, "application/json", m)
        .await
        .unwrap();
    // Delete by tag.
    assert_eq!(
        status_of(&app, delete("/v2/r/manifests/v1")).await,
        StatusCode::ACCEPTED
    );
    // Re-store and delete by digest.
    storage
        .put_manifest("r", Some("v1"), &md, "application/json", m)
        .await
        .unwrap();
    assert_eq!(
        status_of(&app, delete(format!("/v2/r/manifests/{md}"))).await,
        StatusCode::ACCEPTED
    );
    // Delete by an invalid digest reference → 400.
    assert_eq!(
        status_of(&app, delete("/v2/r/manifests/sha256:short")).await,
        StatusCode::BAD_REQUEST
    );
    // Delete a nonexistent manifest *by digest* → 404 MANIFEST_UNKNOWN
    // (not NAME_UNKNOWN).
    let ghost = sha256_of(b"ghost-manifest");
    let v = body_json_of(&app, delete(format!("/v2/r/manifests/{ghost}"))).await;
    assert_eq!(v["errors"][0]["code"], "MANIFEST_UNKNOWN");
    // Delete an absent tag → 404.
    assert_eq!(
        status_of(&app, delete("/v2/r/manifests/ghost")).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn delete_manifest_by_absent_digest_is_404() {
    let (app, _d) = app();
    let absent = sha256_of(b"absent-manifest");
    assert_eq!(
        status_of(&app, delete(format!("/v2/r/manifests/{absent}"))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn delete_manifest_by_tag_io_error_maps_to_500() {
    // `<repo>/index.json` as a directory makes tag→digest resolution fail
    // with a non-NotFound IO error (read_index), exercising the Io arm on
    // the delete-by-tag path.
    let (app, dir) = app();
    std::fs::create_dir_all(dir.path().join("r").join("index.json")).unwrap();
    let resp = send(&app, delete("/v2/r/manifests/t")).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_manifest_non_directory_cas_parent_is_404() {
    // `<repo>/blobs/sha256` as a regular file makes the beneath-root dirfd
    // walk refuse to descend into it (ENOTDIR → treated as absent), so a
    // delete of `.../sha256/<hex>` reports the manifest simply not found
    // (404 MANIFEST_UNKNOWN) rather than a 500 — a symlinked/broken CAS
    // parent can never redirect the deletion outside the store. A genuine IO
    // error (e.g. EACCES) still surfaces as 500 via unlink_beneath.
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
    // A genuine IO error (EACCES from a read-only CAS `<alg>` parent, not a
    // symlink/broken-parent NotFound) on the unlink surfaces as 500, not a
    // false 404. Runs as the unprivileged test user (root bypasses modes).
    use std::os::unix::fs::PermissionsExt as _;
    let (app, storage, dir) = app_with_storage();
    let d = sha256_of(b"present-manifest");
    // Put the manifest, then make its `<alg>` dir read-only so unlink fails.
    storage
        .put_blob("r", &d, b"present-manifest")
        .await
        .unwrap();
    let alg = dir.path().join("r").join("blobs").join("sha256");
    std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o500)).unwrap();
    let resp = send(&app, delete(format!("/v2/r/manifests/{d}"))).await;
    let _ = std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755));
    // Unprivileged: EACCES → 500. Privileged (root): unlink succeeds → 202.
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
    // put_manifest writes the manifest to the CAS first; `<repo>/blobs` as a
    // file makes that write fail, exercising the handler's 500 mapping.
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
    // Pushing an image index records a backref edge from each child manifest
    // digest to the index; a manifest with a subject records the subject
    // edge. Neither child nor subject existence is enforced (they may be
    // pushed later / a subject may be absent per spec).
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
    // Each child carries a backref to the index manifest.
    assert_eq!(
        storage.backrefs("r", &child_a).await.unwrap(),
        vec![idx_digest.as_string()]
    );
    assert_eq!(
        storage.backrefs("r", &child_b).await.unwrap(),
        vec![idx_digest.as_string()]
    );
}

#[tokio::test]
async fn manifest_subject_is_recorded_as_backref() {
    let (app, storage, _d) = app_with_storage();
    let subject = sha256_of(b"the-subject");
    // An artifact-style manifest with no config/layers but a subject.
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
    assert_eq!(
        storage.backrefs("r", &subject).await.unwrap(),
        vec![m_digest.as_string()]
    );
}
