use axum::http::{header, Method, StatusCode};
use roci_storage::*;

use super::common::*;

#[tokio::test]
async fn subject_manifest_appears_in_referrers() {
    let (app, _d) = app();
    let subject = sha256_of(b"the-subject");
    // A referring manifest carrying a `subject` and `artifactType`.
    let referrer = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.example.sig",
        "subject": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": subject.as_string(), "size": 11 },
        "annotations": { "org.opencontainers.image.title": "sig" }
    });
    let body = serde_json::to_vec(&referrer).unwrap();
    let rdigest = sha256_of(&body);
    let put = send(
        &app,
        request(
            Method::PUT,
            format!("/v2/r/manifests/{rdigest}"),
            &[(
                header::CONTENT_TYPE,
                "application/vnd.oci.image.manifest.v1+json",
            )],
            body,
        ),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    assert_eq!(
        hv(&put, header::HeaderName::from_static("oci-subject")).unwrap(),
        subject.as_string()
    );

    // The referrers index for the subject lists exactly this manifest.
    let get_resp = send(&app, get(format!("/v2/r/referrers/{subject}"))).await;
    assert_eq!(
        hv(&get_resp, header::CONTENT_TYPE).unwrap(),
        "application/vnd.oci.image.index.v1+json"
    );
    let idx = json_body(get_resp).await;
    assert_eq!(idx["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(idx["manifests"][0]["digest"], rdigest.as_string());
    assert_eq!(
        idx["manifests"][0]["artifactType"],
        "application/vnd.example.sig"
    );

    // Filtering by a non-matching artifactType yields an empty, filter-applied index.
    let filtered = send(
        &app,
        get(format!(
            "/v2/r/referrers/{}?artifactType=application/vnd.other",
            subject.as_string()
        )),
    )
    .await;
    assert_eq!(
        hv(
            &filtered,
            header::HeaderName::from_static("oci-filters-applied")
        )
        .unwrap(),
        "artifactType"
    );
    let idx = json_body(filtered).await;
    assert_eq!(idx["manifests"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn referrers_pagination_filter_link_and_vary() {
    let (app, storage, _d) = app_with_storage();
    let subject = sha256_of(b"subject");
    let mut sigs = Vec::new();
    for i in 0..5u8 {
        let r = sha256_of(&[i]);
        let at = if i % 2 == 0 {
            "application/sig"
        } else {
            "application/sbom"
        };
        if at == "application/sig" {
            sigs.push(r.as_string());
        }
        let desc = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": r.as_string(),
            "size": 1,
            "artifactType": at,
        });
        storage
            .add_referrer("r", &subject, &r, desc.to_string().as_bytes())
            .await
            .unwrap();
    }
    // Unfiltered: no Vary, no filter header, full list.
    let resp = send(&app, get(format!("/v2/r/referrers/{subject}"))).await;
    assert!(resp.headers().get(header::VARY).is_none());
    assert!(resp.headers().get(header::LINK).is_none());
    // Filtered + paged: walk every page via Link; collect only sigs.
    let mut url = format!(
        "/v2/r/referrers/{}?artifactType=application/sig&n=2",
        subject.as_string()
    );
    let mut seen = Vec::new();
    loop {
        let resp = send(&app, get(&url)).await;
        assert_eq!(resp.headers().get(header::VARY).unwrap(), "Accept");
        assert_eq!(
            resp.headers().get("oci-filters-applied").unwrap(),
            "artifactType"
        );
        let link = resp
            .headers()
            .get(header::LINK)
            .map(|v| v.to_str().unwrap().to_string());
        let v = json_body(resp).await;
        let page = v["manifests"].as_array().unwrap();
        assert!(page.len() <= 2);
        for m in page {
            seen.push(m["digest"].as_str().unwrap().to_string());
        }
        match link {
            Some(l) => url = l[1..l.find('>').unwrap()].to_string(),
            None => break,
        }
    }
    // Pages walk the referrer set in digest order.
    sigs.sort();
    assert_eq!(seen, sigs);
}

#[tokio::test]
async fn next_link_encodes_query_values_and_round_trips() {
    let (app, storage, _d) = app_with_storage();
    let subject = sha256_of(b"subject");
    let at = "application/vnd.x+json; a=b&c#d%";
    for i in 0..3u8 {
        let r = sha256_of(&[i, 9]);
        let desc = serde_json::json!({"digest": r.as_string(), "artifactType": at});
        storage
            .add_referrer("r", &subject, &r, desc.to_string().as_bytes())
            .await
            .unwrap();
    }
    let first = format!(
        "/v2/r/referrers/{}?n=1&{}",
        subject.as_string(),
        serde_urlencoded::to_string([("artifactType", at)]).unwrap()
    );
    let mut url = first;
    let mut pages = 0;
    loop {
        let resp = send(&app, get(&url)).await;
        let link = resp
            .headers()
            .get(header::LINK)
            .map(|v| v.to_str().unwrap().to_string());
        let v = json_body(resp).await;
        // The filter survives every hop: each page still has its one match.
        assert_eq!(v["manifests"].as_array().unwrap().len(), 1);
        pages += 1;
        match link {
            Some(l) => url = l[1..l.find('>').unwrap()].to_string(),
            None => break,
        }
    }
    assert_eq!(pages, 3);
}

#[tokio::test]
async fn referrers_bad_digest_is_400() {
    let (app, _d) = app();
    assert_eq!(
        status_of(&app, get("/v2/r/referrers/notadigest")).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn referrer_artifact_type_falls_back_to_config_media_type() {
    let (app, _d) = app();
    let subject = sha256_of(b"sub");
    let referrer = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": { "mediaType": "application/vnd.example.config", "digest": sha256_of(b"c").as_string(), "size": 1 },
        "subject": { "digest": subject.as_string() }
    });
    let body = serde_json::to_vec(&referrer).unwrap();
    let rd = sha256_of(&body);
    // The config blob the manifest references must exist (referenced-blob
    // existence is enforced on push); upload it monolithically first.
    push_blob(&app, "r", b"c").await;
    push_manifest(
        &app,
        "r",
        &rd.as_string(),
        "application/vnd.oci.image.manifest.v1+json",
        &body,
    )
    .await;
    let resp = send(&app, get(format!("/v2/r/referrers/{subject}"))).await;
    let idx = json_body(resp).await;
    assert_eq!(
        idx["manifests"][0]["artifactType"],
        "application/vnd.example.config"
    );
}

#[tokio::test]
async fn referrer_without_artifact_type_or_config() {
    let (app, _d) = app();
    let subject = sha256_of(b"s2");
    let referrer = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "subject": { "digest": subject.as_string() }
    });
    let body = serde_json::to_vec(&referrer).unwrap();
    let rd = sha256_of(&body);
    push_manifest(
        &app,
        "r",
        &rd.as_string(),
        "application/vnd.oci.image.manifest.v1+json",
        &body,
    )
    .await;
    let resp = send(&app, get(format!("/v2/r/referrers/{subject}"))).await;
    let idx = json_body(resp).await;
    assert!(idx["manifests"][0].get("artifactType").is_none());
}
