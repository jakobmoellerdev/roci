use super::common::store;
use roci_storage::*;

#[tokio::test]
async fn manifest_tag_resolution_and_delete() {
    let (_dir, s) = store();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    s.put_manifest(
        "r",
        Some("v1"),
        &d,
        "application/vnd.oci.image.manifest.v1+json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    let by_tag = s.get_manifest("r", "v1").await.unwrap();
    assert_eq!(by_tag.digest, d);
    let by_digest = s.get_manifest("r", &d.as_string()).await.unwrap();
    assert_eq!(by_digest.bytes, body);
    assert_eq!(
        s.list_tags("r", None, usize::MAX).await.unwrap().items,
        vec!["v1".to_string()]
    );
    s.delete_manifest("r", &d).await.unwrap();
    assert!(matches!(
        s.get_manifest("r", "v1").await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn empty_repo_lists_no_tags() {
    let (_dir, s) = store();
    assert!(s
        .list_tags("brand-new", None, usize::MAX)
        .await
        .unwrap()
        .items
        .is_empty());
}

#[tokio::test]
async fn delete_manifest_removes_pointing_tag() {
    let (_dir, s) = store();
    let body = br#"{"schemaVersion":2}"#;
    let d = sha256_of(body);
    // Tags "a"/"b" point at d; "other" points at a different digest and
    // must survive (covers the retain predicate's keep branch).
    let other = sha256_of(b"different");
    s.put_manifest(
        "r",
        Some("a"),
        &d,
        "application/json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    s.put_manifest(
        "r",
        Some("b"),
        &d,
        "application/json",
        body,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    s.put_manifest(
        "r",
        Some("other"),
        &other,
        "application/json",
        b"different",
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    s.delete_manifest("r", &d).await.unwrap();
    // "a" and "b" removed; "other" remains.
    assert_eq!(
        s.list_tags("r", None, usize::MAX).await.unwrap().items,
        vec!["other".to_string()]
    );
    // Re-pushing the same (tag, digest) is idempotent (dedup keeps one entry).
    s.put_manifest(
        "r",
        Some("other"),
        &other,
        "application/json",
        b"different",
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        s.list_tags("r", None, usize::MAX).await.unwrap().items,
        vec!["other".to_string()]
    );
    // Deleting an untagged manifest in a fresh repo touches no tags.
    let d2 = sha256_of(b"lonely");
    s.put_manifest(
        "solo",
        None,
        &d2,
        "application/json",
        b"lonely",
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    // Untagged re-push is a no-op (dedup by digest).
    s.put_manifest(
        "solo",
        None,
        &d2,
        "application/json",
        b"lonely",
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    s.delete_manifest("solo", &d2).await.unwrap();
    assert!(s
        .list_tags("solo", None, usize::MAX)
        .await
        .unwrap()
        .items
        .is_empty());
}

#[tokio::test]
async fn tag_schema_fallback_skips_malformed_digests() {
    let (_dir, s) = store();
    let subject = sha256_of(b"subj");
    let good = sha256_of(b"good");
    let idx = serde_json::json!({"schemaVersion": 2, "manifests": [
        {"digest": "not-a-digest"}, "junk", {"digest": good.as_string()}
    ]})
    .to_string();
    let id = sha256_of(idx.as_bytes());
    let tag = format!("sha256-{}", &subject.as_string()[7..]);
    s.put_manifest(
        "r",
        Some(&tag),
        &id,
        "application/vnd.oci.image.index.v1+json",
        idx.as_bytes(),
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    let listed = s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items;
    assert_eq!(listed.len(), 1);
}

#[tokio::test]
async fn referrers_roundtrip_and_empty() {
    let (_dir, s) = store();
    let subject = sha256_of(b"subject");
    let referrer = sha256_of(b"referrer");
    // Empty before anything is recorded.
    assert!(s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items
        .is_empty());
    s.put_manifest(
        "r",
        None,
        &referrer,
        "application/json",
        b"referrer",
        ManifestLinks {
            references: &[],
            required: &[],
            subject: Some((&subject, br#"{"digest":"x"}"#)),
        },
    )
    .await
    .unwrap();
    let listed = s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items;
    assert_eq!(listed.len(), 1);
    // The subject link is merged into the stored descriptor.
    let parsed: serde_json::Value = serde_json::from_slice(&listed[0].1).unwrap();
    assert_eq!(parsed.get("digest").and_then(|v| v.as_str()), Some("x"));
    assert_eq!(
        parsed
            .get("subject")
            .and_then(|v| v.get("digest"))
            .and_then(|v| v.as_str()),
        Some(subject.as_string().as_str())
    );
}

#[tokio::test]
async fn referrers_tag_schema_fallback() {
    let (_dir, s) = store();
    let subject = sha256_of(b"subject-without-api-referrers");
    let referrer = sha256_of(b"legacy-sig");
    // A client on a non-referrers registry pushed an index under the
    // `<alg>-<hex>` tag listing the referrer (dist-spec tag-schema fallback).
    let fallback = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json",
             "digest": referrer.as_string(), "size": 10, "artifactType": "a/sig"},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json",
             "digest": referrer.as_string(), "size": 10, "artifactType": "a/sig"}
        ]
    })
    .to_string();
    let fd = sha256_of(fallback.as_bytes());
    let tag = format!("sha256-{}", &subject.as_string()[7..]);
    s.put_manifest(
        "r",
        Some(&tag),
        &fd,
        "application/vnd.oci.image.index.v1+json",
        fallback.as_bytes(),
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    let listed = s
        .list_referrers("r", &subject, None, None, usize::MAX)
        .await
        .unwrap()
        .items;
    assert_eq!(listed.len(), 1, "de-duplicated by digest");
    let d: serde_json::Value = serde_json::from_slice(&listed[0].1).unwrap();
    assert_eq!(d["digest"], referrer.as_string());
    // A malformed body under the fallback tag yields no referrers.
    let other = sha256_of(b"other-subject");
    let junk = b"not json";
    let jd = sha256_of(junk);
    let tag2 = format!("sha256-{}", &other.as_string()[7..]);
    s.put_manifest(
        "r",
        Some(&tag2),
        &jd,
        "application/json",
        junk,
        ManifestLinks::default(),
    )
    .await
    .unwrap();
    assert!(s
        .list_referrers("r", &other, None, None, usize::MAX)
        .await
        .unwrap()
        .items
        .is_empty());
}
