use super::common::store;
use roci_storage::*;

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
    // Tags a/b→d, other→different: delete d, "other" survives.
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
    assert_eq!(
        s.list_tags("r", None, usize::MAX).await.unwrap().items,
        vec!["other".to_string()]
    );
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
    // Tag-schema fallback: index under `<alg>-<hex>` tag lists the referrer.
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

/// Push a manifest under the log engine, then reopen with lmdb — the tag
/// resolves immediately from the migrated metadata, without waiting for the
/// background `index.json` writer.
#[cfg(feature = "lmdb")]
#[tokio::test]
async fn metadata_engine_switch_preserves_tag() {
    use roci_config::{MetadataEngine, StorageConfig};
    use roci_storage::quota::QuotaTracker;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let body = br#"{"schemaVersion":2}"#;
    let d = roci_storage::sha256_of(body);

    // Push under log engine.
    {
        let config = StorageConfig::default();
        assert_eq!(config.metadata.engine, MetadataEngine::Log);
        let s = roci_storage::FsStorage::with_config(
            dir.path(),
            &config,
            Arc::new(QuotaTracker::default()),
        )
        .unwrap();
        s.put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/vnd.oci.image.manifest.v1+json",
            body,
            roci_storage::ManifestLinks::default(),
        )
        .await
        .unwrap();
    }

    // Reopen with lmdb — don't start maintenance / index writer.
    {
        let mut config = StorageConfig::default();
        config.metadata.engine = MetadataEngine::Lmdb;
        let s = roci_storage::FsStorage::with_config(
            dir.path(),
            &config,
            Arc::new(QuotaTracker::default()),
        )
        .unwrap();
        // The tag should resolve from the migrated metadata.
        let m = s.get_manifest("r", "v1").await.unwrap();
        assert_eq!(m.digest, d);
        assert_eq!(m.bytes, body);
    }
}

#[tokio::test]
async fn generic_manifest_cases() {
    let (_dir, s) = store();
    super::suite::case_put_and_get_manifest(&s).await;
    super::suite::case_delete_manifest(&s).await;
    super::suite::case_list_tags_pagination(&s).await;
    super::suite::case_referrers_recorded_and_paginated(&s).await;
}

#[tokio::test]
async fn generic_quota_cases() {
    use roci_storage::quota::{QuotaLimits, QuotaTracker};
    let dir = tempfile::tempdir().unwrap();
    let config = roci_config::StorageConfig {
        root: dir.path().to_path_buf(),
        ..Default::default()
    };
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 20,
        max_total_bytes: 0,
        max_upload_sessions: 1,
    });
    let s = roci_storage::FsStorage::with_config(dir.path(), &config, std::sync::Arc::new(quota))
        .unwrap();
    super::suite::case_quota_repo_byte_cap(&s).await;
    // Need a fresh store for session cap (separate upload namespace).
    let dir2 = tempfile::tempdir().unwrap();
    let config2 = roci_config::StorageConfig {
        root: dir2.path().to_path_buf(),
        ..Default::default()
    };
    let quota2 = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 0,
        max_total_bytes: 0,
        max_upload_sessions: 1,
    });
    let s2 =
        roci_storage::FsStorage::with_config(dir2.path(), &config2, std::sync::Arc::new(quota2))
            .unwrap();
    super::suite::case_quota_session_cap(&s2).await;
}
