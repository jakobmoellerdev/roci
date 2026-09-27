#![allow(dead_code)]
//! Backend-generic storage test suite.
//! Each `case_*` exercises one Storage trait operation against any backend.
//! Cases use distinct repo names so one store can be shared within a group.

use roci_storage::{sha256_of, upload_body, Digest, ManifestLinks, Storage, StorageError};

fn manifest(config: &Digest, layers: &[&Digest], subject: Option<&Digest>) -> Vec<u8> {
    let layers_json: Vec<serde_json::Value> = layers
        .iter()
        .map(|d| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": d.as_string(),
                "size": 100
            })
        })
        .collect();
    let mut m = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config.as_string(),
            "size": 10
        },
        "layers": layers_json
    });
    if let Some(s) = subject {
        m.as_object_mut().unwrap().insert(
            "subject".into(),
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": s.as_string(),
                "size": 100
            }),
        );
    }
    serde_json::to_vec(&m).unwrap()
}

pub async fn case_put_and_read_blob<S: Storage>(s: &S) {
    let data: Vec<u8> = (0..=255u8).collect();
    let digest = sha256_of(&data);
    s.put_blob("suite-put-read", &digest, &data).await.unwrap();
    let read = s.read_blob("suite-put-read", &digest).await.unwrap();
    assert_eq!(read, data, "put_and_read_blob: round-trip");
}

pub async fn case_blob_exists_and_size<S: Storage>(s: &S) {
    let data = b"test data";
    let digest = sha256_of(data);
    assert!(
        !s.blob_exists("suite-exists", &digest).await.unwrap(),
        "blob_exists_and_size: absent"
    );
    s.put_blob("suite-exists", &digest, data).await.unwrap();
    assert!(
        s.blob_exists("suite-exists", &digest).await.unwrap(),
        "blob_exists_and_size: present"
    );
    assert_eq!(
        s.blob_size("suite-exists", &digest).await.unwrap(),
        data.len() as u64,
        "blob_exists_and_size: size"
    );
}

pub async fn case_blob_not_found_cross_repo<S: Storage>(s: &S) {
    let data = b"isolated";
    let digest = sha256_of(data);
    s.put_blob("suite-cross-a", &digest, data).await.unwrap();
    assert!(
        !s.blob_exists("suite-cross-b", &digest).await.unwrap(),
        "blob_not_found_cross_repo: exists"
    );
    assert!(
        matches!(
            s.blob_size("suite-cross-b", &digest).await,
            Err(StorageError::NotFound)
        ),
        "blob_not_found_cross_repo: size"
    );
}

pub async fn case_put_blob_digest_mismatch<S: Storage>(s: &S) {
    let data = b"real content";
    let wrong = sha256_of(b"other content");
    let err = s
        .put_blob("suite-mismatch", &wrong, data)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::DigestMismatch { .. }),
        "put_blob_digest_mismatch"
    );
}

pub async fn case_delete_blob<S: Storage>(s: &S) {
    let data = b"delete me";
    let digest = sha256_of(data);
    s.put_blob("suite-del-blob", &digest, data).await.unwrap();
    assert!(
        s.blob_exists("suite-del-blob", &digest).await.unwrap(),
        "delete_blob: present before"
    );
    s.delete_blob("suite-del-blob", &digest).await.unwrap();
    assert!(
        !s.blob_exists("suite-del-blob", &digest).await.unwrap(),
        "delete_blob: gone after"
    );
}

pub async fn case_chunked_upload_flow<S: Storage>(s: &S) {
    let data = b"chunk-a-chunk-b";
    let digest = sha256_of(data);

    let id = s.begin_upload("suite-chunked").await.unwrap();
    let size_a = s
        .append_upload(
            "suite-chunked",
            &id,
            upload_body(b"chunk-a-"),
            Some(0),
            u64::MAX,
        )
        .await
        .unwrap();
    assert_eq!(size_a, 8, "chunked_upload_flow: first chunk size");
    let size_b = s
        .append_upload(
            "suite-chunked",
            &id,
            upload_body(b"chunk-b"),
            Some(8),
            u64::MAX,
        )
        .await
        .unwrap();
    assert_eq!(size_b, 15, "chunked_upload_flow: total size");
    assert_eq!(
        s.upload_size("suite-chunked", &id).await.unwrap(),
        15,
        "chunked_upload_flow: upload_size"
    );

    s.finish_upload(
        "suite-chunked",
        &id,
        &digest,
        1024 * 1024,
        upload_body(b""),
        u64::MAX,
    )
    .await
    .unwrap();
    let read = s.read_blob("suite-chunked", &digest).await.unwrap();
    assert_eq!(read, data, "chunked_upload_flow: read back");
}

pub async fn case_monolithic_upload<S: Storage>(s: &S) {
    let data = b"monolithic body";
    let digest = sha256_of(data);
    let id = s.begin_upload("suite-mono").await.unwrap();
    s.finish_upload(
        "suite-mono",
        &id,
        &digest,
        1024 * 1024,
        upload_body(data),
        u64::MAX,
    )
    .await
    .unwrap();
    let read = s.read_blob("suite-mono", &digest).await.unwrap();
    assert_eq!(read, data, "monolithic_upload: read back");
}

pub async fn case_upload_range_mismatch<S: Storage>(s: &S) {
    let id = s.begin_upload("suite-range").await.unwrap();
    s.append_upload("suite-range", &id, upload_body(b"abc"), Some(0), u64::MAX)
        .await
        .unwrap();
    let err = s
        .append_upload("suite-range", &id, upload_body(b"def"), Some(0), u64::MAX)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::RangeNotSatisfiable { .. }),
        "upload_range_mismatch"
    );
}

pub async fn case_upload_too_large<S: Storage>(s: &S) {
    let data = b"some data here!!!"; // 17 bytes
    let digest = sha256_of(data);
    let id = s.begin_upload("suite-toolarge").await.unwrap();
    s.append_upload("suite-toolarge", &id, upload_body(data), None, u64::MAX)
        .await
        .unwrap();
    let err = s
        .finish_upload(
            "suite-toolarge",
            &id,
            &digest,
            10,
            upload_body(b""),
            u64::MAX,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::TooLarge { .. }),
        "upload_too_large"
    );
}

pub async fn case_upload_digest_mismatch<S: Storage>(s: &S) {
    let id = s.begin_upload("suite-digmis").await.unwrap();
    s.append_upload("suite-digmis", &id, upload_body(b"real"), None, u64::MAX)
        .await
        .unwrap();
    let wrong = sha256_of(b"wrong");
    let err = s
        .finish_upload(
            "suite-digmis",
            &id,
            &wrong,
            1024 * 1024,
            upload_body(b""),
            u64::MAX,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::DigestMismatch { .. }),
        "upload_digest_mismatch"
    );
}

pub async fn case_abort_upload<S: Storage>(s: &S) {
    let id = s.begin_upload("suite-abort").await.unwrap();
    s.append_upload("suite-abort", &id, upload_body(b"data"), None, u64::MAX)
        .await
        .unwrap();
    assert!(
        s.abort_upload("suite-abort", &id).await.unwrap(),
        "abort_upload: first"
    );
    assert!(
        !s.abort_upload("suite-abort", &id).await.unwrap(),
        "abort_upload: idempotent"
    );
}

pub async fn case_put_and_get_manifest<S: Storage>(s: &S) {
    let config_data = b"config";
    let config_digest = sha256_of(config_data);
    s.put_blob("suite-manifest", &config_digest, config_data)
        .await
        .unwrap();

    let layer_data = b"layer-data";
    let layer_digest = sha256_of(layer_data);
    s.put_blob("suite-manifest", &layer_digest, layer_data)
        .await
        .unwrap();

    let m = manifest(&config_digest, &[&layer_digest], None);
    let md = sha256_of(&m);
    let refs: Vec<Digest> = vec![config_digest.clone(), layer_digest.clone()];
    s.put_manifest(
        "suite-manifest",
        Some("latest"),
        &md,
        "application/vnd.oci.image.manifest.v1+json",
        &m,
        ManifestLinks {
            references: &refs,
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    let by_tag = s.get_manifest("suite-manifest", "latest").await.unwrap();
    assert_eq!(by_tag.bytes, m, "put_and_get_manifest: by tag bytes");
    assert_eq!(by_tag.digest, md, "put_and_get_manifest: by tag digest");

    let by_digest = s
        .get_manifest("suite-manifest", &md.as_string())
        .await
        .unwrap();
    assert_eq!(by_digest.bytes, m, "put_and_get_manifest: by digest");
}

pub async fn case_delete_manifest<S: Storage>(s: &S) {
    let config_data = b"config-dm";
    let cd = sha256_of(config_data);
    s.put_blob("suite-del-m", &cd, config_data).await.unwrap();

    let m = manifest(&cd, &[], None);
    let md = sha256_of(&m);
    s.put_manifest(
        "suite-del-m",
        Some("v1"),
        &md,
        "application/vnd.oci.image.manifest.v1+json",
        &m,
        ManifestLinks {
            references: std::slice::from_ref(&cd),
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    s.delete_manifest("suite-del-m", &md).await.unwrap();
    assert!(
        matches!(
            s.get_manifest("suite-del-m", "v1").await,
            Err(StorageError::NotFound)
        ),
        "delete_manifest: tag gone"
    );
}

pub async fn case_list_tags_pagination<S: Storage>(s: &S) {
    for tag in ["a", "b", "c"] {
        let data = format!("tag-data-{tag}");
        let cd = sha256_of(data.as_bytes());
        s.put_blob("suite-tags", &cd, data.as_bytes())
            .await
            .unwrap();
        let m = manifest(&cd, &[], None);
        let md = sha256_of(&m);
        s.put_manifest(
            "suite-tags",
            Some(tag),
            &md,
            "application/vnd.oci.image.manifest.v1+json",
            &m,
            ManifestLinks {
                references: &[cd],
                required: &[],
                subject: None,
            },
        )
        .await
        .unwrap();
    }

    let page1 = s.list_tags("suite-tags", None, 2).await.unwrap();
    assert_eq!(page1.items, vec!["a", "b"], "list_tags_pagination: page1");
    assert!(page1.more, "list_tags_pagination: page1 more");

    let page2 = s.list_tags("suite-tags", Some("b"), 2).await.unwrap();
    assert_eq!(page2.items, vec!["c"], "list_tags_pagination: page2");
    assert!(!page2.more, "list_tags_pagination: page2 done");
}

pub async fn case_referrers_recorded_and_paginated<S: Storage>(s: &S) {
    let subject_data = b"subject";
    let cd = sha256_of(subject_data);
    s.put_blob("suite-ref", &cd, subject_data).await.unwrap();
    let subject_manifest = manifest(&cd, &[], None);
    let subject_digest = sha256_of(&subject_manifest);
    s.put_manifest(
        "suite-ref",
        Some("base"),
        &subject_digest,
        "application/vnd.oci.image.manifest.v1+json",
        &subject_manifest,
        ManifestLinks {
            references: std::slice::from_ref(&cd),
            required: &[],
            subject: None,
        },
    )
    .await
    .unwrap();

    let ref_config = b"ref-config";
    let ref_cd = sha256_of(ref_config);
    s.put_blob("suite-ref", &ref_cd, ref_config).await.unwrap();
    let referrer_manifest = manifest(&ref_cd, &[], Some(&subject_digest));
    let referrer_digest = sha256_of(&referrer_manifest);
    let descriptor = serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": referrer_digest.as_string(),
        "size": referrer_manifest.len(),
        "artifactType": "application/example"
    });
    let descriptor_bytes = serde_json::to_vec(&descriptor).unwrap();

    s.put_manifest(
        "suite-ref",
        None,
        &referrer_digest,
        "application/vnd.oci.image.manifest.v1+json",
        &referrer_manifest,
        ManifestLinks {
            references: &[ref_cd, subject_digest.clone()],
            required: &[],
            subject: Some((&subject_digest, &descriptor_bytes)),
        },
    )
    .await
    .unwrap();

    let page = s
        .list_referrers("suite-ref", &subject_digest, None, None, 100)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1, "referrers_recorded: count");
    assert_eq!(
        page.items[0].0,
        referrer_digest.as_string(),
        "referrers_recorded: digest"
    );
}

pub async fn case_mount_blob_cross_repo<S: Storage>(s: &S) {
    let data = b"shared blob";
    let digest = sha256_of(data);
    s.put_blob("suite-mount-a", &digest, data).await.unwrap();
    assert!(
        s.mount_blob("suite-mount-a", "suite-mount-b", &digest)
            .await
            .unwrap(),
        "mount_blob_cross_repo: mounted"
    );
    let read = s.read_blob("suite-mount-b", &digest).await.unwrap();
    assert_eq!(read, data, "mount_blob_cross_repo: read back");
}

pub async fn case_mount_blob_absent_source<S: Storage>(s: &S) {
    let digest = sha256_of(b"missing");
    assert!(
        !s.mount_blob("suite-mabs-a", "suite-mabs-b", &digest)
            .await
            .unwrap(),
        "mount_blob_absent_source"
    );
}

pub async fn case_mount_same_repo_noop<S: Storage>(s: &S) {
    let data = b"same-repo";
    let digest = sha256_of(data);
    s.put_blob("suite-msame", &digest, data).await.unwrap();
    assert!(
        s.mount_blob("suite-msame", "suite-msame", &digest)
            .await
            .unwrap(),
        "mount_same_repo_noop"
    );
}

pub async fn case_rejects_traversal_in_repo<S: Storage>(s: &S) {
    let digest = sha256_of(b"x");
    assert!(
        matches!(
            s.blob_exists("../etc", &digest).await,
            Err(StorageError::BadPath(_))
        ),
        "rejects_traversal_in_repo"
    );
}

pub async fn case_quota_repo_byte_cap<S: Storage>(s: &S) {
    let data = b"twelve bytes"; // 12 bytes
    let digest = sha256_of(data);
    s.put_blob("suite-qbyte", &digest, data).await.unwrap();

    let big_data = b"this is a big blob that exceeds twenty bytes of quota";
    let big_digest = sha256_of(big_data);
    let err = s
        .put_blob("suite-qbyte", &big_digest, big_data)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::QuotaExceeded { .. }),
        "quota_repo_byte_cap"
    );
}

pub async fn case_quota_session_cap<S: Storage>(s: &S) {
    let _id1 = s.begin_upload("suite-qsess").await.unwrap();
    let err = s.begin_upload("suite-qsess").await.unwrap_err();
    assert!(
        matches!(err, StorageError::TooManySessions { .. }),
        "quota_session_cap"
    );
}
