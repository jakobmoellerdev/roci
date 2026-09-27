//! Manifest endpoints: GET/HEAD, PUT (validation + referrers/backrefs), DELETE.

use crate::error::{not_found_as, ApiError, ErrorCode};
use crate::http_util::{
    created, digest_value, etag_value, if_none_match_hit, not_modified, read_body_limited,
    CACHE_IMMUTABLE, DOCKER_CONTENT_DIGEST,
};
use crate::AppState;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use roci_storage::{
    digest_of, manifest_references, sha256_of, Digest, ManifestLinks, Storage,
    MEDIA_TYPE_IMAGE_MANIFEST,
};

pub(crate) const MAX_JSON_DEPTH: usize = 32;

/// Allocation-free JSON nesting-depth check.
pub(crate) fn json_depth_exceeds(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

pub(crate) fn descriptor_digest_str(value: &serde_json::Value) -> Option<&str> {
    value.as_object()?.get("digest")?.as_str()
}

/// Cache-Control: immutable by digest, no-cache by tag.
pub(crate) fn manifest_cache_control(by_digest: bool) -> HeaderValue {
    if by_digest {
        HeaderValue::from_static(CACHE_IMMUTABLE)
    } else {
        HeaderValue::from_static("no-cache")
    }
}

fn is_digest_ref(reference: &str) -> bool {
    reference.contains(':')
}

/// Compute and verify content digest against a digest reference.
/// Tag pushes hash sha256. Returns digest and optional tag.
fn content_digest<'r>(
    reference: &'r str,
    body: &[u8],
) -> Result<(Digest, Option<&'r str>), ApiError> {
    if is_digest_ref(reference) {
        let ref_digest = Digest::parse(reference)?;
        let content = digest_of(body, ref_digest.algorithm());
        if content.ct_eq(&ref_digest) {
            Ok((content, None))
        } else {
            Err(ApiError::digest_invalid(
                "manifest digest does not match reference",
            ))
        }
    } else {
        Ok((sha256_of(body), Some(reference)))
    }
}

/// CVE-2021-41190: validate `mediaType` matches Content-Type.
fn check_media_type(content_type: &str, manifest: &serde_json::Value) -> Result<(), ApiError> {
    if let Some(mt) = manifest.get("mediaType") {
        let Some(body_mt) = mt.as_str() else {
            return Err(ApiError::manifest_invalid(
                "manifest mediaType is not a string",
            ));
        };
        let bare = |s: &str| s.split(';').next().unwrap_or(s).trim().to_string();
        if bare(content_type) != bare(body_mt) {
            return Err(ApiError::manifest_invalid(
                "Content-Type does not match manifest mediaType",
            ));
        }
    }
    Ok(())
}

fn descriptor_digest(value: &serde_json::Value, kind: &str) -> Result<Digest, ApiError> {
    let s = descriptor_digest_str(value)
        .ok_or_else(|| ApiError::manifest_invalid(format!("{kind} descriptor is malformed")))?;
    Digest::parse(s).map_err(|_| ApiError::manifest_invalid(format!("{kind} digest is malformed")))
}

/// `config` + each `layers` entry digest; malformed → MANIFEST_INVALID.
fn required_blobs(manifest: &serde_json::Value) -> Result<Vec<Digest>, ApiError> {
    let mut referenced: Vec<Digest> = Vec::new();
    if let Some(cfg) = manifest.get("config") {
        referenced.push(descriptor_digest(cfg, "config")?);
    }
    if let Some(layers) = manifest.get("layers") {
        let Some(layers) = layers.as_array() else {
            return Err(ApiError::manifest_invalid(
                "manifest layers is not an array",
            ));
        };
        for layer in layers {
            referenced.push(descriptor_digest(layer, "layer")?);
        }
    }
    Ok(referenced)
}

fn referrer_descriptor(
    manifest: &serde_json::Value,
    media_type: &str,
    digest: &Digest,
    size: usize,
) -> Vec<u8> {
    let mut descriptor = serde_json::Map::new();
    descriptor.insert(
        "mediaType".into(),
        serde_json::Value::String(media_type.to_string()),
    );
    descriptor.insert(
        "digest".into(),
        serde_json::Value::String(digest.as_string()),
    );
    descriptor.insert("size".into(), serde_json::Value::Number(size.into()));
    let artifact_type = manifest
        .get("artifactType")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            manifest
                .get("config")
                .and_then(|c| c.get("mediaType"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    if let Some(at) = artifact_type {
        descriptor.insert("artifactType".into(), serde_json::Value::String(at));
    }
    if let Some(ann) = manifest.get("annotations") {
        descriptor.insert("annotations".into(), ann.clone());
    }
    serde_json::to_vec(&serde_json::Value::Object(descriptor)).unwrap_or_default()
}

#[tracing::instrument(skip_all, name = "meta.resolve")]
pub(crate) async fn get<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    reference: &str,
    head: bool,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    // Digest = immutable content; tag may be repointed.
    let by_digest = is_digest_ref(reference);
    let m = st
        .storage
        .get_manifest(repo, reference)
        .await
        .map_err(not_found_as(|| {
            ApiError::new(ErrorCode::ManifestUnknown, "manifest unknown to registry")
        }))?;
    let digest_str = m.digest.as_string();
    // ETag = manifest digest; conditional match → 304.
    if if_none_match_hit(headers, &digest_str) {
        return Ok(not_modified(&digest_str, manifest_cache_control(by_digest)));
    }
    let mut resp = HeaderMap::new();
    resp.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&m.media_type).unwrap(),
    );
    resp.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(m.bytes.len() as u64),
    );
    resp.insert(DOCKER_CONTENT_DIGEST, digest_value(&digest_str));
    resp.insert(header::ETAG, etag_value(&digest_str));
    resp.insert(header::CACHE_CONTROL, manifest_cache_control(by_digest));
    if head {
        Ok((StatusCode::OK, resp).into_response())
    } else {
        Ok((StatusCode::OK, resp, m.bytes).into_response())
    }
}

#[tracing::instrument(skip_all, name = "meta.append")]
pub(crate) async fn put<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    reference: &str,
    req: Request,
) -> Result<Response, ApiError> {
    let media_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST)
        .to_string();
    // Bound body by min(body_limit, manifest_cap).
    let max_manifest = st.max_manifest();
    let manifest_limit = st.max_body().min(max_manifest);
    let body = match read_body_limited(req, manifest_limit).await {
        Ok(b) => b,
        Err(e) if st.max_body() <= max_manifest => return Err(e),
        Err(_) => {
            return Err(ApiError::manifest_invalid(
                "manifest exceeds manifest size cap",
            ))
        }
    };
    // Reject deep nesting (SECURITY inv. 14).
    if json_depth_exceeds(&body, MAX_JSON_DEPTH) {
        return Err(ApiError::manifest_invalid("manifest JSON nesting too deep"));
    }
    let (digest, tag) = content_digest(reference, &body)?;
    // Parse manifest for subject/referrers.
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let subject_digest = parsed
        .get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|d| d.as_str())
        .and_then(|d| Digest::parse(d).ok());

    check_media_type(&media_type, &parsed)?;

    // Referenced-blob existence check (MANIFEST_BLOB_UNKNOWN).
    let referenced = required_blobs(&parsed)?;
    for d in &referenced {
        match st.storage.blob_exists(repo, d).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(ApiError::manifest_blob_unknown(format!(
                    "referenced blob {} is not present",
                    d.as_string()
                )))
            }
            Err(e) => return Err(ApiError::from(e)),
        }
    }

    // Manifest + tag + backrefs + referrer committed atomically so
    // a crash never leaves unreferenced blobs.
    let references = manifest_references(&parsed);
    let referrer = subject_digest.as_ref().map(|s| {
        (
            s,
            referrer_descriptor(&parsed, &media_type, &digest, body.len()),
        )
    });
    st.storage
        .put_manifest(
            repo,
            tag,
            &digest,
            &media_type,
            &body,
            ManifestLinks {
                references: &references,
                required: &referenced,
                subject: referrer.as_ref().map(|(s, d)| (*s, d.as_slice())),
            },
        )
        .await?;

    let mut resp = created(
        &format!("/v2/{repo}/manifests/{}", digest.as_string()),
        &digest,
    );
    if let Some(subject) = subject_digest.as_ref() {
        resp.headers_mut().insert(
            "oci-subject",
            HeaderValue::from_str(&subject.as_string()).unwrap(),
        );
    }
    Ok(resp)
}

pub(crate) async fn delete<S: Storage>(
    st: &AppState<S>,
    repo: &str,
    reference: &str,
) -> Result<Response, ApiError> {
    if !st.can_delete() {
        return Err(ApiError::new(
            ErrorCode::Unsupported,
            "the operation is unsupported",
        ));
    }
    // Resolve tag → digest; digest references are parsed directly.
    let d = if is_digest_ref(reference) {
        Digest::parse(reference)?
    } else {
        st.storage
            .get_manifest(repo, reference)
            .await
            .map_err(not_found_as(|| {
                ApiError::new(ErrorCode::ManifestUnknown, "manifest unknown to registry")
            }))?
            .digest
    };
    st.storage
        .delete_manifest(repo, &d)
        .await
        .map_err(not_found_as(|| {
            ApiError::new(ErrorCode::ManifestUnknown, "manifest unknown to registry")
        }))?;
    Ok(StatusCode::ACCEPTED.into_response())
}
