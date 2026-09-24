//! Manifest endpoints: GET/HEAD (with cache validators), PUT (digest/tag,
//! media-type + referenced-blob validation, referrers/backrefs), and DELETE.

use crate::error::{not_found_as, ApiError};
use crate::http_util::{
    created, digest_value, etag_value, if_none_match_hit, not_modified, read_body_limited,
    CACHE_IMMUTABLE, DOCKER_CONTENT_DIGEST,
};
use crate::AppState;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use roci_storage::{digest_of, sha256_of, Digest, Storage, MEDIA_TYPE_IMAGE_MANIFEST};

/// Maximum JSON nesting depth accepted in a manifest body.
pub(crate) const MAX_JSON_DEPTH: usize = 32;

/// Returns true if `bytes` contains JSON bracket/brace nesting deeper than
/// `max`. A cheap, allocation-free pre-scan that treats string literals
/// (skipping escaped quotes) as opaque so `{`/`[` inside strings don't count.
/// Non-JSON input never exceeds the limit.
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

/// The `digest` string of an OCI descriptor: `Some(&str)` only when `value` is
/// a JSON object carrying a string `digest`. A non-object descriptor, or one
/// missing a string `digest`, yields `None` — the caller treats that as a
/// malformed descriptor. A descriptor field that is entirely absent is handled
/// by the caller before calling this (an omitted `config`/`layers` is legal).
pub(crate) fn descriptor_digest_str(value: &serde_json::Value) -> Option<&str> {
    value.as_object()?.get("digest")?.as_str()
}

/// Cache-Control for a manifest read: by-digest is immutable; by-tag must be
/// revalidated (`no-cache`) since a tag can be repointed.
pub(crate) fn manifest_cache_control(by_digest: bool) -> HeaderValue {
    if by_digest {
        HeaderValue::from_static(CACHE_IMMUTABLE)
    } else {
        HeaderValue::from_static("no-cache")
    }
}

/// Whether `reference` is a digest reference (contains `:`).
fn is_digest_ref(reference: &str) -> bool {
    reference.contains(':')
}

/// Compute the content digest, verifying it against a digest reference.
/// A digest reference must match the content (hashed with the reference's
/// algorithm, constant-time); a tag hashes sha256. Returns the digest and,
/// for a tag push, the tag string.
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

/// CVE-2021-41190: a present `mediaType` must be a string equal (bare type,
/// `;`-params stripped) to Content-Type. A body with no `mediaType` skips the
/// check — never inferred.
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

/// One descriptor's digest; `kind` is "config" or "layer" →
/// "{kind} descriptor is malformed" / "{kind} digest is malformed".
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

/// Backref edges: required blobs + index children + subject.
fn backref_edges(
    manifest: &serde_json::Value,
    required: &[Digest],
    subject: Option<&Digest>,
) -> Vec<Digest> {
    let mut edges: Vec<Digest> = required.to_vec();
    if let Some(children) = manifest.get("manifests").and_then(|v| v.as_array()) {
        for child in children {
            if let Some(d) = descriptor_digest_str(child).and_then(|s| Digest::parse(s).ok()) {
                edges.push(d);
            }
        }
    }
    if let Some(subject) = subject {
        edges.push(subject.clone());
    }
    edges
}

/// Serialized referrer descriptor (mediaType, digest, size, artifactType
/// fallback to config.mediaType, annotations).
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
    // artifactType falls back to the config mediaType when absent (OCI rule).
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
    // A digest reference names immutable content; a tag can be repointed. The
    // `Accept` header is advisory — the stored media type is always returned
    // (dist-spec: the registry serves the manifest's real Content-Type).
    let by_digest = is_digest_ref(reference);
    let m = st
        .storage
        .get_manifest(repo, reference)
        .await
        .map_err(not_found_as(ApiError::manifest_unknown))?;
    let digest_str = m.digest.as_string();
    // Conditional request: the ETag is the manifest digest. For a tag,
    // a matching digest means the tag still resolves to the same content.
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
    // Bound the manifest body by the smaller of the configured request-body
    // limit and the configured manifest cap. Exceeding the body limit is
    // a 413 (payload too large); exceeding only the manifest cap is MANIFEST_INVALID.
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
    // Reject pathologically nested JSON before handing bytes to serde_json
    // (bounded-input guard; SECURITY.md inv. 14). A non-JSON body has depth 0.
    if json_depth_exceeds(&body, MAX_JSON_DEPTH) {
        return Err(ApiError::manifest_invalid("manifest JSON nesting too deep"));
    }
    let (digest, tag) = content_digest(reference, &body)?;
    // Parse the manifest to extract subject/artifactType/annotations for the
    // referrers index (best-effort; a non-JSON body simply has no subject).
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let subject_digest = parsed
        .get("subject")
        .and_then(|s| s.get("digest"))
        .and_then(|d| d.as_str())
        .and_then(|d| Digest::parse(d).ok());

    check_media_type(&media_type, &parsed)?;

    // Referenced-blob existence (MANIFEST_BLOB_UNKNOWN): for an image manifest,
    // every blob it references (its `config` and each `layers` entry) MUST be
    // present. A descriptor that is present but malformed (not an object, or no
    // string `digest`) is a bad manifest → MANIFEST_INVALID.
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

    st.storage
        .put_manifest(repo, tag, &digest, &media_type, &body)
        .await?;

    // Record the reverse edges blob→manifest so a future GC (Phase 3) can
    // reclaim an object once its last referencing manifest is deleted. Beyond
    // the config+layers checked above, also record an image index's child
    // `manifests[*]` and a `subject` descriptor — those are CAS objects a GC
    // must treat as reachable (their existence is NOT enforced here: a subject
    // may reference an absent manifest per spec, and an index child may be
    // pushed later). The backref index is a derived, rebuildable-from-the-layout
    // cache (never the source of truth), so a failed append must not fail an
    // otherwise-valid push; Phase 3 GC rebuilds/verifies before consuming it.
    let edges = backref_edges(&parsed, &referenced, subject_digest.as_ref());
    if !edges.is_empty() {
        let _ = st.storage.record_backrefs(repo, &digest, &edges).await;
    }

    if let Some(subject) = subject_digest.as_ref() {
        let descriptor_bytes = referrer_descriptor(&parsed, &media_type, &digest, body.len());
        let _ = st
            .storage
            .add_referrer(repo, subject, &digest, &descriptor_bytes)
            .await;
    }

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
        return Err(ApiError::unsupported());
    }
    // Resolve tag → digest first so tag deletions work too. A `:`-form
    // reference is a digest (grammar checked by Digest::parse → 400 on a
    // malformed digest); otherwise it is a tag resolved via storage.
    let d = if is_digest_ref(reference) {
        Digest::parse(reference)?
    } else {
        st.storage
            .get_manifest(repo, reference)
            .await
            .map_err(not_found_as(ApiError::manifest_unknown))?
            .digest
    };
    st.storage
        .delete_manifest(repo, &d)
        .await
        .map_err(not_found_as(ApiError::manifest_unknown))?;
    Ok(StatusCode::ACCEPTED.into_response())
}
