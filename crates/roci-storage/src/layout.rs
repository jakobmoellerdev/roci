//! OCI image-layout helpers: constants, descriptor accessors, in-memory paging.

use crate::metadata::{self, MetaOp, MetadataStore, Page, Referrer};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// `oci-layout` marker contents (image-layout.md §oci-layout file).
pub const OCI_LAYOUT_MARKER: &str = "{\"imageLayoutVersion\":\"1.0.0\"}";

/// Annotation key naming a tag (image-layout.md §index.json file).
pub const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// OCI image manifest media type; the default when omitted.
pub const MEDIA_TYPE_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

pub const MEDIA_TYPE_IMAGE_INDEX: &str = "application/vnd.oci.image.index.v1+json";

pub fn empty_index() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_IMAGE_INDEX,
        "manifests": [],
    })
}

pub fn descriptor_tag(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor
        .get("annotations")
        .and_then(|a| a.get(REF_NAME_ANNOTATION))
        .and_then(|v| v.as_str())
}

pub fn descriptor_digest(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor.get("digest").and_then(|v| v.as_str())
}

/// The `manifests` array of an image index; empty when absent.
pub fn index_manifests(index: &serde_json::Value) -> &[serde_json::Value] {
    index
        .get("manifests")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The `subject.digest` string, if present.
pub fn subject_digest(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor.get("subject")?.get("digest")?.as_str()
}

/// All digests a manifest references (config, layers, index children, subject) — GC backrefs.
pub fn manifest_references(manifest: &serde_json::Value) -> Vec<crate::Digest> {
    let descriptors = manifest
        .get("config")
        .into_iter()
        .chain(["layers", "manifests"].into_iter().flat_map(|field| {
            manifest
                .get(field)
                .and_then(serde_json::Value::as_array)
                .map_or(&[][..], Vec::as_slice)
        }))
        .chain(manifest.get("subject"));
    descriptors
        .filter_map(|d| crate::Digest::parse(d.as_object()?.get("digest")?.as_str()?).ok())
        .collect()
}

/// Page a sorted, deduped list: at most `limit` items after `last`.
pub fn page_sorted<T>(
    items: Vec<T>,
    key: fn(&T) -> &str,
    last: Option<&str>,
    limit: usize,
) -> Page<T> {
    let start = last.map_or(0, |l| items.partition_point(|i| key(i) <= l));
    metadata::take_page(items.into_iter().skip(start), limit)
}

/// Page referrer candidates by `artifactType`, deduped by digest.
pub fn page_layout_referrers(
    mut refs: Vec<(String, &serde_json::Value)>,
    artifact_type: Option<&str>,
    last: Option<&str>,
    limit: usize,
) -> Page<Referrer> {
    refs.retain(|(_, d)| {
        artifact_type.is_none_or(|t| d.get("artifactType").and_then(|v| v.as_str()) == Some(t))
    });
    refs.sort_by(|a, b| a.0.cmp(&b.0));
    refs.dedup_by(|a, b| a.0 == b.0);
    let page = page_sorted(refs, |(d, _)| d, last, limit);
    Page {
        items: page
            .items
            .into_iter()
            .map(|(d, v)| (d, v.to_string().into_bytes()))
            .collect(),
        more: page.more,
    }
}

/// Build a referrer descriptor with `subject` merged in.
pub fn referrer_descriptor(
    subject: &crate::Digest,
    descriptor: &[u8],
) -> Result<Vec<u8>, crate::StorageError> {
    let invalid = |e: serde_json::Error| {
        crate::StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    };
    let mut merged: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(descriptor).map_err(invalid)?;
    merged.insert(
        "subject".into(),
        serde_json::json!({ "digest": subject.as_string() }),
    );
    serde_json::to_vec(&merged).map_err(invalid)
}

/// Tags page from an in-memory index.json.
pub fn layout_tags_page(
    index: &serde_json::Value,
    last: Option<&str>,
    limit: usize,
) -> Page<String> {
    let mut tags: Vec<String> = index_manifests(index)
        .iter()
        .filter_map(|e| descriptor_tag(e).map(str::to_string))
        .collect();
    tags.sort();
    tags.dedup();
    page_sorted(tags, String::as_str, last, limit)
}

/// Referrer candidates from an in-memory index.json matching `subject`.
pub fn layout_subject_referrers<'a>(
    index: &'a serde_json::Value,
    subject: &str,
) -> Vec<(String, &'a serde_json::Value)> {
    index_manifests(index)
        .iter()
        .filter(|e| subject_digest(e) == Some(subject))
        .filter_map(|e| Some((descriptor_digest(e)?.to_string(), e)))
        .collect()
}

/// Whether two indexes carry the same descriptor set (order-insensitive).
pub(crate) fn same_manifest_set(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let set = |v: &serde_json::Value| -> Vec<String> {
        let mut s: Vec<String> = index_manifests(v).iter().map(|e| e.to_string()).collect();
        s.sort();
        s
    };
    set(a) == set(b)
}

/// Discover repo names under `root` (dirs with `index.json` or `oci-layout`).
///
/// SECURITY: symlinks never followed — `symlink_metadata` / `file_type` ensure
/// no symlinked repo or marker can redirect enumeration outside the store root.
pub(crate) fn discover_repos(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, rel: &[String], depth: usize, out: &mut Vec<String>) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        // SECURITY: symlink_metadata — no-follow so a symlinked marker cannot
        // trick us into treating an external dir as a repo.
        if !rel.is_empty() {
            let has_index = std::fs::symlink_metadata(dir.join("index.json"))
                .map(|m| m.is_file())
                .unwrap_or(false);
            let has_layout = std::fs::symlink_metadata(dir.join("oci-layout"))
                .map(|m| m.is_file())
                .unwrap_or(false);
            if has_index || has_layout {
                out.push(rel.join("/"));
            }
        }
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "blobs" || name == "uploads" || name.starts_with('.') {
                continue;
            }
            let mut child = rel.to_vec();
            child.push(name);
            walk(&entry.path(), &child, depth - 1, out);
        }
    }
    let mut repos = Vec::new();
    walk(root, &[], 16, &mut repos);
    repos
}

/// Visit every CAS blob under `root`: `<repo>/blobs/<alg>/<hex>` for each
/// [`discover_repos`] repo. `.tmp` siblings and foreign names skipped.
///
/// SECURITY: symlinks never followed at any level — only real dirs/files entered.
pub(crate) fn for_each_cas_blob(
    root: &Path,
    mut visit: impl FnMut(&str, &crate::Digest, &std::fs::DirEntry),
) {
    for repo in discover_repos(root) {
        let blobs_path = root.join(&repo).join("blobs");
        match std::fs::symlink_metadata(&blobs_path) {
            Ok(m) if m.is_dir() => {}
            _ => continue,
        }
        let Ok(algs) = std::fs::read_dir(&blobs_path) else {
            continue;
        };
        for alg in algs.flatten() {
            if !alg.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let alg_name = alg.file_name().to_string_lossy().into_owned();
            let Ok(hexes) = std::fs::read_dir(alg.path()) else {
                continue;
            };
            for hex in hexes.flatten() {
                if !hex.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let name = format!("{alg_name}:{}", hex.file_name().to_string_lossy());
                if let Ok(digest) = crate::Digest::parse(&name) {
                    visit(&repo, &digest, &hex);
                }
            }
        }
    }
}

/// Import tagged descriptors from a foreign layout the metadata store has not seen.
pub fn import_foreign_tags(meta: &dyn MetadataStore, repo: &str, existing: &serde_json::Value) {
    for e in index_manifests(existing) {
        let (Some(tag), Some(digest)) = (descriptor_tag(e), descriptor_digest(e)) else {
            continue;
        };
        if crate::Digest::parse(digest).is_err() || meta.resolve_tag(repo, tag).is_some() {
            continue;
        }
        let media_type = e
            .get("mediaType")
            .and_then(|v| v.as_str())
            .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST);
        if let Err(err) = meta.apply(MetaOp::PutManifest {
            repo: repo.to_string(),
            digest: digest.to_string(),
            media_type: media_type.to_string(),
            tag: Some(tag.to_string()),
            references: Vec::new(),
            referrer: None,
        }) {
            tracing::warn!(repo = %repo, error = %err, "import of existing tag failed");
        }
    }
}

/// Rebuild `index.json` from the metadata store merged over the existing on-disk index.
pub fn index_from_meta(
    meta: &dyn MetadataStore,
    repo: &str,
    existing: Option<serde_json::Value>,
    size_lookup: impl Fn(&str) -> Option<u64>,
) -> std::io::Result<serde_json::Value> {
    type Obj = serde_json::Map<String, serde_json::Value>;
    let known: HashSet<String> = meta.manifests(repo).into_iter().collect();

    let mut base: HashMap<String, Obj> = HashMap::new();
    let mut foreign: Vec<serde_json::Value> = Vec::new();
    let existing_ms = existing.as_ref().map_or(&[][..], index_manifests);
    for e in existing_ms {
        let Some(obj) = e.as_object() else {
            foreign.push(e.clone());
            continue;
        };
        let digest = obj.get("digest").and_then(|v| v.as_str());
        match digest {
            Some(d) if known.contains(d) => {
                let mut o = obj.clone();
                if let Some(ann) = o.get_mut("annotations").and_then(|a| a.as_object_mut()) {
                    ann.remove(REF_NAME_ANNOTATION);
                    if ann.is_empty() {
                        o.remove("annotations");
                    }
                }
                base.entry(d.to_string()).or_insert(o);
            }
            _ if descriptor_tag(e).is_none() && e.get("subject").is_none() => {
                foreign.push(e.clone());
            }
            _ => {} // deleted roci-managed manifest
        }
    }

    for d in &known {
        let o = base.entry(d.clone()).or_insert_with(|| {
            let mut o = Obj::new();
            o.insert("digest".into(), serde_json::Value::String(d.clone()));
            o
        });
        if let Some(mt) = meta.manifest_media_type(repo, d) {
            o.insert("mediaType".into(), serde_json::Value::String(mt));
        }
        if !o.contains_key("size") {
            if let Some(size) = size_lookup(d) {
                o.insert("size".into(), serde_json::Value::Number(size.into()));
            }
        }
    }

    // Merge referrer descriptor fields into the base (annotations preserved).
    for (subject, refs) in meta.referrers_snapshot(repo) {
        for (ref_digest, ref_bytes) in refs {
            let o = base.entry(ref_digest.clone()).or_insert_with(|| {
                let mut o = Obj::new();
                o.insert(
                    "digest".into(),
                    serde_json::Value::String(ref_digest.clone()),
                );
                o
            });
            let Ok(r) = serde_json::from_slice::<Obj>(&ref_bytes) else {
                continue;
            };
            for (k, v) in r {
                match k.as_str() {
                    "digest" => {}
                    "mediaType" | "size" => {
                        o.entry(k).or_insert(v);
                    }
                    "annotations" => {
                        let (Some(new), Some(cur)) = (
                            v.as_object(),
                            o.entry("annotations")
                                .or_insert_with(|| serde_json::Value::Object(Obj::new()))
                                .as_object_mut(),
                        ) else {
                            continue;
                        };
                        for (ak, av) in new {
                            if ak != REF_NAME_ANNOTATION {
                                cur.entry(ak.clone()).or_insert_with(|| av.clone());
                            }
                        }
                    }
                    _ => {
                        o.insert(k, v);
                    }
                }
            }
            o.insert("subject".into(), serde_json::json!({ "digest": subject }));
        }
    }

    // Emit: one descriptor per tag, then untagged, then foreign (sorted).
    let tags = meta.tags_snapshot(repo);
    let mut tagged: HashSet<&str> = HashSet::new();
    let mut manifests: Vec<serde_json::Value> = Vec::with_capacity(base.len() + tags.len());
    for (tag, digest, _) in &tags {
        let Some(b) = base.get(digest) else { continue };
        let mut o = b.clone();
        let ann = o
            .entry("annotations")
            .or_insert_with(|| serde_json::Value::Object(Obj::new()));
        if let Some(ann) = ann.as_object_mut() {
            ann.insert(
                REF_NAME_ANNOTATION.into(),
                serde_json::Value::String(tag.clone()),
            );
        }
        tagged.insert(digest.as_str());
        manifests.push(serde_json::Value::Object(o));
    }
    let mut untagged: Vec<(&String, &Obj)> = base
        .iter()
        .filter(|(d, _)| !tagged.contains(d.as_str()))
        .collect();
    untagged.sort_by(|a, b| a.0.cmp(b.0));
    manifests.extend(
        untagged
            .into_iter()
            .map(|(_, o)| serde_json::Value::Object(o.clone())),
    );
    manifests.extend(foreign);
    // Preserve top-level fields another tool wrote; regenerate roci-owned.
    let mut top = existing
        .and_then(|v| match v {
            serde_json::Value::Object(o) => Some(o),
            _ => None,
        })
        .unwrap_or_default();
    top.insert("schemaVersion".into(), serde_json::json!(2));
    top.insert(
        "mediaType".into(),
        serde_json::json!("application/vnd.oci.image.index.v1+json"),
    );
    top.insert("manifests".into(), serde_json::Value::Array(manifests));
    Ok(serde_json::Value::Object(top))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_of;
    use crate::metadata::MetaOp;
    use crate::storage::{ManifestLinks, Storage};
    use crate::FsStorage;

    fn store() -> (tempfile::TempDir, FsStorage) {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        (dir, s)
    }

    #[tokio::test]
    async fn import_foreign_tags_imports_and_skips() {
        let (_dir, s) = store();
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        s.put_blob("ext", &d, body).await.unwrap();
        let existing = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": d.as_string(), "size": body.len(),
                "annotations": {"org.opencontainers.image.ref.name": "foreign"}
            }]
        });
        assert!(
            s.meta.resolve_tag("ext", "foreign").is_none(),
            "precondition"
        );
        import_foreign_tags(&*s.meta, "ext", &existing);
        assert!(s.meta.resolve_tag("ext", "foreign").is_some(), "imported");
        import_foreign_tags(&*s.meta, "ext", &existing); // idempotent

        let skip_cases = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": "sha256:0000000000000000000000000000000000000000000000000000000000000001", "size": 1},
                {"annotations": {"org.opencontainers.image.ref.name": "v1"}, "size": 1},
                {"digest": "garbage", "annotations": {"org.opencontainers.image.ref.name": "v2"}, "size": 1}
            ]
        });
        import_foreign_tags(&*s.meta, "r", &skip_cases);
        assert!(s.meta.resolve_tag("r", "v1").is_none(), "no-digest skipped");
        assert!(
            s.meta.resolve_tag("r", "v2").is_none(),
            "bad-digest skipped"
        );
    }

    #[tokio::test]
    async fn index_from_meta_edge_cases() {
        let (_dir, s) = store();
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        s.put_manifest(
            "r",
            Some("t1"),
            &d,
            "application/json",
            body,
            ManifestLinks::default(),
        )
        .await
        .unwrap();

        let existing = serde_json::json!({
            "schemaVersion": 2,
            "manifests": ["a bare string entry", {"digest": d.as_string(), "size": body.len()}]
        });
        let rebuilt = index_from_meta(&*s.meta, "r", Some(existing), |_| None).unwrap();
        let ms = rebuilt["manifests"].as_array().unwrap();
        assert!(ms.iter().any(|e| e.is_string()), "foreign string preserved");
        assert!(
            ms.iter().any(|e| descriptor_tag(e) == Some("t1")),
            "known tag present"
        );

        let subject = sha256_of(b"subj");
        s.meta
            .apply(MetaOp::PutReferrer {
                repo: "r".to_string(),
                subject: subject.as_string(),
                referrer: "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                descriptor: b"not json at all".to_vec(),
            })
            .unwrap();
        let rebuilt2 = index_from_meta(&*s.meta, "r", None, |_| None).unwrap();
        assert!(
            rebuilt2["manifests"].is_array(),
            "non-json referrer skipped"
        );

        let rebuilt3 =
            index_from_meta(&*s.meta, "r", Some(serde_json::Value::Null), |_| None).unwrap();
        assert_eq!(rebuilt3["schemaVersion"], 2, "null existing handled");
    }
}
