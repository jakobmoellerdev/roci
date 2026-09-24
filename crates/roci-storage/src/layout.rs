//! On-disk OCI image-layout helpers: the marker/media-type constants, the
//! `index.json` descriptor accessors, and the in-memory paging used by the
//! layout read-path fallbacks.

use crate::metadata::{self, MetaOp, MetadataStore, Page, Referrer};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The `oci-layout` marker file contents (image-layout.md §oci-layout file).
pub(crate) const OCI_LAYOUT_MARKER: &str = "{\"imageLayoutVersion\":\"1.0.0\"}";

/// Annotation key a descriptor carries to name a tag (image-layout.md
/// §index.json file).
pub(crate) const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// OCI image manifest media type (image-spec `mediaType`); the default when a
/// descriptor/request omits one.
pub const MEDIA_TYPE_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// OCI image index media type.
pub const MEDIA_TYPE_IMAGE_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// The canonical empty OCI image index.
pub(crate) fn empty_index() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_IMAGE_INDEX,
        "manifests": [],
    })
}

/// The tag a descriptor names via its `org.opencontainers.image.ref.name`
/// annotation, if any.
pub(crate) fn descriptor_tag(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor
        .get("annotations")
        .and_then(|a| a.get(REF_NAME_ANNOTATION))
        .and_then(|v| v.as_str())
}

/// The `digest` field of a descriptor, if present and a string.
pub(crate) fn descriptor_digest(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor.get("digest").and_then(|v| v.as_str())
}

/// The `manifests` descriptors of an image index; empty when absent or not an array.
pub(crate) fn index_manifests(index: &serde_json::Value) -> &[serde_json::Value] {
    index
        .get("manifests")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The `subject.digest` string of a descriptor, if present.
pub(crate) fn subject_digest(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor.get("subject")?.get("digest")?.as_str()
}

/// Every object a manifest references — `config`, each `layers` entry, each
/// image-index `manifests` child, and `subject` — as parsed digests: the GC
/// liveness edges (backrefs). The single definition shared by the push path
/// and the GC startup rebuild, so both derive identical edges. Lenient: a
/// malformed descriptor contributes nothing (the push path validates the
/// required config/layers separately and rejects a malformed manifest).
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

/// Page an in-memory list already sorted and de-duplicated by `key`: at most
/// `limit` items strictly after `last`. Used only by the layout fallbacks,
/// whose cost is bounded by the document they must read whole anyway.
pub(crate) fn page_sorted<T>(
    items: Vec<T>,
    key: fn(&T) -> &str,
    last: Option<&str>,
    limit: usize,
) -> Page<T> {
    let start = last.map_or(0, |l| items.partition_point(|i| key(i) <= l));
    metadata::take_page(items.into_iter().skip(start), limit)
}

/// Page referrer candidates read from the layout, `(digest, descriptor)`, the
/// way the metadata store pages its index: keep the `artifactType` matches,
/// order and de-duplicate by digest (first occurrence wins), and serialize
/// only the served page.
pub(crate) fn page_layout_referrers(
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

/// Whether two image indexes carry the same descriptor set (order-insensitive).
pub(crate) fn same_manifest_set(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let set = |v: &serde_json::Value| -> Vec<String> {
        let mut s: Vec<String> = index_manifests(v).iter().map(|e| e.to_string()).collect();
        s.sort();
        s
    };
    set(a) == set(b)
}

/// Repository names under `root`: every directory (bounded depth) that directly
/// contains an `index.json` file **or** an `oci-layout` marker — the latter
/// catches a blob-only repo (blobs pushed before its first manifest, so no
/// `index.json` yet) whose blobs must still seed the presence filter. Named by
/// its `/`-joined path relative to `root`. Best-effort — an unreadable
/// directory is skipped. Used only to seed the blob-presence filter at startup.
///
/// Symlinks are never followed at any level: `DirEntry::file_type` and
/// `symlink_metadata` are used throughout so a symlinked repo, `blobs`, or
/// algorithm directory cannot redirect enumeration outside the store root.
pub(crate) fn discover_repos(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, rel: &[String], depth: usize, out: &mut Vec<String>) {
        // Bound depth so a pathological tree cannot recurse without limit;
        // repo names are a handful of path segments in practice.
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        // Use symlink_metadata so a symlinked index.json/oci-layout cannot
        // masquerade as a regular file and make us treat an attacker-controlled
        // directory as a valid repo.
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
            // DirEntry::file_type does not follow symlinks on most platforms;
            // only real directories are entered.
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // The CAS/staging subdirs of a repo are never themselves repos, and
            // neither is a dot-directory (the repo grammar forbids a leading
            // `.`; roci keeps internal state such as a quarantine there).
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

/// Visit every CAS blob under `root` as `(repo, digest, dir entry)`: every
/// `<repo>/blobs/<alg>/<hex>` of every [`discover_repos`] repository whose
/// name parses as a wire [`crate::Digest`] (in-progress `.tmp` siblings and
/// foreign names are skipped). Best-effort — an unreadable directory is
/// skipped. The shared startup/GC/scrub enumeration.
///
/// Symlinks are never followed: at the `blobs` and `<alg>` levels only real
/// directories are entered; at the leaf level only regular files (via
/// `symlink_metadata`) are visited — so a symlinked repo, `blobs`, algorithm
/// directory or digest leaf cannot redirect enumeration outside the store root.
pub(crate) fn for_each_cas_blob(
    root: &Path,
    mut visit: impl FnMut(&str, &crate::Digest, &std::fs::DirEntry),
) {
    for repo in discover_repos(root) {
        let blobs_path = root.join(&repo).join("blobs");
        // Skip if `blobs` is a symlink (no-follow check).
        match std::fs::symlink_metadata(&blobs_path) {
            Ok(m) if m.is_dir() => {}
            _ => continue,
        }
        let Ok(algs) = std::fs::read_dir(&blobs_path) else {
            continue;
        };
        for alg in algs.flatten() {
            // Skip algorithm dirs that are symlinks.
            if !alg.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let alg_name = alg.file_name().to_string_lossy().into_owned();
            let Ok(hexes) = std::fs::read_dir(alg.path()) else {
                continue;
            };
            for hex in hexes.flatten() {
                // Leaves must be regular files (not symlinks).
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

/// Record tagged descriptors from an existing index that the metadata store
/// does not yet know (a layout written by another tool) so the write-behind
/// treats them as live.
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

/// Rebuild a spec-valid `index.json` from the metadata store (authoritative
/// for everything roci wrote) merged over the existing on-disk index.
///
/// Rules: a manifest the store knows emits one descriptor per tag (or one
/// untagged descriptor), enriched with its referrer fields (`subject`,
/// `artifactType`, annotations) and any extra fields already on disk. An
/// on-disk entry the store does not know is kept only if it is *foreign*
/// — no `ref.name` tag and no `subject` (roci would have recorded either);
/// otherwise it is a deleted manifest and is dropped.
///
/// `size_lookup` resolves a digest to its byte size (from CAS stat, existing
/// index entry, or manifest bytes length) — avoids coupling to a specific
/// backend's storage access.
pub fn index_from_meta(
    meta: &dyn MetadataStore,
    repo: &str,
    existing: Option<serde_json::Value>,
    size_lookup: impl Fn(&str) -> Option<u64>,
) -> std::io::Result<serde_json::Value> {
    type Obj = serde_json::Map<String, serde_json::Value>;
    let known: HashSet<String> = meta.manifests(repo).into_iter().collect();

    // Per-digest base descriptor (tag stripped) for known manifests, plus
    // foreign entries passed through verbatim.
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

    // Every known manifest gets a base (media type from the store; size
    // from the size_lookup when not already recorded).
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

    // Merge referrer descriptor fields into the referring manifest's base
    // (never overwriting its identity; existing annotations win). A live
    // referrer whose manifest the store does not track (DeleteManifest
    // already drops referrers) contributes its own descriptor.
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

    // Emit: one descriptor per tag, then untagged known manifests, then
    // foreign entries. Sorted for a deterministic, diff-friendly file.
    // `tags_snapshot` is tag-sorted.
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
    // Keep any top-level fields another tool wrote (`annotations`,
    // `artifactType`, `subject`, …); regenerate only what roci owns.
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
