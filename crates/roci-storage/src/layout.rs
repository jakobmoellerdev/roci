//! On-disk OCI image-layout helpers: the marker/media-type constants, the
//! `index.json` descriptor accessors, and the in-memory paging used by the
//! layout read-path fallbacks.

use crate::metadata::{self, Page, Referrer};
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
        if !rel.is_empty() && (dir.join("index.json").is_file() || dir.join("oci-layout").is_file())
        {
            out.push(rel.join("/"));
        }
        for entry in entries.flatten() {
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
pub(crate) fn for_each_cas_blob(
    root: &Path,
    mut visit: impl FnMut(&str, &crate::Digest, &std::fs::DirEntry),
) {
    for repo in discover_repos(root) {
        let Ok(algs) = std::fs::read_dir(root.join(&repo).join("blobs")) else {
            continue;
        };
        for alg in algs.flatten() {
            let alg_name = alg.file_name().to_string_lossy().into_owned();
            let Ok(hexes) = std::fs::read_dir(alg.path()) else {
                continue;
            };
            for hex in hexes.flatten() {
                let name = format!("{alg_name}:{}", hex.file_name().to_string_lossy());
                if let Ok(digest) = crate::Digest::parse(&name) {
                    visit(&repo, &digest, &hex);
                }
            }
        }
    }
}
