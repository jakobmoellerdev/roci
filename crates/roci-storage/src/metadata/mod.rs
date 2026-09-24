//! Derived, rebuildable-from-the-layout metadata index (ARCHITECTURE.md
//! §"Metadata index engine"). The [`MetadataStore`] trait is the read/mutate
//! surface the storage backend resolves tags, manifest media types, and the
//! subject→referrers relation against; the default [`LogMetadataStore`] keeps
//! the state in RAM and durably mirrors every mutation to an append-only,
//! CRC32C-framed `roci-meta.log` so restarts replay in one sequential pass.
//!
//! The on-disk OCI layout (`index.json` + `blobs/`) remains the source of
//! truth (invariant 6); this index is a cache, always reconstructable by
//! replaying the log or, failing that, walking the layout.

mod log;
mod snapshot;
mod wal_hmac;

#[cfg(feature = "redb")]
mod redb;

#[cfg(feature = "redb")]
pub use self::redb::RedbMetadataStore;

pub use log::LogMetadataStore;

use roci_config::{MetadataConfig, MetadataEngine};
use std::io;
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;

/// A tag/manifest/referrer/blob mutation the store can record and replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaOp {
    /// A manifest was stored, committed atomically with everything derived
    /// from it (SECURITY §Storage boundary: one WAL record, so a crash never
    /// leaves a stored manifest whose blobs look unreferenced to GC).
    PutManifest {
        repo: String,
        digest: String,
        media_type: String,
        tag: Option<String>,
        /// Backref edges: every object the manifest references (config,
        /// layers, index children, subject) gains `digest` in its backref set.
        references: Vec<String>,
        /// `(subject, referrer descriptor)` when the manifest has a `subject`.
        referrer: Option<(String, Vec<u8>)>,
    },
    /// Backref edges recorded on their own: the GC startup rebuild restoring
    /// edges an older log or an externally built layout lacks.
    PutBackrefs {
        repo: String,
        manifest: String,
        blobs: Vec<String>,
    },
    /// A manifest (and every tag pointing at it) was deleted: `(repo, digest)`.
    DeleteManifest { repo: String, digest: String },
    /// A referrer descriptor was recorded against a subject digest (the
    /// referrers enable-upgrade of pre-existing `index.json` descriptors).
    PutReferrer {
        repo: String,
        subject: String,
        referrer: String,
        descriptor: Vec<u8>,
    },
    /// A blob's CRC32C and size, recorded when it enters the CAS so the scrub
    /// can verify it with a fast checksum before escalating to a full re-hash.
    PutChecksum {
        repo: String,
        digest: String,
        crc32c: u32,
        size: u64,
    },
    /// A blob left the CAS (API delete, GC, scrub quarantine).
    DeleteBlob { repo: String, digest: String },
}

/// The CRC32C + size recorded for a blob at write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobChecksum {
    pub crc32c: u32,
    pub size: u64,
}

/// The read/mutate surface for derived metadata — the seam every metadata
/// engine implements (append-log + maps by default, embedded KV as an
/// upgrade; ARCHITECTURE §Metadata index engine). Object-safe: backends hold
/// it as `Arc<dyn MetadataStore>`. AuthN/AuthZ is enforced before any call
/// (ARCHITECTURE.md invariant 3), exactly like [`crate::Storage`].
pub trait MetadataStore: Send + Sync + 'static {
    /// Resolve a tag to `(digest, media_type)`, if the tag exists. Both come
    /// from the same locked read, so a resolved tag always carries its media
    /// type (no second lookup, no fallback default).
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)>;
    /// The stored media type for a manifest digest, if known.
    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String>;
    /// One page of `repo`'s tags in lexical order: at most `limit` tags
    /// strictly after `last` (from the start when `None`) — an O(log n) seek,
    /// so the work is bounded by the page, not the repo. `None` when the store
    /// records no tag for `repo` (the caller falls back to the layout).
    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>>;
    /// One page of the referrers recorded for `subject`, ordered by referrer
    /// digest: at most `limit` entries strictly after `last`, restricted to
    /// descriptors whose `artifactType` equals `artifact_type` when given (an
    /// O(log n) seek into a per-type index, never a filtered scan). `None`
    /// when the store records no referrer for `subject` at all.
    fn referrers_page(
        &self,
        repo: &str,
        subject: &str,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Option<Page<Referrer>>;
    /// Whether `referrer` is recorded as a referrer of `subject`.
    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool;
    /// The manifest digests currently recorded as referencing `blob` in `repo`.
    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String>;
    /// The checksum recorded for `digest` in `repo`, if any.
    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum>;
    /// Apply and durably record a mutation (group-committed).
    fn apply(&self, op: MetaOp) -> io::Result<()>;
    /// Apply and record a mutation without waiting for durability — only for
    /// derived records whose loss is harmless (a checksum the scrub rebuilds).
    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()>;
    /// Every repo with at least one manifest or referrer recorded, sorted.
    fn repos(&self) -> Vec<String>;
    /// Every manifest digest recorded in `repo`.
    fn manifests(&self, repo: &str) -> Vec<String>;
    /// `repo`'s tags as `(tag, digest, media_type)`, sorted by tag.
    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)>;
    /// `repo`'s referrers as `(subject, [(referrer, descriptor)])`.
    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)>;
    /// Background upkeep (log compaction / snapshot cut) the maintenance
    /// scheduler calls periodically; a no-op when nothing is due.
    fn maintain(&self) -> io::Result<()>;
}

/// One referrer: `(referrer_digest, descriptor_bytes)`; the digest de-dups.
pub type Referrer = (String, Vec<u8>);

/// One page of a cursor-paginated listing: at most the requested number of
/// items strictly after the request cursor, in the listing's stable order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// At least one further item follows `items` (→ a `Link: rel="next"`).
    pub more: bool,
}

/// Collect at most `limit` items of `it` and record whether any remain.
pub(crate) fn take_page<T>(mut it: impl Iterator<Item = T>, limit: usize) -> Page<T> {
    let items: Vec<T> = it.by_ref().take(limit).collect();
    let more = it.next().is_some();
    Page { items, more }
}

/// The key range strictly after the cursor `last` (everything when `None`).
pub(crate) fn after(last: Option<&str>) -> (Bound<&str>, Bound<&str>) {
    (
        last.map_or(Bound::Unbounded, Bound::Excluded),
        Bound::Unbounded,
    )
}

/// Open the metadata engine `config` selects for the store rooted at `root`.
pub fn open_metadata(root: &Path, config: &MetadataConfig) -> io::Result<Arc<dyn MetadataStore>> {
    match config.engine {
        MetadataEngine::Log => Ok(Arc::new(LogMetadataStore::open_with(root, config)?)),
        #[cfg(feature = "redb")]
        MetadataEngine::Redb => Ok(Arc::new(RedbMetadataStore::open(root, config)?)),
        #[cfg(not(feature = "redb"))]
        MetadataEngine::Redb => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage.metadata.engine = \"redb\" requires a build with the `redb` feature",
        )),
    }
}

// ---------------------------------------------------------------------------
// Shared behavioral suite — every `MetadataStore` engine passes these.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod engine_tests {
    use super::*;
    use roci_config::MetadataConfig;

    fn descriptor(artifact_type: Option<&str>) -> Vec<u8> {
        if let Some(at) = artifact_type {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:ffff",
                "size": 100,
                "artifactType": at,
            })
            .to_string()
            .into_bytes()
        } else {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:ffff",
                "size": 100,
            })
            .to_string()
            .into_bytes()
        }
    }

    /// Macro generating the full shared test suite for each engine.
    macro_rules! engine_tests {
        ($mod_name:ident, $make_store:expr) => {
            mod $mod_name {
                use super::*;

                #[test]
                fn empty_state() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());
                    assert!(store.resolve_tag("repo", "latest").is_none());
                    assert!(store.manifest_media_type("repo", "sha256:a").is_none());
                    assert_eq!(store.repos(), Vec::<String>::new());
                    assert_eq!(store.manifests("repo"), Vec::<String>::new());
                    assert!(store.tags_page("repo", None, 10).is_none());
                    assert!(store
                        .referrers_page("repo", "sha256:a", None, None, 10)
                        .is_none());
                    assert!(!store.has_referrer("repo", "sha256:a", "sha256:b"));
                    assert_eq!(store.backrefs("repo", "sha256:a"), Vec::<String>::new());
                    assert!(store.checksum("repo", "sha256:a").is_none());
                }

                #[test]
                fn put_manifest_with_tag() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:aaa".into(),
                            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                            tag: Some("v1".into()),
                            references: vec!["sha256:bbb".into(), "sha256:ccc".into()],
                            referrer: None,
                        })
                        .unwrap();

                    let (d, mt) = store.resolve_tag("r", "v1").unwrap();
                    assert_eq!(d, "sha256:aaa");
                    assert_eq!(mt, "application/vnd.oci.image.manifest.v1+json");
                    assert_eq!(
                        store.manifest_media_type("r", "sha256:aaa").unwrap(),
                        "application/vnd.oci.image.manifest.v1+json"
                    );

                    // Backrefs: both referenced blobs point back to manifest
                    let mut br = store.backrefs("r", "sha256:bbb");
                    br.sort();
                    assert_eq!(br, vec!["sha256:aaa"]);
                    let mut br2 = store.backrefs("r", "sha256:ccc");
                    br2.sort();
                    assert_eq!(br2, vec!["sha256:aaa"]);

                    // repos/manifests
                    assert_eq!(store.repos(), vec!["r".to_string()]);
                    let mf = store.manifests("r");
                    assert_eq!(mf.len(), 1);
                    assert!(mf.contains(&"sha256:aaa".to_string()));
                }

                #[test]
                fn tag_pages_and_cursors() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    for tag in ["alpha", "beta", "gamma", "delta", "epsilon"] {
                        store
                            .apply(MetaOp::PutManifest {
                                repo: "r".into(),
                                digest: format!("sha256:{tag}"),
                                media_type: "m".into(),
                                tag: Some(tag.into()),
                                references: vec![],
                                referrer: None,
                            })
                            .unwrap();
                    }

                    // Page of 2 from start
                    let p = store.tags_page("r", None, 2).unwrap();
                    assert_eq!(p.items, vec!["alpha", "beta"]);
                    assert!(p.more);

                    // Continue with cursor
                    let p2 = store.tags_page("r", Some("beta"), 2).unwrap();
                    assert_eq!(p2.items, vec!["delta", "epsilon"]);
                    assert!(p2.more);

                    let p3 = store.tags_page("r", Some("epsilon"), 2).unwrap();
                    assert_eq!(p3.items, vec!["gamma"]);
                    assert!(!p3.more);

                    // Cursor past last element
                    let p4 = store.tags_page("r", Some("gamma"), 10).unwrap();
                    assert!(p4.items.is_empty());
                    assert!(!p4.more);

                    // Cursor that no longer exists (deleted tag) — should
                    // resume correctly (strictly after the cursor string).
                    let p5 = store.tags_page("r", Some("bet"), 2).unwrap();
                    assert_eq!(p5.items, vec!["beta", "delta"]);
                    assert!(p5.more);

                    // tags_page returns None for unknown repo
                    assert!(store.tags_page("nope", None, 10).is_none());
                }

                #[test]
                fn tags_snapshot_sorted() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    for tag in ["z", "a", "m"] {
                        store
                            .apply(MetaOp::PutManifest {
                                repo: "r".into(),
                                digest: format!("sha256:{tag}"),
                                media_type: "mt".into(),
                                tag: Some(tag.into()),
                                references: vec![],
                                referrer: None,
                            })
                            .unwrap();
                    }

                    let snap = store.tags_snapshot("r");
                    let tags: Vec<&str> = snap.iter().map(|(t, _, _)| t.as_str()).collect();
                    assert_eq!(tags, vec!["a", "m", "z"]);
                }

                #[test]
                fn put_manifest_with_referrer() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sbom/cyclonedx"));
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:ref1".into(),
                            media_type: "m".into(),
                            tag: None,
                            references: vec![],
                            referrer: Some(("sha256:subj".into(), desc.clone())),
                        })
                        .unwrap();

                    assert!(store.has_referrer("r", "sha256:subj", "sha256:ref1"));
                    let page = store
                        .referrers_page("r", "sha256:subj", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].0, "sha256:ref1");
                    assert_eq!(page.items[0].1, desc);

                    // Repos includes the referrer's repo
                    assert!(store.repos().contains(&"r".to_string()));
                }

                #[test]
                fn referrer_pages_and_artifact_type_filter() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Add 5 referrers: 3 with type "sbom", 2 with type "sig"
                    for i in 0..3 {
                        let desc = descriptor(Some("sbom"));
                        store
                            .apply(MetaOp::PutReferrer {
                                repo: "r".into(),
                                subject: "sha256:subj".into(),
                                referrer: format!("sha256:sbom{i}"),
                                descriptor: desc,
                            })
                            .unwrap();
                    }
                    for i in 0..2 {
                        let desc = descriptor(Some("sig"));
                        store
                            .apply(MetaOp::PutReferrer {
                                repo: "r".into(),
                                subject: "sha256:subj".into(),
                                referrer: format!("sha256:sig{i}"),
                                descriptor: desc,
                            })
                            .unwrap();
                    }

                    // Unfiltered: all 5
                    let p = store
                        .referrers_page("r", "sha256:subj", None, None, 10)
                        .unwrap();
                    assert_eq!(p.items.len(), 5);
                    assert!(!p.more);

                    // Filtered by "sbom": 3
                    let ps = store
                        .referrers_page("r", "sha256:subj", Some("sbom"), None, 10)
                        .unwrap();
                    assert_eq!(ps.items.len(), 3);
                    for (d, _) in &ps.items {
                        assert!(d.starts_with("sha256:sbom"));
                    }

                    // Filtered by "sig": 2
                    let psig = store
                        .referrers_page("r", "sha256:subj", Some("sig"), None, 10)
                        .unwrap();
                    assert_eq!(psig.items.len(), 2);

                    // Filtered by nonexistent type: empty page (not None —
                    // subject has referrers, just not of this type)
                    let pn = store
                        .referrers_page("r", "sha256:subj", Some("nope"), None, 10)
                        .unwrap();
                    assert!(pn.items.is_empty());
                    assert!(!pn.more);

                    // Paging across page boundaries: 2 per page, sbom type
                    let p1 = store
                        .referrers_page("r", "sha256:subj", Some("sbom"), None, 2)
                        .unwrap();
                    assert_eq!(p1.items.len(), 2);
                    assert!(p1.more);
                    let cursor = &p1.items[1].0;
                    let p2 = store
                        .referrers_page("r", "sha256:subj", Some("sbom"), Some(cursor), 2)
                        .unwrap();
                    assert_eq!(p2.items.len(), 1);
                    assert!(!p2.more);

                    // referrers_page returns None for unknown subject
                    assert!(store
                        .referrers_page("r", "sha256:unknown", None, None, 10)
                        .is_none());
                }

                #[test]
                fn referrers_snapshot_structure() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sbom"));
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s1".into(),
                            referrer: "sha256:r1".into(),
                            descriptor: desc.clone(),
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s1".into(),
                            referrer: "sha256:r2".into(),
                            descriptor: desc,
                        })
                        .unwrap();

                    let snap = store.referrers_snapshot("r");
                    assert_eq!(snap.len(), 1);
                    assert_eq!(snap[0].0, "sha256:s1");
                    assert_eq!(snap[0].1.len(), 2);
                }

                #[test]
                fn atomic_put_manifest_with_refs_and_referrer() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sig/cosign"));
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:manifest1".into(),
                            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                            tag: Some("latest".into()),
                            references: vec!["sha256:config".into(), "sha256:layer0".into()],
                            referrer: Some(("sha256:subject1".into(), desc.clone())),
                        })
                        .unwrap();

                    // Tag
                    let (d, _) = store.resolve_tag("r", "latest").unwrap();
                    assert_eq!(d, "sha256:manifest1");

                    // Media type
                    assert!(store.manifest_media_type("r", "sha256:manifest1").is_some());

                    // Backrefs
                    assert_eq!(
                        store.backrefs("r", "sha256:config"),
                        vec!["sha256:manifest1"]
                    );
                    assert_eq!(
                        store.backrefs("r", "sha256:layer0"),
                        vec!["sha256:manifest1"]
                    );

                    // Referrer
                    assert!(store.has_referrer("r", "sha256:subject1", "sha256:manifest1"));
                    let page = store
                        .referrers_page("r", "sha256:subject1", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].1, desc);
                }

                #[test]
                fn delete_manifest_cascades() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(None);

                    // Create manifest with tag, references, referrer, checksum
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: Some("v1".into()),
                            references: vec!["sha256:blob1".into()],
                            referrer: Some(("sha256:subj".into(), desc)),
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutChecksum {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            crc32c: 123,
                            size: 456,
                        })
                        .unwrap();

                    // Verify present
                    assert!(store.resolve_tag("r", "v1").is_some());
                    assert!(store.manifest_media_type("r", "sha256:m1").is_some());
                    assert!(store.has_referrer("r", "sha256:subj", "sha256:m1"));
                    assert!(!store.backrefs("r", "sha256:blob1").is_empty());
                    assert!(store.checksum("r", "sha256:m1").is_some());

                    // Delete
                    store
                        .apply(MetaOp::DeleteManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                        })
                        .unwrap();

                    // All cascaded
                    assert!(store.resolve_tag("r", "v1").is_none());
                    assert!(store.manifest_media_type("r", "sha256:m1").is_none());
                    assert!(!store.has_referrer("r", "sha256:subj", "sha256:m1"));
                    assert!(store.backrefs("r", "sha256:blob1").is_empty());
                    assert!(store.checksum("r", "sha256:m1").is_none());

                    // Referrers page now None (no referrers left)
                    assert!(store
                        .referrers_page("r", "sha256:subj", None, None, 10)
                        .is_none());
                    // Tags page now None
                    assert!(store.tags_page("r", None, 10).is_none());
                }

                #[test]
                fn delete_manifest_only_removes_matching_tags() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Two manifests, two tags
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: Some("v1".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m2".into(),
                            media_type: "mt".into(),
                            tag: Some("v2".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    store
                        .apply(MetaOp::DeleteManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                        })
                        .unwrap();

                    assert!(store.resolve_tag("r", "v1").is_none());
                    assert!(store.resolve_tag("r", "v2").is_some());
                }

                #[test]
                fn put_backrefs_standalone() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutBackrefs {
                            repo: "r".into(),
                            manifest: "sha256:m1".into(),
                            blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
                        })
                        .unwrap();

                    assert_eq!(store.backrefs("r", "sha256:b1"), vec!["sha256:m1"]);
                    assert_eq!(store.backrefs("r", "sha256:b2"), vec!["sha256:m1"]);
                }

                #[test]
                fn put_referrer_standalone() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sbom"));
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s".into(),
                            referrer: "sha256:r".into(),
                            descriptor: desc.clone(),
                        })
                        .unwrap();

                    assert!(store.has_referrer("r", "sha256:s", "sha256:r"));
                    let page = store
                        .referrers_page("r", "sha256:s", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].0, "sha256:r");
                    assert_eq!(page.items[0].1, desc);
                }

                #[test]
                fn put_checksum_and_delete_blob() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutChecksum {
                            repo: "r".into(),
                            digest: "sha256:b1".into(),
                            crc32c: 0xDEAD_BEEF,
                            size: 42,
                        })
                        .unwrap();

                    let bc = store.checksum("r", "sha256:b1").unwrap();
                    assert_eq!(bc.crc32c, 0xDEAD_BEEF);
                    assert_eq!(bc.size, 42);

                    store
                        .apply(MetaOp::DeleteBlob {
                            repo: "r".into(),
                            digest: "sha256:b1".into(),
                        })
                        .unwrap();

                    assert!(store.checksum("r", "sha256:b1").is_none());
                }

                #[test]
                fn apply_relaxed_commits() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply_relaxed(MetaOp::PutChecksum {
                            repo: "r".into(),
                            digest: "sha256:b1".into(),
                            crc32c: 42,
                            size: 100,
                        })
                        .unwrap();

                    // The mutation should be visible even without fsync
                    let bc = store.checksum("r", "sha256:b1").unwrap();
                    assert_eq!(bc.crc32c, 42);
                    assert_eq!(bc.size, 100);
                }

                #[test]
                fn maintain_is_harmless() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());
                    store.maintain().unwrap();

                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:a".into(),
                            media_type: "mt".into(),
                            tag: Some("t".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    store.maintain().unwrap();
                    assert!(store.resolve_tag("r", "t").is_some());
                }

                #[test]
                fn repo_isolation() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutManifest {
                            repo: "a".into(),
                            digest: "sha256:m".into(),
                            media_type: "mt".into(),
                            tag: Some("v1".into()),
                            references: vec!["sha256:blob".into()],
                            referrer: None,
                        })
                        .unwrap();

                    // Repo "b" sees nothing
                    assert!(store.resolve_tag("b", "v1").is_none());
                    assert!(store.tags_page("b", None, 10).is_none());
                    assert!(store.backrefs("b", "sha256:blob").is_empty());
                    assert!(store.manifests("b").is_empty());
                }

                #[test]
                fn tag_reassignment() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Tag points to m1
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: Some("latest".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    // Reassign to m2
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m2".into(),
                            media_type: "mt2".into(),
                            tag: Some("latest".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    let (d, mt) = store.resolve_tag("r", "latest").unwrap();
                    assert_eq!(d, "sha256:m2");
                    assert_eq!(mt, "mt2");

                    // Only one tag entry
                    let p = store.tags_page("r", None, 10).unwrap();
                    assert_eq!(p.items.len(), 1);
                }

                #[test]
                fn referrer_dedup_by_digest() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc1 = descriptor(Some("sbom"));
                    let desc2 = descriptor(Some("sig"));

                    // Same referrer digest, different descriptors → last wins
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s".into(),
                            referrer: "sha256:r".into(),
                            descriptor: desc1,
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s".into(),
                            referrer: "sha256:r".into(),
                            descriptor: desc2.clone(),
                        })
                        .unwrap();

                    let page = store
                        .referrers_page("r", "sha256:s", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].1, desc2);

                    // Old artifact type index is cleaned up
                    let old_type_page = store
                        .referrers_page("r", "sha256:s", Some("sbom"), None, 10)
                        .unwrap();
                    assert!(old_type_page.items.is_empty());
                }

                #[test]
                fn backref_dedup() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Adding the same backref twice should not duplicate
                    store
                        .apply(MetaOp::PutBackrefs {
                            repo: "r".into(),
                            manifest: "sha256:m".into(),
                            blobs: vec!["sha256:b".into()],
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutBackrefs {
                            repo: "r".into(),
                            manifest: "sha256:m".into(),
                            blobs: vec!["sha256:b".into()],
                        })
                        .unwrap();

                    let br = store.backrefs("r", "sha256:b");
                    assert_eq!(br.len(), 1);
                }

                #[test]
                fn delete_manifest_preserves_other_backrefs() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Two manifests reference the same blob
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: None,
                            references: vec!["sha256:shared".into()],
                            referrer: None,
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m2".into(),
                            media_type: "mt".into(),
                            tag: None,
                            references: vec!["sha256:shared".into()],
                            referrer: None,
                        })
                        .unwrap();

                    let mut br = store.backrefs("r", "sha256:shared");
                    br.sort();
                    assert_eq!(br, vec!["sha256:m1", "sha256:m2"]);

                    // Delete m1 — m2's backref survives
                    store
                        .apply(MetaOp::DeleteManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                        })
                        .unwrap();

                    assert_eq!(store.backrefs("r", "sha256:shared"), vec!["sha256:m2"]);
                }
            }
        };
    }

    // ---- Log engine -------------------------------------------------------
    engine_tests!(log_engine, |root: &Path| {
        LogMetadataStore::open(root).unwrap()
    });

    // ---- Redb engine (feature-gated) --------------------------------------
    #[cfg(feature = "redb")]
    engine_tests!(redb_engine, |root: &Path| {
        RedbMetadataStore::open(root, &MetadataConfig::default()).unwrap()
    });

    // ---- open_metadata dispatch -------------------------------------------

    #[test]
    fn open_metadata_log() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = open_metadata(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:a".into(),
                media_type: "mt".into(),
                tag: Some("t".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        assert!(store.resolve_tag("r", "t").is_some());
    }

    #[cfg(feature = "redb")]
    #[test]
    fn open_metadata_redb() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Redb,
            ..MetadataConfig::default()
        };
        let store = open_metadata(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:a".into(),
                media_type: "mt".into(),
                tag: Some("t".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        assert!(store.resolve_tag("r", "t").is_some());
    }

    #[cfg(not(feature = "redb"))]
    #[test]
    fn open_metadata_redb_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Redb,
            ..MetadataConfig::default()
        };
        match open_metadata(dir.path(), &config) {
            Ok(_) => panic!("expected Unsupported error"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
        }
    }

    // ---- Redb persistence across reopen -----------------------------------
    #[cfg(feature = "redb")]
    #[test]
    fn redb_persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();

        {
            let store = RedbMetadataStore::open(dir.path(), &config).unwrap();
            let desc = descriptor(Some("sbom"));
            store
                .apply(MetaOp::PutManifest {
                    repo: "r".into(),
                    digest: "sha256:m".into(),
                    media_type: "mt".into(),
                    tag: Some("v1".into()),
                    references: vec!["sha256:blob".into()],
                    referrer: Some(("sha256:subj".into(), desc)),
                })
                .unwrap();
            store
                .apply(MetaOp::PutChecksum {
                    repo: "r".into(),
                    digest: "sha256:blob".into(),
                    crc32c: 99,
                    size: 200,
                })
                .unwrap();
        }

        // Reopen and verify everything survived
        {
            let store = RedbMetadataStore::open(dir.path(), &config).unwrap();
            let (d, mt) = store.resolve_tag("r", "v1").unwrap();
            assert_eq!(d, "sha256:m");
            assert_eq!(mt, "mt");
            assert_eq!(store.manifest_media_type("r", "sha256:m").unwrap(), "mt");
            assert_eq!(store.backrefs("r", "sha256:blob"), vec!["sha256:m"]);
            assert!(store.has_referrer("r", "sha256:subj", "sha256:m"));
            let bc = store.checksum("r", "sha256:blob").unwrap();
            assert_eq!(bc.crc32c, 99);
            assert_eq!(bc.size, 200);
            assert_eq!(store.repos(), vec!["r"]);
            let snap = store.tags_snapshot("r");
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].0, "v1");
        }
    }
}
