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
        MetadataEngine::Redb => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage.metadata.engine = \"redb\" requires a build with the `redb` feature",
        )),
    }
}
