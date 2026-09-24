//! Storage subsystem for roci: a content-addressable store (CAS) backed by the
//! local filesystem, plus the [`Storage`] trait the registry core is written
//! against. Blob I/O is streamed with hash-on-write; nothing buffers a whole
//! blob in memory (ARCHITECTURE.md invariant 4).
#![forbid(unsafe_code)]

#[macro_use]
mod fault;

mod beneath;
mod cache;
mod digest;
mod error;
mod filter;
mod fs_storage;
mod layout;
mod metadata;
mod publish;
mod storage;

pub use digest::{digest_of, sha256_of, Digest};
pub use error::StorageError;
pub use layout::{MEDIA_TYPE_IMAGE_INDEX, MEDIA_TYPE_IMAGE_MANIFEST};
pub use metadata::{LogMetadataStore, MetaOp, MetadataStore, Page, Referrer};
pub use storage::{ManifestRef, Storage};

use cache::SmallBlobCache;
use filter::BlobPresenceFilter;
use futures::channel::oneshot;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Notify;

/// Per-session upload locks: `(repo, id) → async lock` serializing an upload's
/// append/finish/abort so they never interleave (see [`FsStorage::session_lock`]).
type UploadLocks = Arc<StdMutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>>;

/// Filesystem-backed [`Storage`]. Each repository is a self-contained OCI
/// image layout under `<root>/<repo>/`: `oci-layout` (marker), `index.json`
/// (the image index — source of truth for tags, manifest media types and the
/// subject/referrers relation), `blobs/<algo>/<hex>` (content-addressable
/// store for blobs *and* manifests), and `uploads/<id>` (in-progress, not part
/// of the served layout). This lets roci serve any pre-existing OCI layout.
#[derive(Clone)]
pub struct FsStorage {
    root: Arc<PathBuf>,
    /// Derived, rebuildable metadata index (tags, media types, referrers) kept
    /// in RAM and mirrored to `roci-meta.log`. Reads resolve against this first
    /// and fall back to `index.json`; the layout stays the source of truth.
    meta: Arc<LogMetadataStore>,
    /// In-RAM blob-presence filter: a definite-absent answer short-circuits the
    /// filesystem `stat` on the read path (RESEARCH §8.5). Never authoritative
    /// for presence — a "maybe" always verifies on disk (SECURITY inv. 10).
    presence: Arc<BlobPresenceFilter>,
    /// Bounded in-RAM small-blob content cache (RESEARCH §9.2): serves
    /// manifests/configs with zero syscalls. A miss falls through to the loose
    /// CAS file, which always exists (never the sole copy).
    cache: Arc<SmallBlobCache>,
    /// Per-session async locks serializing `append`/`finish`/`abort` on one
    /// upload id, so a concurrent PATCH cannot inject bytes between a finish's
    /// hash-verify and its promote (a TOCTOU that would commit unverified data
    /// or bypass the size cap). Keyed by `(repo, id)`; entries are dropped when
    /// a session finishes or aborts.
    upload_locks: UploadLocks,
    /// Background index write-behind: repos whose `index.json` lags the
    /// metadata store, with a per-repo mutation generation. Mutations bump the
    /// generation and wake the writer; the writer clears an entry only if its
    /// generation is unchanged after a successful write, so a reader never
    /// sees a repo as clean while its on-disk index is stale.
    index_dirty: Arc<StdMutex<HashMap<String, u64>>>,
    /// Wake channel for the background index writer.
    index_notify: Arc<Notify>,
    /// Held only to be dropped: when the last `FsStorage` clone goes away the
    /// receiver in the writer task resolves and the task exits.
    _index_cancel: Arc<oneshot::Sender<()>>,
}
