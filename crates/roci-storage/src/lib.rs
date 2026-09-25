//! Storage subsystem for roci: a content-addressable store (CAS) backed by the
//! local filesystem, plus the [`Storage`] trait the registry core is written
//! against. Blob I/O is streamed with hash-on-write; nothing buffers a whole
//! blob in memory (ARCHITECTURE.md invariant 4).
#![deny(unsafe_code)]

#[macro_use]
mod fault;

/// Beneath-root, no-follow filesystem primitives (SECURITY inv. 8) shared
/// with other backends' local state (e.g. S3 upload staging).
pub mod beneath;
mod bufpool;
mod cache;
mod dedupe;
mod digest;
mod error;
mod filter;
mod fs_storage;
pub mod gc;
mod layout;
mod metadata;
mod publish;
pub mod quota;
pub mod routing;
mod storage;
mod upload_body;

pub use dedupe::DedupeIndex;
pub use digest::{digest_of, sha256_of, Digest};
pub use error::{QuotaScope, StorageError};
pub use layout::{
    import_foreign_tags, index_from_meta, manifest_references, MEDIA_TYPE_IMAGE_INDEX,
    MEDIA_TYPE_IMAGE_MANIFEST,
};
pub use metadata::{
    open_metadata, BlobChecksum, LogMetadataStore, MetaOp, MetadataStore, Page, Referrer,
};
pub use storage::{
    BlobRead, BlobStream, ManifestLinks, ManifestRef, RangeOpener, Storage, StorageBackend,
};
pub use upload_body::{append_body, upload_body, StagedHash, UploadBody};

use cache::SmallBlobCache;
use filter::BlobPresenceFilter;
use futures::channel::oneshot;
use gc::GcTracker;
use quota::QuotaTracker;
use roci_config::StorageConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Notify;

/// Per-session upload locks: `(repo, id) → async lock` serializing an upload's
/// append/finish/abort so they never interleave (see [`FsStorage::session_lock`]).
/// Per-session lock; its payload is the session's hash-on-write state (so it
/// is dropped with the session).
type SessionLock = Arc<tokio::sync::Mutex<Option<StagedHash>>>;
type UploadLocks = Arc<StdMutex<HashMap<(String, String), SessionLock>>>;
type AdmitLocks = Arc<StdMutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>>;

/// Filesystem-backed [`Storage`]. Each repository is a self-contained OCI
/// image layout under `<root>/<repo>/`: `oci-layout` (marker), `index.json`
/// (the image index — source of truth for tags, manifest media types and the
/// subject/referrers relation), `blobs/<algo>/<hex>` (content-addressable
/// store for blobs *and* manifests), and `uploads/<id>` (in-progress, not part
/// of the served layout). This lets roci serve any pre-existing OCI layout.
#[derive(Clone)]
pub struct FsStorage {
    root: Arc<PathBuf>,
    /// The `[storage]` policy this store runs under (GC, scrub, dedupe, …).
    config: Arc<StorageConfig>,
    /// Derived, rebuildable metadata index (tags, media types, referrers,
    /// backrefs, checksums) behind the engine-agnostic [`MetadataStore`] seam.
    /// Reads resolve against this first and fall back to `index.json`; the
    /// layout stays the source of truth.
    meta: Arc<dyn MetadataStore>,
    /// In-RAM blob-presence filter: a definite-absent answer short-circuits the
    /// filesystem `stat` on the read path (RESEARCH §8.5). Never authoritative
    /// for presence — a "maybe" always verifies on disk (SECURITY inv. 10).
    presence: Arc<BlobPresenceFilter>,
    /// Bounded in-RAM small-blob content cache (RESEARCH §9.2): serves
    /// manifests/configs with zero syscalls. A miss falls through to the loose
    /// CAS file, which always exists (never the sole copy).
    cache: Arc<SmallBlobCache>,
    /// Online-GC candidate set + in-flight fence ([`gc`]).
    gc: Arc<GcTracker>,
    /// Byte quotas + upload-session cap, shared across a registry's backends.
    quota: Arc<QuotaTracker>,
    /// `digest → repo` dedupe cache for linking re-uploaded blobs.
    dedupe: Arc<DedupeIndex>,
    /// Per-session async locks serializing `append`/`finish`/`abort` on one
    /// upload id, so a concurrent PATCH cannot inject bytes between a finish's
    /// hash-verify and its promote (a TOCTOU that would commit unverified data
    /// or bypass the size cap). Keyed by `(repo, id)`; entries are dropped when
    /// a session finishes or aborts.
    upload_locks: UploadLocks,
    /// Upload sessions begun but not yet written to: their staging file is
    /// created by the first append/finalize, inside the blocking hop that
    /// request makes anyway (so `POST` costs no filesystem work). Value: when
    /// the session began, for stale-session expiry. Not persisted — an empty
    /// session does not survive a restart (the client gets
    /// `BLOB_UPLOAD_UNKNOWN` and starts over, as for any expired session).
    pending_uploads: Arc<StdMutex<HashMap<(String, String), std::time::Instant>>>,
    /// Per-`(repo, digest)` async locks serializing blob admission + publication,
    /// so concurrent uploads of the same absent blob cannot both charge quota
    /// while only one actually lands (quota double-count). Entries are transient:
    /// created on first admission for a key, dropped after publication.
    blob_admit_locks: AdmitLocks,
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
