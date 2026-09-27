//! Storage subsystem: content-addressable store backed by the local filesystem,
//! plus the [`Storage`] trait the registry core is written against.
#![deny(unsafe_code)]

#[macro_use]
mod fault;

/// Beneath-root, no-follow filesystem primitives (SECURITY inv. 8).
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
mod lifecycle;
mod lock_map;
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
    empty_index, import_foreign_tags, index_from_meta, layout_subject_referrers, layout_tags_page,
    manifest_references, page_layout_referrers, page_sorted, referrer_descriptor,
    MEDIA_TYPE_IMAGE_INDEX, MEDIA_TYPE_IMAGE_MANIFEST, OCI_LAYOUT_MARKER,
};
pub use lifecycle::{note_blob_entered, note_blob_left};
pub use lock_map::LockMap;
pub use metadata::{
    open_metadata, BlobChecksum, LogMetadataStore, MetaOp, MetadataStore, Page, Referrer,
};
pub use storage::{
    spawn_periodic, BlobRead, BlobStream, ManifestLinks, ManifestRef, RangeOpener, Storage,
    StorageBackend,
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

type SessionLock = Arc<tokio::sync::Mutex<Option<StagedHash>>>;

/// Filesystem-backed [`Storage`]: each repository is a self-contained OCI
/// image layout under `<root>/<repo>/`.
#[derive(Clone)]
pub struct FsStorage {
    root: Arc<PathBuf>,
    config: Arc<StorageConfig>,
    /// Metadata index (tags, media types, referrers, backrefs, checksums).
    meta: Arc<dyn MetadataStore>,
    /// Blob-presence filter: definite-absent skips a `stat` (RESEARCH §8.5).
    /// Never authoritative for presence (SECURITY inv. 10).
    presence: Arc<BlobPresenceFilter>,
    /// Bounded small-blob content cache (RESEARCH §9.2).
    cache: Arc<SmallBlobCache>,
    gc: Arc<GcTracker>,
    quota: Arc<QuotaTracker>,
    dedupe: Arc<DedupeIndex>,
    /// Per-session locks serializing append/finish/abort on one upload id.
    upload_locks: Arc<LockMap<Option<StagedHash>>>,
    /// Upload sessions begun but not yet written to (staging file created
    /// lazily on first append). Not persisted across restarts.
    pending_uploads: Arc<StdMutex<HashMap<(String, String), std::time::Instant>>>,
    blob_admit_locks: Arc<LockMap<()>>,
    /// Repos whose `index.json` lags the metadata store, with mutation gen.
    index_dirty: Arc<StdMutex<HashMap<String, u64>>>,
    index_notify: Arc<Notify>,
    _index_cancel: Arc<oneshot::Sender<()>>,
}
