//! Remote object-storage backend for roci (S3-compatible).
//!
//! Implements [`roci_storage::Storage`] and [`roci_storage::StorageBackend`]
//! against any S3-compatible object store via the `object_store` crate.
//! Feature-gated behind `roci-cli`'s `s3` feature; the routing slice wires
//! this against the `S3Config` from `roci-config`.
#![forbid(unsafe_code)]

mod client;
mod keys;
mod storage_impl;
mod uploads;

#[cfg(test)]
mod tests;

use client::S3Client;
use roci_config::{S3Config, StorageConfig};
use roci_storage::gc::GcTracker;
use roci_storage::quota::QuotaTracker;
use roci_storage::{DedupeIndex, MetadataStore};
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Notify;

/// Keyed async locks: `(repo, id-or-digest) → lock` (upload sessions, blob admission).
type UploadLocks = Arc<StdMutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>>;

/// S3-compatible object-store backend for roci.
///
/// # Contract
/// `pub struct S3Storage` (Clone) with
/// `pub fn open(root, s3, storage, quota) -> io::Result<S3Storage>` (sync).
#[derive(Clone)]
pub struct S3Storage {
    /// Local state directory (metadata log + upload staging).
    root: Arc<PathBuf>,
    /// The object store client (S3 or InMemory for tests).
    client: S3Client,
    /// Derived metadata (tags, media types, referrers, backrefs, checksums).
    meta: Arc<dyn MetadataStore>,
    /// Online-GC candidate set + in-flight fence.
    gc: Arc<GcTracker>,
    /// Byte quotas + upload-session cap, shared across backends.
    quota: Arc<QuotaTracker>,
    /// `digest → repo` dedupe cache for server-side copy.
    dedupe: Arc<DedupeIndex>,
    /// Per-session async locks.
    upload_locks: UploadLocks,
    /// Repos whose remote `index.json` needs updating.
    index_dirty: Arc<StdMutex<HashMap<String, u64>>>,
    /// Wake channel for the background index writer.
    index_notify: Arc<Notify>,
    /// Config snapshot.
    config: Arc<StorageConfig>,
    /// Per-repo oci-layout marker presence cache (avoids a HEAD on every push).
    layout_cache: Arc<StdMutex<HashSet<String>>>,
    /// Recorded manifest sizes for index.json rebuilds (no per-entry HEAD).
    /// Key: `(repo, digest)`, value: byte size.
    manifest_sizes: Arc<StdMutex<HashMap<(String, String), u64>>>,
    /// Cached remote index.json for synchronous media-type lookups.
    cached_remote_index: Arc<StdMutex<HashMap<String, serde_json::Value>>>,
    /// Striped per-`(repo, digest)` async locks serialising admit+publish so
    /// concurrent uploads of the same blob cannot double-charge quota.
    admit_locks: UploadLocks,
}

impl S3Storage {
    /// Open (or create) the S3 backend. Sync; `root` is a local state dir
    /// for the metadata engine + upload staging.
    pub fn open(
        root: &Path,
        s3: &S3Config,
        storage: &StorageConfig,
        quota: Arc<QuotaTracker>,
    ) -> io::Result<Self> {
        Self::open_with_client(root, S3Client::from_config(s3)?, storage, quota)
    }

    /// Internal constructor shared by `open` and tests (InMemory).
    pub(crate) fn open_with_client(
        root: &Path,
        client: S3Client,
        storage: &StorageConfig,
        quota: Arc<QuotaTracker>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(root)?;
        // Create the uploads staging dir.
        std::fs::create_dir_all(root.join("uploads"))?;
        let meta = roci_storage::open_metadata(root, &storage.metadata)?;
        Ok(Self {
            root: Arc::new(root.to_path_buf()),
            client,
            meta,
            gc: Arc::new(GcTracker::new(
                storage.gc.enabled,
                Duration::from_secs(storage.gc.delay_secs),
            )),
            quota,
            dedupe: Arc::new(DedupeIndex::new(storage.dedupe)),
            upload_locks: Arc::new(StdMutex::new(HashMap::new())),
            index_dirty: Arc::new(StdMutex::new(HashMap::new())),
            index_notify: Arc::new(Notify::new()),
            config: Arc::new(storage.clone()),
            layout_cache: Arc::new(StdMutex::new(HashSet::new())),
            manifest_sizes: Arc::new(StdMutex::new(HashMap::new())),
            cached_remote_index: Arc::new(StdMutex::new(HashMap::new())),
            admit_locks: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    /// Acquire (or create) the per-session async lock.
    fn session_lock(&self, repo: &str, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = (repo.to_string(), id.to_string());
        let mut map = self.upload_locks.lock().expect("upload_locks poisoned");
        Arc::clone(
            map.entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Drop a session lock entry.
    fn drop_session_lock(&self, repo: &str, id: &str) {
        self.upload_locks
            .lock()
            .expect("upload_locks poisoned")
            .remove(&(repo.to_string(), id.to_string()));
    }

    /// Acquire (or create) a per-`(repo, digest)` async lock so that
    /// concurrent uploads of the same blob serialise through admit+publish.
    fn admit_lock(&self, repo: &str, digest: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = (repo.to_string(), digest.to_string());
        let mut map = self.admit_locks.lock().expect("admit_locks poisoned");
        Arc::clone(
            map.entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Drop an admit lock entry once the publish is complete.
    /// Removed only when no other admission of the same blob holds or waits
    /// on it (map + the caller's clone), so a waiter never races a fresh lock.
    fn drop_admit_lock(&self, repo: &str, digest: &str) {
        let mut locks = self.admit_locks.lock().expect("admit_locks poisoned");
        let key = (repo.to_string(), digest.to_string());
        if locks.get(&key).is_some_and(|l| Arc::strong_count(l) <= 2) {
            locks.remove(&key);
        }
    }

    /// Mark a repo's remote `index.json` as needing a rewrite.
    fn mark_index_dirty(&self, repo: &str) {
        let mut dirty = self.index_dirty.lock().expect("index_dirty poisoned");
        let gen = dirty.get(repo).copied().unwrap_or(0) + 1;
        dirty.insert(repo.to_string(), gen);
        self.index_notify.notify_one();
    }

    /// Apply a metadata operation and mark the repo dirty.
    fn apply_meta(
        &self,
        repo: &str,
        op: roci_storage::MetaOp,
    ) -> Result<(), roci_storage::StorageError> {
        self.meta.apply(op)?;
        self.mark_index_dirty(repo);
        Ok(())
    }
}
