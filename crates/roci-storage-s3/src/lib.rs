//! Remote S3-compatible object-storage backend for roci.
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

/// S3-compatible object-store backend for roci (Clone).
#[derive(Clone)]
pub struct S3Storage {
    root: Arc<PathBuf>,
    client: S3Client,
    meta: Arc<dyn MetadataStore>,
    gc: Arc<GcTracker>,
    quota: Arc<QuotaTracker>,
    dedupe: Arc<DedupeIndex>,
    upload_locks: Arc<roci_storage::LockMap<()>>,
    index_dirty: Arc<StdMutex<HashMap<String, u64>>>,
    index_notify: Arc<Notify>,
    config: Arc<StorageConfig>,
    layout_cache: Arc<StdMutex<HashSet<String>>>,
    /// Manifest sizes for index.json rebuilds (avoids per-entry HEAD).
    manifest_sizes: Arc<StdMutex<HashMap<(String, String), u64>>>,
    cached_remote_index: Arc<StdMutex<HashMap<String, serde_json::Value>>>,
    admit_locks: Arc<roci_storage::LockMap<()>>,
    /// Last successful readiness probe (valid 10 s).
    readiness_cache: Arc<StdMutex<Option<std::time::Instant>>>,
    create_bucket: bool,
    bucket_ensured: Arc<std::sync::atomic::AtomicBool>,
}

impl S3Storage {
    /// Open (or create) the S3 backend.
    pub fn open(
        root: &Path,
        s3: &S3Config,
        storage: &StorageConfig,
        quota: Arc<QuotaTracker>,
    ) -> io::Result<Self> {
        let mut me = Self::open_with_client(root, S3Client::from_config(s3)?, storage, quota)?;
        me.create_bucket = s3.create_bucket;
        Ok(me)
    }

    pub(crate) fn open_with_client(
        root: &Path,
        client: S3Client,
        storage: &StorageConfig,
        quota: Arc<QuotaTracker>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(root)?;
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
            upload_locks: Arc::default(),
            index_dirty: Arc::new(StdMutex::new(HashMap::new())),
            index_notify: Arc::new(Notify::new()),
            config: Arc::new(storage.clone()),
            layout_cache: Arc::new(StdMutex::new(HashSet::new())),
            manifest_sizes: Arc::new(StdMutex::new(HashMap::new())),
            cached_remote_index: Arc::new(StdMutex::new(HashMap::new())),
            admit_locks: Arc::default(),
            readiness_cache: Arc::new(StdMutex::new(None)),
            create_bucket: false,
            bucket_ensured: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Mark a repo's remote index.json as dirty.
    fn mark_index_dirty(&self, repo: &str) {
        let mut dirty = self.index_dirty.lock().expect("index_dirty poisoned");
        let gen = dirty.get(repo).copied().unwrap_or(0) + 1;
        dirty.insert(repo.to_string(), gen);
        self.index_notify.notify_one();
    }

    /// Apply a metadata operation and mark dirty.
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
