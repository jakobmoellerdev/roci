//! Filesystem [`Storage`] construction and shared internals. `FsStorage`
//! itself is defined at the crate root (the CodeQL path-barrier model keys on
//! `roci_storage::FsStorage`); this module and its children carry the impls.

mod gc;
mod index;
mod lifecycle;
mod maintenance;
mod paths;
mod scrub;
mod storage_impl;
#[cfg(test)]
mod tests;

use super::{FsStorage, MetaOp, StorageError};
use crate::beneath::*;
use crate::cache::SmallBlobCache;
use crate::dedupe::DedupeIndex;
use crate::filter::BlobPresenceFilter;
use crate::gc::GcTracker;
use crate::layout::*;
use crate::metadata::open_metadata;
use crate::quota::QuotaTracker;
use futures::channel::oneshot;
use paths::{repo_rel, SafeComponent};
use roci_config::StorageConfig;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Notify;

impl FsStorage {
    /// Create a store rooted at `root` under the default `[storage]` policy
    /// and no quotas (see [`FsStorage::with_config`]).
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_config(
            root,
            &StorageConfig::default(),
            Arc::new(QuotaTracker::default()),
        )
    }

    /// Create a store rooted at `root` (created if absent) running the given
    /// `[storage]` policy, charging writes to the shared `quota` tracker.
    /// Opens (replaying) the metadata engine, then walks the CAS once to seed
    /// the blob-presence filter (complete, never false-negative), the dedupe
    /// index, quota byte usage and the open upload-session count.
    /// Tags/media-types/referrers are NOT walked at startup — a pre-existing
    /// layout resolves via the `index.json` read-path fallbacks and the
    /// metadata store warms on writes; the layout stays the source of truth.
    /// Background maintenance (GC, scrub, metadata upkeep) starts only via
    /// [`FsStorage::start_maintenance`].
    pub fn with_config(
        root: impl AsRef<Path>,
        config: &StorageConfig,
        quota: Arc<QuotaTracker>,
    ) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let meta = open_metadata(&root, &config.metadata)?;
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let cache = if config.cache_max_bytes == 0 {
            SmallBlobCache::with_limits(0, 0)
        } else {
            SmallBlobCache::with_limits(
                crate::cache::DEFAULT_SMALL_BLOB_THRESHOLD,
                config.cache_max_bytes,
            )
        };
        let store = Self {
            root: Arc::new(root),
            config: Arc::new(config.clone()),
            meta,
            presence: Arc::new(BlobPresenceFilter::new()),
            cache: Arc::new(cache),
            gc: Arc::new(GcTracker::new(
                config.gc.enabled,
                Duration::from_secs(config.gc.delay_secs),
            )),
            quota,
            dedupe: Arc::new(DedupeIndex::new(config.dedupe)),
            upload_locks: Arc::new(StdMutex::new(HashMap::new())),
            blob_admit_locks: Arc::new(StdMutex::new(HashMap::new())),
            index_dirty: Arc::new(StdMutex::new(HashMap::new())),
            index_notify: Arc::new(Notify::new()),
            _index_cancel: Arc::new(cancel_tx),
        };
        store.seed_from_cas();
        store.spawn_index_writer(cancel_rx);
        Ok(store)
    }

    /// The manifest digests currently recorded as referencing `blob` in `repo`
    /// (GC liveness edges).
    pub fn backrefs(&self, repo: &str, blob: &crate::Digest) -> Vec<String> {
        self.meta.backrefs(repo, &blob.as_string())
    }

    /// One-time referrers enable-upgrade pass: walk every repo's `index.json`,
    /// and for any descriptor carrying `subject` register it in the metadata
    /// store so `list_referrers` sees pre-existing links. Call at startup when
    /// the runtime (Tokio) is available.
    pub async fn warm_referrers_from_layout(&self) {
        for repo in discover_repos(&self.root) {
            // No-follow beneath-root read: a symlinked `index.json` cannot inject
            // descriptors from outside the store.
            let Ok(Some(index)) = Self::read_index_beneath(&self.root, &repo).await else {
                continue;
            };
            for entry in index_manifests(&index) {
                let (Some(subject), Some(referrer)) =
                    (subject_digest(entry), descriptor_digest(entry))
                else {
                    continue;
                };
                // Already known (log replay or live push): nothing to upgrade.
                if self.meta.has_referrer(&repo, subject, referrer) {
                    continue;
                }
                let Ok(descriptor) = serde_json::to_vec(entry) else {
                    continue;
                };
                if let Err(e) = self.meta.apply(MetaOp::PutReferrer {
                    repo: repo.clone(),
                    subject: subject.to_string(),
                    referrer: referrer.to_string(),
                    descriptor,
                }) {
                    tracing::warn!(repo = %repo, error = %e, "referrers upgrade record failed");
                }
            }
        }
    }

    /// The async lock for one upload session, creating it on first use. Held
    /// across `append`/`finish`/`abort` so those never interleave on one id.
    /// The id is validated *before* an entry is created, so a stream of
    /// syntactically-invalid ids cannot leak lock-map entries; a caller that
    /// then finds no session drops the entry on its error path.
    fn session_lock(&self, repo: &str, id: &str) -> Result<crate::SessionLock, StorageError> {
        SafeComponent::new(id)?;
        let mut locks = self.upload_locks.lock().expect("upload-locks poisoned");
        Ok(Arc::clone(
            locks
                .entry((repo.to_string(), id.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))),
        ))
    }

    /// Drop a finished/aborted session's lock entry so the map does not grow
    /// unbounded across many uploads.
    fn drop_session_lock(&self, repo: &str, id: &str) {
        self.upload_locks
            .lock()
            .expect("upload-locks poisoned")
            .remove(&(repo.to_string(), id.to_string()));
    }

    /// Per-`(repo, digest)` async lock serializing blob admission + publication.
    /// Prevents two concurrent uploads of the same absent blob from both
    /// charging quota while only one actually lands.
    fn blob_admit_lock(&self, repo: &str, digest: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .blob_admit_locks
            .lock()
            .expect("blob-admit-locks poisoned");
        Arc::clone(
            locks
                .entry((repo.to_string(), digest.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Drop a blob-admission lock entry after publication.
    /// Removed only when no other admission of the same blob holds or waits
    /// on it (map + the caller's clone), so a waiter never races a fresh lock.
    fn drop_blob_admit_lock(&self, repo: &str, digest: &str) {
        let mut locks = self
            .blob_admit_locks
            .lock()
            .expect("blob-admit-locks poisoned");
        let key = (repo.to_string(), digest.to_string());
        if locks.get(&key).is_some_and(|l| Arc::strong_count(l) <= 2) {
            locks.remove(&key);
        }
    }

    /// One startup walk over every CAS blob and staged upload: seeds the
    /// blob-presence filter so a definite absence (filter miss) is
    /// authoritative — the filter is complete, so a miss truly means "not
    /// stored" and can 404 without a syscall (RESEARCH §8.5) — plus the dedupe
    /// index, quota byte usage (one no-follow `lstat` per blob, only when a
    /// byte cap is configured) and the open upload-session count.
    fn seed_from_cas(&self) {
        let track_bytes = self.quota.tracks_bytes();
        for_each_cas_blob(&self.root, |repo, digest, entry| {
            let digest = digest.as_string();
            self.presence.insert(repo, &digest);
            self.dedupe.insert(repo, &digest);
            if track_bytes {
                // `DirEntry::metadata` does not follow a symlink leaf.
                if let Ok(m) = entry.metadata() {
                    if m.is_file() {
                        self.quota.seed(repo, m.len());
                    }
                }
            }
        });
        let sessions: usize = discover_repos(&self.root)
            .iter()
            .filter_map(|repo| std::fs::read_dir(self.root.join(repo).join("uploads")).ok())
            .map(|ups| ups.flatten().count())
            .sum();
        self.quota.seed_sessions(sessions);
    }

    /// Apply a metadata mutation bracketed by dirty marks. Marking *before*
    /// the apply means a concurrent reader never observes the repo as clean
    /// while the store is ahead of `index.json` (its fallback reads would
    /// otherwise resurrect a just-deleted tag/referrer). Bumping the generation
    /// again *after* the apply means a writer that snapshotted in between
    /// cannot clear the entry for a rebuild that predates this mutation.
    fn apply_meta(&self, repo: &str, op: MetaOp) -> Result<(), StorageError> {
        self.mark_index_dirty(repo);
        let applied = self.meta.apply(op).map_err(StorageError::Io);
        self.mark_index_dirty(repo);
        applied
    }

    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        // Anchor the repo dir + `oci-layout` marker to a dirfd walked no-follow
        // beneath the store root: a symlink planted at a repo path component
        // cannot redirect the marker write outside the store (a path-based
        // `create_dir_all`+`write` would follow it). Idempotent.
        let repo_rel = repo_rel(repo)?;
        // On first creation only, persist the repo path entry itself (its
        // parent dir) so a blob-only repository is discoverable after a crash.
        // (Syncing on every call cost one fsync per upload.)
        if ensure_layout_beneath(&self.root, &repo_rel, OCI_LAYOUT_MARKER).await? {
            let repo_dir = self.repo_dir(repo)?;
            sync_dir(repo_dir.parent().unwrap_or(&repo_dir)).await?;
        }
        Ok(())
    }
}
