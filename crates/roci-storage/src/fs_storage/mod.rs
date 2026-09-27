//! Filesystem [`Storage`] construction and shared internals.

mod fast_restart;
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
    /// Default store (no quotas). See [`FsStorage::with_config`].
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_config(
            root,
            &StorageConfig::default(),
            Arc::new(QuotaTracker::default()),
        )
    }

    /// Create a store rooted at `root` with the given policy.
    /// Opens the metadata engine, then restores from a fast-restart stamp or
    /// walks the CAS to seed presence/dedupe/quota/sessions.
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
            SmallBlobCache::with_limits(config.small_blob_threshold, config.cache_max_bytes)
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
            upload_locks: Arc::default(),
            pending_uploads: Arc::new(StdMutex::new(HashMap::new())),
            blob_admit_locks: Arc::default(),
            index_dirty: Arc::new(StdMutex::new(HashMap::new())),
            index_notify: Arc::new(Notify::new()),
            _index_cancel: Arc::new(cancel_tx),
        };

        let fast_restored = if config.fast_restart {
            let hmac_key = config
                .metadata
                .hmac_key_file
                .as_ref()
                .map(|p| crate::metadata::wal_hmac::HmacKey::load(p))
                .transpose()?;
            match Self::try_consume_stamp(
                &store.root,
                config,
                hmac_key.as_ref(),
                store.meta.generation(),
                store.meta.log_len(),
            ) {
                Ok(stamp) => {
                    tracing::info!("fast restart: valid stamp consumed, skipping CAS walk");
                    store.apply_stamp(stamp);
                    true
                }
                Err(reason) => {
                    tracing::info!(%reason, "fast restart: falling back to full CAS walk");
                    false
                }
            }
        } else {
            false
        };

        if !fast_restored {
            store.seed_from_cas();
        }
        store.spawn_index_writer(cancel_rx);
        Ok(store)
    }

    /// Backrefs for `blob` in `repo` (GC liveness edges).
    pub fn backrefs(&self, repo: &str, blob: &crate::Digest) -> Vec<String> {
        self.meta.backrefs(repo, &blob.as_string())
    }

    /// One-time referrers upgrade: import `subject` links from each repo's
    /// `index.json` into the metadata store.
    pub async fn warm_referrers_from_layout(&self) {
        for repo in discover_repos(&self.root) {
            let Ok(Some(index)) = Self::read_index_beneath(&self.root, &repo).await else {
                continue;
            };
            for entry in index_manifests(&index) {
                let (Some(subject), Some(referrer)) =
                    (subject_digest(entry), descriptor_digest(entry))
                else {
                    continue;
                };
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

    /// Session lock for one upload; id is validated to prevent map-entry leaks.
    fn session_lock(&self, repo: &str, id: &str) -> Result<crate::SessionLock, StorageError> {
        SafeComponent::new(id)?;
        Ok(self.upload_locks.get(repo, id))
    }

    /// Whether `(repo, id)` is a pending (no staging file) session.
    fn is_pending(&self, repo: &str, id: &str) -> bool {
        self.pending_uploads
            .lock()
            .expect("pending-uploads poisoned")
            .contains_key(&(repo.to_string(), id.to_string()))
    }

    /// Forget a pending session; `true` if it was pending.
    fn take_pending(&self, repo: &str, id: &str) -> bool {
        self.pending_uploads
            .lock()
            .expect("pending-uploads poisoned")
            .remove(&(repo.to_string(), id.to_string()))
            .is_some()
    }

    /// Startup CAS walk: seed presence filter, dedupe index, quota usage, sessions.
    fn seed_from_cas(&self) {
        let track_bytes = self.quota.tracks_bytes();
        for_each_cas_blob(&self.root, |repo, digest, entry| {
            let digest = digest.as_string();
            self.presence.insert(repo, &digest);
            self.dedupe.insert(repo, &digest);
            if track_bytes {
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

    fn apply_meta(&self, repo: &str, op: MetaOp) -> Result<(), StorageError> {
        self.mark_index_dirty(repo);
        let applied = self.meta.apply(op).map_err(StorageError::Io);
        self.mark_index_dirty(repo);
        applied
    }

    /// Anchor the layout marker beneath the root (no-follow); sync on first creation.
    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        let repo_rel = repo_rel(repo)?;
        if ensure_layout_beneath(&self.root, &repo_rel, OCI_LAYOUT_MARKER).await? {
            let repo_dir = self.repo_dir(repo)?;
            sync_dir(repo_dir.parent().unwrap_or(&repo_dir)).await?;
        }
        Ok(())
    }
}
