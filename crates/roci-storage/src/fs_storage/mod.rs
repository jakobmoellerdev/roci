//! Filesystem [`Storage`] construction and shared internals. `FsStorage`
//! itself is defined at the crate root (the CodeQL path-barrier model keys on
//! `roci_storage::FsStorage`); this module and its children carry the impls.

mod index;
mod paths;
mod storage_impl;
#[cfg(test)]
mod tests;

use super::{FsStorage, MetaOp, StorageError};
use crate::beneath::*;
use crate::cache::SmallBlobCache;
use crate::filter::BlobPresenceFilter;
use crate::layout::*;
use crate::metadata::{LogMetadataStore, MetadataStore};
use futures::channel::oneshot;
use paths::{repo_rel, SafeComponent};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::AsyncReadExt;
use tokio::sync::Notify;

impl FsStorage {
    /// Create a store rooted at `root`, creating it if absent. Opens (replaying)
    /// the metadata log, then seeds the blob-presence filter from the CAS so it
    /// is complete (never false-negatives a stored blob). Tags/media-types/
    /// referrers are NOT walked at startup — a pre-existing layout resolves via
    /// the `index.json` read-path fallbacks and the metadata store warms on
    /// writes; the layout stays the source of truth.
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let meta = Arc::new(LogMetadataStore::open(&root)?);
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let store = Self {
            root: Arc::new(root),
            meta,
            presence: Arc::new(BlobPresenceFilter::new()),
            cache: Arc::new(SmallBlobCache::new()),
            upload_locks: Arc::new(StdMutex::new(HashMap::new())),
            index_dirty: Arc::new(StdMutex::new(HashMap::new())),
            index_notify: Arc::new(Notify::new()),
            _index_cancel: Arc::new(cancel_tx),
        };
        store.seed_presence_from_cas();
        store.spawn_index_writer(cancel_rx);
        Ok(store)
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
    fn session_lock(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, StorageError> {
        SafeComponent::new(id)?;
        let mut locks = self.upload_locks.lock().expect("upload-locks poisoned");
        Ok(Arc::clone(
            locks
                .entry((repo.to_string(), id.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
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

    /// Seed the blob-presence filter from every blob in the CAS so a definite
    /// absence (filter miss) is authoritative — the filter is complete, so a
    /// miss truly means "not stored" and can 404 without a syscall (RESEARCH
    /// §8.5). Walks `<repo>/blobs/<alg>/<hex>` for every repo (a repo dir is one
    /// holding `index.json`); skips in-progress `.tmp` files.
    fn seed_presence_from_cas(&self) {
        let root: &Path = &self.root;
        // Enumerate repo dirs (those containing index.json) up to a bounded
        // depth, then their blobs; best-effort — an unreadable dir just leaves
        // those blobs to fall through to a stat (never a wrong 404, because a
        // blob absent from the filter that IS on disk would only be reached if
        // the walk both saw the repo and failed mid-blobs, which re-adds via the
        // stat fallthrough being authoritative). See test coverage below.
        for repo in discover_repos(root) {
            let alg_root = root.join(&repo).join("blobs");
            let Ok(algs) = std::fs::read_dir(&alg_root) else {
                continue;
            };
            for alg in algs.flatten() {
                let alg_name = alg.file_name().to_string_lossy().into_owned();
                let Ok(hexes) = std::fs::read_dir(alg.path()) else {
                    continue;
                };
                for hex in hexes.flatten() {
                    let name = hex.file_name();
                    let hex_name = name.to_string_lossy();
                    // Skip in-progress tmp files (they carry an extension).
                    if hex_name.contains('.') {
                        continue;
                    }
                    self.presence
                        .insert(&repo, &format!("{alg_name}:{hex_name}"));
                }
            }
        }
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

    /// Best-effort: if the just-promoted blob is small enough, read it back
    /// (no-follow, beneath-root) and warm the small-blob cache. Any IO hiccup
    /// simply skips the warm — the loose CAS file is always the source of truth.
    async fn warm_small_blob_cache(&self, repo: &str, rel: &Path, digest_str: &str) {
        // The blob was just promoted, so it is present and regular. Read it back
        // (no-follow, beneath-root) and cache it only if small; any IO hiccup on
        // this optional warm is simply skipped (the loose CAS file is truth).
        let Ok(f) = open_beneath(&self.root, rel).await else {
            return;
        };
        // The small-blob cache only ever holds blobs up to its configured
        // threshold, and the cache itself enforces an absolute ceiling. Bound the
        // warm read by a compile-time constant (never by the operator threshold
        // alone) so this buffer's size is a fixed constant, not derived from
        // config/user-influenced state: read at most CAP+1 bytes through a capped
        // reader; if the blob exceeds the effective limit it is simply not cached.
        const WARM_CAP: usize = 8 * 1024 * 1024; // absolute ceiling for a warm-cache read
        let threshold = self.cache.threshold();
        // Effective limit is the smaller of the operator threshold and the
        // constant ceiling — so the allocation can never exceed WARM_CAP.
        let limit = threshold.min(WARM_CAP);
        // `take(limit as u64 + 1)`: read one past the limit to detect an
        // over-limit blob without ever buffering more than limit+1 bytes.
        let mut bytes = Vec::new();
        let read = f.take(limit as u64 + 1).read_to_end(&mut bytes).await;
        if read.is_err() || bytes.len() > limit {
            return; // IO hiccup, or too large to cache — skip the optional warm
        }
        self.cache.put(repo, digest_str, &bytes);
    }

    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        // Anchor the repo dir + `oci-layout` marker to a dirfd walked no-follow
        // beneath the store root: a symlink planted at a repo path component
        // cannot redirect the marker write outside the store (a path-based
        // `create_dir_all`+`write` would follow it). Idempotent.
        let repo_rel = repo_rel(repo)?;
        ensure_layout_beneath(&self.root, &repo_rel, OCI_LAYOUT_MARKER).await?;
        // Persist the repo path entry itself (its parent dir) so a blob-only
        // repository is discoverable after a crash. The repo dir is `<root>/…/
        // <name>`, so it has a parent under the root.
        let repo_dir = self.repo_dir(repo)?;
        sync_dir(repo_dir.parent().unwrap_or(&repo_dir)).await?;
        Ok(())
    }
}
