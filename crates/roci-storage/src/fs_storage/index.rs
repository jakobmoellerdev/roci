//! `index.json` write-behind and reconciliation: deriving the on-disk image
//! index from the metadata store, importing foreign tags, and the background
//! writer that persists dirty repos.

use super::paths::repo_rel;
use super::FsStorage;
use crate::beneath::*;
use crate::digest::Digest;
use crate::error::StorageError;
use crate::layout::*;
use crate::metadata::MetadataStore;
use futures::channel::oneshot;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::AsyncReadExt;

/// Retry interval for dirty `index.json` rewrites that failed (transient IO).
const INDEX_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);
/// Quiet period after a mutation before persisting, so a burst of pushes to a
/// repo rewrites its index once rather than per manifest. Reads through roci
/// never wait on it (a dirty repo's index is derived in memory).
const INDEX_COALESCE: std::time::Duration = std::time::Duration::from_millis(50);

impl FsStorage {
    /// Mark `repo` dirty (bumping its generation) and wake the background writer.
    pub(super) fn mark_index_dirty(&self, repo: &str) {
        *self
            .index_dirty
            .lock()
            .expect("index_dirty poisoned")
            .entry(repo.to_string())
            .or_insert(0) += 1;
        self.index_notify.notify_one();
    }

    /// Spawn the coalescing background `index.json` writer. Each wake snapshots
    /// the dirty map, rebuilds every dirty repo's index from the metadata store
    /// (preserving foreign descriptors on disk), writes it atomically, and
    /// clears the entry only if no newer mutation arrived meanwhile. A failed
    /// write stays dirty for the next wake. Exits when the last `FsStorage`
    /// clone drops (cancel sender dropped → `cancel` resolves).
    ///
    /// Constructed outside a Tokio runtime there is nowhere to run the task;
    /// the repos simply stay dirty (reads through roci derive the index in
    /// memory) and [`FsStorage::reconcile_index_json`] persists them later.
    pub(super) fn spawn_index_writer(&self, mut cancel: oneshot::Receiver<()>) {
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let dirty = Arc::clone(&self.index_dirty);
        let notify = Arc::clone(&self.index_notify);
        let root = Arc::clone(&self.root);
        let meta = Arc::clone(&self.meta);
        rt.spawn(async move {
            loop {
                // Wake on a new mutation; while anything is still dirty after a
                // failed pass (transient ENOSPC/EIO), also retry on a bounded
                // backoff so the on-disk index cannot stay stale indefinitely.
                let pending = !dirty.lock().expect("index_dirty poisoned").is_empty();
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(INDEX_RETRY_BACKOFF), if pending => {}
                    _ = &mut cancel => return,
                }
                tokio::time::sleep(INDEX_COALESCE).await;
                Self::flush_dirty(&root, &*meta, &dirty).await;
            }
        });
    }

    /// Persist every currently dirty repo's `index.json` (one pass). A repo
    /// whose existing index cannot be *read* (as opposed to being absent) is
    /// skipped and stays dirty — overwriting it from metadata alone would drop
    /// its foreign descriptors.
    pub(super) async fn flush_dirty(
        root: &Path,
        meta: &dyn MetadataStore,
        dirty: &StdMutex<HashMap<String, u64>>,
    ) {
        let snapshot: Vec<(String, u64)> = dirty
            .lock()
            .expect("index_dirty poisoned")
            .iter()
            .map(|(r, g)| (r.clone(), *g))
            .collect();
        for (repo, generation) in snapshot {
            let existing = match Self::read_index_beneath(root, &repo).await {
                Ok(existing) => existing,
                Err(e) => {
                    tracing::warn!(repo = %repo, error = %e, "index.json unreadable; write-behind deferred");
                    continue;
                }
            };
            let Ok(index) = crate::layout::index_from_meta(meta, &repo, existing, |d| {
                let (alg, hex) = d.split_once(':')?;
                std::fs::metadata(root.join(&repo).join("blobs").join(alg).join(hex))
                    .ok()
                    .map(|m| m.len())
            }) else {
                continue;
            };
            if let Err(e) = Self::write_index_at_root(root, &repo, &index).await {
                tracing::warn!(repo = %repo, error = %e, "index.json write-behind failed");
                continue;
            }
            let mut map = dirty.lock().expect("index_dirty poisoned");
            if map.get(&repo) == Some(&generation) {
                map.remove(&repo);
            }
        }
    }

    /// Read and parse `<repo>/index.json` beneath the root, no-follow. `Ok(None)`
    /// when absent. `Err` when the file exists but cannot be read or parsed
    /// (the GC must treat an unreadable existing index differently from an
    /// absent one — a missing index is benign, but a corrupt/unreadable one
    /// means root digests are unknown and GC must not sweep that repo).
    pub(super) async fn read_index_beneath(
        root: &Path,
        repo: &str,
    ) -> io::Result<Option<serde_json::Value>> {
        let rel = repo_rel(repo)
            .map_err(|e| io::Error::other(e.to_string()))?
            .join("index.json");
        let mut f = match open_beneath(root, &rel).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut b = Vec::new();
        f.read_to_end(&mut b).await?;
        serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Startup reconciliation (crash recovery for the write-behind): for every
    /// repo the metadata store knows, rebuild `index.json` and persist it if it
    /// differs from disk. Closes the window where a WAL record was durable but
    /// the process died before the background rename. Also imports tags from
    /// any pre-existing (externally written) `index.json` the log has not seen,
    /// so the first rebuild never drops them. Run once before serving.
    pub async fn reconcile_index_json(&self) {
        for repo in discover_repos(&self.root) {
            let Ok(Some(existing)) = Self::read_index_beneath(&self.root, &repo).await else {
                continue;
            };
            crate::layout::import_foreign_tags(&*self.meta, &repo, &existing);
            let Ok(rebuilt) =
                crate::layout::index_from_meta(&*self.meta, &repo, Some(existing.clone()), |d| {
                    let (alg, hex) = d.split_once(':')?;
                    std::fs::metadata(self.root.join(&repo).join("blobs").join(alg).join(hex))
                        .ok()
                        .map(|m| m.len())
                })
            else {
                continue;
            };
            if !same_manifest_set(&existing, &rebuilt) {
                self.mark_index_dirty(&repo);
            }
        }
        for repo in self.meta.repos() {
            if Self::read_index_beneath(&self.root, &repo)
                .await
                .ok()
                .flatten()
                .is_none()
            {
                self.mark_index_dirty(&repo);
            }
        }
        Self::flush_dirty(&self.root, &*self.meta, &self.index_dirty).await;
    }

    /// Atomically replace `<repo>/index.json`, anchored to a dirfd walked
    /// no-follow beneath the store root (a symlink planted at any repo
    /// component cannot redirect the write), ensuring the `oci-layout` marker
    /// first. Unique temp → `fsync` → `rename` → dir `fsync`, so every on-disk
    /// state is a complete index.
    pub(super) async fn write_index_at_root(
        root: &Path,
        repo: &str,
        index: &serde_json::Value,
    ) -> io::Result<()> {
        let repo_rel = repo_rel(repo).map_err(|e| io::Error::other(e.to_string()))?;
        ensure_layout_beneath(root, &repo_rel, OCI_LAYOUT_MARKER).await?;
        let bytes =
            serde_json::to_vec(index).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let root = root.to_path_buf();
        run_blocking("write_index_at_root", move || -> io::Result<()> {
            use rustix::fs::{Mode, OFlags};
            use std::io::Write as _;
            let dirfd = dir_beneath(&root, &repo_rel, false)?;
            let mut rnd = [0u8; 8];
            getrandom::fill(&mut rnd).map_err(io::Error::other)?;
            let tmp = format!(".index.json.{}.tmp", hex::encode(rnd));
            let fd = rustix::fs::openat(
                &dirfd,
                tmp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )
            .map_err(io::Error::from)?;
            let mut f = std::fs::File::from(fd);
            let written = f.write_all(&bytes).and_then(|()| f.sync_all());
            drop(f);
            let renamed = written.and_then(|()| {
                rustix::fs::renameat(&dirfd, tmp.as_str(), &dirfd, "index.json")
                    .map_err(io::Error::from)
            });
            if renamed.is_err() {
                let _ = rustix::fs::unlinkat(&dirfd, tmp.as_str(), rustix::fs::AtFlags::empty());
            }
            renamed?;
            rustix::fs::fsync(&dirfd).map_err(io::Error::from)
        })
        .await
    }

    /// Read `<repo>/index.json` as an image index. A missing index yields the
    /// canonical empty image index. A malformed on-disk index is an internal
    /// error (mapped to [`StorageError::Io`]).
    pub(super) async fn read_index(&self, repo: &str) -> Result<serde_json::Value, StorageError> {
        // A dirty repo's on-disk index.json lags the metadata store (write-behind);
        // derive the current view in memory. The background writer persists it.
        let is_dirty = self
            .index_dirty
            .lock()
            .expect("index_dirty poisoned")
            .contains_key(repo);
        if is_dirty {
            let existing = match tokio::fs::read(self.index_path(repo)?).await {
                Ok(b) => serde_json::from_slice(&b).ok(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(StorageError::Io(e)),
            };
            return crate::layout::index_from_meta(&*self.meta, repo, existing, |d| {
                let (alg, hex) = d.split_once(':')?;
                std::fs::metadata(self.root.join(repo).join("blobs").join(alg).join(hex))
                    .ok()
                    .map(|m| m.len())
            })
            .map_err(StorageError::Io);
        }
        match tokio::fs::read(self.index_path(repo)?).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(empty_index()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Fallback: recover a manifest's media type from `index.json` when the
    /// in-RAM index has no entry (e.g. an externally-provided layout the seed
    /// did not cover). `None` if the digest is not listed.
    pub(super) async fn index_media_type_for_digest(
        &self,
        repo: &str,
        digest: &str,
    ) -> Result<Option<String>, StorageError> {
        let index = self.read_index(repo).await?;
        Ok(index_manifests(&index)
            .iter()
            .find(|e| descriptor_digest(e) == Some(digest))
            .and_then(|e| e.get("mediaType"))
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    /// Fallback: resolve a tag to `(digest, media_type)` from `index.json` when
    /// the in-RAM tag map misses. `NotFound` if no descriptor carries the tag.
    pub(super) async fn index_resolve_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<(Digest, String), StorageError> {
        let index = self.read_index(repo).await?;
        let entry = index_manifests(&index)
            .iter()
            .find(|e| descriptor_tag(e) == Some(tag))
            .cloned()
            .ok_or(StorageError::NotFound)?;
        let digest = Digest::parse(descriptor_digest(&entry).ok_or(StorageError::NotFound)?)?;
        let media_type = entry
            .get("mediaType")
            .and_then(|v| v.as_str())
            .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST)
            .to_string();
        Ok((digest, media_type))
    }
}
