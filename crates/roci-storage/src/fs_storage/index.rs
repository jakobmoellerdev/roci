//! `index.json` write-behind and reconciliation.

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

const INDEX_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);
/// Quiet period before persisting, so a burst rewrites the index once.
const INDEX_COALESCE: std::time::Duration = std::time::Duration::from_millis(50);

impl FsStorage {
    /// Mark `repo` dirty and wake the background writer.
    pub(super) fn mark_index_dirty(&self, repo: &str) {
        *self
            .index_dirty
            .lock()
            .expect("index_dirty poisoned")
            .entry(repo.to_string())
            .or_insert(0) += 1;
        self.index_notify.notify_one();
    }

    /// Spawn the coalescing background `index.json` writer. Exits when cancel fires.
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

    /// Read `<repo>/index.json` beneath root (no-follow). `Ok(None)` when absent;
    /// `Err` for corrupt/unreadable (GC must not sweep that repo).
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

    /// Startup reconciliation: rebuild `index.json` from WAL + import foreign
    /// tags. Sweeps stale `.index.json.*.tmp` orphans.
    pub async fn reconcile_index_json(&self) {
        for repo in discover_repos(&self.root) {
            Self::sweep_index_tmp_orphans(&self.root, &repo);
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
            // Sweep repos known to metadata that lack an index/layout.
            Self::sweep_index_tmp_orphans(&self.root, &repo);

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

    /// Remove stale `.index.json.<rand>.tmp` orphans (no-follow, regular files only).
    fn sweep_index_tmp_orphans(root: &Path, repo: &str) {
        let Ok(repo_rel) = repo_rel(repo) else {
            return;
        };
        let repo_dir = root.join(repo_rel);
        let Ok(entries) = std::fs::read_dir(&repo_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with(".index.json.") || !name_str.ends_with(".tmp") {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let _ = std::fs::remove_file(entry.path());
        }
    }

    /// Atomically replace `<repo>/index.json` via `O_TMPFILE`+`linkat` (Linux)
    /// or named-temp fallback.
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

            if Self::try_write_index_otmpfile(&dirfd, &bytes, &tmp)? {
                return Ok(());
            }

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

    /// Linux: write via `O_TMPFILE`+`linkat`. Returns `Ok(false)` if unsupported.
    #[cfg(target_os = "linux")]
    fn try_write_index_otmpfile(
        dirfd: &std::os::fd::OwnedFd,
        bytes: &[u8],
        tmp_name: &str,
    ) -> io::Result<bool> {
        use rustix::fs::{AtFlags, Mode, OFlags};
        use rustix::io::Errno;
        use std::io::Write as _;
        use std::os::fd::AsRawFd;

        let opened = if fault!(FORCE_TMPFILE_UNSUPPORTED) {
            Err(Errno::OPNOTSUPP)
        } else {
            rustix::fs::openat(
                dirfd,
                ".",
                OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )
        };
        let fd = match opened {
            Ok(fd) => fd,
            Err(_) => return Ok(false),
        };
        let mut f = std::fs::File::from(fd);
        f.write_all(bytes)?;
        f.sync_all()?;

        let proc_path = format!("/proc/self/fd/{}", f.as_raw_fd());
        rustix::fs::linkat(
            rustix::fs::CWD,
            proc_path.as_str(),
            dirfd,
            tmp_name,
            AtFlags::SYMLINK_FOLLOW,
        )
        .map_err(io::Error::from)?;
        let renamed = rustix::fs::renameat(dirfd, tmp_name, dirfd, "index.json");
        if renamed.is_err() {
            let _ = rustix::fs::unlinkat(dirfd, tmp_name, AtFlags::empty());
        }
        renamed.map_err(io::Error::from)?;
        rustix::fs::fsync(dirfd).map_err(io::Error::from)?;
        Ok(true)
    }

    /// Non-Linux: `O_TMPFILE` unavailable; signal fallback.
    #[cfg(not(target_os = "linux"))]
    fn try_write_index_otmpfile(
        _dirfd: &std::os::fd::OwnedFd,
        _bytes: &[u8],
        _tmp_name: &str,
    ) -> io::Result<bool> {
        Ok(false)
    }

    /// Read `<repo>/index.json`. Dirty repos derive the current view in memory.
    pub(super) async fn read_index(&self, repo: &str) -> Result<serde_json::Value, StorageError> {
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

    /// Recover media type from `index.json` for a digest not in the in-RAM index.
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

    /// Resolve a tag to `(digest, media_type)` from `index.json` fallback.
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
