//! Filesystem GC: startup backref rebuild + candidate seeding, then periodic
//! O(garbage) sweep via [`crate::gc::GcTracker`].

use super::super::FsStorage;
use super::paths::{blob_dir_rel, repo_rel};
use crate::beneath::*;
use crate::layout::*;
use crate::Digest;
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use tracing::Instrument;

const SWEEP_BATCH_SIZE: usize = 256;

impl FsStorage {
    /// Start GC: background consistency check → periodic sweeps.
    pub(super) fn start_gc(&self, shutdown: watch::Receiver<bool>) {
        let store = self.clone();
        let interval = Duration::from_secs(self.config.gc.interval_secs);
        tokio::spawn(async move {
            if store.gc.is_ready() {
                tracing::info!(
                    candidates = store.gc.len(),
                    "GC ready: fast restart (consistency check skipped)"
                );
            } else {
                store
                    .gc_consistency_check()
                    .instrument(tracing::info_span!("gc.consistency_check"))
                    .await;
                store.gc.set_ready();
                tracing::info!(
                    candidates = store.gc.len(),
                    "GC ready: consistency check complete"
                );
            }
            crate::storage::spawn_periodic(
                store.clone(),
                "gc.sweep",
                interval,
                shutdown,
                |s| async move {
                    s.sweep_at(Instant::now()).await;
                },
            );
        });
    }

    /// Rebuild backrefs and seed unreferenced blobs as candidates.
    pub(crate) async fn gc_consistency_check(&self) {
        let mut repos: Vec<String> = discover_repos(&self.root);
        {
            let meta_repos = self.meta.repos();
            let layout_set: HashSet<String> = repos.iter().cloned().collect();
            for r in meta_repos {
                if !layout_set.contains(&r) {
                    repos.push(r);
                }
            }
        }

        for repo in &repos {
            self.gc_rebuild_repo(repo).await;
        }

        let now = Instant::now();
        let root = self.root.clone();
        let meta = self.meta.clone();
        let gc = self.gc.clone();
        run_blocking("gc_consistency_check", move || {
            for_each_cas_blob(&root, |repo, digest, _entry| {
                let ds = digest.as_string();
                if meta.manifest_media_type(repo, &ds).is_some() || gc.is_root(repo, &ds) {
                    return;
                }
                if meta.backrefs(repo, &ds).is_empty() {
                    gc.mark_at(repo, &ds, now);
                }
            });
            Ok(())
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "GC candidate seeding failed");
        });
    }

    /// Rebuild backrefs for one repo via the shared single-pass walker.
    async fn gc_rebuild_repo(&self, repo: &str) {
        // Gather root digests from metadata + layout.
        let mut roots: HashSet<String> = self.meta.manifests(repo).into_iter().collect();

        match Self::read_index_beneath(&self.root, repo).await {
            Ok(Some(index)) => {
                for entry in index_manifests(&index) {
                    if let Some(d) = descriptor_digest(entry) {
                        roots.insert(d.to_string());
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(repo, error = %e, "unreadable index.json; repo is GC-unsafe");
                self.gc.mark_unsafe(repo);
                return;
            }
        }

        let store = self.clone();
        let repo_owned = repo.to_string();
        crate::gc::rebuild_backrefs(repo, &*self.meta, &self.gc, roots, |d| {
            let store = store.clone();
            let repo = repo_owned.clone();
            async move {
                match blob_dir_rel(&repo, &d) {
                    Ok((dir, leaf)) => {
                        store
                            .read_cas_blob_bounded(
                                &dir.join(leaf),
                                crate::gc::MAX_ROOT_MANIFEST_BYTES,
                            )
                            .await
                    }
                    Err(_) => Ok(None),
                }
            }
        })
        .await;
    }

    /// Read a CAS blob beneath root with an upper size bound.
    async fn read_cas_blob_bounded(
        &self,
        rel: &Path,
        max_bytes: u64,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let mut f = match open_beneath(&self.root, rel).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = f.metadata().await?;
        if meta.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("root manifest {} bytes exceeds {max_bytes} cap", meta.len()),
            ));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        tokio::io::AsyncReadExt::read_to_end(&mut f, &mut bytes).await?;
        Ok(Some(bytes))
    }

    /// One sweep pass; collects due candidates then cleans stale uploads.
    pub(crate) async fn sweep_at(&self, now: Instant) {
        if !self.gc.is_ready() {
            tracing::debug!("GC sweep skipped: not ready");
            return;
        }

        let mut collected_blobs: u64 = 0;
        let mut collected_bytes: u64 = 0;
        let mut errors: u64 = 0;

        let due = self.gc.due(now);
        for batch in due.chunks(SWEEP_BATCH_SIZE) {
            let _fence = self.gc.exclusive().await;
            for (repo, digest) in batch {
                if !self.gc.is_due(repo, digest, now) {
                    continue;
                }
                if self.gc.is_root(repo, digest) {
                    self.gc.clear(repo, digest);
                    continue;
                }
                if self.gc.is_unsafe(repo) {
                    continue;
                }
                if !self.meta.backrefs(repo, digest).is_empty() {
                    self.gc.clear(repo, digest);
                    continue;
                }
                if self.meta.manifest_media_type(repo, digest).is_some() {
                    self.gc.clear(repo, digest);
                    continue;
                }
                let parsed = match Digest::parse(digest) {
                    Ok(d) => d,
                    Err(_) => {
                        self.gc.clear(repo, digest);
                        continue;
                    }
                };
                let (alg_rel, leaf) = match blob_dir_rel(repo, &parsed) {
                    Ok(pair) => pair,
                    Err(_) => {
                        self.gc.clear(repo, digest);
                        continue;
                    }
                };
                let size = match stat_beneath(&self.root, &alg_rel.join(&leaf)).await {
                    Ok(Some((true, s))) => s,
                    Ok(None | Some((false, _))) => {
                        self.gc.clear(repo, digest);
                        continue;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        self.gc.clear(repo, digest);
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(repo, digest, error = %e, "GC stat failed");
                        errors += 1;
                        continue;
                    }
                };
                match unlink_beneath(&self.root, &alg_rel, &leaf).await {
                    Ok(()) => {
                        self.blob_left(repo, digest, Some(size));
                        roci_telemetry::record_gc_collected("blob", size);
                        collected_bytes += size;
                        collected_blobs += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        self.gc.clear(repo, digest);
                    }
                    Err(e) => {
                        tracing::warn!(repo, digest, error = %e, "GC unlink failed");
                        errors += 1;
                    }
                }
            }
        }

        let (stale_uploads, stale_bytes) = self.sweep_stale_uploads().await;

        let total_collected = collected_blobs + stale_uploads;
        let total_bytes = collected_bytes + stale_bytes;
        if total_collected > 0 {
            tracing::info!(
                blobs = collected_blobs,
                uploads = stale_uploads,
                bytes = total_bytes,
                errors,
                "GC sweep collected"
            );
        } else {
            tracing::debug!(errors, "GC sweep: nothing to collect");
        }
    }

    /// Clean up stale uploads beyond the GC delay. Returns `(count, bytes)`.
    async fn sweep_stale_uploads(&self) -> (u64, u64) {
        let delay = self.gc.delay();
        let root = self.root.clone();
        let stale = run_blocking("sweep_stale_uploads", move || {
            let mut stale = Vec::new();
            for repo in discover_repos(&root) {
                let Ok(upload_dir) = repo_rel(&repo).map(|r| r.join("uploads")) else {
                    continue;
                };
                let Ok(entries) = std::fs::read_dir(root.join(&upload_dir)) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let Ok(meta) = entry.metadata() else { continue };
                    let age = meta
                        .modified()
                        .ok()
                        .and_then(|m| SystemTime::now().duration_since(m).ok())
                        .unwrap_or(Duration::ZERO);
                    if age >= delay {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        stale.push((repo.clone(), upload_dir.clone(), name, meta.len()));
                    }
                }
            }
            Ok(stale)
        })
        .await
        .unwrap_or_default();
        let mut count: u64 = 0;
        let mut bytes: u64 = 0;
        // Pending sessions (no staging file) expire the same way.
        let expired: Vec<(String, String)> = self
            .pending_uploads
            .lock()
            .expect("pending-uploads poisoned")
            .iter()
            .filter(|(_, began)| began.elapsed() >= delay)
            .map(|(k, _)| k.clone())
            .collect();
        for (repo, id) in expired {
            let Ok(lock) = self.session_lock(&repo, &id) else {
                continue;
            };
            let Ok(guard) = lock.try_lock() else {
                continue;
            };
            if self.take_pending(&repo, &id) {
                self.quota.end_session();
                roci_telemetry::record_gc_collected("upload", 0);
                count += 1;
            }
            drop(guard);
            self.upload_locks.remove(&repo, &id);
        }
        for (repo, upload_dir, name, _initial_size) in stale {
            // Skip if session is currently locked by an append/finalize/abort.
            let lock = {
                let Ok(l) = self.session_lock(&repo, &name) else {
                    continue;
                };
                l
            };
            let Some(guard) = lock.try_lock().ok() else {
                continue;
            };
            let rel = upload_dir.join(&name);
            let still_stale = match stat_beneath(&self.root, &rel).await {
                Ok(Some((true, size))) => {
                    let full = self.root.join(&rel);
                    let age = std::fs::symlink_metadata(&full)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|m| SystemTime::now().duration_since(m).ok())
                        .unwrap_or(Duration::ZERO);
                    if age >= delay {
                        Some(size)
                    } else {
                        None
                    }
                }
                _ => None, // gone or not a regular file
            };
            let Some(size) = still_stale else {
                drop(guard);
                self.upload_locks.remove(&repo, &name);
                continue;
            };
            if unlink_beneath(&self.root, &upload_dir, &name).await.is_ok() {
                self.quota.end_session();
                roci_telemetry::record_gc_collected("upload", size);
                count += 1;
                bytes += size;
            }
            drop(guard);
            self.upload_locks.remove(&repo, &name);
        }
        (count, bytes)
    }
}
