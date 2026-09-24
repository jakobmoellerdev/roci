//! Online garbage collection for the filesystem backend: the startup
//! consistency check (backref rebuild from the layout + candidate seeding) and
//! the periodic O(garbage) sweep driven by [`crate::gc::GcTracker`].
//!
//! # Startup consistency check (backref rebuild)
//!
//! A crash or an externally-written layout may leave the metadata log missing
//! backref edges. A missing edge would cause GC to treat a referenced blob as
//! unreferenced. The check walks every known repository, reads each root
//! manifest from the CAS, derives edges via [`crate::manifest_references`],
//! and durably appends a `MetaOp::PutBackrefs` for any edge the store lacks.
//! A steady-state restart appends nothing. After the rebuild, every CAS blob
//! that has no backrefs and is not a known manifest is seeded into the
//! candidate set so the sweep can collect it after the grace period.
//!
//! # Sweep
//!
//! Periodic, O(garbage): only visits candidates whose grace period elapsed.
//! Each batch holds the exclusive fence, re-checks liveness, and unlinks
//! confirmed garbage beneath the store root (no-follow). Stale uploads whose
//! mtime exceeds the grace period and whose session is not locked are also
//! cleaned up.

use super::super::FsStorage;
use super::paths::{blob_dir_rel, repo_rel};
use crate::beneath::*;
use crate::layout::*;
use crate::metadata::MetaOp;
use crate::Digest;
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use tracing::Instrument;

/// Maximum number of candidates processed in one exclusive-fence batch.
const SWEEP_BATCH_SIZE: usize = 256;

impl FsStorage {
    /// Start the GC subsystem: background consistency check → `gc.set_ready()`
    /// → periodic sweeps every `config.gc.interval_secs`. Called from
    /// `start_maintenance` only when `gc.enabled()`.
    pub(super) fn start_gc(&self, shutdown: watch::Receiver<bool>) {
        let store = self.clone();
        let interval = Duration::from_secs(self.config.gc.interval_secs);
        tokio::spawn(async move {
            // 1. Startup consistency check (non-blocking — serving proceeds).
            store
                .gc_consistency_check()
                .instrument(tracing::info_span!("gc.consistency_check"))
                .await;
            store.gc.set_ready();
            tracing::info!(
                candidates = store.gc.len(),
                "GC ready: consistency check complete"
            );
            // 2. Periodic sweeps.
            store.spawn_periodic("gc.sweep", interval, shutdown, |s| async move {
                s.sweep_at(Instant::now()).await;
            });
        });
    }

    // ------------------------------------------------------------------
    // Startup consistency check
    // ------------------------------------------------------------------

    /// Walk every known repository: rebuild missing backref edges and seed
    /// the candidate set with unreferenced blobs. Concurrent pushes/deletes
    /// are safe — this only ever *adds* edges (worst case: a temporary leak).
    pub(crate) async fn gc_consistency_check(&self) {
        // Union of repos known from the layout and the metadata store.
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

        // Seed candidates: every CAS blob not a root/manifest with empty backrefs.
        let now = Instant::now();
        let root = self.root.clone();
        let meta = self.meta.clone();
        let gc = self.gc.clone();
        run_blocking(move || {
            for_each_cas_blob(&root, |repo, digest, _entry| {
                let ds = digest.as_string();
                // Skip manifests and roots.
                if meta.manifest_media_type(repo, &ds).is_some() || gc.is_root(repo, &ds) {
                    return;
                }
                // No backrefs → candidate.
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

    /// Rebuild backrefs for one repo. Discovers root manifests from the
    /// metadata store AND the on-disk `index.json`, recursively includes
    /// image-index children, and records missing backref edges.
    async fn gc_rebuild_repo(&self, repo: &str) {
        // Gather root digests from metadata + layout.
        let mut root_digests: HashSet<String> = HashSet::new();

        // (a) From the metadata store.
        for d in self.meta.manifests(repo) {
            root_digests.insert(d);
        }

        // (b) From on-disk index.json descriptors.
        if let Ok(Some(index)) = Self::read_index_beneath(&self.root, repo).await {
            for entry in index_manifests(&index) {
                if let Some(d) = descriptor_digest(entry) {
                    root_digests.insert(d.to_string());
                }
            }
        }

        // Recursively include image-index children present in the CAS.
        let mut to_visit: Vec<String> = root_digests.iter().cloned().collect();
        let mut all_roots: HashSet<String> = root_digests.clone();
        while let Some(digest_str) = to_visit.pop() {
            // Read the manifest from the CAS to discover children.
            let parsed = match Digest::parse(&digest_str) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let rel = match blob_dir_rel(repo, &parsed) {
                Ok((dir, leaf)) => dir.join(leaf),
                Err(_) => continue,
            };
            let bytes = match self.read_cas_blob_beneath(&rel).await {
                Some(b) => b,
                None => continue,
            };
            let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    // Unparseable root → repo unsafe.
                    if root_digests.contains(&digest_str) {
                        tracing::warn!(repo, digest = %digest_str, "unparseable root manifest; repo is GC-unsafe");
                        self.gc.mark_unsafe(repo);
                    }
                    continue;
                }
            };

            // If it's an image index, its `manifests[*]` children are also roots.
            if let Some(children) = manifest.get("manifests").and_then(|v| v.as_array()) {
                for child in children {
                    if let Some(cd) = child.get("digest").and_then(|v| v.as_str()) {
                        if all_roots.insert(cd.to_string()) {
                            to_visit.push(cd.to_string());
                        }
                    }
                }
            }
        }

        // Register the roots the metadata store does not already know as
        // manifests (layout-only ones); recorded manifests are protected by
        // the sweep's media-type check, so they cost no extra memory here.
        for d in &all_roots {
            if self.meta.manifest_media_type(repo, d).is_none() {
                self.gc.add_root(repo, d);
            }
        }

        // For each root manifest, read it, derive edges, and record missing ones.
        for digest_str in &all_roots {
            let parsed = match Digest::parse(digest_str) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let rel = match blob_dir_rel(repo, &parsed) {
                Ok((dir, leaf)) => dir.join(leaf),
                Err(_) => continue,
            };
            let bytes = match self.read_cas_blob_beneath(&rel).await {
                Some(b) => b,
                None => {
                    // A root manifest that exists in the index but not in the CAS:
                    // this makes the repo GC-unsafe — we can't know its edges.
                    if root_digests.contains(digest_str) {
                        tracing::warn!(repo, digest = %digest_str, "root manifest missing from CAS; repo is GC-unsafe");
                        self.gc.mark_unsafe(repo);
                    }
                    continue;
                }
            };
            let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    // Already warned above for root_digests, but a child manifest
                    // that's unparseable also makes the repo unsafe.
                    tracing::warn!(repo, digest = %digest_str, "unparseable manifest; repo is GC-unsafe");
                    self.gc.mark_unsafe(repo);
                    continue;
                }
            };
            let references: Vec<String> = manifest_references(&manifest)
                .iter()
                .map(Digest::as_string)
                .collect();
            // Check which edges are missing and record them.
            let existing_backrefs_by_blob: Vec<(String, bool)> = references
                .iter()
                .map(|blob| {
                    let has = self.meta.backrefs(repo, blob).contains(digest_str);
                    (blob.clone(), has)
                })
                .collect();
            let missing: Vec<String> = existing_backrefs_by_blob
                .into_iter()
                .filter(|(_, has)| !has)
                .map(|(blob, _)| blob)
                .collect();
            if !missing.is_empty() {
                if let Err(e) = self.meta.apply(MetaOp::PutBackrefs {
                    repo: repo.to_string(),
                    manifest: digest_str.clone(),
                    blobs: missing,
                }) {
                    tracing::warn!(repo, digest = %digest_str, error = %e, "recording backref edges failed");
                }
            }
        }
    }

    /// Read a CAS blob beneath the store root; returns `None` for absent or
    /// unreadable blobs (best-effort, never an error).
    async fn read_cas_blob_beneath(&self, rel: &Path) -> Option<Vec<u8>> {
        let mut f = open_beneath(&self.root, rel).await.ok()?;
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut f, &mut bytes)
            .await
            .ok()?;
        Some(bytes)
    }

    // ------------------------------------------------------------------
    // Sweep
    // ------------------------------------------------------------------

    /// Run one sweep pass at the given `now` instant (allows deterministic tests).
    /// Collects due candidates in batches, then cleans up stale uploads.
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
                // Re-check under the exclusive fence.
                if !self.gc.is_due(repo, digest, now) {
                    continue;
                }
                // Skip if it's a root manifest.
                if self.gc.is_root(repo, digest) {
                    self.gc.clear(repo, digest);
                    continue;
                }
                // Skip if the repo is unsafe.
                if self.gc.is_unsafe(repo) {
                    continue;
                }
                // Skip if it has backrefs now (concurrent push may have referenced it).
                if !self.meta.backrefs(repo, digest).is_empty() {
                    self.gc.clear(repo, digest);
                    continue;
                }
                // Skip if the metadata store knows it as a manifest.
                if self.meta.manifest_media_type(repo, digest).is_some() {
                    self.gc.clear(repo, digest);
                    continue;
                }
                // Resolve the blob path.
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
                // Stat for size (no-follow beneath-root).
                let size = match stat_beneath(&self.root, &alg_rel.join(&leaf)).await {
                    Ok(Some((true, s))) => s,
                    Ok(None | Some((false, _))) => {
                        // Already gone or not a regular file.
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
                // Unlink beneath-root (no-follow).
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

        // Stale upload cleanup.
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

    /// Clean up uploads whose mtime is older than the GC delay and whose
    /// session is not currently locked. Returns `(count, bytes)`.
    async fn sweep_stale_uploads(&self) -> (u64, u64) {
        let delay = self.gc.delay();
        // Enumerate stale staging files off the async workers.
        let root = self.root.clone();
        let stale = run_blocking(move || {
            let mut stale = Vec::new();
            for repo in discover_repos(&root) {
                let Ok(upload_dir) = repo_rel(&repo).map(|r| r.join("uploads")) else {
                    continue;
                };
                let Ok(entries) = std::fs::read_dir(root.join(&upload_dir)) else {
                    continue;
                };
                for entry in entries.flatten() {
                    // `DirEntry::metadata` does not follow a symlink leaf.
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
        for (repo, upload_dir, name, size) in stale {
            // A session currently being appended/finalized is not stale.
            if self
                .upload_locks
                .lock()
                .expect("upload-locks poisoned")
                .contains_key(&(repo.clone(), name.clone()))
            {
                continue;
            }
            if unlink_beneath(&self.root, &upload_dir, &name).await.is_ok() {
                self.quota.end_session();
                roci_telemetry::record_gc_collected("upload", size);
                count += 1;
                bytes += size;
            }
        }
        (count, bytes)
    }
}
