//! `index.json` write-behind and reconciliation: deriving the on-disk image
//! index from the metadata store, importing foreign tags, and the background
//! writer that persists dirty repos.

use super::paths::repo_rel;
use super::FsStorage;
use crate::beneath::*;
use crate::digest::Digest;
use crate::error::StorageError;
use crate::layout::*;
use crate::metadata::{MetaOp, MetadataStore};
use futures::channel::oneshot;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::AsyncReadExt;

/// Retry interval for dirty `index.json` rewrites that failed (transient IO).
const INDEX_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

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
            let Ok(index) = Self::index_from_meta(meta, &repo, root, existing) else {
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
    /// when absent or unparseable (the rebuild then starts from the store).
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
        Ok(serde_json::from_slice(&b).ok())
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
            self.import_foreign_tags(&repo, &existing);
            let Ok(rebuilt) =
                Self::index_from_meta(&*self.meta, &repo, &self.root, Some(existing.clone()))
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

    /// Record tagged descriptors from an on-disk index that the metadata store
    /// does not yet know (a layout written by another tool) so the write-behind
    /// treats them as live, not as deleted roci manifests.
    pub(super) fn import_foreign_tags(&self, repo: &str, existing: &serde_json::Value) {
        for e in index_manifests(existing) {
            let (Some(tag), Some(digest)) = (descriptor_tag(e), descriptor_digest(e)) else {
                continue;
            };
            if Digest::parse(digest).is_err() || self.meta.resolve_tag(repo, tag).is_some() {
                continue;
            }
            let media_type = e
                .get("mediaType")
                .and_then(|v| v.as_str())
                .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST);
            if let Err(err) = self.meta.apply(MetaOp::PutManifest {
                repo: repo.to_string(),
                digest: digest.to_string(),
                media_type: media_type.to_string(),
                tag: Some(tag.to_string()),
                references: Vec::new(),
                referrer: None,
            }) {
                tracing::warn!(repo = %repo, error = %err, "import of existing tag failed");
            }
        }
    }

    /// Rebuild a spec-valid `index.json` from the metadata store (authoritative
    /// for everything roci wrote) merged over the existing on-disk index.
    ///
    /// Rules: a manifest the store knows emits one descriptor per tag (or one
    /// untagged descriptor), enriched with its referrer fields (`subject`,
    /// `artifactType`, annotations) and any extra fields already on disk. An
    /// on-disk entry the store does not know is kept only if it is *foreign*
    /// — no `ref.name` tag and no `subject` (roci would have recorded either);
    /// otherwise it is a deleted manifest and is dropped.
    pub(super) fn index_from_meta(
        meta: &dyn MetadataStore,
        repo: &str,
        root: &Path,
        existing: Option<serde_json::Value>,
    ) -> io::Result<serde_json::Value> {
        type Obj = serde_json::Map<String, serde_json::Value>;
        let known: HashSet<String> = meta.manifests(repo).into_iter().collect();

        // Per-digest base descriptor (tag stripped) for known manifests, plus
        // foreign entries passed through verbatim.
        let mut base: HashMap<String, Obj> = HashMap::new();
        let mut foreign: Vec<serde_json::Value> = Vec::new();
        let existing_ms = existing.as_ref().map_or(&[][..], index_manifests);
        for e in existing_ms {
            let Some(obj) = e.as_object() else {
                foreign.push(e.clone());
                continue;
            };
            let digest = obj.get("digest").and_then(|v| v.as_str());
            match digest {
                Some(d) if known.contains(d) => {
                    let mut o = obj.clone();
                    if let Some(ann) = o.get_mut("annotations").and_then(|a| a.as_object_mut()) {
                        ann.remove(REF_NAME_ANNOTATION);
                        if ann.is_empty() {
                            o.remove("annotations");
                        }
                    }
                    base.entry(d.to_string()).or_insert(o);
                }
                _ if descriptor_tag(e).is_none() && e.get("subject").is_none() => {
                    foreign.push(e.clone());
                }
                _ => {} // deleted roci-managed manifest
            }
        }

        // Every known manifest gets a base (media type from the store; size
        // from the CAS when not already recorded).
        for d in &known {
            let o = base.entry(d.clone()).or_insert_with(|| {
                let mut o = Obj::new();
                o.insert("digest".into(), serde_json::Value::String(d.clone()));
                o
            });
            if let Some(mt) = meta.manifest_media_type(repo, d) {
                o.insert("mediaType".into(), serde_json::Value::String(mt));
            }
            if !o.contains_key("size") {
                if let Some((alg, hex)) = d.split_once(':') {
                    if let Ok(m) =
                        std::fs::metadata(root.join(repo).join("blobs").join(alg).join(hex))
                    {
                        o.insert("size".into(), serde_json::Value::Number(m.len().into()));
                    }
                }
            }
        }

        // Merge referrer descriptor fields into the referring manifest's base
        // (never overwriting its identity; existing annotations win). A live
        // referrer whose manifest the store does not track (DeleteManifest
        // already drops referrers) contributes its own descriptor.
        for (subject, refs) in meta.referrers_snapshot(repo) {
            for (ref_digest, ref_bytes) in refs {
                let o = base.entry(ref_digest.clone()).or_insert_with(|| {
                    let mut o = Obj::new();
                    o.insert(
                        "digest".into(),
                        serde_json::Value::String(ref_digest.clone()),
                    );
                    o
                });
                let Ok(r) = serde_json::from_slice::<Obj>(&ref_bytes) else {
                    continue;
                };
                for (k, v) in r {
                    match k.as_str() {
                        "digest" => {}
                        "mediaType" | "size" => {
                            o.entry(k).or_insert(v);
                        }
                        "annotations" => {
                            let (Some(new), Some(cur)) = (
                                v.as_object(),
                                o.entry("annotations")
                                    .or_insert_with(|| serde_json::Value::Object(Obj::new()))
                                    .as_object_mut(),
                            ) else {
                                continue;
                            };
                            for (ak, av) in new {
                                if ak != REF_NAME_ANNOTATION {
                                    cur.entry(ak.clone()).or_insert_with(|| av.clone());
                                }
                            }
                        }
                        _ => {
                            o.insert(k, v);
                        }
                    }
                }
                o.insert("subject".into(), serde_json::json!({ "digest": subject }));
            }
        }

        // Emit: one descriptor per tag, then untagged known manifests, then
        // foreign entries. Sorted for a deterministic, diff-friendly file.
        // `tags_snapshot` is tag-sorted.
        let tags = meta.tags_snapshot(repo);
        let mut tagged: HashSet<&str> = HashSet::new();
        let mut manifests: Vec<serde_json::Value> = Vec::with_capacity(base.len() + tags.len());
        for (tag, digest, _) in &tags {
            let Some(b) = base.get(digest) else { continue };
            let mut o = b.clone();
            let ann = o
                .entry("annotations")
                .or_insert_with(|| serde_json::Value::Object(Obj::new()));
            if let Some(ann) = ann.as_object_mut() {
                ann.insert(
                    REF_NAME_ANNOTATION.into(),
                    serde_json::Value::String(tag.clone()),
                );
            }
            tagged.insert(digest.as_str());
            manifests.push(serde_json::Value::Object(o));
        }
        let mut untagged: Vec<(&String, &Obj)> = base
            .iter()
            .filter(|(d, _)| !tagged.contains(d.as_str()))
            .collect();
        untagged.sort_by(|a, b| a.0.cmp(b.0));
        manifests.extend(
            untagged
                .into_iter()
                .map(|(_, o)| serde_json::Value::Object(o.clone())),
        );
        manifests.extend(foreign);
        // Keep any top-level fields another tool wrote (`annotations`,
        // `artifactType`, `subject`, …); regenerate only what roci owns.
        let mut top = existing
            .and_then(|v| match v {
                serde_json::Value::Object(o) => Some(o),
                _ => None,
            })
            .unwrap_or_default();
        top.insert("schemaVersion".into(), serde_json::json!(2));
        top.insert(
            "mediaType".into(),
            serde_json::json!("application/vnd.oci.image.index.v1+json"),
        );
        top.insert("manifests".into(), serde_json::Value::Array(manifests));
        Ok(serde_json::Value::Object(top))
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
        run_blocking(move || -> io::Result<()> {
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
            return Self::index_from_meta(&*self.meta, repo, &self.root, existing)
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
