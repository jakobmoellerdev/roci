//! [`Storage`] and [`StorageBackend`] implementation for [`S3Storage`].

use crate::keys::{blob_key, index_key, layout_key, repo_prefix, validate_repo};
use crate::S3Storage;
use bytes::Bytes;
use futures::StreamExt;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, WriteMultipart};
use roci_storage::{
    BlobChecksum, BlobRead, BlobStream, Digest, ManifestLinks, ManifestRef, MetaOp, Page,
    RangeOpener, Referrer, Storage, StorageBackend, StorageError,
};
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::time::Duration;

// ── helpers ────────────────────────────────────────────────────────────

fn obj_err(e: object_store::Error) -> StorageError {
    match e {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        other => StorageError::Io(io::Error::other(other.to_string())),
    }
}

/// OCI image layout marker content.
const OCI_LAYOUT_MARKER: &str = "{\"imageLayoutVersion\":\"1.0.0\"}";

const MEDIA_TYPE_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// Build the referrer descriptor with `subject` merged in.
fn referrer_descriptor(subject: &Digest, descriptor: &[u8]) -> Result<Vec<u8>, StorageError> {
    let invalid =
        |e: serde_json::Error| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e));
    let mut merged: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(descriptor).map_err(invalid)?;
    merged.insert(
        "subject".into(),
        serde_json::json!({ "digest": subject.as_string() }),
    );
    serde_json::to_vec(&merged).map_err(invalid)
}

/// Build an empty OCI image index.
fn empty_index() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": []
    })
}

/// Maximum candidates processed per exclusive-fence batch in GC sweep.
const SWEEP_BATCH_SIZE: usize = 256;

/// S3 single CopyObject limit: 5 GiB.
pub(crate) const S3_COPY_LIMIT: u64 = 5 * 1024 * 1024 * 1024;

// ── Storage trait impl ─────────────────────────────────────────────────

impl Storage for S3Storage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        // Refresh the GC stamp under the pin *before* the existence check, so
        // a concurrent sweep either deleted it already (the HEAD then 404s) or
        // sees the fresh stamp and keeps it for another grace period.
        if let Some(_pin) = self.gc.pin().await {
            self.gc.touch(repo, &digest.as_string());
        }
        let meta = self.client.store.head(&path).await.map_err(obj_err)?;
        Ok(meta.size)
    }

    async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        match self.blob_size(repo, digest).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        let result = self.client.store.get(&path).await.map_err(obj_err)?;
        let bytes = result
            .bytes()
            .await
            .map_err(|e| StorageError::Io(io::Error::other(e.to_string())))?;
        Ok(bytes.to_vec())
    }

    async fn open_blob(&self, repo: &str, digest: &Digest) -> Result<BlobRead, StorageError> {
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        let meta = self.client.store.head(&path).await.map_err(obj_err)?;
        let size = meta.size as u64;

        // Redirect: signed GET URL for blobs above redirect_min_size.
        if self.client.redirect_min_size > 0 && size >= self.client.redirect_min_size {
            if let Some(signer) = &self.client.signer {
                let url = signer
                    .signed_url(http::Method::GET, &path, self.client.redirect_ttl)
                    .await;
                if let Ok(url) = url {
                    return Ok(BlobRead::redirect(size, url.to_string()));
                }
                // Signing failed: fall through to ranged proxy.
            }
        }

        // Ranged proxy: stream ranges from S3.
        let store = self.client.store.clone();
        let path_clone = path.clone();
        let opener: RangeOpener = Box::new(move |start: u64, len: u64| {
            let store = store.clone();
            let p = path_clone.clone();
            Box::pin(async move {
                let opts = object_store::GetOptions {
                    range: Some((start..start + len).into()),
                    ..Default::default()
                };
                let result = store
                    .get_opts(&p, opts)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let stream: BlobStream = result
                    .into_stream()
                    .map(|r| r.map_err(|e| io::Error::other(e.to_string())))
                    .boxed();
                Ok(stream)
            })
        });

        Ok(BlobRead::ranged(size, opener))
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        validate_repo(repo)?;
        self.begin_upload_session(repo).await
    }

    async fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> Result<u64, StorageError> {
        validate_repo(repo)?;
        let lock = self.session_lock(repo, id);
        let _guard = lock.lock().await;
        self.append_to_staging(repo, id, chunk, expected_offset)
            .await
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        validate_repo(repo)?;
        self.staging_size(repo, id).await
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        validate_repo(repo)?;
        let lock = self.session_lock(repo, id);
        let _guard = lock.lock().await;
        // staging_rel validates both repo and session-id components.
        let dir_rel = match self.repo_staging_rel(repo) {
            Ok(d) => d,
            Err(_) => {
                self.drop_session_lock(repo, id);
                return Ok(false);
            }
        };
        // Validate the session id is safe to use as a leaf component.
        if self.staging_rel(repo, id).is_err() {
            self.drop_session_lock(repo, id);
            return Ok(false);
        }
        let removed = match roci_storage::beneath::unlink_beneath(&self.root, &dir_rel, id).await {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(StorageError::Io(e)),
        };
        if removed {
            self.quota.end_session();
        }
        self.drop_session_lock(repo, id);
        Ok(removed)
    }

    async fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
        max_size: u64,
        trailing: &[u8],
    ) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let lock = self.session_lock(repo, id);
        let _guard = lock.lock().await;

        // Append trailing bytes (monolithic PUT body).
        if !trailing.is_empty() {
            self.append_to_staging(repo, id, trailing, None).await?;
        }

        // Check size under the lock.
        let staged_size = self.staging_size(repo, id).await?;
        if staged_size > max_size {
            self.discard_session(repo, id).await;
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: staged_size,
            });
        }

        // Stream-hash to verify digest.
        let (actual, crc32c, size) = self.hash_staging(repo, id, expected.algorithm()).await?;
        if !actual.ct_eq(expected) {
            self.discard_session(repo, id).await;
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }

        // Serialize admit+publish per (repo, digest) to prevent double quota charge.
        let digest_str = expected.as_string();
        let admit_lock = self.admit_lock(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;

        // Quota admission.
        let charged = match self.admit_blob(repo, expected, size).await {
            Ok(c) => c,
            Err(e) => {
                // Quota rejection: discard session like FsStorage.
                self.discard_session(repo, id).await;
                return Err(e);
            }
        };

        // GC pin.
        let pin = self.gc.pin().await;

        // Ensure OCI layout marker exists BEFORE publishing the object so a
        // layout-creation failure cannot leave an orphaned S3 blob.
        if let Err(e) = self.ensure_layout(repo).await {
            drop(pin);
            self.quota.release(repo, charged);
            self.discard_session(repo, id).await;
            return Err(e);
        }

        // Dedupe: server-side copy from another repo if available.
        let linked = self
            .try_server_side_copy(repo, expected, &digest_str, size)
            .await;

        if !linked {
            // Upload the staged file to S3 via streaming multipart.
            if let Err(e) = self.upload_staged_blob(repo, expected, id).await {
                drop(pin);
                self.quota.release(repo, charged);
                self.discard_session(repo, id).await;
                return Err(e);
            }
        }

        // Cleanup local staging + end session.
        self.remove_staging(repo, id).await;
        self.drop_session_lock(repo, id);

        // Bookkeeping.
        self.blob_entered(repo, &digest_str, Some(BlobChecksum { crc32c, size }));
        drop(pin);
        self.drop_admit_lock(repo, &digest_str);
        Ok(())
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        validate_repo(repo)?;
        // Verify digest.
        let actual = roci_storage::digest_of(data, digest.algorithm());
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }

        let digest_str = digest.as_string();

        // Serialize admit+publish per (repo, digest) to prevent double quota charge.
        let admit_lock = self.admit_lock(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;

        let charged = self.admit_blob(repo, digest, data.len() as u64).await?;
        let pin = self.gc.pin().await;

        // Ensure OCI layout marker exists BEFORE publishing the object so a
        // layout-creation failure cannot leave an orphaned S3 blob.
        if let Err(e) = self.ensure_layout(repo).await {
            drop(pin);
            self.quota.release(repo, charged);
            return Err(e);
        }

        // Dedupe: server-side copy from another repo.
        let linked = self
            .try_server_side_copy(repo, digest, &digest_str, data.len() as u64)
            .await;

        if !linked {
            // Direct put.
            let key = blob_key(&self.client.prefix, repo, digest)?;
            let path = ObjPath::from(key);
            if let Err(e) = self
                .client
                .store
                .put(&path, PutPayload::from(Bytes::copy_from_slice(data)))
                .await
            {
                drop(pin);
                self.quota.release(repo, charged);
                return Err(obj_err(e));
            }
        }

        self.blob_entered(
            repo,
            &digest_str,
            Some(BlobChecksum {
                crc32c: crc32c::crc32c(data),
                size: data.len() as u64,
            }),
        );
        drop(pin);
        self.drop_admit_lock(repo, &digest_str);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        // Get size before deleting; absent blob → NotFound (spec 404).
        let size = match self.client.store.head(&path).await {
            Ok(meta) => meta.size,
            Err(object_store::Error::NotFound { .. }) => return Err(StorageError::NotFound),
            Err(e) => return Err(obj_err(e)),
        };
        // Delete.
        self.client.store.delete(&path).await.map_err(obj_err)?;
        // Only blob_left after a successful delete.
        self.blob_left(repo, &digest.as_string(), Some(size));
        Ok(())
    }

    async fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
        links: ManifestLinks<'_>,
    ) -> Result<(), StorageError> {
        validate_repo(repo)?;
        // Validate tag.
        if let Some(tag) = tag {
            if tag.is_empty()
                || tag == "."
                || tag == ".."
                || tag.bytes().any(|b| b == b'/' || b == b'\\' || b == 0)
            {
                return Err(StorageError::BadPath(tag.to_string()));
            }
        }
        let referrer = match links.subject {
            Some((subject, descriptor)) => Some((
                subject.as_string(),
                referrer_descriptor(subject, descriptor)?,
            )),
            None => None,
        };

        // ── Hold one GC pin from blob publication through MetaOp apply ──
        // This prevents a concurrent sweep from deleting the manifest blob
        // (or a required blob) in the gap between put and metadata commit.
        let pin = self.gc.pin().await;

        // Store manifest as a blob (verifies digest, ensures layout).
        // put_blob internally acquires its own pin (a shared read-lock),
        // which is compatible with the one we already hold.
        self.put_blob(repo, digest, data).await?;

        // Re-verify every required digest is present under the same fence.
        // A sweep cannot run while we hold the pin, so if they exist now
        // they will still exist when the metadata record is committed.
        for required in links.required {
            if !self.blob_exists(repo, required).await? {
                drop(pin);
                return Err(StorageError::MissingReference(required.as_string()));
            }
        }

        // One atomic metadata record.
        let digest_str = digest.as_string();
        let references: Vec<String> = links.references.iter().map(Digest::as_string).collect();
        self.apply_meta(
            repo,
            MetaOp::PutManifest {
                repo: repo.to_string(),
                digest: digest_str.clone(),
                media_type: media_type.to_string(),
                tag: tag.map(str::to_string),
                references: references.clone(),
                referrer,
            },
        )?;

        // Record manifest size for index.json rebuilds (no per-entry HEAD).
        self.record_manifest_size(repo, &digest_str, data.len() as u64);

        // GC: manifest and its references are live.
        self.gc.clear(repo, &digest_str);
        for r in &references {
            self.gc.clear(repo, r);
        }
        drop(pin);
        Ok(())
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        validate_repo(repo)?;
        let (digest, media_type) = if reference.contains(':') {
            let digest = Digest::parse(reference)?;
            // Try metadata first; fall back to remote index.json media type.
            let media_type = self
                .meta
                .manifest_media_type(repo, reference)
                .or_else(|| self.index_media_type_for_digest(repo, reference))
                .unwrap_or_else(|| MEDIA_TYPE_IMAGE_MANIFEST.to_string());
            (digest, media_type)
        } else {
            match self.meta.resolve_tag(repo, reference) {
                Some((digest_str, media_type)) => (Digest::parse(&digest_str)?, media_type),
                None => {
                    // Fallback: read index.json from S3.
                    self.index_resolve_tag(repo, reference).await?
                }
            }
        };

        let bytes = self.read_blob(repo, &digest).await?;
        Ok(ManifestRef {
            digest,
            media_type,
            bytes,
        })
    }

    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let digest_str = digest.as_string();

        // Read what it references before deleting.
        let references = match self.read_blob(repo, digest).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(|v| roci_storage::manifest_references(&v))
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        // Delete the blob.
        self.delete_blob(repo, digest).await?;
        self.forget_manifest_size(repo, &digest_str);

        // Metadata.
        self.apply_meta(
            repo,
            MetaOp::DeleteManifest {
                repo: repo.to_string(),
                digest: digest_str.clone(),
            },
        )?;

        // GC candidates: objects whose last referencing manifest was this one.
        for r in references.iter().map(Digest::as_string) {
            if self.meta.backrefs(repo, &r).is_empty() {
                self.gc.mark(repo, &r);
            }
        }
        Ok(())
    }

    async fn list_tags(
        &self,
        repo: &str,
        last: Option<&str>,
        limit: usize,
    ) -> Result<Page<String>, StorageError> {
        validate_repo(repo)?;
        if let Some(page) = self.meta.tags_page(repo, last, limit) {
            return Ok(page);
        }
        // Fallback: read index.json.
        let index = self.read_remote_index(repo).await?;
        let manifests = index
            .get("manifests")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();
        let mut tags: Vec<String> = manifests
            .iter()
            .filter_map(|e| {
                e.get("annotations")
                    .and_then(|a| a.get("org.opencontainers.image.ref.name"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .collect();
        tags.sort();
        tags.dedup();
        Ok(page_sorted(tags, last, limit))
    }

    async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Result<Page<Referrer>, StorageError> {
        validate_repo(repo)?;
        let target = subject.as_string();
        if let Some(page) = self
            .meta
            .referrers_page(repo, &target, artifact_type, last, limit)
        {
            return Ok(page);
        }
        // Fallback: scan index.json.
        let index = self.read_remote_index(repo).await?;
        let manifests = index
            .get("manifests")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();
        let linked: Vec<(String, serde_json::Value)> = manifests
            .into_iter()
            .filter(|e| {
                e.get("subject")
                    .and_then(|s| s.get("digest"))
                    .and_then(|d| d.as_str())
                    == Some(target.as_str())
            })
            .filter_map(|e| {
                let d = e.get("digest")?.as_str()?.to_string();
                Some((d, e))
            })
            .collect();
        if linked.is_empty() {
            return Ok(Page::default());
        }
        Ok(page_layout_referrers(linked, artifact_type, last, limit))
    }

    async fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        validate_repo(from_repo)?;
        validate_repo(to_repo)?;

        // Check source exists.
        let size = match self.blob_size(from_repo, digest).await {
            Ok(size) => size,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        let digest_str = digest.as_string();

        // Same-repo mount: already present.
        if from_repo == to_repo {
            return Ok(true);
        }

        // Serialize admit+publish per (repo, digest) to prevent double quota charge.
        let admit_lock = self.admit_lock(to_repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;

        // Quota.
        let charged = self.admit_blob(to_repo, digest, size).await?;
        let pin = self.gc.pin().await;

        // Ensure OCI layout marker exists BEFORE copying the object so a
        // layout-creation failure cannot leave an orphaned S3 blob.
        if let Err(e) = self.ensure_layout(to_repo).await {
            drop(pin);
            self.quota.release(to_repo, charged);
            return Err(e);
        }

        // Server-side copy (may need parallel copy for >5 GiB).
        if let Err(e) = self.copy_object(from_repo, to_repo, digest, size).await {
            drop(pin);
            self.quota.release(to_repo, charged);
            return Err(e);
        }
        roci_telemetry::record_dedupe_link("mount", "server_side_copy");

        let checksum = self.meta.checksum(from_repo, &digest_str);
        self.blob_entered(to_repo, &digest_str, checksum);
        drop(pin);
        self.drop_admit_lock(to_repo, &digest_str);
        Ok(true)
    }
}

// ── StorageBackend ─────────────────────────────────────────────────────

impl StorageBackend for S3Storage {
    async fn recover(&self) {
        self.recover_from_remote_indexes().await;
    }

    fn start_maintenance(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        if self.config.scrub.enabled {
            tracing::info!(
                "scrub enabled but delegated to object store's own integrity for S3 backend"
            );
        }

        // Metadata upkeep.
        self.spawn_periodic(
            "metadata.maintain",
            Duration::from_secs(30),
            shutdown.clone(),
            |s| async move {
                let meta = s.meta.clone();
                match tokio::task::spawn_blocking(move || meta.maintain()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!(error = %e, "metadata upkeep failed"),
                    Err(e) => tracing::warn!(error = %e, "metadata upkeep panicked"),
                }
            },
        );

        // Index.json debounced writer.
        self.spawn_index_writer(shutdown.clone());

        // GC sweep.
        if self.gc.enabled() {
            let store = self.clone();
            let interval = Duration::from_secs(self.config.gc.interval_secs);
            tokio::spawn(async move {
                // Startup consistency check.
                store
                    .gc_consistency_check()
                    .instrument(tracing::info_span!("gc.consistency_check"))
                    .await;
                store.gc.set_ready();
                tracing::info!(
                    candidates = store.gc.len(),
                    "GC ready: consistency check complete"
                );
                // Periodic sweeps.
                store.spawn_periodic("gc.sweep", interval, shutdown, |s| async move {
                    s.gc_sweep().await;
                });
            });
        } else {
            // No GC: still mark ready so other paths don't block.
            self.gc.set_ready();
        }

        tracing::info!(
            gc = self.config.gc.enabled,
            scrub = self.config.scrub.enabled,
            dedupe = self.config.dedupe,
            "S3 storage maintenance started"
        );
    }
}

// ── internal helpers ───────────────────────────────────────────────────

impl S3Storage {
    /// Quota admission: check whether the blob already exists, otherwise admit.
    async fn admit_blob(
        &self,
        repo: &str,
        digest: &Digest,
        size: u64,
    ) -> Result<u64, StorageError> {
        if !self.quota.tracks_bytes() {
            return Ok(0);
        }
        // Already in this repo = no new charge.
        if self.blob_exists(repo, digest).await? {
            return Ok(0);
        }
        self.quota.admit(repo, size)?;
        Ok(size)
    }

    /// Bookkeeping after a blob entered the CAS.
    fn blob_entered(&self, repo: &str, digest: &str, checksum: Option<BlobChecksum>) {
        self.dedupe.insert(repo, digest);
        if let Some(c) = checksum {
            if self.meta.checksum(repo, digest) != Some(c) {
                if let Err(e) = self.meta.apply_relaxed(MetaOp::PutChecksum {
                    repo: repo.to_string(),
                    digest: digest.to_string(),
                    crc32c: c.crc32c,
                    size: c.size,
                }) {
                    tracing::warn!(repo, digest, error = %e, "recording blob checksum failed");
                }
            }
        }
        if self.meta.backrefs(repo, digest).is_empty()
            && self.meta.manifest_media_type(repo, digest).is_none()
        {
            self.gc.mark(repo, digest);
        }
    }

    /// Bookkeeping after a blob left the CAS.
    fn blob_left(&self, repo: &str, digest: &str, size: Option<u64>) {
        self.dedupe.remove(repo, digest);
        self.gc.clear(repo, digest);
        if let Some(size) = size {
            self.quota.release(repo, size);
        }
        if self.meta.checksum(repo, digest).is_some() {
            if let Err(e) = self.meta.apply_relaxed(MetaOp::DeleteBlob {
                repo: repo.to_string(),
                digest: digest.to_string(),
            }) {
                tracing::warn!(repo, digest, error = %e, "recording blob removal failed");
            }
        }
    }

    /// Discard an upload session: remove staging file, end session, drop lock.
    /// Used on digest mismatch, size cap, and quota rejection at finalize.
    async fn discard_session(&self, repo: &str, id: &str) {
        self.remove_staging(repo, id).await;
        self.drop_session_lock(repo, id);
    }

    /// Ensure the OCI layout marker and empty index.json exist for `repo`.
    /// Caches per-repo presence in memory to avoid a HEAD on every push.
    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        // Check in-memory cache first.
        {
            let set = self.layout_cache.lock().expect("layout_cache poisoned");
            if set.contains(repo) {
                return Ok(());
            }
        }
        let lk = layout_key(&self.client.prefix, repo)?;
        let lp = ObjPath::from(lk);
        // Check if layout already exists remotely.
        if self.client.store.head(&lp).await.is_ok() {
            self.layout_cache
                .lock()
                .expect("layout_cache poisoned")
                .insert(repo.to_string());
            return Ok(());
        }
        // Write oci-layout marker.
        self.client
            .store
            .put(&lp, PutPayload::from_static(OCI_LAYOUT_MARKER.as_bytes()))
            .await
            .map_err(obj_err)?;
        // Write empty index.json if it doesn't exist.
        let ik = index_key(&self.client.prefix, repo)?;
        let ip = ObjPath::from(ik);
        if self.client.store.head(&ip).await.is_err() {
            let index = serde_json::to_vec(&empty_index())
                .map_err(|e| StorageError::Io(io::Error::other(e)))?;
            self.client
                .store
                .put(&ip, PutPayload::from(Bytes::from(index)))
                .await
                .map_err(obj_err)?;
        }
        self.layout_cache
            .lock()
            .expect("layout_cache poisoned")
            .insert(repo.to_string());
        Ok(())
    }

    /// Copy an object between repos. Uses single CopyObject for objects ≤5 GiB;
    /// for larger objects, uses ranged GETs feeding a multipart upload with
    /// bounded memory (≤ concurrency × part size).
    async fn copy_object(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
        size: u64,
    ) -> Result<(), StorageError> {
        let from_key = blob_key(&self.client.prefix, from_repo, digest)?;
        let to_key = blob_key(&self.client.prefix, to_repo, digest)?;
        let from_path = ObjPath::from(from_key);
        let to_path = ObjPath::from(to_key);

        if size <= self.client.copy_limit {
            // Single CopyObject request.
            self.client
                .store
                .copy_opts(&from_path, &to_path, Default::default())
                .await
                .map_err(obj_err)?;
        } else {
            // Parallel copy: ranged GETs → multipart upload, bounded memory.
            self.parallel_copy(&from_path, &to_path, size).await?;
        }
        Ok(())
    }

    /// Copy an object >5 GiB via ranged GETs feeding a multipart upload.
    /// At most `multipart_concurrency` parts are in flight (bounded memory).
    async fn parallel_copy(
        &self,
        from: &ObjPath,
        to: &ObjPath,
        size: u64,
    ) -> Result<(), StorageError> {
        let part_size = self.client.multipart_part_size;
        let concurrency = self.client.multipart_concurrency;

        let upload = self
            .client
            .store
            .put_multipart_opts(to, Default::default())
            .await
            .map_err(obj_err)?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, part_size as usize);

        let mut offset: u64 = 0;
        while offset < size {
            // Back-pressure: wait until fewer than `concurrency` parts in flight.
            if let Err(e) = writer.wait_for_capacity(concurrency).await {
                writer.abort().await.map_err(obj_err)?;
                return Err(obj_err(e));
            }
            let len = (size - offset).min(part_size);
            let chunk = self
                .client
                .store
                .get_range(from, offset..offset + len)
                .await
                .map_err(|e| {
                    StorageError::Io(io::Error::other(format!("parallel copy range GET: {e}")))
                })?;
            writer.put(chunk);
            offset += len;
        }

        if let Err(e) = writer.finish().await {
            return Err(obj_err(e));
        }
        Ok(())
    }

    /// Try server-side copy from another repo holding `digest`.
    async fn try_server_side_copy(
        &self,
        repo: &str,
        digest: &Digest,
        digest_str: &str,
        size: u64,
    ) -> bool {
        if !self.dedupe.enabled() {
            return false;
        }
        let Some(source_repo) = self.dedupe.locate(digest_str, repo) else {
            return false;
        };
        match self.copy_object(&source_repo, repo, digest, size).await {
            Ok(()) => {
                roci_telemetry::record_dedupe_link("dedupe", "server_side_copy");
                tracing::debug!(
                    repo,
                    digest = digest_str,
                    source = source_repo.as_str(),
                    "dedupe via server-side copy"
                );
                true
            }
            Err(e) => {
                tracing::debug!(error = %e, "server-side copy failed, falling back to upload");
                false
            }
        }
    }

    /// Upload a staged local file to S3 via streaming I/O. Single PUT below
    /// `multipart_part_size`; otherwise `put_multipart` with
    /// `WriteMultipart::new_with_chunk_size` fed from buffered file reads,
    /// calling `wait_for_capacity(multipart_concurrency)` before each chunk.
    /// Aborts the multipart upload on error.
    ///
    /// All local file access goes through no-follow beneath-root opens so a
    /// symlink planted at `uploads/<repo>` cannot redirect the upload stream.
    async fn upload_staged_blob(
        &self,
        repo: &str,
        digest: &Digest,
        id: &str,
    ) -> Result<(), StorageError> {
        let rel = self.staging_rel(repo, id)?;
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let obj_path = ObjPath::from(key);

        let file_size = match roci_storage::beneath::stat_beneath(&self.root, &rel).await? {
            Some((true, sz)) => sz,
            _ => return Err(StorageError::NotFound),
        };
        let part_size = self.client.multipart_part_size as usize;
        let concurrency = self.client.multipart_concurrency;

        if file_size as usize <= part_size {
            // Single PUT: read entire file (it's below part_size which is the
            // streaming boundary, not the whole-blob invariant boundary — this
            // is bounded by the configured part size, typically 16 MiB).
            let mut f = roci_storage::beneath::open_beneath(&self.root, &rel).await?;
            let mut data = Vec::with_capacity(file_size as usize);
            tokio::io::AsyncReadExt::read_to_end(&mut f, &mut data).await?;
            self.client
                .store
                .put(&obj_path, PutPayload::from(Bytes::from(data)))
                .await
                .map_err(obj_err)?;
        } else {
            // Streaming multipart upload.
            let upload = self
                .client
                .store
                .put_multipart_opts(&obj_path, Default::default())
                .await
                .map_err(obj_err)?;
            let mut writer = WriteMultipart::new_with_chunk_size(upload, part_size);

            let mut file = roci_storage::beneath::open_beneath(&self.root, &rel).await?;
            let mut buf = vec![0u8; part_size];
            loop {
                // Back-pressure: bounded concurrency.
                if let Err(e) = writer.wait_for_capacity(concurrency).await {
                    writer.abort().await.map_err(obj_err)?;
                    return Err(obj_err(e));
                }
                let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.put(Bytes::copy_from_slice(&buf[..n]));
            }

            if let Err(e) = writer.finish().await {
                return Err(obj_err(e));
            }
        }
        Ok(())
    }

    /// Record a manifest's byte size for index.json rebuilds so we never
    /// need a per-entry HEAD when rewriting the index.
    fn record_manifest_size(&self, repo: &str, digest: &str, size: u64) {
        self.manifest_sizes
            .lock()
            .expect("manifest_sizes poisoned")
            .insert((repo.to_string(), digest.to_string()), size);
    }

    /// Forget a deleted manifest's recorded size.
    fn forget_manifest_size(&self, repo: &str, digest: &str) {
        self.manifest_sizes
            .lock()
            .expect("manifest_sizes poisoned")
            .remove(&(repo.to_string(), digest.to_string()));
    }

    /// Read the remote index.json for `repo`.
    pub(crate) async fn read_remote_index(
        &self,
        repo: &str,
    ) -> Result<serde_json::Value, StorageError> {
        let key = index_key(&self.client.prefix, repo)?;
        let path = ObjPath::from(key);
        let result = self.client.store.get(&path).await.map_err(obj_err)?;
        let bytes = result
            .bytes()
            .await
            .map_err(|e| StorageError::Io(io::Error::other(e.to_string())))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))
    }

    /// Resolve a tag from a remote index.json.
    async fn index_resolve_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<(Digest, String), StorageError> {
        let index = self.read_remote_index(repo).await?;
        let manifests = index
            .get("manifests")
            .and_then(|m| m.as_array())
            .ok_or(StorageError::NotFound)?;
        for entry in manifests {
            let entry_tag = entry
                .get("annotations")
                .and_then(|a| a.get("org.opencontainers.image.ref.name"))
                .and_then(|v| v.as_str());
            if entry_tag == Some(tag) {
                let digest_str = entry
                    .get("digest")
                    .and_then(|d| d.as_str())
                    .ok_or(StorageError::NotFound)?;
                let digest = Digest::parse(digest_str)?;
                let media_type = entry
                    .get("mediaType")
                    .and_then(|m| m.as_str())
                    .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST)
                    .to_string();
                return Ok((digest, media_type));
            }
        }
        Err(StorageError::NotFound)
    }

    /// Get a manifest's media type from the cached remote index (for digest
    /// lookups that miss in metadata).
    fn index_media_type_for_digest(&self, repo: &str, digest: &str) -> Option<String> {
        let index = self.cached_remote_index.lock().expect("poisoned");
        let idx = index.get(repo)?;
        idx.get("manifests")
            .and_then(|m| m.as_array())
            .and_then(|ms| {
                ms.iter()
                    .find(|e| e.get("digest").and_then(|d| d.as_str()) == Some(digest))
            })
            .and_then(|e| e.get("mediaType"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    /// Cache a remote index for synchronous lookups.
    fn cache_remote_index(&self, repo: &str, index: serde_json::Value) {
        self.cached_remote_index
            .lock()
            .expect("poisoned")
            .insert(repo.to_string(), index);
    }
}

// ── recovery ───────────────────────────────────────────────────────────

impl S3Storage {
    /// Recover metadata from existing remote index.json objects.
    /// Only imports tags the metadata store lacks (mirrors FsStorage::import_foreign_tags).
    /// Warms referrers only when missing (mirrors warm_referrers_from_layout).
    /// Seeds quota byte usage and dedupe index from the blob listing.
    async fn recover_from_remote_indexes(&self) {
        // Seed session count from existing staging files.
        self.seed_sessions_from_staging();

        // List all objects under the prefix to discover repos.
        let prefix = if self.client.prefix.is_empty() {
            None
        } else {
            Some(ObjPath::from(self.client.prefix.clone()))
        };
        let mut repos = std::collections::HashSet::new();
        let mut list = self.client.store.list(prefix.as_ref());
        while let Some(result) = list.next().await {
            let Ok(meta) = result else { continue };
            let key = meta.location.as_ref();
            // Extract repo from index.json paths.
            if let Some(repo) = extract_repo_from_index_key(key, &self.client.prefix) {
                repos.insert(repo);
            }
        }

        for repo in &repos {
            let Ok(index) = self.read_remote_index(repo).await else {
                continue;
            };

            // Cache the index for media-type lookups.
            self.cache_remote_index(repo, index.clone());

            // Import only tags the metadata store lacks (foreign tags).
            roci_storage::import_foreign_tags(&*self.meta, repo, &index);

            // Warm referrers only when missing.
            let manifests = index
                .get("manifests")
                .and_then(|m| m.as_array())
                .cloned()
                .unwrap_or_default();
            for entry in &manifests {
                let Some(digest_str) = entry.get("digest").and_then(|d| d.as_str()) else {
                    continue;
                };
                // Record the size from index for index.json rebuilds.
                if let Some(size) = entry.get("size").and_then(|s| s.as_u64()) {
                    self.record_manifest_size(repo, digest_str, size);
                }
                // Subject / referrer: warm only when missing.
                let referrer_info = entry
                    .get("subject")
                    .and_then(|s| s.get("digest"))
                    .and_then(|d| d.as_str());
                if let Some(subject_str) = referrer_info {
                    if !self.meta.has_referrer(repo, subject_str, digest_str) {
                        if let Ok(desc) = serde_json::to_vec(entry) {
                            let _ = self.meta.apply(MetaOp::PutManifest {
                                repo: repo.clone(),
                                digest: digest_str.to_string(),
                                media_type: entry
                                    .get("mediaType")
                                    .and_then(|m| m.as_str())
                                    .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST)
                                    .to_string(),
                                tag: None,
                                references: Vec::new(),
                                referrer: Some((subject_str.to_string(), desc)),
                            });
                        }
                    }
                }

                // Dedupe index.
                self.dedupe.insert(repo, digest_str);
            }
        }

        // Seed quota byte usage from blob listing when quota.tracks_bytes().
        if self.quota.tracks_bytes() {
            self.seed_quota_from_listing(&repos).await;
        }

        // Seed dedupe index from blob listing (repos already warmed above
        // from index.json manifests; this catches non-manifest blobs).
        self.seed_dedupe_from_listing(&repos).await;
    }

    /// Seed quota byte usage by listing all blobs.
    async fn seed_quota_from_listing(&self, repos: &std::collections::HashSet<String>) {
        for repo in repos {
            let rp = match repo_prefix(&self.client.prefix, repo) {
                Ok(rp) => rp,
                Err(_) => continue,
            };
            let blob_prefix = ObjPath::from(format!("{rp}/blobs/"));
            let mut list = self.client.store.list(Some(&blob_prefix));
            while let Some(result) = list.next().await {
                let Ok(meta) = result else { continue };
                self.quota.seed(repo, meta.size);
            }
        }
    }

    /// Seed the dedupe index from the blob listing.
    async fn seed_dedupe_from_listing(&self, repos: &std::collections::HashSet<String>) {
        if !self.dedupe.enabled() {
            return;
        }
        for repo in repos {
            let rp = match repo_prefix(&self.client.prefix, repo) {
                Ok(rp) => rp,
                Err(_) => continue,
            };
            let blob_prefix = ObjPath::from(format!("{rp}/blobs/"));
            let mut list = self.client.store.list(Some(&blob_prefix));
            while let Some(result) = list.next().await {
                let Ok(meta) = result else { continue };
                if let Some(digest_str) = extract_digest_from_blob_key(meta.location.as_ref(), &rp)
                {
                    self.dedupe.insert(repo, &digest_str);
                }
            }
        }
    }
}

// ── GC ─────────────────────────────────────────────────────────────────

impl S3Storage {
    /// Startup consistency check: rebuild missing backref edges, register
    /// layout-only roots, seed candidates, expire stale uploads.
    pub(crate) async fn gc_consistency_check(&self) {
        // Discover repos from the listing.
        let prefix = if self.client.prefix.is_empty() {
            None
        } else {
            Some(ObjPath::from(self.client.prefix.clone()))
        };
        let mut repos = std::collections::HashSet::new();
        let mut list = self.client.store.list(prefix.as_ref());
        while let Some(result) = list.next().await {
            let Ok(meta) = result else { continue };
            let key = meta.location.as_ref();
            if let Some(repo) = extract_repo_from_index_key(key, &self.client.prefix) {
                repos.insert(repo);
            }
        }

        // Also include repos known to metadata.
        for r in self.meta.repos() {
            repos.insert(r);
        }

        for repo in &repos {
            self.gc_rebuild_repo(repo).await;
        }

        // Seed candidates: list each repo's blobs. A blob that is not a root,
        // not a manifest, with empty backrefs → mark.
        let now = std::time::Instant::now();
        for repo in &repos {
            let rp = match repo_prefix(&self.client.prefix, repo) {
                Ok(rp) => rp,
                Err(_) => continue,
            };
            let blob_prefix = ObjPath::from(format!("{rp}/blobs/"));
            let mut list = self.client.store.list(Some(&blob_prefix));
            while let Some(result) = list.next().await {
                let Ok(meta) = result else { continue };
                let Some(digest_str) = extract_digest_from_blob_key(meta.location.as_ref(), &rp)
                else {
                    continue;
                };
                // Skip manifests and roots.
                if self.meta.manifest_media_type(repo, &digest_str).is_some()
                    || self.gc.is_root(repo, &digest_str)
                {
                    continue;
                }
                // No backrefs → candidate.
                if self.meta.backrefs(repo, &digest_str).is_empty() {
                    self.gc.mark_at(repo, &digest_str, now);
                }
            }
        }

        // Expire local staging files older than gc.delay that are not session-locked.
        self.sweep_stale_uploads().await;
    }

    /// Rebuild backrefs for one repo: discover roots from metadata + remote
    /// index.json, expand image-index children, record missing edges.
    ///
    /// # Safety invariants
    /// - A remote `index.json` that exists but is malformed/unreadable marks
    ///   the repo GC-unsafe (only a genuine `NotFound` means blob-only repo).
    /// - Root manifests are HEAD-checked and refuse >4 MiB reads; oversized or
    ///   unreadable roots mark the repo unsafe.
    /// - Missing/unreadable checks use `all_roots` (including children) so no
    ///   sweep runs with unknown liveness.
    async fn gc_rebuild_repo(&self, repo: &str) {
        let mut root_digests: HashSet<String> = HashSet::new();

        // (a) From the metadata store.
        for d in self.meta.manifests(repo) {
            root_digests.insert(d);
        }

        // (b) From remote index.json descriptors.
        // Distinguish NotFound (blob-only repo) from parse/read errors (unsafe).
        match self.read_remote_index(repo).await {
            Ok(index) => {
                if let Some(manifests) = index.get("manifests").and_then(|m| m.as_array()) {
                    for entry in manifests {
                        if let Some(d) = entry.get("digest").and_then(|v| v.as_str()) {
                            root_digests.insert(d.to_string());
                        }
                    }
                }
            }
            Err(StorageError::NotFound) => {
                // No index.json: blob-only repo, not an error.
            }
            Err(e) => {
                // Existing but malformed/unreadable: GC-unsafe.
                tracing::warn!(repo, error = %e, "remote index.json unreadable; repo is GC-unsafe");
                self.gc.mark_unsafe(repo);
                return;
            }
        }

        /// Maximum root manifest size allowed during GC consistency check
        /// (4 MiB — same cap the registry's manifest-input policy enforces).
        const MAX_ROOT_SIZE: u64 = 4 * 1024 * 1024;

        // Recursively include image-index children present in the store.
        let mut to_visit: Vec<String> = root_digests.iter().cloned().collect();
        let mut all_roots: HashSet<String> = root_digests.clone();
        while let Some(digest_str) = to_visit.pop() {
            let parsed = match Digest::parse(&digest_str) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // HEAD first: refuse oversized roots to avoid unbounded allocation.
            let size = match self.blob_size(repo, &parsed).await {
                Ok(s) => s,
                Err(_) => {
                    // Missing root or child → repo unsafe.
                    tracing::warn!(repo, digest = %digest_str, "root manifest missing from CAS; repo is GC-unsafe");
                    self.gc.mark_unsafe(repo);
                    continue;
                }
            };
            if size > MAX_ROOT_SIZE {
                tracing::warn!(repo, digest = %digest_str, size, "oversized root manifest; repo is GC-unsafe");
                self.gc.mark_unsafe(repo);
                continue;
            }

            let bytes = match self.read_blob(repo, &parsed).await {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!(repo, digest = %digest_str, "root manifest unreadable; repo is GC-unsafe");
                    self.gc.mark_unsafe(repo);
                    continue;
                }
            };
            let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!(repo, digest = %digest_str, "unparseable root manifest; repo is GC-unsafe");
                    self.gc.mark_unsafe(repo);
                    continue;
                }
            };
            // If it's an image index, its children are also roots.
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

        // Register layout-only roots.
        for d in &all_roots {
            if self.meta.manifest_media_type(repo, d).is_none() {
                self.gc.add_root(repo, d);
            }
        }

        // Derive and record missing backref edges.
        for digest_str in &all_roots {
            let parsed = match Digest::parse(digest_str) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let bytes = match self.read_blob(repo, &parsed).await {
                Ok(b) => b,
                Err(_) => continue,
            };
            let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    self.gc.mark_unsafe(repo);
                    continue;
                }
            };
            let references: Vec<String> = roci_storage::manifest_references(&manifest)
                .iter()
                .map(Digest::as_string)
                .collect();
            let missing: Vec<String> = references
                .iter()
                .filter(|blob| !self.meta.backrefs(repo, blob).contains(digest_str))
                .cloned()
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

    /// GC sweep: collect unreferenced blobs whose grace period has elapsed.
    /// Processes due candidates in bounded batches so the fence is never held
    /// across the whole sweep.
    pub(crate) async fn gc_sweep(&self) {
        if !self.gc.is_ready() {
            return;
        }
        let now = std::time::Instant::now();
        let due = self.gc.due(now);
        if due.is_empty() {
            return;
        }

        let mut collected_blobs: u64 = 0;
        let mut collected_bytes: u64 = 0;
        let mut errors: u64 = 0;

        for batch in due.chunks(SWEEP_BATCH_SIZE) {
            let _fence = self.gc.exclusive().await;
            for (repo, digest_str) in batch {
                // Re-check under the exclusive fence.
                if !self.gc.is_due(repo, digest_str, now) {
                    continue;
                }
                // Skip if it's a root manifest.
                if self.gc.is_root(repo, digest_str) {
                    self.gc.clear(repo, digest_str);
                    continue;
                }
                // Skip if the repo is unsafe.
                if self.gc.is_unsafe(repo) {
                    continue;
                }
                // Skip if it has backrefs now.
                if !self.meta.backrefs(repo, digest_str).is_empty() {
                    self.gc.clear(repo, digest_str);
                    continue;
                }
                // Skip if it's a recorded manifest.
                if self.meta.manifest_media_type(repo, digest_str).is_some() {
                    self.gc.clear(repo, digest_str);
                    continue;
                }
                let Ok(digest) = Digest::parse(digest_str) else {
                    self.gc.clear(repo, digest_str);
                    continue;
                };
                let Ok(key) = blob_key(&self.client.prefix, repo, &digest) else {
                    self.gc.clear(repo, digest_str);
                    continue;
                };
                let path = ObjPath::from(key);
                // HEAD to get size.
                let size = match self.client.store.head(&path).await {
                    Ok(m) => Some(m.size),
                    Err(object_store::Error::NotFound { .. }) => {
                        // Already gone.
                        self.gc.clear(repo, digest_str);
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(repo, digest = %digest_str, error = %e, "GC head failed");
                        errors += 1;
                        continue;
                    }
                };
                // Delete.
                match self.client.store.delete(&path).await {
                    Ok(()) => {
                        // Only blob_left after successful delete.
                        self.blob_left(repo, digest_str, size);
                        if let Some(bytes) = size {
                            roci_telemetry::record_gc_collected("blob", bytes);
                            collected_bytes += bytes;
                        }
                        collected_blobs += 1;
                    }
                    Err(object_store::Error::NotFound { .. }) => {
                        self.gc.clear(repo, digest_str);
                    }
                    Err(e) => {
                        tracing::warn!(repo, digest = %digest_str, error = %e, "GC delete failed");
                        errors += 1;
                    }
                }
            }
        }

        // Stale upload cleanup.
        let (stale_uploads, stale_bytes) = self.sweep_stale_uploads().await;

        let total_collected = collected_blobs + stale_uploads;
        if total_collected > 0 {
            tracing::info!(
                blobs = collected_blobs,
                uploads = stale_uploads,
                bytes = collected_bytes + stale_bytes,
                errors,
                "GC sweep collected"
            );
        } else {
            tracing::debug!(errors, "GC sweep: nothing to collect");
        }
    }

    /// Clean up uploads whose mtime exceeds the GC delay and whose session is
    /// not locked. Acquires the per-session lock (try_lock, skip if held) and
    /// rechecks the file age before removing, so a concurrent upload that
    /// acquires the session after the initial enumeration cannot lose its
    /// staging file. Returns `(count, bytes)`.
    pub(crate) async fn sweep_stale_uploads(&self) -> (u64, u64) {
        let delay = self.gc.delay();
        let stale = self.enumerate_staging_files();
        let mut count: u64 = 0;
        let mut bytes: u64 = 0;
        let now = std::time::SystemTime::now();
        for (repo, id, size, modified) in stale {
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
            if age < delay {
                continue;
            }
            // Acquire the per-session lock; skip if currently held by an upload.
            let lock = self.session_lock(&repo, &id);
            let Ok(_guard) = lock.try_lock() else {
                continue;
            };
            // Re-check age under the lock: a concurrent append could have
            // touched the file between the enumeration and our lock acquire.
            if let Ok(path) = self.staging_path(&repo, &id) {
                let fresh_age = std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|mt| std::time::SystemTime::now().duration_since(mt).ok())
                    .unwrap_or(Duration::ZERO);
                if fresh_age < delay {
                    continue;
                }
                if std::fs::remove_file(&path).is_ok() {
                    self.quota.end_session();
                    roci_telemetry::record_gc_collected("upload", size);
                    count += 1;
                    bytes += size;
                }
            }
            self.drop_session_lock(&repo, &id);
        }
        (count, bytes)
    }
}

// ── index.json writer ──────────────────────────────────────────────────

impl S3Storage {
    /// Debounced background index.json writer.
    fn spawn_index_writer(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = store.index_notify.notified() => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
                // Debounce: wait a short time for more mutations.
                tokio::time::sleep(Duration::from_millis(200)).await;

                // Snapshot the dirty set.
                let dirty: Vec<(String, u64)> = {
                    let d = store.index_dirty.lock().expect("index_dirty poisoned");
                    d.iter().map(|(k, v)| (k.clone(), *v)).collect()
                };
                for (repo, gen) in dirty {
                    if let Err(e) = store.write_remote_index(&repo).await {
                        tracing::warn!(repo = repo.as_str(), error = %e, "index.json rewrite failed");
                        continue;
                    }
                    // Clear only if no newer mutation raced.
                    let mut d = store.index_dirty.lock().expect("index_dirty poisoned");
                    if d.get(&repo) == Some(&gen) {
                        d.remove(&repo);
                    }
                }
            }
        });
    }

    /// Build and upload `index.json` for a repo using the shared
    /// `index_from_meta` merged over the existing remote index.
    /// Size lookup uses recorded manifest sizes + existing index entry sizes
    /// (no per-entry HEAD).
    pub(crate) async fn write_remote_index(&self, repo: &str) -> Result<(), StorageError> {
        // Read the existing remote index.
        let existing = match self.read_remote_index(repo).await {
            Ok(idx) => Some(idx),
            Err(StorageError::NotFound) => None,
            Err(e) => return Err(e),
        };

        // Build a size map from existing index entries.
        let mut size_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        if let Some(ref idx) = existing {
            if let Some(manifests) = idx.get("manifests").and_then(|m| m.as_array()) {
                for entry in manifests {
                    if let (Some(d), Some(s)) = (
                        entry.get("digest").and_then(|v| v.as_str()),
                        entry.get("size").and_then(|v| v.as_u64()),
                    ) {
                        size_map.insert(d.to_string(), s);
                    }
                }
            }
        }

        // Merge in recorded manifest sizes (from put_manifest).
        {
            let ms = self.manifest_sizes.lock().expect("manifest_sizes poisoned");
            for ((r, d), s) in ms.iter() {
                if r == repo {
                    size_map.insert(d.clone(), *s);
                }
            }
        }

        let index = roci_storage::index_from_meta(&*self.meta, repo, existing, |d| {
            size_map.get(d).copied()
        })?;

        let bytes =
            serde_json::to_vec(&index).map_err(|e| StorageError::Io(io::Error::other(e)))?;
        let key = index_key(&self.client.prefix, repo)?;
        let path = ObjPath::from(key);
        self.client
            .store
            .put(&path, PutPayload::from(Bytes::from(bytes)))
            .await
            .map_err(obj_err)?;
        Ok(())
    }

    /// Run `task` every `period` until `shutdown` flips.
    fn spawn_periodic<F, Fut>(
        &self,
        name: &'static str,
        period: Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        task: F,
    ) where
        F: Fn(S3Storage) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticks.tick() => {
                        task(store.clone())
                            .instrument(tracing::info_span!("storage.maintenance", task = name))
                            .await;
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

// ── free functions ─────────────────────────────────────────────────────

/// Extract repo name from an index.json key like `prefix/repo/index.json`.
pub(crate) fn extract_repo_from_index_key(key: &str, prefix: &str) -> Option<String> {
    let suffix = "/index.json";
    if !key.ends_with(suffix) {
        return None;
    }
    let without_suffix = &key[..key.len() - suffix.len()];
    let repo = if prefix.is_empty() {
        without_suffix
    } else {
        without_suffix.strip_prefix(prefix)?.strip_prefix('/')?
    };
    if repo.is_empty() {
        return None;
    }
    Some(repo.to_string())
}

/// Extract `alg:hex` digest from a blob key like `prefix/repo/blobs/alg/hex`.
pub(crate) fn extract_digest_from_blob_key(key: &str, repo_prefix: &str) -> Option<String> {
    let rest = key.strip_prefix(repo_prefix)?.strip_prefix("/blobs/")?;
    let (alg, hex) = rest.split_once('/')?;
    Some(format!("{alg}:{hex}"))
}

/// Page a sorted, deduplicated list.
fn page_sorted(items: Vec<String>, last: Option<&str>, limit: usize) -> Page<String> {
    let start = match last {
        Some(last) => items.partition_point(|s| s.as_str() <= last),
        None => 0,
    };
    let window = &items[start..];
    if window.len() <= limit {
        Page {
            items: window.to_vec(),
            more: false,
        }
    } else {
        Page {
            items: window[..limit].to_vec(),
            more: true,
        }
    }
}

/// Page referrer candidates from the layout.
fn page_layout_referrers(
    mut refs: Vec<(String, serde_json::Value)>,
    artifact_type: Option<&str>,
    last: Option<&str>,
    limit: usize,
) -> Page<Referrer> {
    // Filter by artifact type.
    if let Some(at) = artifact_type {
        refs.retain(|(_, entry)| entry.get("artifactType").and_then(|a| a.as_str()) == Some(at));
    }
    // Sort and dedup by digest.
    refs.sort_by(|a, b| a.0.cmp(&b.0));
    refs.dedup_by(|a, b| a.0 == b.0);
    // Apply cursor.
    let start = match last {
        Some(last) => refs.partition_point(|(d, _)| d.as_str() <= last),
        None => 0,
    };
    let window = &refs[start..];
    let take = window.len().min(limit);
    let items: Vec<Referrer> = window[..take]
        .iter()
        .filter_map(|(d, entry)| {
            serde_json::to_vec(entry)
                .ok()
                .map(|bytes| (d.clone(), bytes))
        })
        .collect();
    Page {
        more: window.len() > limit,
        items,
    }
}

use tracing::Instrument;
