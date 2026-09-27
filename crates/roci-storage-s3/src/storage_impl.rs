use crate::keys::{blob_key, index_key, layout_key, repo_prefix, validate_repo};
use crate::S3Storage;
use bytes::Bytes;
use futures::StreamExt;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, WriteMultipart};
use roci_storage::{
    empty_index, layout_subject_referrers, layout_tags_page, page_layout_referrers,
    referrer_descriptor, BlobChecksum, BlobRead, BlobStream, Digest, ManifestLinks, ManifestRef,
    MetaOp, Page, RangeOpener, Referrer, Storage, StorageBackend, StorageError, UploadBody,
    MEDIA_TYPE_IMAGE_MANIFEST, OCI_LAYOUT_MARKER,
};
use std::collections::HashSet;
use std::io;
use std::time::Duration;

pub(crate) fn obj_err(e: object_store::Error) -> StorageError {
    match e {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        other => StorageError::Io(io::Error::other(other.to_string())),
    }
}

/// Write-path variant: a `NotFound` on PUT/copy (NoSuchBucket) is transient, never `NAME_UNKNOWN`.
pub(crate) fn obj_err_write(e: object_store::Error) -> StorageError {
    match e {
        object_store::Error::NotFound { .. } => StorageError::Unavailable(
            "storage backend returned NotFound on a write (bucket may not exist yet)".to_string(),
        ),
        other => StorageError::Io(io::Error::other(other.to_string())),
    }
}

/// Maximum candidates processed per exclusive-fence batch in GC sweep.
const SWEEP_BATCH_SIZE: usize = 256;

/// S3 single CopyObject limit: 5 GiB.
pub(crate) const S3_COPY_LIMIT: u64 = 5 * 1024 * 1024 * 1024;

/// How long `create_bucket` keeps retrying while the backend starts.
pub(crate) const CREATE_BUCKET_DEADLINE: Duration = Duration::from_secs(60);

impl Storage for S3Storage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        // Refresh GC stamp before existence check so a concurrent sweep
        // either already deleted the blob or keeps it another grace period.
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

        // Signed redirect for blobs above redirect_min_size.
        if self.client.redirect_min_size > 0 && size >= self.client.redirect_min_size {
            if let Some(signer) = &self.client.signer {
                let url = signer
                    .signed_url(http::Method::GET, &path, self.client.redirect_ttl)
                    .await;
                if let Ok(url) = url {
                    if self.client.redirect_guard.permits(&url) {
                        return Ok(BlobRead::redirect(size, url.to_string()));
                    }
                    tracing::warn!(
                        host = url.host_str().unwrap_or("<none>"),
                        "signed redirect URL rejected by host allowlist; proxying"
                    );
                }
            }
        }

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
        body: UploadBody,
        expected_offset: Option<u64>,
        limit: u64,
    ) -> Result<u64, StorageError> {
        validate_repo(repo)?;
        let lock = self.upload_locks.get(repo, id);
        let _guard = lock.lock().await;
        self.append_to_staging(repo, id, body, expected_offset, limit)
            .await
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        validate_repo(repo)?;
        self.staging_size(repo, id).await
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        validate_repo(repo)?;
        let lock = self.upload_locks.get(repo, id);
        let _guard = lock.lock().await;
        let dir_rel = match self.repo_staging_rel(repo) {
            Ok(d) => d,
            Err(_) => {
                self.upload_locks.remove(repo, id);
                return Ok(false);
            }
        };
        if self.staging_rel(repo, id).is_err() {
            self.upload_locks.remove(repo, id);
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
        self.upload_locks.remove(repo, id);
        Ok(removed)
    }

    async fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
        max_size: u64,
        trailing: UploadBody,
        limit: u64,
    ) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let lock = self.upload_locks.get(repo, id);
        let _guard = lock.lock().await;

        self.append_to_staging(repo, id, trailing, None, limit)
            .await?;

        let staged_size = self.staging_size(repo, id).await?;
        if staged_size > max_size {
            self.discard_session(repo, id).await;
            roci_telemetry::record_upload_finalize("too_large");
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: staged_size,
            });
        }

        let (actual, crc32c, size) = self.hash_staging(repo, id, expected.algorithm()).await?;
        if !actual.ct_eq(expected) {
            self.discard_session(repo, id).await;
            roci_telemetry::record_upload_finalize("digest_mismatch");
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }

        // Serialize per (repo, digest) to prevent double quota charge.
        let digest_str = expected.as_string();
        let admit_lock = self.admit_locks.get(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;

        let charged = match self.admit_blob(repo, expected, size).await {
            Ok(c) => c,
            Err(e) => {
                self.discard_session(repo, id).await;
                return Err(e);
            }
        };

        let pin = self.gc.pin().await;

        // Ensure layout before publish; failure cannot leave an orphaned S3 blob.
        if let Err(e) = self.ensure_layout(repo).await {
            drop(pin);
            self.quota.release(repo, charged);
            self.discard_session(repo, id).await;
            return Err(e);
        }

        let linked = self
            .try_server_side_copy(repo, expected, &digest_str, size)
            .await;

        if !linked {
            if let Err(e) = self.upload_staged_blob(repo, expected, id).await {
                drop(pin);
                self.quota.release(repo, charged);
                self.discard_session(repo, id).await;
                return Err(e);
            }
        }

        self.remove_staging(repo, id).await;
        self.upload_locks.remove(repo, id);

        self.blob_entered(repo, &digest_str, Some(BlobChecksum { crc32c, size }));
        drop(pin);
        self.admit_locks.release(repo, &digest_str);
        roci_telemetry::record_upload_finalize("ok");
        Ok(())
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let actual = roci_storage::digest_of(data, digest.algorithm());
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }

        let digest_str = digest.as_string();

        // Serialize per (repo, digest) to prevent double quota charge.
        let admit_lock = self.admit_locks.get(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;

        let charged = self.admit_blob(repo, digest, data.len() as u64).await?;
        let pin = self.gc.pin().await;

        // Ensure layout before publish; failure cannot leave an orphaned S3 blob.
        if let Err(e) = self.ensure_layout(repo).await {
            drop(pin);
            self.quota.release(repo, charged);
            return Err(e);
        }

        let linked = self
            .try_server_side_copy(repo, digest, &digest_str, data.len() as u64)
            .await;

        if !linked {
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
                return Err(obj_err_write(e));
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
        self.admit_locks.release(repo, &digest_str);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        let size = match self.client.store.head(&path).await {
            Ok(meta) => meta.size,
            Err(object_store::Error::NotFound { .. }) => return Err(StorageError::NotFound),
            Err(e) => return Err(obj_err(e)),
        };
        self.client.store.delete(&path).await.map_err(obj_err)?;
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

        // Hold one GC pin from blob publication through MetaOp apply.
        let pin = self.gc.pin().await;
        // Store manifest as a blob (verifies digest, ensures layout).
        self.put_blob(repo, digest, data).await?;

        // Re-verify required digests under the same fence.
        for required in links.required {
            if !self.blob_exists(repo, required).await? {
                drop(pin);
                return Err(StorageError::MissingReference(required.as_string()));
            }
        }

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

        self.record_manifest_size(repo, &digest_str, data.len() as u64);

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
            // Try metadata; fall back to remote index.json.
            let media_type = self
                .meta
                .manifest_media_type(repo, reference)
                .or_else(|| self.index_media_type_for_digest(repo, reference))
                .unwrap_or_else(|| MEDIA_TYPE_IMAGE_MANIFEST.to_string());
            (digest, media_type)
        } else {
            match self.meta.resolve_tag(repo, reference) {
                Some((digest_str, media_type)) => (Digest::parse(&digest_str)?, media_type),
                None => self.index_resolve_tag(repo, reference).await?,
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

        let references = match self.read_blob(repo, digest).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(|v| roci_storage::manifest_references(&v))
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        self.delete_blob(repo, digest).await?;
        self.forget_manifest_size(repo, &digest_str);

        self.apply_meta(
            repo,
            MetaOp::DeleteManifest {
                repo: repo.to_string(),
                digest: digest_str.clone(),
            },
        )?;

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
        Ok(layout_tags_page(
            &self.read_remote_index(repo).await?,
            last,
            limit,
        ))
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
        let index = self.read_remote_index(repo).await?;
        let linked = layout_subject_referrers(&index, &target);
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

        let size = match self.blob_size(from_repo, digest).await {
            Ok(size) => size,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        let digest_str = digest.as_string();

        if from_repo == to_repo {
            return Ok(true);
        }

        // Serialize per (repo, digest) to prevent double quota charge.
        let admit_lock = self.admit_locks.get(to_repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;

        let charged = self.admit_blob(to_repo, digest, size).await?;
        let pin = self.gc.pin().await;

        // Ensure layout before copy; failure cannot leave an orphaned S3 blob.
        if let Err(e) = self.ensure_layout(to_repo).await {
            drop(pin);
            self.quota.release(to_repo, charged);
            return Err(e);
        }

        if let Err(e) = self.copy_object(from_repo, to_repo, digest, size).await {
            drop(pin);
            self.quota.release(to_repo, charged);
            return Err(e);
        }
        roci_telemetry::record_dedupe_link("mount", "server_side_copy");

        let checksum = self.meta.checksum(from_repo, &digest_str);
        self.blob_entered(to_repo, &digest_str, checksum);
        drop(pin);
        self.admit_locks.release(to_repo, &digest_str);
        Ok(true)
    }
}

impl StorageBackend for S3Storage {
    async fn recover(&self) {
        if self.create_bucket {
            match self.ensure_bucket().await {
                Ok(()) => self
                    .bucket_ensured
                    .store(true, std::sync::atomic::Ordering::Release),
                // `ready()` keeps retrying, so /readyz heals once S3 accepts it.
                Err(e) => tracing::error!(error = %e, "create_bucket failed"),
            }
        }
        self.recover_from_remote_indexes().await;
    }

    fn start_maintenance(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        if self.config.scrub.enabled {
            tracing::info!(
                "scrub enabled but delegated to object store's own integrity for S3 backend"
            );
        }

        roci_storage::spawn_periodic(
            self.clone(),
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

        self.spawn_index_writer(shutdown.clone());

        if self.gc.enabled() {
            let store = self.clone();
            let interval = Duration::from_secs(self.config.gc.interval_secs);
            tokio::spawn(async move {
                store
                    .gc_consistency_check()
                    .instrument(tracing::info_span!("gc.consistency_check"))
                    .await;
                store.gc.set_ready();
                tracing::info!(
                    candidates = store.gc.len(),
                    "GC ready: consistency check complete"
                );
                roci_storage::spawn_periodic(
                    store.clone(),
                    "gc.sweep",
                    interval,
                    shutdown,
                    |s| async move {
                        s.gc_sweep().await;
                    },
                );
            });
        } else {
            self.gc.set_ready();
        }

        tracing::info!(
            gc = self.config.gc.enabled,
            scrub = self.config.scrub.enabled,
            dedupe = self.config.dedupe,
            "S3 storage maintenance started"
        );
    }

    async fn ready(&self) -> Result<(), StorageError> {
        // Fast path: a successful probe within the last 10 s is still valid.
        const PROBE_TTL: Duration = Duration::from_secs(10);
        {
            let cache = self
                .readiness_cache
                .lock()
                .expect("readiness_cache poisoned");
            if let Some(ts) = *cache {
                if ts.elapsed() < PROBE_TTL {
                    return Ok(());
                }
            }
        }

        // Startup CreateBucket gave up (backend slow to form): one more attempt
        // per readiness check until it succeeds.
        if self.create_bucket
            && !self
                .bucket_ensured
                .load(std::sync::atomic::Ordering::Acquire)
        {
            self.ensure_bucket_within(Duration::ZERO).await?;
            self.bucket_ensured
                .store(true, std::sync::atomic::Ordering::Release);
        }

        // Probe: PUT then DELETE a sentinel object.
        let key = if self.client.prefix.is_empty() {
            ".roci-readyz-probe".to_string()
        } else {
            format!("{}/.roci-readyz-probe", self.client.prefix)
        };
        let path = ObjPath::from(key);

        self.client
            .store
            .put(&path, PutPayload::from_static(b"ok"))
            .await
            .map_err(|e| StorageError::Unavailable(format!("readiness probe PUT failed: {e}")))?;

        // Best-effort cleanup; failure doesn't affect readiness.
        let _ = self.client.store.delete(&path).await;

        // Cache success.
        {
            let mut cache = self
                .readiness_cache
                .lock()
                .expect("readiness_cache poisoned");
            *cache = Some(std::time::Instant::now());
        }
        Ok(())
    }
}

impl S3Storage {
    /// Quota admission: check existence first, then admit.
    async fn admit_blob(
        &self,
        repo: &str,
        digest: &Digest,
        size: u64,
    ) -> Result<u64, StorageError> {
        if !self.quota.tracks_bytes() {
            return Ok(0);
        }
        if self.blob_exists(repo, digest).await? {
            return Ok(0);
        }
        self.quota.admit(repo, size)?;
        Ok(size)
    }

    /// Bookkeeping after a blob entered CAS.
    fn blob_entered(&self, repo: &str, digest: &str, checksum: Option<BlobChecksum>) {
        roci_storage::note_blob_entered(
            &*self.meta,
            &self.gc,
            &self.dedupe,
            repo,
            digest,
            checksum,
        );
    }

    /// Bookkeeping after a blob left CAS.
    fn blob_left(&self, repo: &str, digest: &str, size: Option<u64>) {
        roci_storage::note_blob_left(
            &*self.meta,
            &self.gc,
            &self.dedupe,
            &self.quota,
            repo,
            digest,
            size,
        );
    }

    /// Discard an upload session.
    async fn discard_session(&self, repo: &str, id: &str) {
        self.remove_staging(repo, id).await;
        self.upload_locks.remove(repo, id);
    }

    /// Ensure OCI layout marker and empty index.json exist for `repo`.
    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        {
            let set = self.layout_cache.lock().expect("layout_cache poisoned");
            if set.contains(repo) {
                return Ok(());
            }
        }
        let lk = layout_key(&self.client.prefix, repo)?;
        let lp = ObjPath::from(lk);
        if self.client.store.head(&lp).await.is_ok() {
            self.layout_cache
                .lock()
                .expect("layout_cache poisoned")
                .insert(repo.to_string());
            return Ok(());
        }
        self.client
            .store
            .put(&lp, PutPayload::from_static(OCI_LAYOUT_MARKER.as_bytes()))
            .await
            .map_err(obj_err_write)?;
        let ik = index_key(&self.client.prefix, repo)?;
        let ip = ObjPath::from(ik);
        if self.client.store.head(&ip).await.is_err() {
            let index = serde_json::to_vec(&empty_index())
                .map_err(|e| StorageError::Io(io::Error::other(e)))?;
            self.client
                .store
                .put(&ip, PutPayload::from(Bytes::from(index)))
                .await
                .map_err(obj_err_write)?;
        }
        self.layout_cache
            .lock()
            .expect("layout_cache poisoned")
            .insert(repo.to_string());
        Ok(())
    }

    /// Copy a blob between repos (single CopyObject ≤5 GiB, parallel otherwise).
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
                .map_err(obj_err_write)?;
        } else {
            // Parallel copy: ranged GETs → multipart upload, bounded memory.
            self.parallel_copy(&from_path, &to_path, size).await?;
        }
        Ok(())
    }

    /// Parallel copy via ranged GETs into a multipart upload, bounded concurrency.
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
            .map_err(obj_err_write)?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, part_size as usize);

        let mut offset: u64 = 0;
        while offset < size {
            if let Err(e) = writer.wait_for_capacity(concurrency).await {
                writer.abort().await.map_err(obj_err_write)?;
                return Err(obj_err_write(e));
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
            return Err(obj_err_write(e));
        }
        Ok(())
    }

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

    /// Upload a staged local file to S3. Single PUT below `multipart_part_size`;
    /// streaming multipart otherwise. Beneath-root opens prevent symlink redirect.
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
            // Single PUT (bounded by configured part size).
            let mut f = roci_storage::beneath::open_beneath(&self.root, &rel).await?;
            let mut data = Vec::with_capacity(file_size as usize);
            tokio::io::AsyncReadExt::read_to_end(&mut f, &mut data).await?;
            self.client
                .store
                .put(&obj_path, PutPayload::from(Bytes::from(data)))
                .await
                .map_err(obj_err_write)?;
        } else {
            let upload = self
                .client
                .store
                .put_multipart_opts(&obj_path, Default::default())
                .await
                .map_err(obj_err_write)?;
            let mut writer = WriteMultipart::new_with_chunk_size(upload, part_size);

            let mut file = roci_storage::beneath::open_beneath(&self.root, &rel).await?;
            let mut buf = vec![0u8; part_size];
            loop {
                if let Err(e) = writer.wait_for_capacity(concurrency).await {
                    writer.abort().await.map_err(obj_err_write)?;
                    return Err(obj_err_write(e));
                }
                let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.put(Bytes::copy_from_slice(&buf[..n]));
            }

            if let Err(e) = writer.finish().await {
                return Err(obj_err_write(e));
            }
        }
        Ok(())
    }

    /// Record manifest size for index.json rebuilds (avoids per-entry HEAD).
    fn record_manifest_size(&self, repo: &str, digest: &str, size: u64) {
        self.manifest_sizes
            .lock()
            .expect("manifest_sizes poisoned")
            .insert((repo.to_string(), digest.to_string()), size);
    }

    /// Forget a deleted manifest's size.
    fn forget_manifest_size(&self, repo: &str, digest: &str) {
        self.manifest_sizes
            .lock()
            .expect("manifest_sizes poisoned")
            .remove(&(repo.to_string(), digest.to_string()));
    }

    /// Read remote index.json for `repo`.
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

    /// Resolve a tag from remote index.json.
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

    /// Media type from cached remote index (digest miss fallback).
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

impl S3Storage {
    /// Ensure the bucket exists via a signed path-style CreateBucket (200/409 = ok);
    /// retries with backoff until [`CREATE_BUCKET_DEADLINE`].
    pub(crate) async fn ensure_bucket(&self) -> Result<(), StorageError> {
        self.ensure_bucket_within(CREATE_BUCKET_DEADLINE).await
    }

    pub(crate) async fn ensure_bucket_within(
        &self,
        deadline: Duration,
    ) -> Result<(), StorageError> {
        let (Some(signer), Some(http)) = (&self.client.signer, &self.client.bucket_http) else {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "create_bucket requires S3 credentials",
            )));
        };
        let give_up = tokio::time::Instant::now() + deadline;
        let mut delay = Duration::from_millis(250);
        loop {
            // Re-sign each attempt: a retry window can outlive one signature.
            let url = signer
                .signed_url(
                    http::Method::PUT,
                    &ObjPath::from(""),
                    Duration::from_secs(60),
                )
                .await
                .map_err(|e| {
                    StorageError::Io(io::Error::other(format!("signing CreateBucket: {e}")))
                })?;
            let request = http::Request::put(url.as_str())
                .body(object_store::client::HttpRequestBody::empty())
                .map_err(|e| StorageError::Io(io::Error::other(e)))?;
            let failure = match http.execute(request).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 || status == 409 {
                        tracing::info!(status, "create_bucket: bucket ready");
                        return Ok(());
                    }
                    format!("HTTP {status}")
                }
                Err(e) => e.to_string(),
            };
            if tokio::time::Instant::now() + delay > give_up {
                return Err(StorageError::Unavailable(format!(
                    "create_bucket failed: {failure}"
                )));
            }
            tracing::warn!(error = %failure, "create_bucket: retrying");
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
        }
    }
}

impl S3Storage {
    /// Recover metadata from remote index.json objects: imports foreign tags,
    /// warms referrers, seeds quota/dedupe.
    async fn recover_from_remote_indexes(&self) {
        self.seed_sessions_from_staging();

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

        for repo in &repos {
            let Ok(index) = self.read_remote_index(repo).await else {
                continue;
            };

            self.cache_remote_index(repo, index.clone());

            roci_storage::import_foreign_tags(&*self.meta, repo, &index);

            let manifests = index
                .get("manifests")
                .and_then(|m| m.as_array())
                .cloned()
                .unwrap_or_default();
            for entry in &manifests {
                let Some(digest_str) = entry.get("digest").and_then(|d| d.as_str()) else {
                    continue;
                };
                if let Some(size) = entry.get("size").and_then(|s| s.as_u64()) {
                    self.record_manifest_size(repo, digest_str, size);
                }
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

                self.dedupe.insert(repo, digest_str);
            }
        }

        if self.quota.tracks_bytes() {
            self.seed_quota_from_listing(&repos).await;
        }

        // Seed dedupe from blob listing (catches non-manifest blobs).
        self.seed_dedupe_from_listing(&repos).await;
    }

    /// Seed quota byte usage from blob listing.
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

    /// Seed dedupe index from blob listing.
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

impl S3Storage {
    /// Startup consistency check: rebuild backrefs, register roots, seed candidates.
    pub(crate) async fn gc_consistency_check(&self) {
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

        for r in self.meta.repos() {
            repos.insert(r);
        }

        for repo in &repos {
            self.gc_rebuild_repo(repo).await;
        }

        // Seed candidates: blobs with no root/manifest/backrefs → mark.
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
                if self.meta.manifest_media_type(repo, &digest_str).is_some()
                    || self.gc.is_root(repo, &digest_str)
                {
                    continue;
                }
                if self.meta.backrefs(repo, &digest_str).is_empty() {
                    self.gc.mark_at(repo, &digest_str, now);
                }
            }
        }

        self.sweep_stale_uploads().await;
    }

    /// Rebuild backrefs for one repo via the shared single-pass walker.
    async fn gc_rebuild_repo(&self, repo: &str) {
        let mut roots: HashSet<String> = self.meta.manifests(repo).into_iter().collect();

        match self.read_remote_index(repo).await {
            Ok(index) => {
                if let Some(manifests) = index.get("manifests").and_then(|m| m.as_array()) {
                    for entry in manifests {
                        if let Some(d) = entry.get("digest").and_then(|v| v.as_str()) {
                            roots.insert(d.to_string());
                        }
                    }
                }
            }
            Err(StorageError::NotFound) => {}
            Err(e) => {
                tracing::warn!(repo, error = %e, "remote index.json unreadable; repo is GC-unsafe");
                self.gc.mark_unsafe(repo);
                return;
            }
        }

        let store = self.clone();
        let repo_owned = repo.to_string();
        roci_storage::gc::rebuild_backrefs(repo, &*self.meta, &self.gc, roots, |d| {
            let store = store.clone();
            let repo = repo_owned.clone();
            async move {
                let size = match store.blob_size(&repo, &d).await {
                    Ok(s) => s,
                    Err(StorageError::NotFound) => return Ok(None),
                    Err(e) => return Err(io::Error::other(e.to_string())),
                };
                if size > roci_storage::gc::MAX_ROOT_MANIFEST_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized root manifest",
                    ));
                }
                match store.read_blob(&repo, &d).await {
                    Ok(b) => Ok(Some(b)),
                    Err(e) => Err(io::Error::other(e.to_string())),
                }
            }
        })
        .await;
    }

    /// GC sweep: collect unreferenced blobs in bounded batches.
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
                if !self.gc.is_due(repo, digest_str, now) {
                    continue;
                }
                if self.gc.is_root(repo, digest_str) {
                    self.gc.clear(repo, digest_str);
                    continue;
                }
                if self.gc.is_unsafe(repo) {
                    continue;
                }
                if !self.meta.backrefs(repo, digest_str).is_empty() {
                    self.gc.clear(repo, digest_str);
                    continue;
                }
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
                let size = match self.client.store.head(&path).await {
                    Ok(m) => Some(m.size),
                    Err(object_store::Error::NotFound { .. }) => {
                        self.gc.clear(repo, digest_str);
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(repo, digest = %digest_str, error = %e, "GC head failed");
                        errors += 1;
                        continue;
                    }
                };
                match self.client.store.delete(&path).await {
                    Ok(()) => {
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

    /// Remove uploads older than GC delay, skipping locked sessions.
    /// Re-checks mtime under lock to prevent racing concurrent uploads.
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
            let lock = self.upload_locks.get(&repo, &id);
            let Ok(_guard) = lock.try_lock() else {
                continue;
            };
            // Re-check age under lock: concurrent append may have refreshed mtime.
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
            self.upload_locks.remove(&repo, &id);
        }
        (count, bytes)
    }
}

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
                tokio::time::sleep(Duration::from_millis(200)).await;

                let dirty: Vec<(String, u64)> = {
                    let d = store.index_dirty.lock().expect("index_dirty poisoned");
                    d.iter().map(|(k, v)| (k.clone(), *v)).collect()
                };
                for (repo, gen) in dirty {
                    if let Err(e) = store.write_remote_index(&repo).await {
                        tracing::warn!(repo = repo.as_str(), error = %e, "index.json rewrite failed");
                        continue;
                    }
                    let mut d = store.index_dirty.lock().expect("index_dirty poisoned");
                    if d.get(&repo) == Some(&gen) {
                        d.remove(&repo);
                    }
                }
            }
        });
    }

    /// Build and upload index.json, merging meta over existing remote index.
    pub(crate) async fn write_remote_index(&self, repo: &str) -> Result<(), StorageError> {
        let existing = match self.read_remote_index(repo).await {
            Ok(idx) => Some(idx),
            Err(StorageError::NotFound) => None,
            Err(e) => return Err(e),
        };

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
            .map_err(obj_err_write)?;
        Ok(())
    }
}

/// Extract repo name from an `index.json` key.
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

/// Extract `alg:hex` digest from a blob key.
pub(crate) fn extract_digest_from_blob_key(key: &str, repo_prefix: &str) -> Option<String> {
    let rest = key.strip_prefix(repo_prefix)?.strip_prefix("/blobs/")?;
    let (alg, hex) = rest.split_once('/')?;
    Some(format!("{alg}:{hex}"))
}

use tracing::Instrument;
