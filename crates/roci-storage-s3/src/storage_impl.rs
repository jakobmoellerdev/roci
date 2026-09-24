//! [`Storage`] and [`StorageBackend`] implementation for [`S3Storage`].

use crate::keys::{blob_key, index_key, layout_key, validate_repo};
use crate::S3Storage;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use roci_storage::{
    BlobChecksum, BlobRead, BlobStream, Digest, ManifestLinks, ManifestRef, MetaOp, Page,
    RangeOpener, Referrer, Storage, StorageBackend, StorageError,
};
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

// ── Storage trait impl ─────────────────────────────────────────────────

impl Storage for S3Storage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        let meta = self.client.store.head(&path).await.map_err(obj_err)?;
        Ok(meta.size as u64)
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
        self.append_to_staging(id, chunk, expected_offset).await
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        validate_repo(repo)?;
        self.staging_size(id).await
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        validate_repo(repo)?;
        let lock = self.session_lock(repo, id);
        let _guard = lock.lock().await;
        let path = match self.staging_path(id) {
            Ok(p) => p,
            Err(_) => {
                self.drop_session_lock(repo, id);
                return Ok(false);
            }
        };
        let removed = match tokio::fs::remove_file(&path).await {
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
            self.append_to_staging(id, trailing, None).await?;
        }

        // Check size under the lock.
        let staged_size = self.staging_size(id).await?;
        if staged_size > max_size {
            self.remove_staging(id).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: staged_size,
            });
        }

        // Stream-hash to verify digest.
        let (actual, crc32c, size) = self.hash_staging(id, expected.algorithm()).await?;
        if !actual.ct_eq(expected) {
            self.remove_staging(id).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }

        // Quota admission.
        let digest_str = expected.as_string();
        let charged = self.admit_blob(repo, expected, size).await?;

        // GC pin.
        let pin = self.gc.pin().await;

        // Dedupe: server-side copy from another repo if available.
        let linked = self.try_server_side_copy(repo, expected, &digest_str).await;

        if !linked {
            // Upload the staged file to S3 via parallel multipart.
            if let Err(e) = self.upload_staged_blob(repo, expected, id).await {
                drop(pin);
                self.quota.release(repo, charged);
                self.remove_staging(id).await;
                self.drop_session_lock(repo, id);
                return Err(e);
            }
        }

        // Ensure OCI layout marker exists.
        self.ensure_layout(repo).await?;

        // Cleanup local staging.
        self.remove_staging(id).await;
        self.drop_session_lock(repo, id);

        // Bookkeeping.
        self.blob_entered(repo, &digest_str, Some(BlobChecksum { crc32c, size }));
        drop(pin);
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

        let charged = self.admit_blob(repo, digest, data.len() as u64).await?;
        let digest_str = digest.as_string();
        let pin = self.gc.pin().await;

        // Dedupe: server-side copy from another repo.
        let linked = self.try_server_side_copy(repo, digest, &digest_str).await;

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

        self.ensure_layout(repo).await?;
        self.blob_entered(
            repo,
            &digest_str,
            Some(BlobChecksum {
                crc32c: crc32c::crc32c(data),
                size: data.len() as u64,
            }),
        );
        drop(pin);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        validate_repo(repo)?;
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let path = ObjPath::from(key);
        // Get size before deleting.
        let size = match self.client.store.head(&path).await {
            Ok(meta) => Some(meta.size),
            Err(_) => None,
        };
        // object_store delete_stream takes a stream of paths.
        let paths_stream: BoxStream<'static, object_store::Result<ObjPath>> =
            futures::stream::once(async move { Ok(path) }).boxed();
        let mut results = self.client.store.delete_stream(paths_stream);
        while let Some(r) = results.next().await {
            r.map_err(obj_err)?;
        }
        self.blob_left(repo, &digest.as_string(), size);
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

        // Store manifest as a blob (verifies digest, ensures layout).
        self.put_blob(repo, digest, data).await?;

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

        // GC: manifest and its references are live.
        self.gc.clear(repo, &digest_str);
        for r in &references {
            self.gc.clear(repo, r);
        }
        Ok(())
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        validate_repo(repo)?;
        let (digest, media_type) = if reference.contains(':') {
            let digest = Digest::parse(reference)?;
            let media_type = self
                .meta
                .manifest_media_type(repo, reference)
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

        // Quota.
        let charged = self.admit_blob(to_repo, digest, size).await?;
        let pin = self.gc.pin().await;

        // Server-side copy (no bytes through roci).
        let from_key = blob_key(&self.client.prefix, from_repo, digest)?;
        let to_key = blob_key(&self.client.prefix, to_repo, digest)?;
        let from_path = ObjPath::from(from_key);
        let to_path = ObjPath::from(to_key);
        if let Err(e) = self
            .client
            .store
            .copy_opts(&from_path, &to_path, Default::default())
            .await
        {
            drop(pin);
            self.quota.release(to_repo, charged);
            return Err(obj_err(e));
        }
        roci_telemetry::record_dedupe_link("mount", "server_side_copy");

        self.ensure_layout(to_repo).await?;
        let checksum = self.meta.checksum(from_repo, &digest_str);
        self.blob_entered(to_repo, &digest_str, checksum);
        drop(pin);
        Ok(true)
    }
}

// ── StorageBackend ─────────────────────────────────────────────────────

impl StorageBackend for S3Storage {
    async fn recover(&self) {
        // Import metadata from existing index.json objects.
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
            let interval = Duration::from_secs(self.config.gc.interval_secs);
            self.spawn_periodic("gc.sweep", interval, shutdown.clone(), |s| async move {
                s.gc_sweep().await;
            });
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

    /// Ensure the OCI layout marker and empty index.json exist for `repo`.
    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        let lk = layout_key(&self.client.prefix, repo)?;
        let lp = ObjPath::from(lk);
        // Check if layout already exists.
        if self.client.store.head(&lp).await.is_ok() {
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
        Ok(())
    }

    /// Try server-side copy from another repo holding `digest`.
    async fn try_server_side_copy(&self, repo: &str, digest: &Digest, digest_str: &str) -> bool {
        if !self.dedupe.enabled() {
            return false;
        }
        let Some(source_repo) = self.dedupe.locate(digest_str, repo) else {
            return false;
        };
        let Ok(from_key) = blob_key(&self.client.prefix, &source_repo, digest) else {
            return false;
        };
        let Ok(to_key) = blob_key(&self.client.prefix, repo, digest) else {
            return false;
        };
        let from_path = ObjPath::from(from_key);
        let to_path = ObjPath::from(to_key);
        match self
            .client
            .store
            .copy_opts(&from_path, &to_path, Default::default())
            .await
        {
            Ok(_) => {
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

    /// Upload a staged local file to S3 via parallel multipart.
    async fn upload_staged_blob(
        &self,
        repo: &str,
        digest: &Digest,
        id: &str,
    ) -> Result<(), StorageError> {
        let path = self.staging_path(id)?;
        let data = tokio::fs::read(&path).await?;
        let key = blob_key(&self.client.prefix, repo, digest)?;
        let obj_path = ObjPath::from(key);

        let part_size = self.client.multipart_part_size as usize;
        let data_len = data.len();

        // Use multipart only for files larger than the part size.
        if data_len > part_size {
            let upload = self
                .client
                .store
                .put_multipart_opts(&obj_path, Default::default())
                .await
                .map_err(obj_err)?;
            let mut writer = object_store::WriteMultipart::new_with_chunk_size(upload, part_size);
            writer.write(&data);
            writer.finish().await.map_err(obj_err)?;
        } else {
            self.client
                .store
                .put(&obj_path, PutPayload::from(Bytes::from(data)))
                .await
                .map_err(obj_err)?;
        }
        Ok(())
    }

    /// Read the remote index.json for `repo`.
    async fn read_remote_index(&self, repo: &str) -> Result<serde_json::Value, StorageError> {
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

    /// Recover metadata from existing remote index.json objects.
    async fn recover_from_remote_indexes(&self) {
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

        for repo in repos {
            let Ok(index) = self.read_remote_index(&repo).await else {
                continue;
            };
            let manifests = index
                .get("manifests")
                .and_then(|m| m.as_array())
                .cloned()
                .unwrap_or_default();
            for entry in &manifests {
                let Some(digest_str) = entry.get("digest").and_then(|d| d.as_str()) else {
                    continue;
                };
                let Ok(_digest) = Digest::parse(digest_str) else {
                    continue;
                };
                let media_type = entry
                    .get("mediaType")
                    .and_then(|m| m.as_str())
                    .unwrap_or(MEDIA_TYPE_IMAGE_MANIFEST);
                let tag = entry
                    .get("annotations")
                    .and_then(|a| a.get("org.opencontainers.image.ref.name"))
                    .and_then(|v| v.as_str());

                // Build references.
                let references: Vec<String> = roci_storage::manifest_references(entry)
                    .iter()
                    .map(Digest::as_string)
                    .collect();

                // Subject / referrer.
                let referrer = entry
                    .get("subject")
                    .and_then(|s| s.get("digest"))
                    .and_then(|d| d.as_str())
                    .and_then(|subject_str| {
                        serde_json::to_vec(entry)
                            .ok()
                            .map(|desc| (subject_str.to_string(), desc))
                    });

                let _ = self.meta.apply(MetaOp::PutManifest {
                    repo: repo.clone(),
                    digest: digest_str.to_string(),
                    media_type: media_type.to_string(),
                    tag: tag.map(str::to_string),
                    references,
                    referrer,
                });

                // Dedupe index.
                self.dedupe.insert(&repo, digest_str);
            }
        }
        self.gc.set_ready();
    }

    /// GC sweep: collect unreferenced blobs whose grace period has elapsed.
    pub(crate) async fn gc_sweep(&self) {
        if !self.gc.is_ready() {
            return;
        }
        let now = std::time::Instant::now();
        let due = self.gc.due(now);
        if due.is_empty() {
            return;
        }
        let _fence = self.gc.exclusive().await;
        for (repo, digest_str) in due {
            if !self.gc.is_due(&repo, &digest_str, now) {
                continue;
            }
            let Ok(digest) = Digest::parse(&digest_str) else {
                self.gc.clear(&repo, &digest_str);
                continue;
            };
            let Ok(key) = blob_key(&self.client.prefix, &repo, &digest) else {
                self.gc.clear(&repo, &digest_str);
                continue;
            };
            let path = ObjPath::from(key);
            let size = self.client.store.head(&path).await.ok().map(|m| m.size);
            let paths_stream: BoxStream<'static, object_store::Result<ObjPath>> =
                futures::stream::once(async move { Ok(path) }).boxed();
            let mut results = self.client.store.delete_stream(paths_stream);
            while let Some(r) = results.next().await {
                if let Err(e) = r {
                    tracing::warn!(repo = repo.as_str(), digest = digest_str.as_str(), error = %e, "GC delete failed");
                }
            }
            self.gc.clear(&repo, &digest_str);
            if let Some(bytes) = size {
                roci_telemetry::record_gc_collected("blob", bytes);
            }
            self.blob_left(&repo, &digest_str, size);
            tracing::debug!(
                repo = repo.as_str(),
                digest = digest_str.as_str(),
                "GC collected"
            );
        }
    }

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

    /// Build and upload `index.json` for a repo from the metadata store.
    pub(crate) async fn write_remote_index(&self, repo: &str) -> Result<(), StorageError> {
        let mut index = empty_index();
        let manifests = index
            .get_mut("manifests")
            .and_then(|m| m.as_array_mut())
            .expect("empty_index has manifests array");

        // Tags snapshot.
        for (tag, digest, media_type) in self.meta.tags_snapshot(repo) {
            let mut desc = serde_json::json!({
                "mediaType": media_type,
                "digest": digest,
                "size": 0,
                "annotations": {
                    "org.opencontainers.image.ref.name": tag
                }
            });
            // Try to get actual size.
            if let Ok(d) = Digest::parse(&digest) {
                if let Ok(key) = blob_key(&self.client.prefix, repo, &d) {
                    let path = ObjPath::from(key);
                    if let Ok(meta) = self.client.store.head(&path).await {
                        desc["size"] = serde_json::json!(meta.size);
                    }
                }
            }
            manifests.push(desc);
        }

        // Untagged manifests (those with media type but no tag).
        let tagged_digests: std::collections::HashSet<String> = manifests
            .iter()
            .filter_map(|e| e.get("digest").and_then(|d| d.as_str()).map(str::to_string))
            .collect();
        for digest_str in self.meta.manifests(repo) {
            if tagged_digests.contains(&digest_str) {
                continue;
            }
            let media_type = self
                .meta
                .manifest_media_type(repo, &digest_str)
                .unwrap_or_else(|| MEDIA_TYPE_IMAGE_MANIFEST.to_string());
            let mut desc = serde_json::json!({
                "mediaType": media_type,
                "digest": digest_str,
                "size": 0
            });
            if let Ok(d) = Digest::parse(&digest_str) {
                if let Ok(key) = blob_key(&self.client.prefix, repo, &d) {
                    let path = ObjPath::from(key);
                    if let Ok(meta) = self.client.store.head(&path).await {
                        desc["size"] = serde_json::json!(meta.size);
                    }
                }
            }
            manifests.push(desc);
        }

        // Referrers: merge subject into descriptors.
        for (subject, referrers) in self.meta.referrers_snapshot(repo) {
            for (referrer_digest, descriptor_bytes) in referrers {
                // Skip if already present.
                if manifests
                    .iter()
                    .any(|e| e.get("digest").and_then(|d| d.as_str()) == Some(&referrer_digest))
                {
                    continue;
                }
                if let Ok(desc) = serde_json::from_slice::<serde_json::Value>(&descriptor_bytes) {
                    let mut obj = desc;
                    if obj.get("subject").is_none() {
                        obj["subject"] = serde_json::json!({ "digest": subject });
                    }
                    manifests.push(obj);
                }
            }
        }

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

/// Extract repo name from an index.json key like `prefix/repo/index.json`.
fn extract_repo_from_index_key(key: &str, prefix: &str) -> Option<String> {
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
