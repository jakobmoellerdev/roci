//! [`Storage`] implementation for [`FsStorage`].

use super::super::FsStorage;
use super::paths::{blob_dir_rel, blob_rel, upload_dir_rel, upload_rel, SafeComponent};
use crate::beneath::*;
use crate::digest::{digest_of, hash_std, Digest};
use crate::error::{map_not_found, StorageError};
use crate::layout::*;
use crate::metadata::{BlobChecksum, MetaOp, Page, Referrer};
use crate::publish::*;
use crate::storage::{BlobRead, ManifestLinks, ManifestRef, Storage};
use crate::upload_body::{
    append_body, append_body_deferring_tail, Deferred, StagedHash, UploadBody,
};
use std::io;
use std::path::Path;
use tokio::io::AsyncReadExt;

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        // Traversal backstop, then presence filter before no-follow stat.
        let rel = blob_rel(repo, digest)?;
        let digest_str = digest.as_string();
        if !self.presence.maybe_present(repo, &digest_str) {
            return Err(StorageError::NotFound);
        }
        self.want_blob(repo, &digest_str).await;
        // Answer HEAD from RAM (inv. 14/15); fall back to stat for imported blobs.
        if let Some(recorded) = self.meta.checksum(repo, &digest_str) {
            return Ok(recorded.size);
        }
        match stat_beneath(&self.root, &rel).await? {
            Some((true, size)) => Ok(size),
            _ => Err(StorageError::NotFound),
        }
    }

    async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        // Traversal backstop, then presence filter before no-follow stat.
        let rel = blob_rel(repo, digest)?;
        let digest_str = digest.as_string();
        if !self.presence.maybe_present(repo, &digest_str) {
            return Ok(false);
        }
        self.want_blob(repo, &digest_str).await;
        // RAM shortcut (inv. 15); authoritative re-check in put_manifest.
        if self.meta.checksum(repo, &digest_str).is_some() {
            return Ok(true);
        }
        Ok(matches!(
            stat_beneath(&self.root, &rel).await?,
            Some((true, _))
        ))
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        let digest_str = digest.as_string();
        // Serve from cache if warm; else read the loose file.
        if let Some(bytes) = self.cache.get(repo, &digest_str) {
            return Ok(bytes.to_vec());
        }
        let rel = blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest_str) {
            return Err(StorageError::NotFound);
        }
        // No-follow beneath-root read (symlink-safe).
        let mut f = open_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).await.map_err(map_not_found)?;
        self.cache.put(repo, &digest_str, &bytes);
        Ok(bytes)
    }

    async fn open_blob(&self, repo: &str, digest: &Digest) -> Result<BlobRead, StorageError> {
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        // No-follow beneath-root open (symlink-safe).
        let rel = blob_rel(repo, digest)?;
        let f = open_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
        let size = f.metadata().await.map_err(map_not_found)?.len();
        Ok(BlobRead::file(f, size))
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| StorageError::Io(io::Error::other(e)))?;
        let id = hex::encode(buf);
        upload_dir_rel(repo, &id)?;
        self.quota.begin_session()?;
        self.pending_uploads
            .lock()
            .expect("pending-uploads poisoned")
            .insert((repo.to_string(), id.clone()), std::time::Instant::now());
        Ok(id)
    }

    async fn append_upload(
        &self,
        repo: &str,
        id: &str,
        body: UploadBody,
        expected_offset: Option<u64>,
        limit: u64,
    ) -> Result<u64, StorageError> {
        // Session lock serializes with concurrent append/finish/abort.
        let lock = self.session_lock(repo, id)?;
        let mut hash = lock.lock().await;
        let (f, current) = match self.prepare_session(repo, id).await? {
            Staging::Ready { file, len, .. } => (tokio::fs::File::from_std(file), len),
            Staging::Missing => {
                self.upload_locks.remove(repo, id);
                return Err(StorageError::NotFound);
            }
            Staging::NotRegular => {
                return Err(StorageError::Io(io::Error::other(format!(
                    "upload {id} is not a regular file"
                ))))
            }
        };
        // Content-Range precondition: current size must equal declared offset.
        if let Some(offset) = expected_offset.filter(|&o| o != current) {
            return Err(StorageError::RangeNotSatisfiable {
                expected: current,
                got: offset,
            });
        }
        let seed = hash.take().or_else(|| (current == 0).then(StagedHash::new));
        let (total, extended) = append_body(f, current, body, limit, seed).await?;
        let appended = total.saturating_sub(current);
        if appended > 0 {
            roci_telemetry::record_upload_bytes(appended);
        }
        *hash = extended;
        Ok(total)
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        // No-follow stat beneath root.
        if self.is_pending(repo, id) {
            return Ok(0);
        }
        let rel = upload_rel(repo, id)?;
        match stat_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?
        {
            Some((true, size)) => Ok(size),
            _ => Err(StorageError::NotFound),
        }
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
        // Session lock covers trailing append + verify + promote.
        let lock = self.session_lock(repo, id)?;
        let mut guard = lock.lock().await;
        let staging_rel = upload_rel(repo, id)?;
        let (file, current, staging_ino) = match self.prepare_session(repo, id).await? {
            Staging::Ready { file, len, ino } => (file, len, ino),
            Staging::Missing => {
                self.upload_locks.remove(repo, id);
                return Err(StorageError::NotFound);
            }
            Staging::NotRegular => {
                self.discard_session(repo, id).await?;
                return Err(StorageError::BadPath(format!(
                    "upload {id} is not a regular file"
                )));
            }
        };
        let seed = guard
            .take()
            .or_else(|| (current == 0).then(StagedHash::new));
        let body = append_body_deferring_tail(
            tokio::fs::File::from_std(file),
            current,
            trailing,
            limit,
            seed,
        )
        .await?;
        let staged_size = body.len;
        // Reject oversized staging file under lock.
        if staged_size > max_size {
            self.discard_session(repo, id).await?;
            roci_telemetry::record_upload_finalize("too_large");
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: staged_size,
            });
        }
        // When hash-on-write covers all staged bytes, the landing hop
        // verifies; otherwise a separate verify hop re-hashes.
        let covers = body.hash.as_ref().is_some_and(|h| h.len() == body.tail_at)
            && expected.algorithm() == "sha256";
        let (verify, verified) = if covers && !self.config.commit {
            (Some((body, expected.clone())), None)
        } else {
            let (root, rel) = (self.root.to_path_buf(), staging_rel.clone());
            let alg = expected.algorithm().to_string();
            let commit = self.config.commit;
            let checked = run_blocking("finish_verify", move || {
                use rustix::fs::OFlags;
                let hash = body.write_tail()?.filter(|_| covers);
                let f = resolve_beneath(&root, &rel, OFlags::RDONLY)?;
                if commit {
                    f.sync_data()?;
                }
                let st = rustix::fs::fstat(&f)?;
                let ino = (st.st_dev as u64, st.st_ino as u64);
                let (d, crc) = match hash {
                    Some(h) => h.finish(),
                    None => hash_std(f, &alg)?,
                };
                Ok((d, crc, ino))
            })
            .await
            .map_err(map_not_found)?;
            (None, Some(checked))
        };
        let staging_ino = verified.as_ref().map_or(staging_ino, |v| v.2);
        if let Some((actual, _, _)) = verified.as_ref().filter(|v| !v.0.ct_eq(expected)) {
            self.discard_session(repo, id).await?;
            roci_telemetry::record_upload_finalize("digest_mismatch");
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        let (alg_rel, hex) = blob_dir_rel(repo, expected)?;
        let repo_rel = super::paths::repo_rel(repo)?;
        let digest_str = expected.as_string();
        // Per-(repo,digest) lock: no double quota charge; GC pin until stamped.
        let admit_lock = self.blob_admit_locks.get(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;
        let pin = self.gc.pin().await;
        let landed = {
            let ctx = LandCtx {
                root: self.root.to_path_buf(),
                repo: repo.to_string(),
                repo_rel,
                up_dir,
                up_leaf,
                alg_rel: alg_rel.clone(),
                hex: hex.clone(),
                digest: digest_str.clone(),
                size: staged_size,
                ino: staging_ino,
                commit: self.config.commit,
                quota: std::sync::Arc::clone(&self.quota),
                dedupe: std::sync::Arc::clone(&self.dedupe),
                warm_limit: self.cache.threshold().min(WARM_CAP),
                verify,
            };
            run_blocking("finish_land", move || Ok(land_blob(ctx))).await?
        };
        let (warm, landed_crc) = match landed {
            Landed::Done { warm, crc } => (warm, crc),
            Landed::Mismatch(actual) => {
                drop(pin);
                drop(_admit_guard);
                self.blob_admit_locks.release(repo, &digest_str);
                self.discard_session(repo, id).await?;
                return Err(StorageError::DigestMismatch {
                    expected: expected.as_string(),
                    actual: actual.as_string(),
                });
            }
            Landed::Rejected(e) => {
                drop(pin);
                drop(_admit_guard);
                self.blob_admit_locks.release(repo, &digest_str);
                self.discard_session(repo, id).await?;
                return Err(e);
            }
            Landed::Failed { charged, error } => {
                drop(pin);
                self.quota.release(repo, charged);
                drop(_admit_guard);
                self.blob_admit_locks.release(repo, &digest_str);
                return Err(error);
            }
        };
        let crc32c = landed_crc.or(verified.map(|v| v.1)).unwrap_or_default();
        self.quota.end_session();
        self.upload_locks.remove(repo, id);
        self.blob_entered(
            repo,
            &digest_str,
            Some(BlobChecksum {
                crc32c,
                size: staged_size,
            }),
        );
        drop(pin);
        drop(_admit_guard);
        self.blob_admit_locks.release(repo, &digest_str);
        if let Some(bytes) = warm {
            self.cache.put(repo, &digest_str, &bytes);
        }
        roci_telemetry::record_upload_finalize("ok");
        Ok(())
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        let lock = self.session_lock(repo, id)?;
        let guard = lock.lock().await;
        // No-follow unlink beneath root; missing = Ok(false).
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        let removed = self.take_pending(repo, id)
            || match unlink_beneath(&self.root, &up_dir, &up_leaf).await {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                Err(e) => return Err(StorageError::Io(e)),
            };
        if removed {
            self.quota.end_session();
        }
        drop(guard);
        self.upload_locks.remove(repo, id);
        Ok(removed)
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        let actual = digest_of(data, digest.algorithm());
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }
        self.ensure_layout(repo).await?;
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let digest_str = digest.as_string();
        let admit_lock = self.blob_admit_locks.get(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;
        let charged = self
            .admit_blob(repo, &alg_rel, &leaf, data.len() as u64)
            .await?;
        let pin = self.gc.pin().await;
        // Dedupe-link or crash-atomic publish (no-follow beneath root).
        if !self.dedupe_link(repo, &alg_rel, &leaf, &digest_str).await {
            if let Err(e) =
                publish_bytes(&self.root, &alg_rel, &leaf, data, self.config.commit).await
            {
                drop(pin);
                self.quota.release(repo, charged);
                drop(_admit_guard);
                self.blob_admit_locks.release(repo, &digest_str);
                return Err(e.into());
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
        drop(_admit_guard);
        self.blob_admit_locks.release(repo, &digest_str);
        self.cache.put(repo, &digest_str, data);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        // No-follow unlink beneath root.
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let size = self.size_for_release(&alg_rel.join(&leaf)).await;
        unlink_beneath(&self.root, &alg_rel, &leaf)
            .await
            .map_err(map_not_found)?;
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
        // Validate tag and build referrer descriptor before writing.
        if let Some(tag) = tag {
            SafeComponent::new(tag)?;
        }
        let referrer = match links.subject {
            Some((subject, descriptor)) => Some((
                subject.as_string(),
                referrer_descriptor(subject, descriptor)?,
            )),
            None => None,
        };
        // GC fence: hold through PutManifest apply + clears; do NOT re-acquire.
        let actual = digest_of(data, digest.algorithm());
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let digest_str = digest.as_string();
        let required = links
            .required
            .iter()
            .map(|r| blob_rel(repo, r))
            .collect::<Result<Vec<_>, _>>()?;
        let pin = self.gc.pin().await;
        // One hop: layout, quota, dedupe/publish, re-check required blobs.
        let ctx = ManifestCtx {
            root: self.root.to_path_buf(),
            repo: repo.to_string(),
            repo_rel: super::paths::repo_rel(repo)?,
            alg_rel,
            leaf,
            digest: digest_str.clone(),
            data: data.to_vec(),
            required,
            quota: std::sync::Arc::clone(&self.quota),
            dedupe: std::sync::Arc::clone(&self.dedupe),
            commit: self.config.commit,
        };
        let landed = run_blocking("manifest_land", move || Ok(land_manifest(ctx))).await?;
        let (missing, recheck_error) = match landed {
            ManifestLanded::Rejected(e) => {
                drop(pin);
                return Err(e);
            }
            ManifestLanded::Failed { charged, error } => {
                drop(pin);
                self.quota.release(repo, charged);
                return Err(error);
            }
            ManifestLanded::Stored { missing, error } => (missing, error),
        };
        self.blob_entered(
            repo,
            &digest_str,
            Some(BlobChecksum {
                crc32c: crc32c::crc32c(data),
                size: data.len() as u64,
            }),
        );
        self.cache.put(repo, &digest_str, data);
        if let Some(e) = recheck_error {
            drop(pin);
            return Err(e);
        }
        if let Some(i) = missing {
            drop(pin);
            return Err(StorageError::MissingReference(
                links.required[i].as_string(),
            ));
        }

        // All edges land in one metadata record (crash-atomic).
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
        self.gc.clear(repo, &digest_str);
        for r in &references {
            self.gc.clear(repo, r);
        }
        drop(pin);
        Ok(())
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        let (digest, media_type) = if reference.contains(':') {
            let digest = Digest::parse(reference)?;
            let media_type = match self.meta.manifest_media_type(repo, reference) {
                Some(mt) => mt,
                None => self
                    .index_media_type_for_digest(repo, reference)
                    .await?
                    .unwrap_or_else(|| MEDIA_TYPE_IMAGE_MANIFEST.to_string()),
            };
            (digest, media_type)
        } else {
            match self.meta.resolve_tag(repo, reference) {
                Some((digest_str, media_type)) => (Digest::parse(&digest_str)?, media_type),
                None => self.index_resolve_tag(repo, reference).await?,
            }
        };
        let digest_str = digest.as_string();
        let bytes = match self.cache.get(repo, &digest_str) {
            Some(cached) => cached.to_vec(),
            None => {
                let mut f = open_beneath(&self.root, &blob_rel(repo, &digest)?)
                    .await
                    .map_err(map_not_found)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b).await.map_err(map_not_found)?;
                self.cache.put(repo, &digest_str, &b);
                b
            }
        };
        Ok(ManifestRef {
            digest,
            media_type,
            bytes,
        })
    }

    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        // Capture references before removing (GC candidate seeding).
        let digest_str = digest.as_string();
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let bytes = match self.cache.get(repo, &digest_str) {
            Some(cached) => cached.to_vec(),
            None => {
                let mut f = open_beneath(&self.root, &alg_rel.join(&leaf))
                    .await
                    .map_err(map_not_found)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b).await.map_err(map_not_found)?;
                b
            }
        };
        let references = serde_json::from_slice(&bytes)
            .map(|v| manifest_references(&v))
            .unwrap_or_default();
        // No-follow unlink beneath root.
        unlink_beneath(&self.root, &alg_rel, &leaf)
            .await
            .map_err(map_not_found)?;
        self.blob_left(repo, &digest_str, Some(bytes.len() as u64));
        self.apply_meta(
            repo,
            MetaOp::DeleteManifest {
                repo: repo.to_string(),
                digest: digest_str,
            },
        )?;
        for r in references.iter().map(Digest::as_string) {
            if self.meta.backrefs(repo, &r).is_empty() && self.presence.maybe_present(repo, &r) {
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
        // In-RAM tag map; fall back to on-disk index.json.
        if let Some(page) = self.meta.tags_page(repo, last, limit) {
            return Ok(page);
        }
        Ok(layout_tags_page(&self.read_index(repo).await?, last, limit))
    }

    async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Result<Page<Referrer>, StorageError> {
        let target = subject.as_string();
        if let Some(page) = self
            .meta
            .referrers_page(repo, &target, artifact_type, last, limit)
        {
            return Ok(page);
        }
        let index = self.read_index(repo).await?;
        let linked = layout_subject_referrers(&index, &target);
        if !linked.is_empty() {
            return Ok(page_layout_referrers(linked, artifact_type, last, limit));
        }
        // Tag-schema fallback (dist-spec §Referrers tag schema).
        let hex_up_to_64 = &subject.hex()[..subject.hex().len().min(64)];
        let tag_schema_tag = format!("{}-{}", subject.algorithm(), hex_up_to_64);
        let resolved = match self.meta.resolve_tag(repo, &tag_schema_tag) {
            Some((digest, _media_type)) => Digest::parse(&digest).ok(),
            None => self
                .index_resolve_tag(repo, &tag_schema_tag)
                .await
                .ok()
                .map(|(d, _)| d),
        };
        let Some(tag_blob_digest) = resolved else {
            return Ok(Page::default());
        };
        let bytes: Vec<u8> = match self.read_blob(repo, &tag_blob_digest).await {
            Ok(b) => b,
            Err(_) => return Ok(Page::default()),
        };
        let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(Page::default()),
        };
        let Some(arr) = parsed.get("manifests").and_then(|m| m.as_array()) else {
            return Ok(Page::default());
        };
        let listed: Vec<(String, &serde_json::Value)> = arr
            .iter()
            .filter_map(|entry| {
                let d = Digest::parse(descriptor_digest(entry)?).ok()?;
                Some((d.as_string(), entry))
            })
            .collect();
        Ok(page_layout_referrers(listed, artifact_type, last, limit))
    }

    async fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        let size = match self.blob_size(from_repo, digest).await {
            Ok(size) => size,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        let digest_str = digest.as_string();
        let (from_alg_rel, leaf) = blob_dir_rel(from_repo, digest)?;
        let (to_alg_rel, _) = blob_dir_rel(to_repo, digest)?;
        if from_alg_rel == to_alg_rel {
            self.presence.insert(to_repo, &digest_str);
            return Ok(true);
        }
        self.ensure_layout(to_repo).await?;
        let admit_lock = self.blob_admit_locks.get(to_repo, &digest_str);
        let _admitting = admit_lock.lock().await;
        let charged = match self.admit_blob(to_repo, &to_alg_rel, &leaf, size).await {
            Ok(c) => c,
            Err(e) => {
                self.blob_admit_locks.release(to_repo, &digest_str);
                return Err(e);
            }
        };
        let pin = self.gc.pin().await;
        // Promote no-follow beneath root: reflink → hard link → copy (SECURITY.md:124).
        let promoted = mount_promote_beneath(
            &self.root,
            &from_alg_rel,
            &to_alg_rel,
            &leaf,
            true,
            self.config.commit,
        )
        .await;
        let how = match promoted {
            Ok(how) => how,
            Err(e) => {
                drop(pin);
                self.quota.release(to_repo, charged);
                self.blob_admit_locks.release(to_repo, &digest_str);
                return Err(match e.kind() {
                    io::ErrorKind::AlreadyExists => StorageError::BadPath(format!(
                        "mount destination for {digest_str} is not a regular file"
                    )),
                    io::ErrorKind::NotFound => StorageError::NotFound,
                    _ => StorageError::Io(e),
                });
            }
        };
        record_promotion("mount", how, to_repo, &digest_str);
        let checksum = self.meta.checksum(from_repo, &digest_str);
        self.blob_entered(to_repo, &digest_str, checksum);
        drop(pin);
        self.blob_admit_locks.release(to_repo, &digest_str);
        Ok(true)
    }
}

/// Log + count how a cross-repo promotion materialized.
pub(super) fn record_promotion(op: &str, how: Promotion, repo: &str, digest: &str) {
    roci_telemetry::record_dedupe_link(op, how.label());
    match how {
        Promotion::Hardlink | Promotion::Copy => tracing::info!(
            op,
            mechanism = how.label(),
            repo,
            digest,
            "reflink unavailable; promoted via fallback"
        ),
        Promotion::Reflink | Promotion::Existing => {
            tracing::debug!(op, mechanism = how.label(), repo, digest, "promoted")
        }
    }
}

impl FsStorage {
    /// Dedupe: link from another repo (reflink → hard link). `true` on success.
    async fn dedupe_link(&self, repo: &str, alg_rel: &Path, leaf: &str, digest: &str) -> bool {
        let Some(src_repo) = self.dedupe.locate(digest, repo) else {
            return false;
        };
        let Ok(d) = Digest::parse(digest) else {
            return false;
        };
        let Ok((src_alg_rel, _)) = blob_dir_rel(&src_repo, &d) else {
            return false;
        };
        match mount_promote_beneath(
            &self.root,
            &src_alg_rel,
            alg_rel,
            leaf,
            false,
            self.config.commit,
        )
        .await
        {
            Ok(how) => {
                record_promotion("dedupe", how, repo, digest);
                true
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    self.dedupe.remove(&src_repo, digest);
                }
                tracing::debug!(repo, digest, error = %e, "dedupe link unavailable; storing a copy");
                false
            }
        }
    }

    /// Blob size for quota release; only stat'ed when byte quotas are tracked.
    async fn size_for_release(&self, rel: &Path) -> Option<u64> {
        if !self.quota.tracks_bytes() {
            return None;
        }
        match stat_beneath(&self.root, rel).await {
            Ok(Some((true, size))) => Some(size),
            _ => None,
        }
    }

    /// Drop an upload session that can never complete.
    async fn discard_session(&self, repo: &str, id: &str) -> Result<(), StorageError> {
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        if self.take_pending(repo, id)
            || unlink_beneath(&self.root, &up_dir, &up_leaf).await.is_ok()
        {
            self.quota.end_session();
        }
        self.upload_locks.remove(repo, id);
        Ok(())
    }
}

/// Ceiling for small-blob cache warm reads.
const WARM_CAP: usize = 8 * 1024 * 1024;

enum Staging {
    Missing,
    NotRegular,
    Ready {
        file: std::fs::File,
        len: u64,
        ino: (u64, u64),
    },
}

/// Blocking: resolve staging file beneath `root` (no-follow), open for appending.
fn prepare_staging(
    root: std::path::PathBuf,
    rel: std::path::PathBuf,
    create: bool,
) -> io::Result<Staging> {
    use rustix::fs::{Mode, OFlags};
    if create {
        // Create staging file (no-follow, O_EXCL) beneath root.
        let dir = rel.parent().unwrap_or(Path::new(""));
        let leaf = rel.file_name().unwrap_or_default();
        let dirfd = dir_beneath(&root, dir, true)?;
        let fd = rustix::fs::openat(
            &dirfd,
            leaf,
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )?;
        let st = rustix::fs::fstat(&fd)?;
        return Ok(Staging::Ready {
            file: std::fs::File::from(fd),
            len: 0,
            ino: (st.st_dev as u64, st.st_ino as u64),
        });
    }
    match stat_beneath_sync(root.clone(), rel.clone())? {
        None => return Ok(Staging::Missing),
        Some((false, _)) => return Ok(Staging::NotRegular),
        Some((true, _)) => {}
    }
    let file = resolve_beneath(&root, &rel, OFlags::WRONLY | OFlags::APPEND)?;
    let st = rustix::fs::fstat(&file)?;
    Ok(Staging::Ready {
        file,
        len: st.st_size as u64,
        ino: (st.st_dev as u64, st.st_ino as u64),
    })
}

struct LandCtx {
    root: std::path::PathBuf,
    repo: String,
    repo_rel: std::path::PathBuf,
    up_dir: std::path::PathBuf,
    up_leaf: String,
    alg_rel: std::path::PathBuf,
    hex: String,
    digest: String,
    size: u64,
    ino: (u64, u64),
    commit: bool,
    quota: std::sync::Arc<crate::quota::QuotaTracker>,
    dedupe: std::sync::Arc<crate::DedupeIndex>,
    warm_limit: usize,
    /// Deferred body tail + hash-on-write state for landing hop verification.
    verify: Option<(Deferred, Digest)>,
}

enum Landed {
    /// Landed; cache warm bytes and optional CRC32C.
    Done {
        warm: Option<Vec<u8>>,
        crc: Option<u32>,
    },
    /// The deferred-tail digest did not match (nothing admitted or moved).
    Mismatch(Digest),
    /// Admission refused (quota): nothing was charged.
    Rejected(StorageError),
    /// A filesystem step failed after `charged` bytes were admitted.
    Failed { charged: u64, error: StorageError },
}

fn land_blob(mut c: LandCtx) -> Landed {
    use std::io::Read;
    let crc = match c.verify.take() {
        None => None,
        Some((body, expected)) => match body.write_tail() {
            Ok(Some(h)) => {
                let (actual, crc) = h.finish();
                if !actual.ct_eq(&expected) {
                    return Landed::Mismatch(actual);
                }
                Some(crc)
            }
            Ok(None) => return Landed::Mismatch(expected),
            Err(e) => {
                return Landed::Failed {
                    charged: 0,
                    error: map_not_found(e),
                }
            }
        },
    };
    let charged = match layout_and_admit(
        &c.root,
        &c.repo_rel,
        &c.quota,
        &c.repo,
        &c.alg_rel,
        &c.hex,
        c.size,
    ) {
        Ok(charged) => charged,
        Err(e) => return Landed::Rejected(e),
    };
    let linked = dedupe_link_sync(&c);
    let result = if linked {
        unlink_beneath_sync(c.root.clone(), c.up_dir.clone(), c.up_leaf.clone())
    } else {
        rename_beneath_sync(
            c.root.clone(),
            c.up_dir.clone(),
            c.up_leaf.clone(),
            c.alg_rel.clone(),
            c.hex.clone(),
            c.ino,
            c.commit,
        )
    };
    if let Err(e) = result {
        return Landed::Failed {
            charged,
            error: map_not_found(e),
        };
    }
    // Cache warm for small blobs.
    let warm = (c.warm_limit > 0 && c.size as usize <= c.warm_limit)
        .then(|| {
            let f = resolve_beneath(&c.root, &c.alg_rel.join(&c.hex), rustix::fs::OFlags::RDONLY)
                .ok()?;
            let mut bytes = Vec::with_capacity(c.size as usize);
            f.take(c.warm_limit as u64 + 1)
                .read_to_end(&mut bytes)
                .ok()?;
            (bytes.len() <= c.warm_limit).then_some(bytes)
        })
        .flatten();
    let _ = charged;
    Landed::Done { warm, crc }
}

fn dedupe_link_sync(c: &LandCtx) -> bool {
    dedupe_link_at(
        &c.root, &c.dedupe, &c.repo, &c.alg_rel, &c.hex, &c.digest, c.commit,
    )
}

/// Link `digest` from another repo (reflink → hard link); `false` if unavailable.
fn dedupe_link_at(
    root: &Path,
    dedupe: &crate::DedupeIndex,
    repo: &str,
    alg_rel: &Path,
    hex: &str,
    digest: &str,
    commit: bool,
) -> bool {
    let c = (root, dedupe, repo, alg_rel, hex, digest, commit);
    let (root, dedupe, repo, alg_rel, hex, digest, commit) = c;
    let Some(src_repo) = dedupe.locate(digest, repo) else {
        return false;
    };
    let Ok(d) = Digest::parse(digest) else {
        return false;
    };
    let Ok((src_alg_rel, _)) = blob_dir_rel(&src_repo, &d) else {
        return false;
    };
    match mount_promote_beneath_sync(
        root.to_path_buf(),
        src_alg_rel,
        alg_rel.to_path_buf(),
        hex.to_string(),
        false,
        commit,
    ) {
        Ok(how) => {
            record_promotion("dedupe", how, repo, digest);
            true
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                dedupe.remove(&src_repo, digest);
            }
            tracing::debug!(repo, digest, error = %e, "dedupe link unavailable; storing a copy");
            false
        }
    }
}

/// Blocking: layout marker + quota admission. Returns bytes charged.
fn layout_and_admit(
    root: &Path,
    repo_rel: &Path,
    quota: &crate::quota::QuotaTracker,
    repo: &str,
    alg_rel: &Path,
    hex: &str,
    size: u64,
) -> Result<u64, StorageError> {
    let marker = OCI_LAYOUT_MARKER.to_string();
    if ensure_layout_beneath_sync(root.to_path_buf(), repo_rel.to_path_buf(), marker)? {
        let repo_dir = root.join(repo_rel);
        let parent = repo_dir.parent().unwrap_or(&repo_dir);
        std::fs::File::open(parent).and_then(|d| d.sync_all())?;
    }
    if !quota.tracks_bytes() {
        return Ok(0);
    }
    if let Some((true, _)) = stat_beneath_sync(root.to_path_buf(), alg_rel.join(hex))? {
        return Ok(0);
    }
    quota.admit(repo, size)?;
    Ok(size)
}

enum ManifestLanded {
    /// Layout or quota refused before anything was written or charged.
    Rejected(StorageError),
    /// Writing the manifest blob failed after `charged` bytes were admitted.
    Failed { charged: u64, error: StorageError },
    /// Stored; `missing` = first required blob not found.
    Stored {
        missing: Option<usize>,
        error: Option<StorageError>,
    },
}

/// Blocking: manifest landing hop (layout, quota, publish, recheck required blobs).
struct ManifestCtx {
    root: std::path::PathBuf,
    repo: String,
    repo_rel: std::path::PathBuf,
    alg_rel: std::path::PathBuf,
    leaf: String,
    digest: String,
    data: Vec<u8>,
    required: Vec<std::path::PathBuf>,
    quota: std::sync::Arc<crate::quota::QuotaTracker>,
    dedupe: std::sync::Arc<crate::DedupeIndex>,
    commit: bool,
}

fn land_manifest(c: ManifestCtx) -> ManifestLanded {
    let size = c.data.len() as u64;
    let charged = match layout_and_admit(
        &c.root,
        &c.repo_rel,
        &c.quota,
        &c.repo,
        &c.alg_rel,
        &c.leaf,
        size,
    ) {
        Ok(charged) => charged,
        Err(e) => return ManifestLanded::Rejected(e),
    };
    let linked = dedupe_link_at(
        &c.root, &c.dedupe, &c.repo, &c.alg_rel, &c.leaf, &c.digest, c.commit,
    );
    if !linked {
        #[cfg(target_os = "linux")]
        let res = publish_bytes_sync(&c.root, &c.alg_rel, &c.leaf, &c.data, true);
        #[cfg(all(unix, not(target_os = "linux")))]
        let res = publish_bytes_rename_sync(&c.root, &c.alg_rel, &c.leaf, &c.data, true);
        if let Err(e) = res {
            return ManifestLanded::Failed {
                charged,
                error: e.into(),
            };
        }
    }
    for (i, rel) in c.required.iter().enumerate() {
        match stat_beneath_sync(c.root.clone(), rel.clone()) {
            Ok(Some((true, _))) => {}
            Ok(_) => {
                return ManifestLanded::Stored {
                    missing: Some(i),
                    error: None,
                }
            }
            Err(e) => {
                return ManifestLanded::Stored {
                    missing: None,
                    error: Some(e.into()),
                }
            }
        }
    }
    ManifestLanded::Stored {
        missing: None,
        error: None,
    }
}

impl FsStorage {
    /// Open a session's staging file for appending (creating for pending sessions).
    async fn prepare_session(&self, repo: &str, id: &str) -> Result<Staging, StorageError> {
        let rel = upload_rel(repo, id)?;
        let create = self.is_pending(repo, id);
        let root = self.root.to_path_buf();
        let staging = run_blocking("upload_prepare", move || prepare_staging(root, rel, create))
            .await
            .map_err(map_not_found)?;
        if create {
            self.take_pending(repo, id);
        }
        Ok(staging)
    }
}
