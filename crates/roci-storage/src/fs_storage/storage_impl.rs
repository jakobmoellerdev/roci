//! The [`Storage`] trait implementation for [`FsStorage`] — the registry's
//! blob/upload/manifest/tag/referrer operations, each anchored beneath the
//! store root.

use super::super::FsStorage;
use super::paths::{blob_dir_rel, blob_rel, repo_rel, upload_dir_rel, upload_rel, SafeComponent};
use crate::beneath::*;
use crate::digest::{digest_of, hash_reader, Digest};
use crate::error::{map_not_found, StorageError};
use crate::layout::*;
use crate::metadata::{MetaOp, MetadataStore, Page, Referrer};
use crate::publish::*;
use crate::storage::{ManifestRef, Storage};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        // Validate the path first (the traversal backstop must run before any
        // short-circuit), then let a definite-absent filter answer skip the
        // stat; a "maybe" falls through to a no-follow stat resolved *beneath*
        // the store root — no symlink at any component (repo, `blobs`, `<alg>`,
        // digest) is followed, so an external file can never be sized as a blob.
        let rel = blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        match stat_beneath(&self.root, &rel).await? {
            Some((true, size)) => Ok(size),
            _ => Err(StorageError::NotFound),
        }
    }

    async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        // Validate the path first (traversal backstop before any short-circuit),
        // then let a definite-absent filter answer skip the stat; a "maybe"
        // falls through to an authoritative no-follow stat resolved beneath the
        // store root. A CAS entry counts as present only if it is a *regular
        // file* reached without traversing any symlink — so neither a planted
        // leaf symlink nor a symlinked parent dir can satisfy a manifest's
        // referenced-blob check and then be served from outside the store.
        let rel = blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Ok(false);
        }
        Ok(matches!(
            stat_beneath(&self.root, &rel).await?,
            Some((true, _))
        ))
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        let digest_str = digest.as_string();
        // Serve small blobs (manifests/configs) from the RAM cache with zero
        // syscalls; a miss falls through to the loose file.
        if let Some(bytes) = self.cache.get(repo, &digest_str) {
            return Ok(bytes.to_vec());
        }
        let rel = blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest_str) {
            return Err(StorageError::NotFound);
        }
        // Read through the same no-follow beneath-root open as open_blob: a
        // planted CAS symlink (leaf or parent) can never redirect a whole-blob
        // read outside the store, even on a cache miss.
        let mut f = open_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).await.map_err(map_not_found)?;
        self.cache.put(repo, &digest_str, &bytes);
        Ok(bytes)
    }

    async fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<tokio::fs::File, StorageError> {
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        // Open beneath the store root, refusing any symlink traversal at every
        // component: a planted `blobs/<alg>/<hex>` leaf — or a symlinked `repo`,
        // `blobs`, or `<alg>` parent — can never stream bytes from outside the CAS.
        let rel = blob_rel(repo, digest)?;
        open_beneath(&self.root, &rel).await.map_err(map_not_found)
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        // A random 128-bit id: unguessable and independent of pid/restart (the
        // old `{pid}-{counter}` scheme collided across restarts). Hex-encoded,
        // so `upload_path`→`safe_component` accepts it unchanged.
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| StorageError::Io(io::Error::other(e)))?;
        let id = hex::encode(buf);
        // Create the staging file anchored to a dirfd walked no-follow beneath
        // the store root (creating `<repo…>/uploads`), so a symlink planted at a
        // repo/`uploads` component cannot redirect the create outside the store
        // the way a path-based `create_dir_all`+`File::create` would.
        let (up_dir, up_leaf) = upload_dir_rel(repo, &id)?;
        create_empty_beneath(&self.root, &up_dir, &up_leaf).await?;
        Ok(id)
    }

    async fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> Result<u64, StorageError> {
        // Serialize with any concurrent append/finish/abort on this session so
        // bytes cannot be appended between a finish's hash-verify and its
        // promote, and so the Content-Range offset check below is atomic with
        // the append (two concurrent PATCHes cannot both pass it).
        let lock = self.session_lock(repo, id)?;
        let _guard = lock.lock().await;
        let rel = upload_rel(repo, id)?;
        let mut f = match open_append_beneath(&self.root, &rel).await {
            Ok(f) => f,
            Err(e) => {
                // No such session: drop the just-created lock entry so a stream
                // of unknown ids cannot leak lock-map entries.
                self.drop_session_lock(repo, id);
                return Err(map_not_found(e));
            }
        };
        // Enforce the Content-Range precondition under the lock: the current
        // committed size must equal the client-declared start offset.
        if let Some(offset) = expected_offset {
            let current = f.metadata().await?.len();
            if current != offset {
                return Err(StorageError::RangeNotSatisfiable {
                    expected: current,
                    got: offset,
                });
            }
        }
        f.write_all(chunk).await?;
        f.flush().await?;
        Ok(f.metadata().await?.len())
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        // Stat the staging file no-follow beneath the store root: a symlinked
        // `uploads`/`<id>` component cannot redirect the size read outside the
        // store. A missing or non-regular entry is NotFound (no such session).
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
        trailing: &[u8],
    ) -> Result<(), StorageError> {
        // Hold the session lock across the trailing append AND the verify+promote
        // so a concurrent PATCH cannot inject bytes between the append and the
        // hash (which would make the digest cover unverified data, or fail a
        // valid completion).
        let lock = self.session_lock(repo, id)?;
        let _guard = lock.lock().await;
        let staging_rel = upload_rel(repo, id)?;
        // Append the monolithic PUT's trailing body (if any) to the staging file
        // under the same lock, no-follow, before hashing.
        if !trailing.is_empty() {
            let mut f = match open_append_beneath(&self.root, &staging_rel).await {
                Ok(f) => f,
                Err(e) => {
                    self.drop_session_lock(repo, id);
                    return Err(map_not_found(e));
                }
            };
            f.write_all(trailing).await?;
            f.flush().await?;
        }
        // Resolve the staging entry beneath the store root with no symlink
        // traversal at any component: a planted `uploads` parent or `uploads/<id>`
        // leaf symlink is not a valid staging file, so it never gets
        // hashed-through and promoted into the CAS.
        let (is_file, staged_size) = match stat_beneath(&self.root, &staging_rel).await? {
            Some(m) => m,
            None => {
                self.drop_session_lock(repo, id);
                return Err(StorageError::NotFound);
            }
        };
        if !is_file {
            let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
            let _ = unlink_beneath(&self.root, &up_dir, &up_leaf).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::BadPath(format!(
                "upload {id} is not a regular file"
            )));
        }
        // Re-check the per-session cap *under the lock*: a PATCH that appended
        // past the cap and was preempted before aborting cannot be promoted by a
        // racing empty-body PUT, because finalize itself rejects an oversized
        // staging file (and drops it) here.
        if staged_size > max_size {
            let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
            let _ = unlink_beneath(&self.root, &up_dir, &up_leaf).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: staged_size,
            });
        }
        // Stream-hash the staging file (no full-blob buffer) through a handle
        // opened *beneath the store root* (no-follow, regular-file-checked), so
        // no parent-symlink swap can redirect the hash input, and verify it
        // matches the client-declared digest before promoting it.
        let staging_fd = open_beneath(&self.root, &staging_rel)
            .await
            .map_err(map_not_found)?;
        // Durability: fsync the staging file's *data* before it is promoted. The
        // trailing append above only `flush`ed to the kernel, and PATCH bodies
        // may sit in page cache; a crash after `rename_beneath` would otherwise
        // leave a named CAS blob with torn/unwritten contents, breaking the
        // atomic-finalize guarantee. Sync on the same fd we hash+promote.
        staging_fd.sync_all().await.map_err(map_not_found)?;
        // Capture the hashed inode's identity so the later name-based
        // `renameat` can prove it is promoting *this* verified inode, not a leaf
        // a hostile local filesystem actor swapped in after the hash.
        let staging_ino = {
            let st = rustix::fs::fstat(&staging_fd).map_err(|e| map_not_found(e.into()))?;
            (st.st_dev as u64, st.st_ino as u64)
        };
        let actual = hash_reader(staging_fd, expected.algorithm())
            .await
            .map_err(map_not_found)?;
        if !actual.ct_eq(expected) {
            // Reject and drop the staging file so a bad upload leaves nothing.
            let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
            let _ = unlink_beneath(&self.root, &up_dir, &up_leaf).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        // Ensure the layout marker exists, then rename the staging file into the
        // CAS via dirfds walked no-follow beneath the store root — atomic on the
        // same filesystem, copy-free, and safe against a symlinked `uploads`,
        // `blobs`, or `<alg>` parent. A crash can never leave a corrupt-but-named
        // blob (a torn write stays under `uploads/` and is discarded).
        self.ensure_layout(repo).await?;
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        let (alg_rel, hex) = blob_dir_rel(repo, expected)?;
        rename_beneath(&self.root, &up_dir, &up_leaf, &alg_rel, &hex, staging_ino)
            .await
            .map_err(map_not_found)?;
        self.drop_session_lock(repo, id);
        // Record presence so future reads skip the stat on a definite miss.
        let digest_str = expected.as_string();
        self.presence.insert(repo, &digest_str);
        // Warm the small-blob cache for a cacheable blob: read it back through
        // the same no-follow beneath-root open (the blob path is the validated
        // `alg_rel/hex` just promoted). A genuine IO hiccup skips the warm.
        let blob_rel = alg_rel.join(&hex);
        self.warm_small_blob_cache(repo, &blob_rel, &digest_str)
            .await;
        Ok(())
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        // Serialize with any concurrent append/finish, then drop the session.
        let lock = self.session_lock(repo, id)?;
        let guard = lock.lock().await;
        // Idempotent: a missing session is `Ok(false)` (nothing removed). Remove
        // via a dirfd walked no-follow beneath the store root so a symlinked
        // `uploads`/`<id>` component cannot redirect the deletion outside the
        // store; a missing entry / symlinked parent maps to NotFound → false.
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        let removed = match unlink_beneath(&self.root, &up_dir, &up_leaf).await {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(StorageError::Io(e)),
        };
        drop(guard);
        self.drop_session_lock(repo, id);
        Ok(removed)
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        // Hash with the *expected* algorithm so sha512 digests are honored, not
        // silently rejected against a sha256 recompute.
        let actual = digest_of(data, digest.algorithm());
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }
        // A repo populated only by blob pushes still gets a valid oci-layout
        // marker so the directory is a well-formed OCI image layout.
        self.ensure_layout(repo).await?;
        // Publish the bytes into the CAS crash-atomically, anchored to a dirfd
        // walked no-follow beneath the store root (dir_beneath creates the
        // `blobs/<alg>` tree): a symlinked parent cannot redirect the write, a
        // partial blob is never namespace-visible (Linux `O_TMPFILE`+`linkat`),
        // and an `EEXIST` at the digest name is dedup only if it is a regular
        // file. Non-Linux / no-`O_TMPFILE` uses a temp+`renameat` in that dirfd.
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        publish_bytes(&self.root, &alg_rel, &leaf, data).await?;
        // Record presence so future reads skip the stat on a definite miss, and
        // warm the small-blob cache (a no-op for large layers).
        let digest_str = digest.as_string();
        self.presence.insert(repo, &digest_str);
        self.cache.put(repo, &digest_str, data);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        // Remove via a dirfd walked no-follow beneath the store root so a
        // symlinked `blobs`/`<alg>` parent cannot redirect the deletion.
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        unlink_beneath(&self.root, &alg_rel, &leaf)
            .await
            .map_err(map_not_found)?;
        let digest_str = digest.as_string();
        self.presence.remove(repo, &digest_str);
        self.cache.invalidate(repo, &digest_str);
        Ok(())
    }

    async fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
    ) -> Result<(), StorageError> {
        // Validate the tag (if any) *before* writing any content so a bad tag
        // cannot leave a manifest blob committed with no index entry.
        if let Some(tag) = tag {
            SafeComponent::new(tag)?;
        }
        // A manifest is a blob addressed by its digest; store it in the CAS
        // (put_blob verifies the digest and ensures the layout marker).
        self.put_blob(repo, digest, data).await?;

        // Record the mutation in the metadata index + durable log (authoritative
        // immediately), then schedule the coalesced index.json rewrite.
        self.apply_meta(
            repo,
            MetaOp::PutManifest {
                repo: repo.to_string(),
                digest: digest.as_string(),
                media_type: media_type.to_string(),
                tag: tag.map(str::to_string),
            },
        )
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        let (digest, media_type) = if reference.contains(':') {
            // By-digest: the digest *is* the reference; recover the media type
            // from the in-RAM index, then the on-disk index, then default.
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
            // By-tag: resolve via the in-RAM tag map; on a miss fall back to the
            // on-disk index.json (the layout is the source of truth).
            match self.meta.resolve_tag(repo, reference) {
                Some((digest_str, media_type)) => (Digest::parse(&digest_str)?, media_type),
                None => self.index_resolve_tag(repo, reference).await?,
            }
        };
        // Manifests are small blobs; serve their bytes from the RAM cache when
        // warm, else read the loose file and warm the cache.
        let digest_str = digest.as_string();
        let bytes = match self.cache.get(repo, &digest_str) {
            Some(cached) => cached.to_vec(),
            None => {
                // Read the manifest blob through a no-follow beneath-root open
                // (regular-file-checked) so a symlinked CAS parent/leaf cannot
                // redirect the read outside the store, even on a cache miss.
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
        // Remove the manifest blob from the CAS via a dirfd walked no-follow
        // beneath the store root (NotFound if absent); a symlinked parent cannot
        // redirect the deletion outside the store.
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        unlink_beneath(&self.root, &alg_rel, &leaf)
            .await
            .map_err(map_not_found)?;
        // Drop the manifest from the presence filter + small-blob cache.
        self.presence.remove(repo, &digest.as_string());
        self.cache.invalidate(repo, &digest.as_string());
        self.apply_meta(
            repo,
            MetaOp::DeleteManifest {
                repo: repo.to_string(),
                digest: digest.as_string(),
            },
        )
    }

    async fn list_tags(
        &self,
        repo: &str,
        last: Option<&str>,
        limit: usize,
    ) -> Result<Page<String>, StorageError> {
        // Fast path: a seek into the in-RAM sorted tag map. A repo the store
        // does not yet cover (e.g. an out-of-band layout mutation after
        // startup) falls back to the on-disk index.json, the source of truth.
        if let Some(page) = self.meta.tags_page(repo, last, limit) {
            return Ok(page);
        }
        let index = self.read_index(repo).await?;
        let mut tags: Vec<String> = index_manifests(&index)
            .iter()
            .filter_map(|e| descriptor_tag(e).map(str::to_string))
            .collect();
        tags.sort();
        tags.dedup();
        Ok(page_sorted(tags, String::as_str, last, limit))
    }

    async fn add_referrer(
        &self,
        repo: &str,
        subject: &Digest,
        referrer: &Digest,
        referrer_descriptor: &[u8],
    ) -> Result<(), StorageError> {
        // Record the subject→referrer link (with richer descriptor fields the
        // core computed: artifactType, annotations) in the metadata store; the
        // write-behind merges it into the referrer's index.json entry. A
        // non-object descriptor is an internal inconsistency → Io.
        // Traversal backstop before any state is recorded (SECURITY inv. 8):
        // the write-behind later builds paths from `repo`.
        repo_rel(repo)?;
        let mut merged: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(referrer_descriptor)
                .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        merged.insert(
            "subject".into(),
            serde_json::json!({ "digest": subject.as_string() }),
        );
        let descriptor = serde_json::to_vec(&merged)
            .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        self.apply_meta(
            repo,
            MetaOp::PutReferrer {
                repo: repo.to_string(),
                subject: subject.as_string(),
                referrer: referrer.as_string(),
                descriptor,
            },
        )
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
        // Fast path: a seek into the in-RAM subject→referrers index.
        if let Some(page) = self
            .meta
            .referrers_page(repo, &target, artifact_type, last, limit)
        {
            return Ok(page);
        }
        // Fallback: scan index.json for any descriptor carrying `subject`.
        let index = self.read_index(repo).await?;
        let linked: Vec<(String, &serde_json::Value)> = index_manifests(&index)
            .iter()
            .filter(|e| subject_digest(e) == Some(target.as_str()))
            .filter_map(|e| Some((descriptor_digest(e)?.to_string(), e)))
            .collect();
        if !linked.is_empty() {
            return Ok(page_layout_referrers(linked, artifact_type, last, limit));
        }
        // Tag-schema fallback (dist-spec §Referrers tag schema): a client that
        // pushed to a registry without the referrers API maintains an image
        // index under the tag `<alg>-<ref>` (ref = hex, truncated to 64). Serve
        // its `manifests`, de-duplicated by digest; anything malformed → empty.
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
        // Only well-formed descriptors: an object whose digest parses under
        // the registry's digest grammar. Anything else is skipped.
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
        // Source absent → the caller falls back to a normal upload session.
        if !self.blob_exists(from_repo, digest).await? {
            return Ok(false);
        }
        // Same-repo mount: source and destination are the same path — already
        // present, nothing to promote (a copy-onto-self would truncate it).
        let (from_alg_rel, leaf) = blob_dir_rel(from_repo, digest)?;
        let (to_alg_rel, _) = blob_dir_rel(to_repo, digest)?;
        if from_alg_rel == to_alg_rel {
            self.presence.insert(to_repo, &digest.as_string());
            return Ok(true);
        }
        self.ensure_layout(to_repo).await?;
        // Promote via dirfds walked no-follow beneath the store root, contract
        // order reflink → hard link → streaming copy (SECURITY.md:124). A
        // pre-existing regular-file destination is idempotent success; a planted
        // symlink/dir parent or destination is rejected (re-validated inside the
        // promotion, closing the check→promote race).
        match mount_promote_beneath(&self.root, &from_alg_rel, &to_alg_rel, &leaf).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StorageError::BadPath(format!(
                    "mount destination for {} is not a regular file",
                    digest.as_string()
                )));
            }
            // A symlinked/non-directory destination parent is refused beneath the
            // root as `NotFound` → 404 (documented), not a raw 500.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StorageError::NotFound),
            Err(e) => return Err(StorageError::Io(e)),
        }
        self.presence.insert(to_repo, &digest.as_string());
        Ok(true)
    }

    async fn record_backrefs(
        &self,
        repo: &str,
        manifest: &Digest,
        blobs: &[Digest],
    ) -> Result<(), StorageError> {
        if blobs.is_empty() {
            return Ok(());
        }
        self.meta
            .apply(MetaOp::PutBackrefs {
                repo: repo.to_string(),
                manifest: manifest.as_string(),
                blobs: blobs.iter().map(Digest::as_string).collect(),
            })
            .map_err(StorageError::Io)
    }

    async fn backrefs(&self, repo: &str, blob: &Digest) -> Result<Vec<String>, StorageError> {
        Ok(self.meta.backrefs(repo, &blob.as_string()))
    }
}
