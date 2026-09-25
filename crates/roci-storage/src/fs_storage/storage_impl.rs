//! The [`Storage`] trait implementation for [`FsStorage`] — the registry's
//! blob/upload/manifest/tag/referrer operations, each anchored beneath the
//! store root.

use super::super::FsStorage;
use super::paths::{blob_dir_rel, blob_rel, upload_dir_rel, upload_rel, SafeComponent};
use crate::beneath::*;
use crate::digest::{digest_of, hash_reader, Digest};
use crate::error::{map_not_found, StorageError};
use crate::layout::*;
use crate::metadata::{BlobChecksum, MetaOp, Page, Referrer};
use crate::publish::*;
use crate::storage::{BlobRead, ManifestLinks, ManifestRef, Storage};
use crate::upload_body::{append_body, StagedHash, UploadBody};
use std::io;
use std::path::Path;
use tokio::io::AsyncReadExt;

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        // Validate the path first (the traversal backstop must run before any
        // short-circuit), then let a definite-absent filter answer skip the
        // stat; a "maybe" falls through to a no-follow stat resolved *beneath*
        // the store root — no symlink at any component (repo, `blobs`, `<alg>`,
        // digest) is followed, so an external file can never be sized as a blob.
        let rel = blob_rel(repo, digest)?;
        let digest_str = digest.as_string();
        if !self.presence.maybe_present(repo, &digest_str) {
            return Err(StorageError::NotFound);
        }
        // A HEAD usually precedes a push that skips this layer: keep it alive.
        self.want_blob(repo, &digest_str).await;
        // Every blob roci wrote has its size recorded with its checksum (kept in
        // lockstep with the CAS by the lifecycle hooks, invariant 15): answer
        // HEAD from RAM with no syscall or blocking-pool hop (invariant 14).
        // Blobs only found on disk (an imported layout) fall back to a stat.
        if let Some(recorded) = self.meta.checksum(repo, &digest_str) {
            return Ok(recorded.size);
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
        let digest_str = digest.as_string();
        if !self.presence.maybe_present(repo, &digest_str) {
            return Ok(false);
        }
        // The manifest push checking this blob is about to reference it.
        self.want_blob(repo, &digest_str).await;
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

    async fn open_blob(&self, repo: &str, digest: &Digest) -> Result<BlobRead, StorageError> {
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        // Open beneath the store root, refusing any symlink traversal at every
        // component: a planted `blobs/<alg>/<hex>` leaf — or a symlinked `repo`,
        // `blobs`, or `<alg>` parent — can never stream bytes from outside the CAS.
        let rel = blob_rel(repo, digest)?;
        let f = open_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
        let size = f.metadata().await.map_err(map_not_found)?.len();
        Ok(BlobRead::file(f, size))
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
        // The concurrent-session cap is checked before anything is created.
        self.quota.begin_session()?;
        if let Err(e) = create_empty_beneath(&self.root, &up_dir, &up_leaf).await {
            self.quota.end_session();
            return Err(e.into());
        }
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
        // Serialize with any concurrent append/finish/abort on this session so
        // bytes cannot be appended between a finish's hash-verify and its
        // promote, and so the Content-Range offset check below is atomic with
        // the append (two concurrent PATCHes cannot both pass it). The guard
        // also carries the session's hash-on-write state.
        let lock = self.session_lock(repo, id)?;
        let mut hash = lock.lock().await;
        let rel = upload_rel(repo, id)?;
        let f = match open_append_beneath(&self.root, &rel).await {
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
        let current = f.metadata().await?.len();
        if let Some(offset) = expected_offset.filter(|&o| o != current) {
            return Err(StorageError::RangeNotSatisfiable {
                expected: current,
                got: offset,
            });
        }
        let seed = hash.take().or_else(|| (current == 0).then(StagedHash::new));
        let (total, extended) = append_body(f, current, body, limit, seed).await?;
        *hash = extended;
        Ok(total)
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
        trailing: UploadBody,
        limit: u64,
    ) -> Result<(), StorageError> {
        // Hold the session lock across the trailing append AND the verify+promote
        // so a concurrent PATCH cannot inject bytes between the append and the
        // hash (which would make the digest cover unverified data, or fail a
        // valid completion).
        let lock = self.session_lock(repo, id)?;
        let mut guard = lock.lock().await;
        let staging_rel = upload_rel(repo, id)?;
        // Resolve the staging entry beneath the store root with no symlink
        // traversal at any component: a planted `uploads` parent or `uploads/<id>`
        // leaf symlink is not a valid staging file, so it never gets
        // hashed-through and promoted into the CAS.
        let is_file = match stat_beneath(&self.root, &staging_rel).await? {
            Some((is_file, _)) => is_file,
            None => {
                self.drop_session_lock(repo, id);
                return Err(StorageError::NotFound);
            }
        };
        if !is_file {
            self.discard_session(repo, id).await?;
            return Err(StorageError::BadPath(format!(
                "upload {id} is not a regular file"
            )));
        }
        // Stream the monolithic PUT's trailing body (if any) onto the staging
        // file under the same lock, no-follow, before hashing.
        let f = open_append_beneath(&self.root, &staging_rel)
            .await
            .map_err(map_not_found)?;
        let current = f.metadata().await?.len();
        let seed = guard
            .take()
            .or_else(|| (current == 0).then(StagedHash::new));
        let (staged_size, hashed) = append_body(f, current, trailing, limit, seed).await?;
        // Re-check the per-session cap *under the lock*: a PATCH that appended
        // past the cap and was preempted before aborting cannot be promoted by a
        // racing empty-body PUT, because finalize itself rejects an oversized
        // staging file (and drops it) here.
        if staged_size > max_size {
            self.discard_session(repo, id).await?;
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
        // Durability (`storage.commit`): fsync the staging file's *data* before
        // it is promoted. The trailing append above only `flush`ed to the
        // kernel, and PATCH bodies may sit in page cache; a crash after
        // `rename_beneath` would otherwise leave a named CAS blob with
        // torn/unwritten contents. Sync on the same fd we hash+promote.
        if self.config.commit {
            staging_fd.sync_data().await.map_err(map_not_found)?;
        }
        // Capture the hashed inode's identity so the later name-based
        // `renameat` can prove it is promoting *this* verified inode, not a leaf
        // a hostile local filesystem actor swapped in after the hash.
        let staging_ino = {
            let st = rustix::fs::fstat(&staging_fd).map_err(|e| map_not_found(e.into()))?;
            (st.st_dev as u64, st.st_ino as u64)
        };
        // Hash-on-write covered every staged byte (sha256): no re-read. Else —
        // a session from before a restart, or sha512 — one pass over the file
        // yields both the digest to verify and the scrub's CRC32C.
        let (actual, crc32c) =
            match hashed.filter(|h| h.len() == staged_size && expected.algorithm() == "sha256") {
                Some(h) => h.finish(),
                None => hash_reader(staging_fd, expected.algorithm())
                    .await
                    .map_err(map_not_found)?,
            };
        if !actual.ct_eq(expected) {
            // Reject and drop the staging file so a bad upload leaves nothing.
            self.discard_session(repo, id).await?;
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        // Ensure the layout marker exists, then land the verified blob in the
        // CAS via dirfds walked no-follow beneath the store root.
        self.ensure_layout(repo).await?;
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        let (alg_rel, hex) = blob_dir_rel(repo, expected)?;
        let digest_str = expected.as_string();
        // Serialize admission + publication per (repo, digest) so concurrent
        // uploads of the same absent blob cannot both charge quota.
        let admit_lock = self.blob_admit_lock(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;
        let charged = match self.admit_blob(repo, &alg_rel, &hex, staged_size).await {
            Ok(c) => c,
            Err(e) => {
                // Over quota: the session can never complete, so drop it.
                drop(_admit_guard);
                self.drop_blob_admit_lock(repo, &digest_str);
                self.discard_session(repo, id).await?;
                return Err(e);
            }
        };
        // Hold the GC pin from before the blob lands until it is stamped, so a
        // sweep never sees it half-registered.
        let pin = self.gc.pin().await;
        // Dedupe: an identical blob already stored in another repo is linked
        // (reflink → hard link) and the staged copy dropped. Otherwise — or if
        // linking is impossible (cross-device) — rename the staging file in
        // place: atomic on the same filesystem, copy-free, and safe against a
        // symlinked `uploads`, `blobs`, or `<alg>` parent. A crash can never
        // leave a corrupt-but-named blob (a torn write stays under `uploads/`).
        let linked = self.dedupe_link(repo, &alg_rel, &hex, &digest_str).await;
        let landed = if linked {
            unlink_beneath(&self.root, &up_dir, &up_leaf)
                .await
                .map_err(map_not_found)
        } else {
            rename_beneath(
                &self.root,
                &up_dir,
                &up_leaf,
                &alg_rel,
                &hex,
                staging_ino,
                self.config.commit,
            )
            .await
            .map_err(map_not_found)
        };
        if let Err(e) = landed {
            drop(pin);
            self.quota.release(repo, charged);
            drop(_admit_guard);
            self.drop_blob_admit_lock(repo, &digest_str);
            return Err(e);
        }
        self.quota.end_session();
        self.drop_session_lock(repo, id);
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
        self.drop_blob_admit_lock(repo, &digest_str);
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
        if removed {
            self.quota.end_session();
        }
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
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let digest_str = digest.as_string();
        // Serialize admission + publication per (repo, digest) so concurrent
        // uploads of the same absent blob cannot both charge quota.
        let admit_lock = self.blob_admit_lock(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;
        let charged = self
            .admit_blob(repo, &alg_rel, &leaf, data.len() as u64)
            .await?;
        let pin = self.gc.pin().await;
        // Dedupe-link an identical blob another repo holds; otherwise publish
        // the bytes into the CAS crash-atomically, anchored to a dirfd walked
        // no-follow beneath the store root (dir_beneath creates the
        // `blobs/<alg>` tree): a symlinked parent cannot redirect the write, a
        // partial blob is never namespace-visible (Linux `O_TMPFILE`+`linkat`),
        // and an `EEXIST` at the digest name is dedup only if it is a regular
        // file. Non-Linux / no-`O_TMPFILE` uses a temp+`renameat` in that dirfd.
        if !self.dedupe_link(repo, &alg_rel, &leaf, &digest_str).await {
            if let Err(e) =
                publish_bytes(&self.root, &alg_rel, &leaf, data, self.config.commit).await
            {
                drop(pin);
                self.quota.release(repo, charged);
                drop(_admit_guard);
                self.drop_blob_admit_lock(repo, &digest_str);
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
        self.drop_blob_admit_lock(repo, &digest_str);
        // Warm the small-blob cache (a no-op for large layers).
        self.cache.put(repo, &digest_str, data);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        // Remove via a dirfd walked no-follow beneath the store root so a
        // symlinked `blobs`/`<alg>` parent cannot redirect the deletion.
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
        // Validate the tag (if any) and build the referrer descriptor *before*
        // writing any content, so a bad tag or descriptor cannot leave a
        // manifest blob committed with no index entry.
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
        // ── Publish the manifest blob under a GC fence held continuously
        // from here through the MetaOp::PutManifest apply and the GC clears.
        // The fence is the backend's shared RwLock read guard (`gc.pin()`);
        // do NOT re-acquire it (a waiting writer deadlocks). ──
        //
        // Verify digest.
        let actual = digest_of(data, digest.algorithm());
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }
        self.ensure_layout(repo).await?;
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let charged = self
            .admit_blob(repo, &alg_rel, &leaf, data.len() as u64)
            .await?;
        let digest_str = digest.as_string();

        // Hold the GC pin from before the blob lands through the metadata
        // commit and GC clears — no sweep can see it half-registered or
        // delete a referenced blob between put_blob and PutManifest.
        let pin = self.gc.pin().await;
        if !self.dedupe_link(repo, &alg_rel, &leaf, &digest_str).await {
            if let Err(e) = publish_bytes(&self.root, &alg_rel, &leaf, data, true).await {
                drop(pin);
                self.quota.release(repo, charged);
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
        self.cache.put(repo, &digest_str, data);

        // Under the same fence, re-verify every `required` digest (config +
        // layers the core already checked) is still present. A sweep that ran
        // before this pin cannot have deleted them (the pin blocks), and one
        // that starts after will see them referenced. This closes the gap
        // between the core's blob_exists check and the metadata commit.
        for req in links.required {
            let req_rel = blob_rel(repo, req)?;
            match stat_beneath(&self.root, &req_rel).await? {
                Some((true, _)) => {} // present as regular file
                _ => {
                    drop(pin);
                    return Err(StorageError::MissingReference(req.as_string()));
                }
            }
        }

        // Manifest, tag, backref edges and referrer land in ONE metadata record
        // (authoritative immediately), then the coalesced index.json rewrite is
        // scheduled. A crash can never keep the manifest but lose its edges.
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
        // The manifest is a GC root, and everything it references is live.
        self.gc.clear(repo, &digest_str);
        for r in &references {
            self.gc.clear(repo, r);
        }
        drop(pin);
        Ok(())
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
        // Read what the manifest references before it goes: those objects may
        // become unreferenced and so GC candidates. A missing manifest is
        // NotFound; an unparseable one simply references nothing.
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
        // Remove the manifest blob from the CAS via a dirfd walked no-follow
        // beneath the store root (NotFound if absent); a symlinked parent cannot
        // redirect the deletion outside the store.
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
        // Every stored object whose last referencing manifest this was is now
        // garbage-in-waiting: collected once its grace period passes untouched.
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
        let size = match self.blob_size(from_repo, digest).await {
            Ok(size) => size,
            Err(StorageError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        let digest_str = digest.as_string();
        // Same-repo mount: source and destination are the same path — already
        // present, nothing to promote (a copy-onto-self would truncate it).
        let (from_alg_rel, leaf) = blob_dir_rel(from_repo, digest)?;
        let (to_alg_rel, _) = blob_dir_rel(to_repo, digest)?;
        if from_alg_rel == to_alg_rel {
            self.presence.insert(to_repo, &digest_str);
            return Ok(true);
        }
        self.ensure_layout(to_repo).await?;
        // Admission and promotion are one critical section per destination
        // blob, so a concurrent duplicate sees the promoted file (no charge).
        let admit_lock = self.blob_admit_lock(to_repo, &digest_str);
        let _admitting = admit_lock.lock().await;
        let charged = match self.admit_blob(to_repo, &to_alg_rel, &leaf, size).await {
            Ok(c) => c,
            Err(e) => {
                self.drop_blob_admit_lock(to_repo, &digest_str);
                return Err(e);
            }
        };
        let pin = self.gc.pin().await;
        // Promote via dirfds walked no-follow beneath the store root, contract
        // order reflink → hard link → streaming copy (SECURITY.md:124). A
        // pre-existing regular-file destination is idempotent success; a planted
        // symlink/dir parent or destination is rejected (re-validated inside the
        // promotion, closing the check→promote race).
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
                self.drop_blob_admit_lock(to_repo, &digest_str);
                return Err(match e.kind() {
                    io::ErrorKind::AlreadyExists => StorageError::BadPath(format!(
                        "mount destination for {digest_str} is not a regular file"
                    )),
                    // A symlinked/non-directory destination parent is refused
                    // beneath the root as `NotFound` → 404 (documented), not 500.
                    io::ErrorKind::NotFound => StorageError::NotFound,
                    _ => StorageError::Io(e),
                });
            }
        };
        record_promotion("mount", how, to_repo, &digest_str);
        let checksum = self.meta.checksum(from_repo, &digest_str);
        self.blob_entered(to_repo, &digest_str, checksum);
        drop(pin);
        self.drop_blob_admit_lock(to_repo, &digest_str);
        Ok(true)
    }
}

/// Log + count how a cross-repo promotion materialized: the hard-link and
/// copy fallbacks are logged so an operator sees reflink is unavailable.
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

/// The stored referrer descriptor: the core-computed descriptor (artifactType,
/// annotations, …) with the `subject` link merged in. A non-object descriptor
/// is an internal inconsistency → `Io`.
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

impl FsStorage {
    /// Dedupe: when another repo holds `digest`, link its copy into
    /// `alg_rel/leaf` (reflink → hard link; never a byte copy — the caller
    /// already holds the bytes). `true` when the destination now holds the
    /// blob; `false` sends the caller down its normal write path.
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
                // The located copy vanished or cannot be linked (other device):
                // forget a stale location and keep the caller's own copy.
                if e.kind() == io::ErrorKind::NotFound {
                    self.dedupe.remove(&src_repo, digest);
                }
                tracing::debug!(repo, digest, error = %e, "dedupe link unavailable; storing a copy");
                false
            }
        }
    }

    /// The blob size to hand back to the quota when it is removed; only
    /// stat'ed when byte quotas are tracked.
    async fn size_for_release(&self, rel: &Path) -> Option<u64> {
        if !self.quota.tracks_bytes() {
            return None;
        }
        match stat_beneath(&self.root, rel).await {
            Ok(Some((true, size))) => Some(size),
            _ => None,
        }
    }

    /// Drop an upload session that can never complete: its staging file (if
    /// still there), its session count, and its lock entry.
    async fn discard_session(&self, repo: &str, id: &str) -> Result<(), StorageError> {
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        if unlink_beneath(&self.root, &up_dir, &up_leaf).await.is_ok() {
            self.quota.end_session();
        }
        self.drop_session_lock(repo, id);
        Ok(())
    }
}
