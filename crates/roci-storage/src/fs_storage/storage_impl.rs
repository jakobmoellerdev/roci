//! The [`Storage`] trait implementation for [`FsStorage`] — the registry's
//! blob/upload/manifest/tag/referrer operations, each anchored beneath the
//! store root.

use super::super::FsStorage;
use super::paths::{blob_dir_rel, blob_rel, upload_dir_rel, upload_rel, SafeComponent};
use crate::beneath::*;
use crate::digest::{digest_of, hash_std, Digest};
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
        // A blob roci wrote has its size recorded in lockstep with the CAS
        // (invariant 15): answer from RAM, no syscall. This is advisory for the
        // manifest push, which re-checks every referenced blob authoritatively
        // (no-follow stat) under the GC fence inside `put_manifest` — so a blob
        // swapped for a symlink since is still rejected (MissingReference).
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
        // The filesystem work runs as three blocking-pool hops (prepare, body,
        // land) instead of one per syscall: each hop costs a queue + two
        // thread wake-ups, far more than a cached stat/open itself.
        //
        // Hop 1 — resolve the staging entry beneath the store root with no
        // symlink traversal at any component (a planted `uploads` parent or
        // `uploads/<id>` symlink is not a valid staging file, so it is never
        // hashed-through and promoted), open it for the trailing append, and
        // capture its size and inode.
        let prepared = {
            let (root, rel) = (self.root.to_path_buf(), staging_rel.clone());
            run_blocking("finish_prepare", move || prepare_staging(root, rel))
                .await
                .map_err(map_not_found)?
        };
        let (file, current, staging_ino) = match prepared {
            Staging::Ready { file, len, ino } => (file, len, ino),
            Staging::Missing => {
                self.drop_session_lock(repo, id);
                return Err(StorageError::NotFound);
            }
            Staging::NotRegular => {
                self.discard_session(repo, id).await?;
                return Err(StorageError::BadPath(format!(
                    "upload {id} is not a regular file"
                )));
            }
        };
        // Hop 2 (per 1 MiB batch) — stream the monolithic PUT's trailing body
        // onto the staging file under the same lock, before hashing.
        let seed = guard
            .take()
            .or_else(|| (current == 0).then(StagedHash::new));
        let (staged_size, hashed) = append_body(
            tokio::fs::File::from_std(file),
            current,
            trailing,
            limit,
            seed,
        )
        .await?;
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
        // Hash-on-write covered every staged byte (sha256) through the handle
        // opened in hop 1, so the verified inode is `staging_ino`. Otherwise —
        // a session from before a restart, or sha512 — re-hash in one pass; and
        // `storage.commit` syncs the staged data before it is promoted (a crash
        // after the rename must not leave a named blob with torn contents).
        let covered = hashed.filter(|h| h.len() == staged_size && expected.algorithm() == "sha256");
        let (actual, crc32c, staging_ino) = match covered {
            Some(h) if !self.config.commit => {
                let (d, crc) = h.finish();
                (d, crc, staging_ino)
            }
            covered => {
                let (root, rel) = (self.root.to_path_buf(), staging_rel.clone());
                let alg = expected.algorithm().to_string();
                let commit = self.config.commit;
                run_blocking("finish_verify", move || {
                    use rustix::fs::OFlags;
                    let f = resolve_beneath(&root, &rel, OFlags::RDONLY)?;
                    if commit {
                        f.sync_data()?;
                    }
                    let st = rustix::fs::fstat(&f)?;
                    let ino = (st.st_dev as u64, st.st_ino as u64);
                    let (d, crc) = match covered {
                        Some(h) => h.finish(),
                        None => hash_std(f, &alg)?,
                    };
                    Ok((d, crc, ino))
                })
                .await
                .map_err(map_not_found)?
            }
        };
        if !actual.ct_eq(expected) {
            // Reject and drop the staging file so a bad upload leaves nothing.
            self.discard_session(repo, id).await?;
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        let (up_dir, up_leaf) = upload_dir_rel(repo, id)?;
        let (alg_rel, hex) = blob_dir_rel(repo, expected)?;
        let repo_rel = super::paths::repo_rel(repo)?;
        let digest_str = expected.as_string();
        // Serialize admission + publication per (repo, digest) so concurrent
        // uploads of the same absent blob cannot both charge quota, and hold the
        // GC pin from before the blob lands until it is stamped, so a sweep
        // never sees it half-registered.
        let admit_lock = self.blob_admit_lock(repo, &digest_str);
        let _admit_guard = admit_lock.lock().await;
        let pin = self.gc.pin().await;
        // Hop 3 — ensure the layout marker, charge quota, then land the
        // verified blob: dedupe-link an identical blob another repo already
        // stores (reflink → hard link; the staged copy is dropped), otherwise
        // rename the staging file in place — atomic on one filesystem,
        // copy-free, and safe against a symlinked `uploads`, `blobs` or `<alg>`
        // parent (a crash never leaves a corrupt-but-named blob). A small blob
        // is read back for the cache in the same hop.
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
            };
            run_blocking("finish_land", move || Ok(land_blob(ctx))).await?
        };
        let (charged, warm) = match landed {
            Landed::Done { charged, warm } => (charged, warm),
            Landed::Rejected(e) => {
                // Over quota: the session can never complete, so drop it.
                drop(pin);
                drop(_admit_guard);
                self.drop_blob_admit_lock(repo, &digest_str);
                self.discard_session(repo, id).await?;
                return Err(e);
            }
            Landed::Failed { charged, error } => {
                drop(pin);
                self.quota.release(repo, charged);
                drop(_admit_guard);
                self.drop_blob_admit_lock(repo, &digest_str);
                return Err(error);
            }
        };
        let _ = charged;
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
        if let Some(bytes) = warm {
            self.cache.put(repo, &digest_str, &bytes);
        }
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
        let (alg_rel, leaf) = blob_dir_rel(repo, digest)?;
        let digest_str = digest.as_string();
        let required = links
            .required
            .iter()
            .map(|r| blob_rel(repo, r))
            .collect::<Result<Vec<_>, _>>()?;
        // Hold the GC pin from before the blob lands through the metadata
        // commit and GC clears — no sweep can see it half-registered or
        // delete a referenced blob between the publish and PutManifest.
        let pin = self.gc.pin().await;
        // One blocking hop: layout marker, quota admission, dedupe link or
        // crash-atomic publish of the manifest blob, then — under the same
        // fence — the authoritative re-check that every `required` digest
        // (config + layers the core already checked) is still a regular file.
        // A sweep that ran before this pin cannot have deleted them (the pin
        // blocks), and one that starts after will see them referenced.
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

/// Absolute ceiling for a small-blob cache warm read (never derived from
/// config alone, so the read-back buffer is bounded by a constant).
const WARM_CAP: usize = 8 * 1024 * 1024;

/// The staging file of an upload session, as resolved by `finish_upload`.
enum Staging {
    Missing,
    NotRegular,
    Ready {
        file: std::fs::File,
        len: u64,
        ino: (u64, u64),
    },
}

/// Blocking: resolve the staging file beneath `root` (no symlink at any
/// component), require a regular file, and open it for appending.
fn prepare_staging(root: std::path::PathBuf, rel: std::path::PathBuf) -> io::Result<Staging> {
    use rustix::fs::OFlags;
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

/// Everything the landing hop needs, owned so it can move to the blocking pool.
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
}

enum Landed {
    /// Landed; `charged` quota bytes, and the bytes to warm the cache with.
    Done { charged: u64, warm: Option<Vec<u8>> },
    /// Admission refused (quota): nothing was charged.
    Rejected(StorageError),
    /// A filesystem step failed after `charged` bytes were admitted.
    Failed { charged: u64, error: StorageError },
}

/// Blocking: the landing half of `finish_upload` in one hop.
fn land_blob(c: LandCtx) -> Landed {
    use std::io::Read;
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
    // Optional small-blob cache warm: read back (no-follow, beneath-root) at
    // most limit+1 bytes; an IO hiccup or an over-limit blob skips it.
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
    Landed::Done { charged, warm }
}

/// Blocking twin of `FsStorage::dedupe_link` for the landing hops.
fn dedupe_link_sync(c: &LandCtx) -> bool {
    dedupe_link_at(
        &c.root, &c.dedupe, &c.repo, &c.alg_rel, &c.hex, &c.digest, c.commit,
    )
}

/// Link `digest` into `repo` (at `alg_rel/hex`) from another repo that already
/// stores it (reflink → hard link); `false` when there is none or it cannot be
/// linked, so the caller stores its own copy.
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

/// Blocking: ensure the repo's layout marker (persisting a newly created repo
/// entry) and admit `size` bytes against quota — nothing is charged when the
/// blob is already present. Returns the bytes charged.
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

/// Outcome of the manifest landing hop.
enum ManifestLanded {
    /// Layout or quota refused before anything was written or charged.
    Rejected(StorageError),
    /// Writing the manifest blob failed after `charged` bytes were admitted.
    Failed { charged: u64, error: StorageError },
    /// The manifest blob is stored; `missing` indexes the first `required`
    /// blob that is not (or no longer) a regular file in the repo, and
    /// `error` is a genuine IO error from that re-check.
    Stored {
        missing: Option<usize>,
        error: Option<StorageError>,
    },
}

/// Blocking: the filesystem half of `put_manifest` in one hop — layout marker,
/// quota admission, dedupe link or crash-atomic publish of the manifest blob
/// (always synced: a committed WAL record must never name a torn manifest),
/// then the authoritative no-follow re-check of every `required` blob.
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
        if let Err(e) = publish_bytes_sync(&c.root, &c.alg_rel, &c.leaf, &c.data, true) {
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
