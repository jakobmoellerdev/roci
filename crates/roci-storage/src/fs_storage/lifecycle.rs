//! Blob lifecycle bookkeeping shared by every path that adds a blob to, or
//! removes one from, a repository's CAS: quota admission, the presence filter,
//! the dedupe index, the scrub checksum record, and GC candidacy. Keeping these
//! in one place is what keeps the derived structures consistent with the CAS.

use super::super::FsStorage;
use crate::beneath::stat_beneath;
use crate::metadata::{BlobChecksum, MetaOp};
use crate::StorageError;
use std::path::Path;

impl FsStorage {
    /// Something is about to depend on `(repo, digest)` — a `HEAD` before a
    /// client skips re-uploading it, the existence check of a manifest push:
    /// refresh its GC stamp under the pin, so a concurrent sweep either
    /// finished before (the blob is gone and the caller sees that) or sees the
    /// fresh stamp and keeps it for another grace period.
    pub(super) async fn want_blob(&self, repo: &str, digest: &str) {
        if let Some(_pin) = self.gc.pin().await {
            self.gc.touch(repo, digest);
        }
    }

    /// Quota admission for `size` bytes about to land at `alg_rel/leaf` in
    /// `repo`. Nothing is charged when a regular file is already there (a
    /// re-upload adds no bytes) or no byte cap is configured. Returns the bytes
    /// charged — hand them back with `quota.release` if the promote fails.
    pub(super) async fn admit_blob(
        &self,
        repo: &str,
        alg_rel: &Path,
        leaf: &str,
        size: u64,
    ) -> Result<u64, StorageError> {
        if !self.quota.tracks_bytes() {
            return Ok(0);
        }
        if let Some((true, _)) = stat_beneath(&self.root, &alg_rel.join(leaf)).await? {
            return Ok(0);
        }
        self.quota.admit(repo, size)?;
        Ok(size)
    }

    /// Bookkeeping after `digest` landed in `repo`'s CAS: presence, dedupe
    /// location, the scrub checksum (a relaxed record — losing it only costs
    /// the scrub a full re-hash), and GC candidacy: a blob no manifest
    /// references yet is stamped a candidate now, so it is collected only if it
    /// stays unreferenced for the whole grace period. Call while holding the
    /// GC pin taken before the promote, so no sweep observes the gap.
    pub(super) fn blob_entered(&self, repo: &str, digest: &str, checksum: Option<BlobChecksum>) {
        self.presence.insert(repo, digest);
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

    /// Bookkeeping after `digest` left `repo`'s CAS (API delete, GC, scrub
    /// quarantine): every derived structure forgets it and its `size` bytes (if
    /// known) are returned to the quota.
    pub(super) fn blob_left(&self, repo: &str, digest: &str, size: Option<u64>) {
        self.presence.remove(repo, digest);
        self.cache.invalidate(repo, digest);
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
}
