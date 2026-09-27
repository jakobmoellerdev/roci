//! Blob lifecycle bookkeeping for the filesystem backend.

use super::super::FsStorage;
use crate::beneath::stat_beneath;
use crate::lifecycle::{note_blob_entered, note_blob_left};
use crate::metadata::BlobChecksum;
use crate::StorageError;
use std::path::Path;

impl FsStorage {
    /// Refresh GC stamp so a concurrent sweep keeps this blob alive.
    pub(super) async fn want_blob(&self, repo: &str, digest: &str) {
        if let Some(_pin) = self.gc.pin().await {
            self.gc.touch(repo, digest);
        }
    }

    /// Admit `size` bytes for `alg_rel/leaf`; nothing charged if already present.
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

    /// Bookkeeping after `digest` landed in `repo`.
    pub(super) fn blob_entered(&self, repo: &str, digest: &str, checksum: Option<BlobChecksum>) {
        self.presence.insert(repo, digest);
        note_blob_entered(&*self.meta, &self.gc, &self.dedupe, repo, digest, checksum);
    }

    /// Bookkeeping after `digest` left `repo`.
    pub(super) fn blob_left(&self, repo: &str, digest: &str, size: Option<u64>) {
        self.presence.remove(repo, digest);
        self.cache.invalidate(repo, digest);
        note_blob_left(
            &*self.meta,
            &self.gc,
            &self.dedupe,
            &self.quota,
            repo,
            digest,
            size,
        );
    }
}
