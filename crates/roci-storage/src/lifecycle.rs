//! Shared blob lifecycle bookkeeping.

use crate::dedupe::DedupeIndex;
use crate::gc::GcTracker;
use crate::metadata::{BlobChecksum, MetaOp, MetadataStore};
use crate::quota::QuotaTracker;

/// Bookkeeping after `digest` landed in `repo`'s CAS.
pub fn note_blob_entered(
    meta: &dyn MetadataStore,
    gc: &GcTracker,
    dedupe: &DedupeIndex,
    repo: &str,
    digest: &str,
    checksum: Option<BlobChecksum>,
) {
    dedupe.insert(repo, digest);
    if let Some(c) = checksum {
        if meta.checksum(repo, digest) != Some(c) {
            if let Err(e) = meta.apply_relaxed(MetaOp::PutChecksum {
                repo: repo.to_string(),
                digest: digest.to_string(),
                crc32c: c.crc32c,
                size: c.size,
            }) {
                tracing::warn!(repo, digest, error = %e, "recording blob checksum failed");
            }
        }
    }
    if meta.backrefs(repo, digest).is_empty() && meta.manifest_media_type(repo, digest).is_none() {
        gc.mark(repo, digest);
    }
}

/// Bookkeeping after `digest` left `repo`'s CAS.
pub fn note_blob_left(
    meta: &dyn MetadataStore,
    gc: &GcTracker,
    dedupe: &DedupeIndex,
    quota: &QuotaTracker,
    repo: &str,
    digest: &str,
    size: Option<u64>,
) {
    dedupe.remove(repo, digest);
    gc.clear(repo, digest);
    if let Some(size) = size {
        quota.release(repo, size);
    }
    if meta.checksum(repo, digest).is_some() {
        if let Err(e) = meta.apply_relaxed(MetaOp::DeleteBlob {
            repo: repo.to_string(),
            digest: digest.to_string(),
        }) {
            tracing::warn!(repo, digest, error = %e, "recording blob removal failed");
        }
    }
}
