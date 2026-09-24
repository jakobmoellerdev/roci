//! The registry storage contract (`Storage` trait) and its resolved-reference type.

use crate::metadata::{Page, Referrer};
use crate::{Digest, StorageError};
use std::future::Future;

/// A resolved reference target: either a tag pointing at a manifest digest, or
/// a direct manifest digest.
#[derive(Debug, Clone)]
pub struct ManifestRef {
    pub digest: Digest,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// The registry storage contract. AuthN/AuthZ is enforced *before* any call
/// into this trait (ARCHITECTURE.md invariant 3).
pub trait Storage: Send + Sync + 'static {
    /// Whether a blob exists, returning its size.
    fn blob_size(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Whether a blob is present in the CAS. A dedicated presence check the
    /// manifest push path uses to enforce referenced-blob existence; cheaper
    /// than [`Storage::blob_size`] for the common absent case (the presence
    /// filter answers a definite miss without a `stat`).
    fn blob_exists(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Read a whole blob (used by manifests; large blobs stream via [`Storage::open_blob`]).
    fn read_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<Vec<u8>, StorageError>> + Send;
    /// Open a blob file for streaming.
    fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<tokio::fs::File, StorageError>> + Send;
    /// Begin a chunked upload session, returning its id.
    fn begin_upload(&self, repo: &str)
        -> impl Future<Output = Result<String, StorageError>> + Send;
    /// Append bytes to an upload session, returning the new total size. When
    /// `expected_offset` is `Some(n)`, the current committed size MUST equal
    /// `n` (a `Content-Range` precondition checked *inside* the session lock so
    /// two concurrent PATCHes cannot both pass an out-of-lock check) — a
    /// mismatch yields [`StorageError::RangeNotSatisfiable`].
    fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Current size of an in-progress upload.
    fn upload_size(
        &self,
        repo: &str,
        id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Abort an in-progress upload session, discarding its staging file.
    /// Idempotent: returns `Ok(true)` if a session was removed, `Ok(false)` if
    /// none existed.
    fn abort_upload(
        &self,
        repo: &str,
        id: &str,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Mount a blob from `from_repo` into `to_repo` without re-uploading it
    /// (dist-spec end-11 cross-repository blob mount). Returns `Ok(true)` when
    /// the blob was present in `from_repo` and is now linked into `to_repo`;
    /// `Ok(false)` when the source blob is absent (the caller falls back to a
    /// normal upload session). Promotion is a filesystem hard-link with a copy
    /// fallback — no blob bytes pass through memory.
    fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Finalize an upload: under the session lock, append `trailing` (a
    /// monolithic PUT's body, empty for a plain finalize) atomically with the
    /// verify+promote so a concurrent PATCH cannot inject bytes between the
    /// trailing append and the finalize hash; verify it hashes to `expected` and
    /// does not exceed `max_size` bytes (the per-session cap, re-checked here
    /// under the lock so a promote cannot race the cap); then move it into the CAS.
    fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
        max_size: u64,
        trailing: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Store a blob given its bytes (verifies digest), used by monolithic/mount paths.
    fn put_blob(
        &self,
        repo: &str,
        digest: &Digest,
        data: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Delete a blob.
    fn delete_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Store a manifest by digest and (optionally) associate a tag.
    fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Resolve a manifest by tag or digest reference.
    fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> impl Future<Output = Result<ManifestRef, StorageError>> + Send;
    /// Delete a manifest by digest.
    fn delete_manifest(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// One page of `repo`'s tags in lexical order: at most `limit` tags
    /// strictly after `last` (from the start when `None`, whether or not
    /// `last` itself still exists). Per-request work is bounded by the page,
    /// not the repo (SECURITY inv. 14).
    fn list_tags(
        &self,
        repo: &str,
        last: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Page<String>, StorageError>> + Send;
    /// Record a referrer: `subject` is the digest a manifest points at via its
    /// `subject` field; `referrer_descriptor` is the JSON descriptor of the
    /// referring manifest to include in the subject's referrers index.
    fn add_referrer(
        &self,
        repo: &str,
        subject: &Digest,
        referrer: &Digest,
        referrer_descriptor: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// One page of the referrers recorded for `subject` as
    /// `(referrer_digest, descriptor_json)`, ordered by referrer digest: at
    /// most `limit` entries strictly after `last`, restricted to descriptors
    /// whose `artifactType` equals `artifact_type` when given. Per-request work
    /// is bounded by the page, not the subject's referrer set.
    fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Page<Referrer>, StorageError>> + Send;
    /// Record the reverse edges `blob_digest → manifest_digest` for every blob
    /// a manifest references (its config + layers), so a future GC can reclaim
    /// a blob the moment its last referencing manifest is deleted. Called by
    /// the core after a successful [`Storage::put_manifest`]; the delete side
    /// is handled inside [`Storage::delete_manifest`].
    fn record_backrefs(
        &self,
        repo: &str,
        manifest: &Digest,
        blobs: &[Digest],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// The manifest digests currently known to reference `blob` in `repo`.
    fn backrefs(
        &self,
        repo: &str,
        blob: &Digest,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
}
