//! The registry storage contract (`Storage` trait) and its value types: the
//! resolved-reference [`ManifestRef`], the backend-agnostic [`BlobRead`], and
//! the atomically-committed [`ManifestLinks`].

use crate::metadata::{Page, Referrer};
use crate::upload_body::UploadBody;
use crate::{Digest, StorageError};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use futures::StreamExt;
use std::future::Future;
use std::io;

/// Bytes read per blocking-pool hop when streaming a local blob. Each hop is a
/// thread hand-off costing tens of µs, so `ReaderStream`'s 4 KiB default made
/// pulls hop-bound; 256 KiB amortizes it while bounding per-stream memory to
/// two chunks (the one being sent + one read ahead).
const FILE_CHUNK: u64 = 256 * 1024;

/// Recycled full-size read chunks: at most 64 idle (16 MiB).
static READ_POOL: crate::bufpool::BufPool = crate::bufpool::BufPool::new(FILE_CHUNK as usize, 64);

type ChunkRead = tokio::task::JoinHandle<io::Result<(std::fs::File, Bytes)>>;

/// Read exactly `n` bytes (after seeking to `seek`, if given) on the blocking
/// pool. The file is moved in and handed back, so no lock is needed and only
/// one read per stream is ever in flight.
fn read_chunk(file: std::fs::File, seek: Option<u64>, n: u64) -> ChunkRead {
    roci_telemetry::record_blocking_hop("read_chunk");
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Seek};
        let mut file = file;
        if let Some(start) = seek {
            file.seek(io::SeekFrom::Start(start))?;
        }
        // Full-size chunks recycle through a bounded pool (steady RSS under
        // load); a small tail/blob gets an exact allocation instead of pinning
        // a pooled chunk.
        let pooled = n >= FILE_CHUNK / 4;
        let mut buf = if pooled {
            READ_POOL.get()
        } else {
            Vec::with_capacity(n as usize)
        };
        (&mut file).take(n).read_to_end(&mut buf)?;
        if (buf.len() as u64) < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "blob file is shorter than its recorded size",
            ));
        }
        let bytes = if pooled {
            READ_POOL.freeze(buf)
        } else {
            Bytes::from(buf)
        };
        Ok((file, bytes))
    })
}

/// Stream `[start, start + len)` of a local file in [`FILE_CHUNK`] pieces with
/// one chunk of read-ahead: the next read runs while the current chunk is being
/// written to the socket. Backpressure is async (an unpolled stream holds a
/// finished chunk, never a blocking-pool thread), so slow clients cannot pin
/// the pool. A read error ends the stream after yielding it.
fn file_stream(file: std::fs::File, start: u64, len: u64) -> BlobStream {
    let first = FILE_CHUNK.min(len);
    let pending = read_chunk(file, (start > 0).then_some(start), first);
    futures::stream::unfold(Some((pending, len - first)), |state| async move {
        let (pending, remaining) = state?;
        let (file, bytes) = match pending.await.map_err(io::Error::other).and_then(|r| r) {
            Ok(read) => read,
            Err(e) => return Some((Err(e), None)),
        };
        let next = (remaining > 0).then(|| {
            let n = FILE_CHUNK.min(remaining);
            (read_chunk(file, None, n), remaining - n)
        });
        Some((Ok(bytes), next))
    })
    .boxed()
}

/// A resolved reference target: either a tag pointing at a manifest digest, or
/// a direct manifest digest.
#[derive(Debug, Clone)]
pub struct ManifestRef {
    pub digest: Digest,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// A streamed blob body.
pub type BlobStream = BoxStream<'static, io::Result<Bytes>>;

/// Opens the byte range `[start, start + len)` of a remote blob as a stream.
pub type RangeOpener =
    Box<dyn FnOnce(u64, u64) -> BoxFuture<'static, io::Result<BlobStream>> + Send>;

/// A blob opened for a GET: its total size plus how its bytes are delivered —
/// a local file (streamed, never buffered whole), a backend range reader, or a
/// short-lived redirect URL the client fetches directly (remote backends above
/// `redirect_min_size`, ARCHITECTURE §Storage trait & backends).
pub struct BlobRead {
    size: u64,
    source: BlobSource,
}

enum BlobSource {
    File(tokio::fs::File),
    Ranged(RangeOpener),
    Redirect(String),
}

impl BlobRead {
    /// A local file of `size` bytes.
    pub fn file(file: tokio::fs::File, size: u64) -> Self {
        Self {
            size,
            source: BlobSource::File(file),
        }
    }

    /// A remote blob of `size` bytes whose ranges `open` streams on demand.
    pub fn ranged(size: u64, open: RangeOpener) -> Self {
        Self {
            size,
            source: BlobSource::Ranged(open),
        }
    }

    /// A blob the client should fetch from `url` (a `307`).
    pub fn redirect(size: u64, url: String) -> Self {
        Self {
            size,
            source: BlobSource::Redirect(url),
        }
    }

    /// Total blob size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The redirect target, when the backend asks the client to fetch directly.
    pub fn redirect_url(&self) -> Option<&str> {
        match &self.source {
            BlobSource::Redirect(url) => Some(url),
            _ => None,
        }
    }

    /// Stream `len` bytes starting at `start` (`start + len <= size`). A
    /// redirect has no local body: [`io::ErrorKind::Unsupported`].
    pub async fn into_stream(self, start: u64, len: u64) -> io::Result<BlobStream> {
        match self.source {
            BlobSource::File(f) => Ok(file_stream(f.into_std().await, start, len)),
            BlobSource::Ranged(open) => open(start, len).await,
            BlobSource::Redirect(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "redirected blob has no local body",
            )),
        }
    }
}

/// The derived links one manifest push commits **atomically with the manifest
/// itself** (one WAL record — SECURITY §Storage boundary "GC as an integrity
/// property"): backref edges and, for a manifest carrying `subject`, its
/// referrer registration. A crash can never leave a stored manifest whose
/// blobs look unreferenced to GC.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManifestLinks<'a> {
    /// Every object the manifest references — config, layers, image-index
    /// children, and `subject` — recorded as `object → manifest` backrefs.
    pub references: &'a [Digest],
    /// The subset of `references` that MUST be present in the repository
    /// (config + layers). The backend re-checks them under the GC fence held
    /// through the metadata commit, so no sweep can remove one between the
    /// client-facing existence check and the commit
    /// ([`StorageError::MissingReference`] otherwise).
    pub required: &'a [Digest],
    /// `(subject digest, referrer descriptor JSON)` when the manifest carries a
    /// `subject`; the descriptor is stored with the subject link merged in.
    pub subject: Option<(&'a Digest, &'a [u8])>,
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
    /// Open a blob for a GET: its size plus a streamable body (or a redirect).
    fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<BlobRead, StorageError>> + Send;
    /// Begin a chunked upload session, returning its id.
    fn begin_upload(&self, repo: &str)
        -> impl Future<Output = Result<String, StorageError>> + Send;
    /// Stream `body` onto an upload session, returning the new total size. When
    /// `expected_offset` is `Some(n)`, the current committed size MUST equal
    /// `n` (a `Content-Range` precondition checked *inside* the session lock so
    /// two concurrent PATCHes cannot both pass an out-of-lock check) — a
    /// mismatch yields [`StorageError::RangeNotSatisfiable`]. A body over
    /// `limit` bytes is [`StorageError::TooLarge`]; any failure leaves the
    /// session exactly as it was (never whole-blob buffered, invariant 4).
    fn append_upload(
        &self,
        repo: &str,
        id: &str,
        body: UploadBody,
        expected_offset: Option<u64>,
        limit: u64,
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
    /// `Ok(false)` when the source blob is absent or the backends cannot share
    /// it (the caller falls back to a normal upload session). No blob bytes
    /// pass through memory: the backend links or copies server-side.
    fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Finalize an upload: under the session lock, stream `trailing` (a
    /// monolithic PUT's body — at most `limit` bytes — empty for a plain
    /// finalize) atomically with the
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
        trailing: UploadBody,
        limit: u64,
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
    /// Store a manifest by digest, (optionally) associate a tag, and record its
    /// [`ManifestLinks`] — manifest, tag, backrefs and referrer land in **one**
    /// metadata record, so a crash never desynchronizes them.
    fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
        links: ManifestLinks<'_>,
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
}

/// The server-driven lifecycle of a concrete backend, on top of the request
/// surface: startup recovery before any request is served, then background
/// maintenance until shutdown. The routing layer fans both out to every
/// backend of a multi-path registry.
pub trait StorageBackend: Storage {
    /// Startup recovery (e.g. referrers enable-upgrade, `index.json`
    /// reconciliation with the replayed metadata log). Run once, before
    /// serving.
    fn recover(&self) -> impl Future<Output = ()> + Send;
    /// Start the enabled background subsystems (GC, scrub, metadata upkeep);
    /// every task stops when `shutdown` becomes `true`.
    fn start_maintenance(&self, shutdown: tokio::sync::watch::Receiver<bool>);
}
