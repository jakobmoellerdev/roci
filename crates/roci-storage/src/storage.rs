//! Storage trait, [`ManifestRef`], [`BlobRead`], and [`ManifestLinks`].

use crate::metadata::{Page, Referrer};
use crate::upload_body::UploadBody;
use crate::{Digest, StorageError};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use futures::StreamExt;
use std::future::Future;
use std::io;
use tracing::Instrument;

/// 256 KiB per blocking-pool hop: amortizes hop overhead while bounding per-stream memory.
const FILE_CHUNK: u64 = 256 * 1024;

/// Recycled full-size read chunks: at most 64 idle (16 MiB).
static READ_POOL: crate::bufpool::BufPool = crate::bufpool::BufPool::new(FILE_CHUNK as usize, 64);

type ChunkRead = tokio::task::JoinHandle<io::Result<(std::fs::File, Bytes)>>;

/// Read `n` bytes (optionally seeking first) on the blocking pool, propagating `span`.
fn read_chunk(file: std::fs::File, seek: Option<u64>, n: u64, span: tracing::Span) -> ChunkRead {
    roci_telemetry::record_blocking_hop("read_chunk");
    tokio::task::spawn_blocking(move || {
        let _guard = span.enter();
        use std::io::{Read, Seek};
        let mut file = file;
        if let Some(start) = seek {
            file.seek(io::SeekFrom::Start(start))?;
        }
        // Full-size chunks recycle through a bounded pool; small tails get exact allocations.
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

/// Stream `[start, start+len)` in [`FILE_CHUNK`] pieces with one read-ahead.
/// Backpressure is async: an unpolled stream holds a finished chunk, never a pool thread.
fn file_stream(file: std::fs::File, start: u64, len: u64, span: tracing::Span) -> BlobStream {
    let first = FILE_CHUNK.min(len);
    let pending = read_chunk(file, (start > 0).then_some(start), first, span.clone());
    futures::stream::unfold(Some((pending, len - first, span)), |state| async move {
        let (pending, remaining, span) = state?;
        let (file, bytes) = match pending.await.map_err(io::Error::other).and_then(|r| r) {
            Ok(read) => read,
            Err(e) => return Some((Err(e), None)),
        };
        let next = (remaining > 0).then(|| {
            let n = FILE_CHUNK.min(remaining);
            (read_chunk(file, None, n, span.clone()), remaining - n, span)
        });
        Some((Ok(bytes), next))
    })
    .boxed()
}

/// A resolved tag-or-digest reference to a manifest.
#[derive(Debug, Clone)]
pub struct ManifestRef {
    pub digest: Digest,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

pub type BlobStream = BoxStream<'static, io::Result<Bytes>>;

pub type RangeOpener =
    Box<dyn FnOnce(u64, u64) -> BoxFuture<'static, io::Result<BlobStream>> + Send>;

/// A blob opened for GET: size + delivery mode (file, range reader, or redirect).
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
    pub fn file(file: tokio::fs::File, size: u64) -> Self {
        Self {
            size,
            source: BlobSource::File(file),
        }
    }

    pub fn ranged(size: u64, open: RangeOpener) -> Self {
        Self {
            size,
            source: BlobSource::Ranged(open),
        }
    }

    pub fn redirect(size: u64, url: String) -> Self {
        Self {
            size,
            source: BlobSource::Redirect(url),
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn redirect_url(&self) -> Option<&str> {
        match &self.source {
            BlobSource::Redirect(url) => Some(url),
            _ => None,
        }
    }

    /// Stream `len` bytes from `start`. Redirect → [`io::ErrorKind::Unsupported`].
    /// On Linux/FreeBSD issues `posix_fadvise` (Sequential or WillNeed); `DONTNEED`
    /// intentionally not issued to preserve page cache for concurrent readers.
    pub async fn into_stream(self, start: u64, len: u64) -> io::Result<BlobStream> {
        let span = tracing::info_span!("blob.stream", bytes = len, range.start = start,);
        match self.source {
            BlobSource::File(f) => {
                let file = f.into_std().await;
                advise_blob(&file, start, len, self.size);
                Ok(file_stream(file, start, len, span))
            }
            BlobSource::Ranged(open) => open(start, len).await,
            BlobSource::Redirect(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "redirected blob has no local body",
            )),
        }
    }
}

/// `posix_fadvise` hints: `Sequential` for full reads (doubles kernel readahead),
/// `WillNeed` for range reads. `DONTNEED` not issued: hot layers share the page cache.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn advise_blob(file: &std::fs::File, start: u64, len: u64, total_size: u64) {
    use rustix::fs::{fadvise, Advice};
    use std::num::NonZeroU64;

    let is_full = start == 0 && len == total_size;
    if is_full {
        let _ = fadvise(file, 0, None, Advice::Sequential);
    } else {
        if let Some(nz) = NonZeroU64::new(len) {
            let _ = fadvise(file, start, Some(nz), Advice::WillNeed);
        }
    }
}

/// No-op on platforms without `posix_fadvise`.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn advise_blob(_file: &std::fs::File, _start: u64, _len: u64, _total_size: u64) {}

/// Links committed atomically with a manifest (SECURITY §Storage boundary
/// "GC as an integrity property"): backrefs and optional referrer registration.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManifestLinks<'a> {
    /// All referenced objects, recorded as `object → manifest` backrefs.
    pub references: &'a [Digest],
    /// Subset of `references` that must exist; re-checked under the GC fence.
    pub required: &'a [Digest],
    /// Subject digest + referrer descriptor JSON when the manifest has a `subject`.
    pub subject: Option<(&'a Digest, &'a [u8])>,
}

/// The registry storage contract. AuthN/AuthZ is enforced *before* any call
/// into this trait (ARCHITECTURE.md invariant 3).
pub trait Storage: Send + Sync + 'static {
    fn blob_size(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    fn blob_exists(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    fn read_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<Vec<u8>, StorageError>> + Send;
    fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<BlobRead, StorageError>> + Send;
    fn begin_upload(&self, repo: &str)
        -> impl Future<Output = Result<String, StorageError>> + Send;
    /// Append `body` to a session, returning new size. `expected_offset` enforces
    /// a `Content-Range` precondition under the session lock.
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
    /// Abort a session. Returns whether one was removed.
    fn abort_upload(
        &self,
        repo: &str,
        id: &str,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Cross-repo blob mount (dist-spec end-11). `Ok(true)` = mounted;
    /// `Ok(false)` = absent/incompatible (caller falls back to upload).
    fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Finalize an upload: append `trailing`, verify digest, promote to CAS.
    /// Atomically locked so a concurrent PATCH cannot inject bytes mid-finalize.
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
    /// Store a manifest + tag + [`ManifestLinks`] in one atomic metadata record.
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
    /// Paginated tags in lexical order, bounded per page (SECURITY inv. 14).
    fn list_tags(
        &self,
        repo: &str,
        last: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Page<String>, StorageError>> + Send;
    /// Paginated referrers for `subject`, optionally filtered by `artifact_type`.
    fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Page<Referrer>, StorageError>> + Send;
}

/// Backend lifecycle: recovery, maintenance, and shutdown.
pub trait StorageBackend: Storage {
    /// One-time startup recovery (before serving).
    fn recover(&self) -> impl Future<Output = ()> + Send;
    /// Start background subsystems; each stops when `shutdown` becomes `true`.
    fn start_maintenance(&self, shutdown: tokio::sync::watch::Receiver<bool>);
    /// Best-effort state persistence for faster restart.
    fn on_shutdown(&self) {}
    /// Readiness probe: returns `Ok(())` when the backend is ready to serve
    /// writes, or a [`StorageError`] describing why not. The default is
    /// always-ready (filesystem backend). Remote backends (S3) override this
    /// to probe actual write accessibility (bucket reachability).
    fn ready(&self) -> impl Future<Output = Result<(), StorageError>> + Send {
        std::future::ready(Ok(()))
    }
}

/// Run `task` every `period` until `shutdown` flips; slow runs delay the next tick.
pub fn spawn_periodic<S, F, Fut>(
    store: S,
    name: &'static str,
    period: std::time::Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    task: F,
) where
    S: Clone + Send + 'static,
    F: Fn(S) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
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
