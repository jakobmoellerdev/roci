//! Streamed upload bodies: request bytes go straight to a staging file in
//! large batches on the blocking pool — never whole-blob buffered (invariant
//! 4) — optionally hashing as they are written so finalize need not re-read.

use crate::{Digest, StorageError};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
#[allow(unused_imports)]
use sha2::Digest as _;
use sha2::Sha256;
use std::io::{self, Write};
use std::sync::Arc;

/// A streamed request body.
pub type UploadBody = BoxStream<'static, io::Result<Bytes>>;

/// Bytes accumulated per blocking-pool write: large enough that the hop is
/// amortized, small enough to bound per-upload memory.
const WRITE_BATCH: usize = 1 << 20;

/// A body holding exactly `data` (tests, and callers that already have bytes).
pub fn upload_body(data: impl AsRef<[u8]>) -> UploadBody {
    let b = Bytes::copy_from_slice(data.as_ref());
    futures::stream::once(async move { Ok(b) }).boxed()
}

/// Incremental sha256 + CRC32C over the first `len` bytes of a staging file.
#[derive(Clone)]
pub struct StagedHash {
    sha: Sha256,
    crc: u32,
    len: u64,
}

impl StagedHash {
    /// Hash state for an empty file.
    pub fn new() -> Self {
        Self {
            sha: Sha256::new(),
            crc: 0,
            len: 0,
        }
    }

    pub(crate) fn update(&mut self, buf: &[u8]) {
        self.sha.update(buf);
        self.crc = crc32c::crc32c_append(self.crc, buf);
        self.len += buf.len() as u64;
    }

    /// Bytes covered.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether no bytes are covered.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The sha256 digest and CRC32C of the covered bytes.
    pub fn finish(self) -> (Digest, u32) {
        (crate::digest::finish_sha256(self.sha), self.crc)
    }
}

impl Default for StagedHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Recycled upload batch buffers: at most 16 idle (16 MiB).
static UPLOAD_POOL: crate::bufpool::BufPool = crate::bufpool::BufPool::new(WRITE_BATCH, 16);

/// Write `batch` (and extend `hash` over it) on the blocking pool, returning
/// the emptied buffer for the next batch.
async fn write_batch(
    file: &Arc<std::fs::File>,
    batch: Vec<u8>,
    hash: Option<StagedHash>,
) -> io::Result<(Vec<u8>, Option<StagedHash>)> {
    let f = Arc::clone(file);
    roci_telemetry::record_blocking_hop("write_batch");
    tokio::task::spawn_blocking(move || {
        let (mut batch, mut hash) = (batch, hash);
        (&*f).write_all(&batch)?;
        if let Some(h) = hash.as_mut() {
            h.update(&batch);
        }
        batch.clear();
        Ok((batch, hash))
    })
    .await
    .map_err(io::Error::other)
    .and_then(|r| r)
}

/// Append `body` (at most `limit` bytes) to `file`, an append-mode handle whose
/// current length is `start`, extending `hash` when it covers exactly `start`
/// bytes. On any failure — body error, over `limit`, IO — the file is truncated
/// back to `start` (a rejected request leaves the session as it was) and the
/// error returned. Returns the new length and the extended hash, if any.
pub async fn append_body(
    file: tokio::fs::File,
    start: u64,
    body: UploadBody,
    limit: u64,
    hash: Option<StagedHash>,
) -> Result<(u64, Option<StagedHash>), StorageError> {
    let d = append_inner(file, start, body, limit, hash, false).await?;
    UPLOAD_POOL.put(d.tail);
    Ok((d.len, d.hash))
}

/// A streamed body whose last (< 1 MiB) batch is not yet written, so the
/// caller can write it inside the blocking hop it makes next anyway. `hash`
/// covers `tail_at` bytes (everything but `tail`); `len` includes the tail.
pub(crate) struct Deferred {
    pub len: u64,
    pub hash: Option<StagedHash>,
    pub tail: Vec<u8>,
    pub tail_at: u64,
    pub file: Arc<std::fs::File>,
}

impl Deferred {
    /// Blocking: write the tail (truncating back to `tail_at` on failure) and
    /// fold it into the hash; returns the hash covering `len` bytes, if any.
    pub(crate) fn write_tail(mut self) -> io::Result<Option<StagedHash>> {
        if !self.tail.is_empty() {
            if let Err(e) = (&*self.file).write_all(&self.tail) {
                let _ = self.file.set_len(self.tail_at);
                return Err(e);
            }
            if let Some(h) = self.hash.as_mut() {
                h.update(&self.tail);
            }
        }
        UPLOAD_POOL.put(std::mem::take(&mut self.tail));
        Ok(self.hash)
    }
}

/// [`append_body`] without writing the final partial batch (see [`Deferred`]).
pub(crate) async fn append_body_deferring_tail(
    file: tokio::fs::File,
    start: u64,
    body: UploadBody,
    limit: u64,
    hash: Option<StagedHash>,
) -> Result<Deferred, StorageError> {
    append_inner(file, start, body, limit, hash, true).await
}

async fn append_inner(
    file: tokio::fs::File,
    start: u64,
    mut body: UploadBody,
    limit: u64,
    hash: Option<StagedHash>,
    defer_tail: bool,
) -> Result<Deferred, StorageError> {
    let file = Arc::new(file.into_std().await);
    let mut hash = hash.filter(|h| h.len == start);
    let mut written = 0u64;
    let mut batch = UPLOAD_POOL.get();
    let result: Result<(), StorageError> = async {
        loop {
            let next = body.next().await.transpose()?;
            let done = next.is_none();
            if let Some(chunk) = next {
                let received = written + batch.len() as u64 + chunk.len() as u64;
                if received > limit {
                    return Err(StorageError::TooLarge {
                        limit,
                        actual: received,
                    });
                }
                // Fill the batch to exactly WRITE_BATCH (never growing the
                // pooled buffer), writing each full batch as it completes.
                let mut rest = &chunk[..];
                while !rest.is_empty() {
                    let take = rest.len().min(WRITE_BATCH - batch.len());
                    batch.extend_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    if batch.len() == WRITE_BATCH {
                        (batch, hash) =
                            write_batch(&file, std::mem::take(&mut batch), hash.take()).await?;
                        written += WRITE_BATCH as u64;
                    }
                }
            }
            if done {
                if !defer_tail && !batch.is_empty() {
                    let n = batch.len() as u64;
                    (batch, hash) =
                        write_batch(&file, std::mem::take(&mut batch), hash.take()).await?;
                    written += n;
                }
                return Ok(());
            }
        }
    }
    .await;
    match result {
        Ok(()) => {
            let tail_at = start + written;
            let len = tail_at + batch.len() as u64;
            Ok(Deferred {
                len,
                hash,
                tail: batch,
                tail_at,
                file,
            })
        }
        Err(e) => {
            UPLOAD_POOL.put(batch);
            let f = Arc::clone(&file);
            tokio::task::spawn_blocking(move || f.set_len(start))
                .await
                .map_err(io::Error::other)
                .and_then(|r| r)?;
            Err(e)
        }
    }
}
