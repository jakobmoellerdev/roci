//! Streamed upload bodies: request bytes go straight to a staging file in
//! large batches on the blocking pool — never whole-blob buffered (invariant
//! 4) — optionally hashing as they are written so finalize need not re-read.

use crate::{Digest, StorageError};
use bytes::{Bytes, BytesMut};
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

    fn update(&mut self, buf: &[u8]) {
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

/// Append `body` (at most `limit` bytes) to `file`, an append-mode handle whose
/// current length is `start`, extending `hash` when it covers exactly `start`
/// bytes. On any failure — body error, over `limit`, IO — the file is truncated
/// back to `start` (a rejected request leaves the session as it was) and the
/// error returned. Returns the new length and the extended hash, if any.
pub async fn append_body(
    file: tokio::fs::File,
    start: u64,
    mut body: UploadBody,
    limit: u64,
    hash: Option<StagedHash>,
) -> Result<(u64, Option<StagedHash>), StorageError> {
    let file = Arc::new(file.into_std().await);
    let mut hash = hash.filter(|h| h.len == start);
    let mut written = 0u64;
    let mut batch = BytesMut::new();
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
                batch.extend_from_slice(&chunk);
            }
            if batch.len() >= WRITE_BATCH || (done && !batch.is_empty()) {
                let buf = batch.split().freeze();
                let n = buf.len() as u64;
                let f = Arc::clone(&file);
                let mut h = hash.take();
                hash = tokio::task::spawn_blocking(move || {
                    (&*f).write_all(&buf)?;
                    if let Some(h) = h.as_mut() {
                        h.update(&buf);
                    }
                    Ok::<_, io::Error>(h)
                })
                .await
                .map_err(io::Error::other)
                .and_then(|r| r)?;
                written += n;
            }
            if done {
                return Ok(());
            }
        }
    }
    .await;
    match result {
        Ok(()) => Ok((start + written, hash)),
        Err(e) => {
            let f = Arc::clone(&file);
            tokio::task::spawn_blocking(move || f.set_len(start))
                .await
                .map_err(io::Error::other)
                .and_then(|r| r)?;
            Err(e)
        }
    }
}
