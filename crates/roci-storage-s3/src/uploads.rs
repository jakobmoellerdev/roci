//! Local upload staging: resumable chunked sessions staged under `root/uploads/`
//! with random 128-bit hex ids, per-session lock, Content-Range precondition.

use crate::S3Storage;
use roci_storage::StorageError;
use std::io;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl S3Storage {
    /// Staging file path for an upload session.
    pub(crate) fn staging_path(&self, id: &str) -> Result<PathBuf, StorageError> {
        validate_session_id(id)?;
        Ok(self.root.join("uploads").join(id))
    }

    /// Begin a new upload session. Returns the session id.
    pub(crate) async fn begin_upload_session(&self, _repo: &str) -> Result<String, StorageError> {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| StorageError::Io(io::Error::other(e)))?;
        let id = hex::encode(buf);
        self.quota.begin_session()?;
        let path = self.staging_path(&id)?;
        if let Err(e) = tokio::fs::File::create(&path).await {
            self.quota.end_session();
            return Err(StorageError::Io(e));
        }
        Ok(id)
    }

    /// Append bytes to a staging file under the session lock.
    pub(crate) async fn append_to_staging(
        &self,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> Result<u64, StorageError> {
        let path = self.staging_path(id)?;
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .map_err(map_not_found)?;
        if let Some(offset) = expected_offset {
            let current = f.metadata().await?.len();
            if current != offset {
                return Err(StorageError::RangeNotSatisfiable {
                    expected: current,
                    got: offset,
                });
            }
        }
        f.write_all(chunk).await?;
        f.flush().await?;
        Ok(f.metadata().await?.len())
    }

    /// Get the current size of a staging file.
    pub(crate) async fn staging_size(&self, id: &str) -> Result<u64, StorageError> {
        let path = self.staging_path(id)?;
        let meta = tokio::fs::metadata(&path).await.map_err(map_not_found)?;
        Ok(meta.len())
    }

    /// Remove a staging file and release the session.
    pub(crate) async fn remove_staging(&self, id: &str) {
        if let Ok(path) = self.staging_path(id) {
            let _ = tokio::fs::remove_file(&path).await;
        }
        self.quota.end_session();
    }

    /// Stream-hash a staging file: returns (digest, crc32c, size).
    pub(crate) async fn hash_staging(
        &self,
        id: &str,
        algorithm: &str,
    ) -> Result<(roci_storage::Digest, u32, u64), StorageError> {
        let path = self.staging_path(id)?;
        let mut f = tokio::fs::File::open(&path).await.map_err(map_not_found)?;
        let size = f.metadata().await?.len();

        let (digest, crc) = match algorithm {
            "sha256" => hash_file::<sha2::Sha256>(algorithm, &mut f).await?,
            "sha512" => hash_file::<sha2::Sha512>(algorithm, &mut f).await?,
            _ => {
                return Err(StorageError::BadDigest(format!(
                    "unsupported algorithm: {algorithm}"
                )))
            }
        };
        Ok((digest, crc, size))
    }
}

/// Stream a file through a hasher + CRC32C in 64 KiB reads.
async fn hash_file<H: sha2::Digest>(
    algorithm: &str,
    f: &mut tokio::fs::File,
) -> Result<(roci_storage::Digest, u32), StorageError> {
    let mut hasher = H::new();
    let mut crc: u32 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        crc = crc32c::crc32c_append(crc, &buf[..n]);
    }
    let hash = hasher.finalize();
    let hex_str = hex::encode(hash);
    let digest_str = format!("{algorithm}:{hex_str}");
    let digest = roci_storage::Digest::parse(&digest_str)?;
    Ok((digest, crc))
}

/// Validate a session id (hex, 32 chars).
fn validate_session_id(id: &str) -> Result<(), StorageError> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.len() > 64
        || id.bytes().any(|b| b == b'/' || b == b'\\' || b == 0)
    {
        return Err(StorageError::BadPath(id.to_string()));
    }
    Ok(())
}

fn map_not_found(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound {
        StorageError::NotFound
    } else {
        StorageError::Io(e)
    }
}
