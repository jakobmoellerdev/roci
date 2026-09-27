//! Local upload staging: resumable chunked sessions staged under
//! `root/uploads/<repo components>/<id>` with random 128-bit hex ids,
//! per-session lock, Content-Range precondition.
//! All staging file I/O uses `roci_storage::beneath` component-wise no-follow
//! opens so a symlink planted at `uploads/<repo>` or at the session id cannot
//! redirect operations outside the storage root.

use crate::S3Storage;
use roci_storage::beneath::{
    create_empty_beneath, open_append_beneath, open_beneath, stat_beneath, unlink_beneath,
};
use roci_storage::{append_body, StorageError, UploadBody};
use std::io;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

impl S3Storage {
    pub(crate) fn repo_staging_rel(&self, repo: &str) -> Result<PathBuf, StorageError> {
        crate::keys::validate_repo(repo)?;
        Ok(Path::new("uploads").join(repo))
    }

    pub(crate) fn staging_rel(&self, repo: &str, id: &str) -> Result<PathBuf, StorageError> {
        validate_session_id(id)?;
        Ok(self.repo_staging_rel(repo)?.join(id))
    }

    pub(crate) fn staging_path(&self, repo: &str, id: &str) -> Result<PathBuf, StorageError> {
        validate_session_id(id)?;
        crate::keys::validate_repo(repo)?;
        Ok(self.root.join("uploads").join(repo).join(id))
    }

    pub(crate) async fn begin_upload_session(&self, repo: &str) -> Result<String, StorageError> {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| StorageError::Io(io::Error::other(e)))?;
        let id = hex::encode(buf);
        validate_session_id(&id)?;
        self.quota.begin_session()?;
        // Create the staging file via no-follow beneath-root open.
        let dir_rel = self.repo_staging_rel(repo)?;
        if let Err(e) = create_empty_beneath(&self.root, &dir_rel, &id).await {
            self.quota.end_session();
            return Err(StorageError::Io(e));
        }
        Ok(id)
    }

    pub(crate) async fn append_to_staging(
        &self,
        repo: &str,
        id: &str,
        body: UploadBody,
        expected_offset: Option<u64>,
        limit: u64,
    ) -> Result<u64, StorageError> {
        let rel = self.staging_rel(repo, id)?;
        let f = open_append_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
        let current = f.metadata().await?.len();
        if let Some(offset) = expected_offset.filter(|&o| o != current) {
            return Err(StorageError::RangeNotSatisfiable {
                expected: current,
                got: offset,
            });
        }
        // The S3 finalize re-hashes the staged file, so no hash-on-write here.
        let (total, _) = append_body(f, current, body, limit, None).await?;
        let appended = total.saturating_sub(current);
        if appended > 0 {
            roci_telemetry::record_upload_bytes(appended);
        }
        Ok(total)
    }

    pub(crate) async fn staging_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        let rel = self.staging_rel(repo, id)?;
        match stat_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?
        {
            Some((true, size)) => Ok(size),
            _ => Err(StorageError::NotFound),
        }
    }

    pub(crate) async fn remove_staging(&self, repo: &str, id: &str) {
        if let Ok(dir_rel) = self.repo_staging_rel(repo) {
            if validate_session_id(id).is_ok() {
                let _ = unlink_beneath(&self.root, &dir_rel, id).await;
            }
        }
        self.quota.end_session();
    }

    pub(crate) async fn hash_staging(
        &self,
        repo: &str,
        id: &str,
        algorithm: &str,
    ) -> Result<(roci_storage::Digest, u32, u64), StorageError> {
        let rel = self.staging_rel(repo, id)?;
        let mut f = open_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
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

    pub(crate) fn seed_sessions_from_staging(&self) {
        let uploads_dir = self.root.join("uploads");
        let count = count_staging_files(&uploads_dir);
        if count > 0 {
            self.quota.seed_sessions(count);
            tracing::info!(
                sessions = count,
                "seeded upload sessions from staging files"
            );
        }
    }

    pub(crate) fn enumerate_staging_files(
        &self,
    ) -> Vec<(String, String, u64, std::time::SystemTime)> {
        let uploads_dir = self.root.join("uploads");
        let mut result = Vec::new();
        walk_staging_files(&uploads_dir, &uploads_dir, &mut result);
        result
    }
}

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

fn validate_session_id(id: &str) -> Result<(), StorageError> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id.len() > 64
        || id.bytes().any(|b| b == b'/' || b == b'\\' || b == 0)
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
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

fn count_staging_files(dir: &std::path::Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                count += count_staging_files(&entry.path());
            } else if ft.is_file() {
                count += 1;
            }
        }
    }
    count
}

fn walk_staging_files(
    base: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(String, String, u64, std::time::SystemTime)>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            walk_staging_files(base, &entry.path(), out);
        } else if ft.is_file() {
            let Ok(meta) = entry.metadata() else { continue };
            let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            // Extract repo and id from path: base/<repo components>/<id>
            let path = entry.path();
            let Ok(rel) = path.strip_prefix(base) else {
                continue;
            };
            let components: Vec<&str> = rel
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect();
            if components.len() < 2 {
                continue;
            }
            let id = components[components.len() - 1].to_string();
            let repo = components[..components.len() - 1].join("/");
            out.push((repo, id, meta.len(), modified));
        }
    }
}
