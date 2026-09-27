//! Path construction beneath the store root (SECURITY.md inv. 8).

use super::FsStorage;
use crate::{Digest, StorageError};
use std::path::{Path, PathBuf};

/// A validated single path component (SECURITY.md inv. 8): no `.`/`..`/separator/NUL.
pub(super) struct SafeComponent<'a>(&'a str);
impl<'a> SafeComponent<'a> {
    /// Validate `s` as a single path component (SECURITY.md inv. 8).
    pub(super) fn new(s: &'a str) -> Result<Self, StorageError> {
        if s.is_empty()
            || s == "."
            || s == ".."
            || s.bytes().any(|b| b == b'/' || b == b'\\' || b == 0)
        {
            return Err(StorageError::BadPath(s.to_string()));
        }
        Ok(Self(s))
    }
}

impl AsRef<Path> for SafeComponent<'_> {
    fn as_ref(&self) -> &Path {
        Path::new(self.0)
    }
}

/// `<repo…>` relative to root, every `/`-component validated.
pub(super) fn repo_rel(repo: &str) -> Result<PathBuf, StorageError> {
    repo.split('/').map(SafeComponent::new).collect()
}

/// (`<repo…>/blobs/<alg>`, `<hex>`): dirfd-anchored write side.
pub(super) fn blob_dir_rel(repo: &str, d: &Digest) -> Result<(PathBuf, String), StorageError> {
    let dir = repo_rel(repo)?.join("blobs").join(d.algorithm());
    Ok((dir, SafeComponent::new(d.hex())?.0.to_owned()))
}

/// `<repo…>/blobs/<alg>/<hex>`, every component validated.
pub(super) fn blob_rel(repo: &str, d: &Digest) -> Result<PathBuf, StorageError> {
    let (dir, leaf) = blob_dir_rel(repo, d)?;
    Ok(dir.join(leaf))
}

/// (`<repo…>/uploads`, `<id>`): dirfd-anchored upload dir + validated id leaf.
pub(super) fn upload_dir_rel(repo: &str, id: &str) -> Result<(PathBuf, String), StorageError> {
    let dir = repo_rel(repo)?.join("uploads");
    Ok((dir, SafeComponent::new(id)?.0.to_owned()))
}

/// `<repo…>/uploads/<id>`, every component validated.
pub(super) fn upload_rel(repo: &str, id: &str) -> Result<PathBuf, StorageError> {
    let (dir, leaf) = upload_dir_rel(repo, id)?;
    Ok(dir.join(leaf))
}

impl FsStorage {
    pub(super) fn repo_dir(&self, repo: &str) -> Result<PathBuf, StorageError> {
        Ok(self.root.join(repo_rel(repo)?))
    }

    pub(super) fn index_path(&self, repo: &str) -> Result<PathBuf, StorageError> {
        Ok(self.repo_dir(repo)?.join("index.json"))
    }

    #[cfg(test)]
    pub(super) fn blob_path(&self, repo: &str, d: &Digest) -> Result<PathBuf, StorageError> {
        Ok(self.root.join(blob_rel(repo, d)?))
    }

    #[cfg(test)]
    pub(super) fn upload_path(&self, repo: &str, id: &str) -> Result<PathBuf, StorageError> {
        Ok(self.root.join(upload_rel(repo, id)?))
    }
}
