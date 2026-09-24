//! Path construction beneath the store root. Every untrusted component is
//! validated through [`SafeComponent`] (SECURITY.md inv. 8) before it reaches a
//! filesystem join, so no `.`/`..`/separator/NUL can escape the CAS.

use super::FsStorage;
use crate::{Digest, StorageError};
use std::path::{Path, PathBuf};

/// A single path component that has passed traversal validation. Its only
/// constructor is [`SafeComponent::new`], so any [`Path`] built by joining a
/// `SafeComponent` is provably free of `.`/`..`/separator/NUL injection — the
/// validation is a visible barrier between untrusted input and the filesystem
/// (SECURITY.md inv. 8), and a taint analysis sees the sanitizer boundary.
pub(super) struct SafeComponent<'a>(&'a str);

impl<'a> SafeComponent<'a> {
    /// Validate `s` as a single untrusted path component, returning a barrier
    /// wrapper whose only constructor is this validation (defense-in-depth so the
    /// CAS is safe regardless of the caller, SECURITY.md inv. 8). Rejects empty,
    /// `.`, `..`, and any embedded separator (`/`, `\\`) or NUL.
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

/// `<repo…>` relative to the store root, every `/`-component validated by
/// [`SafeComponent`].
pub(super) fn repo_rel(repo: &str) -> Result<PathBuf, StorageError> {
    repo.split('/').map(SafeComponent::new).collect()
}

/// (`<repo…>/blobs/<alg>`, `<hex>`): the dirfd-anchored write side. The
/// directory is opened beneath-root (no-follow) and the leaf operated on
/// relative to that dirfd, so a symlinked parent cannot redirect a promotion.
pub(super) fn blob_dir_rel(repo: &str, d: &Digest) -> Result<(PathBuf, String), StorageError> {
    let dir = repo_rel(repo)?.join("blobs").join(d.algorithm());
    Ok((dir, SafeComponent::new(d.hex())?.0.to_owned()))
}

/// `<repo…>/blobs/<alg>/<hex>`, every component validated. Fed to the
/// beneath-root resolver so a symlink planted at any level cannot escape the CAS.
pub(super) fn blob_rel(repo: &str, d: &Digest) -> Result<PathBuf, StorageError> {
    let (dir, leaf) = blob_dir_rel(repo, d)?;
    Ok(dir.join(leaf))
}

/// (`<repo…>/uploads`, `<id>`): the dirfd-anchored upload staging directory
/// plus its validated session-id leaf.
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
        // A repo name may contain `/`; build the path from each *validated*
        // component so no unchecked input reaches the filesystem join.
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
