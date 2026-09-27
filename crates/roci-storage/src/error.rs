//! Storage error types.

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("not found")]
    NotFound,
    #[error("malformed digest: {0}")]
    BadDigest(String),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("unsafe path component: {0}")]
    BadPath(String),
    #[error("content range start {got} does not match current offset {expected}")]
    RangeNotSatisfiable { expected: u64, got: u64 },
    #[error("upload size {actual} exceeds maximum {limit}")]
    TooLarge { limit: u64, actual: u64 },
    #[error("{scope} quota of {limit} bytes exceeded ({requested} bytes requested)")]
    QuotaExceeded {
        scope: QuotaScope,
        limit: u64,
        requested: u64,
    },
    #[error("referenced blob {0} is not present")]
    MissingReference(String),
    #[error("too many concurrent upload sessions (limit {limit})")]
    TooManySessions { limit: usize },
    /// The storage backend is temporarily unavailable (e.g. bucket not yet
    /// accessible on all nodes). Write-path callers surface this as a 503.
    #[error("storage unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaScope {
    /// The per-repository cap (`storage.quota.max_repo_bytes`) → `413`.
    Repository,
    /// The registry-wide cap (`storage.quota.max_total_bytes`) → `507`.
    Total,
}

impl std::fmt::Display for QuotaScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            QuotaScope::Repository => "repository",
            QuotaScope::Total => "registry",
        })
    }
}

pub(crate) fn map_not_found(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound {
        StorageError::NotFound
    } else {
        StorageError::Io(e)
    }
}
