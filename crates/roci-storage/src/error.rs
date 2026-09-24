//! Storage error type and IO-error mapping helper.

use std::io;
use thiserror::Error;

/// Errors surfaced by the storage layer.
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
    /// Admitting a blob would push a quota past its cap.
    #[error("{scope} quota of {limit} bytes exceeded ({requested} bytes requested)")]
    QuotaExceeded {
        scope: QuotaScope,
        limit: u64,
        requested: u64,
    },
    /// A manifest's required blob is absent at commit time.
    #[error("referenced blob {0} is not present")]
    MissingReference(String),
    /// The concurrent upload-session cap is reached.
    #[error("too many concurrent upload sessions (limit {limit})")]
    TooManySessions { limit: usize },
}

/// Which storage quota a rejected write would exceed.
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
