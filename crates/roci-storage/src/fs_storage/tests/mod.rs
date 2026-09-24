//! Unit tests for the filesystem storage internals, split by concern. These
//! reach private items (path builders, beneath-root helpers, fault seams), so
//! they live here rather than in the public integration suite.

mod faults;
mod gc;
mod hardening;
mod index;
mod policies;
mod sessions;

pub(crate) use crate::beneath::*;
pub(crate) use crate::digest::*;
pub(crate) use crate::error::*;
#[cfg(target_os = "linux")]
pub(crate) use crate::fault::*;
pub(crate) use crate::layout::*;
pub(crate) use crate::metadata::*;
#[cfg(target_os = "linux")]
pub(crate) use crate::publish::*;
pub(crate) use crate::storage::*;
pub(crate) use crate::FsStorage;
pub(crate) use std::collections::HashMap;
pub(crate) use std::path::Path;
pub(crate) use std::sync::Mutex as StdMutex;

/// A fresh store in its own tempdir; hold the `TempDir` for the test's lifetime.
pub(crate) fn store() -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let s = FsStorage::new(dir.path()).unwrap();
    (dir, s)
}
