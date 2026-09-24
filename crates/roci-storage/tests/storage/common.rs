//! Shared fixtures for the storage integration suite.

/// A fresh store in its own tempdir; hold the `TempDir` for the test's lifetime.
pub fn store() -> (tempfile::TempDir, roci_storage::FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let s = roci_storage::FsStorage::new(dir.path()).unwrap();
    (dir, s)
}
