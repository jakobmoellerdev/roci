pub fn store() -> (tempfile::TempDir, roci_storage::FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let s = roci_storage::FsStorage::new(dir.path()).unwrap();
    (dir, s)
}
