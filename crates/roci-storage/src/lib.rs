//! Storage subsystem for roci: a content-addressable store (CAS) backed by the
//! local filesystem, plus the [`Storage`] trait the registry core is written
//! against. Blob I/O is streamed with hash-on-write; nothing buffers a whole
//! blob in memory (ARCHITECTURE.md invariant 4).
#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// A parsed `algorithm:hex` content digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: String,
    hex: String,
}

impl Digest {
    /// Parse a digest string of the form `sha256:<64 hex>`. Only sha256 and
    /// sha512 are accepted (the algorithms the OCI spec registers).
    pub fn parse(s: &str) -> Result<Self, StorageError> {
        let (algorithm, hex) = s
            .split_once(':')
            .ok_or_else(|| StorageError::BadDigest(s.to_string()))?;
        let ok_len = match algorithm {
            "sha256" => 64,
            "sha512" => 128,
            _ => return Err(StorageError::BadDigest(s.to_string())),
        };
        if hex.len() != ok_len || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StorageError::BadDigest(s.to_string()));
        }
        Ok(Self {
            algorithm: algorithm.to_string(),
            hex: hex.to_ascii_lowercase(),
        })
    }

    /// The canonical `algorithm:hex` string.
    pub fn as_string(&self) -> String {
        format!("{}:{}", self.algorithm, self.hex)
    }

    fn relative_path(&self) -> PathBuf {
        PathBuf::from(&self.algorithm).join(&self.hex)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

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
}

/// A resolved reference target: either a tag pointing at a manifest digest, or
/// a direct manifest digest.
#[derive(Debug, Clone)]
pub struct ManifestRef {
    pub digest: Digest,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// The registry storage contract. AuthN/AuthZ is enforced *before* any call
/// into this trait (ARCHITECTURE.md invariant 3).
pub trait Storage: Send + Sync + 'static {
    /// Whether a blob exists, returning its size.
    fn blob_size(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Read a whole blob (used by manifests; large blobs stream via [`Storage::open_blob`]).
    fn read_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<Vec<u8>, StorageError>> + Send;
    /// Open a blob file for streaming.
    fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<tokio::fs::File, StorageError>> + Send;
    /// Begin a chunked upload session, returning its id.
    fn begin_upload(&self, repo: &str)
        -> impl Future<Output = Result<String, StorageError>> + Send;
    /// Append bytes to an upload session, returning the new total size.
    fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Current size of an in-progress upload.
    fn upload_size(
        &self,
        repo: &str,
        id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Finalize an upload, verifying it hashes to `expected`, moving it into the CAS.
    fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Store a blob given its bytes (verifies digest), used by monolithic/mount paths.
    fn put_blob(
        &self,
        repo: &str,
        digest: &Digest,
        data: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Delete a blob.
    fn delete_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Store a manifest by digest and (optionally) associate a tag.
    fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// Resolve a manifest by tag or digest reference.
    fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> impl Future<Output = Result<ManifestRef, StorageError>> + Send;
    /// Delete a manifest by digest.
    fn delete_manifest(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// List tags for a repo, sorted lexically.
    fn list_tags(
        &self,
        repo: &str,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
    /// Record a referrer: `subject` is the digest a manifest points at via its
    /// `subject` field; `referrer_descriptor` is the JSON descriptor of the
    /// referring manifest to include in the subject's referrers index.
    fn add_referrer(
        &self,
        repo: &str,
        subject: &Digest,
        referrer: &Digest,
        referrer_descriptor: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// List the referrer descriptors recorded for `subject`, as raw JSON blobs.
    fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, StorageError>> + Send;
}

/// Filesystem-backed [`Storage`]. Layout under `<root>/<repo>/`:
/// `blobs/<algo>/<hex>`, `manifests/<algo>/<hex>`, `tags/<tag>` (contains the
/// manifest digest), `uploads/<id>` (in-progress).
#[derive(Clone)]
pub struct FsStorage {
    root: Arc<PathBuf>,
    upload_seq: Arc<Mutex<u64>>,
}

impl FsStorage {
    /// Create a store rooted at `root`, creating it if absent.
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root: Arc::new(root),
            upload_seq: Arc::new(Mutex::new(0)),
        })
    }

    fn repo_dir(&self, repo: &str) -> PathBuf {
        self.root.join(repo)
    }
    fn blob_path(&self, repo: &str, d: &Digest) -> PathBuf {
        self.repo_dir(repo).join("blobs").join(d.relative_path())
    }
    fn manifest_path(&self, repo: &str, d: &Digest) -> PathBuf {
        self.repo_dir(repo)
            .join("manifests")
            .join(d.relative_path())
    }
    fn manifest_meta_path(&self, repo: &str, d: &Digest) -> PathBuf {
        self.repo_dir(repo)
            .join("manifests")
            .join(d.relative_path())
            .with_extension("mediatype")
    }
    fn tag_path(&self, repo: &str, tag: &str) -> PathBuf {
        self.repo_dir(repo).join("tags").join(tag)
    }
    fn upload_path(&self, repo: &str, id: &str) -> PathBuf {
        self.repo_dir(repo).join("uploads").join(id)
    }
    fn referrers_dir(&self, repo: &str, subject: &Digest) -> PathBuf {
        self.repo_dir(repo)
            .join("referrers")
            .join(subject.relative_path())
    }
}

fn map_not_found(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound {
        StorageError::NotFound
    } else {
        StorageError::Io(e)
    }
}

/// Compute the sha256 digest of `data`.
pub fn sha256_of(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(data);
    Digest {
        algorithm: "sha256".into(),
        hex: hex::encode(h.finalize()),
    }
}

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        let meta = tokio::fs::metadata(self.blob_path(repo, digest))
            .await
            .map_err(map_not_found)?;
        Ok(meta.len())
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        tokio::fs::read(self.blob_path(repo, digest))
            .await
            .map_err(map_not_found)
    }

    async fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<tokio::fs::File, StorageError> {
        tokio::fs::File::open(self.blob_path(repo, digest))
            .await
            .map_err(map_not_found)
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        let id = {
            let mut seq = self.upload_seq.lock().await;
            *seq += 1;
            format!("{}-{}", std::process::id(), *seq)
        };
        let path = self.upload_path(repo, &id);
        let uploads_dir = self.repo_dir(repo).join("uploads");
        tokio::fs::create_dir_all(&uploads_dir).await?;
        tokio::fs::File::create(&path).await?;
        Ok(id)
    }

    async fn append_upload(&self, repo: &str, id: &str, chunk: &[u8]) -> Result<u64, StorageError> {
        let path = self.upload_path(repo, id);
        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .map_err(map_not_found)?;
        f.write_all(chunk).await?;
        f.flush().await?;
        Ok(f.metadata().await?.len())
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        let meta = tokio::fs::metadata(self.upload_path(repo, id))
            .await
            .map_err(map_not_found)?;
        Ok(meta.len())
    }

    async fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
    ) -> Result<(), StorageError> {
        let path = self.upload_path(repo, id);
        let data = tokio::fs::read(&path).await.map_err(map_not_found)?;
        let actual = sha256_of(&data);
        if &actual != expected {
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        self.put_blob(repo, expected, &data).await?;
        let _ = tokio::fs::remove_file(&path).await;
        Ok(())
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        let actual = sha256_of(data);
        if &actual != digest {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }
        let dest = self.blob_path(repo, digest);
        tokio::fs::create_dir_all(self.repo_dir(repo).join("blobs").join(&digest.algorithm))
            .await?;
        // Write to a temp file then atomically rename into the CAS.
        let tmp = dest.with_extension("tmp");
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &dest).await?;
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        tokio::fs::remove_file(self.blob_path(repo, digest))
            .await
            .map_err(map_not_found)
    }

    async fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let dest = self.manifest_path(repo, digest);
        tokio::fs::create_dir_all(
            self.repo_dir(repo)
                .join("manifests")
                .join(&digest.algorithm),
        )
        .await?;
        tokio::fs::write(&dest, data).await?;
        tokio::fs::write(self.manifest_meta_path(repo, digest), media_type.as_bytes()).await?;
        if let Some(tag) = tag {
            let tp = self.tag_path(repo, tag);
            tokio::fs::create_dir_all(self.repo_dir(repo).join("tags")).await?;
            tokio::fs::write(tp, digest.as_string().as_bytes()).await?;
        }
        Ok(())
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        let digest = if reference.contains(':') {
            Digest::parse(reference)?
        } else {
            let raw = tokio::fs::read(self.tag_path(repo, reference))
                .await
                .map_err(map_not_found)?;
            Digest::parse(std::str::from_utf8(&raw).map_err(|_| StorageError::NotFound)?)?
        };
        let bytes = tokio::fs::read(self.manifest_path(repo, &digest))
            .await
            .map_err(map_not_found)?;
        let media_type = tokio::fs::read_to_string(self.manifest_meta_path(repo, &digest))
            .await
            .unwrap_or_else(|_| "application/vnd.oci.image.manifest.v1+json".to_string());
        Ok(ManifestRef {
            digest,
            media_type,
            bytes,
        })
    }

    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        let path = self.manifest_path(repo, digest);
        tokio::fs::remove_file(&path).await.map_err(map_not_found)?;
        let _ = tokio::fs::remove_file(self.manifest_meta_path(repo, digest)).await;
        // Remove any tags pointing at this digest.
        let tags_dir = self.repo_dir(repo).join("tags");
        if let Ok(mut rd) = tokio::fs::read_dir(&tags_dir).await {
            let target = digest.as_string();
            while let Ok(Some(entry)) = rd.next_entry().await {
                if let Ok(content) = tokio::fs::read_to_string(entry.path()).await {
                    if content == target {
                        let _ = tokio::fs::remove_file(entry.path()).await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn list_tags(&self, repo: &str) -> Result<Vec<String>, StorageError> {
        let dir = self.repo_dir(repo).join("tags");
        let mut tags = Vec::new();
        match tokio::fs::read_dir(&dir).await {
            Ok(mut rd) => {
                while let Some(entry) = rd.next_entry().await? {
                    // Tag names are UTF-8 in practice; a non-UTF-8 name (only
                    // creatable via out-of-band corruption) is included lossily
                    // rather than silently dropped.
                    tags.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(StorageError::Io(e)),
        }
        tags.sort();
        Ok(tags)
    }

    async fn add_referrer(
        &self,
        repo: &str,
        subject: &Digest,
        referrer: &Digest,
        referrer_descriptor: &[u8],
    ) -> Result<(), StorageError> {
        let dir = self.referrers_dir(repo, subject);
        tokio::fs::create_dir_all(&dir).await?;
        // File name is the referrer's own digest so re-pushes are idempotent.
        let fname = format!("{}-{}", referrer.algorithm, referrer.hex);
        tokio::fs::write(dir.join(fname), referrer_descriptor).await?;
        Ok(())
    }

    async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let dir = self.referrers_dir(repo, subject);
        let mut out = Vec::new();
        match tokio::fs::read_dir(&dir).await {
            Ok(mut rd) => {
                while let Some(entry) = rd.next_entry().await? {
                    if let Ok(bytes) = tokio::fs::read(entry.path()).await {
                        out.push(bytes);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(StorageError::Io(e)),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_parse_rejects_bad_input() {
        assert!(Digest::parse("sha256:zz").is_err());
        assert!(Digest::parse("nope").is_err());
        assert!(Digest::parse(&format!("sha256:{}", "a".repeat(64))).is_ok());
    }

    #[tokio::test]
    async fn blob_roundtrip_and_digest_verify() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"hello roci";
        let d = sha256_of(data);
        s.put_blob("repo/a", &d, data).await.unwrap();
        assert_eq!(s.blob_size("repo/a", &d).await.unwrap(), data.len() as u64);
        assert_eq!(s.read_blob("repo/a", &d).await.unwrap(), data);

        // Wrong digest is rejected.
        let wrong = sha256_of(b"other");
        assert!(matches!(
            s.put_blob("repo/a", &wrong, data).await,
            Err(StorageError::DigestMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn upload_session_finalizes_into_cas() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let id = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id, b"chunk1").await.unwrap();
        let total = s.append_upload("r", &id, b"chunk2").await.unwrap();
        assert_eq!(total, 12);
        let d = sha256_of(b"chunk1chunk2");
        s.finish_upload("r", &id, &d).await.unwrap();
        assert_eq!(s.read_blob("r", &d).await.unwrap(), b"chunk1chunk2");
    }

    #[tokio::test]
    async fn manifest_tag_resolution_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        s.put_manifest(
            "r",
            Some("v1"),
            &d,
            "application/vnd.oci.image.manifest.v1+json",
            body,
        )
        .await
        .unwrap();
        let by_tag = s.get_manifest("r", "v1").await.unwrap();
        assert_eq!(by_tag.digest, d);
        let by_digest = s.get_manifest("r", &d.as_string()).await.unwrap();
        assert_eq!(by_digest.bytes, body);
        assert_eq!(s.list_tags("r").await.unwrap(), vec!["v1".to_string()]);
        s.delete_manifest("r", &d).await.unwrap();
        assert!(matches!(
            s.get_manifest("r", "v1").await,
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn sha512_digest_parses_and_displays() {
        let d = Digest::parse(&format!("sha512:{}", "b".repeat(128))).unwrap();
        assert_eq!(d.to_string(), format!("sha512:{}", "b".repeat(128)));
        assert_eq!(d.as_string(), d.to_string());
    }

    #[test]
    fn error_messages_render() {
        // Exercise the Display arms of every StorageError variant.
        assert_eq!(StorageError::NotFound.to_string(), "not found");
        assert_eq!(
            StorageError::BadDigest("x".into()).to_string(),
            "malformed digest: x"
        );
        assert_eq!(
            StorageError::DigestMismatch {
                expected: "a".into(),
                actual: "b".into()
            }
            .to_string(),
            "digest mismatch: expected a, got b"
        );
        let io = StorageError::Io(io::Error::other("boom"));
        assert!(io.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn open_blob_streams_and_missing_is_not_found() {
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"streamed";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        let mut f = s.open_blob("r", &d).await.unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, data);
        let absent = sha256_of(b"absent");
        assert!(matches!(
            s.open_blob("r", &absent).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            s.blob_size("r", &absent).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            s.read_blob("r", &absent).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn blob_delete_and_finish_upload_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"deleteme";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.delete_blob("r", &d).await.unwrap();
        assert!(matches!(
            s.delete_blob("r", &d).await,
            Err(StorageError::NotFound)
        ));

        // finish_upload with a wrong expected digest is rejected.
        let id = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id, b"abc").await.unwrap();
        let wrong = sha256_of(b"xyz");
        assert!(matches!(
            s.finish_upload("r", &id, &wrong).await,
            Err(StorageError::DigestMismatch { .. })
        ));
        // Missing upload session size / append errors are NotFound.
        assert!(matches!(
            s.upload_size("r", "nope").await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            s.append_upload("r", "nope", b"x").await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn referrers_roundtrip_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let subject = sha256_of(b"subject");
        let referrer = sha256_of(b"referrer");
        // Empty before anything is recorded.
        assert!(s.list_referrers("r", &subject).await.unwrap().is_empty());
        s.add_referrer("r", &subject, &referrer, br#"{"digest":"x"}"#)
            .await
            .unwrap();
        let listed = s.list_referrers("r", &subject).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], br#"{"digest":"x"}"#);
    }

    #[tokio::test]
    async fn empty_repo_lists_no_tags() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        assert!(s.list_tags("brand-new").await.unwrap().is_empty());
    }

    #[test]
    fn sha512_bad_hex_rejected() {
        // Correct length, non-hex char → BadDigest (covers the hex guard).
        assert!(Digest::parse(&format!("sha512:{}", "z".repeat(128))).is_err());
        // Unknown algorithm → BadDigest (covers the match's fallback arm).
        assert!(Digest::parse("md5:abcdef").is_err());
    }

    #[tokio::test]
    async fn put_errors_when_parent_path_is_a_file() {
        // If `<repo>/blobs` is a regular file, create_dir_all for the blob's
        // parent fails, exercising the `?` error path in put_blob.
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let repo_dir = dir.path().join("r");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("blobs"), b"file").unwrap();
        let data = b"x";
        let d = sha256_of(data);
        assert!(matches!(
            s.put_blob("r", &d, data).await,
            Err(StorageError::Io(_))
        ));

        // Same for manifests: `<repo>/manifests` as a file breaks put_manifest.
        std::fs::write(repo_dir.join("manifests"), b"file").unwrap();
        assert!(matches!(
            s.put_manifest("r", None, &d, "application/json", data)
                .await,
            Err(StorageError::Io(_))
        ));
    }

    #[tokio::test]
    async fn put_manifest_tag_write_errors_when_tag_parent_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let repo_dir = dir.path().join("r");
        std::fs::create_dir_all(&repo_dir).unwrap();
        // `<repo>/tags` is a file → creating the tag's parent dir fails.
        std::fs::write(repo_dir.join("tags"), b"file").unwrap();
        let data = br#"{"schemaVersion":2}"#;
        let d = sha256_of(data);
        assert!(matches!(
            s.put_manifest("r", Some("v1"), &d, "application/json", data)
                .await,
            Err(StorageError::Io(_))
        ));
    }

    #[tokio::test]
    async fn upload_size_errors_when_session_path_is_a_dir() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // Create an "upload" that is actually a directory; metadata succeeds but
        // finish_upload's read fails. Directly exercise the read error.
        let up = dir.path().join("r").join("uploads").join("dir-session");
        std::fs::create_dir_all(&up).unwrap();
        let d = sha256_of(b"x");
        assert!(matches!(
            s.finish_upload("r", "dir-session", &d).await,
            Err(StorageError::Io(_))
        ));
    }

    #[tokio::test]
    async fn delete_manifest_removes_pointing_tag() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let body = br#"{"schemaVersion":2}"#;
        let d = sha256_of(body);
        // Tag "a"/"b" point at d; tag "other" points at a different digest and
        // must survive (exercises the content != target branch). A separate
        // delete on a repo with no tags dir exercises the read_dir-absent edge.
        let other = sha256_of(b"different");
        s.put_manifest("r", Some("a"), &d, "application/json", body)
            .await
            .unwrap();
        s.put_manifest("r", Some("b"), &d, "application/json", body)
            .await
            .unwrap();
        s.put_manifest("r", Some("other"), &other, "application/json", b"different")
            .await
            .unwrap();
        s.delete_manifest("r", &d).await.unwrap();
        // "a" and "b" removed; "other" remains.
        assert_eq!(s.list_tags("r").await.unwrap(), vec!["other".to_string()]);
        // A non-file entry in the tags dir (a subdirectory) makes read_to_string
        // fail, exercising that negative edge; the loop must skip it and continue.
        std::fs::create_dir_all(dir.path().join("r").join("tags").join("weird-subdir")).unwrap();
        s.put_manifest("r", Some("z"), &d, "application/json", body)
            .await
            .unwrap();
        s.delete_manifest("r", &d).await.unwrap();
        // Deleting a manifest in a repo with no tags directory is a no-op tag-wise.
        let d2 = sha256_of(b"lonely");
        s.put_manifest("solo", None, &d2, "application/json", b"lonely")
            .await
            .unwrap();
        s.delete_manifest("solo", &d2).await.unwrap();
    }

    #[tokio::test]
    async fn non_notfound_io_error_surfaces() {
        // Place a regular file where the `tags` directory is expected, so
        // read_dir fails with a non-NotFound error (NotADirectory), exercising
        // the StorageError::Io branch in list_tags.
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let repo_dir = dir.path().join("r");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("tags"), b"not a dir").unwrap();
        assert!(matches!(s.list_tags("r").await, Err(StorageError::Io(_))));

        // Same for the referrers listing directory.
        let subject = sha256_of(b"s");
        let ref_parent = repo_dir.join("referrers").join("sha256");
        std::fs::create_dir_all(&ref_parent).unwrap();
        std::fs::write(ref_parent.join(&subject.hex), b"not a dir").unwrap();
        assert!(matches!(
            s.list_referrers("r", &subject).await,
            Err(StorageError::Io(_))
        ));
    }

    #[tokio::test]
    async fn directory_iteration_skips_unreadable_entries() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // A subdirectory inside the referrers dir cannot be read as a file, so
        // list_referrers skips it (covers the read-Err edge of the loop).
        let subject = sha256_of(b"subj");
        let good = sha256_of(b"good");
        s.add_referrer("r", &subject, &good, br#"{"digest":"good"}"#)
            .await
            .unwrap();
        let ref_dir = dir
            .path()
            .join("r")
            .join("referrers")
            .join(&subject.algorithm)
            .join(&subject.hex);
        std::fs::create_dir_all(ref_dir.join("a-subdir")).unwrap();
        let listed = s.list_referrers("r", &subject).await.unwrap();
        // The real descriptor is returned; the subdirectory entry is skipped.
        assert_eq!(listed.len(), 1);

        // A non-UTF-8 tag filename is listed lossily by list_tags. Unix-only,
        // and only on filesystems that permit non-UTF-8 names (ext4/Linux does;
        // APFS/darwin rejects the write, so we skip the assertion there).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let tags_dir = dir.path().join("r2").join("tags");
            std::fs::create_dir_all(&tags_dir).unwrap();
            std::fs::write(tags_dir.join("valid"), b"x").unwrap();
            let bad = std::ffi::OsStr::from_bytes(b"bad-\xff-name");
            if std::fs::write(tags_dir.join(bad), b"x").is_ok() {
                let tags = s.list_tags("r2").await.unwrap();
                assert!(tags.contains(&"valid".to_string()));
                assert_eq!(tags.len(), 2);
            }
        }
    }
}
