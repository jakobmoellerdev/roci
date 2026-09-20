//! Storage subsystem for roci: a content-addressable store (CAS) backed by the
//! local filesystem, plus the [`Storage`] trait the registry core is written
//! against. Blob I/O is streamed with hash-on-write; nothing buffers a whole
//! blob in memory (ARCHITECTURE.md invariant 4).
#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256, Sha512};
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

    /// The digest's wire algorithm (`sha256` or `sha512`).
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Constant-time equality: compares the algorithm, then the hex bytes with
    /// a branch-free accumulator so digest verification leaks no timing signal
    /// (SECURITY.md §Storage boundary).
    pub fn ct_eq(&self, other: &Digest) -> bool {
        if self.algorithm != other.algorithm || self.hex.len() != other.hex.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.hex.bytes().zip(other.hex.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
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
    #[error("unsafe path component: {0}")]
    BadPath(String),
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

/// Filesystem-backed [`Storage`]. Each repository is a self-contained OCI
/// image layout under `<root>/<repo>/`: `oci-layout` (marker), `index.json`
/// (the image index — source of truth for tags, manifest media types and the
/// subject/referrers relation), `blobs/<algo>/<hex>` (content-addressable
/// store for blobs *and* manifests), and `uploads/<id>` (in-progress, not part
/// of the served layout). This lets roci serve any pre-existing OCI layout.
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

    /// Validate a single untrusted path component and **return it** so callers
    /// build paths from the validated value (a barrier the taint analysis and
    /// a human both see). Rejects empty, `.`/`..`, and any embedded separator
    /// (`/`, `\`) or NUL. Defense-in-depth backstop so the CAS is safe
    /// regardless of the caller (SECURITY.md inv. 8).
    fn safe_component(s: &str) -> Result<&str, StorageError> {
        if s.is_empty()
            || s == "."
            || s == ".."
            || s.bytes().any(|b| b == b'/' || b == b'\\' || b == 0)
        {
            return Err(StorageError::BadPath(s.to_string()));
        }
        Ok(s)
    }

    fn repo_dir(&self, repo: &str) -> Result<PathBuf, StorageError> {
        // A repo name may contain `/`; build the path from each *validated*
        // component so no unchecked input reaches the filesystem join.
        let mut path = PathBuf::clone(&self.root);
        for component in repo.split('/') {
            path.push(Self::safe_component(component)?);
        }
        Ok(path)
    }
    fn blob_path(&self, repo: &str, d: &Digest) -> Result<PathBuf, StorageError> {
        Ok(self.repo_dir(repo)?.join("blobs").join(d.relative_path()))
    }
    fn layout_path(&self, repo: &str) -> Result<PathBuf, StorageError> {
        Ok(self.repo_dir(repo)?.join("oci-layout"))
    }
    fn index_path(&self, repo: &str) -> Result<PathBuf, StorageError> {
        Ok(self.repo_dir(repo)?.join("index.json"))
    }
    /// Ensure `<repo>/` exists and carries a valid `oci-layout` marker so the
    /// directory is a well-formed OCI image layout even if only blobs (no
    /// manifest) have been pushed. Idempotent.
    async fn ensure_layout(&self, repo: &str) -> Result<(), StorageError> {
        let repo_dir = self.repo_dir(repo)?;
        tokio::fs::create_dir_all(&repo_dir).await?;
        let marker = self.layout_path(repo)?;
        match tokio::fs::metadata(&marker).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tokio::fs::write(&marker, OCI_LAYOUT_MARKER).await?;
            }
            Err(e) => return Err(StorageError::Io(e)),
        }
        Ok(())
    }
    /// Read `<repo>/index.json` as an image index. A missing index yields the
    /// canonical empty image index. A malformed on-disk index is an internal
    /// error (mapped to [`StorageError::Io`]).
    async fn read_index(&self, repo: &str) -> Result<serde_json::Value, StorageError> {
        match tokio::fs::read(self.index_path(repo)?).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(empty_index()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }
    /// Write `<repo>/index.json` atomically (tmp + rename), first ensuring the
    /// layout marker exists.
    async fn write_index(&self, repo: &str, index: &serde_json::Value) -> Result<(), StorageError> {
        self.ensure_layout(repo).await?;
        let dest = self.index_path(repo)?;
        let tmp = dest.with_extension("json.tmp");
        let bytes = serde_json::to_vec(index)
            .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &dest).await?;
        Ok(())
    }
    fn upload_path(&self, repo: &str, id: &str) -> Result<PathBuf, StorageError> {
        Ok(self
            .repo_dir(repo)?
            .join("uploads")
            .join(Self::safe_component(id)?))
    }
}

fn map_not_found(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound {
        StorageError::NotFound
    } else {
        StorageError::Io(e)
    }
}

/// The `oci-layout` marker file contents (image-layout.md §oci-layout file).
const OCI_LAYOUT_MARKER: &str = "{\"imageLayoutVersion\":\"1.0.0\"}";

/// Annotation key a descriptor carries to name a tag (image-layout.md
/// §index.json file).
const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// The canonical empty OCI image index.
fn empty_index() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [],
    })
}

/// Borrow the `manifests` array of an image index, replacing a missing or
/// non-array `manifests` field with an empty array first.
fn index_manifests_mut(index: &mut serde_json::Value) -> &mut Vec<serde_json::Value> {
    let obj = match index {
        serde_json::Value::Object(o) => o,
        other => {
            *other = empty_index();
            other.as_object_mut().expect("empty_index is an object")
        }
    };
    let entry = obj
        .entry("manifests")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !entry.is_array() {
        *entry = serde_json::Value::Array(Vec::new());
    }
    entry.as_array_mut().expect("manifests coerced to array")
}

/// The tag a descriptor names via its `org.opencontainers.image.ref.name`
/// annotation, if any.
fn descriptor_tag(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor
        .get("annotations")
        .and_then(|a| a.get(REF_NAME_ANNOTATION))
        .and_then(|v| v.as_str())
}

/// The `digest` field of a descriptor, if present and a string.
fn descriptor_digest(descriptor: &serde_json::Value) -> Option<&str> {
    descriptor.get("digest").and_then(|v| v.as_str())
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

/// Compute the digest of `data` using the given wire algorithm (sha256 or
/// sha512 — the values [`Digest::parse`] accepts). Verification hashes with the
/// *expected* algorithm so a sha512 digest is honored, not silently rejected.
pub fn digest_of(data: &[u8], algorithm: &str) -> Digest {
    match algorithm {
        "sha512" => {
            let mut h = Sha512::new();
            h.update(data);
            Digest {
                algorithm: "sha512".into(),
                hex: hex::encode(h.finalize()),
            }
        }
        // Default to sha256 for the only other allowlisted algorithm.
        _ => sha256_of(data),
    }
}

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        let meta = tokio::fs::metadata(self.blob_path(repo, digest)?)
            .await
            .map_err(map_not_found)?;
        Ok(meta.len())
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        tokio::fs::read(self.blob_path(repo, digest)?)
            .await
            .map_err(map_not_found)
    }

    async fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<tokio::fs::File, StorageError> {
        tokio::fs::File::open(self.blob_path(repo, digest)?)
            .await
            .map_err(map_not_found)
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        let id = {
            let mut seq = self.upload_seq.lock().await;
            *seq += 1;
            format!("{}-{}", std::process::id(), *seq)
        };
        let path = self.upload_path(repo, &id)?;
        let uploads_dir = self.repo_dir(repo)?.join("uploads");
        tokio::fs::create_dir_all(&uploads_dir).await?;
        tokio::fs::File::create(&path).await?;
        Ok(id)
    }

    async fn append_upload(&self, repo: &str, id: &str, chunk: &[u8]) -> Result<u64, StorageError> {
        let path = self.upload_path(repo, id)?;
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
        let meta = tokio::fs::metadata(self.upload_path(repo, id)?)
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
        let path = self.upload_path(repo, id)?;
        let data = tokio::fs::read(&path).await.map_err(map_not_found)?;
        // put_blob verifies the digest (hashing with the expected algorithm);
        // only promote into the CAS and drop the staging file on success.
        self.put_blob(repo, expected, &data).await?;
        let _ = tokio::fs::remove_file(&path).await;
        Ok(())
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        // Hash with the *expected* algorithm so sha512 digests are honored, not
        // silently rejected against a sha256 recompute.
        let actual = digest_of(data, &digest.algorithm);
        if !actual.ct_eq(digest) {
            return Err(StorageError::DigestMismatch {
                expected: digest.as_string(),
                actual: actual.as_string(),
            });
        }
        // A repo populated only by blob pushes still gets a valid oci-layout
        // marker so the directory is a well-formed OCI image layout.
        self.ensure_layout(repo).await?;
        let dest = self.blob_path(repo, digest)?;
        tokio::fs::create_dir_all(self.repo_dir(repo)?.join("blobs").join(&digest.algorithm))
            .await?;
        // Write to a temp file then atomically rename into the CAS.
        let tmp = dest.with_extension("tmp");
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &dest).await?;
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        tokio::fs::remove_file(self.blob_path(repo, digest)?)
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
        // Validate the tag (if any) *before* writing any content so a bad tag
        // cannot leave a manifest blob committed with no index entry.
        if let Some(tag) = tag {
            Self::safe_component(tag)?;
        }
        // A manifest is a blob addressed by its digest; store it in the CAS
        // (put_blob verifies the digest and ensures the layout marker).
        self.put_blob(repo, digest, data).await?;

        // Record/refresh the manifest's descriptor in index.json.
        let mut index = self.read_index(repo).await?;
        let digest_str = digest.as_string();
        let manifests = index_manifests_mut(&mut index);
        // Drop any prior entry that would collide: the same tag (a tag move) or,
        // for this exact (digest, tag) pair, an exact duplicate (idempotent
        // re-push). Foreign descriptors and other tags are preserved.
        manifests.retain(|entry| {
            let same_tag = tag.is_some() && descriptor_tag(entry) == tag;
            let same_untagged = tag.is_none()
                && descriptor_tag(entry).is_none()
                && descriptor_digest(entry) == Some(digest_str.as_str());
            !(same_tag || same_untagged)
        });
        let mut descriptor = serde_json::Map::new();
        descriptor.insert(
            "mediaType".into(),
            serde_json::Value::String(media_type.to_string()),
        );
        descriptor.insert("digest".into(), serde_json::Value::String(digest_str));
        descriptor.insert("size".into(), serde_json::Value::Number(data.len().into()));
        if let Some(tag) = tag {
            let mut ann = serde_json::Map::new();
            ann.insert(
                REF_NAME_ANNOTATION.into(),
                serde_json::Value::String(tag.to_string()),
            );
            descriptor.insert("annotations".into(), serde_json::Value::Object(ann));
        }
        manifests.push(serde_json::Value::Object(descriptor));
        self.write_index(repo, &index).await
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        let index = self.read_index(repo).await?;
        let manifests = index.get("manifests").and_then(|m| m.as_array());
        let (digest, media_type) = if reference.contains(':') {
            // By-digest: recover the media type from the index if listed; a blob
            // present but unlisted (e.g. an externally-provided layout) defaults
            // to the image-manifest media type.
            let digest = Digest::parse(reference)?;
            let media_type = manifests
                .and_then(|ms| ms.iter().find(|e| descriptor_digest(e) == Some(reference)))
                .and_then(|e| e.get("mediaType"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".to_string());
            (digest, media_type)
        } else {
            // By-tag: resolve via the ref.name annotation.
            let entry = manifests
                .and_then(|ms| ms.iter().find(|e| descriptor_tag(e) == Some(reference)))
                .ok_or(StorageError::NotFound)?;
            let digest = Digest::parse(descriptor_digest(entry).ok_or(StorageError::NotFound)?)?;
            let media_type = entry
                .get("mediaType")
                .and_then(|v| v.as_str())
                .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                .to_string();
            (digest, media_type)
        };
        let bytes = tokio::fs::read(self.blob_path(repo, &digest)?)
            .await
            .map_err(map_not_found)?;
        Ok(ManifestRef {
            digest,
            media_type,
            bytes,
        })
    }

    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        // Remove the manifest blob from the CAS (NotFound if absent).
        tokio::fs::remove_file(self.blob_path(repo, digest)?)
            .await
            .map_err(map_not_found)?;
        // Drop every index entry (including tags) pointing at this digest.
        let mut index = self.read_index(repo).await?;
        let target = digest.as_string();
        let manifests = index_manifests_mut(&mut index);
        manifests.retain(|entry| descriptor_digest(entry) != Some(target.as_str()));
        self.write_index(repo, &index).await
    }

    async fn list_tags(&self, repo: &str) -> Result<Vec<String>, StorageError> {
        let index = self.read_index(repo).await?;
        let mut tags: Vec<String> = index
            .get("manifests")
            .and_then(|m| m.as_array())
            .map(|ms| {
                ms.iter()
                    .filter_map(|e| descriptor_tag(e).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
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
        // The referring manifest is already recorded by put_manifest; merge its
        // `subject` link (and any richer descriptor fields the core computed:
        // artifactType, annotations) into that entry so list_referrers can find
        // it. If for some reason no entry exists yet, append the descriptor.
        let mut merged: serde_json::Value = serde_json::from_slice(referrer_descriptor)
            .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        if let Some(obj) = merged.as_object_mut() {
            obj.insert(
                "subject".into(),
                serde_json::json!({ "digest": subject.as_string() }),
            );
        }
        let referrer_str = referrer.as_string();
        let mut index = self.read_index(repo).await?;
        let manifests = index_manifests_mut(&mut index);
        match manifests
            .iter_mut()
            .find(|e| descriptor_digest(e) == Some(referrer_str.as_str()))
        {
            Some(entry) => {
                // Preserve the tag annotation the existing entry may carry.
                if let (Some(existing), Some(new)) = (entry.as_object_mut(), merged.as_object()) {
                    for (k, v) in new {
                        if k == "annotations" && existing.contains_key("annotations") {
                            continue;
                        }
                        existing.insert(k.clone(), v.clone());
                    }
                }
            }
            None => manifests.push(merged),
        }
        self.write_index(repo, &index).await
    }

    async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let index = self.read_index(repo).await?;
        let target = subject.as_string();
        let out = index
            .get("manifests")
            .and_then(|m| m.as_array())
            .map(|ms| {
                ms.iter()
                    .filter(|e| {
                        e.get("subject")
                            .and_then(|s| s.get("digest"))
                            .and_then(|v| v.as_str())
                            == Some(target.as_str())
                    })
                    .filter_map(|e| serde_json::to_vec(e).ok())
                    .collect()
            })
            .unwrap_or_default();
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

    #[test]
    fn ct_eq_matches_equal_and_rejects_differences() {
        let a = sha256_of(b"payload");
        let b = sha256_of(b"payload");
        assert!(a.ct_eq(&b));
        let c = sha256_of(b"other");
        assert!(!a.ct_eq(&c));
        // Differing algorithm never matches.
        let s512 = Digest::parse(&format!("sha512:{}", "a".repeat(128))).unwrap();
        let s256 = Digest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        assert!(!s512.ct_eq(&s256));
    }

    #[tokio::test]
    async fn path_backstop_rejects_traversal_components() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"x");
        // A `..` repo component is rejected before any filesystem access.
        assert!(matches!(
            s.blob_size("a/../b", &d).await,
            Err(StorageError::BadPath(_))
        ));
        // A `..` reference resolves through index.json, never a path built from
        // the tag, so traversal is impossible: it is simply not found.
        assert!(matches!(
            s.get_manifest("r", "..").await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            s.append_upload("r", "../evil", b"x").await,
            Err(StorageError::BadPath(_))
        ));
        // BadPath renders a message.
        assert_eq!(
            StorageError::BadPath("..".into()).to_string(),
            "unsafe path component: .."
        );
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
        // add_referrer merges the subject link into the stored descriptor.
        let parsed: serde_json::Value = serde_json::from_slice(&listed[0]).unwrap();
        assert_eq!(parsed.get("digest").and_then(|v| v.as_str()), Some("x"));
        assert_eq!(
            parsed
                .get("subject")
                .and_then(|v| v.get("digest"))
                .and_then(|v| v.as_str()),
            Some(subject.as_string().as_str())
        );
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

        // put_manifest first writes the manifest blob (fails here too since
        // `<repo>/blobs` is a file), covering the CAS-write error path.
        assert!(matches!(
            s.put_manifest("r", None, &d, "application/json", data)
                .await,
            Err(StorageError::Io(_))
        ));

        // In a clean repo where the blob write succeeds, a pre-existing
        // `index.json` *directory* makes the atomic index rename fail, covering
        // write_index's error path.
        let body = br#"{"schemaVersion":2}"#;
        let bd = sha256_of(body);
        std::fs::create_dir_all(dir.path().join("r2").join("index.json")).unwrap();
        assert!(matches!(
            s.put_manifest("r2", Some("v1"), &bd, "application/json", body)
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
        // Tags "a"/"b" point at d; "other" points at a different digest and
        // must survive (covers the retain predicate's keep branch).
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
        // Re-pushing the same (tag, digest) is idempotent (dedup keeps one entry).
        s.put_manifest("r", Some("other"), &other, "application/json", b"different")
            .await
            .unwrap();
        assert_eq!(s.list_tags("r").await.unwrap(), vec!["other".to_string()]);
        // Deleting an untagged manifest in a fresh repo touches no tags.
        let d2 = sha256_of(b"lonely");
        s.put_manifest("solo", None, &d2, "application/json", b"lonely")
            .await
            .unwrap();
        // Untagged re-push is a no-op (dedup by digest).
        s.put_manifest("solo", None, &d2, "application/json", b"lonely")
            .await
            .unwrap();
        s.delete_manifest("solo", &d2).await.unwrap();
        assert!(s.list_tags("solo").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn non_notfound_io_error_surfaces() {
        // A pre-existing `index.json` *directory* makes read_index fail with a
        // non-NotFound error, surfacing as StorageError::Io through every reader.
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let repo_dir = dir.path().join("r");
        std::fs::create_dir_all(repo_dir.join("index.json")).unwrap();
        assert!(matches!(s.list_tags("r").await, Err(StorageError::Io(_))));
        let subject = sha256_of(b"s");
        assert!(matches!(
            s.list_referrers("r", &subject).await,
            Err(StorageError::Io(_))
        ));
        // A syntactically corrupt index.json is also an internal Io error.
        let repo2 = dir.path().join("r2");
        std::fs::create_dir_all(&repo2).unwrap();
        std::fs::write(repo2.join("index.json"), b"{ not json").unwrap();
        assert!(matches!(s.list_tags("r2").await, Err(StorageError::Io(_))));
    }

    #[tokio::test]
    async fn index_preserves_foreign_entries_and_referrer_append() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // Seed an index with a foreign descriptor (no ref.name annotation, no
        // subject) and a non-array `manifests` sibling field would be coerced.
        let subject = sha256_of(b"subject");
        let referrer = sha256_of(b"referrer");
        s.ensure_layout("r").await.unwrap();
        let seeded = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/xml", "digest": "sha256:dead", "size": 3}
            ]
        });
        s.write_index("r", &seeded).await.unwrap();
        // The foreign entry contributes no tag and is not a referrer.
        assert!(s.list_tags("r").await.unwrap().is_empty());
        assert!(s.list_referrers("r", &subject).await.unwrap().is_empty());
        // add_referrer with no pre-existing manifest entry appends the merged
        // descriptor (carrying the subject link) — covers the append branch.
        s.add_referrer(
            "r",
            &subject,
            &referrer,
            br#"{"digest":"x","artifactType":"a/b"}"#,
        )
        .await
        .unwrap();
        let listed = s.list_referrers("r", &subject).await.unwrap();
        assert_eq!(listed.len(), 1);
        let parsed: serde_json::Value = serde_json::from_slice(&listed[0]).unwrap();
        assert_eq!(
            parsed
                .get("subject")
                .and_then(|v| v.get("digest"))
                .and_then(|v| v.as_str()),
            Some(subject.as_string().as_str())
        );
        // The foreign descriptor is still present after the append.
        let idx = s.read_index("r").await.unwrap();
        assert_eq!(idx["manifests"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn index_manifests_mut_coerces_non_object_and_non_array() {
        // A non-object index is replaced with the empty index.
        let mut v = serde_json::Value::String("garbage".into());
        assert!(index_manifests_mut(&mut v).is_empty());
        assert_eq!(v["schemaVersion"], serde_json::json!(2));
        // A non-array `manifests` field is replaced with an empty array.
        let mut v2 = serde_json::json!({"manifests": 7});
        assert!(index_manifests_mut(&mut v2).is_empty());
        assert!(v2["manifests"].is_array());
    }

    #[tokio::test]
    async fn serves_external_oci_layout() {
        // Hand-build a valid OCI image layout roci did NOT write, then prove it
        // serves the tagged manifest and its config blob (the headline feature).
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("app");
        let config = br#"{"architecture":"amd64","os":"linux"}"#;
        let config_d = sha256_of(config);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":{}}},"layers":[]}}"#,
            config_d.as_string(),
            config.len()
        );
        let manifest_d = sha256_of(manifest.as_bytes());
        // Lay out oci-layout + blobs/<alg>/<hex> + index.json by hand.
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("oci-layout"), OCI_LAYOUT_MARKER).unwrap();
        let blobs = repo.join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join(&config_d.hex), config).unwrap();
        std::fs::write(blobs.join(&manifest_d.hex), manifest.as_bytes()).unwrap();
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_d.as_string(),
                "size": manifest.len(),
                "annotations": {"org.opencontainers.image.ref.name": "v1"}
            }]
        });
        std::fs::write(repo.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();

        let s = FsStorage::new(dir.path()).unwrap();
        let by_tag = s.get_manifest("app", "v1").await.unwrap();
        assert_eq!(by_tag.digest, manifest_d);
        assert_eq!(
            by_tag.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(by_tag.bytes, manifest.as_bytes());
        assert_eq!(s.list_tags("app").await.unwrap(), vec!["v1".to_string()]);
        assert_eq!(s.read_blob("app", &config_d).await.unwrap(), config);
        // A by-digest manifest blob present but unlisted in index.json falls
        // back to the image-manifest media type.
        let extra = br#"{"schemaVersion":2}"#;
        let extra_d = sha256_of(extra);
        std::fs::write(blobs.join(&extra_d.hex), extra).unwrap();
        let by_digest = s.get_manifest("app", &extra_d.as_string()).await.unwrap();
        assert_eq!(
            by_digest.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(by_digest.bytes, extra);
        // A digest that is neither listed nor present is NotFound.
        let absent = sha256_of(b"absent");
        assert!(matches!(
            s.get_manifest("app", &absent.as_string()).await,
            Err(StorageError::NotFound)
        ));
    }
}
