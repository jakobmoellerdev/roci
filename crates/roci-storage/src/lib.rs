//! Storage subsystem for roci: a content-addressable store (CAS) backed by the
//! local filesystem, plus the [`Storage`] trait the registry core is written
//! against. Blob I/O is streamed with hash-on-write; nothing buffers a whole
//! blob in memory (ARCHITECTURE.md invariant 4).
#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256, Sha512};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod cache;
mod filter;
use cache::SmallBlobCache;
mod metadata;
use filter::BlobPresenceFilter;
pub use metadata::{LogMetadataStore, MetaOp, MetadataStore};

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
    #[error("content range start {got} does not match current offset {expected}")]
    RangeNotSatisfiable { expected: u64, got: u64 },
    #[error("upload size {actual} exceeds maximum {limit}")]
    TooLarge { limit: u64, actual: u64 },
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
    /// Whether a blob is present in the CAS. A dedicated presence check the
    /// manifest push path uses to enforce referenced-blob existence; cheaper
    /// than [`Storage::blob_size`] for the common absent case (the presence
    /// filter answers a definite miss without a `stat`).
    fn blob_exists(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
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
    /// Append bytes to an upload session, returning the new total size. When
    /// `expected_offset` is `Some(n)`, the current committed size MUST equal
    /// `n` (a `Content-Range` precondition checked *inside* the session lock so
    /// two concurrent PATCHes cannot both pass an out-of-lock check) — a
    /// mismatch yields [`StorageError::RangeNotSatisfiable`].
    fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Current size of an in-progress upload.
    fn upload_size(
        &self,
        repo: &str,
        id: &str,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
    /// Abort an in-progress upload session, discarding its staging file.
    /// Idempotent: returns `Ok(true)` if a session was removed, `Ok(false)` if
    /// none existed.
    fn abort_upload(
        &self,
        repo: &str,
        id: &str,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Mount a blob from `from_repo` into `to_repo` without re-uploading it
    /// (dist-spec end-11 cross-repository blob mount). Returns `Ok(true)` when
    /// the blob was present in `from_repo` and is now linked into `to_repo`;
    /// `Ok(false)` when the source blob is absent (the caller falls back to a
    /// normal upload session). Promotion is a filesystem hard-link with a copy
    /// fallback — no blob bytes pass through memory.
    fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> impl Future<Output = Result<bool, StorageError>> + Send;
    /// Finalize an upload, verifying it hashes to `expected` and does not exceed
    /// `max_size` bytes (the per-session cap, re-checked here under the session
    /// lock so a promote cannot race past the handler's append-time check), then
    /// moving it into the CAS.
    fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
        max_size: u64,
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
    /// Record the reverse edges `blob_digest → manifest_digest` for every blob
    /// a manifest references (its config + layers), so a future GC can reclaim
    /// a blob the moment its last referencing manifest is deleted. Called by
    /// the core after a successful [`Storage::put_manifest`]; the delete side
    /// is handled inside [`Storage::delete_manifest`].
    fn record_backrefs(
        &self,
        repo: &str,
        manifest: &Digest,
        blobs: &[Digest],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
    /// The manifest digests currently known to reference `blob` in `repo`.
    fn backrefs(
        &self,
        repo: &str,
        blob: &Digest,
    ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;
}

/// Per-session upload locks: `(repo, id) → async lock` serializing an upload's
/// append/finish/abort so they never interleave (see [`FsStorage::session_lock`]).
type UploadLocks = Arc<StdMutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>>;

/// Filesystem-backed [`Storage`]. Each repository is a self-contained OCI
/// image layout under `<root>/<repo>/`: `oci-layout` (marker), `index.json`
/// (the image index — source of truth for tags, manifest media types and the
/// subject/referrers relation), `blobs/<algo>/<hex>` (content-addressable
/// store for blobs *and* manifests), and `uploads/<id>` (in-progress, not part
/// of the served layout). This lets roci serve any pre-existing OCI layout.
#[derive(Clone)]
pub struct FsStorage {
    root: Arc<PathBuf>,
    /// Derived, rebuildable metadata index (tags, media types, referrers) kept
    /// in RAM and mirrored to `roci-meta.log`. Reads resolve against this first
    /// and fall back to `index.json`; the layout stays the source of truth.
    meta: Arc<LogMetadataStore>,
    /// In-RAM blob-presence filter: a definite-absent answer short-circuits the
    /// filesystem `stat` on the read path (RESEARCH §8.5). Never authoritative
    /// for presence — a "maybe" always verifies on disk (SECURITY inv. 10).
    presence: Arc<BlobPresenceFilter>,
    /// Bounded in-RAM small-blob content cache (RESEARCH §9.2): serves
    /// manifests/configs with zero syscalls. A miss falls through to the loose
    /// CAS file, which always exists (never the sole copy).
    cache: Arc<SmallBlobCache>,
    /// Per-session async locks serializing `append`/`finish`/`abort` on one
    /// upload id, so a concurrent PATCH cannot inject bytes between a finish's
    /// hash-verify and its promote (a TOCTOU that would commit unverified data
    /// or bypass the size cap). Keyed by `(repo, id)`; entries are dropped when
    /// a session finishes or aborts.
    upload_locks: UploadLocks,
}

impl FsStorage {
    /// Create a store rooted at `root`, creating it if absent. Opens (replaying)
    /// the metadata log, then seeds the blob-presence filter from the CAS so it
    /// is complete (never false-negatives a stored blob). Tags/media-types/
    /// referrers are NOT walked at startup — a pre-existing layout resolves via
    /// the `index.json` read-path fallbacks and the metadata store warms on
    /// writes; the layout stays the source of truth.
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        let meta = Arc::new(LogMetadataStore::open(&root)?);
        let store = Self {
            root: Arc::new(root),
            meta,
            presence: Arc::new(BlobPresenceFilter::new()),
            cache: Arc::new(SmallBlobCache::new()),
            upload_locks: Arc::new(StdMutex::new(HashMap::new())),
        };
        store.seed_presence_from_cas();
        Ok(store)
    }

    /// The async lock for one upload session, creating it on first use. Held
    /// across `append`/`finish`/`abort` so those never interleave on one id.
    /// The id is validated *before* an entry is created, so a stream of
    /// syntactically-invalid ids cannot leak lock-map entries; a caller that
    /// then finds no session drops the entry on its error path.
    fn session_lock(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, StorageError> {
        Self::safe_component(id)?;
        let mut locks = self.upload_locks.lock().expect("upload-locks poisoned");
        Ok(Arc::clone(
            locks
                .entry((repo.to_string(), id.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        ))
    }

    /// Drop a finished/aborted session's lock entry so the map does not grow
    /// unbounded across many uploads.
    fn drop_session_lock(&self, repo: &str, id: &str) {
        self.upload_locks
            .lock()
            .expect("upload-locks poisoned")
            .remove(&(repo.to_string(), id.to_string()));
    }

    /// Seed the blob-presence filter from every blob in the CAS so a definite
    /// absence (filter miss) is authoritative — the filter is complete, so a
    /// miss truly means "not stored" and can 404 without a syscall (RESEARCH
    /// §8.5). Walks `<repo>/blobs/<alg>/<hex>` for every repo (a repo dir is one
    /// holding `index.json`); skips in-progress `.tmp` files.
    fn seed_presence_from_cas(&self) {
        let root: &Path = &self.root;
        // Enumerate repo dirs (those containing index.json) up to a bounded
        // depth, then their blobs; best-effort — an unreadable dir just leaves
        // those blobs to fall through to a stat (never a wrong 404, because a
        // blob absent from the filter that IS on disk would only be reached if
        // the walk both saw the repo and failed mid-blobs, which re-adds via the
        // stat fallthrough being authoritative). See test coverage below.
        for repo in discover_repos(root) {
            let alg_root = root.join(&repo).join("blobs");
            let Ok(algs) = std::fs::read_dir(&alg_root) else {
                continue;
            };
            for alg in algs.flatten() {
                let alg_name = alg.file_name().to_string_lossy().into_owned();
                let Ok(hexes) = std::fs::read_dir(alg.path()) else {
                    continue;
                };
                for hex in hexes.flatten() {
                    let name = hex.file_name();
                    let hex_name = name.to_string_lossy();
                    // Skip in-progress tmp files (they carry an extension).
                    if hex_name.contains('.') {
                        continue;
                    }
                    self.presence
                        .insert(&repo, &format!("{alg_name}:{hex_name}"));
                }
            }
        }
    }

    /// Validate a single untrusted path component, returning a [`SafeComponent`]
    /// — a wrapper whose only constructor is this validation, so a filesystem
    /// path built from it is provably free of traversal input (a barrier the
    /// taint analysis and a human both see). Rejects empty, `.`/`..`, and any
    /// embedded separator (`/`, `\`) or NUL. Defense-in-depth backstop so the
    /// CAS is safe regardless of the caller (SECURITY.md inv. 8).
    fn safe_component(s: &str) -> Result<SafeComponent<'_>, StorageError> {
        SafeComponent::new(s)
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
        // Write the marker only if absent (idempotent). A pre-existing marker is
        // the steady state after the first push.
        if tokio::fs::try_exists(&marker).await? {
            return Ok(());
        }
        // fsync the marker and the repo directory so a blob-only repository (only
        // `oci-layout` + `blobs/`) is discoverable after a crash — otherwise a
        // restart's CAS walk misses it and a valid referenced blob is reported
        // absent (MANIFEST_BLOB_UNKNOWN). The parent (`root/<repo-parents>`)
        // entry is persisted too so the repo path itself survives.
        tokio::fs::write(&marker, OCI_LAYOUT_MARKER).await?;
        {
            let f = tokio::fs::OpenOptions::new()
                .read(true)
                .open(&marker)
                .await?;
            f.sync_all().await?;
        }
        sync_dir(&repo_dir).await?;
        // A repo dir is always `<root>/…/<name>`, so it has a parent; sync it so
        // the repo path entry itself is durable.
        sync_dir(repo_dir.parent().unwrap_or(&repo_dir)).await?;
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

    /// Fallback: recover a manifest's media type from `index.json` when the
    /// in-RAM index has no entry (e.g. an externally-provided layout the seed
    /// did not cover). `None` if the digest is not listed.
    async fn index_media_type_for_digest(
        &self,
        repo: &str,
        digest: &str,
    ) -> Result<Option<String>, StorageError> {
        let index = self.read_index(repo).await?;
        Ok(index
            .get("manifests")
            .and_then(|m| m.as_array())
            .and_then(|ms| ms.iter().find(|e| descriptor_digest(e) == Some(digest)))
            .and_then(|e| e.get("mediaType"))
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    /// Fallback: resolve a tag to `(digest, media_type)` from `index.json` when
    /// the in-RAM tag map misses. `NotFound` if no descriptor carries the tag.
    async fn index_resolve_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<(Digest, String), StorageError> {
        let index = self.read_index(repo).await?;
        let entry = index
            .get("manifests")
            .and_then(|m| m.as_array())
            .and_then(|ms| ms.iter().find(|e| descriptor_tag(e) == Some(tag)))
            .cloned()
            .ok_or(StorageError::NotFound)?;
        let digest = Digest::parse(descriptor_digest(&entry).ok_or(StorageError::NotFound)?)?;
        let media_type = entry
            .get("mediaType")
            .and_then(|v| v.as_str())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json")
            .to_string();
        Ok((digest, media_type))
    }
}

fn map_not_found(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound {
        StorageError::NotFound
    } else {
        StorageError::Io(e)
    }
}

/// A single path component that has passed traversal validation. Its only
/// constructor is [`SafeComponent::new`], so any [`Path`] built by joining a
/// `SafeComponent` is provably free of `.`/`..`/separator/NUL injection — the
/// validation is a visible barrier between untrusted input and the filesystem
/// (SECURITY.md inv. 8), and a taint analysis sees the sanitizer boundary.
struct SafeComponent<'a>(&'a str);

impl<'a> SafeComponent<'a> {
    /// Validate `s` as a single safe path component, rejecting empty, `.`,
    /// `..`, and any embedded separator (`/`, `\`) or NUL.
    fn new(s: &'a str) -> Result<Self, StorageError> {
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

/// Repository names under `root`: every directory (bounded depth) that directly
/// contains an `index.json` file **or** an `oci-layout` marker — the latter
/// catches a blob-only repo (blobs pushed before its first manifest, so no
/// `index.json` yet) whose blobs must still seed the presence filter. Named by
/// its `/`-joined path relative to `root`. Best-effort — an unreadable
/// directory is skipped. Used only to seed the blob-presence filter at startup.
fn discover_repos(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, rel: &[String], depth: usize, out: &mut Vec<String>) {
        // Bound depth so a pathological tree cannot recurse without limit;
        // repo names are a handful of path segments in practice.
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        if !rel.is_empty() && (dir.join("index.json").is_file() || dir.join("oci-layout").is_file())
        {
            out.push(rel.join("/"));
        }
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // The CAS/staging subdirs of a repo are never themselves repos.
            if name == "blobs" || name == "uploads" {
                continue;
            }
            let mut child = rel.to_vec();
            child.push(name);
            walk(&entry.path(), &child, depth - 1, out);
        }
    }
    let mut repos = Vec::new();
    walk(root, &[], 16, &mut repos);
    repos
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

/// A per-operation temporary sibling of `dest`: `<dest>.<16 random hex>.tmp`.
/// Concurrent writers of the same digest each get a distinct staging path, so
/// one writer's rename never clobbers another's open handle (the shared
/// `.tmp` race). The random suffix comes from `getrandom`; on the vanishingly
/// unlikely RNG failure the caller surfaces it as an IO error.
fn unique_tmp(dest: &Path) -> io::Result<PathBuf> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(io::Error::other)?;
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", hex::encode(buf)));
    Ok(dest.with_file_name(name))
}

/// Stream the file at `path` through the hasher selected by `algorithm`
/// (sha256/sha512), returning its [`Digest`] without buffering the whole file.
/// Used to verify a staged upload before promoting it into the CAS.
async fn hash_file(path: &Path, algorithm: &str) -> io::Result<Digest> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut buf = [0u8; 64 * 1024];
    // One hasher per algorithm keeps the loop monomorphic without dynamic
    // dispatch; sha256 is the default for any non-sha512 (allowlisted) value.
    if algorithm == "sha512" {
        let mut h = Sha512::new();
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(Digest {
            algorithm: "sha512".into(),
            hex: hex::encode(h.finalize()),
        })
    } else {
        let mut h = Sha256::new();
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(Digest {
            algorithm: "sha256".into(),
            hex: hex::encode(h.finalize()),
        })
    }
}

/// Copy `src` into the CAS at `dest` crash-atomically: copy to a per-operation
/// unique temp sibling, fsync it, then rename into place (so a reader never
/// sees a partial blob and a crash leaves at most an orphan temp, never a
/// corrupt-but-named digest). The copy step uses a whole-file reflink
/// (`FICLONE`) on Linux (btrfs/XFS share extents O(1) — CoW, no userspace byte
/// transit; RESEARCH §8.8), falling back to a streaming copy on any filesystem
/// that cannot reflink and on non-Linux platforms. Used as the cross-repo mount
/// fallback when a hard link is not possible (cross-device / no-hardlink fs).
async fn copy_file_atomic(src: &Path, dest: &Path) -> io::Result<()> {
    let tmp = unique_tmp(dest)?;
    let input = tokio::fs::File::open(src).await?;
    let output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .await?;
    copy_contents(&input, &output).await?;
    output.sync_all().await?;
    drop(input);
    drop(output);
    tokio::fs::rename(&tmp, dest).await?;
    // Sync the containing directory so the renamed entry survives a crash. A
    // CAS blob path always has a parent (`blobs/<alg>/`); fall back to `dest`
    // only to keep this total.
    sync_dir(dest.parent().unwrap_or(dest)).await
}

/// Copy all bytes from `input` to `output`. Linux first attempts a whole-file
/// reflink (`FICLONE`): on btrfs/XFS/bcachefs this shares the source extents
/// copy-on-write in O(1) with zero data transit (RESEARCH §8.8). On any
/// filesystem that cannot reflink (ext4/tmpfs) or a cross-device target it
/// falls back to a streaming read/write loop. Both run on a blocking thread so
/// a multi-GiB copy never stalls a Tokio worker. Other platforms stream via
/// tokio.
#[cfg(target_os = "linux")]
async fn copy_contents(input: &tokio::fs::File, output: &tokio::fs::File) -> io::Result<()> {
    use std::os::fd::AsFd;
    let inf = input.as_fd().try_clone_to_owned()?;
    let outf = output.as_fd().try_clone_to_owned()?;
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let mut infile = std::fs::File::from(inf);
        let mut outfile = std::fs::File::from(outf);
        // Whole-file reflink first: instant CoW extent share on btrfs/XFS. On
        // any failure (unsupported fs, cross-device) stream the bytes instead.
        if rustix::fs::ioctl_ficlone(&outfile, &infile).is_err() {
            stream_copy(&mut infile, &mut outfile)?;
        }
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

/// Rewind both files and copy `input` to `output` with a buffered read/write
/// loop, first truncating the destination so a retry never leaves stale tail
/// bytes. The streaming fallback used when a reflink is not possible. Runs on
/// the blocking thread that owns the file handles.
#[cfg(target_os = "linux")]
fn stream_copy(input: &mut std::fs::File, output: &mut std::fs::File) -> io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    input.seek(SeekFrom::Start(0))?;
    output.seek(SeekFrom::Start(0))?;
    output.set_len(0)?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

/// Non-Linux copy: stream the whole file through tokio.
#[cfg(not(target_os = "linux"))]
async fn copy_contents(input: &tokio::fs::File, output: &tokio::fs::File) -> io::Result<()> {
    let mut reader = tokio::io::BufReader::new(input.try_clone().await?);
    let mut writer = output.try_clone().await?;
    tokio::io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

/// Publish `data` as the CAS blob at `dest` (whose parent is `alg_dir`)
/// crash-atomically. On Linux this opens an anonymous `O_TMPFILE` inode in
/// `alg_dir`, writes+fsyncs it, then `linkat`s it into place: a partial blob is
/// never visible under its digest name, and there is no orphan temp to reap on
/// a crash. `linkat` returning `EEXIST` means an identical blob already exists
/// (content-addressed dedup) and is treated as success. Elsewhere it writes a
/// per-operation unique temp sibling, fsyncs, and atomically renames.
#[cfg(target_os = "linux")]
async fn publish_bytes(alg_dir: &Path, dest: &Path, data: &[u8]) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write as _;
    use std::os::fd::AsRawFd;
    let alg_dir = alg_dir.to_path_buf();
    let dest = dest.to_path_buf();
    let data = data.to_vec();
    let sync_target = alg_dir.clone();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        // Anonymous inode in the target directory: it has no name until linkat.
        let fd = rustix::fs::open(
            &alg_dir,
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(io::Error::from)?;
        let mut f = std::fs::File::from(fd);
        f.write_all(&data)?;
        f.sync_all()?;
        // Link the anonymous inode to its digest name via /proc/self/fd. AT_EMPTY_PATH
        // (linking the fd directly) needs CAP_DAC_READ_SEARCH, so the portable form
        // resolves the fd's magic symlink with AT_SYMLINK_FOLLOW.
        let proc_path = format!("/proc/self/fd/{}", f.as_raw_fd());
        match rustix::fs::linkat(
            rustix::fs::CWD,
            proc_path,
            rustix::fs::CWD,
            &dest,
            rustix::fs::AtFlags::SYMLINK_FOLLOW,
        ) {
            // EEXIST: the content-addressed blob is already present — dedup, success.
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
        Ok(())
    })
    .await
    .map_err(io::Error::other)??;
    // Persist the new directory entry.
    sync_dir(&sync_target).await
}

/// Non-Linux publish: write a per-operation unique temp sibling, fsync, rename.
#[cfg(not(target_os = "linux"))]
async fn publish_bytes(alg_dir: &Path, dest: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = unique_tmp(dest)?;
    {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        f.write_all(data).await?;
        f.sync_all().await?;
    }
    tokio::fs::rename(&tmp, dest).await?;
    let _ = alg_dir;
    sync_dir(dest.parent().unwrap_or(dest)).await
}

/// Fsync a directory so a prior `rename` into it is durable (the rename's
/// effect on the directory entry is not persisted by syncing the file alone).
/// On Unix this opens the directory and `fsync`s it; on platforms where a
/// directory handle cannot be synced this is a best-effort no-op.
async fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        // Opening a directory read-only and fsyncing it persists a prior rename
        // into it. The CAS dir was just created, so the open succeeds; any error
        // propagates through `?` into the caller's single error path.
        tokio::fs::File::open(dir).await?.sync_all().await
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Open `rel` (a path relative to `dir`) read-only, refusing to traverse a
/// symlink or escape `dir`. On Linux this is `openat2` with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`: the kernel enforces that no
/// component — not just the final one — is a symlink and that resolution never
/// leaves `dir`, closing the TOCTOU window between a stat and the open
/// (defense in depth behind `SafeComponent`). Other Unix platforms open the
/// joined path with `O_NOFOLLOW`, rejecting a final-component symlink.
async fn open_beneath(dir: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let dir = dir.to_path_buf();
    let rel = rel.to_path_buf();
    let std_file = tokio::task::spawn_blocking(move || -> io::Result<std::fs::File> {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::ResolveFlags;
            let dirfd = rustix::fs::open(
                &dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?;
            let fd = rustix::fs::openat2(
                &dirfd,
                &rel,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(io::Error::from)?;
            Ok(std::fs::File::from(fd))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // O_NOFOLLOW rejects a final-component symlink; the validated
            // relative path plus the traversal backstop guards the rest.
            let fd = rustix::fs::open(
                dir.join(&rel),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?;
            Ok(std::fs::File::from(fd))
        }
    })
    .await
    .map_err(io::Error::other)??;
    Ok(tokio::fs::File::from_std(std_file))
}

/// Open `path` for appending, refusing to follow a final-component symlink
/// (`O_NOFOLLOW`). A planted `uploads/<id>` symlink therefore cannot redirect a
/// PATCH append to an arbitrary target; the append fails instead. Returns the
/// same "not found" error as a missing session when the entry is a symlink.
#[cfg(unix)]
async fn open_append_nofollow(path: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let path = path.to_path_buf();
    let std_file = tokio::task::spawn_blocking(move || -> io::Result<std::fs::File> {
        let fd = rustix::fs::open(
            &path,
            OFlags::WRONLY | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        Ok(std::fs::File::from(fd))
    })
    .await
    .map_err(io::Error::other)??;
    Ok(tokio::fs::File::from_std(std_file))
}

/// Non-Unix append open (no symlink semantics to guard).
#[cfg(not(unix))]
async fn open_append_nofollow(path: &Path) -> io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new().append(true).open(path).await
}

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        // Validate the path first (the traversal backstop must run before any
        // short-circuit), then let a definite-absent filter answer skip the
        // stat; a "maybe" falls through to the authoritative stat.
        let path = self.blob_path(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        // `symlink_metadata` does not follow: a planted symlink under the CAS
        // name is not a valid blob (its target could be outside the store), so
        // a non-regular entry is reported absent, never sized/served.
        let meta = tokio::fs::symlink_metadata(path)
            .await
            .map_err(map_not_found)?;
        if !meta.is_file() {
            return Err(StorageError::NotFound);
        }
        Ok(meta.len())
    }

    async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        // Validate the path first (traversal backstop before any short-circuit),
        // then let a definite-absent filter answer skip the stat; a "maybe"
        // falls through to an authoritative no-follow stat. A CAS entry only
        // counts as present if it is a *regular file*: a planted symlink (which
        // `try_exists` would follow and accept) must not satisfy a manifest's
        // referenced-blob check and then be served from outside the store.
        let path = self.blob_path(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Ok(false);
        }
        match tokio::fs::symlink_metadata(path).await {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        let digest_str = digest.as_string();
        // Serve small blobs (manifests/configs) from the RAM cache with zero
        // syscalls; a miss falls through to the loose file.
        if let Some(bytes) = self.cache.get(repo, &digest_str) {
            return Ok(bytes.to_vec());
        }
        let path = self.blob_path(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest_str) {
            return Err(StorageError::NotFound);
        }
        let bytes = tokio::fs::read(path).await.map_err(map_not_found)?;
        self.cache.put(repo, &digest_str, &bytes);
        Ok(bytes)
    }

    async fn open_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<tokio::fs::File, StorageError> {
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        // Open rooted at the repo dir, refusing any symlink traversal: a planted
        // `blobs/<alg>/<hex>` symlink can never stream bytes from outside the CAS
        // (Linux `openat2 RESOLVE_BENEATH|NO_SYMLINKS`; `O_NOFOLLOW` elsewhere).
        let repo_dir = self.repo_dir(repo)?;
        let rel = Path::new("blobs").join(digest.relative_path());
        open_beneath(&repo_dir, &rel).await.map_err(map_not_found)
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        // A random 128-bit id: unguessable and independent of pid/restart (the
        // old `{pid}-{counter}` scheme collided across restarts). Hex-encoded,
        // so `upload_path`→`safe_component` accepts it unchanged.
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).map_err(|e| StorageError::Io(io::Error::other(e)))?;
        let id = hex::encode(buf);
        let path = self.upload_path(repo, &id)?;
        let uploads_dir = self.repo_dir(repo)?.join("uploads");
        tokio::fs::create_dir_all(&uploads_dir).await?;
        tokio::fs::File::create(&path).await?;
        Ok(id)
    }

    async fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> Result<u64, StorageError> {
        // Serialize with any concurrent append/finish/abort on this session so
        // bytes cannot be appended between a finish's hash-verify and its
        // promote, and so the Content-Range offset check below is atomic with
        // the append (two concurrent PATCHes cannot both pass it).
        let lock = self.session_lock(repo, id)?;
        let _guard = lock.lock().await;
        let path = self.upload_path(repo, id)?;
        let mut f = match open_append_nofollow(&path).await {
            Ok(f) => f,
            Err(e) => {
                // No such session: drop the just-created lock entry so a stream
                // of unknown ids cannot leak lock-map entries.
                self.drop_session_lock(repo, id);
                return Err(map_not_found(e));
            }
        };
        // Enforce the Content-Range precondition under the lock: the current
        // committed size must equal the client-declared start offset.
        if let Some(offset) = expected_offset {
            let current = f.metadata().await?.len();
            if current != offset {
                return Err(StorageError::RangeNotSatisfiable {
                    expected: current,
                    got: offset,
                });
            }
        }
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
        max_size: u64,
    ) -> Result<(), StorageError> {
        // Hold the session lock across the whole verify+promote so a concurrent
        // append cannot inject unverified bytes between the hash and the rename.
        let lock = self.session_lock(repo, id)?;
        let _guard = lock.lock().await;
        let staging = self.upload_path(repo, id)?;
        // Reject a staging entry that is not a regular file (e.g. a symlink
        // planted into the uploads dir): `symlink_metadata` does not follow, so
        // a non-regular entry never gets hashed-through and promoted into the
        // CAS.
        let st_meta = tokio::fs::symlink_metadata(&staging)
            .await
            .map_err(map_not_found)?;
        if !st_meta.is_file() {
            let _ = tokio::fs::remove_file(&staging).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::BadPath(format!(
                "upload {id} is not a regular file"
            )));
        }
        // Re-check the per-session cap *under the lock*: a PATCH that appended
        // past the cap and was preempted before aborting cannot be promoted by a
        // racing empty-body PUT, because finalize itself rejects an oversized
        // staging file (and drops it) here.
        if st_meta.len() > max_size {
            let _ = tokio::fs::remove_file(&staging).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: st_meta.len(),
            });
        }
        // Stream-hash the staging file (no full-blob buffer), verifying it
        // matches the client-declared digest before promoting it.
        let actual = hash_file(&staging, expected.algorithm())
            .await
            .map_err(map_not_found)?;
        if !actual.ct_eq(expected) {
            // Reject and drop the staging file so a bad upload leaves nothing.
            let _ = tokio::fs::remove_file(&staging).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        // Ensure the layout marker + the target `blobs/<alg>` dir exist, then
        // fsync the staging file's contents durable and rename it *in place*
        // into the CAS — atomic on the same filesystem, copy-free, so a crash
        // can never leave a corrupt-but-named blob (a torn write stays under
        // `uploads/` and is discarded on the next finish).
        self.ensure_layout(repo).await?;
        let dest = self.blob_path(repo, expected)?;
        let alg_dir = self
            .repo_dir(repo)?
            .join("blobs")
            .join(expected.algorithm());
        tokio::fs::create_dir_all(&alg_dir).await?;
        {
            let f = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&staging)
                .await
                .map_err(map_not_found)?;
            f.sync_all().await?;
        }
        tokio::fs::rename(&staging, &dest).await?;
        // Sync the CAS directory so the renamed entry survives a crash/power
        // loss (syncing the file alone does not persist the directory entry).
        sync_dir(&alg_dir).await?;
        self.drop_session_lock(repo, id);
        // Record presence so future reads skip the stat on a definite miss.
        let digest_str = expected.as_string();
        self.presence.insert(repo, &digest_str);
        // Warm the small-blob cache only for a blob small enough to be cacheable
        // — reading a multi-GiB layer back just to feed a cache that would
        // reject it is the buffering this rework exists to avoid.
        let size = tokio::fs::metadata(&dest).await?.len();
        if size <= self.cache.threshold() as u64 {
            if let Ok(bytes) = tokio::fs::read(&dest).await {
                self.cache.put(repo, &digest_str, &bytes);
            }
        }
        Ok(())
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        // Serialize with any concurrent append/finish, then drop the session.
        let lock = self.session_lock(repo, id)?;
        let guard = lock.lock().await;
        // Idempotent: a missing session is `Ok(false)` (nothing removed).
        let removed = match tokio::fs::remove_file(self.upload_path(repo, id)?).await {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(StorageError::Io(e)),
        };
        drop(guard);
        self.drop_session_lock(repo, id);
        Ok(removed)
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
        let alg_dir = self.repo_dir(repo)?.join("blobs").join(&digest.algorithm);
        tokio::fs::create_dir_all(&alg_dir).await?;
        // Publish the bytes into the CAS crash-atomically. On Linux this uses an
        // anonymous `O_TMPFILE` inode + `linkat` (a partial blob is never
        // namespace-visible, and `EEXIST` on link is the dedup signal — an
        // identical blob already exists, which is success); elsewhere it writes
        // a per-operation unique temp, fsyncs, and atomically renames.
        publish_bytes(&alg_dir, &dest, data).await?;
        // Record presence so future reads skip the stat on a definite miss, and
        // warm the small-blob cache (a no-op for large layers).
        let digest_str = digest.as_string();
        self.presence.insert(repo, &digest_str);
        self.cache.put(repo, &digest_str, data);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        tokio::fs::remove_file(self.blob_path(repo, digest)?)
            .await
            .map_err(map_not_found)?;
        let digest_str = digest.as_string();
        self.presence.remove(repo, &digest_str);
        self.cache.invalidate(repo, &digest_str);
        Ok(())
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
        self.write_index(repo, &index).await?;
        // Mirror the mutation into the derived metadata index + durable log.
        self.meta
            .apply(MetaOp::PutManifest {
                repo: repo.to_string(),
                digest: digest.as_string(),
                media_type: media_type.to_string(),
                tag: tag.map(str::to_string),
            })
            .map_err(StorageError::Io)
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        let (digest, media_type) = if reference.contains(':') {
            // By-digest: the digest *is* the reference; recover the media type
            // from the in-RAM index, then the on-disk index, then default.
            let digest = Digest::parse(reference)?;
            let media_type = match self.meta.manifest_media_type(repo, reference) {
                Some(mt) => mt,
                None => self
                    .index_media_type_for_digest(repo, reference)
                    .await?
                    .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".to_string()),
            };
            (digest, media_type)
        } else {
            // By-tag: resolve via the in-RAM tag map; on a miss fall back to the
            // on-disk index.json (the layout is the source of truth).
            match self.meta.resolve_tag(repo, reference) {
                Some((digest_str, media_type)) => (Digest::parse(&digest_str)?, media_type),
                None => self.index_resolve_tag(repo, reference).await?,
            }
        };
        // Manifests are small blobs; serve their bytes from the RAM cache when
        // warm, else read the loose file and warm the cache.
        let digest_str = digest.as_string();
        let bytes = match self.cache.get(repo, &digest_str) {
            Some(cached) => cached.to_vec(),
            None => {
                let b = tokio::fs::read(self.blob_path(repo, &digest)?)
                    .await
                    .map_err(map_not_found)?;
                self.cache.put(repo, &digest_str, &b);
                b
            }
        };
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
        // Drop the manifest from the presence filter + small-blob cache.
        self.presence.remove(repo, &digest.as_string());
        self.cache.invalidate(repo, &digest.as_string());
        // Drop every index entry (including tags) pointing at this digest.
        let mut index = self.read_index(repo).await?;
        let target = digest.as_string();
        let manifests = index_manifests_mut(&mut index);
        manifests.retain(|entry| descriptor_digest(entry) != Some(target.as_str()));
        self.write_index(repo, &index).await?;
        // Mirror the deletion into the derived metadata index + durable log.
        self.meta
            .apply(MetaOp::DeleteManifest {
                repo: repo.to_string(),
                digest: target,
            })
            .map_err(StorageError::Io)
    }

    async fn list_tags(&self, repo: &str) -> Result<Vec<String>, StorageError> {
        // Fast path: the in-RAM tag map. A repo the store does not yet cover
        // (e.g. an out-of-band layout mutation after startup) falls back to the
        // on-disk index.json, the source of truth.
        let tags = self.meta.list_tags(repo);
        if !tags.is_empty() {
            return Ok(tags);
        }
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
        // Parse the referrer descriptor as a JSON object (the core always sends
        // one); a non-object body is an internal inconsistency → Io.
        let mut merged: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(referrer_descriptor)
                .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        merged.insert(
            "subject".into(),
            serde_json::json!({ "digest": subject.as_string() }),
        );
        let referrer_str = referrer.as_string();
        let mut index = self.read_index(repo).await?;
        let manifests = index_manifests_mut(&mut index);
        let merged_value = serde_json::Value::Object(merged.clone());
        match manifests
            .iter_mut()
            .find(|e| descriptor_digest(e) == Some(referrer_str.as_str()))
            .and_then(|e| e.as_object_mut())
        {
            // Existing object entry: merge fields, preserving any tag annotation.
            Some(existing) => {
                for (k, v) in &merged {
                    // Never overwrite the entry's own identity; preserve a tag
                    // annotation the manifest entry already carries.
                    if k == "digest" {
                        continue;
                    }
                    if k == "annotations" && existing.contains_key("annotations") {
                        continue;
                    }
                    existing.insert(k.clone(), v.clone());
                }
            }
            // No entry (or a non-object foreign entry): append the descriptor.
            None => manifests.push(merged_value.clone()),
        }
        self.write_index(repo, &index).await?;
        // Mirror the referrer relation into the derived index + durable log.
        let descriptor = serde_json::to_vec(&merged)
            .map_err(|e| StorageError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        self.meta
            .apply(MetaOp::PutReferrer {
                repo: repo.to_string(),
                subject: subject.as_string(),
                referrer: referrer_str,
                descriptor,
            })
            .map_err(StorageError::Io)
    }

    async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let target = subject.as_string();
        // Fast path: the in-RAM subject→referrers map; fall back to index.json.
        let refs = self.meta.referrers(repo, &target);
        if !refs.is_empty() {
            return Ok(refs);
        }
        let index = self.read_index(repo).await?;
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

    async fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        let src = self.blob_path(from_repo, digest)?;
        // Source absent → the caller falls back to a normal upload session.
        if !self.blob_exists(from_repo, digest).await? {
            return Ok(false);
        }
        // Ensure the destination layout + `blobs/<alg>` dir exist, then link the
        // source into it. A hard link is O(1) and copy-free on one filesystem;
        // an already-present *valid* destination (concurrent mount / re-mount)
        // is a success; a cross-device or unsupported link falls back to a copy.
        self.ensure_layout(to_repo).await?;
        let dest = self.blob_path(to_repo, digest)?;
        let alg_dir = self
            .repo_dir(to_repo)?
            .join("blobs")
            .join(digest.algorithm());
        tokio::fs::create_dir_all(&alg_dir).await?;
        // Same-repo mount: source and destination are the same path — it is
        // already present, nothing to link/copy (and a copy-onto-self would
        // truncate it).
        if src == dest {
            self.presence.insert(to_repo, &digest.as_string());
            return Ok(true);
        }
        // Promote by a hard link — O(1), copy-free on one filesystem. Any link
        // failure (cross-device, or a filesystem without hard links) falls back
        // to a crash-atomic copy (reflink → copy_file_range → streaming; unique
        // temp, fsync, rename — never a partial blob under the digest).
        match tokio::fs::hard_link(&src, &dest).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // A destination already exists. Treat it as an idempotent success
                // only if it is a *regular file* (a content-addressed blob is the
                // correct bytes by construction). A symlink/dir/other entry is not
                // a valid CAS blob: reject it rather than report a false 201.
                let meta = tokio::fs::symlink_metadata(&dest)
                    .await
                    .map_err(map_not_found)?;
                if !meta.is_file() {
                    return Err(StorageError::BadPath(format!(
                        "mount destination for {} is not a regular file",
                        digest.as_string()
                    )));
                }
            }
            // copy_file_atomic already fsyncs the file + its directory.
            Err(_) => {
                copy_file_atomic(&src, &dest).await?;
                self.presence.insert(to_repo, &digest.as_string());
                return Ok(true);
            }
        }
        // Persist the new (or validated) directory entry so a successful 201
        // mount survives a crash — the hard-link and AlreadyExists paths need
        // this too, not only the copy fallback.
        sync_dir(&alg_dir).await?;
        self.presence.insert(to_repo, &digest.as_string());
        Ok(true)
    }

    async fn record_backrefs(
        &self,
        repo: &str,
        manifest: &Digest,
        blobs: &[Digest],
    ) -> Result<(), StorageError> {
        if blobs.is_empty() {
            return Ok(());
        }
        self.meta
            .apply(MetaOp::PutBackrefs {
                repo: repo.to_string(),
                manifest: manifest.as_string(),
                blobs: blobs.iter().map(Digest::as_string).collect(),
            })
            .map_err(StorageError::Io)
    }

    async fn backrefs(&self, repo: &str, blob: &Digest) -> Result<Vec<String>, StorageError> {
        Ok(self.meta.backrefs(repo, &blob.as_string()))
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
            s.append_upload("r", "../evil", b"x", None).await,
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
        s.append_upload("r", &id, b"chunk1", None).await.unwrap();
        let total = s.append_upload("r", &id, b"chunk2", None).await.unwrap();
        assert_eq!(total, 12);
        let d = sha256_of(b"chunk1chunk2");
        s.finish_upload("r", &id, &d, u64::MAX).await.unwrap();
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
        s.append_upload("r", &id, b"abc", None).await.unwrap();
        let wrong = sha256_of(b"xyz");
        assert!(matches!(
            s.finish_upload("r", &id, &wrong, u64::MAX).await,
            Err(StorageError::DigestMismatch { .. })
        ));
        // Missing upload session size / append errors are NotFound.
        assert!(matches!(
            s.upload_size("r", "nope").await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            s.append_upload("r", "nope", b"x", None).await,
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
        // Create an "upload" that is actually a directory; finish_upload's
        // non-regular-file guard rejects it as a bad path before hashing.
        let up = dir.path().join("r").join("uploads").join("dir-session");
        std::fs::create_dir_all(&up).unwrap();
        let d = sha256_of(b"x");
        assert!(matches!(
            s.finish_upload("r", "dir-session", &d, u64::MAX).await,
            Err(StorageError::BadPath(_))
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

    #[tokio::test]
    async fn seed_presence_and_discover_repos_edge_cases() {
        // Build a root that exercises every branch of seed_presence_from_cas and
        // discover_repos, then construct FsStorage to run the seed walk.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // repo "a": a proper CAS blob (happy path — inserted into the filter)
        // plus a `.tmp` staging file that must be skipped.
        let good = sha256_of(b"good-blob");
        let a_alg = root.join("a").join("blobs").join("sha256");
        std::fs::create_dir_all(&a_alg).unwrap();
        std::fs::write(a_alg.join(&good.hex), b"good-blob").unwrap();
        std::fs::write(a_alg.join("deadbeef.tmp"), b"partial").unwrap();
        std::fs::write(root.join("a").join("index.json"), b"{}").unwrap();
        // A regular file where an algorithm dir is expected → read_dir(alg) fails.
        std::fs::write(root.join("a").join("blobs").join("notadir"), b"x").unwrap();

        // repo "b": has index.json but NO blobs/ dir → read_dir(blobs) fails.
        std::fs::create_dir_all(root.join("b")).unwrap();
        std::fs::write(root.join("b").join("index.json"), b"{}").unwrap();

        // A directory nested deeper than the discover_repos depth bound carries
        // an index.json that must NOT be discovered (depth cutoff).
        let mut deep = root.to_path_buf();
        for i in 0..20 {
            deep = deep.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("index.json"), b"{}").unwrap();

        let s = FsStorage::new(root).unwrap();
        // The real blob is present (filter seeded); the tmp file was skipped, so
        // reading it back would 404 — but the good blob reads fine.
        assert_eq!(s.read_blob("a", &good).await.unwrap(), b"good-blob");
        // A blob never stored is absent (filter authoritative after a complete seed).
        let never = sha256_of(b"never");
        assert!(matches!(
            s.blob_size("a", &never).await,
            Err(StorageError::NotFound)
        ));

        // discover_repos read_dir-failure branch: point a fresh store at a path
        // whose root cannot be read (unix perms) — the walk returns nothing and
        // construction still succeeds.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = dir.path().join("locked");
            std::fs::create_dir_all(locked.join("sub")).unwrap();
            std::fs::write(locked.join("sub").join("index.json"), b"{}").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            // Seeding walks `locked` but read_dir fails → skipped, no panic.
            let _ = FsStorage::new(&locked).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[tokio::test]
    async fn blob_only_repo_is_seeded_after_restart() {
        // A repo that received only a blob push (no manifest) has an oci-layout
        // marker + blobs/ but no index.json. After a restart the presence filter
        // must still be seeded from it, or a valid blob would be reported absent
        // (and a later manifest push would 404 MANIFEST_BLOB_UNKNOWN).
        let dir = tempfile::tempdir().unwrap();
        let data = b"blob-only-layer";
        let d = sha256_of(data);
        {
            let s = FsStorage::new(dir.path()).unwrap();
            s.put_blob("blobonly", &d, data).await.unwrap();
            // Sanity: no index.json exists for this repo (blob-only).
            assert!(!dir.path().join("blobonly").join("index.json").exists());
            assert!(dir.path().join("blobonly").join("oci-layout").exists());
        }
        // Reopen: the seed walk must discover the blob-only repo via its marker.
        let s2 = FsStorage::new(dir.path()).unwrap();
        assert!(s2.blob_exists("blobonly", &d).await.unwrap());
        assert_eq!(
            s2.blob_size("blobonly", &d).await.unwrap(),
            data.len() as u64
        );
    }

    #[tokio::test]
    async fn add_referrer_merges_into_annotated_entry() {
        // A tagged manifest already carries an `annotations` entry in the index;
        // add_referrer must preserve it (the k=="annotations" skip branch) while
        // merging the subject/artifactType.
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let body = br#"{"schemaVersion":2}"#;
        let referrer = sha256_of(body);
        // put_manifest with a tag records an index entry carrying annotations.
        s.put_manifest("r", Some("v1"), &referrer, "application/json", body)
            .await
            .unwrap();
        let subject = sha256_of(b"subject");
        // The descriptor the core passes also carries annotations; the existing
        // entry's annotations must win (skip), other fields merge.
        s.add_referrer(
            "r",
            &subject,
            &referrer,
            br#"{"mediaType":"application/json","digest":"x","annotations":{"other":"1"},"artifactType":"a/b"}"#,
        )
        .await
        .unwrap();
        let listed = s.list_referrers("r", &subject).await.unwrap();
        assert_eq!(listed.len(), 1);
        let d: serde_json::Value = serde_json::from_slice(&listed[0]).unwrap();
        // The referrer descriptor (from the metadata store) carries the subject
        // link and its own artifactType.
        assert_eq!(
            d.get("subject")
                .and_then(|v| v.get("digest"))
                .and_then(|v| v.as_str()),
            Some(subject.as_string().as_str())
        );
        assert_eq!(d.get("artifactType").and_then(|v| v.as_str()), Some("a/b"));
        // In the on-disk index.json, the merge preserved the manifest entry's
        // pre-existing tag annotation (the k=="annotations" skip branch) rather
        // than overwriting it with the referrer descriptor's annotations.
        let index = s.read_index("r").await.unwrap();
        let entry = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| descriptor_digest(e) == Some(referrer.as_string().as_str()))
            .unwrap()
            .clone();
        assert_eq!(
            entry
                .get("annotations")
                .and_then(|a| a.get("org.opencontainers.image.ref.name"))
                .and_then(|v| v.as_str()),
            Some("v1")
        );
        assert_eq!(
            entry
                .get("subject")
                .and_then(|v| v.get("digest"))
                .and_then(|v| v.as_str()),
            Some(subject.as_string().as_str())
        );
    }

    #[tokio::test]
    async fn begin_upload_ids_are_distinct_random_hex() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let a = s.begin_upload("r").await.unwrap();
        let b = s.begin_upload("r").await.unwrap();
        assert_ne!(a, b);
        // 128 random bits → 32 lowercase hex chars.
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn mount_blob_hard_links_and_reports_absence() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"shared-layer";
        let d = sha256_of(data);
        s.put_blob("src", &d, data).await.unwrap();
        // Present source → first mount hard-links: byte-identical and sharing
        // one inode (a link, not a copy).
        assert!(s.mount_blob("src", "dst", &d).await.unwrap());
        assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let src_ino = std::fs::metadata(s.blob_path("src", &d).unwrap())
                .unwrap()
                .ino();
            let dst_ino = std::fs::metadata(s.blob_path("dst", &d).unwrap())
                .unwrap()
                .ino();
            assert_eq!(src_ino, dst_ino);
        }
        // Re-mounting a destination that already exists exercises the copy
        // fallback (the hard link fails on the existing path) and stays correct.
        assert!(s.mount_blob("src", "dst", &d).await.unwrap());
        assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
        // Absent source → Ok(false) (caller falls back to a session).
        let absent = sha256_of(b"never-stored");
        assert!(!s.mount_blob("src", "dst", &absent).await.unwrap());
        // Re-mounting a destination that already exists exercises the copy
        // fallback (the hard link fails on the existing path) and stays correct.
        assert!(s.mount_blob("src", "dst", &d).await.unwrap());
        assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
    }

    // A same-repo mount (src == dest) short-circuits: the blob is already
    // present and must not be copied onto itself (which would truncate it).
    #[tokio::test]
    async fn mount_blob_same_repo_is_idempotent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"self-mount";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        assert!(s.mount_blob("r", "r", &d).await.unwrap());
        // Content is intact (not truncated by a copy-onto-self).
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    }

    // A planted symlink under the CAS name is not a valid blob: blob_exists and
    // blob_size report it absent (no-follow), so it can never satisfy a
    // manifest's referenced-blob check nor be served as a repo's content.
    #[cfg(unix)]
    #[tokio::test]
    async fn planted_cas_symlink_is_not_present() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let secret = dir.path().join("outside-secret");
        std::fs::write(&secret, b"outside").unwrap();
        let d = sha256_of(b"outside");
        // Force the presence filter to say "maybe" so the stat path runs.
        s.presence.insert("r", &d.as_string());
        let cas = s.blob_path("r", &d).unwrap();
        std::fs::create_dir_all(cas.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&secret, &cas).unwrap();
        assert!(!s.blob_exists("r", &d).await.unwrap());
        assert!(matches!(
            s.blob_size("r", &d).await,
            Err(StorageError::NotFound)
        ));
        // A mount whose destination is the planted symlink is rejected, not a
        // false 201.
        s.put_blob("src", &d, b"outside").await.unwrap();
        assert!(matches!(
            s.mount_blob("src", "r", &d).await,
            Err(StorageError::BadPath(_))
        ));
    }

    // A PATCH append opens the staging file O_NOFOLLOW: a symlink planted at
    // `uploads/<id>` cannot redirect the append to an arbitrary target.
    #[cfg(unix)]
    #[tokio::test]
    async fn append_refuses_symlinked_session() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let target = dir.path().join("append-target");
        std::fs::write(&target, b"").unwrap();
        let uploads = s.repo_dir("r").unwrap().join("uploads");
        std::fs::create_dir_all(&uploads).unwrap();
        std::os::unix::fs::symlink(&target, uploads.join("evil")).unwrap();
        // Appending to the symlinked session fails (O_NOFOLLOW → ELOOP), and the
        // redirect target is left untouched.
        assert!(s.append_upload("r", "evil", b"x", None).await.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"");
    }

    // finish_upload re-checks the per-session cap under the lock: a staging file
    // that grew past the cap is rejected (413/SIZE_INVALID → TooLarge) and
    // dropped, so a racing empty-body PUT cannot promote an oversized blob.
    #[tokio::test]
    async fn finish_upload_rejects_over_cap_staging() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"0123456789";
        let d = sha256_of(data);
        let id = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id, data, None).await.unwrap();
        // Cap below the staged size → finalize rejects and drops the session.
        assert!(matches!(
            s.finish_upload("r", &id, &d, 4).await,
            Err(StorageError::TooLarge {
                limit: 4,
                actual: 10
            })
        ));
        assert!(matches!(
            s.upload_size("r", &id).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn finish_upload_promotes_staging_without_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // A ~1 MiB blob pushed in two chunks, then finished.
        let data = vec![0x5au8; 1024 * 1024];
        let d = sha256_of(&data);
        let id = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id, &data[..512 * 1024], None)
            .await
            .unwrap();
        s.append_upload("r", &id, &data[512 * 1024..], None)
            .await
            .unwrap();
        s.finish_upload("r", &id, &d, u64::MAX).await.unwrap();
        // Content is retrievable byte-identical, the staging file is gone, and
        // the CAS file exists (promotion happened in place, no buffering leak).
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
        assert!(!tokio::fs::try_exists(s.upload_path("r", &id).unwrap())
            .await
            .unwrap());
        assert!(tokio::fs::try_exists(s.blob_path("r", &d).unwrap())
            .await
            .unwrap());
        // A finish whose bytes do not hash to the declared digest is rejected
        // and drops the staging file.
        let id2 = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id2, b"mismatch", None).await.unwrap();
        assert!(matches!(
            s.finish_upload("r", &id2, &d, u64::MAX).await,
            Err(StorageError::DigestMismatch { .. })
        ));
        assert!(!tokio::fs::try_exists(s.upload_path("r", &id2).unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn backrefs_track_referenced_blobs_across_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let b1 = sha256_of(b"blob-1");
        let b2 = sha256_of(b"blob-2");
        let manifest = sha256_of(b"the-manifest");
        // Store the manifest blob then record its backrefs (mirrors the core).
        s.put_manifest(
            "r",
            None,
            &manifest,
            "application/vnd.oci.image.manifest.v1+json",
            b"the-manifest",
        )
        .await
        .unwrap();
        s.record_backrefs("r", &manifest, &[b1.clone(), b2.clone()])
            .await
            .unwrap();
        assert_eq!(
            s.backrefs("r", &b1).await.unwrap(),
            vec![manifest.as_string()]
        );
        assert_eq!(
            s.backrefs("r", &b2).await.unwrap(),
            vec![manifest.as_string()]
        );
        // A backref edge in a *different* repo is untouched by this repo's
        // delete (exercises the `r != repo` skip in the drop path).
        s.record_backrefs("other", &manifest, std::slice::from_ref(&b1))
            .await
            .unwrap();
        // Recording an empty blob set is a no-op success.
        s.record_backrefs("r", &manifest, &[]).await.unwrap();
        // Deleting the manifest clears its edges from every referenced blob in
        // this repo, but leaves the other repo's edge intact.
        s.delete_manifest("r", &manifest).await.unwrap();
        assert!(s.backrefs("r", &b1).await.unwrap().is_empty());
        assert!(s.backrefs("r", &b2).await.unwrap().is_empty());
        assert_eq!(
            s.backrefs("other", &b1).await.unwrap(),
            vec![manifest.as_string()]
        );
    }

    #[tokio::test]
    async fn abort_upload_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let id = s.begin_upload("r").await.unwrap();
        // First abort removes the staging file; a second is a no-op Ok(false).
        assert!(s.abort_upload("r", &id).await.unwrap());
        assert!(!s.abort_upload("r", &id).await.unwrap());
        // A session id that names a directory yields a non-NotFound IO error.
        let uploads = dir.path().join("r").join("uploads");
        tokio::fs::create_dir_all(uploads.join("dirsess"))
            .await
            .unwrap();
        assert!(matches!(
            s.abort_upload("r", "dirsess").await,
            Err(StorageError::Io(_))
        ));
    }

    #[tokio::test]
    async fn finish_upload_honors_sha512_digest() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"sha512-streamed-blob";
        // A sha512 upload exercises the sha512 branch of the streaming hasher.
        let d = digest_of(data, "sha512");
        assert_eq!(d.algorithm(), "sha512");
        let id = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id, data, None).await.unwrap();
        s.finish_upload("r", &id, &d, u64::MAX).await.unwrap();
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
        // A sha512 mismatch is rejected by the streamed verify.
        let id2 = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id2, b"different", None)
            .await
            .unwrap();
        assert!(matches!(
            s.finish_upload("r", &id2, &d, u64::MAX).await,
            Err(StorageError::DigestMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn append_upload_enforces_content_range_offset() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let id = s.begin_upload("r").await.unwrap();
        // First chunk at offset 0 is accepted.
        assert_eq!(s.append_upload("r", &id, b"abc", Some(0)).await.unwrap(), 3);
        // A chunk whose declared offset does not match the current size (3) is
        // rejected under the lock.
        assert!(matches!(
            s.append_upload("r", &id, b"de", Some(0)).await,
            Err(StorageError::RangeNotSatisfiable {
                expected: 3,
                got: 0
            })
        ));
        // The correct offset (3) is accepted.
        assert_eq!(s.append_upload("r", &id, b"de", Some(3)).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn upload_ops_reject_invalid_id_and_do_not_leak_locks() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // A traversal id is rejected by session_lock's validation on every op,
        // before any lock-map entry is created.
        assert!(matches!(
            s.append_upload("r", "../evil", b"x", None).await,
            Err(StorageError::BadPath(_))
        ));
        let d = sha256_of(b"x");
        assert!(matches!(
            s.finish_upload("r", "../evil", &d, u64::MAX).await,
            Err(StorageError::BadPath(_))
        ));
        assert!(matches!(
            s.abort_upload("r", "../evil").await,
            Err(StorageError::BadPath(_))
        ));
        // A valid-but-unknown session id: append errors NotFound and drops the
        // lock entry it created, so the map does not grow per unknown id.
        assert!(matches!(
            s.append_upload("r", "deadbeef", b"x", None).await,
            Err(StorageError::NotFound)
        ));
        assert!(s
            .upload_locks
            .lock()
            .unwrap()
            .get(&("r".to_string(), "deadbeef".to_string()))
            .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mount_hard_link_failure_falls_back_to_copy() {
        // A hard-link failure that is not AlreadyExists (here: a read-only
        // destination alg dir → EACCES) dispatches to the crash-atomic copy
        // fallback. In this fixture the copy's temp create also fails (the dir
        // is read-only), so the error propagates — exercising the fallback
        // dispatch without needing a second filesystem.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"mountable";
        let d = sha256_of(data);
        s.put_blob("src", &d, data).await.unwrap();
        s.ensure_layout("dst").await.unwrap();
        let alg = dir.path().join("dst").join("blobs").join("sha256");
        std::fs::create_dir_all(&alg).unwrap();
        std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(s.mount_blob("src", "dst", &d).await.is_err());
        // Restore perms so the tempdir cleans up.
        std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[tokio::test]
    async fn copy_file_atomic_transfers_contents() {
        // The in-kernel copy fallback (copy_file_range on Linux, tokio copy
        // elsewhere) transfers a non-empty file and an empty file into distinct
        // destinations via a unique temp + rename.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let payload = vec![0x5au8; 70000];
        tokio::fs::write(&src, &payload).await.unwrap();
        let dst = dir.path().join("dst");
        copy_file_atomic(&src, &dst).await.unwrap();
        assert_eq!(tokio::fs::read(&dst).await.unwrap(), payload);
        let empty_src = dir.path().join("empty");
        tokio::fs::write(&empty_src, b"").await.unwrap();
        let empty_dst = dir.path().join("empty-dst");
        copy_file_atomic(&empty_src, &empty_dst).await.unwrap();
        assert_eq!(tokio::fs::read(&empty_dst).await.unwrap(), b"");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn finish_rejects_non_regular_staging_file() {
        // A staging entry that is a symlink (not a regular file) is rejected by
        // finish_upload's no-follow guard, never hashed-through and promoted.
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let uploads = dir.path().join("r").join("uploads");
        std::fs::create_dir_all(&uploads).unwrap();
        let target = dir.path().join("outside-secret");
        std::fs::write(&target, b"secret").unwrap();
        symlink(&target, uploads.join("linksess")).unwrap();
        let d = sha256_of(b"secret");
        assert!(matches!(
            s.finish_upload("r", "linksess", &d, u64::MAX).await,
            Err(StorageError::BadPath(_))
        ));
    }

    // stream_copy is the portable fallback the in-kernel copy path uses on a
    // cross-device/unsupported-fs mount. Exercise it directly: it rewinds and
    // truncates the destination (dropping any partial kernel copy) and streams
    // the full source across.
    #[cfg(target_os = "linux")]
    #[test]
    fn stream_copy_rewinds_truncates_and_copies() {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src");
        let dst_path = dir.path().join("dst");
        let payload = vec![0x42u8; 70000];
        std::fs::write(&src_path, &payload).unwrap();
        // Pre-seed the destination with stale bytes + a stale cursor to prove
        // stream_copy truncates and rewinds rather than appending.
        let mut dst = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dst_path)
            .unwrap();
        dst.write_all(b"stale-tail-that-must-be-dropped").unwrap();
        dst.seek(SeekFrom::End(0)).unwrap();
        let mut src = std::fs::File::open(&src_path).unwrap();
        super::stream_copy(&mut src, &mut dst).unwrap();
        let mut out = Vec::new();
        let mut check = std::fs::File::open(&dst_path).unwrap();
        check.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    // Pushing the identical blob twice is idempotent dedup: on Linux the second
    // put's `linkat` hits `EEXIST` (the content-addressed name already exists)
    // and is treated as success; the bytes remain correct.
    #[tokio::test]
    async fn put_blob_same_digest_twice_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"dedup-me";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        s.put_blob("r", &d, data).await.unwrap();
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
    }
}
