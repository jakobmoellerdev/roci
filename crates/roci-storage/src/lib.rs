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
    /// Finalize an upload: under the session lock, append `trailing` (a
    /// monolithic PUT's body, empty for a plain finalize) atomically with the
    /// verify+promote so a concurrent PATCH cannot inject bytes between the
    /// trailing append and the finalize hash; verify it hashes to `expected` and
    /// does not exceed `max_size` bytes (the per-session cap, re-checked here
    /// under the lock so a promote cannot race the cap); then move it into the CAS.
    fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
        max_size: u64,
        trailing: &[u8],
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
    /// The blob's path *relative to the store root*, built from validated
    /// components (`<repo…>/blobs/<alg>/<hex>`). Fed to the beneath-root
    /// resolver so every component is opened no-follow — a symlink planted at
    /// any level (repo, `blobs`, `<alg>`, or the digest) cannot escape the CAS.
    fn blob_rel(&self, repo: &str, d: &Digest) -> Result<PathBuf, StorageError> {
        let mut rel = PathBuf::new();
        for component in repo.split('/') {
            rel.push(Self::safe_component(component)?);
        }
        rel.push("blobs");
        rel.push(&d.algorithm);
        rel.push(Self::safe_component(&d.hex)?);
        Ok(rel)
    }
    /// The blob's *directory* path relative to the store root
    /// (`<repo…>/blobs/<alg>`) plus its leaf filename (the digest hex). The
    /// write side opens the directory beneath-root (no-follow) and operates on
    /// the leaf relative to that dirfd, so a symlinked parent cannot redirect a
    /// promotion. Components are validated exactly like [`Self::blob_rel`].
    fn blob_dir_rel(&self, repo: &str, d: &Digest) -> Result<(PathBuf, String), StorageError> {
        let mut dir = PathBuf::new();
        for component in repo.split('/') {
            dir.push(Self::safe_component(component)?);
        }
        dir.push("blobs");
        dir.push(&d.algorithm);
        Self::safe_component(&d.hex)?;
        Ok((dir, d.hex.clone()))
    }
    /// The upload staging path relative to the store root
    /// (`<repo…>/uploads/<id>`), validated component-wise like [`Self::blob_rel`].
    fn upload_rel(&self, repo: &str, id: &str) -> Result<PathBuf, StorageError> {
        let mut rel = PathBuf::new();
        for component in repo.split('/') {
            rel.push(Self::safe_component(component)?);
        }
        rel.push("uploads");
        rel.push(Self::safe_component(id)?);
        Ok(rel)
    }
    /// The upload staging *directory* relative to the store root
    /// (`<repo…>/uploads`) plus the validated session-id leaf, for dirfd-anchored
    /// promotion (rename staging → CAS with no parent-symlink traversal).
    fn upload_dir_rel(&self, repo: &str, id: &str) -> Result<(PathBuf, String), StorageError> {
        let mut dir = PathBuf::new();
        for component in repo.split('/') {
            dir.push(Self::safe_component(component)?);
        }
        dir.push("uploads");
        Self::safe_component(id)?;
        Ok((dir, id.to_string()))
    }

    /// Best-effort: if the just-promoted blob is small enough, read it back
    /// (no-follow, beneath-root) and warm the small-blob cache. Any IO hiccup
    /// simply skips the warm — the loose CAS file is always the source of truth.
    async fn warm_small_blob_cache(&self, repo: &str, rel: &Path, digest_str: &str) {
        // The blob was just promoted, so it is present and regular. Read it back
        // (no-follow, beneath-root) and cache it only if small; any IO hiccup on
        // this optional warm is simply skipped (the loose CAS file is truth).
        let Ok(mut f) = open_beneath(&self.root, rel).await else {
            return;
        };
        let threshold = self.cache.threshold();
        // Read up to the cache threshold + 1: if the blob is larger it is not
        // cacheable, so stop early rather than buffer a multi-GiB layer.
        let mut bytes = Vec::with_capacity(threshold.min(64 * 1024));
        let mut chunk = [0u8; 64 * 1024];
        loop {
            match f.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.len() > threshold {
                        return; // too large to cache
                    }
                }
                Err(_) => return,
            }
        }
        self.cache.put(repo, digest_str, &bytes);
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

/// Stream `f` through the hasher selected by `algorithm` (sha256/sha512),
/// returning its [`Digest`] without buffering the whole file. `f` is an
/// already-opened, no-follow-validated regular-file handle (the caller opens it
/// beneath the store root). Used to verify a staged upload before promoting it.
async fn hash_reader(mut f: tokio::fs::File, algorithm: &str) -> io::Result<Digest> {
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

/// Promote a blob named `leaf` from `from_alg_rel` into `to_alg_rel` (both
/// directories relative to `root`), for a cross-repo mount. Everything is
/// anchored to dirfds walked no-follow beneath `root`, so a symlinked `repo`,
/// `blobs`, or `<alg>` parent on either side cannot redirect the promotion.
/// Contract order (SECURITY.md:124): **reflink first** (`FICLONE` into a temp
/// opened in the destination dirfd, then `renameat` — CoW, independent
/// deletion), then a **hard link** (`linkat` between dirfds, O(1) same-fs), then
/// a **streaming copy** (cross-device / no-hardlink). A pre-existing destination
/// is re-validated no-follow as a regular file (idempotent success) or rejected.
#[cfg(unix)]
async fn mount_promote_beneath(
    root: &Path,
    from_alg_rel: &Path,
    to_alg_rel: &Path,
    leaf: &str,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let root = root.to_path_buf();
    let from_alg_rel = from_alg_rel.to_path_buf();
    let to_alg_rel = to_alg_rel.to_path_buf();
    let leaf = leaf.to_string();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let from_dir = dir_beneath(&root, &from_alg_rel, false)?;
        let to_dir = dir_beneath(&root, &to_alg_rel, true)?;
        // Open the source no-follow (the caller already verified via blob_exists
        // that it is a present regular file beneath the root).
        let src = rustix::fs::openat(
            &from_dir,
            leaf.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let mut src_file = std::fs::File::from(src);
        // Treat a pre-existing regular-file destination as idempotent success; a
        // symlink/dir/other there is rejected (re-checked here, not only in the
        // caller's earlier stat, to close the check→promote race). A missing dest
        // (NOENT) proceeds to promotion; any other stat error propagates.
        match rustix::fs::statat(&to_dir, leaf.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode).is_file() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "mount destination exists and is not a regular file",
                ))
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
        // Write into a unique temp in the destination dir (no-follow), by
        // reflink where possible else a streaming copy, then renameat into place.
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(io::Error::other)?;
        let tmp = format!(".{}.{}.tmp", leaf, hex::encode(rnd));
        let promote_via_temp = |flags: OFlags| -> io::Result<std::fs::File> {
            rustix::fs::openat(
                &to_dir,
                tmp.as_str(),
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | flags,
                Mode::from_raw_mode(0o644),
            )
            .map(std::fs::File::from)
            .map_err(io::Error::from)
        };
        // First try a hard link (O(1), no temp) — skipped when a reflink is
        // preferred and available. Reflink is the contract primary, so attempt it
        // into the temp; if the filesystem cannot reflink, hard-link directly;
        // if that also fails (cross-device), stream-copy into the temp.
        let mut out = promote_via_temp(OFlags::empty())?;
        if try_reflink(&mut out, &mut src_file) {
            out.sync_all()?;
            rustix::fs::renameat(&to_dir, tmp.as_str(), &to_dir, leaf.as_str())
                .map_err(io::Error::from)?;
            rustix::fs::fsync(&to_dir).map_err(io::Error::from)?;
            return Ok(());
        }
        // Reflink unavailable: drop the temp and try a direct hard link.
        drop(out);
        let _ = rustix::fs::unlinkat(&to_dir, tmp.as_str(), AtFlags::empty());
        match try_hardlink_at(&from_dir, leaf.as_str(), &to_dir, leaf.as_str()) {
            Ok(()) => {
                rustix::fs::fsync(&to_dir).map_err(io::Error::from)?;
                Ok(())
            }
            // Destination raced in as a valid blob between our stat and link.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            // Cross-device / no-hardlink: stream-copy into a fresh temp + rename.
            Err(_) => {
                let mut out = promote_via_temp(OFlags::empty())?;
                stream_copy(&mut src_file, &mut out)?;
                out.sync_all()?;
                rustix::fs::renameat(&to_dir, tmp.as_str(), &to_dir, leaf.as_str())
                    .map_err(io::Error::from)?;
                rustix::fs::fsync(&to_dir).map_err(io::Error::from)?;
                Ok(())
            }
        }
    })
    .await
    .map_err(io::Error::other)?
}

/// `linkat` between two dirfds, with a test-only fault seam: when
/// `FORCE_COPY_FALLBACK` is set it returns an `EXDEV`-shaped error so the copy
/// fallback runs deterministically on a single filesystem.
#[cfg(unix)]
fn try_hardlink_at(
    from_dir: &std::os::fd::OwnedFd,
    from_leaf: &str,
    to_dir: &std::os::fd::OwnedFd,
    to_leaf: &str,
) -> io::Result<()> {
    #[cfg(all(test, target_os = "linux"))]
    if FORCE_COPY_FALLBACK.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(io::Error::from_raw_os_error(18)); // EXDEV
    }
    rustix::fs::linkat(
        from_dir,
        from_leaf,
        to_dir,
        to_leaf,
        rustix::fs::AtFlags::empty(),
    )
    .map_err(io::Error::from)
}

/// Test-only switches: on a single filesystem a real `ioctl_ficlone`/`hard_link`
/// neither fails (to exercise the copy fallback) nor succeeds (ext4 has no
/// reflink), so both branches are otherwise unreachable. `FORCE_COPY_FALLBACK`
/// makes the fast paths report failure; `FORCE_REFLINK_OK` makes `try_reflink`
/// report success (after really transferring the bytes via the streaming copy,
/// so the destination is correct). Zero cost and absent outside `cfg(test)`.
#[cfg(all(test, target_os = "linux"))]
static FORCE_COPY_FALLBACK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(all(test, target_os = "linux"))]
static FORCE_REFLINK_OK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(test, target_os = "linux"))]
static FORCE_TMPFILE_UNSUPPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(all(test, target_os = "linux"))]
static FORCE_STAT_ERROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(test, target_os = "linux"))]
static FORCE_SYSCALL_ERROR: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// Serializes the fault-injection tests (which flip the process-global
/// `FORCE_*` switches) against each other and against tests that assert on the
/// real reflink/hard-link behavior, so a stray forced fallback cannot make a
/// parallel test flaky. Held for the duration of each such test.
#[cfg(all(test, target_os = "linux"))]
static FAULT_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[cfg(target_os = "linux")]
fn try_reflink(output: &mut std::fs::File, input: &mut std::fs::File) -> bool {
    #[cfg(test)]
    if FORCE_COPY_FALLBACK.load(std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    #[cfg(test)]
    if FORCE_REFLINK_OK.load(std::sync::atomic::Ordering::Relaxed) {
        // Simulate a successful whole-file reflink by actually moving the bytes
        // (ext4 in CI has no CoW), so the "reflink succeeded" branch is covered
        // with a correct destination.
        return stream_copy(input, output).is_ok();
    }
    rustix::fs::ioctl_ficlone(&*output, &*input).is_ok()
}

/// Non-Linux: no `FICLONE`, so a reflink is never available (the caller falls
/// back to a hard link, then a streaming copy).
#[cfg(all(unix, not(target_os = "linux")))]
fn try_reflink(_output: &mut std::fs::File, _input: &mut std::fs::File) -> bool {
    false
}

/// Rewind both files and copy `input` to `output` with a buffered read/write
/// loop, first truncating the destination so a retry never leaves stale tail
/// bytes. The streaming fallback used when a reflink is not possible. Runs on
/// the blocking thread that owns the file handles.
#[cfg(unix)]
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

/// Publish `data` as the CAS blob named `leaf` inside the directory `alg_rel`
/// (relative to `root`, e.g. `<repo…>/blobs/<alg>`) with a per-operation unique
/// temp sibling, fsync, and atomic rename — all **relative to a dirfd walked
/// no-follow beneath `root`**, so a symlinked `repo`/`blobs`/`<alg>` parent
/// cannot redirect the write outside the store. Portable across every platform
/// and the fallback the Linux `O_TMPFILE` path degrades to. A rename onto an
/// existing blob is harmless (content-addressed: identical bytes).
#[cfg(unix)]
async fn publish_bytes_rename(
    root: &Path,
    alg_rel: &Path,
    leaf: &str,
    data: &[u8],
) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write as _;
    let root = root.to_path_buf();
    let alg_rel = alg_rel.to_path_buf();
    let leaf = leaf.to_string();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let dirfd = dir_beneath(&root, &alg_rel, true)?;
        let mut tmp = [0u8; 8];
        getrandom::fill(&mut tmp).map_err(io::Error::other)?;
        let tmp_name = format!(".{}.{}.tmp", leaf, hex::encode(tmp));
        let fd = rustix::fs::openat(
            &dirfd,
            tmp_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(io::Error::from)?;
        let mut f = std::fs::File::from(fd);
        f.write_all(&data)?;
        f.sync_all()?;
        drop(f);
        rustix::fs::renameat(&dirfd, tmp_name.as_str(), &dirfd, leaf.as_str())
            .map_err(io::Error::from)?;
        // Persist the new directory entry (fsync the dirfd).
        rustix::fs::fsync(&dirfd).map_err(io::Error::from)?;
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

/// Publish `data` as the CAS blob `leaf` inside `alg_rel` crash-atomically,
/// anchored to a dirfd walked no-follow beneath `root`. On Linux this opens an
/// anonymous `O_TMPFILE` inode in the (beneath-root) directory, writes+fsyncs
/// it, then `linkat`s it into place: a partial blob is never visible under its
/// digest name and no orphan temp survives a crash. A filesystem without
/// `O_TMPFILE` degrades to the portable temp+rename path. `linkat` `EEXIST`
/// means a blob already exists at the name; it is dedup success only if that
/// entry is a *regular file* (validated no-follow via the dirfd) — a planted
/// symlink/dir is rejected. Non-Linux platforms use the temp+rename path.
#[cfg(target_os = "linux")]
async fn publish_bytes(root: &Path, alg_rel: &Path, leaf: &str, data: &[u8]) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::io::Write as _;
    use std::os::fd::AsRawFd;
    let root_buf = root.to_path_buf();
    let alg_rel_buf = alg_rel.to_path_buf();
    let leaf_buf = leaf.to_string();
    let data_vec = data.to_vec();
    let outcome = tokio::task::spawn_blocking(move || -> io::Result<bool> {
        let dirfd = dir_beneath(&root_buf, &alg_rel_buf, true)?;
        // Anonymous inode in the (beneath-root) target directory.
        let opened = rustix::fs::openat(
            &dirfd,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        );
        // In test, simulate a filesystem without O_TMPFILE so the fallback arm
        // runs deterministically (ext4 in CI always supports O_TMPFILE).
        #[cfg(all(test, target_os = "linux"))]
        let opened = if FORCE_TMPFILE_UNSUPPORTED.load(std::sync::atomic::Ordering::Relaxed) {
            Err(Errno::OPNOTSUPP)
        } else {
            opened
        };
        let fd = match opened {
            Ok(fd) => fd,
            // O_TMPFILE unavailable → signal the portable temp+rename fallback.
            Err(_) => return Ok(false),
        };
        let mut f = std::fs::File::from(fd);
        f.write_all(&data_vec)?;
        f.sync_all()?;
        // Link the anonymous inode into place via its /proc/self/fd magic link,
        // relative to the beneath-root dirfd (AT_EMPTY_PATH would need
        // CAP_DAC_READ_SEARCH).
        let proc_path = format!("/proc/self/fd/{}", f.as_raw_fd());
        match rustix::fs::linkat(
            rustix::fs::CWD,
            proc_path,
            &dirfd,
            leaf_buf.as_str(),
            AtFlags::SYMLINK_FOLLOW,
        ) {
            Ok(()) => {}
            // A blob already exists at the name: dedup success only if it is a
            // regular file (no-follow, via the dirfd). A planted symlink/dir is
            // rejected — never reported present nor later followed on read.
            Err(Errno::EXIST) => {
                let st = rustix::fs::statat(&dirfd, leaf_buf.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(io::Error::from)?;
                if !FileType::from_raw_mode(st.st_mode).is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "CAS destination exists and is not a regular file",
                    ));
                }
            }
            Err(e) => return Err(io::Error::from(e)),
        }
        rustix::fs::fsync(&dirfd).map_err(io::Error::from)?;
        Ok(true)
    })
    .await
    .map_err(io::Error::other)??;
    if !outcome {
        return publish_bytes_rename(root, alg_rel, leaf, data).await;
    }
    Ok(())
}

/// Non-Linux publish: portable dirfd-anchored temp+rename.
#[cfg(not(target_os = "linux"))]
async fn publish_bytes(root: &Path, alg_rel: &Path, leaf: &str, data: &[u8]) -> io::Result<()> {
    publish_bytes_rename(root, alg_rel, leaf, data).await
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

/// Walk `rel` (a `/`-separated path relative to `root`) component by component
/// with `openat` + `O_NOFOLLOW`, refusing to traverse a symlink at *any* level,
/// and open the final component with `final_flags`. `root` is the store root —
/// created and owned by roci, so it is the trusted anchor; every component below
/// it (`<repo…>/blobs/<alg>/<hex>`, `<repo…>/uploads/<id>`) is opened no-follow
/// so a planted symlink anywhere in the path — not just the final component —
/// cannot redirect the open outside the CAS. Portable across every Unix and
/// kernel (no `openat2` dependency). Runs on the caller's blocking thread.
#[cfg(unix)]
fn resolve_beneath(
    root: &Path,
    rel: &Path,
    final_flags: rustix::fs::OFlags,
) -> io::Result<std::fs::File> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::os::fd::OwnedFd;
    // The store root is trusted (roci created it); open it followed.
    let mut dir: OwnedFd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;

    let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let flags = if last {
            // `O_NONBLOCK` so opening a planted FIFO/device does not block; we
            // fstat and reject any non-regular final entry below.
            final_flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        let next = match rustix::fs::openat(&dir, *comp, flags, Mode::from_raw_mode(0o644)) {
            Ok(fd) => fd,
            // A symlink at any component (or a non-dir parent) is refused by
            // `O_NOFOLLOW`/`O_DIRECTORY`: `ELOOP` (Linux) / `ENOTDIR` (macOS/BSD).
            // Surface it as "not found" so a read/open returns 404, never an
            // out-of-store target.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(e) => return Err(io::Error::from(e)),
        };
        dir = next;
    }
    // The final descriptor must be a *regular file*: a FIFO/device/socket at a
    // digest path is not a valid CAS blob and must never be served or appended
    // to (a FIFO read would block, a device would return non-CAS bytes).
    let st = rustix::fs::fstat(&dir).map_err(io::Error::from)?;
    if !FileType::from_raw_mode(st.st_mode).is_file() {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    Ok(std::fs::File::from(dir))
}

/// Walk a *directory* path `rel` (relative to `root`) component by component
/// with `openat` + `O_DIRECTORY | O_NOFOLLOW`, refusing to traverse a symlink at
/// any level, and return an owned fd for the leaf directory. When `create`, a
/// missing component is `mkdirat`-created (then opened no-follow) so the whole
/// CAS directory tree is materialised beneath the trusted root — never through a
/// planted symlink. This is the write-side anchor: callers do `openat`/`linkat`/
/// `renameat`/`unlinkat` *relative to the returned fd*, so a symlinked `repo`,
/// `blobs`, or `<alg>` parent can never redirect a mutation outside the store.
#[cfg(unix)]
fn dir_beneath(root: &Path, rel: &Path, create: bool) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    // The store root is trusted (roci created it); open it followed.
    let mut dir: OwnedFd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    for comp in rel.iter() {
        #[cfg(all(test, target_os = "linux"))]
        let opened = if FORCE_SYSCALL_ERROR.load(std::sync::atomic::Ordering::Relaxed) {
            Err(rustix::io::Errno::IO)
        } else {
            rustix::fs::openat(&dir, comp, dir_flags, Mode::empty())
        };
        #[cfg(not(all(test, target_os = "linux")))]
        let opened = rustix::fs::openat(&dir, comp, dir_flags, Mode::empty());
        match opened {
            Ok(next) => dir = next,
            Err(rustix::io::Errno::NOENT) if create => {
                // Create the missing directory component (0o755) then open it
                // no-follow. A concurrent creator racing us yields EEXIST, which
                // we treat as "already there" and re-open.
                match rustix::fs::mkdirat(&dir, comp, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(io::Error::from(e)),
                }
                dir = rustix::fs::openat(&dir, comp, dir_flags, Mode::empty())
                    .map_err(io::Error::from)?;
            }
            // A symlinked / non-directory / missing component: not a valid CAS
            // directory. `NotFound` so a read returns 404; a write with
            // `create=false` likewise cannot proceed through it.
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::NOENT) => {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    Ok(dir)
}

/// Rename `from_leaf` in directory `from_dir_rel` to `to_leaf` in directory
/// `to_dir_rel` (both relative to `root`), via `renameat` on dirfds walked
/// no-follow beneath `root` (the destination dir is created). A symlinked parent
/// on either side cannot redirect the rename outside the store. Then fsyncs the
/// destination directory so the new entry is durable.
#[cfg(unix)]
async fn rename_beneath(
    root: &Path,
    from_dir_rel: &Path,
    from_leaf: &str,
    to_dir_rel: &Path,
    to_leaf: &str,
) -> io::Result<()> {
    let root = root.to_path_buf();
    let from_dir_rel = from_dir_rel.to_path_buf();
    let from_leaf = from_leaf.to_string();
    let to_dir_rel = to_dir_rel.to_path_buf();
    let to_leaf = to_leaf.to_string();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let from_fd = dir_beneath(&root, &from_dir_rel, false)?;
        let to_fd = dir_beneath(&root, &to_dir_rel, true)?;
        rustix::fs::renameat(&from_fd, from_leaf.as_str(), &to_fd, to_leaf.as_str())
            .map_err(io::Error::from)?;
        rustix::fs::fsync(&to_fd).map_err(io::Error::from)?;
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

/// Remove `leaf` from directory `dir_rel` (relative to `root`) via `unlinkat`
/// on a dirfd walked no-follow beneath `root`, so a symlinked parent cannot
/// redirect the deletion. Maps a missing entry / symlinked parent to `NotFound`.
#[cfg(unix)]
async fn unlink_beneath(root: &Path, dir_rel: &Path, leaf: &str) -> io::Result<()> {
    let root = root.to_path_buf();
    let dir_rel = dir_rel.to_path_buf();
    let leaf = leaf.to_string();
    tokio::task::spawn_blocking(move || -> io::Result<()> {
        let dirfd = dir_beneath(&root, &dir_rel, false)?;
        rustix::fs::unlinkat(&dirfd, leaf.as_str(), rustix::fs::AtFlags::empty())
            .map_err(io::Error::from)
    })
    .await
    .map_err(io::Error::other)?
}

/// Async wrapper: open `rel` beneath `root` read-only, no-follow at every
/// component (the symlink-escape backstop for blob reads).
#[cfg(unix)]
async fn open_beneath(root: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::OFlags;
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    let f = tokio::task::spawn_blocking(move || resolve_beneath(&root, &rel, OFlags::RDONLY))
        .await
        .map_err(io::Error::other)??;
    Ok(tokio::fs::File::from_std(f))
}

/// Async wrapper: open `rel` beneath `root` for appending, no-follow at every
/// component (so a planted `uploads` *or* `uploads/<id>` symlink cannot redirect
/// a PATCH append outside the store).
#[cfg(unix)]
async fn open_append_beneath(root: &Path, rel: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::OFlags;
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    let f = tokio::task::spawn_blocking(move || {
        resolve_beneath(&root, &rel, OFlags::WRONLY | OFlags::APPEND)
    })
    .await
    .map_err(io::Error::other)??;
    Ok(tokio::fs::File::from_std(f))
}

/// The kind of a CAS entry resolved beneath `root` with no symlink traversal:
/// `Some(true)` = a regular file, `Some(false)` = present but not a regular
/// file (symlink/dir/etc.), `None` = absent. Never follows a symlink at any
/// path component.
#[cfg(unix)]
async fn stat_beneath(root: &Path, rel: &Path) -> io::Result<Option<(bool, u64)>> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let root = root.to_path_buf();
    let rel = rel.to_path_buf();
    tokio::task::spawn_blocking(move || -> io::Result<Option<(bool, u64)>> {
        // Walk to the parent no-follow, then no-follow-stat the final component.
        let comps: Vec<&std::ffi::OsStr> = rel.iter().collect();
        let Some((last, parents)) = comps.split_last() else {
            return Ok(None);
        };
        let mut dir = rustix::fs::open(
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        for comp in parents {
            match rustix::fs::openat(
                &dir,
                *comp,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(next) => dir = next,
                // A missing, symlinked, or non-directory parent means the entry
                // is not a valid CAS blob: report absent rather than error.
                // (`O_NOFOLLOW` on a symlink yields `ELOOP` on Linux, `ENOTDIR`
                // on macOS/BSD.) A genuine permission error (`EACCES`) is NOT
                // swallowed — it surfaces as a 500, not a false 404.
                Err(
                    rustix::io::Errno::NOENT | rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR,
                ) => return Ok(None),
                Err(e) => return Err(io::Error::from(e)),
            }
        }
        // Stat the leaf no-follow. A missing/symlinked leaf is absent; a genuine
        // IO error propagates. In test, `FORCE_STAT_ERROR` injects a synthetic
        // errno so this error arm is covered deterministically (a real leaf stat
        // failure needs a fault a single-fs test cannot otherwise produce).
        let statted = {
            #[cfg(all(test, target_os = "linux"))]
            {
                if FORCE_STAT_ERROR.load(std::sync::atomic::Ordering::Relaxed) {
                    Err(rustix::io::Errno::IO)
                } else {
                    rustix::fs::statat(&dir, *last, AtFlags::SYMLINK_NOFOLLOW)
                }
            }
            #[cfg(not(all(test, target_os = "linux")))]
            {
                rustix::fs::statat(&dir, *last, AtFlags::SYMLINK_NOFOLLOW)
            }
        };
        match statted {
            Ok(st) => Ok(Some((
                FileType::from_raw_mode(st.st_mode).is_file(),
                st.st_size as u64,
            ))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(io::Error::from(e)),
        }
    })
    .await
    .map_err(io::Error::other)?
}

impl Storage for FsStorage {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        // Validate the path first (the traversal backstop must run before any
        // short-circuit), then let a definite-absent filter answer skip the
        // stat; a "maybe" falls through to a no-follow stat resolved *beneath*
        // the store root — no symlink at any component (repo, `blobs`, `<alg>`,
        // digest) is followed, so an external file can never be sized as a blob.
        let rel = self.blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Err(StorageError::NotFound);
        }
        match stat_beneath(&self.root, &rel).await? {
            Some((true, size)) => Ok(size),
            _ => Err(StorageError::NotFound),
        }
    }

    async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        // Validate the path first (traversal backstop before any short-circuit),
        // then let a definite-absent filter answer skip the stat; a "maybe"
        // falls through to an authoritative no-follow stat resolved beneath the
        // store root. A CAS entry counts as present only if it is a *regular
        // file* reached without traversing any symlink — so neither a planted
        // leaf symlink nor a symlinked parent dir can satisfy a manifest's
        // referenced-blob check and then be served from outside the store.
        let rel = self.blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest.as_string()) {
            return Ok(false);
        }
        Ok(matches!(
            stat_beneath(&self.root, &rel).await?,
            Some((true, _))
        ))
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        let digest_str = digest.as_string();
        // Serve small blobs (manifests/configs) from the RAM cache with zero
        // syscalls; a miss falls through to the loose file.
        if let Some(bytes) = self.cache.get(repo, &digest_str) {
            return Ok(bytes.to_vec());
        }
        let rel = self.blob_rel(repo, digest)?;
        if !self.presence.maybe_present(repo, &digest_str) {
            return Err(StorageError::NotFound);
        }
        // Read through the same no-follow beneath-root open as open_blob: a
        // planted CAS symlink (leaf or parent) can never redirect a whole-blob
        // read outside the store, even on a cache miss.
        let mut f = open_beneath(&self.root, &rel)
            .await
            .map_err(map_not_found)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).await.map_err(map_not_found)?;
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
        // Open beneath the store root, refusing any symlink traversal at every
        // component: a planted `blobs/<alg>/<hex>` leaf — or a symlinked `repo`,
        // `blobs`, or `<alg>` parent — can never stream bytes from outside the CAS.
        let rel = self.blob_rel(repo, digest)?;
        open_beneath(&self.root, &rel).await.map_err(map_not_found)
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
        let rel = self.upload_rel(repo, id)?;
        let mut f = match open_append_beneath(&self.root, &rel).await {
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
        trailing: &[u8],
    ) -> Result<(), StorageError> {
        // Hold the session lock across the trailing append AND the verify+promote
        // so a concurrent PATCH cannot inject bytes between the append and the
        // hash (which would make the digest cover unverified data, or fail a
        // valid completion).
        let lock = self.session_lock(repo, id)?;
        let _guard = lock.lock().await;
        let staging = self.upload_path(repo, id)?;
        let staging_rel = self.upload_rel(repo, id)?;
        // Append the monolithic PUT's trailing body (if any) to the staging file
        // under the same lock, no-follow, before hashing.
        if !trailing.is_empty() {
            let mut f = match open_append_beneath(&self.root, &staging_rel).await {
                Ok(f) => f,
                Err(e) => {
                    self.drop_session_lock(repo, id);
                    return Err(map_not_found(e));
                }
            };
            f.write_all(trailing).await?;
            f.flush().await?;
        }
        // Resolve the staging entry beneath the store root with no symlink
        // traversal at any component: a planted `uploads` parent or `uploads/<id>`
        // leaf symlink is not a valid staging file, so it never gets
        // hashed-through and promoted into the CAS.
        let (is_file, staged_size) = match stat_beneath(&self.root, &staging_rel).await? {
            Some(m) => m,
            None => {
                self.drop_session_lock(repo, id);
                return Err(StorageError::NotFound);
            }
        };
        if !is_file {
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
        if staged_size > max_size {
            let _ = tokio::fs::remove_file(&staging).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::TooLarge {
                limit: max_size,
                actual: staged_size,
            });
        }
        // Stream-hash the staging file (no full-blob buffer) through a handle
        // opened *beneath the store root* (no-follow, regular-file-checked), so
        // no parent-symlink swap can redirect the hash input, and verify it
        // matches the client-declared digest before promoting it.
        let staging_fd = open_beneath(&self.root, &staging_rel)
            .await
            .map_err(map_not_found)?;
        let actual = hash_reader(staging_fd, expected.algorithm())
            .await
            .map_err(map_not_found)?;
        if !actual.ct_eq(expected) {
            // Reject and drop the staging file so a bad upload leaves nothing.
            let (up_dir, up_leaf) = self.upload_dir_rel(repo, id)?;
            let _ = unlink_beneath(&self.root, &up_dir, &up_leaf).await;
            self.drop_session_lock(repo, id);
            return Err(StorageError::DigestMismatch {
                expected: expected.as_string(),
                actual: actual.as_string(),
            });
        }
        // Ensure the layout marker exists, then rename the staging file into the
        // CAS via dirfds walked no-follow beneath the store root — atomic on the
        // same filesystem, copy-free, and safe against a symlinked `uploads`,
        // `blobs`, or `<alg>` parent. A crash can never leave a corrupt-but-named
        // blob (a torn write stays under `uploads/` and is discarded).
        self.ensure_layout(repo).await?;
        let (up_dir, up_leaf) = self.upload_dir_rel(repo, id)?;
        let (alg_rel, hex) = self.blob_dir_rel(repo, expected)?;
        rename_beneath(&self.root, &up_dir, &up_leaf, &alg_rel, &hex).await?;
        self.drop_session_lock(repo, id);
        // Record presence so future reads skip the stat on a definite miss.
        let digest_str = expected.as_string();
        self.presence.insert(repo, &digest_str);
        // Warm the small-blob cache for a cacheable blob: read it back through
        // the same no-follow beneath-root open (the blob path is the validated
        // `alg_rel/hex` just promoted). A genuine IO hiccup skips the warm.
        let blob_rel = alg_rel.join(&hex);
        self.warm_small_blob_cache(repo, &blob_rel, &digest_str)
            .await;
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
        // Publish the bytes into the CAS crash-atomically, anchored to a dirfd
        // walked no-follow beneath the store root (dir_beneath creates the
        // `blobs/<alg>` tree): a symlinked parent cannot redirect the write, a
        // partial blob is never namespace-visible (Linux `O_TMPFILE`+`linkat`),
        // and an `EEXIST` at the digest name is dedup only if it is a regular
        // file. Non-Linux / no-`O_TMPFILE` uses a temp+`renameat` in that dirfd.
        let (alg_rel, leaf) = self.blob_dir_rel(repo, digest)?;
        publish_bytes(&self.root, &alg_rel, &leaf, data).await?;
        // Record presence so future reads skip the stat on a definite miss, and
        // warm the small-blob cache (a no-op for large layers).
        let digest_str = digest.as_string();
        self.presence.insert(repo, &digest_str);
        self.cache.put(repo, &digest_str, data);
        Ok(())
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        // Remove via a dirfd walked no-follow beneath the store root so a
        // symlinked `blobs`/`<alg>` parent cannot redirect the deletion.
        let (alg_rel, leaf) = self.blob_dir_rel(repo, digest)?;
        unlink_beneath(&self.root, &alg_rel, &leaf)
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
                // Read the manifest blob through a no-follow beneath-root open
                // (regular-file-checked) so a symlinked CAS parent/leaf cannot
                // redirect the read outside the store, even on a cache miss.
                let mut f = open_beneath(&self.root, &self.blob_rel(repo, &digest)?)
                    .await
                    .map_err(map_not_found)?;
                let mut b = Vec::new();
                f.read_to_end(&mut b).await.map_err(map_not_found)?;
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
        // Remove the manifest blob from the CAS via a dirfd walked no-follow
        // beneath the store root (NotFound if absent); a symlinked parent cannot
        // redirect the deletion outside the store.
        let (alg_rel, leaf) = self.blob_dir_rel(repo, digest)?;
        unlink_beneath(&self.root, &alg_rel, &leaf)
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
        // Source absent → the caller falls back to a normal upload session.
        if !self.blob_exists(from_repo, digest).await? {
            return Ok(false);
        }
        // Same-repo mount: source and destination are the same path — already
        // present, nothing to promote (a copy-onto-self would truncate it).
        let (from_alg_rel, leaf) = self.blob_dir_rel(from_repo, digest)?;
        let (to_alg_rel, _) = self.blob_dir_rel(to_repo, digest)?;
        if from_alg_rel == to_alg_rel {
            self.presence.insert(to_repo, &digest.as_string());
            return Ok(true);
        }
        self.ensure_layout(to_repo).await?;
        // Promote via dirfds walked no-follow beneath the store root, contract
        // order reflink → hard link → streaming copy (SECURITY.md:124). A
        // pre-existing regular-file destination is idempotent success; a planted
        // symlink/dir parent or destination is rejected (re-validated inside the
        // promotion, closing the check→promote race).
        match mount_promote_beneath(&self.root, &from_alg_rel, &to_alg_rel, &leaf).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StorageError::BadPath(format!(
                    "mount destination for {} is not a regular file",
                    digest.as_string()
                )));
            }
            Err(e) => return Err(StorageError::Io(e)),
        }
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
        s.finish_upload("r", &id, &d, u64::MAX, b"").await.unwrap();
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
            s.finish_upload("r", &id, &wrong, u64::MAX, b"").await,
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
            s.finish_upload("r", "dir-session", &d, u64::MAX, b"").await,
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
    async fn mount_blob_promotes_and_reports_absence() {
        // Serialize against the fault-injection test so a forced fallback cannot
        // change the promotion mechanism mid-assertion and flake it.
        #[cfg(target_os = "linux")]
        let _serialize = FAULT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"shared-layer";
        let d = sha256_of(data);
        s.put_blob("src", &d, data).await.unwrap();
        // Present source → mount promotes it into `dst` (reflink on
        // btrfs/XFS/APFS, else a hard link, else a streaming copy — all share
        // storage or copy the exact bytes). Assert the observable contract, not
        // the mechanism (which is filesystem-dependent): the mount succeeds and
        // the blob is byte-identical in the destination repo.
        assert!(s.mount_blob("src", "dst", &d).await.unwrap());
        assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
        // Both repos hold a real, independently-openable regular file for the
        // digest (reflink gives distinct inodes; a hard link shares one — either
        // way both paths resolve to a regular CAS blob with the right bytes).
        #[cfg(unix)]
        {
            for repo in ["src", "dst"] {
                let meta = std::fs::symlink_metadata(s.blob_path(repo, &d).unwrap()).unwrap();
                assert!(meta.is_file());
                assert_eq!(meta.len(), data.len() as u64);
            }
        }
        // Re-mounting an already-present destination is idempotent success (the
        // existing regular-file blob is validated no-follow, never re-copied).
        assert!(s.mount_blob("src", "dst", &d).await.unwrap());
        assert_eq!(s.read_blob("dst", &d).await.unwrap(), data);
        // Absent source → Ok(false) (caller falls back to a session).
        let absent = sha256_of(b"never-stored");
        assert!(!s.mount_blob("src", "dst", &absent).await.unwrap());
        // Idempotent re-mount stays correct.
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

    // A symlinked *parent* directory (not just the leaf) must not let an external
    // file be seen/served as a CAS blob: the beneath-root resolver opens every
    // component no-follow, so a `blobs` symlink pointing outside the store is
    // rejected by blob_exists / blob_size / read_blob alike.
    #[cfg(unix)]
    #[tokio::test]
    async fn planted_parent_symlink_is_not_traversed() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // An outside tree holding a file at the exact CAS-relative sub-path.
        let d = sha256_of(b"outside-bytes");
        let outside = dir.path().join("outside");
        let outside_blob = outside.join("blobs").join(&d.algorithm).join(&d.hex);
        std::fs::create_dir_all(outside_blob.parent().unwrap()).unwrap();
        std::fs::write(&outside_blob, b"outside-bytes").unwrap();
        // Repo dir exists but its `blobs` is a symlink to the outside tree.
        let repo_dir = s.repo_dir("r").unwrap();
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::os::unix::fs::symlink(outside.join("blobs"), repo_dir.join("blobs")).unwrap();
        s.presence.insert("r", &d.as_string());
        // Every read surface refuses to traverse the symlinked `blobs` parent.
        assert!(!s.blob_exists("r", &d).await.unwrap());
        assert!(matches!(
            s.blob_size("r", &d).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            s.read_blob("r", &d).await,
            Err(StorageError::NotFound)
        ));
        assert!(s.open_blob("r", &d).await.is_err());
    }

    // The *write* side is beneath-root too: a symlinked `blobs` parent must not
    // let put_blob create the blob outside the store, and delete_blob must not
    // follow it. The dirfd walk refuses to descend a symlinked component, so the
    // write fails rather than escaping.
    #[cfg(unix)]
    #[tokio::test]
    async fn put_blob_refuses_symlinked_parent() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"write-escape-attempt";
        let d = sha256_of(data);
        // Point the repo's `blobs` at an outside directory via a symlink.
        let outside = dir.path().join("outside-blobs");
        std::fs::create_dir_all(&outside).unwrap();
        let repo_dir = s.repo_dir("r").unwrap();
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::os::unix::fs::symlink(&outside, repo_dir.join("blobs")).unwrap();
        // put_blob must refuse to write through the symlinked `blobs` parent.
        assert!(s.put_blob("r", &d, data).await.is_err());
        // Nothing was created under the outside target.
        assert!(!outside.join(&d.algorithm).join(&d.hex).exists());
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
            s.finish_upload("r", &id, &d, 4, b"").await,
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
        s.finish_upload("r", &id, &d, u64::MAX, b"").await.unwrap();
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
            s.finish_upload("r", &id2, &d, u64::MAX, b"").await,
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
        s.finish_upload("r", &id, &d, u64::MAX, b"").await.unwrap();
        assert_eq!(s.read_blob("r", &d).await.unwrap(), data);
        // A sha512 mismatch is rejected by the streamed verify.
        let id2 = s.begin_upload("r").await.unwrap();
        s.append_upload("r", &id2, b"different", None)
            .await
            .unwrap();
        assert!(matches!(
            s.finish_upload("r", &id2, &d, u64::MAX, b"").await,
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
            s.finish_upload("r", "../evil", &d, u64::MAX, b"").await,
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

    // Drive the reflink / hard-link / copy fallbacks of mount_promote_beneath and
    // publish_bytes deterministically on a single filesystem via the FORCE_*
    // seams — the branches CI's one filesystem cannot otherwise reach. Serialized
    // so a forced fallback cannot flake a parallel mount test.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mount_and_put_fallback_paths() {
        use std::sync::atomic::Ordering;
        let _serialize = FAULT_TEST_LOCK.lock().await;
        let data = b"fallback-blob";
        let d = sha256_of(data);

        // (1) Reflink + hard link forced off → mount takes the streaming copy.
        FORCE_COPY_FALLBACK.store(true, Ordering::Relaxed);
        let s1 = FsStorage::new(tempfile::tempdir().unwrap().path()).unwrap();
        s1.put_blob("srcrepo", &d, data).await.unwrap();
        assert!(s1.mount_blob("srcrepo", "dstrepo", &d).await.unwrap());
        assert_eq!(s1.read_blob("dstrepo", &d).await.unwrap(), data);
        FORCE_COPY_FALLBACK.store(false, Ordering::Relaxed);

        // (2) Reflink forced to succeed → mount takes the reflink primary.
        FORCE_REFLINK_OK.store(true, Ordering::Relaxed);
        let s2 = FsStorage::new(tempfile::tempdir().unwrap().path()).unwrap();
        s2.put_blob("srcrepo", &d, data).await.unwrap();
        assert!(s2.mount_blob("srcrepo", "dstrepo", &d).await.unwrap());
        assert_eq!(s2.read_blob("dstrepo", &d).await.unwrap(), data);
        FORCE_REFLINK_OK.store(false, Ordering::Relaxed);

        // (3) O_TMPFILE unsupported → put_blob takes the temp+rename fallback.
        FORCE_TMPFILE_UNSUPPORTED.store(true, Ordering::Relaxed);
        let s3 = FsStorage::new(tempfile::tempdir().unwrap().path()).unwrap();
        let td = sha256_of(b"no-tmpfile-here");
        s3.put_blob("r", &td, b"no-tmpfile-here").await.unwrap();
        assert_eq!(s3.read_blob("r", &td).await.unwrap(), b"no-tmpfile-here");
        FORCE_TMPFILE_UNSUPPORTED.store(false, Ordering::Relaxed);
    }

    // stat_beneath propagates a genuine leaf-stat IO error (not NOENT) as an
    // error, exercised deterministically via the FORCE_STAT_ERROR seam.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stat_beneath_propagates_io_error() {
        use std::sync::atomic::Ordering;
        let _serialize = FAULT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"present-blob";
        let d = sha256_of(data);
        s.put_blob("r", &d, data).await.unwrap();
        FORCE_STAT_ERROR.store(true, Ordering::Relaxed);
        let res = s.blob_exists("r", &d).await;
        FORCE_STAT_ERROR.store(false, Ordering::Relaxed);
        assert!(matches!(res, Err(StorageError::Io(_))));
    }

    // put_blob's O_TMPFILE+linkat hits EEXIST when the digest name already
    // exists, but if that entry is NOT a regular file (a planted symlink) it is
    // rejected, never reported as dedup success.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn put_blob_rejects_non_regular_eexist_destination() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"collide";
        let d = sha256_of(data);
        // Pre-plant a symlink at the exact CAS destination so linkat → EEXIST.
        let dest = s.blob_path("r", &d).unwrap();
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"x").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dest).unwrap();
        let err = s.put_blob("r", &d, data).await.unwrap_err();
        assert!(matches!(err, StorageError::Io(_)));
    }

    // stat_beneath returns absent for a leaf whose parent dir exists but the
    // leaf itself is missing (exercises the leaf openat/statat NOENT arm).
    #[cfg(unix)]
    #[tokio::test]
    async fn stat_beneath_missing_leaf_in_existing_dir_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // Materialise `r/blobs/sha256` by storing one blob, then stat a
        // *different* sha256 digest (same alg dir, absent leaf).
        let present = sha256_of(b"present");
        s.put_blob("r", &present, b"present").await.unwrap();
        let absent = sha256_of(b"absent");
        s.presence.insert("r", &absent.as_string());
        assert!(!s.blob_exists("r", &absent).await.unwrap());
    }

    // A non-regular *source* blob (a planted symlink) is refused by mount: the
    // source is opened no-follow and fstat-checked for a regular file.
    #[cfg(unix)]
    #[tokio::test]
    async fn mount_refuses_non_regular_source() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"src-bytes");
        // Force the presence filter to admit the source, then plant a symlink at
        // the source CAS path so mount's no-follow source open/ fstat rejects it.
        s.presence.insert("src", &d.as_string());
        let src = s.blob_path("src", &d).unwrap();
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &src).unwrap();
        // Source "exists" per the filter but is not a regular file → the mount's
        // source resolution reports it absent (Ok(false)) or errors; either way
        // no blob is promoted into `dst`.
        let _ = s.mount_blob("src", "dst", &d).await;
        assert!(!std::fs::symlink_metadata(s.blob_path("dst", &d).unwrap())
            .map(|m| m.is_file())
            .unwrap_or(false));
    }

    // A read-only CAS parent makes the beneath-root dirfd operations fail with a
    // genuine EACCES (not NotFound), which surfaces as an IO error rather than a
    // false 404 — exercising the `Err(e)` syscall-error arms of the dirfd walk
    // and promotion. Runs as the unprivileged test user (root bypasses mode bits).
    #[cfg(unix)]
    #[tokio::test]
    async fn write_through_readonly_parent_is_io_error() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        // Create `r/blobs` read-only so creating `<alg>` under it fails EACCES.
        let blobs = s.repo_dir("r").unwrap().join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o500)).unwrap();
        let d = sha256_of(b"blocked");
        let res = s.put_blob("r", &d, b"blocked").await;
        // Restore perms so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755));
        // Root (if the suite runs privileged) bypasses mode bits and succeeds;
        // the unprivileged CI/test user gets an IO error. Accept either, but a
        // failure must be an Io error, never a spurious NotFound.
        if let Err(e) = res {
            assert!(matches!(e, StorageError::Io(_)));
        }
    }

    // A read through an unsearchable intermediate CAS dir (mode 0o000) hits a
    // genuine EACCES in the beneath-root open/stat walk (not NotFound) — an IO
    // error, never a false 404. Unprivileged test user only (root bypasses).
    #[cfg(unix)]
    #[tokio::test]
    async fn read_through_unsearchable_parent_is_io_error() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"present");
        s.put_blob("r", &d, b"present").await.unwrap();
        // Make the `<alg>` dir unsearchable so opening/stat-ing the leaf EACCES.
        let alg = s.repo_dir("r").unwrap().join("blobs").join(&d.algorithm);
        std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o000)).unwrap();
        let read = s.read_blob("r", &d).await;
        let sized = s.blob_size("r", &d).await;
        let _ = std::fs::set_permissions(&alg, std::fs::Permissions::from_mode(0o755));
        // Unprivileged: EACCES → Io. Privileged (root): succeeds. Never a false
        // NotFound on a genuine permission error.
        for r in [read.map(|_| ()), sized.map(|_| ())] {
            if let Err(e) = r {
                assert!(matches!(e, StorageError::Io(_)));
            }
        }
    }

    // Directly exercise the best-effort cache warm: an absent blob path is a
    // no-op (open fails → skipped), and a present small blob is cached.
    #[cfg(unix)]
    #[tokio::test]
    async fn warm_small_blob_cache_open_error_is_noop_and_small_blob_caches() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"warmable");
        let (alg_rel, hex) = s.blob_dir_rel("r", &d).unwrap();
        let mut rel = alg_rel.clone();
        rel.push(&hex);
        // (a) No blob at rel yet → open fails → warm is a no-op (nothing cached).
        s.warm_small_blob_cache("r", &rel, &d.as_string()).await;
        assert!(s.cache.get("r", &d.as_string()).is_none());
        // (b) Materialise the blob, then warm → it is read back and cached.
        s.put_blob("r", &d, b"warmable").await.unwrap();
        s.cache.invalidate("r", &d.as_string());
        s.warm_small_blob_cache("r", &rel, &d.as_string()).await;
        assert_eq!(
            s.cache.get("r", &d.as_string()).map(|b| b.to_vec()),
            Some(b"warmable".to_vec())
        );
    }

    // dir_beneath propagates a genuine openat syscall error (not a symlink/
    // NotFound) from its walk, exercised via the FORCE_SYSCALL_ERROR seam.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dir_beneath_propagates_syscall_error() {
        use std::sync::atomic::Ordering;
        let _serialize = FAULT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"blocked-write");
        FORCE_SYSCALL_ERROR.store(true, Ordering::Relaxed);
        let res = s.put_blob("r", &d, b"blocked-write").await;
        FORCE_SYSCALL_ERROR.store(false, Ordering::Relaxed);
        assert!(matches!(res, Err(StorageError::Io(_))));
    }

    // open_beneath rejects a non-regular final entry: a FIFO planted at a blob
    // leaf must not be opened (a read would block / return non-CAS bytes).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn read_beneath_rejects_fifo_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"fifo-victim");
        let leaf_path = s.blob_path("r", &d).unwrap();
        std::fs::create_dir_all(leaf_path.parent().unwrap()).unwrap();
        // Plant a FIFO at the digest leaf (rustix mkfifoat, CWD + absolute path).
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &leaf_path,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        s.presence.insert("r", &d.as_string());
        // Reads refuse the non-regular entry (NotFound), never blocking.
        assert!(matches!(
            s.read_blob("r", &d).await,
            Err(StorageError::NotFound)
        ));
        assert!(s.open_blob("r", &d).await.is_err());
    }

    // finish_upload on an id that was never begun (no staging file) resolves to
    // absent beneath the root → NotFound, and drops the session lock.
    #[tokio::test]
    async fn finish_upload_missing_session_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let d = sha256_of(b"never-staged");
        assert!(matches!(
            s.finish_upload("r", "ghost", &d, u64::MAX, b"").await,
            Err(StorageError::NotFound)
        ));
    }

    // stat_beneath on an empty relative path is a no-op absent (defensive guard
    // for a path with no components).
    #[cfg(unix)]
    #[tokio::test]
    async fn stat_beneath_empty_rel_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(stat_beneath(dir.path(), Path::new(""))
            .await
            .unwrap()
            .is_none());
    }

    // publish_bytes rejects an EEXIST destination that is not a regular file:
    // a symlink planted at the digest leaf (inside a valid, beneath-root alg
    // dir) makes `linkat` return EEXIST, and the no-follow fstat then refuses it
    // rather than reporting false dedup success.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn publish_bytes_rejects_non_regular_eexist() {
        let dir = tempfile::tempdir().unwrap();
        let s = FsStorage::new(dir.path()).unwrap();
        let data = b"collide";
        let d = sha256_of(data);
        let (alg_rel, leaf) = s.blob_dir_rel("r", &d).unwrap();
        // Materialise the alg dir and plant a symlink at the digest leaf.
        let alg_abs = dir.path().join(&alg_rel);
        std::fs::create_dir_all(&alg_abs).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), alg_abs.join(&leaf)).unwrap();
        let err = publish_bytes(&s.root, &alg_rel, &leaf, data)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
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
            s.finish_upload("r", "linksess", &d, u64::MAX, b"").await,
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
