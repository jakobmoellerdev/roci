//! Derived, rebuildable-from-the-layout metadata index (ARCHITECTURE.md
//! §"Metadata index engine"). The [`MetadataStore`] trait is the read/mutate
//! surface the storage backend resolves tags, manifest media types, and the
//! subject→referrers relation against; the default [`LogMetadataStore`] keeps
//! the state in RAM and durably mirrors every mutation to an append-only,
//! CRC32C-framed `roci-meta.log` so restarts replay in one sequential pass.
//!
//! The on-disk OCI layout (`index.json` + `blobs/`) remains the source of
//! truth (invariant 6); this index is a cache, always reconstructable by
//! replaying the log or, failing that, walking the layout.

mod log;
mod snapshot;
pub(crate) mod wal_hmac;

#[cfg(feature = "lmdb")]
mod lmdb;

#[cfg(feature = "lmdb")]
pub use self::lmdb::LmdbMetadataStore;

pub use log::LogMetadataStore;

use roci_config::{MetadataConfig, MetadataEngine};
use std::io::{self, Write};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A tag/manifest/referrer/blob mutation the store can record and replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaOp {
    /// A manifest was stored, committed atomically with everything derived
    /// from it (SECURITY §Storage boundary: one WAL record, so a crash never
    /// leaves a stored manifest whose blobs look unreferenced to GC).
    PutManifest {
        repo: String,
        digest: String,
        media_type: String,
        tag: Option<String>,
        /// Backref edges: every object the manifest references (config,
        /// layers, index children, subject) gains `digest` in its backref set.
        references: Vec<String>,
        /// `(subject, referrer descriptor)` when the manifest has a `subject`.
        referrer: Option<(String, Vec<u8>)>,
    },
    /// Backref edges recorded on their own: the GC startup rebuild restoring
    /// edges an older log or an externally built layout lacks.
    PutBackrefs {
        repo: String,
        manifest: String,
        blobs: Vec<String>,
    },
    /// A manifest (and every tag pointing at it) was deleted: `(repo, digest)`.
    DeleteManifest { repo: String, digest: String },
    /// A referrer descriptor was recorded against a subject digest (the
    /// referrers enable-upgrade of pre-existing `index.json` descriptors).
    PutReferrer {
        repo: String,
        subject: String,
        referrer: String,
        descriptor: Vec<u8>,
    },
    /// A blob's CRC32C and size, recorded when it enters the CAS so the scrub
    /// can verify it with a fast checksum before escalating to a full re-hash.
    PutChecksum {
        repo: String,
        digest: String,
        crc32c: u32,
        size: u64,
    },
    /// A blob left the CAS (API delete, GC, scrub quarantine).
    DeleteBlob { repo: String, digest: String },
}

/// The CRC32C + size recorded for a blob at write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobChecksum {
    pub crc32c: u32,
    pub size: u64,
}

/// The read/mutate surface for derived metadata — the seam every metadata
/// engine implements (append-log + maps by default, embedded KV as an
/// upgrade; ARCHITECTURE §Metadata index engine). Object-safe: backends hold
/// it as `Arc<dyn MetadataStore>`. AuthN/AuthZ is enforced before any call
/// (ARCHITECTURE.md invariant 3), exactly like [`crate::Storage`].
pub trait MetadataStore: Send + Sync + 'static {
    /// Resolve a tag to `(digest, media_type)`, if the tag exists. Both come
    /// from the same locked read, so a resolved tag always carries its media
    /// type (no second lookup, no fallback default).
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)>;
    /// The stored media type for a manifest digest, if known.
    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String>;
    /// One page of `repo`'s tags in lexical order: at most `limit` tags
    /// strictly after `last` (from the start when `None`) — an O(log n) seek,
    /// so the work is bounded by the page, not the repo. `None` when the store
    /// records no tag for `repo` (the caller falls back to the layout).
    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>>;
    /// One page of the referrers recorded for `subject`, ordered by referrer
    /// digest: at most `limit` entries strictly after `last`, restricted to
    /// descriptors whose `artifactType` equals `artifact_type` when given (an
    /// O(log n) seek into a per-type index, never a filtered scan). `None`
    /// when the store records no referrer for `subject` at all.
    fn referrers_page(
        &self,
        repo: &str,
        subject: &str,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Option<Page<Referrer>>;
    /// Whether `referrer` is recorded as a referrer of `subject`.
    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool;
    /// The manifest digests currently recorded as referencing `blob` in `repo`.
    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String>;
    /// The checksum recorded for `digest` in `repo`, if any.
    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum>;
    /// Apply and durably record a mutation (group-committed).
    fn apply(&self, op: MetaOp) -> io::Result<()>;
    /// Apply and record a mutation without waiting for durability — only for
    /// derived records whose loss is harmless (a checksum the scrub rebuilds).
    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()>;
    /// Every repo with at least one manifest or referrer recorded, sorted.
    fn repos(&self) -> Vec<String>;
    /// Every manifest digest recorded in `repo`.
    fn manifests(&self, repo: &str) -> Vec<String>;
    /// `repo`'s tags as `(tag, digest, media_type)`, sorted by tag.
    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)>;
    /// `repo`'s referrers as `(subject, [(referrer, descriptor)])`.
    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)>;
    /// Background upkeep (log compaction / snapshot cut) the maintenance
    /// scheduler calls periodically; a no-op when nothing is due.
    fn maintain(&self) -> io::Result<()>;
    /// The WAL/snapshot generation — monotonically increasing on each
    /// compaction/snapshot. Used by the fast-restart stamp to verify that the
    /// metadata state matches the stamp. Engines without a WAL return 0.
    fn generation(&self) -> u64;
    /// Size of the metadata WAL file on disk (bytes). Used by the fast-restart
    /// stamp to detect whether metadata state changed since the stamp was
    /// written (any append changes the file size). Engines without a WAL
    /// return 0.
    fn log_len(&self) -> u64;
    /// Emit the minimal op image that reconstructs the full state. The `sink`
    /// receives one `MetaOp` at a time; the caller decides how to persist.
    fn export(&self, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()>;
}

/// One referrer: `(referrer_digest, descriptor_bytes)`; the digest de-dups.
pub type Referrer = (String, Vec<u8>);

/// One page of a cursor-paginated listing: at most the requested number of
/// items strictly after the request cursor, in the listing's stable order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// At least one further item follows `items` (→ a `Link: rel="next"`).
    pub more: bool,
}

/// Collect at most `limit` items of `it` and record whether any remain.
pub(crate) fn take_page<T>(mut it: impl Iterator<Item = T>, limit: usize) -> Page<T> {
    let items: Vec<T> = it.by_ref().take(limit).collect();
    let more = it.next().is_some();
    Page { items, more }
}

/// The key range strictly after the cursor `last` (everything when `None`).
pub(crate) fn after(last: Option<&str>) -> (Bound<&str>, Bound<&str>) {
    (
        last.map_or(Bound::Unbounded, Bound::Excluded),
        Bound::Unbounded,
    )
}

/// Open the metadata engine `config` selects for the store rooted at `root`.
///
/// When the configured engine differs from the active one (detected via a
/// `roci-meta.engine` marker or artifact probing), performs a lossless
/// migration: export from the source, verify, then atomically swap.
pub fn open_metadata(root: &Path, config: &MetadataConfig) -> io::Result<Arc<dyn MetadataStore>> {
    if config.engine == MetadataEngine::Redb {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage.metadata.engine: the redb engine has been removed; \
             use \"lmdb\" instead — metadata is rebuilt from the layout",
        ));
    }
    #[cfg(not(feature = "lmdb"))]
    if config.engine == MetadataEngine::Lmdb {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage.metadata.engine = \"lmdb\" requires a build with the `lmdb` feature",
        ));
    }

    let active = detect_active_engine(root, config)?;

    if active == config.engine {
        // Same engine — open it, write the marker if missing.
        let store = open_engine(root, config.engine, config)?;
        write_marker_if_missing(root, config);
        return Ok(store);
    }

    // Engine switch requested.
    migrate(root, active, config)
}

// ---------------------------------------------------------------------------
// Engine marker: `roci-meta.engine` JSON file
// ---------------------------------------------------------------------------

const MARKER_FILE: &str = "roci-meta.engine";

/// Marker content: `{"engine":"log","format":"plain"}` etc.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct EngineMarker {
    engine: String,
    format: String,
}

fn marker_path(root: &Path) -> PathBuf {
    root.join(MARKER_FILE)
}

fn format_label(config: &MetadataConfig) -> &'static str {
    if config.hmac_key_file.is_some() {
        match config.engine {
            MetadataEngine::Log => "hmac",
            MetadataEngine::Lmdb => "chacha20poly1305-v1",
            MetadataEngine::Redb => "plain",
        }
    } else {
        "plain"
    }
}

fn read_marker(root: &Path) -> io::Result<Option<EngineMarker>> {
    let p = marker_path(root);
    match std::fs::read_to_string(&p) {
        Ok(s) => {
            let m: EngineMarker = serde_json::from_str(&s).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad {MARKER_FILE}: {e}"),
                )
            })?;
            Ok(Some(m))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        // Unreadable marker: detection falls back to probing artifacts, the
        // same answer an absent marker gives (the log engine itself opens
        // lazily, so an unreadable root must not become fatal here).
        Err(e) => {
            tracing::warn!(error = %e, "{MARKER_FILE} unreadable; probing engine artifacts");
            Ok(None)
        }
    }
}

fn write_marker(root: &Path, config: &MetadataConfig) -> io::Result<()> {
    let engine_name = match config.engine {
        MetadataEngine::Log => "log",
        MetadataEngine::Lmdb => "lmdb",
        MetadataEngine::Redb => "redb",
    };
    let marker = EngineMarker {
        engine: engine_name.to_string(),
        format: format_label(config).to_string(),
    };
    let json = serde_json::to_string(&marker).expect("marker serialization");
    let p = marker_path(root);
    let tmp = p.with_extension("engine.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &p)?;
    if let Some(dir) = p.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// Record the active engine when no marker exists yet. Best-effort: without a
/// marker the next start probes artifacts and reaches the same engine. Only
/// the migration's marker flip (the commit point) is fatal on error.
fn write_marker_if_missing(root: &Path, config: &MetadataConfig) {
    if !marker_path(root).exists() {
        if let Err(e) = write_marker(root, config) {
            tracing::warn!(error = %e, "could not record {MARKER_FILE}");
        }
    }
}

// ---------------------------------------------------------------------------
// Engine detection
// ---------------------------------------------------------------------------

fn marker_to_engine(name: &str) -> Option<MetadataEngine> {
    match name {
        "log" => Some(MetadataEngine::Log),
        "lmdb" => Some(MetadataEngine::Lmdb),
        _ => None,
    }
}

fn detect_active_engine(root: &Path, config: &MetadataConfig) -> io::Result<MetadataEngine> {
    if let Some(m) = read_marker(root)? {
        if let Some(e) = marker_to_engine(&m.engine) {
            return Ok(e);
        }
    }
    // No marker: probe artifacts.
    let has_log = root.join("roci-meta.log").exists();
    let has_lmdb = root.join("roci-meta.lmdb").is_dir();
    match (has_log, has_lmdb) {
        (true, false) => Ok(MetadataEngine::Log),
        (false, true) => Ok(MetadataEngine::Lmdb),
        (true, true) => {
            tracing::warn!(
                "both roci-meta.log and roci-meta.lmdb/ exist; \
                 using configured engine {:?}",
                config.engine
            );
            Ok(config.engine)
        }
        (false, false) => Ok(config.engine),
    }
}

// ---------------------------------------------------------------------------
// Open an individual engine
// ---------------------------------------------------------------------------

fn open_engine(
    root: &Path,
    engine: MetadataEngine,
    config: &MetadataConfig,
) -> io::Result<Arc<dyn MetadataStore>> {
    match engine {
        MetadataEngine::Log => Ok(Arc::new(LogMetadataStore::open_with(root, config)?)),
        #[cfg(feature = "lmdb")]
        MetadataEngine::Lmdb => Ok(Arc::new(LmdbMetadataStore::open(root, config)?)),
        #[cfg(not(feature = "lmdb"))]
        MetadataEngine::Lmdb => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage.metadata.engine = \"lmdb\" requires a build with the `lmdb` feature",
        )),
        MetadataEngine::Redb => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the redb engine has been removed",
        )),
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

#[cfg(feature = "lmdb")]
fn migrate(
    root: &Path,
    source_engine: MetadataEngine,
    config: &MetadataConfig,
) -> io::Result<Arc<dyn MetadataStore>> {
    use std::time::Instant;

    let dest_engine = config.engine;
    tracing::info!(
        from = ?source_engine,
        to = ?dest_engine,
        "metadata engine migration starting"
    );
    let start = Instant::now();

    // Clean up leftover migrating artifacts from a crashed run.
    clean_migrating_leftovers(root);

    // Move aside stale destination artifacts from an earlier switch-away.
    move_stale_destination_aside(root, dest_engine)?;

    // Open the source with the current config key.
    let source = match open_engine(root, source_engine, config) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "source engine failed to open; falling back to fresh destination \
                 (metadata will be rebuilt from the layout)"
            );
            let store = open_engine(root, dest_engine, config)?;
            write_marker(root, config)?;
            return Ok(store);
        }
    };

    // Check if the marker reveals both engine AND key/format changed.
    if let Some(m) = read_marker(root)? {
        let current_format = format_label(config);
        if m.format != current_format {
            tracing::warn!(
                old_format = %m.format,
                new_format = %current_format,
                "both the metadata engine and the encryption/key changed; \
                 for safety, consider changing the key and the engine in \
                 separate restarts"
            );
        }
    }

    // Build the destination in a temp location.
    let (temp_artifact, dest_final) = temp_and_final_paths(root, dest_engine);
    let op_count = build_destination(root, dest_engine, config, &source, &temp_artifact)?;

    // Open the temp destination for verification.
    let dest_store = open_engine_at(root, dest_engine, config, &temp_artifact)?;

    // Verify: repos, manifests, tags_snapshot, referrers_snapshot must be equal.
    verify_migration(&*source, &*dest_store)?;

    // Drop source and dest_store so files are not open during rename.
    drop(dest_store);
    drop(source);

    // Rename temp → final (the commit point for the destination artifacts).
    std::fs::rename(&temp_artifact, &dest_final).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "rename {} → {}: {e}",
                temp_artifact.display(),
                dest_final.display()
            ),
        )
    })?;
    dir_fsync(root)?;

    // Write the marker — this is the commit point.
    write_marker(root, config)?;

    // Move old source artifacts to *.migrated-<ts>.
    let ts = unix_ts();
    move_old_source(root, source_engine, ts)?;

    let elapsed = start.elapsed();
    tracing::info!(
        ops = op_count,
        elapsed_ms = elapsed.as_millis() as u64,
        "metadata engine migration complete"
    );

    // Open the final destination.
    open_engine(root, dest_engine, config)
}

#[cfg(not(feature = "lmdb"))]
fn migrate(
    _root: &Path,
    _source_engine: MetadataEngine,
    config: &MetadataConfig,
) -> io::Result<Arc<dyn MetadataStore>> {
    if config.engine == MetadataEngine::Lmdb {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "storage.metadata.engine = \"lmdb\" requires a build with the `lmdb` feature",
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "migration target requires the `lmdb` feature",
    ))
}

#[cfg(feature = "lmdb")]
fn clean_migrating_leftovers(root: &Path) {
    for name in ["roci-meta.lmdb.migrating", "roci-meta.log.migrating"] {
        let p = root.join(name);
        if p.is_dir() {
            tracing::info!(path = %p.display(), "removing leftover migrating directory");
            let _ = std::fs::remove_dir_all(&p);
        } else if p.exists() {
            tracing::info!(path = %p.display(), "removing leftover migrating file");
            let _ = std::fs::remove_file(&p);
        }
    }
    // Also clean log verify dir.
    let verify_dir = root.join("roci-meta.log.migrating.verify");
    if verify_dir.is_dir() {
        let _ = std::fs::remove_dir_all(&verify_dir);
    }
}

#[cfg(feature = "lmdb")]
fn move_stale_destination_aside(root: &Path, dest_engine: MetadataEngine) -> io::Result<()> {
    let dest_artifact = match dest_engine {
        MetadataEngine::Lmdb => root.join("roci-meta.lmdb"),
        MetadataEngine::Log => root.join("roci-meta.log"),
        _ => return Ok(()),
    };
    if dest_artifact.exists() {
        let ts = unix_ts();
        let aside = root.join(format!(
            "{}.migrated-{ts}",
            dest_artifact.file_name().unwrap().to_string_lossy()
        ));
        tracing::info!(
            from = %dest_artifact.display(),
            to = %aside.display(),
            "moving stale destination aside"
        );
        std::fs::rename(&dest_artifact, &aside)?;
        // For log engine, also move the snapshot if present.
        if dest_engine == MetadataEngine::Log {
            let snap = root.join("roci-meta.snapshot");
            if snap.exists() {
                let snap_aside = root.join(format!("roci-meta.snapshot.migrated-{ts}"));
                std::fs::rename(&snap, &snap_aside)?;
            }
        }
    }
    Ok(())
}

#[cfg(feature = "lmdb")]
fn temp_and_final_paths(root: &Path, dest_engine: MetadataEngine) -> (PathBuf, PathBuf) {
    match dest_engine {
        MetadataEngine::Lmdb => (
            root.join("roci-meta.lmdb.migrating"),
            root.join("roci-meta.lmdb"),
        ),
        MetadataEngine::Log => (
            root.join("roci-meta.log.migrating"),
            root.join("roci-meta.log"),
        ),
        MetadataEngine::Redb => unreachable!("redb rejected earlier"),
    }
}

#[cfg(feature = "lmdb")]
fn build_destination(
    root: &Path,
    dest_engine: MetadataEngine,
    config: &MetadataConfig,
    source: &Arc<dyn MetadataStore>,
    temp_artifact: &Path,
) -> io::Result<usize> {
    match dest_engine {
        MetadataEngine::Lmdb => build_lmdb_destination(root, config, source, temp_artifact),
        MetadataEngine::Log => build_log_destination(config, source, temp_artifact),
        MetadataEngine::Redb => unreachable!(),
    }
}

#[cfg(feature = "lmdb")]
fn build_lmdb_destination(
    _root: &Path,
    config: &MetadataConfig,
    source: &Arc<dyn MetadataStore>,
    temp_dir: &Path,
) -> io::Result<usize> {
    std::fs::create_dir_all(temp_dir)?;
    let store = LmdbMetadataStore::open_at(temp_dir, config)?;
    let mut count = 0usize;
    let mut batch = Vec::with_capacity(10_000);
    source.export(&mut |op| {
        batch.push(op);
        count += 1;
        if batch.len() >= 10_000 {
            store.bulk_apply(&batch)?;
            batch.clear();
        }
        Ok(())
    })?;
    if !batch.is_empty() {
        store.bulk_apply(&batch)?;
    }
    store.force_sync_public()?;
    Ok(count)
}

#[cfg(feature = "lmdb")]
fn build_log_destination(
    config: &MetadataConfig,
    source: &Arc<dyn MetadataStore>,
    temp_file: &Path,
) -> io::Result<usize> {
    use wal_hmac::{encode_header, FramingMode, HmacKey};

    let hmac_key = config
        .hmac_key_file
        .as_ref()
        .map(|p| HmacKey::load(p))
        .transpose()?;
    let key_ref = hmac_key.as_ref();
    let mode = if key_ref.is_some() {
        FramingMode::HmacSha256
    } else {
        FramingMode::Plain
    };

    let mut f = std::io::BufWriter::new(std::fs::File::create(temp_file)?);
    f.write_all(&log::encode_record_raw(&encode_header(mode), key_ref))?;

    let mut count = 0usize;
    source.export(&mut |op| {
        let record = log::encode_record(&op, key_ref);
        f.write_all(&record)?;
        count += 1;
        Ok(())
    })?;
    let f = f.into_inner().map_err(io::IntoInnerError::into_error)?;
    f.sync_all()?;
    Ok(count)
}

#[cfg(feature = "lmdb")]
fn verify_migration(source: &dyn MetadataStore, dest: &dyn MetadataStore) -> io::Result<()> {
    let src_repos = source.repos();
    let dst_repos = dest.repos();
    if src_repos != dst_repos {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "migration verify failed: repos differ (source={src_repos:?}, dest={dst_repos:?})"
            ),
        ));
    }
    for repo in &src_repos {
        let src_manifests = {
            let mut v = source.manifests(repo);
            v.sort();
            v
        };
        let dst_manifests = {
            let mut v = dest.manifests(repo);
            v.sort();
            v
        };
        if src_manifests != dst_manifests {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("migration verify failed: manifests differ for repo {repo:?}"),
            ));
        }
        let src_tags = source.tags_snapshot(repo);
        let dst_tags = dest.tags_snapshot(repo);
        if src_tags != dst_tags {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("migration verify failed: tags differ for repo {repo:?}"),
            ));
        }
        let src_refs = {
            let mut v = source.referrers_snapshot(repo);
            v.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, refs) in &mut v {
                refs.sort_by(|a, b| a.0.cmp(&b.0));
            }
            v
        };
        let dst_refs = {
            let mut v = dest.referrers_snapshot(repo);
            v.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, refs) in &mut v {
                refs.sort_by(|a, b| a.0.cmp(&b.0));
            }
            v
        };
        if src_refs != dst_refs {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("migration verify failed: referrers differ for repo {repo:?}"),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "lmdb")]
fn open_engine_at(
    _root: &Path,
    engine: MetadataEngine,
    config: &MetadataConfig,
    artifact: &Path,
) -> io::Result<Arc<dyn MetadataStore>> {
    match engine {
        MetadataEngine::Lmdb => Ok(Arc::new(LmdbMetadataStore::open_at(artifact, config)?)),
        MetadataEngine::Log => {
            // LogMetadataStore expects root/roci-meta.log. Our temp artifact is
            // roci-meta.log.migrating. Create a verify dir to host it.
            let parent = artifact.parent().unwrap_or(Path::new("."));
            let verify_dir = parent.join("roci-meta.log.migrating.verify");
            std::fs::create_dir_all(&verify_dir)?;
            std::fs::copy(artifact, verify_dir.join("roci-meta.log"))?;
            let store = LogMetadataStore::open_with(&verify_dir, config)?;
            let _ = std::fs::remove_dir_all(&verify_dir);
            Ok(Arc::new(store))
        }
        _ => unreachable!(),
    }
}

#[cfg(feature = "lmdb")]
fn move_old_source(root: &Path, source_engine: MetadataEngine, ts: u64) -> io::Result<()> {
    match source_engine {
        MetadataEngine::Log => {
            let log = root.join("roci-meta.log");
            if log.exists() {
                std::fs::rename(&log, root.join(format!("roci-meta.log.migrated-{ts}")))?;
            }
            let snap = root.join("roci-meta.snapshot");
            if snap.exists() {
                std::fs::rename(
                    &snap,
                    root.join(format!("roci-meta.snapshot.migrated-{ts}")),
                )?;
            }
        }
        MetadataEngine::Lmdb => {
            let lmdb = root.join("roci-meta.lmdb");
            if lmdb.exists() {
                std::fs::rename(&lmdb, root.join(format!("roci-meta.lmdb.migrated-{ts}")))?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(feature = "lmdb")]
fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(feature = "lmdb")]
fn dir_fsync(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

// ---------------------------------------------------------------------------
// Shared behavioral suite — every `MetadataStore` engine passes these.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod engine_tests {
    use super::*;
    use roci_config::MetadataConfig;

    fn descriptor(artifact_type: Option<&str>) -> Vec<u8> {
        if let Some(at) = artifact_type {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:ffff",
                "size": 100,
                "artifactType": at,
            })
            .to_string()
            .into_bytes()
        } else {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:ffff",
                "size": 100,
            })
            .to_string()
            .into_bytes()
        }
    }

    /// Macro generating the full shared test suite for each engine.
    macro_rules! engine_tests {
        ($mod_name:ident, $make_store:expr) => {
            mod $mod_name {
                use super::*;

                #[test]
                fn empty_state() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());
                    assert!(store.resolve_tag("repo", "latest").is_none());
                    assert!(store.manifest_media_type("repo", "sha256:a").is_none());
                    assert_eq!(store.repos(), Vec::<String>::new());
                    assert_eq!(store.manifests("repo"), Vec::<String>::new());
                    assert!(store.tags_page("repo", None, 10).is_none());
                    assert!(store
                        .referrers_page("repo", "sha256:a", None, None, 10)
                        .is_none());
                    assert!(!store.has_referrer("repo", "sha256:a", "sha256:b"));
                    assert_eq!(store.backrefs("repo", "sha256:a"), Vec::<String>::new());
                    assert!(store.checksum("repo", "sha256:a").is_none());
                }

                #[test]
                fn put_manifest_with_tag() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:aaa".into(),
                            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                            tag: Some("v1".into()),
                            references: vec!["sha256:bbb".into(), "sha256:ccc".into()],
                            referrer: None,
                        })
                        .unwrap();

                    let (d, mt) = store.resolve_tag("r", "v1").unwrap();
                    assert_eq!(d, "sha256:aaa");
                    assert_eq!(mt, "application/vnd.oci.image.manifest.v1+json");
                    assert_eq!(
                        store.manifest_media_type("r", "sha256:aaa").unwrap(),
                        "application/vnd.oci.image.manifest.v1+json"
                    );

                    // Backrefs: both referenced blobs point back to manifest
                    let mut br = store.backrefs("r", "sha256:bbb");
                    br.sort();
                    assert_eq!(br, vec!["sha256:aaa"]);
                    let mut br2 = store.backrefs("r", "sha256:ccc");
                    br2.sort();
                    assert_eq!(br2, vec!["sha256:aaa"]);

                    // repos/manifests
                    assert_eq!(store.repos(), vec!["r".to_string()]);
                    let mf = store.manifests("r");
                    assert_eq!(mf.len(), 1);
                    assert!(mf.contains(&"sha256:aaa".to_string()));
                }

                #[test]
                fn tag_pages_and_cursors() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    for tag in ["alpha", "beta", "gamma", "delta", "epsilon"] {
                        store
                            .apply(MetaOp::PutManifest {
                                repo: "r".into(),
                                digest: format!("sha256:{tag}"),
                                media_type: "m".into(),
                                tag: Some(tag.into()),
                                references: vec![],
                                referrer: None,
                            })
                            .unwrap();
                    }

                    // Page of 2 from start
                    let p = store.tags_page("r", None, 2).unwrap();
                    assert_eq!(p.items, vec!["alpha", "beta"]);
                    assert!(p.more);

                    // Continue with cursor
                    let p2 = store.tags_page("r", Some("beta"), 2).unwrap();
                    assert_eq!(p2.items, vec!["delta", "epsilon"]);
                    assert!(p2.more);

                    let p3 = store.tags_page("r", Some("epsilon"), 2).unwrap();
                    assert_eq!(p3.items, vec!["gamma"]);
                    assert!(!p3.more);

                    // Cursor past last element
                    let p4 = store.tags_page("r", Some("gamma"), 10).unwrap();
                    assert!(p4.items.is_empty());
                    assert!(!p4.more);

                    // Cursor that no longer exists (deleted tag) — should
                    // resume correctly (strictly after the cursor string).
                    let p5 = store.tags_page("r", Some("bet"), 2).unwrap();
                    assert_eq!(p5.items, vec!["beta", "delta"]);
                    assert!(p5.more);

                    // tags_page returns None for unknown repo
                    assert!(store.tags_page("nope", None, 10).is_none());
                }

                #[test]
                fn tags_snapshot_sorted() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    for tag in ["z", "a", "m"] {
                        store
                            .apply(MetaOp::PutManifest {
                                repo: "r".into(),
                                digest: format!("sha256:{tag}"),
                                media_type: "mt".into(),
                                tag: Some(tag.into()),
                                references: vec![],
                                referrer: None,
                            })
                            .unwrap();
                    }

                    let snap = store.tags_snapshot("r");
                    let tags: Vec<&str> = snap.iter().map(|(t, _, _)| t.as_str()).collect();
                    assert_eq!(tags, vec!["a", "m", "z"]);
                }

                #[test]
                fn put_manifest_with_referrer() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sbom/cyclonedx"));
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:ref1".into(),
                            media_type: "m".into(),
                            tag: None,
                            references: vec![],
                            referrer: Some(("sha256:subj".into(), desc.clone())),
                        })
                        .unwrap();

                    assert!(store.has_referrer("r", "sha256:subj", "sha256:ref1"));
                    let page = store
                        .referrers_page("r", "sha256:subj", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].0, "sha256:ref1");
                    assert_eq!(page.items[0].1, desc);

                    // Repos includes the referrer's repo
                    assert!(store.repos().contains(&"r".to_string()));
                }

                #[test]
                fn referrer_pages_and_artifact_type_filter() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Add 5 referrers: 3 with type "sbom", 2 with type "sig"
                    for i in 0..3 {
                        let desc = descriptor(Some("sbom"));
                        store
                            .apply(MetaOp::PutReferrer {
                                repo: "r".into(),
                                subject: "sha256:subj".into(),
                                referrer: format!("sha256:sbom{i}"),
                                descriptor: desc,
                            })
                            .unwrap();
                    }
                    for i in 0..2 {
                        let desc = descriptor(Some("sig"));
                        store
                            .apply(MetaOp::PutReferrer {
                                repo: "r".into(),
                                subject: "sha256:subj".into(),
                                referrer: format!("sha256:sig{i}"),
                                descriptor: desc,
                            })
                            .unwrap();
                    }

                    // Unfiltered: all 5
                    let p = store
                        .referrers_page("r", "sha256:subj", None, None, 10)
                        .unwrap();
                    assert_eq!(p.items.len(), 5);
                    assert!(!p.more);

                    // Filtered by "sbom": 3
                    let ps = store
                        .referrers_page("r", "sha256:subj", Some("sbom"), None, 10)
                        .unwrap();
                    assert_eq!(ps.items.len(), 3);
                    for (d, _) in &ps.items {
                        assert!(d.starts_with("sha256:sbom"));
                    }

                    // Filtered by "sig": 2
                    let psig = store
                        .referrers_page("r", "sha256:subj", Some("sig"), None, 10)
                        .unwrap();
                    assert_eq!(psig.items.len(), 2);

                    // Filtered by nonexistent type: empty page (not None —
                    // subject has referrers, just not of this type)
                    let pn = store
                        .referrers_page("r", "sha256:subj", Some("nope"), None, 10)
                        .unwrap();
                    assert!(pn.items.is_empty());
                    assert!(!pn.more);

                    // Paging across page boundaries: 2 per page, sbom type
                    let p1 = store
                        .referrers_page("r", "sha256:subj", Some("sbom"), None, 2)
                        .unwrap();
                    assert_eq!(p1.items.len(), 2);
                    assert!(p1.more);
                    let cursor = &p1.items[1].0;
                    let p2 = store
                        .referrers_page("r", "sha256:subj", Some("sbom"), Some(cursor), 2)
                        .unwrap();
                    assert_eq!(p2.items.len(), 1);
                    assert!(!p2.more);

                    // referrers_page returns None for unknown subject
                    assert!(store
                        .referrers_page("r", "sha256:unknown", None, None, 10)
                        .is_none());
                }

                #[test]
                fn referrers_snapshot_structure() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sbom"));
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s1".into(),
                            referrer: "sha256:r1".into(),
                            descriptor: desc.clone(),
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s1".into(),
                            referrer: "sha256:r2".into(),
                            descriptor: desc,
                        })
                        .unwrap();

                    let snap = store.referrers_snapshot("r");
                    assert_eq!(snap.len(), 1);
                    assert_eq!(snap[0].0, "sha256:s1");
                    assert_eq!(snap[0].1.len(), 2);
                }

                #[test]
                fn atomic_put_manifest_with_refs_and_referrer() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sig/cosign"));
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:manifest1".into(),
                            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                            tag: Some("latest".into()),
                            references: vec!["sha256:config".into(), "sha256:layer0".into()],
                            referrer: Some(("sha256:subject1".into(), desc.clone())),
                        })
                        .unwrap();

                    // Tag
                    let (d, _) = store.resolve_tag("r", "latest").unwrap();
                    assert_eq!(d, "sha256:manifest1");

                    // Media type
                    assert!(store.manifest_media_type("r", "sha256:manifest1").is_some());

                    // Backrefs
                    assert_eq!(
                        store.backrefs("r", "sha256:config"),
                        vec!["sha256:manifest1"]
                    );
                    assert_eq!(
                        store.backrefs("r", "sha256:layer0"),
                        vec!["sha256:manifest1"]
                    );

                    // Referrer
                    assert!(store.has_referrer("r", "sha256:subject1", "sha256:manifest1"));
                    let page = store
                        .referrers_page("r", "sha256:subject1", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].1, desc);
                }

                #[test]
                fn delete_manifest_cascades() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(None);

                    // Create manifest with tag, references, referrer, checksum
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: Some("v1".into()),
                            references: vec!["sha256:blob1".into()],
                            referrer: Some(("sha256:subj".into(), desc)),
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutChecksum {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            crc32c: 123,
                            size: 456,
                        })
                        .unwrap();

                    // Verify present
                    assert!(store.resolve_tag("r", "v1").is_some());
                    assert!(store.manifest_media_type("r", "sha256:m1").is_some());
                    assert!(store.has_referrer("r", "sha256:subj", "sha256:m1"));
                    assert!(!store.backrefs("r", "sha256:blob1").is_empty());
                    assert!(store.checksum("r", "sha256:m1").is_some());

                    // Delete
                    store
                        .apply(MetaOp::DeleteManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                        })
                        .unwrap();

                    // All cascaded
                    assert!(store.resolve_tag("r", "v1").is_none());
                    assert!(store.manifest_media_type("r", "sha256:m1").is_none());
                    assert!(!store.has_referrer("r", "sha256:subj", "sha256:m1"));
                    assert!(store.backrefs("r", "sha256:blob1").is_empty());
                    assert!(store.checksum("r", "sha256:m1").is_none());

                    // Referrers page now None (no referrers left)
                    assert!(store
                        .referrers_page("r", "sha256:subj", None, None, 10)
                        .is_none());
                    // Tags page now None
                    assert!(store.tags_page("r", None, 10).is_none());
                }

                #[test]
                fn delete_manifest_only_removes_matching_tags() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Two manifests, two tags
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: Some("v1".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m2".into(),
                            media_type: "mt".into(),
                            tag: Some("v2".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    store
                        .apply(MetaOp::DeleteManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                        })
                        .unwrap();

                    assert!(store.resolve_tag("r", "v1").is_none());
                    assert!(store.resolve_tag("r", "v2").is_some());
                }

                #[test]
                fn put_backrefs_standalone() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutBackrefs {
                            repo: "r".into(),
                            manifest: "sha256:m1".into(),
                            blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
                        })
                        .unwrap();

                    assert_eq!(store.backrefs("r", "sha256:b1"), vec!["sha256:m1"]);
                    assert_eq!(store.backrefs("r", "sha256:b2"), vec!["sha256:m1"]);
                }

                #[test]
                fn put_referrer_standalone() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc = descriptor(Some("sbom"));
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s".into(),
                            referrer: "sha256:r".into(),
                            descriptor: desc.clone(),
                        })
                        .unwrap();

                    assert!(store.has_referrer("r", "sha256:s", "sha256:r"));
                    let page = store
                        .referrers_page("r", "sha256:s", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].0, "sha256:r");
                    assert_eq!(page.items[0].1, desc);
                }

                #[test]
                fn put_checksum_and_delete_blob() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutChecksum {
                            repo: "r".into(),
                            digest: "sha256:b1".into(),
                            crc32c: 0xDEAD_BEEF,
                            size: 42,
                        })
                        .unwrap();

                    let bc = store.checksum("r", "sha256:b1").unwrap();
                    assert_eq!(bc.crc32c, 0xDEAD_BEEF);
                    assert_eq!(bc.size, 42);

                    store
                        .apply(MetaOp::DeleteBlob {
                            repo: "r".into(),
                            digest: "sha256:b1".into(),
                        })
                        .unwrap();

                    assert!(store.checksum("r", "sha256:b1").is_none());
                }

                #[test]
                fn apply_relaxed_commits() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply_relaxed(MetaOp::PutChecksum {
                            repo: "r".into(),
                            digest: "sha256:b1".into(),
                            crc32c: 42,
                            size: 100,
                        })
                        .unwrap();

                    // The mutation should be visible even without fsync
                    let bc = store.checksum("r", "sha256:b1").unwrap();
                    assert_eq!(bc.crc32c, 42);
                    assert_eq!(bc.size, 100);
                }

                #[test]
                fn maintain_is_harmless() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());
                    store.maintain().unwrap();

                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:a".into(),
                            media_type: "mt".into(),
                            tag: Some("t".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    store.maintain().unwrap();
                    assert!(store.resolve_tag("r", "t").is_some());
                }

                #[test]
                fn repo_isolation() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    store
                        .apply(MetaOp::PutManifest {
                            repo: "a".into(),
                            digest: "sha256:m".into(),
                            media_type: "mt".into(),
                            tag: Some("v1".into()),
                            references: vec!["sha256:blob".into()],
                            referrer: None,
                        })
                        .unwrap();

                    // Repo "b" sees nothing
                    assert!(store.resolve_tag("b", "v1").is_none());
                    assert!(store.tags_page("b", None, 10).is_none());
                    assert!(store.backrefs("b", "sha256:blob").is_empty());
                    assert!(store.manifests("b").is_empty());
                }

                #[test]
                fn tag_reassignment() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Tag points to m1
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: Some("latest".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    // Reassign to m2
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m2".into(),
                            media_type: "mt2".into(),
                            tag: Some("latest".into()),
                            references: vec![],
                            referrer: None,
                        })
                        .unwrap();

                    let (d, mt) = store.resolve_tag("r", "latest").unwrap();
                    assert_eq!(d, "sha256:m2");
                    assert_eq!(mt, "mt2");

                    // Only one tag entry
                    let p = store.tags_page("r", None, 10).unwrap();
                    assert_eq!(p.items.len(), 1);
                }

                #[test]
                fn referrer_dedup_by_digest() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    let desc1 = descriptor(Some("sbom"));
                    let desc2 = descriptor(Some("sig"));

                    // Same referrer digest, different descriptors → last wins
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s".into(),
                            referrer: "sha256:r".into(),
                            descriptor: desc1,
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutReferrer {
                            repo: "r".into(),
                            subject: "sha256:s".into(),
                            referrer: "sha256:r".into(),
                            descriptor: desc2.clone(),
                        })
                        .unwrap();

                    let page = store
                        .referrers_page("r", "sha256:s", None, None, 10)
                        .unwrap();
                    assert_eq!(page.items.len(), 1);
                    assert_eq!(page.items[0].1, desc2);

                    // Old artifact type index is cleaned up
                    let old_type_page = store
                        .referrers_page("r", "sha256:s", Some("sbom"), None, 10)
                        .unwrap();
                    assert!(old_type_page.items.is_empty());
                }

                #[test]
                fn backref_dedup() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Adding the same backref twice should not duplicate
                    store
                        .apply(MetaOp::PutBackrefs {
                            repo: "r".into(),
                            manifest: "sha256:m".into(),
                            blobs: vec!["sha256:b".into()],
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutBackrefs {
                            repo: "r".into(),
                            manifest: "sha256:m".into(),
                            blobs: vec!["sha256:b".into()],
                        })
                        .unwrap();

                    let br = store.backrefs("r", "sha256:b");
                    assert_eq!(br.len(), 1);
                }

                #[test]
                fn delete_manifest_preserves_other_backrefs() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = $make_store(dir.path());

                    // Two manifests reference the same blob
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                            media_type: "mt".into(),
                            tag: None,
                            references: vec!["sha256:shared".into()],
                            referrer: None,
                        })
                        .unwrap();
                    store
                        .apply(MetaOp::PutManifest {
                            repo: "r".into(),
                            digest: "sha256:m2".into(),
                            media_type: "mt".into(),
                            tag: None,
                            references: vec!["sha256:shared".into()],
                            referrer: None,
                        })
                        .unwrap();

                    let mut br = store.backrefs("r", "sha256:shared");
                    br.sort();
                    assert_eq!(br, vec!["sha256:m1", "sha256:m2"]);

                    // Delete m1 — m2's backref survives
                    store
                        .apply(MetaOp::DeleteManifest {
                            repo: "r".into(),
                            digest: "sha256:m1".into(),
                        })
                        .unwrap();

                    assert_eq!(store.backrefs("r", "sha256:shared"), vec!["sha256:m2"]);
                }
            }
        };
    }

    // ---- Log engine -------------------------------------------------------
    engine_tests!(log_engine, |root: &Path| {
        LogMetadataStore::open(root).unwrap()
    });

    // ---- LMDB engine (feature-gated) -------------------------------------
    #[cfg(feature = "lmdb")]
    engine_tests!(lmdb_engine, |root: &Path| {
        LmdbMetadataStore::open(root, &MetadataConfig::default()).unwrap()
    });

    // ---- LMDB encrypted engine -------------------------------------------
    #[cfg(feature = "lmdb")]
    engine_tests!(lmdb_encrypted_engine, |root: &Path| {
        let key_path = root.join("hmac-test.key");
        std::fs::write(&key_path, b"test-key-material-32-bytes-long!").unwrap();
        let config = MetadataConfig {
            hmac_key_file: Some(key_path),
            ..MetadataConfig::default()
        };
        LmdbMetadataStore::open(root, &config).unwrap()
    });

    // ---- open_metadata dispatch -------------------------------------------

    #[test]
    fn open_metadata_log() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = open_metadata(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:a".into(),
                media_type: "mt".into(),
                tag: Some("t".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        assert!(store.resolve_tag("r", "t").is_some());
    }

    #[cfg(feature = "lmdb")]
    #[test]
    fn open_metadata_lmdb() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let store = open_metadata(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:a".into(),
                media_type: "mt".into(),
                tag: Some("t".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        assert!(store.resolve_tag("r", "t").is_some());
    }

    #[cfg(not(feature = "lmdb"))]
    #[test]
    fn open_metadata_lmdb_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        match open_metadata(dir.path(), &config) {
            Ok(_) => panic!("expected Unsupported error"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
        }
    }

    // ---- LMDB persistence across reopen ----------------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn lmdb_persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();

        {
            let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
            let desc = descriptor(Some("sbom"));
            store
                .apply(MetaOp::PutManifest {
                    repo: "r".into(),
                    digest: "sha256:m".into(),
                    media_type: "mt".into(),
                    tag: Some("v1".into()),
                    references: vec!["sha256:blob".into()],
                    referrer: Some(("sha256:subj".into(), desc)),
                })
                .unwrap();
            store
                .apply(MetaOp::PutChecksum {
                    repo: "r".into(),
                    digest: "sha256:blob".into(),
                    crc32c: 99,
                    size: 200,
                })
                .unwrap();
        }

        // Reopen and verify everything survived
        {
            let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
            let (d, mt) = store.resolve_tag("r", "v1").unwrap();
            assert_eq!(d, "sha256:m");
            assert_eq!(mt, "mt");
            assert_eq!(store.manifest_media_type("r", "sha256:m").unwrap(), "mt");
            assert_eq!(store.backrefs("r", "sha256:blob"), vec!["sha256:m"]);
            assert!(store.has_referrer("r", "sha256:subj", "sha256:m"));
            let bc = store.checksum("r", "sha256:blob").unwrap();
            assert_eq!(bc.crc32c, 99);
            assert_eq!(bc.size, 200);
            assert_eq!(store.repos(), vec!["r"]);
            let snap = store.tags_snapshot("r");
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].0, "v1");
        }
    }

    // ---- Config rejects engine = "redb" ----------------------------------
    #[test]
    fn config_rejects_redb_engine() {
        let toml_str = r#"
            [storage.metadata]
            engine = "redb"
        "#;
        // serde accepts the variant (it's kept for a clear message) but
        // validation rejects it.
        let config: roci_config::Config = toml::from_str(toml_str).unwrap();
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("storage.metadata.engine"),
            "error should name the field: {msg}"
        );
        assert!(
            msg.contains("redb engine has been removed"),
            "error should explain removal: {msg}"
        );
        assert!(msg.contains("lmdb"), "error should suggest lmdb: {msg}");
    }

    // ====================================================================
    // Migration / engine-switch tests
    // ====================================================================

    /// Seed a store with a representative op sequence.
    fn seed_ops(store: &dyn MetadataStore) {
        let desc_sbom = descriptor(Some("sbom/cyclonedx"));
        let desc_sig = descriptor(Some("sig/cosign"));

        // Manifest with tag and references
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v1".into()),
                references: vec!["sha256:cfg".into(), "sha256:layer1".into()],
                referrer: None,
            })
            .unwrap();

        // Multiple tags for the same manifest
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("latest".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();

        // Untagged manifest with referrer
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:sbom1".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: None,
                references: vec![],
                referrer: Some(("sha256:m1".into(), desc_sbom.clone())),
            })
            .unwrap();

        // Standalone PutReferrer
        store
            .apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:m1".into(),
                referrer: "sha256:sig1".into(),
                descriptor: desc_sig.clone(),
            })
            .unwrap();

        // PutBackrefs
        store
            .apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m1".into(),
                blobs: vec!["sha256:extra_blob".into()],
            })
            .unwrap();

        // PutChecksum
        store
            .apply(MetaOp::PutChecksum {
                repo: "r".into(),
                digest: "sha256:layer1".into(),
                crc32c: 12345,
                size: 98765,
            })
            .unwrap();

        // Second repo
        store
            .apply(MetaOp::PutManifest {
                repo: "other/repo".into(),
                digest: "sha256:m2".into(),
                media_type: "application/vnd.oci.image.index.v1+json".into(),
                tag: Some("stable".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();

        // Delete a manifest then re-add (exercise the delete path isn't exported)
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:deleted".into(),
                media_type: "m".into(),
                tag: Some("gone".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        store
            .apply(MetaOp::DeleteManifest {
                repo: "r".into(),
                digest: "sha256:deleted".into(),
            })
            .unwrap();
    }

    /// Assert two stores have identical visible state.
    fn assert_stores_equal(a: &dyn MetadataStore, b: &dyn MetadataStore) {
        assert_eq!(a.repos(), b.repos(), "repos differ");
        for repo in &a.repos() {
            let mut am = a.manifests(repo);
            am.sort();
            let mut bm = b.manifests(repo);
            bm.sort();
            assert_eq!(am, bm, "manifests differ for {repo}");

            assert_eq!(
                a.tags_snapshot(repo),
                b.tags_snapshot(repo),
                "tags differ for {repo}"
            );

            // Referrers (sort for comparison)
            let mut ar = a.referrers_snapshot(repo);
            ar.sort_by(|x, y| x.0.cmp(&y.0));
            for (_, refs) in &mut ar {
                refs.sort_by(|x, y| x.0.cmp(&y.0));
            }
            let mut br = b.referrers_snapshot(repo);
            br.sort_by(|x, y| x.0.cmp(&y.0));
            for (_, refs) in &mut br {
                refs.sort_by(|x, y| x.0.cmp(&y.0));
            }
            assert_eq!(ar, br, "referrers differ for {repo}");

            // Check individual queries
            for (tag, digest, media_type) in &a.tags_snapshot(repo) {
                let (d, mt) = b.resolve_tag(repo, tag).unwrap_or_else(|| {
                    panic!("tag {tag} missing in dest for {repo}");
                });
                assert_eq!(&d, digest);
                assert_eq!(&mt, media_type);
            }

            for digest in &am {
                assert_eq!(
                    a.manifest_media_type(repo, digest),
                    b.manifest_media_type(repo, digest),
                    "media_type differs for {repo}/{digest}"
                );
                assert_eq!(
                    a.checksum(repo, digest),
                    b.checksum(repo, digest),
                    "checksum differs for {repo}/{digest}"
                );
                let mut ab = a.backrefs(repo, digest);
                ab.sort();
                let mut bb = b.backrefs(repo, digest);
                bb.sort();
                assert_eq!(ab, bb, "backrefs differ for {repo}/{digest}");
            }

            // Referrer pages
            let tags = a.tags_page(repo, None, 1000);
            let tags_b = b.tags_page(repo, None, 1000);
            assert_eq!(tags, tags_b, "tags_page differs for {repo}");

            // Referrers page (unfiltered and filtered)
            for (subject, _) in &ar {
                let pa = a.referrers_page(repo, subject, None, None, 1000);
                let pb = b.referrers_page(repo, subject, None, None, 1000);
                assert_eq!(pa, pb, "referrers_page differs for {repo}/{subject}");

                let pa_sbom = a.referrers_page(repo, subject, Some("sbom/cyclonedx"), None, 1000);
                let pb_sbom = b.referrers_page(repo, subject, Some("sbom/cyclonedx"), None, 1000);
                assert_eq!(pa_sbom, pb_sbom, "filtered referrers_page differs");
            }
        }
    }

    // ---- Round trip: log → lmdb → log ------------------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn migration_round_trip_plain() {
        let dir = tempfile::tempdir().unwrap();
        let log_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Log,
            ..MetadataConfig::default()
        };

        // Populate via log engine.
        {
            let store = open_metadata(dir.path(), &log_config).unwrap();
            seed_ops(&*store);
        }

        // Switch to lmdb.
        let lmdb_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let lmdb_store = open_metadata(dir.path(), &lmdb_config).unwrap();

        // Marker should say lmdb.
        let marker = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.engine, "lmdb");
        assert_eq!(marker.format, "plain");

        // Old log should be moved to *.migrated-*.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("roci-meta.log.migrated-")
            })
            .collect();
        assert!(!entries.is_empty(), "old log should be moved aside");

        // Verify the lmdb store has all the data.
        // Re-open source log from the migrated file for comparison.
        let log_migrated = entries[0].path();
        let verify_dir = tempfile::tempdir().unwrap();
        std::fs::copy(&log_migrated, verify_dir.path().join("roci-meta.log")).unwrap();
        let log_store_verify = LogMetadataStore::open(verify_dir.path()).unwrap();
        assert_stores_equal(&log_store_verify, &*lmdb_store);

        // Now switch back to log.
        drop(lmdb_store);
        let log_config2 = MetadataConfig {
            engine: roci_config::MetadataEngine::Log,
            ..MetadataConfig::default()
        };
        let log_store2 = open_metadata(dir.path(), &log_config2).unwrap();

        let marker2 = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker2.engine, "log");

        // Old lmdb should be moved aside.
        let lmdb_migrated: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("roci-meta.lmdb.migrated-")
            })
            .collect();
        assert!(!lmdb_migrated.is_empty(), "old lmdb should be moved aside");

        // Round trip should preserve all data.
        assert_stores_equal(&log_store_verify, &*log_store2);
    }

    // ---- Round trip with HMAC key ----------------------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn migration_round_trip_hmac() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("hmac-test.key");
        std::fs::write(&key_path, b"test-key-material-32-bytes-long!").unwrap();

        let log_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Log,
            hmac_key_file: Some(key_path.clone()),
            ..MetadataConfig::default()
        };

        {
            let store = open_metadata(dir.path(), &log_config).unwrap();
            seed_ops(&*store);
        }

        // Switch to encrypted lmdb.
        let lmdb_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            hmac_key_file: Some(key_path.clone()),
            ..MetadataConfig::default()
        };
        let lmdb_store = open_metadata(dir.path(), &lmdb_config).unwrap();

        let marker = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.engine, "lmdb");
        assert_eq!(marker.format, "chacha20poly1305-v1");

        // Switch back to log.
        drop(lmdb_store);
        let log_store = open_metadata(dir.path(), &log_config).unwrap();

        let marker2 = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker2.engine, "log");
        assert_eq!(marker2.format, "hmac");

        // Verify round trip.
        let verify_dir = tempfile::tempdir().unwrap();
        let log_migrated: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("roci-meta.log.migrated-")
            })
            .collect();
        // The migrated log was from the first switch. Copy it to verify.
        std::fs::copy(
            log_migrated[0].path(),
            verify_dir.path().join("roci-meta.log"),
        )
        .unwrap();
        std::fs::copy(&key_path, verify_dir.path().join("hmac-test.key")).unwrap();
        let orig = LogMetadataStore::open_with(
            verify_dir.path(),
            &MetadataConfig {
                hmac_key_file: Some(verify_dir.path().join("hmac-test.key")),
                ..MetadataConfig::default()
            },
        )
        .unwrap();
        assert_stores_equal(&orig, &*log_store);
    }

    // ---- Crash: leftover .migrating cleaned up ---------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn crash_leftover_migrating_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let log_config = MetadataConfig::default();

        {
            let store = open_metadata(dir.path(), &log_config).unwrap();
            seed_ops(&*store);
        }

        // Simulate a crashed migration leaving a .migrating dir.
        let leftover = dir.path().join("roci-meta.lmdb.migrating");
        std::fs::create_dir_all(&leftover).unwrap();
        std::fs::write(leftover.join("dummy"), b"stale").unwrap();

        // Switch to lmdb — should clean up the leftover and succeed.
        let lmdb_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let store = open_metadata(dir.path(), &lmdb_config).unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());
        assert!(!leftover.exists(), "leftover should be removed");
    }

    // ---- Crash: leftover .migrating file for log -------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn crash_leftover_migrating_file_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let lmdb_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };

        {
            let store = open_metadata(dir.path(), &lmdb_config).unwrap();
            seed_ops(&*store);
        }

        // Simulate a crashed migration leaving a .migrating file.
        let leftover = dir.path().join("roci-meta.log.migrating");
        std::fs::write(&leftover, b"stale log data").unwrap();

        // Switch to log — should clean up and succeed.
        let log_config = MetadataConfig::default();
        let store = open_metadata(dir.path(), &log_config).unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());
        assert!(!leftover.exists(), "leftover should be removed");
    }

    // ---- Stale destination moved aside -----------------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn stale_destination_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let log_config = MetadataConfig::default();

        // Create with log, then switch to lmdb.
        {
            let store = open_metadata(dir.path(), &log_config).unwrap();
            seed_ops(&*store);
        }

        let lmdb_config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        {
            let _ = open_metadata(dir.path(), &lmdb_config).unwrap();
        }

        // Now switch back to log — the old lmdb dir is the "stale destination".
        {
            let _ = open_metadata(dir.path(), &log_config).unwrap();
        }

        // Switch to lmdb again — the leftover roci-meta.lmdb.migrated-* from
        // the previous back-switch should not interfere; the fresh log data
        // should be migrated.
        let store = open_metadata(dir.path(), &lmdb_config).unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());
    }

    // ---- No-marker upgrade: log artifact only ----------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn no_marker_log_artifact_only() {
        let dir = tempfile::tempdir().unwrap();

        // Create a log store without any marker.
        {
            let store = LogMetadataStore::open(dir.path()).unwrap();
            seed_ops(&store);
        }
        assert!(!marker_path(dir.path()).exists());

        // Open with log config — should detect log, open it, write marker.
        let config = MetadataConfig::default();
        let store = open_metadata(dir.path(), &config).unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());
        assert!(marker_path(dir.path()).exists());

        let marker = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.engine, "log");
    }

    // ---- No-marker upgrade: lmdb artifact only ---------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn no_marker_lmdb_artifact_only() {
        let dir = tempfile::tempdir().unwrap();

        // Create an lmdb store without marker.
        {
            let config = MetadataConfig {
                engine: roci_config::MetadataEngine::Lmdb,
                ..MetadataConfig::default()
            };
            let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
            seed_ops(&store);
        }
        // No marker yet (LmdbMetadataStore::open doesn't write one).
        assert!(!marker_path(dir.path()).exists());

        // Open with lmdb config — should detect lmdb, open it, write marker.
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let store = open_metadata(dir.path(), &config).unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());

        let marker = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.engine, "lmdb");
    }

    // ---- No-marker upgrade: both artifacts, config wins ------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn no_marker_both_artifacts_config_wins() {
        let dir = tempfile::tempdir().unwrap();

        // Create both a log and an lmdb store.
        {
            let store = LogMetadataStore::open(dir.path()).unwrap();
            seed_ops(&store);
        }
        {
            let config = MetadataConfig {
                engine: roci_config::MetadataEngine::Lmdb,
                ..MetadataConfig::default()
            };
            let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
            seed_ops(&store);
        }

        // Open with lmdb config — should warn and use lmdb.
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let store = open_metadata(dir.path(), &config).unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());

        let marker = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.engine, "lmdb");
    }

    // ---- Verify-mismatch: export failure aborts with source intact -------
    #[cfg(feature = "lmdb")]
    #[test]
    fn verify_mismatch_aborts_source_intact() {
        // We test the verify_migration function directly by constructing
        // a destination that is intentionally different.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let store_a = LogMetadataStore::open(dir_a.path()).unwrap();
        seed_ops(&store_a);

        // Create a different store_b (missing some data).
        let store_b = LogMetadataStore::open(dir_b.path()).unwrap();
        store_b
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v1".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();

        let result = verify_migration(&store_a, &store_b);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("migration verify failed"),
            "error should mention verify: {err_msg}"
        );

        // Source should be intact.
        assert!(store_a.resolve_tag("r", "v1").is_some());
        assert!(store_a.resolve_tag("other/repo", "stable").is_some());
    }

    // ---- No-marker, no-artifacts: fresh start ----------------------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn no_marker_no_artifacts_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let store = open_metadata(dir.path(), &config).unwrap();
        assert_eq!(store.repos(), Vec::<String>::new());

        let marker = read_marker(dir.path()).unwrap().unwrap();
        assert_eq!(marker.engine, "lmdb");
    }

    // ---- Export round trip: log export → apply → compare -----------------
    #[test]
    fn log_export_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LogMetadataStore::open(dir.path()).unwrap();
        seed_ops(&store);

        let mut ops = Vec::new();
        store
            .export(&mut |op| {
                ops.push(op);
                Ok(())
            })
            .unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = LogMetadataStore::open(dir2.path()).unwrap();
        for op in ops {
            store2.apply(op).unwrap();
        }

        assert_stores_equal(&store, &store2);
    }

    // ---- Export round trip: lmdb export → apply → compare ----------------
    #[cfg(feature = "lmdb")]
    #[test]
    fn lmdb_export_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            engine: roci_config::MetadataEngine::Lmdb,
            ..MetadataConfig::default()
        };
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
        seed_ops(&store);

        let mut ops = Vec::new();
        store
            .export(&mut |op| {
                ops.push(op);
                Ok(())
            })
            .unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = LmdbMetadataStore::open(dir2.path(), &config).unwrap();
        for op in ops {
            store2.apply(op).unwrap();
        }

        assert_stores_equal(&store, &store2);
    }
}
