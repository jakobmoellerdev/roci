//! Feature-gated embedded B+ tree metadata engine backed by LMDB via heed
//! (stable mdb.master branch; ARCHITECTURE §Metadata index engine).
//!
//! Every query is a bounded range seek over named LMDB databases whose
//! composite keys encode `(repo, …)` prefixes with `\0` separators — no
//! full-table scans, no in-RAM index copies. One [`RwTxn`] per
//! [`MetadataStore::apply`] call keeps every [`MetaOp`] atomic (the combined
//! `PutManifest` stays one record). [`apply_relaxed`](MetadataStore::apply_relaxed)
//! commits without fsync (env opened with `NO_SYNC`; `apply` and `maintain`
//! call [`force_sync`](heed::Env::force_sync) after commit).

use super::{BlobChecksum, MetaOp, MetadataStore, Page, Referrer};
use heed::types::Bytes;
use heed::{Database, DatabaseFlags, EnvFlags, EnvOpenOptions, WithoutTls};
use roci_config::MetadataConfig;
use std::io;
use std::ops::Bound;
use std::path::Path;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Named LMDB databases
// ---------------------------------------------------------------------------
//
// Composite keys: parts joined with `\0` after each part, so a prefix
// `"repo\0"` never accidentally matches `"repo2\0…"`. Byte-order ==
// tuple order. All queries use bounded range/prefix seeks.

/// Number of named databases we create. `max_dbs` must be ≥ this.
const DB_COUNT: u32 = 10;

// Convenience alias.
type Db = Database<Bytes, Bytes>;

// ---------------------------------------------------------------------------
// Database-index constants — used to index into the arrays in `Dbs`.
// ---------------------------------------------------------------------------

const I_TAGS: usize = 0;
const I_TAGS_BY_DIGEST: usize = 1;
const I_MEDIA_TYPES: usize = 2;
const I_REFERRERS: usize = 3;
const I_REFERRER_TYPES: usize = 4;
const I_REFERRERS_BY_TYPE: usize = 5;
const I_REFERRERS_REVERSE: usize = 6;
const I_BACKREFS: usize = 7; // DUP_SORT
const I_BACKREFS_REVERSE: usize = 8; // DUP_SORT
const I_CHECKSUMS: usize = 9;

// ---------------------------------------------------------------------------
// Composite key helpers
// ---------------------------------------------------------------------------

/// Build a composite key from parts: each part is followed by `\0`.
fn make_key(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len() + 1).sum();
    let mut buf = Vec::with_capacity(total);
    for p in parts {
        buf.extend_from_slice(p);
        buf.push(0);
    }
    buf
}

/// Build a prefix from the first N parts of a composite key.
fn make_prefix(parts: &[&[u8]]) -> Vec<u8> {
    make_key(parts) // same encoding; prefix_iter matches by prefix bytes
}

/// The exclusive upper-bound key for a prefix: increment the last byte that is
/// not `0xFF`. Returns `None` if the prefix is all-`0xFF` (degenerate).
fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut s = prefix.to_vec();
    while let Some(&last) = s.last() {
        if last < 0xFF {
            *s.last_mut().unwrap() += 1;
            return Some(s);
        }
        s.pop();
    }
    None
}

/// Build a half-open `[start, end)` range of `(Bound<&[u8]>, Bound<&[u8]>)`,
/// which satisfies `RangeBounds<[u8]>` for heed's `Database::range`.
fn byte_range<'a>(start: &'a [u8], end: &'a [u8]) -> (Bound<&'a [u8]>, Bound<&'a [u8]>) {
    (Bound::Included(start), Bound::Excluded(end))
}

/// Split a composite key on `\0` separators.
fn split_key(key: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (i, &b) in key.iter().enumerate() {
        if b == 0 {
            parts.push(&key[start..i]);
            start = i + 1;
        }
    }
    parts
}

// ---------------------------------------------------------------------------
// Checksum encoding (12 bytes: u32 LE crc32c + u64 LE size)
// ---------------------------------------------------------------------------

fn encode_checksum(crc: u32, size: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[..4].copy_from_slice(&crc.to_le_bytes());
    buf[4..].copy_from_slice(&size.to_le_bytes());
    buf
}

fn decode_checksum(bytes: &[u8]) -> BlobChecksum {
    let crc32c = u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"));
    let size = u64::from_le_bytes(bytes[4..12].try_into().expect("8 bytes"));
    BlobChecksum { crc32c, size }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_heed_err(e: heed::Error) -> io::Error {
    let msg = e.to_string();
    if msg.contains("MDB_MAP_FULL") {
        io::Error::other(format!(
            "LMDB map full — increase `storage.metadata.map_size_bytes` \
             in the config; current error: {e}"
        ))
    } else {
        io::Error::other(format!("lmdb: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Database names (in creation order)
// ---------------------------------------------------------------------------

const DB_NAMES: [&str; 10] = [
    "tags",
    "tags_by_digest",
    "media_types",
    "referrers",
    "referrer_types",
    "referrers_by_type",
    "referrers_reverse",
    "backrefs",
    "backrefs_reverse",
    "checksums",
];

/// Which databases use DUP_SORT.
const DUP_SORT_INDICES: [usize; 2] = [I_BACKREFS, I_BACKREFS_REVERSE];

fn is_dup_sort(idx: usize) -> bool {
    DUP_SORT_INDICES.contains(&idx)
}

// ---------------------------------------------------------------------------
// open_env: single env-open helper — the only `unsafe` env open site
// ---------------------------------------------------------------------------

/// Open (or create) an LMDB env at `dir` with the given map size, returning
/// the env and all 10 named databases. There is exactly one `unsafe` env open
/// and one `unsafe` NO_SYNC flags call, both audited here.
fn open_env(dir: &Path, map_size: usize) -> io::Result<(heed::Env<WithoutTls>, [Db; 10])> {
    std::fs::create_dir_all(dir)
        .map_err(|e| io::Error::new(e.kind(), format!("creating {}: {e}", dir.display())))?;

    let mut opts = EnvOpenOptions::new().read_txn_without_tls();
    opts.map_size(map_size);
    opts.max_dbs(DB_COUNT);

    #[allow(unsafe_code)]
    // SAFETY: NO_SYNC is required for `apply_relaxed` to skip fsync;
    // `apply` and `maintain` call `force_sync()` explicitly. Single
    // process owns the env dir (ARCHITECTURE.md invariant 6).
    unsafe {
        opts.flags(EnvFlags::NO_SYNC);
    }

    #[allow(unsafe_code)]
    // SAFETY: single-process ownership, local filesystem, no concurrent
    // external writers. SIGBUS on external truncation is the same risk as
    // the snapshot mmap the log engine already accepts.
    let env = unsafe { opts.open(dir) }.map_err(map_heed_err)?;

    let mut wtxn = env.write_txn().map_err(map_heed_err)?;
    let mut dbs_arr: [Option<Db>; 10] = Default::default();
    for (i, name) in DB_NAMES.iter().enumerate() {
        let db = if is_dup_sort(i) {
            env.database_options()
                .types::<Bytes, Bytes>()
                .name(name)
                .flags(DatabaseFlags::DUP_SORT)
                .create(&mut wtxn)
                .map_err(map_heed_err)?
        } else {
            env.create_database(&mut wtxn, Some(name))
                .map_err(map_heed_err)?
        };
        dbs_arr[i] = Some(db);
    }
    wtxn.commit().map_err(map_heed_err)?;
    let dbs = dbs_arr.map(|o| o.expect("all dbs created"));
    Ok((env, dbs))
}

// ---------------------------------------------------------------------------
// LmdbMetadataStore
// ---------------------------------------------------------------------------

/// Embedded LMDB metadata engine.
///
/// The env directory lives at `<root>/roci-meta.lmdb/`. All queries are
/// bounded range seeks — no in-RAM copies of the full dataset. A single
/// `Mutex<()>` serializes write transactions (LMDB enforces single-writer
/// anyway); reads use `read_txn` which can overlap.
pub struct LmdbMetadataStore {
    env: heed::Env<WithoutTls>,
    dbs: [Db; 10],
    write_lock: Mutex<()>,
}

impl LmdbMetadataStore {
    /// Open (or create) the LMDB metadata store at `<root>/roci-meta.lmdb/`.
    pub fn open(root: &Path, config: &MetadataConfig) -> io::Result<Self> {
        let dir = root.join("roci-meta.lmdb");

        if config.hmac_key_file.is_some() {
            tracing::info!(
                "hmac_key_file only authenticates the log engine; \
                 LMDB relies on volume encryption"
            );
        }

        let map_size = config.map_size_bytes as usize;
        let (env, dbs) = open_env(&dir, map_size)?;

        // Warn about leftover redb database (never delete — user may want it).
        let redb_path = root.join("roci-meta.redb");
        if redb_path.exists() {
            tracing::warn!(
                path = %redb_path.display(),
                "found obsolete redb metadata database; \
                 the redb engine has been removed — the file is no longer used \
                 and can be deleted manually"
            );
        }

        Ok(Self {
            env,
            dbs,
            write_lock: Mutex::new(()),
        })
    }

    /// Apply `op` and optionally fsync.
    fn apply_inner(&self, op: MetaOp, durable: bool) -> io::Result<()> {
        let _guard = self.write_lock.lock().expect("lmdb write lock poisoned");
        let mut txn = self.env.write_txn().map_err(map_heed_err)?;
        self.apply_op(&mut txn, &op)?;
        txn.commit().map_err(map_heed_err)?;
        if durable {
            self.env.force_sync().map_err(map_heed_err)?;
        }
        roci_telemetry::record_meta_wal_append();
        Ok(())
    }

    fn apply_op(&self, txn: &mut heed::RwTxn<'_>, op: &MetaOp) -> io::Result<()> {
        match op {
            MetaOp::PutManifest {
                repo,
                digest,
                media_type,
                tag,
                references,
                referrer,
            } => {
                // media type
                {
                    let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                    self.dbs[I_MEDIA_TYPES]
                        .put(txn, &key, media_type.as_bytes())
                        .map_err(map_heed_err)?;
                }
                // tag
                if let Some(tag) = tag {
                    let tag_key = make_key(&[repo.as_bytes(), tag.as_bytes()]);
                    // Remove old reverse entry if this tag pointed elsewhere
                    if let Some(old_val) =
                        self.dbs[I_TAGS].get(txn, &tag_key).map_err(map_heed_err)?
                    {
                        if let Some(sep) = old_val.iter().position(|&b| b == 0) {
                            let old_digest = &old_val[..sep];
                            let rev_key = make_key(&[repo.as_bytes(), old_digest, tag.as_bytes()]);
                            self.dbs[I_TAGS_BY_DIGEST]
                                .delete(txn, &rev_key)
                                .map_err(map_heed_err)?;
                        }
                    }
                    let mut val = Vec::with_capacity(digest.len() + 1 + media_type.len());
                    val.extend_from_slice(digest.as_bytes());
                    val.push(0);
                    val.extend_from_slice(media_type.as_bytes());
                    self.dbs[I_TAGS]
                        .put(txn, &tag_key, &val)
                        .map_err(map_heed_err)?;

                    let rev_key = make_key(&[repo.as_bytes(), digest.as_bytes(), tag.as_bytes()]);
                    self.dbs[I_TAGS_BY_DIGEST]
                        .put(txn, &rev_key, &[])
                        .map_err(map_heed_err)?;
                }
                // backrefs
                self.add_backrefs_in_txn(txn, repo, digest, references)?;
                // referrer
                if let Some((subject, descriptor)) = referrer {
                    self.add_referrer_in_txn(txn, repo, subject, digest, descriptor)?;
                }
            }

            MetaOp::DeleteManifest { repo, digest } => {
                // Remove checksum + media type
                {
                    let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                    self.dbs[I_CHECKSUMS]
                        .delete(txn, &key)
                        .map_err(map_heed_err)?;
                    self.dbs[I_MEDIA_TYPES]
                        .delete(txn, &key)
                        .map_err(map_heed_err)?;
                }
                // Drop every tag pointing at this digest
                {
                    let prefix = make_prefix(&[repo.as_bytes(), digest.as_bytes()]);
                    let keys = keys_with_prefix(&self.dbs[I_TAGS_BY_DIGEST], txn, &prefix)?;
                    for rev_key in &keys {
                        let parts = split_key(rev_key);
                        if parts.len() >= 3 {
                            let tag = parts[2];
                            let tag_key = make_key(&[repo.as_bytes(), tag]);
                            self.dbs[I_TAGS]
                                .delete(txn, &tag_key)
                                .map_err(map_heed_err)?;
                        }
                        self.dbs[I_TAGS_BY_DIGEST]
                            .delete(txn, rev_key)
                            .map_err(map_heed_err)?;
                    }
                }
                // Drop this digest as a referrer of any subject
                {
                    let prefix = make_prefix(&[repo.as_bytes(), digest.as_bytes()]);
                    let keys = keys_with_prefix(&self.dbs[I_REFERRERS_REVERSE], txn, &prefix)?;
                    for rev_key in &keys {
                        let parts = split_key(rev_key);
                        if parts.len() >= 3 {
                            let subject = parts[2];
                            self.remove_referrer_in_txn(
                                txn,
                                repo,
                                std::str::from_utf8(subject).unwrap_or(""),
                                digest,
                            )?;
                        }
                    }
                }
                // Drop this digest from every blob's backref set
                {
                    let dup_key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                    let blobs = dup_values_in_write(&self.dbs[I_BACKREFS_REVERSE], txn, &dup_key)?;
                    for blob in &blobs {
                        let fwd_key = make_key(&[repo.as_bytes(), blob]);
                        self.dbs[I_BACKREFS]
                            .delete_one_duplicate(txn, &fwd_key, digest.as_bytes())
                            .map_err(map_heed_err)?;
                    }
                    self.dbs[I_BACKREFS_REVERSE]
                        .delete(txn, &dup_key)
                        .map_err(map_heed_err)?;
                }
            }

            MetaOp::PutBackrefs {
                repo,
                manifest,
                blobs,
            } => {
                self.add_backrefs_in_txn(txn, repo, manifest, blobs)?;
            }

            MetaOp::PutReferrer {
                repo,
                subject,
                referrer,
                descriptor,
            } => {
                self.add_referrer_in_txn(txn, repo, subject, referrer, descriptor)?;
            }

            MetaOp::PutChecksum {
                repo,
                digest,
                crc32c,
                size,
            } => {
                let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                let buf = encode_checksum(*crc32c, *size);
                self.dbs[I_CHECKSUMS]
                    .put(txn, &key, &buf)
                    .map_err(map_heed_err)?;
            }

            MetaOp::DeleteBlob { repo, digest } => {
                let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                self.dbs[I_CHECKSUMS]
                    .delete(txn, &key)
                    .map_err(map_heed_err)?;
            }
        }
        Ok(())
    }

    fn add_backrefs_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo: &str,
        manifest: &str,
        blobs: &[String],
    ) -> io::Result<()> {
        for blob in blobs {
            let fwd_key = make_key(&[repo.as_bytes(), blob.as_bytes()]);
            self.dbs[I_BACKREFS]
                .put(txn, &fwd_key, manifest.as_bytes())
                .map_err(map_heed_err)?;
            let rev_key = make_key(&[repo.as_bytes(), manifest.as_bytes()]);
            self.dbs[I_BACKREFS_REVERSE]
                .put(txn, &rev_key, blob.as_bytes())
                .map_err(map_heed_err)?;
        }
        Ok(())
    }

    fn add_referrer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo: &str,
        subject: &str,
        referrer: &str,
        descriptor: &[u8],
    ) -> io::Result<()> {
        self.remove_referrer_in_txn(txn, repo, subject, referrer)?;

        let artifact_type: Option<String> = serde_json::from_slice::<serde_json::Value>(descriptor)
            .ok()
            .and_then(|v| v.get("artifactType")?.as_str().map(str::to_string));

        {
            let key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
            self.dbs[I_REFERRERS]
                .put(txn, &key, descriptor)
                .map_err(map_heed_err)?;
        }
        {
            let rev_key = make_key(&[repo.as_bytes(), referrer.as_bytes(), subject.as_bytes()]);
            self.dbs[I_REFERRERS_REVERSE]
                .put(txn, &rev_key, &[])
                .map_err(map_heed_err)?;
        }
        if let Some(at) = &artifact_type {
            let rt_key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
            self.dbs[I_REFERRER_TYPES]
                .put(txn, &rt_key, at.as_bytes())
                .map_err(map_heed_err)?;
            let bt_key = make_key(&[
                repo.as_bytes(),
                subject.as_bytes(),
                at.as_bytes(),
                referrer.as_bytes(),
            ]);
            self.dbs[I_REFERRERS_BY_TYPE]
                .put(txn, &bt_key, &[])
                .map_err(map_heed_err)?;
        }
        Ok(())
    }

    fn remove_referrer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo: &str,
        subject: &str,
        referrer: &str,
    ) -> io::Result<()> {
        let rt_key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
        let had_type = self.dbs[I_REFERRER_TYPES]
            .get(txn, &rt_key)
            .map_err(map_heed_err)?
            .map(|v| v.to_vec());

        {
            let key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
            self.dbs[I_REFERRERS]
                .delete(txn, &key)
                .map_err(map_heed_err)?;
        }
        {
            let rev_key = make_key(&[repo.as_bytes(), referrer.as_bytes(), subject.as_bytes()]);
            self.dbs[I_REFERRERS_REVERSE]
                .delete(txn, &rev_key)
                .map_err(map_heed_err)?;
        }
        self.dbs[I_REFERRER_TYPES]
            .delete(txn, &rt_key)
            .map_err(map_heed_err)?;
        if let Some(at) = &had_type {
            let bt_key = make_key(&[repo.as_bytes(), subject.as_bytes(), at, referrer.as_bytes()]);
            self.dbs[I_REFERRERS_BY_TYPE]
                .delete(txn, &bt_key)
                .map_err(map_heed_err)?;
        }
        Ok(())
    }
}

impl LmdbMetadataStore {
    /// Open an LMDB env at an arbitrary directory (used for migration temp).
    pub(crate) fn open_at(dir: &Path, config: &MetadataConfig) -> io::Result<Self> {
        let map_size = config.map_size_bytes as usize;
        let (env, dbs) = open_env(dir, map_size)?;
        Ok(Self {
            env,
            dbs,
            write_lock: Mutex::new(()),
        })
    }

    /// Apply a batch of ops in one RwTxn (for migration bulk load).
    pub(crate) fn bulk_apply(&self, ops: &[MetaOp]) -> io::Result<()> {
        let _guard = self.write_lock.lock().expect("lmdb write lock poisoned");
        let mut txn = self.env.write_txn().map_err(map_heed_err)?;
        for op in ops {
            self.apply_op(&mut txn, op)?;
        }
        txn.commit().map_err(map_heed_err)?;
        Ok(())
    }

    /// Force sync (public wrapper for migration).
    pub(crate) fn force_sync_public(&self) -> io::Result<()> {
        self.env.force_sync().map_err(map_heed_err)
    }

    /// Walk all LMDB tables in one read txn and emit MetaOp ops via the sink.
    fn export_impl(&self, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
        let rtx = self.env.read_txn().map_err(map_heed_err)?;

        // Collect all tags to know which digests are tagged.
        let mut tagged = std::collections::BTreeSet::<(String, String)>::new();

        // 1. Tags → PutManifest with tag
        {
            let iter = self.dbs[I_TAGS].iter(&rtx).map_err(map_heed_err)?;
            for entry in iter {
                let (k, v) = entry.map_err(map_heed_err)?;
                let parts = split_key(k);
                if parts.len() < 2 {
                    continue;
                }
                let repo = std::str::from_utf8(parts[0]).unwrap_or("");
                let tag = std::str::from_utf8(parts[1]).unwrap_or("");
                let sep = match v.iter().position(|&b| b == 0) {
                    Some(s) => s,
                    None => continue,
                };
                let digest = std::str::from_utf8(&v[..sep]).unwrap_or("");
                let media_type = std::str::from_utf8(&v[sep + 1..]).unwrap_or("");
                tagged.insert((repo.to_string(), digest.to_string()));
                sink(MetaOp::PutManifest {
                    repo: repo.to_string(),
                    digest: digest.to_string(),
                    media_type: media_type.to_string(),
                    tag: Some(tag.to_string()),
                    references: Vec::new(),
                    referrer: None,
                })?;
            }
        }

        // 2. Untagged manifests (media_types not in tagged set) → PutManifest
        {
            let iter = self.dbs[I_MEDIA_TYPES].iter(&rtx).map_err(map_heed_err)?;
            for entry in iter {
                let (k, v) = entry.map_err(map_heed_err)?;
                let parts = split_key(k);
                if parts.len() < 2 {
                    continue;
                }
                let repo = std::str::from_utf8(parts[0]).unwrap_or("");
                let digest = std::str::from_utf8(parts[1]).unwrap_or("");
                if tagged.contains(&(repo.to_string(), digest.to_string())) {
                    continue;
                }
                let media_type = std::str::from_utf8(v).unwrap_or("");
                sink(MetaOp::PutManifest {
                    repo: repo.to_string(),
                    digest: digest.to_string(),
                    media_type: media_type.to_string(),
                    tag: None,
                    references: Vec::new(),
                    referrer: None,
                })?;
            }
        }

        // 3. Backrefs → PutBackrefs
        {
            let iter = self.dbs[I_BACKREFS].iter(&rtx).map_err(map_heed_err)?;
            for entry in iter {
                let (k, v) = entry.map_err(map_heed_err)?;
                let parts = split_key(k);
                if parts.len() < 2 {
                    continue;
                }
                let repo = std::str::from_utf8(parts[0]).unwrap_or("");
                let blob = std::str::from_utf8(parts[1]).unwrap_or("");
                let manifest = std::str::from_utf8(v).unwrap_or("");
                sink(MetaOp::PutBackrefs {
                    repo: repo.to_string(),
                    manifest: manifest.to_string(),
                    blobs: vec![blob.to_string()],
                })?;
            }
        }

        // 4. Referrers → PutReferrer
        {
            let iter = self.dbs[I_REFERRERS].iter(&rtx).map_err(map_heed_err)?;
            for entry in iter {
                let (k, v) = entry.map_err(map_heed_err)?;
                let parts = split_key(k);
                if parts.len() < 3 {
                    continue;
                }
                let repo = std::str::from_utf8(parts[0]).unwrap_or("");
                let subject = std::str::from_utf8(parts[1]).unwrap_or("");
                let referrer = std::str::from_utf8(parts[2]).unwrap_or("");
                sink(MetaOp::PutReferrer {
                    repo: repo.to_string(),
                    subject: subject.to_string(),
                    referrer: referrer.to_string(),
                    descriptor: v.to_vec(),
                })?;
            }
        }

        // 5. Checksums → PutChecksum
        {
            let iter = self.dbs[I_CHECKSUMS].iter(&rtx).map_err(map_heed_err)?;
            for entry in iter {
                let (k, v) = entry.map_err(map_heed_err)?;
                let parts = split_key(k);
                if parts.len() < 2 {
                    continue;
                }
                let repo = std::str::from_utf8(parts[0]).unwrap_or("");
                let digest = std::str::from_utf8(parts[1]).unwrap_or("");
                let ck = decode_checksum(v);
                sink(MetaOp::PutChecksum {
                    repo: repo.to_string(),
                    digest: digest.to_string(),
                    crc32c: ck.crc32c,
                    size: ck.size,
                })?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free-standing read helpers — no `Inner` indirection, direct db access
// ---------------------------------------------------------------------------

/// Collect all (key, value) pairs in a range, fully owned.
fn range_owned(
    db: &Db,
    txn: &heed::RoTxn<'_, WithoutTls>,
    start: &[u8],
    end: &[u8],
) -> heed::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let r = &byte_range(start, end);
    let iter = db.range(txn, r)?;
    Ok(iter
        .filter_map(|e| e.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
        .collect())
}

/// Range inside a write txn.
fn range_in_write(
    db: &Db,
    txn: &mut heed::RwTxn<'_>,
    start: &[u8],
    end: &[u8],
) -> heed::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let r = &byte_range(start, end);
    let iter = db.range(txn, r)?;
    Ok(iter
        .filter_map(|e| e.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
        .collect())
}

/// Check if any key with prefix exists.
fn has_any_with_prefix(db: &Db, txn: &heed::RoTxn<'_, WithoutTls>, prefix: &[u8]) -> bool {
    let Some(end) = prefix_successor(prefix) else {
        return false;
    };
    let r = &byte_range(prefix, &end);
    db.range(txn, r).ok().and_then(|mut it| it.next()).is_some()
}

/// Collect all duplicate values for a key in a DUP_SORT db (write txn).
fn dup_values_in_write(db: &Db, txn: &mut heed::RwTxn<'_>, key: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut values = Vec::new();
    if let Some(iter) = db.get_duplicates(txn, key).map_err(map_heed_err)? {
        for entry in iter {
            let (_k, v) = entry.map_err(map_heed_err)?;
            values.push(v.to_vec());
        }
    }
    Ok(values)
}

/// Collect all duplicate values as strings (read txn).
fn dup_values_as_strings(db: &Db, txn: &heed::RoTxn<'_, WithoutTls>, key: &[u8]) -> Vec<String> {
    let mut values = Vec::new();
    if let Ok(Some(iter)) = db.get_duplicates(txn, key) {
        for (_k, v) in iter.flatten() {
            if let Ok(s) = std::str::from_utf8(v) {
                values.push(s.to_string());
            }
        }
    }
    values
}

/// Collect keys with a given prefix (write txn).
fn keys_with_prefix(db: &Db, txn: &mut heed::RwTxn<'_>, prefix: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let Some(end) = prefix_successor(prefix) else {
        return Ok(Vec::new());
    };
    range_in_write(db, txn, prefix, &end)
        .map(|pairs| pairs.into_iter().map(|(k, _)| k).collect())
        .map_err(map_heed_err)
}

// ---------------------------------------------------------------------------
// MetadataStore impl
// ---------------------------------------------------------------------------

impl MetadataStore for LmdbMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let rtx = self.env.read_txn().ok()?;
        let key = make_key(&[repo.as_bytes(), tag.as_bytes()]);
        let val = self.dbs[I_TAGS].get(&rtx, &key).ok()??;
        let sep = val.iter().position(|&b| b == 0)?;
        let digest = std::str::from_utf8(&val[..sep]).ok()?;
        let media_type = std::str::from_utf8(&val[sep + 1..]).ok()?;
        Some((digest.to_string(), media_type.to_string()))
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let rtx = self.env.read_txn().ok()?;
        let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
        let val = self.dbs[I_MEDIA_TYPES].get(&rtx, &key).ok()??;
        std::str::from_utf8(val).ok().map(str::to_string)
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let rtx = self.env.read_txn().ok()?;

        let repo_prefix = make_prefix(&[repo.as_bytes()]);
        if !has_any_with_prefix(&self.dbs[I_TAGS], &rtx, &repo_prefix) {
            return None;
        }

        let start = match last {
            Some(cursor) => {
                let mut k = make_key(&[repo.as_bytes(), cursor.as_bytes()]);
                k.push(0);
                k
            }
            None => repo_prefix.clone(),
        };

        let end = prefix_successor(&repo_prefix)?;
        let pairs = range_owned(&self.dbs[I_TAGS], &rtx, &start, &end).ok()?;

        let mut items = Vec::new();
        for (k, _v) in &pairs {
            let parts = split_key(k);
            if parts.is_empty() || parts[0] != repo.as_bytes() {
                break;
            }
            if items.len() == limit {
                return Some(Page { items, more: true });
            }
            if parts.len() >= 2 {
                items.push(String::from_utf8_lossy(parts[1]).into_owned());
            }
        }
        Some(Page { items, more: false })
    }

    fn referrers_page(
        &self,
        repo: &str,
        subject: &str,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Option<Page<Referrer>> {
        let rtx = self.env.read_txn().ok()?;

        match artifact_type {
            None => {
                let subj_prefix = make_prefix(&[repo.as_bytes(), subject.as_bytes()]);
                if !has_any_with_prefix(&self.dbs[I_REFERRERS], &rtx, &subj_prefix) {
                    return None;
                }
                let start = match last {
                    Some(cursor) => {
                        let mut k =
                            make_key(&[repo.as_bytes(), subject.as_bytes(), cursor.as_bytes()]);
                        k.push(0);
                        k
                    }
                    None => subj_prefix.clone(),
                };
                let end = prefix_successor(&subj_prefix)?;
                let pairs = range_owned(&self.dbs[I_REFERRERS], &rtx, &start, &end).ok()?;

                let mut items = Vec::new();
                for (k, v) in &pairs {
                    let parts = split_key(k);
                    if parts.len() < 3
                        || parts[0] != repo.as_bytes()
                        || parts[1] != subject.as_bytes()
                    {
                        break;
                    }
                    if items.len() == limit {
                        return Some(Page { items, more: true });
                    }
                    let referrer_digest = String::from_utf8_lossy(parts[2]).into_owned();
                    items.push((referrer_digest, v.clone()));
                }
                Some(Page { items, more: false })
            }
            Some(at) => {
                let type_prefix =
                    make_prefix(&[repo.as_bytes(), subject.as_bytes(), at.as_bytes()]);
                let has_typed =
                    has_any_with_prefix(&self.dbs[I_REFERRERS_BY_TYPE], &rtx, &type_prefix);
                if !has_typed {
                    let subj_prefix = make_prefix(&[repo.as_bytes(), subject.as_bytes()]);
                    if !has_any_with_prefix(&self.dbs[I_REFERRERS], &rtx, &subj_prefix) {
                        return None;
                    }
                    return Some(Page::default());
                }
                let start = match last {
                    Some(cursor) => {
                        let mut k = make_key(&[
                            repo.as_bytes(),
                            subject.as_bytes(),
                            at.as_bytes(),
                            cursor.as_bytes(),
                        ]);
                        k.push(0);
                        k
                    }
                    None => type_prefix.clone(),
                };
                let end = prefix_successor(&type_prefix)?;
                let by_type_pairs =
                    range_owned(&self.dbs[I_REFERRERS_BY_TYPE], &rtx, &start, &end).ok()?;

                let mut items = Vec::new();
                for (k, _) in &by_type_pairs {
                    let parts = split_key(k);
                    if parts.len() < 4
                        || parts[0] != repo.as_bytes()
                        || parts[1] != subject.as_bytes()
                        || parts[2] != at.as_bytes()
                    {
                        break;
                    }
                    if items.len() == limit {
                        return Some(Page { items, more: true });
                    }
                    let referrer = std::str::from_utf8(parts[3]).unwrap_or("");
                    let ref_key =
                        make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
                    if let Ok(Some(desc)) = self.dbs[I_REFERRERS].get(&rtx, &ref_key) {
                        items.push((referrer.to_string(), desc.to_vec()));
                    }
                }
                Some(Page { items, more: false })
            }
        }
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let rtx = match self.env.read_txn() {
            Ok(r) => r,
            Err(_) => return false,
        };
        let key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
        self.dbs[I_REFERRERS]
            .get(&rtx, &key)
            .ok()
            .flatten()
            .is_some()
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let rtx = match self.env.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let key = make_key(&[repo.as_bytes(), blob.as_bytes()]);
        dup_values_as_strings(&self.dbs[I_BACKREFS], &rtx, &key)
    }

    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum> {
        let rtx = self.env.read_txn().ok()?;
        let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
        let val = self.dbs[I_CHECKSUMS].get(&rtx, &key).ok()??;
        Some(decode_checksum(val))
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        self.apply_inner(op, true)
    }

    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()> {
        self.apply_inner(op, false)
    }

    fn repos(&self) -> Vec<String> {
        let rtx = match self.env.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut repos = std::collections::BTreeSet::new();

        for idx in [I_MEDIA_TYPES, I_REFERRERS] {
            if let Ok(iter) = self.dbs[idx].iter(&rtx) {
                for entry in iter.flatten() {
                    let (k, _) = entry;
                    let parts = split_key(k);
                    if let Some(first) = parts.first() {
                        if let Ok(repo) = std::str::from_utf8(first) {
                            repos.insert(repo.to_string());
                        }
                    }
                }
            }
        }

        repos.into_iter().collect()
    }

    fn manifests(&self, repo: &str) -> Vec<String> {
        let rtx = match self.env.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let prefix = make_prefix(&[repo.as_bytes()]);
        let Some(end) = prefix_successor(&prefix) else {
            return Vec::new();
        };
        let Ok(pairs) = range_owned(&self.dbs[I_MEDIA_TYPES], &rtx, &prefix, &end) else {
            return Vec::new();
        };
        pairs
            .iter()
            .filter_map(|(k, _)| {
                let parts = split_key(k);
                if parts.len() >= 2 {
                    std::str::from_utf8(parts[1]).ok().map(str::to_string)
                } else {
                    None
                }
            })
            .collect()
    }

    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)> {
        let rtx = match self.env.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let prefix = make_prefix(&[repo.as_bytes()]);
        let Some(end) = prefix_successor(&prefix) else {
            return Vec::new();
        };
        let Ok(pairs) = range_owned(&self.dbs[I_TAGS], &rtx, &prefix, &end) else {
            return Vec::new();
        };
        pairs
            .iter()
            .filter_map(|(k, v)| {
                let parts = split_key(k);
                if parts.len() < 2 || parts[0] != repo.as_bytes() {
                    return None;
                }
                let tag = std::str::from_utf8(parts[1]).ok()?;
                let sep = v.iter().position(|&b| b == 0)?;
                let digest = std::str::from_utf8(&v[..sep]).ok()?;
                let media_type = std::str::from_utf8(&v[sep + 1..]).ok()?;
                Some((tag.to_string(), digest.to_string(), media_type.to_string()))
            })
            .collect()
    }

    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)> {
        let rtx = match self.env.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let prefix = make_prefix(&[repo.as_bytes()]);
        let Some(end) = prefix_successor(&prefix) else {
            return Vec::new();
        };
        let Ok(pairs) = range_owned(&self.dbs[I_REFERRERS], &rtx, &prefix, &end) else {
            return Vec::new();
        };

        let mut result: std::collections::BTreeMap<String, Vec<Referrer>> =
            std::collections::BTreeMap::new();

        for (k, v) in &pairs {
            let parts = split_key(k);
            if parts.len() < 3 || parts[0] != repo.as_bytes() {
                break;
            }
            let subject = String::from_utf8_lossy(parts[1]).into_owned();
            let referrer = String::from_utf8_lossy(parts[2]).into_owned();
            result
                .entry(subject)
                .or_default()
                .push((referrer, v.clone()));
        }

        result.into_iter().collect()
    }

    fn maintain(&self) -> io::Result<()> {
        self.env.force_sync().map_err(map_heed_err)?;
        Ok(())
    }

    fn generation(&self) -> u64 {
        0
    }

    fn log_len(&self) -> u64 {
        0
    }

    fn export(&self, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
        self.export_impl(sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roci_config::MetadataConfig;

    fn make_config() -> MetadataConfig {
        MetadataConfig::default()
    }

    #[test]
    fn prefix_boundary_repos() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        for repo in ["team", "team2"] {
            store
                .apply(MetaOp::PutManifest {
                    repo: repo.into(),
                    digest: "sha256:aaa".into(),
                    media_type: "mt".into(),
                    tag: Some("v1".into()),
                    references: vec![],
                    referrer: None,
                })
                .unwrap();
        }

        let page = store.tags_page("team", None, 10).unwrap();
        assert_eq!(page.items, vec!["v1"]);
        assert!(!page.more);

        let page2 = store.tags_page("team2", None, 10).unwrap();
        assert_eq!(page2.items, vec!["v1"]);
        assert!(!page2.more);

        assert_eq!(store.manifests("team"), vec!["sha256:aaa"]);
        assert_eq!(store.manifests("team2"), vec!["sha256:aaa"]);
    }

    #[test]
    fn prefix_boundary_tags() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        for tag in ["a", "ab", "b"] {
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

        let page = store.tags_page("r", None, 1).unwrap();
        assert_eq!(page.items, vec!["a"]);
        assert!(page.more);

        let page2 = store.tags_page("r", Some("a"), 1).unwrap();
        assert_eq!(page2.items, vec!["ab"]);
        assert!(page2.more);

        let page3 = store.tags_page("r", Some("ab"), 10).unwrap();
        assert_eq!(page3.items, vec!["b"]);
        assert!(!page3.more);
    }

    #[test]
    fn prefix_successor_all_0xff() {
        let all_ff = vec![0xFFu8; 4];
        assert_eq!(prefix_successor(&all_ff), None);
    }

    #[test]
    fn prefix_successor_trailing_0xff() {
        let input = vec![0x01, 0xFF, 0xFF];
        let result = prefix_successor(&input).unwrap();
        assert_eq!(result, vec![0x02]);
    }

    #[test]
    fn prefix_successor_normal() {
        let input = vec![0x01, 0x02];
        let result = prefix_successor(&input).unwrap();
        assert_eq!(result, vec![0x01, 0x03]);
    }

    #[test]
    fn map_heed_err_map_full() {
        let err = io::Error::other("MDB_MAP_FULL something");
        let mapped = map_heed_err(heed::Error::Io(err));
        let mapped_msg = mapped.to_string();
        assert!(
            mapped_msg.contains("map_size_bytes") || mapped_msg.contains("MDB_MAP_FULL"),
            "should mention map full: {mapped_msg}"
        );
    }

    #[test]
    fn maintain_calls_force_sync() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:a".into(),
                media_type: "mt".into(),
                tag: Some("v1".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        store.maintain().unwrap();
        assert!(store.resolve_tag("r", "v1").is_some());
    }

    #[test]
    fn export_round_trip_all_op_types() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                media_type: "mt".into(),
                tag: Some("v1".into()),
                references: vec!["sha256:blob1".into()],
                referrer: None,
            })
            .unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m2".into(),
                media_type: "mt2".into(),
                tag: None,
                references: vec![],
                referrer: None,
            })
            .unwrap();
        let desc = br#"{"artifactType":"sbom","digest":"sha256:ref","size":10}"#;
        store
            .apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:subj".into(),
                referrer: "sha256:ref".into(),
                descriptor: desc.to_vec(),
            })
            .unwrap();
        store
            .apply(MetaOp::PutChecksum {
                repo: "r".into(),
                digest: "sha256:blob1".into(),
                crc32c: 0xABCD,
                size: 1024,
            })
            .unwrap();

        let mut ops = Vec::new();
        store
            .export(&mut |op| {
                ops.push(op);
                Ok(())
            })
            .unwrap();

        assert!(!ops.is_empty(), "export should produce ops");

        let has_tagged = ops
            .iter()
            .any(|op| matches!(op, MetaOp::PutManifest { tag: Some(_), .. }));
        let has_untagged = ops
            .iter()
            .any(|op| matches!(op, MetaOp::PutManifest { tag: None, .. }));
        let has_backref = ops
            .iter()
            .any(|op| matches!(op, MetaOp::PutBackrefs { .. }));
        let has_referrer = ops
            .iter()
            .any(|op| matches!(op, MetaOp::PutReferrer { .. }));
        let has_checksum = ops
            .iter()
            .any(|op| matches!(op, MetaOp::PutChecksum { .. }));
        assert!(has_tagged, "should export tagged manifest");
        assert!(has_untagged, "should export untagged manifest");
        assert!(has_backref, "should export backrefs");
        assert!(has_referrer, "should export referrer");
        assert!(has_checksum, "should export checksum");

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = LmdbMetadataStore::open(dir2.path(), &config).unwrap();
        for op in ops {
            store2.apply(op).unwrap();
        }

        assert_eq!(store.repos(), store2.repos());
        assert_eq!(store.manifests("r"), store2.manifests("r"));
        assert_eq!(store.tags_snapshot("r"), store2.tags_snapshot("r"));
        assert_eq!(
            store.checksum("r", "sha256:blob1"),
            store2.checksum("r", "sha256:blob1")
        );
    }

    #[test]
    fn redb_warning_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let redb_path = dir.path().join("roci-meta.redb");
        std::fs::write(&redb_path, b"fake redb").unwrap();

        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
        assert!(redb_path.exists(), "redb file not deleted");
        drop(store);
    }

    #[test]
    fn tags_page_cursor_past_end() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m".into(),
                media_type: "mt".into(),
                tag: Some("a".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        let page = store.tags_page("r", Some("z"), 10).unwrap();
        assert!(page.items.is_empty());
    }

    #[test]
    fn referrers_page_with_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        for i in 0..3 {
            let desc = serde_json::json!({
                "digest": format!("sha256:r{i}"),
                "size": 10,
                "mediaType": "application/vnd.oci.image.manifest.v1+json"
            })
            .to_string()
            .into_bytes();
            store
                .apply(MetaOp::PutReferrer {
                    repo: "r".into(),
                    subject: "sha256:s".into(),
                    referrer: format!("sha256:r{i}"),
                    descriptor: desc,
                })
                .unwrap();
        }

        let p1 = store
            .referrers_page("r", "sha256:s", None, None, 2)
            .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert!(p1.more);

        let cursor = &p1.items[1].0;
        let p2 = store
            .referrers_page("r", "sha256:s", None, Some(cursor), 10)
            .unwrap();
        assert_eq!(p2.items.len(), 1);
        assert!(!p2.more);
    }

    #[test]
    fn referrers_page_typed_no_match_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        let desc = serde_json::json!({
            "artifactType": "sbom",
            "digest": "sha256:r1",
            "size": 10,
            "mediaType": "application/vnd.oci.image.manifest.v1+json"
        })
        .to_string()
        .into_bytes();
        store
            .apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:s".into(),
                referrer: "sha256:r1".into(),
                descriptor: desc,
            })
            .unwrap();

        let p = store
            .referrers_page("r", "sha256:s", Some("nonexistent"), None, 10)
            .unwrap();
        assert!(p.items.is_empty(), "no match for nonexistent type");
    }

    #[test]
    fn referrers_page_typed_with_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        for i in 0..3 {
            let desc = serde_json::json!({
                "artifactType": "sbom",
                "digest": format!("sha256:r{i}"),
                "size": 10,
                "mediaType": "application/vnd.oci.image.manifest.v1+json"
            })
            .to_string()
            .into_bytes();
            store
                .apply(MetaOp::PutReferrer {
                    repo: "r".into(),
                    subject: "sha256:s".into(),
                    referrer: format!("sha256:r{i}"),
                    descriptor: desc,
                })
                .unwrap();
        }

        let p1 = store
            .referrers_page("r", "sha256:s", Some("sbom"), None, 1)
            .unwrap();
        assert_eq!(p1.items.len(), 1);
        assert!(p1.more);

        let cursor = &p1.items[0].0;
        let p2 = store
            .referrers_page("r", "sha256:s", Some("sbom"), Some(cursor), 10)
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        assert!(!p2.more);
    }

    #[test]
    fn repos_includes_referrer_only_repos() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        store
            .apply(MetaOp::PutManifest {
                repo: "r1".into(),
                digest: "sha256:m".into(),
                media_type: "mt".into(),
                tag: None,
                references: vec![],
                referrer: None,
            })
            .unwrap();

        let desc = br#"{"digest":"sha256:ref","size":10}"#;
        store
            .apply(MetaOp::PutReferrer {
                repo: "r2".into(),
                subject: "sha256:s".into(),
                referrer: "sha256:ref".into(),
                descriptor: desc.to_vec(),
            })
            .unwrap();

        let repos = store.repos();
        assert!(repos.contains(&"r1".to_string()), "r1 via media_types");
        assert!(repos.contains(&"r2".to_string()), "r2 via referrers");
    }

    #[test]
    fn referrers_snapshot_structure() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        let desc = serde_json::json!({
            "artifactType": "sbom",
            "digest": "sha256:r1",
            "size": 10,
            "mediaType": "application/vnd.oci.image.manifest.v1+json"
        })
        .to_string()
        .into_bytes();

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
        assert_eq!(snap.len(), 1, "one subject");
        assert_eq!(snap[0].0, "sha256:s1");
        assert_eq!(snap[0].1.len(), 2, "two referrers");
    }

    #[test]
    fn bulk_apply_multiple_ops() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();

        let ops = vec![
            MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                media_type: "mt".into(),
                tag: Some("v1".into()),
                references: vec![],
                referrer: None,
            },
            MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m2".into(),
                media_type: "mt".into(),
                tag: Some("v2".into()),
                references: vec![],
                referrer: None,
            },
        ];
        store.bulk_apply(&ops).unwrap();
        store.force_sync_public().unwrap();

        assert!(store.resolve_tag("r", "v1").is_some());
        assert!(store.resolve_tag("r", "v2").is_some());
    }
}
