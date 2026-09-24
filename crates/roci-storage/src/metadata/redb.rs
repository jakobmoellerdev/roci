//! Feature-gated embedded B-tree KV metadata engine backed by redb
//! (ARCHITECTURE §Metadata index engine — pure-Rust/musl option;
//! RESEARCH §8.6).
//!
//! Every query is a bounded range seek over typed tables whose composite
//! keys embed `(repo, …)` prefixes — no full-table scans, no in-RAM
//! index copies. One write transaction per [`MetadataStore::apply`] call
//! keeps every `MetaOp` atomic (the combined `PutManifest` stays one
//! record). [`apply_relaxed`](MetadataStore::apply_relaxed) commits
//! without fsync via [`Durability::None`](redb::Durability::None).

use super::{BlobChecksum, MetaOp, MetadataStore, Page, Referrer};
use redb::{
    Database, Durability, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable,
    ReadableTable, TableDefinition,
};
use roci_config::MetadataConfig;
use std::io;
use std::path::Path;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Table definitions
// ---------------------------------------------------------------------------

/// `(repo, tag) → (digest, media_type)` — the live tag index.
const TAGS: TableDefinition<(&str, &str), (&str, &str)> = TableDefinition::new("tags");

/// `(repo, digest, tag)` — reverse index so DeleteManifest can find every
/// tag pointing at a digest without a full scan. Value is `()` (unit).
const TAGS_BY_DIGEST: TableDefinition<(&str, &str, &str), ()> =
    TableDefinition::new("tags_by_digest");

/// `(repo, digest) → media_type`.
const MEDIA_TYPES: TableDefinition<(&str, &str), &str> = TableDefinition::new("media_types");

/// `(repo, subject, referrer) → descriptor` — the primary referrer index.
const REFERRERS: TableDefinition<(&str, &str, &str), &[u8]> = TableDefinition::new("referrers");

/// `(repo, subject, referrer) → artifactType` — stored separately so we can
/// look up the type for a known referrer.
const REFERRER_TYPES: TableDefinition<(&str, &str, &str), &str> =
    TableDefinition::new("referrer_types");

/// `(repo, subject, artifactType, referrer)` — filtered-page index: a range
/// scan on `(repo, subject, artifactType)` prefix yields referrer digests in
/// order. Value is `()`.
const REFERRERS_BY_TYPE: TableDefinition<(&str, &str, &str, &str), ()> =
    TableDefinition::new("referrers_by_type");

/// `(repo, referrer, subject)` — reverse index so DeleteManifest can drop a
/// deleted manifest as a referrer of any subject. Value is `()`.
const REFERRERS_REVERSE: TableDefinition<(&str, &str, &str), ()> =
    TableDefinition::new("referrers_reverse");

/// `(repo, blob, manifest)` — backrefs: every manifest that references a
/// blob. Value is `()` (the key encodes all the data).
const BACKREFS: MultimapTableDefinition<(&str, &str), &str> =
    MultimapTableDefinition::new("backrefs");

/// `(repo, manifest, blob)` — reverse backrefs so DeleteManifest can remove
/// a manifest from every blob's backref set without scanning. Value is `()`.
const BACKREFS_REVERSE: MultimapTableDefinition<(&str, &str), &str> =
    MultimapTableDefinition::new("backrefs_reverse");

/// `(repo, digest) → (crc32c_le ++ size_le)` — checksum 12-byte blob.
const CHECKSUMS: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("checksums");

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
// RedbMetadataStore
// ---------------------------------------------------------------------------

/// Embedded B-tree KV metadata engine backed by redb.
///
/// The database file lives at `<root>/roci-meta.redb`. All queries are
/// bounded range seeks — no in-RAM copies of the full dataset. The store
/// is opened with `create` (creates or opens) and a single
/// `Mutex<Database>` serializes write transactions (redb enforces
/// single-writer anyway); reads use `begin_read` which can overlap.
pub struct RedbMetadataStore {
    db: Database,
    /// Serialize write transactions; redb only permits one at a time, but
    /// the Mutex lets callers queue rather than getting an error.
    write_lock: Mutex<()>,
}

impl RedbMetadataStore {
    /// Open (or create) the redb metadata store at `<root>/roci-meta.redb`.
    pub fn open(root: &Path, _config: &MetadataConfig) -> io::Result<Self> {
        let path = root.join("roci-meta.redb");
        let db = Database::create(&path).map_err(map_db_err)?;
        // Pre-create all tables so reads never hit TableDoesNotExist.
        {
            let txn = db.begin_write().map_err(map_txn_err)?;
            txn.open_table(TAGS).map_err(map_table_err)?;
            txn.open_table(TAGS_BY_DIGEST).map_err(map_table_err)?;
            txn.open_table(MEDIA_TYPES).map_err(map_table_err)?;
            txn.open_table(REFERRERS).map_err(map_table_err)?;
            txn.open_table(REFERRER_TYPES).map_err(map_table_err)?;
            txn.open_table(REFERRERS_BY_TYPE).map_err(map_table_err)?;
            txn.open_table(REFERRERS_REVERSE).map_err(map_table_err)?;
            txn.open_multimap_table(BACKREFS).map_err(map_table_err)?;
            txn.open_multimap_table(BACKREFS_REVERSE)
                .map_err(map_table_err)?;
            txn.open_table(CHECKSUMS).map_err(map_table_err)?;
            txn.commit().map_err(map_commit_err)?;
        }
        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }

    /// Apply `op` with the given durability level.
    fn apply_with(&self, op: MetaOp, durability: Durability) -> io::Result<()> {
        let _guard = self.write_lock.lock().expect("redb write lock poisoned");
        let mut txn = self.db.begin_write().map_err(map_txn_err)?;
        txn.set_durability(durability)
            .map_err(|e| io::Error::other(format!("redb set_durability: {e}")))?;
        self.apply_op(&txn, &op)?;
        txn.commit().map_err(map_commit_err)?;
        Ok(())
    }

    /// Apply a single `MetaOp` within the given write transaction.
    fn apply_op(&self, txn: &redb::WriteTransaction, op: &MetaOp) -> io::Result<()> {
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
                    let mut t = txn.open_table(MEDIA_TYPES).map_err(map_table_err)?;
                    t.insert((repo.as_str(), digest.as_str()), media_type.as_str())
                        .map_err(map_storage_err)?;
                }
                // tag
                if let Some(tag) = tag {
                    let mut t = txn.open_table(TAGS).map_err(map_table_err)?;
                    // Remove old reverse entry if this tag pointed elsewhere
                    if let Some(old) = t
                        .get((repo.as_str(), tag.as_str()))
                        .map_err(map_storage_err)?
                    {
                        let (old_digest, _) = old.value();
                        let old_digest = old_digest.to_string();
                        drop(old);
                        let mut rev = txn.open_table(TAGS_BY_DIGEST).map_err(map_table_err)?;
                        rev.remove((repo.as_str(), old_digest.as_str(), tag.as_str()))
                            .map_err(map_storage_err)?;
                    }
                    t.insert(
                        (repo.as_str(), tag.as_str()),
                        (digest.as_str(), media_type.as_str()),
                    )
                    .map_err(map_storage_err)?;
                    let mut rev = txn.open_table(TAGS_BY_DIGEST).map_err(map_table_err)?;
                    rev.insert((repo.as_str(), digest.as_str(), tag.as_str()), ())
                        .map_err(map_storage_err)?;
                }
                // backrefs
                Self::add_backrefs_in_txn(txn, repo, digest, references)?;
                // referrer
                if let Some((subject, descriptor)) = referrer {
                    Self::add_referrer_in_txn(txn, repo, subject, digest, descriptor)?;
                }
            }

            MetaOp::DeleteManifest { repo, digest } => {
                // Remove checksum
                {
                    let mut t = txn.open_table(CHECKSUMS).map_err(map_table_err)?;
                    t.remove((repo.as_str(), digest.as_str()))
                        .map_err(map_storage_err)?;
                }
                // Remove media type
                {
                    let mut t = txn.open_table(MEDIA_TYPES).map_err(map_table_err)?;
                    t.remove((repo.as_str(), digest.as_str()))
                        .map_err(map_storage_err)?;
                }
                // Drop every tag pointing at this digest via reverse index
                {
                    let rev = txn.open_table(TAGS_BY_DIGEST).map_err(map_table_err)?;
                    let prefix_start = (repo.as_str(), digest.as_str(), "");
                    let prefix_end = (repo.as_str(), digest.as_str(), "\x7f\x7f\x7f\x7f");
                    let tags_to_remove: Vec<String> = rev
                        .range(prefix_start..=prefix_end)
                        .map_err(map_storage_err)?
                        .filter_map(|entry| {
                            let (k, _) = entry.ok()?;
                            let (_, _, tag) = k.value();
                            Some(tag.to_string())
                        })
                        .collect();
                    drop(rev);

                    let mut tags_tbl = txn.open_table(TAGS).map_err(map_table_err)?;
                    let mut rev_tbl = txn.open_table(TAGS_BY_DIGEST).map_err(map_table_err)?;
                    for tag in &tags_to_remove {
                        tags_tbl
                            .remove((repo.as_str(), tag.as_str()))
                            .map_err(map_storage_err)?;
                        rev_tbl
                            .remove((repo.as_str(), digest.as_str(), tag.as_str()))
                            .map_err(map_storage_err)?;
                    }
                }
                // Drop this digest as a referrer of any subject (reverse index)
                {
                    let rev = txn.open_table(REFERRERS_REVERSE).map_err(map_table_err)?;
                    let prefix_start = (repo.as_str(), digest.as_str(), "");
                    let prefix_end = (repo.as_str(), digest.as_str(), "\x7f\x7f\x7f\x7f");
                    let subjects: Vec<String> = rev
                        .range(prefix_start..=prefix_end)
                        .map_err(map_storage_err)?
                        .filter_map(|entry| {
                            let (k, _) = entry.ok()?;
                            let (_, _, subject) = k.value();
                            Some(subject.to_string())
                        })
                        .collect();
                    drop(rev);

                    for subject in &subjects {
                        Self::remove_referrer_in_txn(txn, repo, subject, digest)?;
                    }
                }
                // Drop this digest from every blob's backref set (reverse index)
                {
                    let rev = txn
                        .open_multimap_table(BACKREFS_REVERSE)
                        .map_err(map_table_err)?;
                    let blobs: Vec<String> = rev
                        .get((repo.as_str(), digest.as_str()))
                        .map_err(map_storage_err)?
                        .filter_map(|entry| {
                            let v = entry.ok()?;
                            Some(v.value().to_string())
                        })
                        .collect();
                    drop(rev);

                    let mut fwd = txn.open_multimap_table(BACKREFS).map_err(map_table_err)?;
                    let mut rev_tbl = txn
                        .open_multimap_table(BACKREFS_REVERSE)
                        .map_err(map_table_err)?;
                    for blob in &blobs {
                        fwd.remove((repo.as_str(), blob.as_str()), digest.as_str())
                            .map_err(map_storage_err)?;
                    }
                    // Remove the entire reverse entry for this manifest
                    rev_tbl
                        .remove_all((repo.as_str(), digest.as_str()))
                        .map_err(map_storage_err)?;
                }
            }

            MetaOp::PutBackrefs {
                repo,
                manifest,
                blobs,
            } => {
                Self::add_backrefs_in_txn(txn, repo, manifest, blobs)?;
            }

            MetaOp::PutReferrer {
                repo,
                subject,
                referrer,
                descriptor,
            } => {
                Self::add_referrer_in_txn(txn, repo, subject, referrer, descriptor)?;
            }

            MetaOp::PutChecksum {
                repo,
                digest,
                crc32c,
                size,
            } => {
                let mut t = txn.open_table(CHECKSUMS).map_err(map_table_err)?;
                let buf = encode_checksum(*crc32c, *size);
                t.insert((repo.as_str(), digest.as_str()), buf.as_slice())
                    .map_err(map_storage_err)?;
            }

            MetaOp::DeleteBlob { repo, digest } => {
                let mut t = txn.open_table(CHECKSUMS).map_err(map_table_err)?;
                t.remove((repo.as_str(), digest.as_str()))
                    .map_err(map_storage_err)?;
            }
        }
        Ok(())
    }

    fn add_backrefs_in_txn(
        txn: &redb::WriteTransaction,
        repo: &str,
        manifest: &str,
        blobs: &[String],
    ) -> io::Result<()> {
        let mut fwd = txn.open_multimap_table(BACKREFS).map_err(map_table_err)?;
        let mut rev = txn
            .open_multimap_table(BACKREFS_REVERSE)
            .map_err(map_table_err)?;
        for blob in blobs {
            fwd.insert((repo, blob.as_str()), manifest)
                .map_err(map_storage_err)?;
            rev.insert((repo, manifest), blob.as_str())
                .map_err(map_storage_err)?;
        }
        Ok(())
    }

    fn add_referrer_in_txn(
        txn: &redb::WriteTransaction,
        repo: &str,
        subject: &str,
        referrer: &str,
        descriptor: &[u8],
    ) -> io::Result<()> {
        // Remove old entry first (de-duplicate by referrer digest)
        Self::remove_referrer_in_txn(txn, repo, subject, referrer)?;

        let artifact_type: Option<String> = serde_json::from_slice::<serde_json::Value>(descriptor)
            .ok()
            .and_then(|v| v.get("artifactType")?.as_str().map(str::to_string));

        {
            let mut t = txn.open_table(REFERRERS).map_err(map_table_err)?;
            t.insert((repo, subject, referrer), descriptor)
                .map_err(map_storage_err)?;
        }
        {
            let mut rev = txn.open_table(REFERRERS_REVERSE).map_err(map_table_err)?;
            rev.insert((repo, referrer, subject), ())
                .map_err(map_storage_err)?;
        }
        if let Some(at) = &artifact_type {
            let mut t = txn.open_table(REFERRER_TYPES).map_err(map_table_err)?;
            t.insert((repo, subject, referrer), at.as_str())
                .map_err(map_storage_err)?;
            let mut bt = txn.open_table(REFERRERS_BY_TYPE).map_err(map_table_err)?;
            bt.insert((repo, subject, at.as_str(), referrer), ())
                .map_err(map_storage_err)?;
        }
        Ok(())
    }

    fn remove_referrer_in_txn(
        txn: &redb::WriteTransaction,
        repo: &str,
        subject: &str,
        referrer: &str,
    ) -> io::Result<()> {
        // Check if the referrer exists
        let had_type = {
            let t = txn.open_table(REFERRER_TYPES).map_err(map_table_err)?;
            let val = t.get((repo, subject, referrer)).map_err(map_storage_err)?;
            val.map(|v| v.value().to_string())
        };

        {
            let mut t = txn.open_table(REFERRERS).map_err(map_table_err)?;
            t.remove((repo, subject, referrer))
                .map_err(map_storage_err)?;
        }
        {
            let mut rev = txn.open_table(REFERRERS_REVERSE).map_err(map_table_err)?;
            rev.remove((repo, referrer, subject))
                .map_err(map_storage_err)?;
        }
        {
            let mut t = txn.open_table(REFERRER_TYPES).map_err(map_table_err)?;
            t.remove((repo, subject, referrer))
                .map_err(map_storage_err)?;
        }
        if let Some(at) = &had_type {
            let mut bt = txn.open_table(REFERRERS_BY_TYPE).map_err(map_table_err)?;
            bt.remove((repo, subject, at.as_str(), referrer))
                .map_err(map_storage_err)?;
        }
        Ok(())
    }
}

impl MetadataStore for RedbMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let rtx = self.db.begin_read().ok()?;
        let t = rtx.open_table(TAGS).ok()?;
        let val = t.get((repo, tag)).ok()??;
        let (digest, media_type) = val.value();
        Some((digest.to_string(), media_type.to_string()))
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let rtx = self.db.begin_read().ok()?;
        let t = rtx.open_table(MEDIA_TYPES).ok()?;
        let val = t.get((repo, digest)).ok()??;
        Some(val.value().to_string())
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let rtx = self.db.begin_read().ok()?;
        let t = rtx.open_table(TAGS).ok()?;

        // Check if repo has any tags at all
        let has_any = t
            .range::<(&str, &str)>((repo, "")..=(repo, "\x7f\x7f\x7f\x7f"))
            .ok()?
            .next()
            .is_some();
        if !has_any {
            return None;
        }

        let range_start = match last {
            Some(cursor) => {
                // Strictly after cursor
                let cursor_next = next_prefix(cursor);
                (repo.to_string(), cursor_next)
            }
            None => (repo.to_string(), String::new()),
        };

        let mut items = Vec::new();
        let range = t
            .range::<(&str, &str)>((range_start.0.as_str(), range_start.1.as_str())..)
            .ok()?;
        for entry in range {
            let (k, _v) = entry.ok()?;
            let (r, tag) = k.value();
            if r != repo {
                break;
            }
            if items.len() == limit {
                return Some(Page { items, more: true });
            }
            items.push(tag.to_string());
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
        let rtx = self.db.begin_read().ok()?;

        match artifact_type {
            None => {
                let t = rtx.open_table(REFERRERS).ok()?;
                // Check if subject has any referrers
                let has_any = t
                    .range::<(&str, &str, &str)>(
                        (repo, subject, "")..=(repo, subject, "\x7f\x7f\x7f\x7f"),
                    )
                    .ok()?
                    .next()
                    .is_some();
                if !has_any {
                    return None;
                }

                let start_referrer = match last {
                    Some(cursor) => next_prefix(cursor),
                    None => String::new(),
                };

                let mut items = Vec::new();
                let range = t
                    .range::<(&str, &str, &str)>(
                        (repo, subject, start_referrer.as_str())
                            ..=(repo, subject, "\x7f\x7f\x7f\x7f"),
                    )
                    .ok()?;
                for entry in range {
                    let (k, v) = entry.ok()?;
                    let (r, s, _) = k.value();
                    if r != repo || s != subject {
                        break;
                    }
                    if items.len() == limit {
                        return Some(Page { items, more: true });
                    }
                    let referrer_digest = k.value().2.to_string();
                    let descriptor = v.value().to_vec();
                    items.push((referrer_digest, descriptor));
                }
                Some(Page { items, more: false })
            }
            Some(at) => {
                let bt = rtx.open_table(REFERRERS_BY_TYPE).ok()?;
                // Check if this artifact type has any entries
                let has_any = bt
                    .range::<(&str, &str, &str, &str)>(
                        (repo, subject, at, "")..=(repo, subject, at, "\x7f\x7f\x7f\x7f"),
                    )
                    .ok()?
                    .next()
                    .is_some();
                if !has_any {
                    // An artifact type with no entries → empty page, not None.
                    // But None only if the subject has no referrers at all.
                    // Check the main referrers table for any referrers for this subject.
                    let t = rtx.open_table(REFERRERS).ok()?;
                    let subject_has_any = t
                        .range::<(&str, &str, &str)>(
                            (repo, subject, "")..=(repo, subject, "\x7f\x7f\x7f\x7f"),
                        )
                        .ok()?
                        .next()
                        .is_some();
                    if !subject_has_any {
                        return None;
                    }
                    return Some(Page::default());
                }

                let start_referrer = match last {
                    Some(cursor) => next_prefix(cursor),
                    None => String::new(),
                };

                let t = rtx.open_table(REFERRERS).ok()?;
                let mut items = Vec::new();
                let range = bt
                    .range::<(&str, &str, &str, &str)>(
                        (repo, subject, at, start_referrer.as_str())
                            ..=(repo, subject, at, "\x7f\x7f\x7f\x7f"),
                    )
                    .ok()?;
                for entry in range {
                    let (k, _) = entry.ok()?;
                    let (r, s, a, referrer) = k.value();
                    if r != repo || s != subject || a != at {
                        break;
                    }
                    if items.len() == limit {
                        return Some(Page { items, more: true });
                    }
                    // Look up the descriptor in the main referrers table
                    if let Some(desc) = t.get((repo, subject, referrer)).ok().flatten() {
                        items.push((referrer.to_string(), desc.value().to_vec()));
                    }
                }
                Some(Page { items, more: false })
            }
        }
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let Ok(rtx) = self.db.begin_read() else {
            return false;
        };
        let Ok(t) = rtx.open_table(REFERRERS) else {
            return false;
        };
        t.get((repo, subject, referrer)).ok().flatten().is_some()
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let Ok(rtx) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = rtx.open_multimap_table(BACKREFS) else {
            return Vec::new();
        };
        let Ok(values) = t.get((repo, blob)) else {
            return Vec::new();
        };
        values
            .filter_map(|v| Some(v.ok()?.value().to_string()))
            .collect()
    }

    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum> {
        let rtx = self.db.begin_read().ok()?;
        let t = rtx.open_table(CHECKSUMS).ok()?;
        let val = t.get((repo, digest)).ok()??;
        Some(decode_checksum(val.value()))
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        self.apply_with(op, Durability::Immediate)
    }

    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()> {
        self.apply_with(op, Durability::None)
    }

    fn repos(&self) -> Vec<String> {
        let Ok(rtx) = self.db.begin_read() else {
            return Vec::new();
        };
        let mut repos = std::collections::BTreeSet::new();

        // Collect repos from media_types
        if let Ok(t) = rtx.open_table(MEDIA_TYPES) {
            if let Ok(range) = t.iter() {
                for (k, _) in range.flatten() {
                    let (repo, _) = k.value();
                    repos.insert(repo.to_string());
                }
            }
        }

        // Collect repos from referrers
        if let Ok(t) = rtx.open_table(REFERRERS) {
            if let Ok(range) = t.iter() {
                for (k, _) in range.flatten() {
                    let (repo, _, _) = k.value();
                    repos.insert(repo.to_string());
                }
            }
        }

        repos.into_iter().collect()
    }

    fn manifests(&self, repo: &str) -> Vec<String> {
        let Ok(rtx) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = rtx.open_table(MEDIA_TYPES) else {
            return Vec::new();
        };
        let Ok(range) = t.range::<(&str, &str)>((repo, "")..=(repo, "\x7f\x7f\x7f\x7f")) else {
            return Vec::new();
        };
        range
            .filter_map(|entry| {
                let (k, _) = entry.ok()?;
                let (_, d) = k.value();
                Some(d.to_string())
            })
            .collect()
    }

    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)> {
        let Ok(rtx) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = rtx.open_table(TAGS) else {
            return Vec::new();
        };
        let Ok(range) = t.range::<(&str, &str)>((repo, "")..=(repo, "\x7f\x7f\x7f\x7f")) else {
            return Vec::new();
        };
        range
            .filter_map(|entry| {
                let (k, v) = entry.ok()?;
                let (_, tag) = k.value();
                let (digest, media_type) = v.value();
                Some((tag.to_string(), digest.to_string(), media_type.to_string()))
            })
            .collect()
    }

    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)> {
        let Ok(rtx) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = rtx.open_table(REFERRERS) else {
            return Vec::new();
        };
        let Ok(range) = t.range::<(&str, &str, &str)>(
            (repo, "", "")..=(repo, "\x7f\x7f\x7f\x7f", "\x7f\x7f\x7f\x7f"),
        ) else {
            return Vec::new();
        };

        let mut result: std::collections::BTreeMap<String, Vec<Referrer>> =
            std::collections::BTreeMap::new();

        for entry in range {
            let Ok((k, v)) = entry else { continue };
            let (r, subject, referrer) = k.value();
            if r != repo {
                break;
            }
            result
                .entry(subject.to_string())
                .or_default()
                .push((referrer.to_string(), v.value().to_vec()));
        }

        result.into_iter().collect()
    }

    fn maintain(&self) -> io::Result<()> {
        // redb handles its own file management; compact() could be called
        // here but redb's B-tree does not need periodic compaction in the
        // way an LSM would — the file grows modestly and space is reclaimed
        // on write. This is a documented no-op.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a string that sorts immediately after `s` in lexicographic order.
/// Used to compute exclusive-after cursors: the range `[next_prefix(cursor), …)`
/// skips `cursor` itself. For ASCII/UTF-8 keys this appends '\0'.
fn next_prefix(s: &str) -> String {
    let mut r = s.to_string();
    r.push('\0');
    r
}

// ---------------------------------------------------------------------------
// Error mapping — redb errors → io::Error
// ---------------------------------------------------------------------------

fn map_db_err(e: redb::DatabaseError) -> io::Error {
    io::Error::other(format!("redb: {e}"))
}

fn map_txn_err(e: redb::TransactionError) -> io::Error {
    io::Error::other(format!("redb transaction: {e}"))
}

fn map_table_err(e: redb::TableError) -> io::Error {
    io::Error::other(format!("redb table: {e}"))
}

fn map_storage_err(e: redb::StorageError) -> io::Error {
    io::Error::other(format!("redb storage: {e}"))
}

fn map_commit_err(e: redb::CommitError) -> io::Error {
    io::Error::other(format!("redb commit: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_basic_ops() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        // Empty state
        assert!(store.resolve_tag("repo", "latest").is_none());
        assert!(store.manifest_media_type("repo", "sha256:aaa").is_none());
        assert_eq!(store.repos(), Vec::<String>::new());
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        {
            let store = RedbMetadataStore::open(dir.path(), &config).unwrap();
            store
                .apply(MetaOp::PutManifest {
                    repo: "r".into(),
                    digest: "sha256:aaa".into(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                    tag: Some("v1".into()),
                    references: vec!["sha256:bbb".into()],
                    referrer: None,
                })
                .unwrap();
        }
        // Reopen
        {
            let store = RedbMetadataStore::open(dir.path(), &config).unwrap();
            let (d, mt) = store.resolve_tag("r", "v1").unwrap();
            assert_eq!(d, "sha256:aaa");
            assert_eq!(mt, "application/vnd.oci.image.manifest.v1+json");
            assert_eq!(
                store.backrefs("r", "sha256:bbb"),
                vec!["sha256:aaa".to_string()]
            );
        }
    }

    #[test]
    fn checksum_encode_decode() {
        let buf = encode_checksum(0xDEAD_BEEF, 42);
        let bc = decode_checksum(&buf);
        assert_eq!(bc.crc32c, 0xDEAD_BEEF);
        assert_eq!(bc.size, 42);
    }

    #[test]
    fn next_prefix_works() {
        let n = next_prefix("abc");
        assert!(n.as_str() > "abc");
        assert!(n.as_str() < "abd");
    }

    #[test]
    fn delete_manifest_cascades_tags_referrers_backrefs() {
        // Covers reverse-index cascade lines 204-286: tags_by_digest,
        // referrers_reverse, backrefs_reverse cleanup.
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        // Put a manifest with a tag, as a referrer, and with backrefs.
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:aaa".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v1".into()),
                references: vec!["sha256:blob1".into(), "sha256:blob2".into()],
                referrer: Some((
                    "sha256:subject".into(),
                    br#"{"artifactType":"sig","digest":"sha256:aaa"}"#.to_vec(),
                )),
            })
            .unwrap();
        // Another tag pointing at same digest to test multiple-tag cascade.
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:aaa".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v1-alias".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();

        // Verify pre-state.
        assert!(store.resolve_tag("r", "v1").is_some());
        assert!(store.resolve_tag("r", "v1-alias").is_some());
        assert!(store.has_referrer("r", "sha256:subject", "sha256:aaa"));
        assert!(!store.backrefs("r", "sha256:blob1").is_empty());
        assert!(!store.backrefs("r", "sha256:blob2").is_empty());

        // Delete the manifest.
        store
            .apply(MetaOp::DeleteManifest {
                repo: "r".into(),
                digest: "sha256:aaa".into(),
            })
            .unwrap();

        // Everything cascaded.
        assert!(store.resolve_tag("r", "v1").is_none());
        assert!(store.resolve_tag("r", "v1-alias").is_none());
        assert!(!store.has_referrer("r", "sha256:subject", "sha256:aaa"));
        assert!(store.backrefs("r", "sha256:blob1").is_empty());
        assert!(store.backrefs("r", "sha256:blob2").is_empty());
        assert!(store.manifest_media_type("r", "sha256:aaa").is_none());
        assert!(store.checksum("r", "sha256:aaa").is_none());
    }

    #[test]
    fn tags_page_pagination() {
        // Covers tags_page lines 465 (repo break), 468 (more=true).
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        for t in ["v1", "v2", "v3", "v4"] {
            store
                .apply(MetaOp::PutManifest {
                    repo: "r".into(),
                    digest: format!("sha256:{t}"),
                    media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                    tag: Some(t.into()),
                    references: vec![],
                    referrer: None,
                })
                .unwrap();
        }
        // Another repo to test repo-break.
        store
            .apply(MetaOp::PutManifest {
                repo: "zzz".into(),
                digest: "sha256:other".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("latest".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();

        let page = store.tags_page("r", None, 2).unwrap();
        assert_eq!(page.items, vec!["v1".to_string(), "v2".to_string()]);
        assert!(page.more);

        let page2 = store.tags_page("r", Some("v2"), 10).unwrap();
        assert_eq!(page2.items, vec!["v3".to_string(), "v4".to_string()]);
        assert!(!page2.more);

        // No tags for missing repo.
        assert!(store.tags_page("nope", None, 10).is_none());
    }

    #[test]
    fn referrers_page_unfiltered_and_filtered() {
        // Covers referrers_page lines 501-582 including filtered path.
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        let add_ref = |referrer: &str, at: Option<&str>| {
            let desc = if let Some(at) = at {
                format!(r#"{{"artifactType":"{at}","digest":"{referrer}"}}"#)
            } else {
                format!(r#"{{"digest":"{referrer}"}}"#)
            };
            store
                .apply(MetaOp::PutReferrer {
                    repo: "r".into(),
                    subject: "sha256:s".into(),
                    referrer: referrer.into(),
                    descriptor: desc.into_bytes(),
                })
                .unwrap();
        };

        add_ref("sha256:r1", Some("sig"));
        add_ref("sha256:r2", Some("sig"));
        add_ref("sha256:r3", Some("sbom"));
        add_ref("sha256:r4", None);

        // Unfiltered: all 4 referrers.
        let page = store
            .referrers_page("r", "sha256:s", None, None, usize::MAX)
            .unwrap();
        assert_eq!(page.items.len(), 4);

        // Unfiltered pagination (more=true).
        let page_lim = store
            .referrers_page("r", "sha256:s", None, None, 2)
            .unwrap();
        assert_eq!(page_lim.items.len(), 2);
        assert!(page_lim.more);

        // Filtered by "sig": r1, r2.
        let page_sig = store
            .referrers_page("r", "sha256:s", Some("sig"), None, usize::MAX)
            .unwrap();
        assert_eq!(page_sig.items.len(), 2);

        // Filtered with pagination (more=true).
        let page_sig_lim = store
            .referrers_page("r", "sha256:s", Some("sig"), None, 1)
            .unwrap();
        assert_eq!(page_sig_lim.items.len(), 1);
        assert!(page_sig_lim.more);

        // Filtered by non-existent type → empty page (not None).
        let page_empty = store
            .referrers_page("r", "sha256:s", Some("nonexistent"), None, 10)
            .unwrap();
        assert!(page_empty.items.is_empty());
        assert!(!page_empty.more);

        // No referrers at all for a subject → None.
        assert!(store
            .referrers_page("r", "sha256:none", None, None, 10)
            .is_none());

        // Filtered on a subject with no referrers at all → None.
        assert!(store
            .referrers_page("r", "sha256:none", Some("sig"), None, 10)
            .is_none());
    }

    #[test]
    fn has_referrer_and_backrefs_and_checksum() {
        // Covers has_referrer lines 589-594, backrefs lines 599-609,
        // checksum lines 612-616.
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        assert!(!store.has_referrer("r", "sha256:s", "sha256:r1"));
        assert!(store.backrefs("r", "sha256:b1").is_empty());
        assert!(store.checksum("r", "sha256:d1").is_none());

        store
            .apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:s".into(),
                referrer: "sha256:r1".into(),
                descriptor: br#"{"digest":"sha256:r1"}"#.to_vec(),
            })
            .unwrap();
        store
            .apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m1".into(),
                blobs: vec!["sha256:b1".into()],
            })
            .unwrap();
        store
            .apply(MetaOp::PutChecksum {
                repo: "r".into(),
                digest: "sha256:d1".into(),
                crc32c: 0x1234,
                size: 42,
            })
            .unwrap();

        assert!(store.has_referrer("r", "sha256:s", "sha256:r1"));
        assert_eq!(
            store.backrefs("r", "sha256:b1"),
            vec!["sha256:m1".to_string()]
        );
        assert_eq!(
            store.checksum("r", "sha256:d1"),
            Some(BlobChecksum {
                crc32c: 0x1234,
                size: 42
            })
        );
    }

    #[test]
    fn apply_relaxed_and_delete_blob() {
        // Covers apply_relaxed (line 624) and DeleteBlob op (lines 318-322).
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        store
            .apply_relaxed(MetaOp::PutChecksum {
                repo: "r".into(),
                digest: "sha256:b1".into(),
                crc32c: 0xAAAA,
                size: 99,
            })
            .unwrap();
        assert!(store.checksum("r", "sha256:b1").is_some());

        store
            .apply(MetaOp::DeleteBlob {
                repo: "r".into(),
                digest: "sha256:b1".into(),
            })
            .unwrap();
        assert!(store.checksum("r", "sha256:b1").is_none());
    }

    #[test]
    fn repos_and_manifests() {
        // Covers repos lines 628-653, manifests lines 658-676.
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        assert!(store.repos().is_empty());
        assert!(store.manifests("r").is_empty());

        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:aaa".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v1".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:bbb".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: None,
                references: vec![],
                referrer: None,
            })
            .unwrap();
        // Add referrer to a different repo so repos() includes it.
        store
            .apply(MetaOp::PutReferrer {
                repo: "r2".into(),
                subject: "sha256:s".into(),
                referrer: "sha256:rr".into(),
                descriptor: br#"{"digest":"sha256:rr"}"#.to_vec(),
            })
            .unwrap();

        let repos = store.repos();
        assert!(repos.contains(&"r".to_string()));
        assert!(repos.contains(&"r2".to_string()));

        let mf = store.manifests("r");
        assert!(mf.contains(&"sha256:aaa".to_string()));
        assert!(mf.contains(&"sha256:bbb".to_string()));
        assert!(store.manifests("empty_repo").is_empty());
    }

    #[test]
    fn tags_snapshot_and_referrers_snapshot() {
        // Covers tags_snapshot lines 680-700, referrers_snapshot lines 704-731.
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        assert!(store.tags_snapshot("r").is_empty());
        assert!(store.referrers_snapshot("r").is_empty());

        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:aaa".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v1".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:bbb".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: Some("v2".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        store
            .apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:s1".into(),
                referrer: "sha256:ref1".into(),
                descriptor: br#"{"digest":"sha256:ref1"}"#.to_vec(),
            })
            .unwrap();
        store
            .apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:s1".into(),
                referrer: "sha256:ref2".into(),
                descriptor: br#"{"digest":"sha256:ref2"}"#.to_vec(),
            })
            .unwrap();
        // Different repo to test repo-break in referrers_snapshot (line 723).
        store
            .apply(MetaOp::PutReferrer {
                repo: "zzz".into(),
                subject: "sha256:s1".into(),
                referrer: "sha256:ref3".into(),
                descriptor: br#"{"digest":"sha256:ref3"}"#.to_vec(),
            })
            .unwrap();

        let ts = store.tags_snapshot("r");
        assert_eq!(ts.len(), 2);
        assert!(ts.iter().any(|(t, _, _)| t == "v1"));
        assert!(ts.iter().any(|(t, _, _)| t == "v2"));
        assert!(store.tags_snapshot("empty").is_empty());

        let rs = store.referrers_snapshot("r");
        assert_eq!(rs.len(), 1); // one subject
        assert_eq!(rs[0].0, "sha256:s1");
        assert_eq!(rs[0].1.len(), 2);

        // The zzz repo should not appear in r's snapshot.
        let rs_zzz = store.referrers_snapshot("zzz");
        assert_eq!(rs_zzz.len(), 1);
    }

    #[test]
    fn maintain_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();
        store.maintain().unwrap();
    }

    #[test]
    fn error_mapping_functions() {
        // Exercise the error mapping helpers (lines 744-762).
        use std::io::ErrorKind;

        // map_db_err: construct via a corrupted database.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("broken.redb");
        std::fs::write(&db_path, b"not a redb file").unwrap();
        let err = Database::create(&db_path).unwrap_err();
        let io_err = map_db_err(err);
        assert_eq!(io_err.kind(), ErrorKind::Other);
        assert!(io_err.to_string().contains("redb"), "{io_err}");

        // map_txn_err: TransactionError::Storage wraps StorageError.
        let txn_err = redb::TransactionError::Storage(redb::StorageError::Corrupted(
            "test corruption".into(),
        ));
        let io_err = map_txn_err(txn_err);
        assert_eq!(io_err.kind(), ErrorKind::Other);
        assert!(io_err.to_string().contains("transaction"), "{io_err}");

        // map_table_err: TableError::Storage wraps StorageError.
        let table_err =
            redb::TableError::Storage(redb::StorageError::Corrupted("test table err".into()));
        let io_err = map_table_err(table_err);
        assert_eq!(io_err.kind(), ErrorKind::Other);
        assert!(io_err.to_string().contains("table"), "{io_err}");

        // map_storage_err: StorageError::Corrupted.
        let storage_err = redb::StorageError::Corrupted("test storage".into());
        let io_err = map_storage_err(storage_err);
        assert_eq!(io_err.kind(), ErrorKind::Other);
        assert!(io_err.to_string().contains("storage"), "{io_err}");

        // map_commit_err: CommitError::Storage wraps StorageError.
        let commit_err =
            redb::CommitError::Storage(redb::StorageError::Corrupted("test commit".into()));
        let io_err = map_commit_err(commit_err);
        assert_eq!(io_err.kind(), ErrorKind::Other);
        assert!(io_err.to_string().contains("commit"), "{io_err}");
    }

    #[test]
    fn delete_manifest_with_checksum_and_referrer_with_type() {
        // Ensure DeleteManifest also removes checksums, and that referrer
        // removal cleans up the by-type index.
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig::default();
        let store = RedbMetadataStore::open(dir.path(), &config).unwrap();

        // Add manifest with referrer that has artifactType.
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                tag: None,
                references: vec![],
                referrer: Some((
                    "sha256:parent".into(),
                    br#"{"artifactType":"sig","digest":"sha256:m1"}"#.to_vec(),
                )),
            })
            .unwrap();
        store
            .apply(MetaOp::PutChecksum {
                repo: "r".into(),
                digest: "sha256:m1".into(),
                crc32c: 0xDEAD,
                size: 10,
            })
            .unwrap();

        assert!(store.has_referrer("r", "sha256:parent", "sha256:m1"));
        assert!(store.checksum("r", "sha256:m1").is_some());

        // Filtered referrer page should show m1.
        let page = store
            .referrers_page("r", "sha256:parent", Some("sig"), None, 10)
            .unwrap();
        assert_eq!(page.items.len(), 1);

        // Delete the manifest.
        store
            .apply(MetaOp::DeleteManifest {
                repo: "r".into(),
                digest: "sha256:m1".into(),
            })
            .unwrap();

        assert!(!store.has_referrer("r", "sha256:parent", "sha256:m1"));
        assert!(store.checksum("r", "sha256:m1").is_none());
        // The subject should have no referrers left.
        assert!(store
            .referrers_page("r", "sha256:parent", None, None, 10)
            .is_none());
    }
}
