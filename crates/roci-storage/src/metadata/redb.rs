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
                            let (r, d, tag) = k.value();
                            if r == repo && d == digest {
                                Some(tag.to_string())
                            } else {
                                None
                            }
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
                            let (r, d, subject) = k.value();
                            if r == repo && d == digest {
                                Some(subject.to_string())
                            } else {
                                None
                            }
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
                let (r, d) = k.value();
                if r == repo {
                    Some(d.to_string())
                } else {
                    None
                }
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
                let (r, tag) = k.value();
                if r == repo {
                    let (digest, media_type) = v.value();
                    Some((tag.to_string(), digest.to_string(), media_type.to_string()))
                } else {
                    None
                }
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
}
