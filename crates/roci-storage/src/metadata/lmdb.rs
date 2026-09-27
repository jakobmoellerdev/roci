//! LMDB metadata engine (heed3 / ChaCha20-Poly1305 encryption-at-rest).
//! ARCHITECTURE §Metadata index engine.

use super::{BlobChecksum, MetaOp, MetadataStore, Page, Referrer};
use heed3::types::Bytes;
use heed3::{DatabaseFlags, EnvFlags, EnvOpenOptions, WithoutTls};
use roci_config::MetadataConfig;
use std::io;
use std::ops::Bound;
use std::path::Path;
use std::sync::Mutex;

const DB_COUNT: u32 = 10;

type PlainDb = heed3::Database<Bytes, Bytes>;
type EncDb = heed3::EncryptedDatabase<Bytes, Bytes>;

const FORMAT_PLAIN: &str = "plain";
const FORMAT_ENCRYPTED: &str = "chacha20poly1305-v1";

/// HKDF info for ChaCha20-Poly1305 key derivation.
const HKDF_INFO: &[u8] = b"roci-meta.lmdb encryption v1";

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

/// Composite key: each part followed by `\0`.
fn make_key(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len() + 1).sum();
    let mut buf = Vec::with_capacity(total);
    for p in parts {
        buf.extend_from_slice(p);
        buf.push(0);
    }
    buf
}

fn make_prefix(parts: &[&[u8]]) -> Vec<u8> {
    make_key(parts) // same encoding; prefix_iter matches by prefix bytes
}

/// Exclusive upper-bound for a prefix scan.
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

/// Half-open `[start, end)` range for heed3 range scans.
fn byte_range<'a>(start: &'a [u8], end: &'a [u8]) -> (Bound<&'a [u8]>, Bound<&'a [u8]>) {
    (Bound::Included(start), Bound::Excluded(end))
}

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

/// Derive a 32-byte encryption key from the HMAC key file via HKDF-SHA256.
fn derive_encryption_key(key_file_bytes: &[u8]) -> io::Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, key_file_bytes);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| io::Error::other(format!("HKDF key derivation failed: {e}")))?;
    Ok(okm)
}

fn map_heed_err(e: heed3::Error) -> io::Error {
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

/// Plain or encrypted LMDB env + databases.
enum Inner {
    Plain {
        env: heed3::Env<WithoutTls>,
        dbs: [PlainDb; 10],
    },
    Encrypted {
        env: heed3::EncryptedEnv<WithoutTls>,
        dbs: [EncDb; 10],
    },
}

macro_rules! both {
    ($self:expr, $b:ident => $e:expr) => {
        match $self {
            Inner::Plain { $b, .. } => $e,
            Inner::Encrypted { $b, .. } => $e,
        }
    };
}

impl Inner {
    fn write_txn(&self) -> heed3::Result<heed3::RwTxn<'_>> {
        both!(self, env => env.write_txn())
    }

    fn read_txn(&self) -> heed3::Result<heed3::RoTxn<'_, WithoutTls>> {
        both!(self, env => env.read_txn())
    }

    fn force_sync(&self) -> heed3::Result<()> {
        both!(self, env => env.force_sync())
    }
}

impl Inner {
    fn put(
        &self,
        txn: &mut heed3::RwTxn<'_>,
        idx: usize,
        key: &[u8],
        val: &[u8],
    ) -> heed3::Result<()> {
        both!(self, dbs => dbs[idx].put(txn, key, val))
    }

    fn delete(&self, txn: &mut heed3::RwTxn<'_>, idx: usize, key: &[u8]) -> heed3::Result<bool> {
        both!(self, dbs => dbs[idx].delete(txn, key))
    }

    fn delete_one_dup(
        &self,
        txn: &mut heed3::RwTxn<'_>,
        idx: usize,
        key: &[u8],
        val: &[u8],
    ) -> heed3::Result<bool> {
        both!(self, dbs => dbs[idx].delete_one_duplicate(txn, key, val))
    }
}

impl Inner {
    fn get_owned(
        &self,
        txn: &mut heed3::RoTxn<'_, WithoutTls>,
        idx: usize,
        key: &[u8],
    ) -> heed3::Result<Option<Vec<u8>>> {
        both!(self, dbs => Ok(dbs[idx].get(txn, key)?.map(|v| v.to_vec())))
    }

    fn range_owned(
        &self,
        txn: &mut heed3::RoTxn<'_, WithoutTls>,
        idx: usize,
        start: &[u8],
        end: &[u8],
    ) -> heed3::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let r = &byte_range(start, end);
        both!(self, dbs => {
            let iter = dbs[idx].range(txn, r)?;
            Ok(iter
                .filter_map(|e| e.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
                .collect())
        })
    }

    fn iter_owned(
        &self,
        txn: &mut heed3::RoTxn<'_, WithoutTls>,
        idx: usize,
    ) -> heed3::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        both!(self, dbs => {
            let iter = dbs[idx].iter(txn)?;
            Ok(iter
                .filter_map(|e| e.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
                .collect())
        })
    }

    fn has_any_with_prefix(
        &self,
        txn: &mut heed3::RoTxn<'_, WithoutTls>,
        idx: usize,
        prefix: &[u8],
    ) -> bool {
        let Some(end) = prefix_successor(prefix) else {
            return false;
        };
        let r = &byte_range(prefix, &end);
        both!(self, dbs => dbs[idx]
            .range(txn, r)
            .ok()
            .and_then(|mut it| it.next())
            .is_some())
    }

    fn dup_values_in_write(
        &self,
        txn: &mut heed3::RwTxn<'_>,
        idx: usize,
        key: &[u8],
    ) -> heed3::Result<Vec<Vec<u8>>> {
        let mut values = Vec::new();
        both!(self, dbs => {
            if let Some(iter) = dbs[idx].get_duplicates(txn, key)? {
                for entry in iter {
                    let (_k, v) = entry?;
                    values.push(v.to_vec());
                }
            }
        });
        Ok(values)
    }

    fn dup_values_as_strings(
        &self,
        txn: &mut heed3::RoTxn<'_, WithoutTls>,
        idx: usize,
        key: &[u8],
    ) -> Vec<String> {
        let mut values = Vec::new();
        both!(self, dbs => {
            if let Ok(Some(iter)) = dbs[idx].get_duplicates(txn, key) {
                for (_k, v) in iter.flatten() {
                    if let Ok(s) = std::str::from_utf8(v) {
                        values.push(s.to_string());
                    }
                }
            }
        });
        values
    }

    fn keys_with_prefix_in_write(
        &self,
        txn: &mut heed3::RwTxn<'_>,
        idx: usize,
        prefix: &[u8],
    ) -> heed3::Result<Vec<Vec<u8>>> {
        let Some(end) = prefix_successor(prefix) else {
            return Ok(Vec::new());
        };
        self.range_owned(&mut *txn, idx, prefix, &end)
            .map(|pairs| pairs.into_iter().map(|(k, _)| k).collect())
    }
}

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

const DUP_SORT_INDICES: [usize; 2] = [I_BACKREFS, I_BACKREFS_REVERSE];

fn is_dup_sort(idx: usize) -> bool {
    DUP_SORT_INDICES.contains(&idx)
}

/// Embedded LMDB metadata engine.
pub struct LmdbMetadataStore {
    inner: Inner,
    write_lock: Mutex<()>,
}

impl LmdbMetadataStore {
    /// Open (or create) the LMDB metadata store.
    pub fn open(root: &Path, config: &MetadataConfig) -> io::Result<Self> {
        let dir = root.join("roci-meta.lmdb");
        std::fs::create_dir_all(&dir)
            .map_err(|e| io::Error::new(e.kind(), format!("creating {}: {e}", dir.display())))?;

        let encrypted = config.hmac_key_file.is_some();
        let expected_format = if encrypted {
            FORMAT_ENCRYPTED
        } else {
            FORMAT_PLAIN
        };

        let format_path = dir.join("roci-format");
        if format_path.exists() {
            let existing = std::fs::read_to_string(&format_path).unwrap_or_default();
            let existing = existing.trim();
            if !existing.is_empty() && existing != expected_format {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let aside = root.join(format!("roci-meta.lmdb.untrusted-{ts}"));
                tracing::warn!(
                    from = %dir.display(),
                    to = %aside.display(),
                    existing_format = existing,
                    expected_format,
                    "encryption mismatch — moving LMDB env aside; \
                     metadata will be rebuilt from the layout"
                );
                std::fs::rename(&dir, &aside).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "moving {d} → {a}: {e}",
                            d = dir.display(),
                            a = aside.display()
                        ),
                    )
                })?;
                std::fs::create_dir_all(&dir).map_err(|e| {
                    io::Error::new(e.kind(), format!("recreating {}: {e}", dir.display()))
                })?;
            }
        }

        let map_size = config.map_size_bytes as usize;

        macro_rules! create_dbs {
            ($env:expr, $wtxn:expr) => {{
                let mut arr: [Option<_>; 10] = Default::default();
                for (i, name) in DB_NAMES.iter().enumerate() {
                    let db = if is_dup_sort(i) {
                        $env.database_options()
                            .types::<Bytes, Bytes>()
                            .name(name)
                            .flags(DatabaseFlags::DUP_SORT)
                            .create(&mut $wtxn)
                            .map_err(map_heed_err)?
                    } else {
                        $env.create_database(&mut $wtxn, Some(name))
                            .map_err(map_heed_err)?
                    };
                    arr[i] = Some(db);
                }
                $wtxn.commit().map_err(map_heed_err)?;
                arr.map(|o| o.expect("all dbs created"))
            }};
        }

        let inner = if let Some(ref key_file) = config.hmac_key_file {
            let key_bytes = std::fs::read(key_file).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("reading hmac_key_file {}: {e}", key_file.display()),
                )
            })?;
            let derived = derive_encryption_key(&key_bytes)?;
            let aead_key = chacha20poly1305::Key::from(derived);

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
            let env = unsafe {
                opts.open_encrypted::<chacha20poly1305::ChaCha20Poly1305, _>(aead_key, &dir)
            }
            .map_err(map_heed_err)?;

            let mut wtxn = env.write_txn().map_err(map_heed_err)?;
            let dbs = create_dbs!(env, wtxn);
            Inner::Encrypted { env, dbs }
        } else {
            let mut opts = EnvOpenOptions::new().read_txn_without_tls();
            opts.map_size(map_size);
            opts.max_dbs(DB_COUNT);
            #[allow(unsafe_code)]
            // SAFETY: NO_SYNC — same rationale as encrypted path above.
            unsafe {
                opts.flags(EnvFlags::NO_SYNC);
            }
            #[allow(unsafe_code)]
            // SAFETY: single-process ownership, local filesystem, no concurrent
            // external writers. SIGBUS on external truncation same as snapshot mmap.
            let env = unsafe { opts.open(&dir) }.map_err(map_heed_err)?;

            let mut wtxn = env.write_txn().map_err(map_heed_err)?;
            let dbs = create_dbs!(env, wtxn);
            Inner::Plain { env, dbs }
        };

        std::fs::write(&format_path, expected_format).map_err(|e| {
            io::Error::new(e.kind(), format!("writing {}: {e}", format_path.display()))
        })?;

        // Warn about leftover redb database.
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
            inner,
            write_lock: Mutex::new(()),
        })
    }

    fn apply_inner(&self, op: MetaOp, durable: bool) -> io::Result<()> {
        let _guard = self.write_lock.lock().expect("lmdb write lock poisoned");
        let mut txn = self.inner.write_txn().map_err(map_heed_err)?;
        self.apply_op(&mut txn, &op)?;
        txn.commit().map_err(map_heed_err)?;
        if durable {
            self.inner.force_sync().map_err(map_heed_err)?;
        }
        roci_telemetry::record_meta_wal_append();
        Ok(())
    }

    fn apply_op(&self, txn: &mut heed3::RwTxn<'_>, op: &MetaOp) -> io::Result<()> {
        match op {
            MetaOp::PutManifest {
                repo,
                digest,
                media_type,
                tag,
                references,
                referrer,
            } => {
                {
                    let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                    self.inner
                        .put(txn, I_MEDIA_TYPES, &key, media_type.as_bytes())
                        .map_err(map_heed_err)?;
                }
                if let Some(tag) = tag {
                    let tag_key = make_key(&[repo.as_bytes(), tag.as_bytes()]);
                    if let Some(old_val) = self
                        .inner
                        .get_owned(&mut *txn, I_TAGS, &tag_key)
                        .map_err(map_heed_err)?
                    {
                        if let Some(sep) = old_val.iter().position(|&b| b == 0) {
                            let old_digest = &old_val[..sep];
                            let rev_key = make_key(&[repo.as_bytes(), old_digest, tag.as_bytes()]);
                            self.inner
                                .delete(txn, I_TAGS_BY_DIGEST, &rev_key)
                                .map_err(map_heed_err)?;
                        }
                    }
                    let mut val = Vec::with_capacity(digest.len() + 1 + media_type.len());
                    val.extend_from_slice(digest.as_bytes());
                    val.push(0);
                    val.extend_from_slice(media_type.as_bytes());
                    self.inner
                        .put(txn, I_TAGS, &tag_key, &val)
                        .map_err(map_heed_err)?;

                    let rev_key = make_key(&[repo.as_bytes(), digest.as_bytes(), tag.as_bytes()]);
                    self.inner
                        .put(txn, I_TAGS_BY_DIGEST, &rev_key, &[])
                        .map_err(map_heed_err)?;
                }
                self.add_backrefs_in_txn(txn, repo, digest, references)?;
                if let Some((subject, descriptor)) = referrer {
                    self.add_referrer_in_txn(txn, repo, subject, digest, descriptor)?;
                }
            }

            MetaOp::DeleteManifest { repo, digest } => {
                {
                    let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                    self.inner
                        .delete(txn, I_CHECKSUMS, &key)
                        .map_err(map_heed_err)?;
                    self.inner
                        .delete(txn, I_MEDIA_TYPES, &key)
                        .map_err(map_heed_err)?;
                }
                {
                    let prefix = make_prefix(&[repo.as_bytes(), digest.as_bytes()]);
                    let keys = self
                        .inner
                        .keys_with_prefix_in_write(txn, I_TAGS_BY_DIGEST, &prefix)
                        .map_err(map_heed_err)?;
                    for rev_key in &keys {
                        let parts = split_key(rev_key);
                        if parts.len() >= 3 {
                            let tag = parts[2];
                            let tag_key = make_key(&[repo.as_bytes(), tag]);
                            self.inner
                                .delete(txn, I_TAGS, &tag_key)
                                .map_err(map_heed_err)?;
                        }
                        self.inner
                            .delete(txn, I_TAGS_BY_DIGEST, rev_key)
                            .map_err(map_heed_err)?;
                    }
                }
                {
                    let prefix = make_prefix(&[repo.as_bytes(), digest.as_bytes()]);
                    let keys = self
                        .inner
                        .keys_with_prefix_in_write(txn, I_REFERRERS_REVERSE, &prefix)
                        .map_err(map_heed_err)?;
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
                {
                    let dup_key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                    let blobs = self
                        .inner
                        .dup_values_in_write(txn, I_BACKREFS_REVERSE, &dup_key)
                        .map_err(map_heed_err)?;
                    for blob in &blobs {
                        let fwd_key = make_key(&[repo.as_bytes(), blob]);
                        self.inner
                            .delete_one_dup(txn, I_BACKREFS, &fwd_key, digest.as_bytes())
                            .map_err(map_heed_err)?;
                    }
                    self.inner
                        .delete(txn, I_BACKREFS_REVERSE, &dup_key)
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
                self.inner
                    .put(txn, I_CHECKSUMS, &key, &buf)
                    .map_err(map_heed_err)?;
            }

            MetaOp::DeleteBlob { repo, digest } => {
                let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
                self.inner
                    .delete(txn, I_CHECKSUMS, &key)
                    .map_err(map_heed_err)?;
            }
        }
        Ok(())
    }

    fn add_backrefs_in_txn(
        &self,
        txn: &mut heed3::RwTxn<'_>,
        repo: &str,
        manifest: &str,
        blobs: &[String],
    ) -> io::Result<()> {
        for blob in blobs {
            let fwd_key = make_key(&[repo.as_bytes(), blob.as_bytes()]);
            self.inner
                .put(txn, I_BACKREFS, &fwd_key, manifest.as_bytes())
                .map_err(map_heed_err)?;
            let rev_key = make_key(&[repo.as_bytes(), manifest.as_bytes()]);
            self.inner
                .put(txn, I_BACKREFS_REVERSE, &rev_key, blob.as_bytes())
                .map_err(map_heed_err)?;
        }
        Ok(())
    }

    fn add_referrer_in_txn(
        &self,
        txn: &mut heed3::RwTxn<'_>,
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
            self.inner
                .put(txn, I_REFERRERS, &key, descriptor)
                .map_err(map_heed_err)?;
        }
        {
            let rev_key = make_key(&[repo.as_bytes(), referrer.as_bytes(), subject.as_bytes()]);
            self.inner
                .put(txn, I_REFERRERS_REVERSE, &rev_key, &[])
                .map_err(map_heed_err)?;
        }
        if let Some(at) = &artifact_type {
            let rt_key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
            self.inner
                .put(txn, I_REFERRER_TYPES, &rt_key, at.as_bytes())
                .map_err(map_heed_err)?;
            let bt_key = make_key(&[
                repo.as_bytes(),
                subject.as_bytes(),
                at.as_bytes(),
                referrer.as_bytes(),
            ]);
            self.inner
                .put(txn, I_REFERRERS_BY_TYPE, &bt_key, &[])
                .map_err(map_heed_err)?;
        }
        Ok(())
    }

    fn remove_referrer_in_txn(
        &self,
        txn: &mut heed3::RwTxn<'_>,
        repo: &str,
        subject: &str,
        referrer: &str,
    ) -> io::Result<()> {
        let rt_key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
        let had_type = self
            .inner
            .get_owned(&mut *txn, I_REFERRER_TYPES, &rt_key)
            .map_err(map_heed_err)?;

        {
            let key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
            self.inner
                .delete(txn, I_REFERRERS, &key)
                .map_err(map_heed_err)?;
        }
        {
            let rev_key = make_key(&[repo.as_bytes(), referrer.as_bytes(), subject.as_bytes()]);
            self.inner
                .delete(txn, I_REFERRERS_REVERSE, &rev_key)
                .map_err(map_heed_err)?;
        }
        self.inner
            .delete(txn, I_REFERRER_TYPES, &rt_key)
            .map_err(map_heed_err)?;
        if let Some(at) = &had_type {
            let bt_key = make_key(&[repo.as_bytes(), subject.as_bytes(), at, referrer.as_bytes()]);
            self.inner
                .delete(txn, I_REFERRERS_BY_TYPE, &bt_key)
                .map_err(map_heed_err)?;
        }
        Ok(())
    }
}

impl LmdbMetadataStore {
    /// Open an LMDB env at an arbitrary directory (used for migration temp).
    pub(crate) fn open_at(dir: &Path, config: &MetadataConfig) -> io::Result<Self> {
        // `open` builds the path as root.join("roci-meta.lmdb"). For open_at
        // we *are* given the lmdb dir itself, so we create a shim.
        std::fs::create_dir_all(dir)?;

        let encrypted = config.hmac_key_file.is_some();
        let expected_format = if encrypted {
            FORMAT_ENCRYPTED
        } else {
            FORMAT_PLAIN
        };

        let format_path = dir.join("roci-format");
        if format_path.exists() {
            let existing = std::fs::read_to_string(&format_path).unwrap_or_default();
            let existing = existing.trim();
            if !existing.is_empty() && existing != expected_format {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "LMDB format mismatch at {}: found {existing}, expected {expected_format}",
                        dir.display()
                    ),
                ));
            }
        }

        let map_size = config.map_size_bytes as usize;
        let inner = if let Some(ref key_file) = config.hmac_key_file {
            let key_bytes = std::fs::read(key_file).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("reading hmac_key_file {}: {e}", key_file.display()),
                )
            })?;
            let derived = derive_encryption_key(&key_bytes)?;
            let aead_key = chacha20poly1305::Key::from(derived);

            let mut opts = EnvOpenOptions::new().read_txn_without_tls();
            opts.map_size(map_size);
            opts.max_dbs(DB_COUNT);
            #[allow(unsafe_code)]
            unsafe {
                opts.flags(EnvFlags::NO_SYNC);
            }
            #[allow(unsafe_code)]
            let env = unsafe {
                opts.open_encrypted::<chacha20poly1305::ChaCha20Poly1305, _>(aead_key, dir)
            }
            .map_err(map_heed_err)?;

            let mut wtxn = env.write_txn().map_err(map_heed_err)?;
            let mut dbs_arr: [Option<EncDb>; 10] = Default::default();
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
            Inner::Encrypted { env, dbs }
        } else {
            let mut opts = EnvOpenOptions::new().read_txn_without_tls();
            opts.map_size(map_size);
            opts.max_dbs(DB_COUNT);
            #[allow(unsafe_code)]
            unsafe {
                opts.flags(EnvFlags::NO_SYNC);
            }
            #[allow(unsafe_code)]
            let env = unsafe { opts.open(dir) }.map_err(map_heed_err)?;

            let mut wtxn = env.write_txn().map_err(map_heed_err)?;
            let mut dbs_arr: [Option<PlainDb>; 10] = Default::default();
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
            Inner::Plain { env, dbs }
        };

        std::fs::write(&format_path, expected_format)?;

        Ok(Self {
            inner,
            write_lock: Mutex::new(()),
        })
    }

    /// Apply a batch of ops in one RwTxn (for migration bulk load).
    pub(crate) fn bulk_apply(&self, ops: &[MetaOp]) -> io::Result<()> {
        let _guard = self.write_lock.lock().expect("lmdb write lock poisoned");
        let mut txn = self.inner.write_txn().map_err(map_heed_err)?;
        for op in ops {
            self.apply_op(&mut txn, op)?;
        }
        txn.commit().map_err(map_heed_err)?;
        Ok(())
    }

    /// Force sync (public wrapper for migration).
    pub(crate) fn force_sync_public(&self) -> io::Result<()> {
        self.inner.force_sync().map_err(map_heed_err)
    }

    /// Walk all LMDB tables in one read txn and emit MetaOp ops via the sink.
    fn export_impl(&self, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
        let mut rtx = self.inner.read_txn().map_err(map_heed_err)?;

        // Collect all tags to know which digests are tagged.
        let mut tagged = std::collections::BTreeSet::<(String, String)>::new();

        // 1. Tags → PutManifest with tag
        {
            let entries = self
                .inner
                .iter_owned(&mut rtx, I_TAGS)
                .map_err(map_heed_err)?;
            for (k, v) in &entries {
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
            let entries = self
                .inner
                .iter_owned(&mut rtx, I_MEDIA_TYPES)
                .map_err(map_heed_err)?;
            for (k, v) in &entries {
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
            let entries = self
                .inner
                .iter_owned(&mut rtx, I_BACKREFS)
                .map_err(map_heed_err)?;
            for (k, v) in &entries {
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
            let entries = self
                .inner
                .iter_owned(&mut rtx, I_REFERRERS)
                .map_err(map_heed_err)?;
            for (k, v) in &entries {
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
                    descriptor: v.clone(),
                })?;
            }
        }

        // 5. Checksums → PutChecksum
        {
            let entries = self
                .inner
                .iter_owned(&mut rtx, I_CHECKSUMS)
                .map_err(map_heed_err)?;
            for (k, v) in &entries {
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

impl MetadataStore for LmdbMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let mut rtx = self.inner.read_txn().ok()?;
        let key = make_key(&[repo.as_bytes(), tag.as_bytes()]);
        let val = self.inner.get_owned(&mut rtx, I_TAGS, &key).ok()??;
        let sep = val.iter().position(|&b| b == 0)?;
        let digest = std::str::from_utf8(&val[..sep]).ok()?;
        let media_type = std::str::from_utf8(&val[sep + 1..]).ok()?;
        Some((digest.to_string(), media_type.to_string()))
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let mut rtx = self.inner.read_txn().ok()?;
        let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
        let val = self.inner.get_owned(&mut rtx, I_MEDIA_TYPES, &key).ok()??;
        std::str::from_utf8(&val).ok().map(str::to_string)
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let mut rtx = self.inner.read_txn().ok()?;

        let repo_prefix = make_prefix(&[repo.as_bytes()]);
        if !self
            .inner
            .has_any_with_prefix(&mut rtx, I_TAGS, &repo_prefix)
        {
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
        let pairs = self
            .inner
            .range_owned(&mut rtx, I_TAGS, &start, &end)
            .ok()?;

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
        let mut rtx = self.inner.read_txn().ok()?;

        match artifact_type {
            None => {
                let subj_prefix = make_prefix(&[repo.as_bytes(), subject.as_bytes()]);
                if !self
                    .inner
                    .has_any_with_prefix(&mut rtx, I_REFERRERS, &subj_prefix)
                {
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
                let pairs = self
                    .inner
                    .range_owned(&mut rtx, I_REFERRERS, &start, &end)
                    .ok()?;

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
                    self.inner
                        .has_any_with_prefix(&mut rtx, I_REFERRERS_BY_TYPE, &type_prefix);
                if !has_typed {
                    let subj_prefix = make_prefix(&[repo.as_bytes(), subject.as_bytes()]);
                    if !self
                        .inner
                        .has_any_with_prefix(&mut rtx, I_REFERRERS, &subj_prefix)
                    {
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
                let by_type_pairs = self
                    .inner
                    .range_owned(&mut rtx, I_REFERRERS_BY_TYPE, &start, &end)
                    .ok()?;

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
                    if let Ok(Some(desc)) = self.inner.get_owned(&mut rtx, I_REFERRERS, &ref_key) {
                        items.push((referrer.to_string(), desc));
                    }
                }
                Some(Page { items, more: false })
            }
        }
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let mut rtx = match self.inner.read_txn() {
            Ok(r) => r,
            Err(_) => return false,
        };
        let key = make_key(&[repo.as_bytes(), subject.as_bytes(), referrer.as_bytes()]);
        self.inner
            .get_owned(&mut rtx, I_REFERRERS, &key)
            .ok()
            .flatten()
            .is_some()
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let mut rtx = match self.inner.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let key = make_key(&[repo.as_bytes(), blob.as_bytes()]);
        self.inner.dup_values_as_strings(&mut rtx, I_BACKREFS, &key)
    }

    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum> {
        let mut rtx = self.inner.read_txn().ok()?;
        let key = make_key(&[repo.as_bytes(), digest.as_bytes()]);
        let val = self.inner.get_owned(&mut rtx, I_CHECKSUMS, &key).ok()??;
        Some(decode_checksum(&val))
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        self.apply_inner(op, true)
    }

    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()> {
        self.apply_inner(op, false)
    }

    fn repos(&self) -> Vec<String> {
        let mut rtx = match self.inner.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut repos = std::collections::BTreeSet::new();

        for idx in [I_MEDIA_TYPES, I_REFERRERS] {
            if let Ok(entries) = self.inner.iter_owned(&mut rtx, idx) {
                for (k, _) in &entries {
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
        let mut rtx = match self.inner.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let prefix = make_prefix(&[repo.as_bytes()]);
        let Some(end) = prefix_successor(&prefix) else {
            return Vec::new();
        };
        let Ok(pairs) = self
            .inner
            .range_owned(&mut rtx, I_MEDIA_TYPES, &prefix, &end)
        else {
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
        let mut rtx = match self.inner.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let prefix = make_prefix(&[repo.as_bytes()]);
        let Some(end) = prefix_successor(&prefix) else {
            return Vec::new();
        };
        let Ok(pairs) = self.inner.range_owned(&mut rtx, I_TAGS, &prefix, &end) else {
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
        let mut rtx = match self.inner.read_txn() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let prefix = make_prefix(&[repo.as_bytes()]);
        let Some(end) = prefix_successor(&prefix) else {
            return Vec::new();
        };
        let Ok(pairs) = self.inner.range_owned(&mut rtx, I_REFERRERS, &prefix, &end) else {
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
        self.inner.force_sync().map_err(map_heed_err)?;
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

    fn make_encrypted_config(root: &Path) -> MetadataConfig {
        let key_path = root.join("hmac-test.key");
        std::fs::write(&key_path, b"test-key-material-32-bytes-long!").unwrap();
        MetadataConfig {
            hmac_key_file: Some(key_path),
            ..MetadataConfig::default()
        }
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
    fn encryption_mismatch_moves_aside() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_config();
        let store = LmdbMetadataStore::open(dir.path(), &config).unwrap();
        store
            .apply(MetaOp::PutManifest {
                repo: "r".into(),
                digest: "sha256:aaa".into(),
                media_type: "mt".into(),
                tag: Some("v1".into()),
                references: vec![],
                referrer: None,
            })
            .unwrap();
        drop(store);

        let format_path = dir.path().join("roci-meta.lmdb/roci-format");
        assert_eq!(std::fs::read_to_string(&format_path).unwrap(), "plain");

        let enc_config = make_encrypted_config(dir.path());
        let store2 = LmdbMetadataStore::open(dir.path(), &enc_config).unwrap();

        assert!(store2.resolve_tag("r", "v1").is_none());

        let untrusted: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("roci-meta.lmdb.untrusted-")
            })
            .collect();
        assert_eq!(untrusted.len(), 1, "expected one untrusted dir");

        assert_eq!(
            std::fs::read_to_string(&format_path).unwrap(),
            "chacha20poly1305-v1"
        );
    }

    #[test]
    fn encrypted_reopen_persists() {
        let dir = tempfile::tempdir().unwrap();
        let enc_config = make_encrypted_config(dir.path());

        {
            let store = LmdbMetadataStore::open(dir.path(), &enc_config).unwrap();
            store
                .apply(MetaOp::PutManifest {
                    repo: "r".into(),
                    digest: "sha256:m".into(),
                    media_type: "mt".into(),
                    tag: Some("v1".into()),
                    references: vec!["sha256:blob".into()],
                    referrer: None,
                })
                .unwrap();
            store
                .apply(MetaOp::PutChecksum {
                    repo: "r".into(),
                    digest: "sha256:blob".into(),
                    crc32c: 42,
                    size: 999,
                })
                .unwrap();
        }

        {
            let store = LmdbMetadataStore::open(dir.path(), &enc_config).unwrap();
            let (d, mt) = store.resolve_tag("r", "v1").unwrap();
            assert_eq!(d, "sha256:m");
            assert_eq!(mt, "mt");
            assert_eq!(store.backrefs("r", "sha256:blob"), vec!["sha256:m"]);
            let bc = store.checksum("r", "sha256:blob").unwrap();
            assert_eq!(bc.crc32c, 42);
            assert_eq!(bc.size, 999);
        }
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
        let mapped = map_heed_err(heed3::Error::Io(err));
        let mapped_msg = mapped.to_string();
        assert!(
            mapped_msg.contains("map_size_bytes") || mapped_msg.contains("MDB_MAP_FULL"),
            "should mention map full: {mapped_msg}"
        );
    }

    #[test]
    fn open_at_format_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let lmdb_dir = dir.path().join("lmdb-at");
        std::fs::create_dir_all(&lmdb_dir).unwrap();
        std::fs::write(lmdb_dir.join("roci-format"), "chacha20poly1305-v1").unwrap();
        let config = make_config();
        match LmdbMetadataStore::open_at(&lmdb_dir, &config) {
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
                assert!(
                    err.to_string().contains("format mismatch"),
                    "expected format mismatch: {err}"
                );
            }
            Ok(_) => panic!("expected InvalidData error"),
        }
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
    fn key_file_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = MetadataConfig {
            hmac_key_file: Some(dir.path().join("nonexistent.key")),
            ..MetadataConfig::default()
        };
        match LmdbMetadataStore::open(dir.path(), &config) {
            Err(err) => assert!(
                err.to_string().contains("hmac_key_file"),
                "should mention key file: {err}"
            ),
            Ok(_) => panic!("expected error for missing key file"),
        }
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
