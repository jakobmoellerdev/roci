//! Default metadata engine: in-RAM maps mirrored to an append-only,
//! CRC32C-framed `roci-meta.log`. Supports compaction and WAL HMAC
//! (SECURITY §Storage boundary).

use super::wal_hmac::{self, decode_header, FramingMode, HmacKey};
use super::{after, take_page, BlobChecksum, MetaOp, MetadataStore, Page, Referrer};
use roci_config::MetadataConfig;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// In-RAM metadata maps mirrored to an append-only CRC32C-framed log.
pub struct LogMetadataStore {
    inner: Mutex<State>,
    appended: AtomicU64,
    sync: Mutex<SyncCoord>,
    log_path: PathBuf,
    compact_threshold: u64,
    hmac_key: Option<HmacKey>,
    generation: Mutex<u64>,
    /// Image len at last compaction; upkeep triggers on growth past it.
    image_len: AtomicU64,
}

impl std::fmt::Debug for LogMetadataStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogMetadataStore")
            .field("log_path", &self.log_path)
            .finish()
    }
}

#[derive(Default)]
struct SyncCoord {
    synced: u64,
    handle: Option<std::fs::File>,
}

#[derive(Default, Clone)]
struct SubjectReferrers {
    by_digest: BTreeMap<String, (Option<String>, Vec<u8>)>,
    by_type: HashMap<String, BTreeSet<String>>,
}

impl SubjectReferrers {
    fn insert(&mut self, referrer: &str, descriptor: &[u8]) {
        let artifact_type = serde_json::from_slice::<serde_json::Value>(descriptor)
            .ok()
            .and_then(|v| v.get("artifactType")?.as_str().map(str::to_string));
        self.remove(referrer);
        if let Some(t) = &artifact_type {
            self.by_type
                .entry(t.clone())
                .or_default()
                .insert(referrer.to_string());
        }
        self.by_digest
            .insert(referrer.to_string(), (artifact_type, descriptor.to_vec()));
    }

    fn remove(&mut self, referrer: &str) {
        let Some((Some(t), _)) = self.by_digest.remove(referrer) else {
            return;
        };
        if let Some(set) = self.by_type.get_mut(&t) {
            set.remove(referrer);
            if set.is_empty() {
                self.by_type.remove(&t);
            }
        }
    }

    fn page(
        &self,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Page<Referrer> {
        match artifact_type {
            None => take_page(
                self.by_digest
                    .range::<str, _>(after(last))
                    .map(|(d, (_, bytes))| (d.clone(), bytes.clone())),
                limit,
            ),
            Some(t) => match self.by_type.get(t) {
                Some(set) => take_page(
                    set.range::<str, _>(after(last))
                        .map(|d| (d.clone(), self.by_digest[d].1.clone())),
                    limit,
                ),
                None => Page::default(),
            },
        }
    }
}

/// Per-repository metadata.  One shared `Box<str>` repo name per repo instead
/// of one `String` copy per every map entry.
#[derive(Default, Clone)]
struct RepoState {
    tags: BTreeMap<String, (String, Arc<str>)>,
    media_types: HashMap<String, Arc<str>>,
    referrers: HashMap<String, SubjectReferrers>,
    backrefs: HashMap<String, Vec<String>>,
    checksums: HashMap<String, BlobChecksum>,
}

/// Full in-RAM state.
#[derive(Default)]
struct State {
    repos: HashMap<Box<str>, RepoState>,
    /// Small interner for media-type strings (bounded by distinct values).
    media_type_interner: HashSet<Arc<str>>,
    log: Option<std::fs::File>,
}

impl State {
    fn intern_media_type(&mut self, s: &str) -> Arc<str> {
        if let Some(existing) = self.media_type_interner.get(s) {
            return Arc::clone(existing);
        }
        let arc: Arc<str> = Arc::from(s);
        self.media_type_interner.insert(Arc::clone(&arc));
        arc
    }

    fn repo_mut(&mut self, repo: &str) -> &mut RepoState {
        if !self.repos.contains_key(repo) {
            self.repos.insert(Box::from(repo), RepoState::default());
        }
        self.repos.get_mut(repo).unwrap()
    }

    fn add_backrefs(&mut self, repo: &str, manifest: &str, blobs: &[String]) {
        let rs = self.repo_mut(repo);
        for blob in blobs {
            let set = rs.backrefs.entry(blob.clone()).or_default();
            if !set.iter().any(|m| m == manifest) {
                set.push(manifest.to_string());
            }
        }
    }

    fn add_referrer(&mut self, repo: &str, subject: &str, referrer: &str, descriptor: &[u8]) {
        self.repo_mut(repo)
            .referrers
            .entry(subject.to_string())
            .or_default()
            .insert(referrer, descriptor);
    }
}

fn framing_mode(key: Option<&HmacKey>) -> FramingMode {
    if key.is_some() {
        FramingMode::HmacSha256
    } else {
        FramingMode::Plain
    }
}

fn discard_log(log_path: &Path) {
    let _ = wal_hmac::move_aside(log_path);
}

impl LogMetadataStore {
    /// Open with the `[storage.metadata]` policy.
    pub fn open_with(root: &Path, config: &MetadataConfig) -> io::Result<Self> {
        let hmac_key = config
            .hmac_key_file
            .as_ref()
            .map(|p| HmacKey::load(p))
            .transpose()?;
        Self::open_inner(root, config.compact_threshold_bytes, hmac_key)
    }

    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_inner(root, 0, None)
    }

    fn open_inner(
        root: &Path,
        compact_threshold: u64,
        hmac_key: Option<HmacKey>,
    ) -> io::Result<Self> {
        let log_path = root.join("roci-meta.log");
        let mut state = State::default();
        let mut generation = 0u64;

        if let Ok(bytes) = std::fs::read(&log_path) {
            if !bytes.is_empty() {
                let expected_mode = framing_mode(hmac_key.as_ref());
                match check_log_framing(&bytes, expected_mode, hmac_key.as_ref()) {
                    LogFramingCheck::Compatible => {
                        replay_log(&bytes, &mut state, hmac_key.as_ref(), &mut generation);
                    }
                    LogFramingCheck::Incompatible => {
                        tracing::warn!(
                            "WAL framing/key mismatch; moving log aside and starting fresh"
                        );
                        discard_log(&log_path);
                    }
                    LogFramingCheck::NoHeader => {
                        if hmac_key.is_some() {
                            tracing::warn!(
                                "unauthenticated log found with HMAC key configured; \
                                 moving log aside"
                            );
                            discard_log(&log_path);
                        } else {
                            replay_legacy(&bytes, &mut state);
                        }
                    }
                }
            }
        }

        let snapshot_path = root.join("roci-meta.snapshot");
        if snapshot_path.exists() {
            tracing::warn!(
                path = %snapshot_path.display(),
                "found obsolete rkyv metadata snapshot; \
                 the snapshot option has been removed — the file is no longer used \
                 and can be deleted manually"
            );
        }

        let image_len = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            inner: Mutex::new(state),
            appended: AtomicU64::new(0),
            sync: Mutex::new(SyncCoord::default()),
            log_path,
            compact_threshold,
            hmac_key,
            generation: Mutex::new(generation),
            image_len: AtomicU64::new(image_len),
        })
    }

    fn apply_in_ram(state: &mut State, op: &MetaOp) {
        match op {
            MetaOp::PutManifest {
                repo,
                digest,
                media_type,
                tag,
                references,
                referrer,
            } => {
                let mt = state.intern_media_type(media_type);
                let rs = state.repo_mut(repo);
                rs.media_types.insert(digest.clone(), Arc::clone(&mt));
                if let Some(tag) = tag {
                    rs.tags
                        .insert(tag.clone(), (digest.clone(), Arc::clone(&mt)));
                }
                state.add_backrefs(repo, digest, references);
                if let Some((subject, descriptor)) = referrer {
                    state.add_referrer(repo, subject, digest, descriptor);
                }
            }
            MetaOp::DeleteManifest { repo, digest } => {
                let rs = state.repo_mut(repo);
                rs.checksums.remove(digest.as_str());
                rs.media_types.remove(digest.as_str());
                rs.tags.retain(|_, (d, _)| d != digest);
                rs.referrers.retain(|_, refs| {
                    refs.remove(digest);
                    !refs.by_digest.is_empty()
                });
                rs.backrefs.retain(|_, manifests| {
                    manifests.retain(|m| m != digest);
                    !manifests.is_empty()
                });
            }
            MetaOp::PutBackrefs {
                repo,
                manifest,
                blobs,
            } => state.add_backrefs(repo, manifest, blobs),
            MetaOp::PutReferrer {
                repo,
                subject,
                referrer,
                descriptor,
            } => state.add_referrer(repo, subject, referrer, descriptor),
            MetaOp::PutChecksum {
                repo,
                digest,
                crc32c,
                size,
            } => {
                let rs = state.repo_mut(repo);
                rs.checksums.insert(
                    digest.clone(),
                    BlobChecksum {
                        crc32c: *crc32c,
                        size: *size,
                    },
                );
            }
            MetaOp::DeleteBlob { repo, digest } => {
                let rs = state.repo_mut(repo);
                rs.checksums.remove(digest.as_str());
            }
        }
    }
}

impl MetadataStore for LogMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let rs = state.repos.get(repo)?;
        let (digest, media) = rs.tags.get(tag)?;
        Some((digest.clone(), media.to_string()))
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let rs = state.repos.get(repo)?;
        rs.media_types.get(digest).map(|v| v.to_string())
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let tags = &state.repos.get(repo)?.tags;
        if tags.is_empty() {
            return None;
        }
        Some(take_page(
            tags.range::<str, _>(after(last)).map(|(t, _)| t.clone()),
            limit,
        ))
    }

    fn referrers_page(
        &self,
        repo: &str,
        subject: &str,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Option<Page<Referrer>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let refs = state.repos.get(repo)?.referrers.get(subject)?;
        Some(refs.page(artifact_type, last, limit))
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .repos
            .get(repo)
            .and_then(|rs| rs.referrers.get(subject))
            .is_some_and(|refs| refs.by_digest.contains_key(referrer))
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .repos
            .get(repo)
            .and_then(|rs| rs.backrefs.get(blob))
            .cloned()
            .unwrap_or_default()
    }

    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .repos
            .get(repo)
            .and_then(|rs| rs.checksums.get(digest))
            .copied()
    }

    fn apply(&self, op: MetaOp) -> io::Result<()> {
        let my_seq = self.append_record(&op)?;
        self.group_commit_through(my_seq)
    }

    fn apply_relaxed(&self, op: MetaOp) -> io::Result<()> {
        self.append_record(&op).map(drop)
    }

    fn repos(&self) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let mut repos: Vec<String> = state
            .repos
            .iter()
            .filter(|(_, rs)| !rs.media_types.is_empty() || !rs.referrers.is_empty())
            .map(|(r, _)| r.to_string())
            .collect();
        repos.sort();
        repos
    }

    fn manifests(&self, repo: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .repos
            .get(repo)
            .map(|rs| rs.media_types.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .repos
            .get(repo)
            .map(|rs| {
                rs.tags
                    .iter()
                    .map(|(t, (d, m))| (t.clone(), d.clone(), m.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        state
            .repos
            .get(repo)
            .map(|rs| {
                rs.referrers
                    .iter()
                    .filter(|(_, sr)| !sr.by_digest.is_empty())
                    .map(|(subject, sr)| {
                        let refs = sr
                            .by_digest
                            .iter()
                            .map(|(d, (_, bytes))| (d.clone(), bytes.clone()))
                            .collect();
                        (subject.clone(), refs)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn export(&self, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        export_state(&state, sink)
    }

    fn maintain(&self) -> io::Result<()> {
        self.do_maintain()
    }

    fn generation(&self) -> u64 {
        *self.generation.lock().expect("gen lock poisoned")
    }

    fn log_len(&self) -> u64 {
        std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }
}

impl LogMetadataStore {
    fn append_record(&self, op: &MetaOp) -> io::Result<u64> {
        let record = encode(op, self.hmac_key.as_ref());
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        if state.log.is_none() {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)?;
            let clone = f.try_clone()?;
            let meta = f.metadata()?;
            if meta.len() == 0 {
                let mode = framing_mode(self.hmac_key.as_ref());
                let header_payload = wal_hmac::encode_header(mode);
                let header_record = encode_raw(&header_payload, self.hmac_key.as_ref());
                let mut combined = header_record;
                combined.extend_from_slice(&record);
                (&f).write_all(&combined)?;
                (&f).flush()?;
            } else {
                (&f).write_all(&record)?;
                (&f).flush()?;
            }
            state.log = Some(f);
            self.sync.lock().expect("sync lock poisoned").handle = Some(clone);
            let seq = self.appended.fetch_add(1, Ordering::AcqRel) + 1;
            Self::apply_in_ram(&mut state, op);
            roci_telemetry::record_meta_wal_append();
            return Ok(seq);
        }
        let log = state.log.as_mut().expect("log opened above");
        log.write_all(&record)?;
        log.flush()?;
        let seq = self.appended.fetch_add(1, Ordering::AcqRel) + 1;
        Self::apply_in_ram(&mut state, op);
        roci_telemetry::record_meta_wal_append();
        Ok(seq)
    }

    fn group_commit_through(&self, my_seq: u64) -> io::Result<()> {
        let mut sync = self.sync.lock().expect("sync lock poisoned");
        if sync.synced >= my_seq {
            return Ok(());
        }
        let covered = self.appended.load(Ordering::Acquire);
        sync.handle
            .as_ref()
            .expect("log handle set on first append")
            .sync_data()?;
        let batch = covered.saturating_sub(sync.synced);
        sync.synced = sync.synced.max(covered);
        roci_telemetry::record_meta_wal_batch_size(batch);
        Ok(())
    }

    /// Compact the WAL when growth exceeds the threshold.
    fn do_maintain(&self) -> io::Result<()> {
        let log_size = std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let grown = log_size.saturating_sub(self.image_len.load(Ordering::Acquire));
        if self.compact_threshold == 0 || grown <= self.compact_threshold {
            return Ok(());
        }
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        let mut gen = self.generation.lock().expect("gen lock poisoned");
        let next = *gen + 1;
        let (tmp, len) = self.write_log_image(&state, Some(next))?;
        self.install_log(&mut state, &tmp)?;
        self.image_len.store(len, Ordering::Release);
        *gen = next;
        roci_telemetry::record_meta_compaction("ok");
        Ok(())
    }

    /// Write the minimal record image reproducing `full` to a temp file.
    fn write_log_image(&self, full: &State, gen: Option<u64>) -> io::Result<(PathBuf, u64)> {
        let key = self.hmac_key.as_ref();
        let tmp = self.log_path.with_extension("log.compact.tmp");
        let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        let mode = framing_mode(key);
        f.write_all(&encode_raw(&wal_hmac::encode_header(mode), key))?;
        if let Some(gen) = gen {
            let marker = format!("{{\"op\":\"gen\",\"gen\":{gen}}}");
            f.write_all(&encode_raw(marker.as_bytes(), key))?;
        }
        let mut tagged: BTreeSet<(&str, &str)> = BTreeSet::new();
        for (repo, rs) in &full.repos {
            for (tag, (digest, media_type)) in &rs.tags {
                f.write_all(&encode(
                    &MetaOp::PutManifest {
                        repo: repo.to_string(),
                        digest: digest.clone(),
                        media_type: media_type.to_string(),
                        tag: Some(tag.clone()),
                        references: Vec::new(),
                        referrer: None,
                    },
                    key,
                ))?;
                tagged.insert((repo, digest));
            }
        }
        for (repo, rs) in &full.repos {
            for (digest, media_type) in &rs.media_types {
                if !tagged.contains(&(repo.as_ref(), digest.as_str())) {
                    f.write_all(&encode(
                        &MetaOp::PutManifest {
                            repo: repo.to_string(),
                            digest: digest.clone(),
                            media_type: media_type.to_string(),
                            tag: None,
                            references: Vec::new(),
                            referrer: None,
                        },
                        key,
                    ))?;
                }
            }
        }
        for (repo, rs) in &full.repos {
            for (blob, manifests) in &rs.backrefs {
                for m in manifests {
                    f.write_all(&encode(
                        &MetaOp::PutBackrefs {
                            repo: repo.to_string(),
                            manifest: m.clone(),
                            blobs: vec![blob.clone()],
                        },
                        key,
                    ))?;
                }
            }
        }
        for (repo, rs) in &full.repos {
            for (subject, refs) in &rs.referrers {
                for (referrer, (_, descriptor)) in &refs.by_digest {
                    f.write_all(&encode(
                        &MetaOp::PutReferrer {
                            repo: repo.to_string(),
                            subject: subject.clone(),
                            referrer: referrer.clone(),
                            descriptor: descriptor.clone(),
                        },
                        key,
                    ))?;
                }
            }
        }
        for (repo, rs) in &full.repos {
            for (digest, ck) in &rs.checksums {
                f.write_all(&encode(
                    &MetaOp::PutChecksum {
                        repo: repo.to_string(),
                        digest: digest.clone(),
                        crc32c: ck.crc32c,
                        size: ck.size,
                    },
                    key,
                ))?;
            }
        }
        let f = f.into_inner().map_err(io::IntoInnerError::into_error)?;
        f.sync_all()?;
        let len = f.metadata()?.len();
        Ok((tmp, len))
    }

    fn install_log(&self, state: &mut State, tmp: &Path) -> io::Result<()> {
        std::fs::rename(tmp, &self.log_path)?;
        if let Some(dir) = self.log_path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.log_path)?;
        let clone = f.try_clone()?;
        state.log = Some(f);
        let mut sync = self.sync.lock().expect("sync lock poisoned");
        sync.handle = Some(clone);
        sync.synced = self.appended.load(Ordering::Acquire);
        Ok(())
    }
}

/// Emit the minimal `MetaOp` image reproducing `state` — reuses the same
/// iteration order as `write_log_image` (compaction): one PutManifest per tag,
/// one PutManifest per untagged manifest, one PutBackrefs per edge, one
/// PutReferrer per referrer, one PutChecksum per checksum.
fn export_state(full: &State, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
    use std::collections::BTreeSet;
    let mut tagged: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (repo, rs) in &full.repos {
        for (tag, (digest, media_type)) in &rs.tags {
            sink(MetaOp::PutManifest {
                repo: repo.to_string(),
                digest: digest.clone(),
                media_type: media_type.to_string(),
                tag: Some(tag.clone()),
                references: Vec::new(),
                referrer: None,
            })?;
            tagged.insert((repo, digest));
        }
    }
    for (repo, rs) in &full.repos {
        for (digest, media_type) in &rs.media_types {
            if !tagged.contains(&(repo.as_ref(), digest.as_str())) {
                sink(MetaOp::PutManifest {
                    repo: repo.to_string(),
                    digest: digest.clone(),
                    media_type: media_type.to_string(),
                    tag: None,
                    references: Vec::new(),
                    referrer: None,
                })?;
            }
        }
    }
    for (repo, rs) in &full.repos {
        for (blob, manifests) in &rs.backrefs {
            for m in manifests {
                sink(MetaOp::PutBackrefs {
                    repo: repo.to_string(),
                    manifest: m.clone(),
                    blobs: vec![blob.clone()],
                })?;
            }
        }
    }
    for (repo, rs) in &full.repos {
        for (subject, refs) in &rs.referrers {
            for (referrer, (_, descriptor)) in &refs.by_digest {
                sink(MetaOp::PutReferrer {
                    repo: repo.to_string(),
                    subject: subject.clone(),
                    referrer: referrer.clone(),
                    descriptor: descriptor.clone(),
                })?;
            }
        }
    }
    for (repo, rs) in &full.repos {
        for (digest, ck) in &rs.checksums {
            sink(MetaOp::PutChecksum {
                repo: repo.to_string(),
                digest: digest.clone(),
                crc32c: ck.crc32c,
                size: ck.size,
            })?;
        }
    }
    Ok(())
}

// ============================================================================
// Log framing: encode, replay, compatibility checking
// ============================================================================

/// Encode a MetaOp as a framed record.
pub(crate) fn encode_record(op: &MetaOp, hmac_key: Option<&HmacKey>) -> Vec<u8> {
    let payload = serialize_op(op);
    encode_record_raw(&payload, hmac_key)
}

/// Encode raw payload bytes as a framed record.
pub(crate) fn encode_record_raw(payload: &[u8], hmac_key: Option<&HmacKey>) -> Vec<u8> {
    let crc = crc32c::crc32c(payload);
    let hmac_tag = hmac_key.map(|k| k.tag(payload));
    let total = 8 + payload.len() + if hmac_tag.is_some() { 32 } else { 0 };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(payload);
    if let Some(tag) = hmac_tag {
        out.extend_from_slice(&tag);
    }
    out
}

/// Backwards-compat: internal callers still use `encode` / `encode_raw`.
fn encode(op: &MetaOp, hmac_key: Option<&HmacKey>) -> Vec<u8> {
    encode_record(op, hmac_key)
}
fn encode_raw(payload: &[u8], hmac_key: Option<&HmacKey>) -> Vec<u8> {
    encode_record_raw(payload, hmac_key)
}

/// Result of checking the first record of a log for framing compatibility.
enum LogFramingCheck {
    Compatible,
    Incompatible,
    NoHeader,
}

fn check_log_framing(
    bytes: &[u8],
    expected: FramingMode,
    hmac_key: Option<&HmacKey>,
) -> LogFramingCheck {
    if bytes.len() < 8 {
        return LogFramingCheck::NoHeader;
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let crc = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let payload_end = 8 + len;
    if payload_end > bytes.len() {
        return LogFramingCheck::NoHeader;
    }
    let payload = &bytes[8..payload_end];
    if crc32c::crc32c(payload) != crc {
        return LogFramingCheck::NoHeader;
    }
    match decode_header(payload) {
        Some(mode) if mode == expected => {
            if let Some(key) = hmac_key {
                let hmac_start = payload_end;
                let hmac_end = hmac_start + 32;
                if hmac_end > bytes.len() {
                    return LogFramingCheck::Incompatible;
                }
                let tag: [u8; 32] = bytes[hmac_start..hmac_end].try_into().expect("32 bytes");
                if !key.verify(payload, &tag) {
                    return LogFramingCheck::Incompatible;
                }
            }
            LogFramingCheck::Compatible
        }
        Some(_) => LogFramingCheck::Incompatible,
        None => LogFramingCheck::NoHeader,
    }
}

fn generation_marker(payload: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    if v.get("op")?.as_str()? != "gen" {
        return None;
    }
    v.get("gen")?.as_u64()
}

/// Replay a WAL-header log into `state`; record the generation marker if found.
fn replay_log(bytes: &[u8], state: &mut State, hmac_key: Option<&HmacKey>, generation: &mut u64) {
    let mut pos = 0usize;
    let hmac_extra = if hmac_key.is_some() { 32 } else { 0 };
    let mut index = 0usize;

    while pos + 8 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let crc = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let payload_start = pos + 8;
        let payload_end = payload_start + len;
        let record_end = payload_end + hmac_extra;
        if record_end > bytes.len() {
            break; // truncated tail
        }
        let payload = &bytes[payload_start..payload_end];
        if crc32c::crc32c(payload) != crc {
            break; // corrupt record
        }
        if let Some(key) = hmac_key {
            let tag: [u8; 32] = bytes[payload_end..record_end].try_into().expect("32 bytes");
            if !key.verify(payload, &tag) {
                break; // HMAC verification failed
            }
        }
        pos = record_end;
        index += 1;

        if index == 1 && decode_header(payload).is_some() {
            continue;
        }
        if index <= 2 {
            if let Some(g) = generation_marker(payload) {
                *generation = g;
                continue;
            }
        }

        if let Some(op) = deserialize_op(payload) {
            LogMetadataStore::apply_in_ram(state, &op);
        }
    }
}

fn replay_legacy(bytes: &[u8], state: &mut State) {
    let mut pos = 0usize;
    while pos + 8 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let crc = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        let start = pos + 8;
        let end = start + len;
        if end > bytes.len() {
            break;
        }
        let payload = &bytes[start..end];
        if crc32c::crc32c(payload) != crc {
            break;
        }
        if let Some(op) = deserialize_op(payload) {
            LogMetadataStore::apply_in_ram(state, &op);
        }
        pos = end;
    }
}

fn serialize_op(op: &MetaOp) -> Vec<u8> {
    let v = match op {
        MetaOp::PutManifest {
            repo,
            digest,
            media_type,
            tag,
            references,
            referrer,
        } => {
            let mut v = serde_json::json!({
                "op": "put_manifest",
                "repo": repo,
                "digest": digest,
                "media_type": media_type,
                "tag": tag,
            });
            if !references.is_empty() {
                v["references"] = serde_json::json!(references);
            }
            if let Some((subject, descriptor)) = referrer {
                v["subject"] = serde_json::json!(subject);
                v["descriptor"] = serde_json::json!(String::from_utf8_lossy(descriptor));
            }
            v
        }
        MetaOp::DeleteManifest { repo, digest } => serde_json::json!({
            "op": "delete_manifest",
            "repo": repo,
            "digest": digest,
        }),
        MetaOp::PutReferrer {
            repo,
            subject,
            referrer,
            descriptor,
        } => serde_json::json!({
            "op": "put_referrer",
            "repo": repo,
            "subject": subject,
            "referrer": referrer,
            "descriptor": String::from_utf8_lossy(descriptor),
        }),
        MetaOp::PutBackrefs {
            repo,
            manifest,
            blobs,
        } => serde_json::json!({
            "op": "put_backrefs",
            "repo": repo,
            "manifest": manifest,
            "blobs": blobs,
        }),
        MetaOp::PutChecksum {
            repo,
            digest,
            crc32c,
            size,
        } => serde_json::json!({
            "op": "put_checksum",
            "repo": repo,
            "digest": digest,
            "crc32c": crc32c,
            "size": size,
        }),
        MetaOp::DeleteBlob { repo, digest } => serde_json::json!({
            "op": "delete_blob",
            "repo": repo,
            "digest": digest,
        }),
    };
    serde_json::to_vec(&v).expect("MetaOp serializes")
}

fn deserialize_op(payload: &[u8]) -> Option<MetaOp> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let strings = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    match v.get("op").and_then(|x| x.as_str())? {
        "put_manifest" => Some(MetaOp::PutManifest {
            repo: s("repo")?,
            digest: s("digest")?,
            media_type: s("media_type")?,
            tag: s("tag"),
            references: strings("references"),
            referrer: s("subject").zip(s("descriptor").map(String::into_bytes)),
        }),
        "delete_manifest" => Some(MetaOp::DeleteManifest {
            repo: s("repo")?,
            digest: s("digest")?,
        }),
        "put_referrer" => Some(MetaOp::PutReferrer {
            repo: s("repo")?,
            subject: s("subject")?,
            referrer: s("referrer")?,
            descriptor: s("descriptor")?.into_bytes(),
        }),
        "put_backrefs" => Some(MetaOp::PutBackrefs {
            repo: s("repo")?,
            manifest: s("manifest")?,
            blobs: strings("blobs"),
        }),
        "put_checksum" => Some(MetaOp::PutChecksum {
            repo: s("repo")?,
            digest: s("digest")?,
            crc32c: u32::try_from(v.get("crc32c")?.as_u64()?).ok()?,
            size: v.get("size")?.as_u64()?,
        }),
        "delete_blob" => Some(MetaOp::DeleteBlob {
            repo: s("repo")?,
            digest: s("digest")?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(repo: &str, digest: &str, tag: Option<&str>) -> MetaOp {
        MetaOp::PutManifest {
            repo: repo.into(),
            digest: digest.into(),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            tag: tag.map(str::to_string),
            references: Vec::new(),
            referrer: None,
        }
    }

    fn make_key(dir: &Path) -> PathBuf {
        let p = dir.join("hmac.key");
        std::fs::write(&p, [0xABu8; 64]).unwrap();
        p
    }

    fn hmac_cfg(key: PathBuf) -> MetadataConfig {
        MetadataConfig {
            hmac_key_file: Some(key),
            ..Default::default()
        }
    }

    fn raw_record(payload: &[u8], crc: Option<u32>, key: Option<&HmacKey>) -> Vec<u8> {
        let crc = crc.unwrap_or_else(|| crc32c::crc32c(payload));
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(payload);
        if let Some(k) = key {
            buf.extend_from_slice(&k.tag(payload));
        }
        buf
    }

    #[test]
    fn backrefs_apply_query_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = LogMetadataStore::open(dir.path()).unwrap();
            s.apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m".into(),
                blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
            })
            .unwrap();
            s.apply(MetaOp::PutBackrefs {
                repo: "r".into(),
                manifest: "sha256:m".into(),
                blobs: vec!["sha256:b1".into()],
            })
            .unwrap();
            assert_eq!(s.backrefs("r", "sha256:b1"), vec!["sha256:m".to_string()]);
            assert!(s.backrefs("r", "sha256:absent").is_empty());
        }
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(s2.backrefs("r", "sha256:b2"), vec!["sha256:m".to_string()]);
        s2.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:m".into(),
        })
        .unwrap();
        assert!(s2.backrefs("r", "sha256:b1").is_empty());
    }

    #[test]
    fn log_replays_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = LogMetadataStore::open(dir.path()).unwrap();
            s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
            s.apply(MetaOp::PutReferrer {
                repo: "r".into(),
                subject: "sha256:aa".into(),
                referrer: "sha256:rr".into(),
                descriptor: br#"{"digest":"sha256:rr"}"#.to_vec(),
            })
            .unwrap();
            s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
            s.apply(MetaOp::DeleteManifest {
                repo: "r".into(),
                digest: "sha256:bb".into(),
            })
            .unwrap();
        }
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s2.referrers_page("r", "sha256:aa", None, None, usize::MAX)
                .unwrap()
                .items
                .len(),
            1
        );
        assert_eq!(s2.resolve_tag("r", "v2"), None);
    }

    #[test]
    fn replay_stops_at_torn_tail_and_bad_crc() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);
        let log = dir.path().join("roci-meta.log");
        let good = std::fs::read(&log).unwrap();

        let mut torn = good.clone();
        torn.extend_from_slice(&(999u32).to_le_bytes());
        torn.extend_from_slice(&(0u32).to_le_bytes());
        torn.extend_from_slice(b"partial");
        std::fs::write(&log, &torn).unwrap();
        let s1 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s1.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "truncated trailing record"
        );
        drop(s1);

        let mut bad = good.clone();
        let payload = b"{\"op\":\"delete_manifest\",\"repo\":\"r\",\"digest\":\"sha256:aa\"}";
        bad.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bad.extend_from_slice(&(0xDEAD_BEEFu32).to_le_bytes());
        bad.extend_from_slice(payload);
        std::fs::write(&log, &bad).unwrap();
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "bad CRC"
        );

        let mut unknown = good.clone();
        let up = b"{\"op\":\"nope\"}";
        unknown.extend_from_slice(&(up.len() as u32).to_le_bytes());
        unknown.extend_from_slice(&crc32c::crc32c(up).to_le_bytes());
        unknown.extend_from_slice(up);
        unknown.extend_from_slice(&encode(&put("r", "sha256:bb", Some("v2")), None));
        std::fs::write(&log, &unknown).unwrap();
        let s3 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s3.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb"),
            "unknown op skipped"
        );
    }

    #[test]
    fn deserialize_rejects_malformed_payloads() {
        assert!(deserialize_op(b"not json").is_none());
        assert!(deserialize_op(b"{\"no_op_field\":1}").is_none());
    }

    #[test]
    fn group_commit_coalesces_syncs() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        let seq1 = s.append_record(&put("r", "sha256:aa", Some("v1"))).unwrap();
        let seq2 = s.append_record(&put("r", "sha256:bb", Some("v2"))).unwrap();
        assert_eq!((seq1, seq2), (1, 2));
        s.group_commit_through(seq2).unwrap();
        s.group_commit_through(seq1).unwrap();
        drop(s);
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
        assert_eq!(
            s2.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb")
        );
        s2.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc")
        );
    }

    #[test]
    fn compaction_preserves_all_queries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(put("r", "sha256:cc", None)).unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:aa".into(),
            referrer: "sha256:ref1".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:ref1"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:aa".into(),
            blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0x12345678,
            size: 1024,
        })
        .unwrap();

        let tags_before = s.tags_snapshot("r");
        let refs_before = s.referrers_snapshot("r");
        let backrefs_before = s.backrefs("r", "sha256:b1");
        let ck_before = s.checksum("r", "sha256:b1");
        let mt_before = s.manifest_media_type("r", "sha256:cc");
        let repos_before = s.repos();
        let manifests_before = s.manifests("r");

        s.maintain().unwrap();

        assert_eq!(
            s.tags_snapshot("r"),
            tags_before,
            "tags_snapshot after compact"
        );
        assert_eq!(
            s.referrers_snapshot("r"),
            refs_before,
            "referrers_snapshot after compact"
        );
        assert_eq!(
            s.backrefs("r", "sha256:b1"),
            backrefs_before,
            "backrefs after compact"
        );
        assert_eq!(
            s.checksum("r", "sha256:b1"),
            ck_before,
            "checksum after compact"
        );
        assert_eq!(
            s.manifest_media_type("r", "sha256:cc"),
            mt_before,
            "media_type after compact"
        );
        assert_eq!(s.repos(), repos_before, "repos after compact");
        assert_eq!(
            s.manifests("r"),
            manifests_before,
            "manifests after compact"
        );

        s.apply(put("r", "sha256:dd", Some("v3"))).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:dd"),
            "append after compact"
        );

        drop(s);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.tags_snapshot("r"), {
            let mut t = tags_before.clone();
            t.push((
                "v3".into(),
                "sha256:dd".into(),
                "application/vnd.oci.image.manifest.v1+json".into(),
            ));
            t.sort();
            t
        });
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "reopen after compact"
        );
    }

    #[test]
    fn torn_tail_after_compaction_handled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        drop(s);

        let log = dir.path().join("roci-meta.log");
        let mut data = std::fs::read(&log).unwrap();
        data.extend_from_slice(&(999u32).to_le_bytes());
        data.extend_from_slice(b"garbage");
        std::fs::write(&log, &data).unwrap();

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "v1 from compacted image"
        );
        assert_eq!(
            s2.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb"),
            "v2 from log tail"
        );
    }

    #[test]
    fn hmac_tampered_payload_stops_replay() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let cfg = hmac_cfg(key_path);
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        drop(s);

        let log = dir.path().join("roci-meta.log");
        let mut data = std::fs::read(&log).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&log, &data).unwrap();

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v2"), None);
    }

    #[test]
    fn hmac_wrong_key_moves_log_aside() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let cfg1 = hmac_cfg(key_path);
        let s = LogMetadataStore::open_with(dir.path(), &cfg1).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);

        let key2_path = dir.path().join("hmac2.key");
        std::fs::write(&key2_path, [0xCDu8; 64]).unwrap();
        let cfg2 = hmac_cfg(key2_path);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg2).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("untrusted"))
            .collect();
        assert!(!entries.is_empty(), "log should be moved aside");
    }

    #[test]
    fn hmac_unauthenticated_with_key_moves_aside() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);

        let key_path = make_key(dir.path());
        let cfg = hmac_cfg(key_path);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
    }

    #[test]
    fn hmac_key_too_short_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("short.key");
        std::fs::write(&key_path, [0u8; 31]).unwrap();
        let cfg = hmac_cfg(key_path);
        let err = LogMetadataStore::open_with(dir.path(), &cfg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
    #[test]
    fn subject_referrers_remove_cleans_type_index() {
        let mut sr = SubjectReferrers::default();
        sr.insert("sha256:r1", br#"{"artifactType":"sig"}"#);
        sr.insert("sha256:r2", br#"{"artifactType":"sig"}"#);
        assert_eq!(sr.by_type.get("sig").map(|s| s.len()), Some(2));
        sr.remove("sha256:r1");
        assert_eq!(
            sr.by_type.get("sig").map(|s| s.len()),
            Some(1),
            "pruned from set"
        );
        sr.remove("sha256:r2");
        assert!(!sr.by_type.contains_key("sig"), "type key deleted");
        sr.remove("sha256:r99");
    }

    #[test]
    fn legacy_log_replay_cases() {
        fn build_log(label: &str, p1: &[u8]) -> Vec<u8> {
            match label {
                "valid_legacy" => {
                    let mut bytes = raw_record(p1, None, None);
                    let p2 = serialize_op(&MetaOp::PutChecksum {
                        repo: "r".into(),
                        digest: "sha256:b1".into(),
                        crc32c: 0x1111,
                        size: 256,
                    });
                    bytes.extend_from_slice(&raw_record(&p2, None, None));
                    bytes
                }
                "truncated_tail" => {
                    let mut bytes = raw_record(p1, None, None);
                    bytes.extend_from_slice(&(9999u32).to_le_bytes());
                    bytes.extend_from_slice(&(0u32).to_le_bytes());
                    bytes.extend_from_slice(b"short");
                    bytes
                }
                "bad_crc_stops" => {
                    let mut bytes = raw_record(p1, None, None);
                    let p2 = serialize_op(&put("r", "sha256:bb", Some("v2")));
                    bytes.extend_from_slice(&raw_record(&p2, Some(0xDEAD_BEEF), None));
                    bytes
                }
                "no_hmac_legacy" => raw_record(p1, None, None),
                _ => unreachable!(),
            }
        }

        for label in [
            "valid_legacy",
            "truncated_tail",
            "bad_crc_stops",
            "no_hmac_legacy",
        ] {
            let p1 = serialize_op(&put("r", "sha256:aa", Some("v1")));
            let bytes = build_log(label, &p1);
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("roci-meta.log"), &bytes).unwrap();

            let s = LogMetadataStore::open(dir.path()).unwrap();
            assert_eq!(
                s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
                Some("sha256:aa"),
                "{label}"
            );
            if label == "valid_legacy" {
                assert_eq!(
                    s.checksum("r", "sha256:b1"),
                    Some(BlobChecksum {
                        crc32c: 0x1111,
                        size: 256,
                    }),
                    "{label}"
                );
            }
            if label == "bad_crc_stops" {
                assert_eq!(s.resolve_tag("r", "v2"), None, "{label}");
            }
        }
    }

    #[test]
    fn check_framing_noheader_cases() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("short_bytes", b"short".to_vec()),
            ("truncated_payload", {
                let mut buf = Vec::new();
                buf.extend_from_slice(&(999u32).to_le_bytes());
                buf.extend_from_slice(&(0u32).to_le_bytes());
                buf.extend_from_slice(b"x");
                buf
            }),
            ("bad_crc", {
                let payload = wal_hmac::encode_header(FramingMode::Plain);
                raw_record(&payload, Some(0xBAAD_F00D), None)
            }),
            ("non_header_payload", {
                let payload = b"not_a_header_record";
                raw_record(payload, None, None)
            }),
        ];
        for (label, buf) in &cases {
            assert!(
                matches!(
                    check_log_framing(buf, FramingMode::Plain, None),
                    LogFramingCheck::NoHeader
                ),
                "{label}"
            );
        }
    }

    #[test]
    fn check_framing_incompatible_cases() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let key = HmacKey::load(&key_path).unwrap();

        let cases: Vec<(&str, Vec<u8>, FramingMode, Option<&HmacKey>)> = vec![
            (
                "hmac_truncated_tag",
                {
                    let payload = wal_hmac::encode_header(FramingMode::HmacSha256);
                    raw_record(&payload, None, None) // no HMAC tag appended
                },
                FramingMode::HmacSha256,
                Some(&key),
            ),
            (
                "hmac_wrong_tag",
                {
                    let payload = wal_hmac::encode_header(FramingMode::HmacSha256);
                    let mut buf = raw_record(&payload, None, None);
                    buf.extend_from_slice(&[0xFFu8; 32]); // wrong HMAC
                    buf
                },
                FramingMode::HmacSha256,
                Some(&key),
            ),
            (
                "mode_mismatch",
                {
                    let payload = wal_hmac::encode_header(FramingMode::Plain);
                    raw_record(&payload, None, None)
                },
                FramingMode::HmacSha256,
                None,
            ),
        ];
        for (label, buf, mode, k) in &cases {
            assert!(
                matches!(
                    check_log_framing(buf, *mode, *k),
                    LogFramingCheck::Incompatible
                ),
                "{label}"
            );
        }
    }
    #[test]
    fn delete_blob_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xAAAA,
            size: 128,
        })
        .unwrap();
        assert!(s.checksum("r", "sha256:b1").is_some(), "before delete");
        s.apply(MetaOp::DeleteBlob {
            repo: "r".into(),
            digest: "sha256:b1".into(),
        })
        .unwrap();
        assert!(s.checksum("r", "sha256:b1").is_none(), "after delete");
        drop(s);
        let s2 = LogMetadataStore::open(dir.path()).unwrap();
        assert!(s2.checksum("r", "sha256:b1").is_none(), "after replay");
    }

    #[test]
    fn raw_record_with_hmac_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let key = HmacKey::load(&key_path).unwrap();

        let payload = b"test payload";
        let record = raw_record(payload, None, Some(&key));

        let expected_len = 4 + 4 + payload.len() + 32;
        assert_eq!(record.len(), expected_len, "should include HMAC tag");
    }

    #[test]
    fn compaction_install_log_with_parent_dir_sync() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = MetadataConfig {
            snapshot: false,
            compact_threshold_bytes: 1,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();

        s.maintain().unwrap();

        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "v1 after compaction"
        );
        assert_eq!(
            s.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb"),
            "v2 after compaction"
        );
    }

    #[test]
    fn leftover_snapshot_file_survives_open() {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("roci-meta.snapshot");
        std::fs::write(&snap, b"fake snapshot").unwrap();
        let store = LogMetadataStore::open(dir.path()).unwrap();
        assert!(snap.exists(), "snapshot file must not be deleted");
        drop(store);
    }
}
