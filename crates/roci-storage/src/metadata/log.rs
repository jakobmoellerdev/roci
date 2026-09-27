//! Default metadata engine: in-RAM maps mirrored to an append-only,
//! CRC32C-framed `roci-meta.log`. Supports compaction, rkyv mmap
//! snapshots, and WAL HMAC (SECURITY §Storage boundary).

use super::snapshot::{self, SnapshotState};
use super::wal_hmac::{self, decode_header, FramingMode, HmacKey};
use super::{after, take_page, BlobChecksum, MetaOp, MetadataStore, Page, Referrer};
use roci_config::MetadataConfig;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// In-RAM metadata maps mirrored to an append-only CRC32C-framed log.
pub struct LogMetadataStore {
    inner: Mutex<State>,
    appended: AtomicU64,
    sync: Mutex<SyncCoord>,
    log_path: PathBuf,
    snapshot_path: PathBuf,
    compact_threshold: u64,
    snapshot_enabled: bool,
    hmac_key: Option<HmacKey>,
    snap_base: Mutex<Option<snapshot::VerifiedSnapshot>>,
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

type RepoKey = (String, String);

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

/// Delta overlay when a snapshot base is present.
#[derive(Default)]
struct State {
    tags: HashMap<String, BTreeMap<String, (String, String)>>,
    media_types: HashMap<RepoKey, String>,
    referrers: HashMap<RepoKey, SubjectReferrers>,
    backrefs: HashMap<RepoKey, Vec<String>>,
    checksums: HashMap<RepoKey, BlobChecksum>,
    log: Option<std::fs::File>,
    deleted_digests: HashMap<String, BTreeSet<String>>,
    deleted_checksums: BTreeSet<RepoKey>,
}

impl State {
    fn add_backrefs(&mut self, repo: &str, manifest: &str, blobs: &[String]) {
        for blob in blobs {
            let set = self
                .backrefs
                .entry((repo.to_string(), blob.clone()))
                .or_default();
            if !set.iter().any(|m| m == manifest) {
                set.push(manifest.to_string());
            }
        }
    }

    fn add_referrer(&mut self, repo: &str, subject: &str, referrer: &str, descriptor: &[u8]) {
        self.referrers
            .entry((repo.to_string(), subject.to_string()))
            .or_default()
            .insert(referrer, descriptor);
    }

    fn is_digest_deleted(&self, repo: &str, digest: &str) -> bool {
        self.deleted_digests
            .get(repo)
            .is_some_and(|s| s.contains(digest))
    }

    /// Materialize full state from delta + snapshot base.
    fn materialize(&self, base: Option<&snapshot::VerifiedSnapshot>) -> State {
        if base.is_none() {
            return State {
                tags: self.tags.clone(),
                media_types: self.media_types.clone(),
                referrers: self.referrers.clone(),
                backrefs: self.backrefs.clone(),
                checksums: self.checksums.clone(),
                log: None,
                deleted_digests: self.deleted_digests.clone(),
                deleted_checksums: self.deleted_checksums.clone(),
            };
        }
        let archived = base.unwrap().archived();
        let mut out = State::default();

        for entry in archived.tags.iter() {
            let repo: String = entry.repo.as_str().into();
            let deleted = self.deleted_digests.get(&repo);
            for tag_entry in entry.tags.iter() {
                let tag: String = tag_entry.tag.as_str().into();
                let digest: String = tag_entry.digest.as_str().into();
                let media: String = tag_entry.media_type.as_str().into();
                if deleted.is_some_and(|s| s.contains(&digest)) {
                    continue;
                }
                out.tags
                    .entry(repo.clone())
                    .or_default()
                    .insert(tag, (digest, media));
            }
        }
        for (repo, delta_tags) in &self.tags {
            let out_tags = out.tags.entry(repo.clone()).or_default();
            for (tag, val) in delta_tags {
                out_tags.insert(tag.clone(), val.clone());
            }
        }

        for entry in archived.media_types.iter() {
            let repo: String = entry.repo.as_str().into();
            let digest: String = entry.digest.as_str().into();
            let media: String = entry.media_type.as_str().into();
            let key = (repo, digest);
            if self.is_digest_deleted(&key.0, &key.1) {
                continue;
            }
            out.media_types.insert(key, media);
        }
        for (k, v) in &self.media_types {
            out.media_types.insert(k.clone(), v.clone());
        }

        for entry in archived.referrers.iter() {
            let repo: String = entry.repo.as_str().into();
            let subject: String = entry.subject.as_str().into();
            let key = (repo.clone(), subject);
            let deleted = self.deleted_digests.get(&repo);
            let out_refs = out.referrers.entry(key).or_default();
            for ref_entry in entry.referrers.iter() {
                let referrer: String = ref_entry.referrer_digest.as_str().into();
                if deleted.is_some_and(|s| s.contains(&referrer)) {
                    continue;
                }
                let descriptor: Vec<u8> = ref_entry.descriptor.as_slice().to_vec();
                out_refs.insert(&referrer, &descriptor);
            }
        }
        for (k, v) in &self.referrers {
            let out_refs = out.referrers.entry(k.clone()).or_default();
            for (d, (_, bytes)) in &v.by_digest {
                out_refs.insert(d, bytes);
            }
        }
        out.referrers.retain(|_, v| !v.by_digest.is_empty());

        for entry in archived.backrefs.iter() {
            let repo: String = entry.repo.as_str().into();
            let blob: String = entry.blob.as_str().into();
            let key = (repo.clone(), blob);
            let deleted = self.deleted_digests.get(&repo);
            let mut manifests: Vec<String> = entry
                .manifests
                .iter()
                .map(|s| s.as_str().to_string())
                .filter(|m| !deleted.is_some_and(|s| s.contains(m)))
                .collect();
            if let Some(delta) = self.backrefs.get(&key) {
                for m in delta {
                    if !manifests.contains(m) {
                        manifests.push(m.clone());
                    }
                }
            }
            if !manifests.is_empty() {
                out.backrefs.insert(key, manifests);
            }
        }
        for (k, v) in &self.backrefs {
            if !out.backrefs.contains_key(k) {
                out.backrefs.insert(k.clone(), v.clone());
            }
        }

        for entry in archived.checksums.iter() {
            let repo: String = entry.repo.as_str().into();
            let digest: String = entry.digest.as_str().into();
            let key = (repo, digest);
            if self.deleted_checksums.contains(&key) {
                continue;
            }
            if self.is_digest_deleted(&key.0, &key.1) {
                continue;
            }
            out.checksums.insert(
                key,
                BlobChecksum {
                    crc32c: entry.crc32c.into(),
                    size: entry.size.into(),
                },
            );
        }
        for (k, v) in &self.checksums {
            out.checksums.insert(k.clone(), *v);
        }

        out
    }
}

fn framing_mode(key: Option<&HmacKey>) -> FramingMode {
    if key.is_some() {
        FramingMode::HmacSha256
    } else {
        FramingMode::Plain
    }
}

fn discard_log(
    log_path: &Path,
    snapshot_path: &Path,
    snap_base: &mut Option<snapshot::VerifiedSnapshot>,
) {
    let _ = wal_hmac::move_aside(log_path);
    if snap_base.is_some() {
        *snap_base = None;
        let _ = std::fs::remove_file(snapshot_path);
    }
}

impl LogMetadataStore {
    /// Open with the `[storage.metadata]` policy.
    pub fn open_with(root: &Path, config: &MetadataConfig) -> io::Result<Self> {
        let hmac_key = config
            .hmac_key_file
            .as_ref()
            .map(|p| HmacKey::load(p))
            .transpose()?;
        Self::open_inner(
            root,
            config.compact_threshold_bytes,
            config.snapshot,
            hmac_key,
        )
    }

    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_inner(root, 0, false, None)
    }

    fn open_inner(
        root: &Path,
        compact_threshold: u64,
        snapshot_enabled: bool,
        hmac_key: Option<HmacKey>,
    ) -> io::Result<Self> {
        let log_path = root.join("roci-meta.log");
        let snapshot_path = root.join("roci-meta.snapshot");
        let mut state = State::default();
        let mut generation = 0u64;
        let mut covered: Option<(u64, u64)> = None;
        let mut snap_base: Option<snapshot::VerifiedSnapshot> = None;

        if snapshot_enabled {
            match snapshot::VerifiedSnapshot::open(&snapshot_path, hmac_key.as_ref()) {
                Ok(Some(verified)) => {
                    let archived = verified.archived();
                    generation = archived.generation.into();
                    covered = Some((generation, archived.log_offset.into()));
                    snap_base = Some(verified);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "discarding invalid snapshot; falling back to log replay"
                    );
                    let _ = std::fs::remove_file(&snapshot_path);
                }
            }
        }

        if let Ok(bytes) = std::fs::read(&log_path) {
            if !bytes.is_empty() {
                let expected_mode = framing_mode(hmac_key.as_ref());
                match check_log_framing(&bytes, expected_mode, hmac_key.as_ref()) {
                    LogFramingCheck::Compatible => {
                        replay_log(&bytes, &mut state, hmac_key.as_ref(), covered);
                    }
                    LogFramingCheck::Incompatible => {
                        tracing::warn!(
                            "WAL framing/key mismatch; moving log aside and starting fresh"
                        );
                        discard_log(&log_path, &snapshot_path, &mut snap_base);
                    }
                    LogFramingCheck::NoHeader => {
                        if hmac_key.is_some() {
                            tracing::warn!(
                                "unauthenticated log found with HMAC key configured; \
                                 moving log aside"
                            );
                            discard_log(&log_path, &snapshot_path, &mut snap_base);
                        } else {
                            replay_legacy(&bytes, &mut state);
                        }
                    }
                }
            }
        }

        Ok(Self {
            inner: Mutex::new(state),
            appended: AtomicU64::new(0),
            sync: Mutex::new(SyncCoord::default()),
            log_path,
            snapshot_path,
            compact_threshold,
            snapshot_enabled,
            hmac_key,
            snap_base: Mutex::new(snap_base),
            generation: Mutex::new(generation),
            image_len: AtomicU64::new(covered.map_or(0, |(_, offset)| offset)),
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
                state
                    .media_types
                    .insert((repo.clone(), digest.clone()), media_type.clone());
                if let Some(tag) = tag {
                    state
                        .tags
                        .entry(repo.clone())
                        .or_default()
                        .insert(tag.clone(), (digest.clone(), media_type.clone()));
                }
                state.add_backrefs(repo, digest, references);
                if let Some((subject, descriptor)) = referrer {
                    state.add_referrer(repo, subject, digest, descriptor);
                }
            }
            MetaOp::DeleteManifest { repo, digest } => {
                state.checksums.remove(&(repo.clone(), digest.clone()));
                state
                    .deleted_checksums
                    .insert((repo.clone(), digest.clone()));
                state.media_types.remove(&(repo.clone(), digest.clone()));
                state
                    .deleted_digests
                    .entry(repo.clone())
                    .or_default()
                    .insert(digest.clone());
                if let Some(tags) = state.tags.get_mut(repo) {
                    tags.retain(|_, (d, _)| d != digest);
                    if tags.is_empty() {
                        state.tags.remove(repo);
                    }
                }
                state.referrers.retain(|(r, _), refs| {
                    if r == repo {
                        refs.remove(digest);
                    }
                    !refs.by_digest.is_empty()
                });
                state.backrefs.retain(|(r, _), manifests| {
                    if r == repo {
                        manifests.retain(|m| m != digest);
                    }
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
                let key = (repo.clone(), digest.clone());
                state.deleted_checksums.remove(&key);
                state.checksums.insert(
                    key,
                    BlobChecksum {
                        crc32c: *crc32c,
                        size: *size,
                    },
                );
            }
            MetaOp::DeleteBlob { repo, digest } => {
                let key = (repo.clone(), digest.clone());
                state.checksums.remove(&key);
                state.deleted_checksums.insert(key);
            }
        }
    }
}

impl MetadataStore for LogMetadataStore {
    fn resolve_tag(&self, repo: &str, tag: &str) -> Option<(String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        if let Some(tags) = state.tags.get(repo) {
            if let Some(v) = tags.get(tag) {
                return Some(v.clone());
            }
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a.tags.binary_search_by(|e| e.repo.as_str().cmp(repo)) {
                for entry in a.tags[idx].tags.iter() {
                    if entry.tag.as_str() == tag {
                        let digest: String = entry.digest.as_str().into();
                        if state.is_digest_deleted(repo, &digest) {
                            return None;
                        }
                        return Some((digest, entry.media_type.as_str().into()));
                    }
                }
            }
        }
        None
    }

    fn manifest_media_type(&self, repo: &str, digest: &str) -> Option<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        if let Some(v) = state
            .media_types
            .get(&(repo.to_string(), digest.to_string()))
        {
            return Some(v.clone());
        }
        if state.is_digest_deleted(repo, digest) {
            return None;
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .media_types
                .binary_search_by(|e| (e.repo.as_str(), e.digest.as_str()).cmp(&(repo, digest)))
            {
                return Some(a.media_types[idx].media_type.as_str().into());
            }
        }
        None
    }

    fn tags_page(&self, repo: &str, last: Option<&str>, limit: usize) -> Option<Page<String>> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");

        if base.is_none() {
            let tags = state.tags.get(repo)?;
            return Some(take_page(
                tags.range::<str, _>(after(last)).map(|(t, _)| t.clone()),
                limit,
            ));
        }

        let a = base.as_ref().unwrap().archived();
        let delta_tags = state.tags.get(repo);
        let base_repo = a
            .tags
            .binary_search_by(|e| e.repo.as_str().cmp(repo))
            .ok()
            .map(|i| &a.tags[i].tags);

        if delta_tags.is_none() && base_repo.is_none() {
            return None;
        }

        let mut merged = BTreeMap::new();
        if let Some(base_tags) = base_repo {
            for entry in base_tags.iter() {
                let tag: String = entry.tag.as_str().into();
                let digest: String = entry.digest.as_str().into();
                if !state.is_digest_deleted(repo, &digest) {
                    merged.insert(tag, ());
                }
            }
        }
        if let Some(dt) = delta_tags {
            for t in dt.keys() {
                merged.insert(t.clone(), ());
            }
        }

        if merged.is_empty() {
            return None;
        }

        Some(take_page(
            merged.range::<str, _>(after(last)).map(|(t, _)| t.clone()),
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
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let key = (repo.to_string(), subject.to_string());

        if base.is_none() {
            let refs = state.referrers.get(&key)?;
            return Some(refs.page(artifact_type, last, limit));
        }

        let a = base.as_ref().unwrap().archived();
        let base_refs = a
            .referrers
            .binary_search_by(|e| (e.repo.as_str(), e.subject.as_str()).cmp(&(repo, subject)))
            .ok()
            .map(|i| &a.referrers[i].referrers);
        let delta_refs = state.referrers.get(&key);

        if base_refs.is_none() && delta_refs.is_none() {
            return None;
        }

        let mut merged = SubjectReferrers::default();
        if let Some(br) = base_refs {
            for entry in br.iter() {
                let referrer: String = entry.referrer_digest.as_str().into();
                if state.is_digest_deleted(repo, &referrer) {
                    continue;
                }
                let descriptor: Vec<u8> = entry.descriptor.as_slice().to_vec();
                merged.insert(&referrer, &descriptor);
            }
        }
        if let Some(dr) = delta_refs {
            for (d, (_, bytes)) in &dr.by_digest {
                merged.insert(d, bytes);
            }
        }

        if merged.by_digest.is_empty() {
            return None;
        }

        Some(merged.page(artifact_type, last, limit))
    }

    fn has_referrer(&self, repo: &str, subject: &str, referrer: &str) -> bool {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let key = (repo.to_string(), subject.to_string());
        if let Some(refs) = state.referrers.get(&key) {
            if refs.by_digest.contains_key(referrer) {
                return true;
            }
        }
        if state.is_digest_deleted(repo, referrer) {
            return false;
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .referrers
                .binary_search_by(|e| (e.repo.as_str(), e.subject.as_str()).cmp(&(repo, subject)))
            {
                return a.referrers[idx]
                    .referrers
                    .binary_search_by(|e| e.referrer_digest.as_str().cmp(referrer))
                    .is_ok();
            }
        }
        false
    }

    fn backrefs(&self, repo: &str, blob: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let key = (repo.to_string(), blob.to_string());
        let base = self.snap_base.lock().expect("snap lock poisoned");

        let mut result: Vec<String> = Vec::new();

        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .backrefs
                .binary_search_by(|e| (e.repo.as_str(), e.blob.as_str()).cmp(&(repo, blob)))
            {
                for m in a.backrefs[idx].manifests.iter() {
                    let ms: String = m.as_str().into();
                    if !state.is_digest_deleted(repo, &ms) {
                        result.push(ms);
                    }
                }
            }
        }

        if let Some(delta) = state.backrefs.get(&key) {
            for m in delta {
                if !result.contains(m) {
                    result.push(m.clone());
                }
            }
        }

        result
    }

    fn checksum(&self, repo: &str, digest: &str) -> Option<BlobChecksum> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let key = (repo.to_string(), digest.to_string());
        if let Some(v) = state.checksums.get(&key) {
            return Some(*v);
        }
        if state.deleted_checksums.contains(&key) || state.is_digest_deleted(repo, digest) {
            return None;
        }
        let base = self.snap_base.lock().expect("snap lock poisoned");
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a
                .checksums
                .binary_search_by(|e| (e.repo.as_str(), e.digest.as_str()).cmp(&(repo, digest)))
            {
                return Some(BlobChecksum {
                    crc32c: a.checksums[idx].crc32c.into(),
                    size: a.checksums[idx].size.into(),
                });
            }
        }
        None
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
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let mut repos: BTreeSet<String> = state
            .media_types
            .keys()
            .chain(state.referrers.keys())
            .map(|(r, _)| r.clone())
            .collect();
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            for entry in a.media_types.iter() {
                let repo: String = entry.repo.as_str().into();
                let digest: String = entry.digest.as_str().into();
                if !state.is_digest_deleted(&repo, &digest) {
                    repos.insert(repo);
                }
            }
            for entry in a.referrers.iter() {
                let repo: String = entry.repo.as_str().into();
                let has_live = entry
                    .referrers
                    .iter()
                    .any(|r| !state.is_digest_deleted(&repo, r.referrer_digest.as_str()));
                if has_live {
                    repos.insert(repo);
                }
            }
        }
        repos.into_iter().collect()
    }

    fn manifests(&self, repo: &str) -> Vec<String> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let mut result: Vec<String> = state
            .media_types
            .keys()
            .filter(|(r, _)| r == repo)
            .map(|(_, d)| d.clone())
            .collect();
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            for entry in a.media_types.iter() {
                if entry.repo.as_str() == repo {
                    let digest: String = entry.digest.as_str().into();
                    if !state.is_digest_deleted(repo, &digest) && !result.contains(&digest) {
                        result.push(digest);
                    }
                }
            }
        }
        result
    }

    fn tags_snapshot(&self, repo: &str) -> Vec<(String, String, String)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");

        let mut merged: BTreeMap<String, (String, String)> = BTreeMap::new();
        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            if let Ok(idx) = a.tags.binary_search_by(|e| e.repo.as_str().cmp(repo)) {
                for entry in a.tags[idx].tags.iter() {
                    let digest: String = entry.digest.as_str().into();
                    if !state.is_digest_deleted(repo, &digest) {
                        merged.insert(
                            entry.tag.as_str().into(),
                            (digest, entry.media_type.as_str().into()),
                        );
                    }
                }
            }
        }
        if let Some(dt) = state.tags.get(repo) {
            for (t, v) in dt {
                merged.insert(t.clone(), v.clone());
            }
        }
        merged.into_iter().map(|(t, (d, m))| (t, d, m)).collect()
    }

    fn referrers_snapshot(&self, repo: &str) -> Vec<(String, Vec<Referrer>)> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");

        let mut by_subject: HashMap<String, SubjectReferrers> = HashMap::new();

        if let Some(snap) = base.as_ref() {
            let a = snap.archived();
            for entry in a.referrers.iter() {
                if entry.repo.as_str() != repo {
                    continue;
                }
                let subject: String = entry.subject.as_str().into();
                let sr = by_subject.entry(subject).or_default();
                for ref_entry in entry.referrers.iter() {
                    let referrer: String = ref_entry.referrer_digest.as_str().into();
                    if !state.is_digest_deleted(repo, &referrer) {
                        let descriptor: Vec<u8> = ref_entry.descriptor.as_slice().to_vec();
                        sr.insert(&referrer, &descriptor);
                    }
                }
            }
        }

        for ((r, subject), refs) in &state.referrers {
            if r != repo {
                continue;
            }
            let sr = by_subject.entry(subject.clone()).or_default();
            for (d, (_, bytes)) in &refs.by_digest {
                sr.insert(d, bytes);
            }
        }

        by_subject
            .into_iter()
            .filter(|(_, sr)| !sr.by_digest.is_empty())
            .map(|(subject, sr)| {
                let refs = sr
                    .by_digest
                    .into_iter()
                    .map(|(d, (_, bytes))| (d, bytes))
                    .collect();
                (subject, refs)
            })
            .collect()
    }

    fn export(&self, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
        let state = self.inner.lock().expect("metadata lock poisoned");
        let base = self.snap_base.lock().expect("snap lock poisoned");
        let full = state.materialize(base.as_ref());
        drop(base);
        drop(state);
        export_state(&full, sink)
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

    /// Compact the WAL and optionally cut a snapshot when growth exceeds the threshold.
    fn do_maintain(&self) -> io::Result<()> {
        let log_size = std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let grown = log_size.saturating_sub(self.image_len.load(Ordering::Acquire));
        if self.compact_threshold == 0 || grown <= self.compact_threshold {
            return Ok(());
        }
        let mut state = self.inner.lock().expect("metadata lock poisoned");
        let mut base = self.snap_base.lock().expect("snap lock poisoned");
        let full = state.materialize(base.as_ref());
        if self.snapshot_enabled {
            let mut gen = self.generation.lock().expect("gen lock poisoned");
            let next = *gen + 1;
            let (tmp, covered) = self.write_log_image(&full, Some(next))?;
            let snap_state = state_to_snapshot(&full, next, covered);
            let body = rkyv::to_bytes::<rkyv::rancor::Error>(&snap_state)
                .map_err(|e| io::Error::other(format!("rkyv: {e}")))?;
            let hdr = snapshot::encode_header(&body, self.hmac_key.as_ref());
            snapshot::write_atomic(&self.snapshot_path, &hdr, &body)?;
            self.install_log(&mut state, &tmp)?;
            self.image_len.store(covered, Ordering::Release);
            *base = snapshot::VerifiedSnapshot::open(&self.snapshot_path, self.hmac_key.as_ref())?;
            *gen = next;
            state.tags.clear();
            state.media_types.clear();
            state.referrers.clear();
            state.backrefs.clear();
            state.checksums.clear();
            state.deleted_digests.clear();
            state.deleted_checksums.clear();
            roci_telemetry::record_meta_compaction("ok");
            roci_telemetry::record_meta_snapshot("ok");
        } else {
            let (tmp, len) = self.write_log_image(&full, None)?;
            self.install_log(&mut state, &tmp)?;
            self.image_len.store(len, Ordering::Release);
            roci_telemetry::record_meta_compaction("ok");
        }
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
        for (repo, tags) in &full.tags {
            for (tag, (digest, media_type)) in tags {
                f.write_all(&encode(
                    &MetaOp::PutManifest {
                        repo: repo.clone(),
                        digest: digest.clone(),
                        media_type: media_type.clone(),
                        tag: Some(tag.clone()),
                        references: Vec::new(),
                        referrer: None,
                    },
                    key,
                ))?;
                tagged.insert((repo, digest));
            }
        }
        for ((repo, digest), media_type) in &full.media_types {
            if !tagged.contains(&(repo.as_str(), digest.as_str())) {
                f.write_all(&encode(
                    &MetaOp::PutManifest {
                        repo: repo.clone(),
                        digest: digest.clone(),
                        media_type: media_type.clone(),
                        tag: None,
                        references: Vec::new(),
                        referrer: None,
                    },
                    key,
                ))?;
            }
        }
        for ((repo, blob), manifests) in &full.backrefs {
            for m in manifests {
                f.write_all(&encode(
                    &MetaOp::PutBackrefs {
                        repo: repo.clone(),
                        manifest: m.clone(),
                        blobs: vec![blob.clone()],
                    },
                    key,
                ))?;
            }
        }
        for ((repo, subject), refs) in &full.referrers {
            for (referrer, (_, descriptor)) in &refs.by_digest {
                f.write_all(&encode(
                    &MetaOp::PutReferrer {
                        repo: repo.clone(),
                        subject: subject.clone(),
                        referrer: referrer.clone(),
                        descriptor: descriptor.clone(),
                    },
                    key,
                ))?;
            }
        }
        for ((repo, digest), ck) in &full.checksums {
            f.write_all(&encode(
                &MetaOp::PutChecksum {
                    repo: repo.clone(),
                    digest: digest.clone(),
                    crc32c: ck.crc32c,
                    size: ck.size,
                },
                key,
            ))?;
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

fn state_to_snapshot(state: &State, generation: u64, log_offset: u64) -> SnapshotState {
    use snapshot::*;

    let mut tags: Vec<RepoTags> = state
        .tags
        .iter()
        .map(|(repo, btree)| RepoTags {
            repo: repo.clone(),
            tags: btree
                .iter()
                .map(|(tag, (digest, media))| TagEntry {
                    tag: tag.clone(),
                    digest: digest.clone(),
                    media_type: media.clone(),
                })
                .collect(),
        })
        .collect();
    tags.sort_by(|a, b| a.repo.cmp(&b.repo));

    let mut media_types: Vec<MediaTypeEntry> = state
        .media_types
        .iter()
        .map(|((r, d), m)| MediaTypeEntry {
            repo: r.clone(),
            digest: d.clone(),
            media_type: m.clone(),
        })
        .collect();
    media_types.sort_by(|a, b| (&a.repo, &a.digest).cmp(&(&b.repo, &b.digest)));

    let mut referrers: Vec<SubjectReferrers> = state
        .referrers
        .iter()
        .map(|((repo, subject), sr)| {
            let mut entries: Vec<ReferrerEntry> = sr
                .by_digest
                .iter()
                .map(|(d, (at, bytes))| ReferrerEntry {
                    referrer_digest: d.clone(),
                    artifact_type: at.clone().unwrap_or_default(),
                    descriptor: bytes.clone(),
                })
                .collect();
            entries.sort_by(|a, b| a.referrer_digest.cmp(&b.referrer_digest));
            snapshot::SubjectReferrers {
                repo: repo.clone(),
                subject: subject.clone(),
                referrers: entries,
            }
        })
        .collect();
    referrers.sort_by(|a, b| (&a.repo, &a.subject).cmp(&(&b.repo, &b.subject)));

    let mut backrefs: Vec<BackrefEntry> = state
        .backrefs
        .iter()
        .map(|((r, b), ms)| BackrefEntry {
            repo: r.clone(),
            blob: b.clone(),
            manifests: ms.clone(),
        })
        .collect();
    backrefs.sort_by(|a, b| (&a.repo, &a.blob).cmp(&(&b.repo, &b.blob)));

    let mut checksums: Vec<ChecksumEntry> = state
        .checksums
        .iter()
        .map(|((r, d), ck)| ChecksumEntry {
            repo: r.clone(),
            digest: d.clone(),
            crc32c: ck.crc32c,
            size: ck.size,
        })
        .collect();
    checksums.sort_by(|a, b| (&a.repo, &a.digest).cmp(&(&b.repo, &b.digest)));

    SnapshotState {
        tags,
        media_types,
        referrers,
        backrefs,
        checksums,
        generation,
        log_offset,
    }
}

/// Emit the minimal `MetaOp` image reproducing `state` — reuses the same
/// iteration order as `write_log_image` (compaction): one PutManifest per tag,
/// one PutManifest per untagged manifest, one PutBackrefs per edge, one
/// PutReferrer per referrer, one PutChecksum per checksum.
fn export_state(full: &State, sink: &mut dyn FnMut(MetaOp) -> io::Result<()>) -> io::Result<()> {
    use std::collections::BTreeSet;
    let mut tagged: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (repo, tags) in &full.tags {
        for (tag, (digest, media_type)) in tags {
            sink(MetaOp::PutManifest {
                repo: repo.clone(),
                digest: digest.clone(),
                media_type: media_type.clone(),
                tag: Some(tag.clone()),
                references: Vec::new(),
                referrer: None,
            })?;
            tagged.insert((repo, digest));
        }
    }
    for ((repo, digest), media_type) in &full.media_types {
        if !tagged.contains(&(repo.as_str(), digest.as_str())) {
            sink(MetaOp::PutManifest {
                repo: repo.clone(),
                digest: digest.clone(),
                media_type: media_type.clone(),
                tag: None,
                references: Vec::new(),
                referrer: None,
            })?;
        }
    }
    for ((repo, blob), manifests) in &full.backrefs {
        for m in manifests {
            sink(MetaOp::PutBackrefs {
                repo: repo.clone(),
                manifest: m.clone(),
                blobs: vec![blob.clone()],
            })?;
        }
    }
    for ((repo, subject), refs) in &full.referrers {
        for (referrer, (_, descriptor)) in &refs.by_digest {
            sink(MetaOp::PutReferrer {
                repo: repo.clone(),
                subject: subject.clone(),
                referrer: referrer.clone(),
                descriptor: descriptor.clone(),
            })?;
        }
    }
    for ((repo, digest), ck) in &full.checksums {
        sink(MetaOp::PutChecksum {
            repo: repo.clone(),
            digest: digest.clone(),
            crc32c: ck.crc32c,
            size: ck.size,
        })?;
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

/// Replay a WAL-header log; with a snapshot, skip covered records.
fn replay_log(
    bytes: &[u8],
    state: &mut State,
    hmac_key: Option<&HmacKey>,
    covered: Option<(u64, u64)>,
) {
    let mut pos = 0usize;
    let hmac_extra = if hmac_key.is_some() { 32 } else { 0 };
    let mut index = 0usize;
    let mut log_generation = 0u64;

    while pos + 8 <= bytes.len() {
        let record_start = pos;
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
                log_generation = g;
                continue;
            }
        }
        if let Some((snap_generation, offset)) = covered {
            if log_generation != snap_generation {
                return;
            }
            if (record_start as u64) < offset {
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

    fn snapshot_cfg() -> MetadataConfig {
        MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: 1,
            ..Default::default()
        }
    }

    fn hmac_cfg(key: PathBuf) -> MetadataConfig {
        MetadataConfig {
            hmac_key_file: Some(key),
            ..Default::default()
        }
    }

    fn seed_base(s: &LogMetadataStore) {
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xABCD,
            size: 512,
        })
        .unwrap();
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
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
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
            "v1 from snapshot"
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
    fn snapshot_reopen_identical_queries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        seed_base(&s);

        let tags_before = s.tags_snapshot("r");
        let refs_before = s.referrers_page("r", "sha256:aa", None, None, usize::MAX);
        let ck_before = s.checksum("r", "sha256:b1");
        let br_before = s.backrefs("r", "sha256:b1");

        s.maintain().unwrap();
        drop(s);

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.tags_snapshot("r"), tags_before, "tags");
        assert_eq!(
            s2.referrers_page("r", "sha256:aa", None, None, usize::MAX),
            refs_before,
            "referrers"
        );
        assert_eq!(s2.checksum("r", "sha256:b1"), ck_before, "checksum");
        assert_eq!(s2.backrefs("r", "sha256:b1"), br_before, "backrefs");
    }

    #[test]
    fn snapshot_delta_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.maintain().unwrap();

        s.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();

        assert_eq!(s.resolve_tag("r", "v1"), None, "v1 deleted");
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc"),
            "v3 added"
        );
        assert_eq!(s.manifest_media_type("r", "sha256:aa"), None, "aa deleted");

        s.apply(put("r", "sha256:aa", Some("v1-new"))).unwrap();
        assert_eq!(
            s.resolve_tag("r", "v1-new").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "re-add"
        );

        s.maintain().unwrap();
        drop(s);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None, "reopen v1 gone");
        assert_eq!(
            s2.resolve_tag("r", "v1-new").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "reopen v1-new"
        );
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc"),
            "reopen v3"
        );
    }

    #[test]
    fn snapshot_page_merge_across_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        s.maintain().unwrap();

        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(put("r", "sha256:dd", Some("v4"))).unwrap();

        let page = |last, limit| {
            let p = s.tags_page("r", last, limit).unwrap();
            (p.items, p.more)
        };
        let v = |ts: &[&str]| ts.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        assert_eq!(page(None, 2), (v(&["v1", "v2"]), true), "first page");
        assert_eq!(
            page(Some("v2"), 2),
            (v(&["v3", "v4"]), false),
            "second page"
        );
        assert_eq!(page(None, 4), (v(&["v1", "v2", "v3", "v4"]), false), "all");
    }

    #[test]
    fn snapshot_corrupted_byte_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        let snap_path = dir.path().join("roci-meta.snapshot");
        let mut data = std::fs::read(&snap_path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&snap_path, &data).unwrap();

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s2.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa")
        );
    }

    #[test]
    fn snapshot_wrong_hmac_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let mut cfg = snapshot_cfg();
        cfg.hmac_key_file = Some(key_path);
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        let key2_path = dir.path().join("hmac2.key");
        std::fs::write(&key2_path, [0xCDu8; 64]).unwrap();
        let mut cfg2 = snapshot_cfg();
        cfg2.hmac_key_file = Some(key2_path);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg2).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
    }

    #[test]
    fn snapshot_stale_log_tail_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        drop(s);

        let log_path = dir.path().join("roci-meta.log");
        let saved_log = std::fs::read(&log_path).unwrap();

        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s2.maintain().unwrap();
        drop(s2);

        std::fs::write(&log_path, &saved_log).unwrap();

        let s3 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s3.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "v1 from snapshot"
        );
        assert_eq!(
            s3.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb"),
            "v2 from snapshot gen 2"
        );
    }

    #[test]
    fn snapshot_is_cut_only_past_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = |threshold| MetadataConfig {
            snapshot: true,
            compact_threshold_bytes: threshold,
            ..Default::default()
        };
        let s = LogMetadataStore::open_with(dir.path(), &cfg(1 << 20)).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        assert!(
            !dir.path().join("roci-meta.snapshot").exists(),
            "below threshold"
        );
        drop(s);
        let s = LogMetadataStore::open_with(dir.path(), &cfg(1)).unwrap();
        s.maintain().unwrap();
        let first = std::fs::metadata(dir.path().join("roci-meta.snapshot")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.maintain().unwrap();
        let again = std::fs::metadata(dir.path().join("roci-meta.snapshot")).unwrap();
        assert_eq!(
            first.modified().unwrap(),
            again.modified().unwrap(),
            "no rewrite"
        );
        drop(s);
        let s = LogMetadataStore::open_with(dir.path(), &cfg(1)).unwrap();
        assert!(s.inner.lock().unwrap().tags.is_empty(), "heap delta empty");
        assert_eq!(
            s.resolve_tag("r", "v1").map(|(d, _)| d).as_deref(),
            Some("sha256:aa"),
            "from snapshot"
        );
    }

    #[test]
    fn snapshot_reopen_replays_only_the_tail_but_falls_back_to_the_image() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        for i in 0..20 {
            s.apply(put(
                "r",
                &format!("sha256:{i:02}"),
                Some(&format!("t{i:02}")),
            ))
            .unwrap();
        }
        s.maintain().unwrap();
        s.apply(put("r", "sha256:ff", Some("tail"))).unwrap();
        drop(s);
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s.inner.lock().unwrap().tags["r"].len(),
            1,
            "only tail in heap"
        );
        assert_eq!(
            s.tags_page("r", None, 100).unwrap().items.len(),
            21,
            "merged"
        );
        drop(s);
        std::fs::write(dir.path().join("roci-meta.snapshot"), b"garbage").unwrap();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(
            s.tags_page("r", None, 100).unwrap().items.len(),
            21,
            "fallback to log"
        );
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
    fn incompatible_framing_discards_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = make_key(dir.path());
        let mut cfg = snapshot_cfg();
        cfg.hmac_key_file = Some(key_path);
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.maintain().unwrap();
        drop(s);

        assert!(dir.path().join("roci-meta.snapshot").exists());

        let cfg2 = snapshot_cfg();
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg2).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
    }

    #[test]
    fn noheader_with_hmac_key_discards_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let s = LogMetadataStore::open(dir.path()).unwrap();
        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        drop(s);

        let snap_path = dir.path().join("roci-meta.snapshot");
        std::fs::write(&snap_path, b"dummy-snapshot").unwrap();

        let key_path = make_key(dir.path());
        let mut cfg = snapshot_cfg();
        cfg.hmac_key_file = Some(key_path);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None);
        assert!(!snap_path.exists(), "snapshot should be removed");
    }

    #[test]
    fn snapshot_base_delta_tags_and_media_types() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
        s.apply(put("r2", "sha256:cc", Some("latest"))).unwrap();
        s.maintain().unwrap();

        s.apply(put("r", "sha256:dd", Some("v3"))).unwrap();
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();

        assert_eq!(s.resolve_tag("r", "v1"), None, "deleted from base");
        assert_eq!(
            s.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb"),
            "from base"
        );
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:dd"),
            "from delta"
        );
        assert_eq!(s.resolve_tag("r", "v_missing"), None, "miss in base");

        assert_eq!(s.manifest_media_type("r", "sha256:aa"), None, "deleted");
        assert!(s.manifest_media_type("r", "sha256:bb").is_some(), "base");
        assert!(s.manifest_media_type("r", "sha256:dd").is_some(), "delta");
        assert_eq!(s.manifest_media_type("r", "sha256:zz"), None, "missing");

        let page = s.tags_page("r", None, usize::MAX).unwrap();
        assert_eq!(
            page.items,
            vec!["v2".to_string(), "v3".to_string()],
            "merged tags"
        );

        let p1 = s.tags_page("r", None, 1).unwrap();
        assert_eq!(p1.items, vec!["v2".to_string()], "paging p1");
        assert!(p1.more);
        let p2 = s.tags_page("r", Some("v2"), 1).unwrap();
        assert_eq!(p2.items, vec!["v3".to_string()], "paging p2");
        assert!(!p2.more);

        s.apply(MetaOp::DeleteManifest {
            repo: "r2".into(),
            digest: "sha256:cc".into(),
        })
        .unwrap();
        assert!(s.tags_page("r2", None, usize::MAX).is_none(), "r2 empty");
        assert!(
            s.tags_page("no_repo", None, usize::MAX).is_none(),
            "unknown repo"
        );

        let snap = s.tags_snapshot("r");
        assert_eq!(snap.len(), 2, "tags_snapshot count");
        assert!(snap.iter().any(|(t, _, _)| t == "v2"));
        assert!(snap.iter().any(|(t, _, _)| t == "v3"));

        let repos = s.repos();
        assert!(repos.contains(&"r".to_string()), "r present");
        assert!(!repos.contains(&"r2".to_string()), "r2 gone");

        let mf = s.manifests("r");
        assert!(!mf.contains(&"sha256:aa".to_string()), "aa tombstoned");
        assert!(mf.contains(&"sha256:bb".to_string()), "bb from base");
        assert!(mf.contains(&"sha256:dd".to_string()), "dd from delta");
    }

    #[test]
    fn snapshot_base_delta_referrers() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r1".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:r1"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r2".into(),
            descriptor: br#"{"artifactType":"sbom","digest":"sha256:r2"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s2".into(),
            referrer: "sha256:r3".into(),
            descriptor: br#"{"digest":"sha256:r3"}"#.to_vec(),
        })
        .unwrap();
        s.maintain().unwrap();

        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:r1".into(),
        })
        .unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r4".into(),
            descriptor: br#"{"artifactType":"sig","digest":"sha256:r4"}"#.to_vec(),
        })
        .unwrap();

        let page = s
            .referrers_page("r", "sha256:s", None, None, usize::MAX)
            .unwrap();
        let digests: Vec<_> = page.items.iter().map(|(d, _)| d.as_str()).collect();
        assert!(!digests.contains(&"sha256:r1"), "r1 tombstoned");
        assert!(digests.contains(&"sha256:r2"), "r2 from base");
        assert!(digests.contains(&"sha256:r4"), "r4 from delta");

        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:r3".into(),
        })
        .unwrap();
        assert!(
            s.referrers_page("r", "sha256:s2", None, None, usize::MAX)
                .is_none(),
            "s2 empty"
        );
        assert!(
            s.referrers_page("r", "sha256:none", None, None, usize::MAX)
                .is_none(),
            "no referrers"
        );

        assert!(!s.has_referrer("r", "sha256:s", "sha256:r1"), "tombstoned");
        assert!(s.has_referrer("r", "sha256:s", "sha256:r2"), "from base");
        assert!(s.has_referrer("r", "sha256:s", "sha256:r4"), "from delta");

        let rs = s.referrers_snapshot("r");
        let s_entry = rs.iter().find(|(sub, _)| sub == "sha256:s");
        assert!(s_entry.is_some(), "snapshot entry");
        let (_, refs) = s_entry.unwrap();
        assert_eq!(refs.len(), 2, "snapshot refs count");
    }

    #[test]
    fn snapshot_base_delta_backrefs() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:m1".into(),
            blobs: vec!["sha256:b1".into(), "sha256:b2".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:m2".into(),
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
        s.maintain().unwrap();

        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:m1".into(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:m3".into(),
            blobs: vec!["sha256:b1".into(), "sha256:b3".into()],
        })
        .unwrap();

        let br = s.backrefs("r", "sha256:b1");
        assert!(!br.contains(&"sha256:m1".to_string()), "m1 tombstoned");
        assert!(br.contains(&"sha256:m2".to_string()), "m2 from base");
        assert!(br.contains(&"sha256:m3".to_string()), "m3 from delta");

        assert!(s.backrefs("r", "sha256:b2").is_empty(), "b2 empty");
        assert_eq!(
            s.backrefs("r", "sha256:b3"),
            vec!["sha256:m3".to_string()],
            "b3 delta-only"
        );
    }

    #[test]
    fn snapshot_base_delta_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:c1".into(),
            crc32c: 0x1111,
            size: 100,
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:c2".into(),
            crc32c: 0x2222,
            size: 200,
        })
        .unwrap();
        s.maintain().unwrap();

        s.apply(MetaOp::DeleteBlob {
            repo: "r".into(),
            digest: "sha256:c1".into(),
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:c3".into(),
            crc32c: 0x3333,
            size: 300,
        })
        .unwrap();

        assert_eq!(s.checksum("r", "sha256:c1"), None, "c1 deleted");
        assert_eq!(
            s.checksum("r", "sha256:c2"),
            Some(BlobChecksum {
                crc32c: 0x2222,
                size: 200
            }),
            "c2 from base"
        );
        assert_eq!(
            s.checksum("r", "sha256:c3"),
            Some(BlobChecksum {
                crc32c: 0x3333,
                size: 300
            }),
            "c3 from delta"
        );
        assert_eq!(s.checksum("r", "sha256:c99"), None, "missing");
    }

    #[test]
    fn snapshot_materialize_full_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();

        s.apply(put("r", "sha256:aa", Some("v1"))).unwrap();
        s.apply(put("r", "sha256:bb", Some("v2"))).unwrap();
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
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b1".into(),
            crc32c: 0xABCD,
            size: 512,
        })
        .unwrap();
        s.maintain().unwrap();

        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:aa".into(),
        })
        .unwrap();
        s.apply(MetaOp::DeleteManifest {
            repo: "r".into(),
            digest: "sha256:ref1".into(),
        })
        .unwrap();
        s.apply(put("r", "sha256:cc", Some("v3"))).unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "r".into(),
            subject: "sha256:cc".into(),
            referrer: "sha256:ref2".into(),
            descriptor: br#"{"digest":"sha256:ref2"}"#.to_vec(),
        })
        .unwrap();
        s.apply(MetaOp::PutBackrefs {
            repo: "r".into(),
            manifest: "sha256:cc".into(),
            blobs: vec!["sha256:b1".into()],
        })
        .unwrap();
        s.apply(MetaOp::PutChecksum {
            repo: "r".into(),
            digest: "sha256:b2".into(),
            crc32c: 0x1234,
            size: 64,
        })
        .unwrap();

        s.maintain().unwrap();

        assert_eq!(s.resolve_tag("r", "v1"), None, "v1 gone");
        assert_eq!(
            s.resolve_tag("r", "v2").map(|(d, _)| d).as_deref(),
            Some("sha256:bb"),
            "v2 kept"
        );
        assert_eq!(
            s.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc"),
            "v3 added"
        );
        assert!(
            !s.has_referrer("r", "sha256:aa", "sha256:ref1"),
            "ref1 gone"
        );
        assert!(
            s.has_referrer("r", "sha256:cc", "sha256:ref2"),
            "ref2 present"
        );
        assert_eq!(
            s.backrefs("r", "sha256:b1"),
            vec!["sha256:cc".to_string()],
            "backrefs"
        );

        drop(s);
        let s2 = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        assert_eq!(s2.resolve_tag("r", "v1"), None, "reopen v1");
        assert_eq!(
            s2.resolve_tag("r", "v3").map(|(d, _)| d).as_deref(),
            Some("sha256:cc"),
            "reopen v3"
        );
        assert_eq!(
            s2.checksum("r", "sha256:b2"),
            Some(BlobChecksum {
                crc32c: 0x1234,
                size: 64
            }),
            "reopen checksum"
        );
    }

    #[test]
    fn snapshot_repos_from_base_with_referrers() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = snapshot_cfg();
        let s = LogMetadataStore::open_with(dir.path(), &cfg).unwrap();
        s.apply(MetaOp::PutReferrer {
            repo: "ref-only".into(),
            subject: "sha256:s".into(),
            referrer: "sha256:r1".into(),
            descriptor: br#"{"digest":"sha256:r1"}"#.to_vec(),
        })
        .unwrap();
        s.maintain().unwrap();

        let repos = s.repos();
        assert!(
            repos.contains(&"ref-only".to_string()),
            "ref-only from base referrers"
        );

        s.apply(MetaOp::DeleteManifest {
            repo: "ref-only".into(),
            digest: "sha256:r1".into(),
        })
        .unwrap();
        let repos2 = s.repos();
        assert!(
            !repos2.contains(&"ref-only".to_string()),
            "tombstoned referrer hides repo"
        );
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
}
