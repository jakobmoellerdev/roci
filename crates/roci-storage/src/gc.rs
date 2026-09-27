//! Online GC bookkeeping (ARCHITECTURE §Inline storage optimizations,
//! RESEARCH §8.3): candidate set of unreferenced blobs, each stamped,
//! plus an in-flight fence for safe concurrent sweeps.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub type BlobKey = (String, String);

#[derive(Debug)]
pub struct GcTracker {
    enabled: bool,
    delay: Duration,
    candidates: Mutex<HashMap<BlobKey, Instant>>,
    /// Shared by want-paths, exclusive for sweeps.
    fence: RwLock<()>,
    ready: AtomicBool,
    /// Root manifests immune to GC (from index.json / image-index children).
    roots: Mutex<HashSet<BlobKey>>,
    /// Repos with unreadable roots; sweeps skip them entirely.
    unsafe_repos: Mutex<HashSet<String>>,
}

impl GcTracker {
    pub fn new(enabled: bool, delay: Duration) -> Self {
        Self {
            enabled,
            delay,
            candidates: Mutex::default(),
            fence: RwLock::new(()),
            ready: AtomicBool::new(false),
            roots: Mutex::default(),
            unsafe_repos: Mutex::default(),
        }
    }

    pub fn disabled() -> Self {
        Self::new(false, Duration::ZERO)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Hold while depending on a blob's presence; `None` when GC is off.
    pub async fn pin(&self) -> Option<RwLockReadGuard<'_, ()>> {
        if self.enabled {
            Some(self.fence.read().await)
        } else {
            None
        }
    }

    /// Exclusive sweep fence: no want-path runs while held.
    pub async fn exclusive(&self) -> RwLockWriteGuard<'_, ()> {
        self.fence.write().await
    }

    pub fn mark(&self, repo: &str, digest: &str) {
        self.mark_at(repo, digest, Instant::now());
    }

    /// Stamp as candidate at `at` (deterministic startup seeding).
    pub fn mark_at(&self, repo: &str, digest: &str, at: Instant) {
        if self.enabled {
            self.lock()
                .insert((repo.to_string(), digest.to_string()), at);
        }
    }

    /// Refresh stamp if `(repo, digest)` is a candidate.
    pub fn touch(&self, repo: &str, digest: &str) {
        if self.enabled {
            if let Some(t) = self.lock().get_mut(&(repo.to_string(), digest.to_string())) {
                *t = Instant::now();
            }
        }
    }

    pub fn clear(&self, repo: &str, digest: &str) {
        if self.enabled {
            self.lock().remove(&(repo.to_string(), digest.to_string()));
        }
    }

    pub fn due(&self, now: Instant) -> Vec<BlobKey> {
        self.lock()
            .iter()
            .filter(|(_, t)| now.saturating_duration_since(**t) >= self.delay)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Re-check under [`GcTracker::exclusive`]: still due at `now`?
    pub fn is_due(&self, repo: &str, digest: &str, now: Instant) -> bool {
        self.lock()
            .get(&(repo.to_string(), digest.to_string()))
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.delay)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mark ready after startup consistency check.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.enabled && self.ready.load(Ordering::Acquire)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BlobKey, Instant>> {
        self.candidates.lock().expect("gc lock poisoned")
    }

    pub fn add_root(&self, repo: &str, digest: &str) {
        if self.enabled {
            self.roots
                .lock()
                .expect("gc roots lock poisoned")
                .insert((repo.to_string(), digest.to_string()));
        }
    }

    pub fn is_root(&self, repo: &str, digest: &str) -> bool {
        self.roots
            .lock()
            .expect("gc roots lock poisoned")
            .contains(&(repo.to_string(), digest.to_string()))
    }

    pub fn mark_unsafe(&self, repo: &str) {
        if self.enabled {
            self.unsafe_repos
                .lock()
                .expect("gc unsafe lock poisoned")
                .insert(repo.to_string());
        }
    }

    pub fn is_unsafe(&self, repo: &str) -> bool {
        self.unsafe_repos
            .lock()
            .expect("gc unsafe lock poisoned")
            .contains(repo)
    }

    #[cfg(test)]
    pub fn roots_len(&self) -> usize {
        self.roots.lock().expect("gc roots lock poisoned").len()
    }

    /// Candidate keys snapshot for fast-restart.
    pub fn candidate_keys(&self) -> Vec<(String, String)> {
        self.lock().keys().cloned().collect()
    }

    /// Root keys snapshot for fast-restart.
    pub fn root_keys(&self) -> Vec<(String, String)> {
        self.roots
            .lock()
            .expect("gc roots lock poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Unsafe repo names snapshot for fast-restart.
    pub fn unsafe_repo_names(&self) -> Vec<String> {
        self.unsafe_repos
            .lock()
            .expect("gc unsafe lock poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

/// Max bytes when reading a root manifest for GC consistency.
pub const MAX_ROOT_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Rebuild missing backref edges for one repo by walking a manifest worklist.
pub async fn rebuild_backrefs<F, Fut>(
    repo: &str,
    meta: &dyn crate::MetadataStore,
    gc: &GcTracker,
    roots: HashSet<String>,
    mut read_manifest: F,
) where
    F: FnMut(crate::Digest) -> Fut,
    Fut: Future<Output = std::io::Result<Option<Vec<u8>>>>,
{
    let mut to_visit: Vec<String> = roots.iter().cloned().collect();
    let mut all_roots: HashSet<String> = roots;

    while let Some(digest_str) = to_visit.pop() {
        let parsed = match crate::Digest::parse(&digest_str) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let bytes = match read_manifest(parsed).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                tracing::warn!(repo, digest = %digest_str, "root manifest missing from CAS; repo is GC-unsafe");
                gc.mark_unsafe(repo);
                continue;
            }
            Err(e) => {
                tracing::warn!(repo, digest = %digest_str, error = %e, "oversized or unreadable root manifest; repo is GC-unsafe");
                gc.mark_unsafe(repo);
                continue;
            }
        };
        let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(repo, digest = %digest_str, "unparseable root manifest; repo is GC-unsafe");
                gc.mark_unsafe(repo);
                continue;
            }
        };

        for child in crate::layout::index_manifests(&manifest) {
            if let Some(cd) = crate::layout::descriptor_digest(child) {
                if all_roots.insert(cd.to_string()) {
                    to_visit.push(cd.to_string());
                }
            }
        }

        let references: Vec<String> = crate::layout::manifest_references(&manifest)
            .iter()
            .map(crate::Digest::as_string)
            .collect();
        let missing: Vec<String> = references
            .iter()
            .filter(|blob| !meta.backrefs(repo, blob).contains(&digest_str))
            .cloned()
            .collect();
        if !missing.is_empty() {
            if let Err(e) = meta.apply(crate::MetaOp::PutBackrefs {
                repo: repo.to_string(),
                manifest: digest_str.clone(),
                blobs: missing,
            }) {
                tracing::warn!(repo, digest = %digest_str, error = %e, "recording backref edges failed");
            }
        }
    }

    for d in &all_roots {
        if meta.manifest_media_type(repo, d).is_none() {
            gc.add_root(repo, d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_become_due_after_the_delay_and_touch_restarts_it() {
        let gc = GcTracker::new(true, Duration::from_secs(60));
        gc.mark("r", "sha256:a");
        let now = Instant::now();
        assert!(gc.due(now).is_empty());
        assert!(!gc.is_due("r", "sha256:a", now));
        let later = now + Duration::from_secs(61);
        assert_eq!(gc.due(later), vec![("r".into(), "sha256:a".into())]);
        assert!(gc.is_due("r", "sha256:a", later));
        gc.touch("r", "sha256:a");
        assert!(!gc.is_due("r", "sha256:a", Instant::now()));
        gc.touch("r", "sha256:b");
        assert_eq!(gc.len(), 1);
        gc.clear("r", "sha256:a");
        assert!(gc.is_empty());
    }

    #[tokio::test]
    async fn disabled_tracker_is_inert() {
        let gc = GcTracker::disabled();
        gc.mark("r", "d");
        assert!(gc.is_empty());
        assert!(gc.pin().await.is_none());
        gc.set_ready();
        assert!(!gc.is_ready());
        gc.add_root("r", "d");
        assert_eq!(gc.roots_len(), 0); // disabled → no-op
        gc.mark_unsafe("r");
        assert!(!gc.is_unsafe("r")); // disabled → no-op
    }

    #[tokio::test]
    async fn exclusive_fence_waits_for_pins() {
        let gc = std::sync::Arc::new(GcTracker::new(true, Duration::ZERO));
        assert!(!gc.is_ready());
        gc.set_ready();
        assert!(gc.is_ready());
        let pin = gc.pin().await.expect("enabled");
        let g2 = gc.clone();
        let sweeper = tokio::spawn(async move {
            let _x = g2.exclusive().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!sweeper.is_finished(), "sweep must wait for the pin");
        drop(pin);
        sweeper.await.unwrap();
    }

    #[test]
    fn mark_at_allows_deterministic_timestamps() {
        let gc = GcTracker::new(true, Duration::from_secs(10));
        let base = Instant::now();
        gc.mark_at("r", "sha256:a", base);
        assert!(!gc.is_due("r", "sha256:a", base + Duration::from_secs(5)));
        assert!(gc.is_due("r", "sha256:a", base + Duration::from_secs(11)));
    }

    #[test]
    fn roots_and_unsafe_repos() {
        let gc = GcTracker::new(true, Duration::from_secs(60));
        assert!(!gc.is_root("r", "sha256:a"));
        gc.add_root("r", "sha256:a");
        assert!(gc.is_root("r", "sha256:a"));
        assert!(!gc.is_root("r", "sha256:b"));
        assert_eq!(gc.roots_len(), 1);

        assert!(!gc.is_unsafe("r"));
        gc.mark_unsafe("r");
        assert!(gc.is_unsafe("r"));
        assert!(!gc.is_unsafe("other"));
    }
}
