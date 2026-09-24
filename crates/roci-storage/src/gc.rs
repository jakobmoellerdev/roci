//! Online GC bookkeeping (ARCHITECTURE §Inline storage optimizations, RESEARCH
//! §8.3): the **candidate set** of blobs that are currently unreferenced, each
//! stamped with the last time something wanted it, plus the **fence** that
//! makes "is it still collectable?" and "delete it" atomic with respect to
//! every path that wants a blob.
//!
//! A blob becomes a candidate when it enters the CAS unreferenced (a pushed
//! layer before its manifest arrives) or when its backref set empties (its last
//! manifest was deleted); it stops being one when a manifest references it.
//! Work is **O(garbage)**: the set holds only unreferenced blobs, and a sweep
//! visits only candidates whose grace period (`delay`) has elapsed.
//!
//! **In-flight safety.** Every path that is about to depend on a blob — a
//! `HEAD`/existence check before a manifest push, a finalize/mount/put that
//! lands it — holds [`GcTracker::pin`] (a shared fence) while it refreshes the
//! blob's stamp. The sweeper takes the fence exclusively while it re-checks a
//! candidate and unlinks it, so a blob is never deleted between a client's
//! existence check and the manifest that references it (the Harbor in-flight
//! deletion class): the refreshed stamp keeps it out of the sweep for another
//! full `delay`, far longer than any push takes.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A `(repo, digest)` candidate key.
pub type BlobKey = (String, String);

#[derive(Debug)]
pub struct GcTracker {
    enabled: bool,
    delay: Duration,
    /// `(repo, digest) → last time the blob was wanted` for unreferenced blobs.
    candidates: Mutex<HashMap<BlobKey, Instant>>,
    /// Shared by want-paths, exclusive for a sweep's re-check + unlink.
    fence: RwLock<()>,
    /// Set once the startup consistency check (backref rebuild + candidate
    /// seeding) completed; sweeps are refused until then.
    ready: AtomicBool,
    /// Root manifest digests that are GC-immune: manifests known from the
    /// layout (`index.json` descriptors / image-index children) are roots
    /// regardless of whether the metadata store recorded them.
    roots: Mutex<HashSet<BlobKey>>,
    /// Repos whose root manifests are unreadable or unparseable: sweeps skip
    /// these entirely (a missing edge must never read as "unreferenced").
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

    /// A tracker that records nothing and never sweeps.
    pub fn disabled() -> Self {
        Self::new(false, Duration::ZERO)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The grace period an unreferenced blob must stay untouched.
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Hold while depending on a blob's presence (existence check, promote).
    /// `None` when GC is disabled (nothing to fence against).
    pub async fn pin(&self) -> Option<RwLockReadGuard<'_, ()>> {
        if self.enabled {
            Some(self.fence.read().await)
        } else {
            None
        }
    }

    /// Exclusive fence for a sweep batch: no want-path runs while held.
    pub async fn exclusive(&self) -> RwLockWriteGuard<'_, ()> {
        self.fence.write().await
    }

    /// `(repo, digest)` is unreferenced as of now: (re)stamp it a candidate.
    pub fn mark(&self, repo: &str, digest: &str) {
        self.mark_at(repo, digest, Instant::now());
    }

    /// `(repo, digest)` is unreferenced as of `at`: stamp it a candidate.
    /// Allows the startup seed to use a deterministic timestamp.
    pub fn mark_at(&self, repo: &str, digest: &str, at: Instant) {
        if self.enabled {
            self.lock()
                .insert((repo.to_string(), digest.to_string()), at);
        }
    }

    /// Something wants `(repo, digest)`: refresh its stamp if it is a candidate.
    pub fn touch(&self, repo: &str, digest: &str) {
        if self.enabled {
            if let Some(t) = self.lock().get_mut(&(repo.to_string(), digest.to_string())) {
                *t = Instant::now();
            }
        }
    }

    /// `(repo, digest)` is referenced (or gone): no longer a candidate.
    pub fn clear(&self, repo: &str, digest: &str) {
        if self.enabled {
            self.lock().remove(&(repo.to_string(), digest.to_string()));
        }
    }

    /// Candidates whose grace period has elapsed at `now`.
    pub fn due(&self, now: Instant) -> Vec<BlobKey> {
        self.lock()
            .iter()
            .filter(|(_, t)| now.saturating_duration_since(**t) >= self.delay)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Whether `(repo, digest)` is still a due candidate at `now` — the
    /// sweeper's re-check under [`GcTracker::exclusive`].
    pub fn is_due(&self, repo: &str, digest: &str, now: Instant) -> bool {
        self.lock()
            .get(&(repo.to_string(), digest.to_string()))
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.delay)
    }

    /// Number of current candidates.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Open the sweep gate after the startup consistency check.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Whether sweeps may run.
    pub fn is_ready(&self) -> bool {
        self.enabled && self.ready.load(Ordering::Acquire)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BlobKey, Instant>> {
        self.candidates.lock().expect("gc lock poisoned")
    }

    /// Record `(repo, digest)` as a GC root: a manifest known from the layout
    /// that the sweeper must never collect.
    pub fn add_root(&self, repo: &str, digest: &str) {
        if self.enabled {
            self.roots
                .lock()
                .expect("gc roots lock poisoned")
                .insert((repo.to_string(), digest.to_string()));
        }
    }

    /// Whether `(repo, digest)` is a root manifest.
    pub fn is_root(&self, repo: &str, digest: &str) -> bool {
        self.roots
            .lock()
            .expect("gc roots lock poisoned")
            .contains(&(repo.to_string(), digest.to_string()))
    }

    /// Mark `repo` as GC-unsafe: sweeps skip it entirely.
    pub fn mark_unsafe(&self, repo: &str) {
        if self.enabled {
            self.unsafe_repos
                .lock()
                .expect("gc unsafe lock poisoned")
                .insert(repo.to_string());
        }
    }

    /// Whether `repo` is GC-unsafe.
    pub fn is_unsafe(&self, repo: &str) -> bool {
        self.unsafe_repos
            .lock()
            .expect("gc unsafe lock poisoned")
            .contains(repo)
    }

    /// Number of root manifests tracked.
    pub fn roots_len(&self) -> usize {
        self.roots.lock().expect("gc roots lock poisoned").len()
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
        // A touch restamps: not due relative to the same instant any more.
        gc.touch("r", "sha256:a");
        assert!(!gc.is_due("r", "sha256:a", Instant::now()));
        // Touching a non-candidate does not create one.
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
        // Roots and unsafe repos are still trackable (disabled only means no sweeps).
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
        // Not due before delay elapses relative to the stamped instant.
        assert!(!gc.is_due("r", "sha256:a", base + Duration::from_secs(5)));
        // Due after the delay from the stamped instant.
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
