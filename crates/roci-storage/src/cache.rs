//! Bounded in-RAM small-blob content cache (ARCHITECTURE.md §"Small-blob
//! content cache", RESEARCH §9.2). Manifests and configs (1–50 KB) dominate
//! request *count* but a trivial fraction of *bytes*; caching them serves the
//! dominant request type with zero `open()`/`close()` syscalls.
//!
//! Only blobs below `small_blob_threshold` (default 100 KB — the DB-vs-file
//! crossover) are cached; large layer blobs go straight to streaming
//! (`sendfile`) and are never cached (caching them would only pollute RAM). The
//! loose CAS file always exists (the cache is a pure hot-path accelerator, never
//! the sole copy — the `blobs/<alg>/<hex>` layout stays OCI-conformant), so a
//! miss simply falls through to the file.

use lru::LruCache;
use std::sync::{Arc, Mutex};

/// Default small-blob threshold: blobs at or below this size are cacheable
/// (RESEARCH §9.2 — the ~100 KB DB-vs-file crossover).
pub const DEFAULT_SMALL_BLOB_THRESHOLD: usize = 100 * 1024;

/// Default total byte budget for the cache (256 MB — bounded, back-pressured).
pub const DEFAULT_CACHE_CAPACITY: usize = 256 * 1024 * 1024;

/// A byte-bounded LRU cache of small blob contents keyed by `"<repo>\0<digest>"`.
pub struct SmallBlobCache {
    inner: Mutex<Inner>,
    /// Blobs strictly larger than this are never cached.
    threshold: usize,
    /// Maximum total bytes of cached content.
    capacity: usize,
}

struct Inner {
    map: LruCache<String, Arc<[u8]>>,
    total_bytes: usize,
}

fn key(repo: &str, digest: &str) -> String {
    let mut k = String::with_capacity(repo.len() + 1 + digest.len());
    k.push_str(repo);
    k.push('\0');
    k.push_str(digest);
    k
}

impl SmallBlobCache {
    /// Create a cache with the default threshold and capacity.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_SMALL_BLOB_THRESHOLD, DEFAULT_CACHE_CAPACITY)
    }

    /// Create a cache with explicit `threshold` (max cacheable blob size) and
    /// `capacity` (total byte budget).
    pub fn with_limits(threshold: usize, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                // Unbounded entry count; eviction is driven by the byte budget.
                map: LruCache::unbounded(),
                total_bytes: 0,
            }),
            threshold,
            capacity,
        }
    }

    /// Return the cached bytes for `(repo, digest)`, marking it most-recently
    /// used, or `None` on a miss.
    pub fn get(&self, repo: &str, digest: &str) -> Option<Arc<[u8]>> {
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        inner.map.get(&key(repo, digest)).cloned()
    }

    /// Cache `data` for `(repo, digest)` if it is small enough and fits the
    /// budget. Content larger than the threshold, or larger than the whole
    /// capacity, is not cached. Inserting evicts least-recently-used entries
    /// until the total fits the byte budget.
    pub fn put(&self, repo: &str, digest: &str, data: &[u8]) {
        if data.len() > self.threshold || data.len() > self.capacity {
            return;
        }
        let k = key(repo, digest);
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        // Replace any existing entry's byte accounting.
        if let Some(old) = inner.map.pop(&k) {
            inner.total_bytes -= old.len();
        }
        let bytes: Arc<[u8]> = Arc::from(data);
        inner.total_bytes += bytes.len();
        inner.map.put(k, bytes);
        // Evict LRU entries until within the byte budget. The just-inserted
        // entry is ≤ capacity (larger content is rejected above), so while the
        // total exceeds the budget the map is always non-empty — pop_lru yields.
        while inner.total_bytes > self.capacity {
            let (_, evicted) = inner.map.pop_lru().expect("non-empty while over budget");
            inner.total_bytes -= evicted.len();
        }
    }

    /// Drop a cached entry (on blob/manifest delete).
    pub fn invalidate(&self, repo: &str, digest: &str) {
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        if let Some(old) = inner.map.pop(&key(repo, digest)) {
            inner.total_bytes -= old.len();
        }
    }
}

impl Default for SmallBlobCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_small_blobs_and_serves_hits() {
        let c = SmallBlobCache::new();
        assert!(c.get("r", "sha256:aa").is_none());
        c.put("r", "sha256:aa", b"manifest bytes");
        assert_eq!(&*c.get("r", "sha256:aa").unwrap(), b"manifest bytes");
        // Repo isolation: same digest, different repo, is a distinct key.
        assert!(c.get("other", "sha256:aa").is_none());
    }

    #[test]
    fn rejects_blobs_over_threshold() {
        let c = SmallBlobCache::with_limits(8, 1024);
        c.put("r", "sha256:big", b"0123456789"); // 10 bytes > 8
        assert!(c.get("r", "sha256:big").is_none());
        c.put("r", "sha256:ok", b"01234567"); // 8 bytes == threshold
        assert!(c.get("r", "sha256:ok").is_some());
    }

    #[test]
    fn evicts_lru_to_stay_within_byte_budget() {
        // Capacity 20 bytes, threshold 20.
        let c = SmallBlobCache::with_limits(20, 20);
        c.put("r", "a", b"0123456789"); // 10 bytes
        c.put("r", "b", b"0123456789"); // 10 bytes → total 20, fits
        assert!(c.get("r", "a").is_some());
        // Touch "a" so "b" becomes least-recently-used.
        assert!(c.get("r", "a").is_some());
        c.put("r", "c", b"0123456789"); // +10 → over budget, evict LRU ("b")
        assert!(c.get("r", "c").is_some());
        assert!(c.get("r", "a").is_some());
        assert!(c.get("r", "b").is_none());
    }

    #[test]
    fn put_replaces_existing_and_adjusts_bytes() {
        let c = SmallBlobCache::with_limits(100, 100);
        c.put("r", "k", b"0123456789"); // 10
        c.put("r", "k", b"01"); // replace with 2 bytes
        assert_eq!(&*c.get("r", "k").unwrap(), b"01");
        // The byte accounting was adjusted, so a near-capacity fill still fits.
        c.put("r", "big", &[0u8; 98]); // 2 + 98 = 100, fits exactly
        assert!(c.get("r", "big").is_some());
        assert!(c.get("r", "k").is_some());
    }

    #[test]
    fn invalidate_drops_entry_and_frees_bytes() {
        let c = SmallBlobCache::with_limits(100, 20);
        c.put("r", "a", b"0123456789");
        c.invalidate("r", "a");
        assert!(c.get("r", "a").is_none());
        // Freed bytes are reusable.
        c.put("r", "b", b"0123456789");
        c.put("r", "c", b"0123456789");
        assert!(c.get("r", "b").is_some());
        assert!(c.get("r", "c").is_some());
        // Invalidating an absent key is a no-op.
        c.invalidate("r", "absent");
    }

    #[test]
    fn content_larger_than_capacity_is_not_cached() {
        let c = SmallBlobCache::with_limits(1000, 8);
        // Under the threshold but larger than the whole capacity → not cached.
        c.put("r", "k", b"0123456789");
        assert!(c.get("r", "k").is_none());
    }

    #[test]
    fn default_and_nonzero_capacity_are_sane() {
        let c = SmallBlobCache::default();
        c.put("r", "k", b"hi");
        assert!(c.get("r", "k").is_some());
        // A degenerate zero capacity caches nothing (every blob exceeds it).
        let z = SmallBlobCache::with_limits(0, 0);
        z.put("r", "k", b"");
        // An empty blob (0 bytes) fits a 0 threshold+capacity and is cached.
        assert!(z.get("r", "k").is_some());
    }
}
