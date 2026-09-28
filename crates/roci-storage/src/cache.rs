//! Bounded in-RAM small-blob content cache (ARCHITECTURE §"Small-blob content
//! cache", RESEARCH §9.2). Holds blobs at or below `small_blob_threshold` that
//! were read, plus manifests at push time; uploads of other blobs never warm it.

use lru::LruCache;
use std::sync::{Arc, Mutex};

/// Default small-blob threshold (RESEARCH §9.2).
pub const DEFAULT_SMALL_BLOB_THRESHOLD: usize = 100 * 1024;

/// Default total byte budget (256 MB).
pub const DEFAULT_CACHE_CAPACITY: usize = 256 * 1024 * 1024;

/// Heap charged per entry beyond its key and content: the LRU node, the hash
/// slot and the `Arc` header, rounded up for allocator size classes. Without
/// it a budget of tiny blobs overshoots by the bookkeeping (RESEARCH §9.9).
const ENTRY_OVERHEAD: usize = 128;

/// Budget charged for caching `data` under `key`.
fn entry_cost(key: &str, data: &[u8]) -> usize {
    key.len() + data.len() + ENTRY_OVERHEAD
}

/// Byte-bounded LRU cache keyed by `"<repo>\0<digest>"`; the budget covers
/// each entry's key, content and bookkeeping, not just the content.
pub struct SmallBlobCache {
    inner: Mutex<Inner>,
    threshold: usize,
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
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_SMALL_BLOB_THRESHOLD, DEFAULT_CACHE_CAPACITY)
    }

    /// Create a cache with explicit threshold and capacity.
    pub fn with_limits(threshold: usize, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: LruCache::unbounded(),
                total_bytes: 0,
            }),
            threshold,
            capacity,
        }
    }

    /// Return cached bytes, or `None` on a miss.
    pub fn get(&self, repo: &str, digest: &str) -> Option<Arc<[u8]>> {
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        inner.map.get(&key(repo, digest)).cloned()
    }

    /// Cache `data` if it fits the threshold and budget; evicts LRU as needed.
    pub fn put(&self, repo: &str, digest: &str, data: &[u8]) {
        let k = key(repo, digest);
        let cost = entry_cost(&k, data);
        if data.len() > self.threshold || cost > self.capacity {
            return;
        }
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        if let Some(old) = inner.map.pop(&k) {
            inner.total_bytes -= entry_cost(&k, &old);
        }
        inner.total_bytes += cost;
        inner.map.put(k, Arc::from(data));
        while inner.total_bytes > self.capacity {
            let (k, evicted) = inner.map.pop_lru().expect("non-empty while over budget");
            inner.total_bytes -= entry_cost(&k, &evicted);
        }
    }

    /// Drop a cached entry.
    pub fn invalidate(&self, repo: &str, digest: &str) {
        let k = key(repo, digest);
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        if let Some(old) = inner.map.pop(&k) {
            inner.total_bytes -= entry_cost(&k, &old);
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

    /// Budget charged for one entry, as `put` computes it.
    fn cost(repo: &str, digest: &str, data: &[u8]) -> usize {
        entry_cost(&key(repo, digest), data)
    }

    #[test]
    fn evicts_lru_to_stay_within_byte_budget() {
        let ten = b"0123456789";
        // Room for exactly two entries: key + content + bookkeeping each.
        let c = SmallBlobCache::with_limits(20, 2 * cost("r", "a", ten));
        c.put("r", "a", ten);
        c.put("r", "b", ten);
        assert!(c.get("r", "a").is_some());
        assert!(c.get("r", "b").is_some());
        assert!(c.get("r", "a").is_some()); // "b" is now least recent
        c.put("r", "c", ten);
        assert!(c.get("r", "c").is_some());
        assert!(c.get("r", "a").is_some());
        assert!(c.get("r", "b").is_none());
    }

    #[test]
    fn budget_counts_keys_and_bookkeeping_not_just_content() {
        // 100 one-byte blobs: 100 content bytes, but far more heap in keys and
        // entries. A budget of 10x the content must not admit them all.
        let c = SmallBlobCache::with_limits(100, 1000);
        for i in 0..100 {
            c.put("r", &format!("sha256:{i:064}"), b"x");
        }
        let held = (0..100)
            .filter(|i| c.get("r", &format!("sha256:{i:064}")).is_some())
            .count();
        let per_entry = cost("r", &format!("sha256:{:064}", 0), b"x");
        assert_eq!(held, 1000 / per_entry);
        assert!(held < 100);
    }

    #[test]
    fn put_replaces_existing_and_adjusts_bytes() {
        let big = [0u8; 98];
        let c = SmallBlobCache::with_limits(100, cost("r", "k", b"01") + cost("r", "big", &big));
        c.put("r", "k", b"0123456789");
        c.put("r", "k", b"01"); // replacing refunds the 10-byte entry
        assert_eq!(&*c.get("r", "k").unwrap(), b"01");
        c.put("r", "big", &big); // fits exactly beside the 2-byte "k"
        assert!(c.get("r", "big").is_some());
        assert!(c.get("r", "k").is_some());
    }

    #[test]
    fn invalidate_drops_entry_and_frees_bytes() {
        let ten = b"0123456789";
        let c = SmallBlobCache::with_limits(100, 2 * cost("r", "a", ten));
        c.put("r", "a", ten);
        c.invalidate("r", "a");
        assert!(c.get("r", "a").is_none());
        c.put("r", "b", ten);
        c.put("r", "c", ten);
        assert!(c.get("r", "b").is_some());
        assert!(c.get("r", "c").is_some());
        c.invalidate("r", "absent");
    }

    #[test]
    fn entry_costing_more_than_capacity_is_not_cached() {
        let c = SmallBlobCache::with_limits(1000, cost("r", "k", b"0123456789") - 1);
        c.put("r", "k", b"0123456789");
        assert!(c.get("r", "k").is_none());
    }

    #[test]
    fn zero_capacity_caches_nothing() {
        let c = SmallBlobCache::default();
        c.put("r", "k", b"hi");
        assert!(c.get("r", "k").is_some());
        let disabled = SmallBlobCache::with_limits(0, 0);
        disabled.put("r", "k", b"");
        assert!(disabled.get("r", "k").is_none());
    }
}
