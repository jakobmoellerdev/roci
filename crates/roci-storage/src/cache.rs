//! Bounded in-RAM small-blob content cache (ARCHITECTURE §"Small-blob content
//! cache", RESEARCH §9.2). Caches manifests/configs below `small_blob_threshold`.

use lru::LruCache;
use std::sync::{Arc, Mutex};

/// Default small-blob threshold (RESEARCH §9.2).
pub const DEFAULT_SMALL_BLOB_THRESHOLD: usize = 100 * 1024;

/// Default total byte budget (256 MB).
pub const DEFAULT_CACHE_CAPACITY: usize = 256 * 1024 * 1024;

/// Byte-bounded LRU cache keyed by `"<repo>\0<digest>"`.
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

    /// Max cacheable blob size.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Return cached bytes, or `None` on a miss.
    pub fn get(&self, repo: &str, digest: &str) -> Option<Arc<[u8]>> {
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        inner.map.get(&key(repo, digest)).cloned()
    }

    /// Cache `data` if it fits threshold and byte budget; evicts LRU as needed.
    pub fn put(&self, repo: &str, digest: &str, data: &[u8]) {
        if data.len() > self.threshold || data.len() > self.capacity {
            return;
        }
        let k = key(repo, digest);
        let mut inner = self.inner.lock().expect("cache lock poisoned");
        if let Some(old) = inner.map.pop(&k) {
            inner.total_bytes -= old.len();
        }
        let bytes: Arc<[u8]> = Arc::from(data);
        inner.total_bytes += bytes.len();
        inner.map.put(k, bytes);
        while inner.total_bytes > self.capacity {
            let (_, evicted) = inner.map.pop_lru().expect("non-empty while over budget");
            inner.total_bytes -= evicted.len();
        }
    }

    /// Drop a cached entry.
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
        let c = SmallBlobCache::with_limits(20, 20);
        c.put("r", "a", b"0123456789"); // 10 bytes
        c.put("r", "b", b"0123456789"); // 10 bytes → total 20, fits
        assert!(c.get("r", "a").is_some());
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
        c.put("r", "b", b"0123456789");
        c.put("r", "c", b"0123456789");
        assert!(c.get("r", "b").is_some());
        assert!(c.get("r", "c").is_some());
        c.invalidate("r", "absent");
    }

    #[test]
    fn content_larger_than_capacity_is_not_cached() {
        let c = SmallBlobCache::with_limits(1000, 8);
        c.put("r", "k", b"0123456789");
        assert!(c.get("r", "k").is_none());
    }

    #[test]
    fn default_and_nonzero_capacity_are_sane() {
        let c = SmallBlobCache::default();
        c.put("r", "k", b"hi");
        assert!(c.get("r", "k").is_some());
        let z = SmallBlobCache::with_limits(0, 0);
        z.put("r", "k", b"");
        assert!(z.get("r", "k").is_some());
    }
}
