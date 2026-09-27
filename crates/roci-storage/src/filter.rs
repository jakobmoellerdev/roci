//! Approximate-membership filter for blob presence (ARCHITECTURE §"Existence
//! filter", RESEARCH §8.5). `false` = definite absence (skip `stat`); `true`
//! = maybe (MUST verify on disk, SECURITY inv. 10). Overflow disables the
//! filter (fail-open, no false negatives).

use std::sync::Mutex;

use cuckoofilter::CuckooFilter;
use std::collections::hash_map::DefaultHasher;

/// Mutable blob-presence filter keyed by `"<repo>\0<digest>"`.
pub struct BlobPresenceFilter {
    inner: Mutex<Inner>,
}

struct Inner {
    /// `None` once overflow disabled the filter.
    filter: Option<CuckooFilter<DefaultHasher>>,
}

fn key(repo: &str, digest: &str) -> String {
    let mut k = String::with_capacity(repo.len() + 1 + digest.len());
    k.push_str(repo);
    k.push('\0');
    k.push_str(digest);
    k
}

impl Default for BlobPresenceFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobPresenceFilter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                filter: Some(CuckooFilter::new()),
            }),
        }
    }

    /// Sized for `capacity` entries (test-only).
    #[cfg(test)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                filter: Some(CuckooFilter::with_capacity(capacity)),
            }),
        }
    }

    /// Record a blob as present; overflow disables the filter (fail-open).
    pub fn insert(&self, repo: &str, digest: &str) {
        let mut inner = self.inner.lock().expect("filter lock poisoned");
        if let Some(filter) = inner.filter.as_mut() {
            if filter.add(&key(repo, digest)).is_err() {
                inner.filter = None;
            }
        }
    }

    /// Remove membership (best-effort).
    pub fn remove(&self, repo: &str, digest: &str) {
        let mut inner = self.inner.lock().expect("filter lock poisoned");
        if let Some(filter) = inner.filter.as_mut() {
            filter.delete(&key(repo, digest));
        }
    }

    /// `false` = definite absence; `true` = maybe-present (caller MUST verify).
    pub fn maybe_present(&self, repo: &str, digest: &str) -> bool {
        let inner = self.inner.lock().expect("filter lock poisoned");
        match inner.filter.as_ref() {
            Some(filter) => filter.contains(&key(repo, digest)),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_is_definite_present_is_maybe() {
        let f = BlobPresenceFilter::new();
        assert!(!f.maybe_present("r", "sha256:aa"));
        f.insert("r", "sha256:aa");
        assert!(f.maybe_present("r", "sha256:aa"));
        assert!(!f.maybe_present("r", "sha256:zz"));
        assert!(!f.maybe_present("other", "sha256:aa"));
    }

    #[test]
    fn remove_clears_membership() {
        let f = BlobPresenceFilter::new();
        f.insert("r", "sha256:aa");
        assert!(f.maybe_present("r", "sha256:aa"));
        f.remove("r", "sha256:aa");
        assert!(!f.maybe_present("r", "sha256:aa"));
        f.remove("r", "sha256:absent");
    }

    #[test]
    fn disabled_filter_reports_maybe_present() {
        let f = BlobPresenceFilter::new();
        {
            let mut inner = f.inner.lock().unwrap();
            inner.filter = None;
        }
        assert!(f.maybe_present("r", "sha256:anything"));
        f.insert("r", "sha256:aa");
        f.remove("r", "sha256:aa");
        assert!(f.maybe_present("r", "sha256:aa"));
    }

    #[test]
    fn default_constructs_enabled_filter() {
        let f = BlobPresenceFilter::default();
        assert!(!f.maybe_present("r", "sha256:aa"));
    }

    #[test]
    fn overflow_disables_filter_via_insert_path() {
        // Tiny capacity → fills quickly → fail-open.
        let f = BlobPresenceFilter::with_capacity(1);
        for i in 0..10_000 {
            f.insert("r", &format!("sha256:{i:064x}"));
        }
        assert!(f.maybe_present("r", "sha256:definitely-never-inserted"));
    }
}
