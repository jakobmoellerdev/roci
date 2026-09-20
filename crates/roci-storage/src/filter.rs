//! In-RAM approximate-membership filter fronting the blob-presence hot path
//! (ARCHITECTURE.md §"Existence filter", RESEARCH §8.5). A cuckoo filter is the
//! only production-Rust deletable filter, so it fits the *mutable* blob set
//! (deletes are needed for GC / blob removal).
//!
//! **Invariant (no false negatives for present blobs).** The filter is only
//! ever used to short-circuit a *definite absence*: `contains == false` ⇒ the
//! blob is not stored, answered with zero filesystem syscalls. A `contains ==
//! true` is only "maybe present" and MUST fall through to the filesystem, which
//! is the authority (SECURITY.md invariant 10 — a filter hit is never the sole
//! authority for a `200`). To keep the no-false-negative guarantee, a cuckoo
//! insert that fails (the filter is full) **disables** the filter: it then
//! reports every key as maybe-present, degrading to a plain `stat` rather than
//! ever wrongly reporting a stored blob as absent.

use std::sync::Mutex;

use cuckoofilter::CuckooFilter;
use std::collections::hash_map::DefaultHasher;

/// A mutable blob-presence filter keyed by `"<repo>\0<digest>"`.
pub struct BlobPresenceFilter {
    inner: Mutex<Inner>,
}

struct Inner {
    /// `None` once an insert overflowed — the filter is disabled and every
    /// lookup conservatively reports "maybe present" (no false negatives).
    filter: Option<CuckooFilter<DefaultHasher>>,
}

/// Membership key: repo and digest joined by a NUL (never valid in either).
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
    /// Create an empty, enabled filter.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                filter: Some(CuckooFilter::new()),
            }),
        }
    }

    /// Create an enabled filter sized for `capacity` entries. A tiny capacity
    /// lets tests exercise the full-filter fail-open path.
    #[cfg(test)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                filter: Some(CuckooFilter::with_capacity(capacity)),
            }),
        }
    }

    /// Record a blob as present. A full-filter insert failure disables the
    /// filter (fail-open to preserve the no-false-negative invariant).
    pub fn insert(&self, repo: &str, digest: &str) {
        let mut inner = self.inner.lock().expect("filter lock poisoned");
        if let Some(filter) = inner.filter.as_mut() {
            if filter.add(&key(repo, digest)).is_err() {
                // Filter is full; disable it rather than risk a false negative.
                inner.filter = None;
            }
        }
    }

    /// Drop a blob's membership (best-effort; deleting an absent key is a no-op).
    pub fn remove(&self, repo: &str, digest: &str) {
        let mut inner = self.inner.lock().expect("filter lock poisoned");
        if let Some(filter) = inner.filter.as_mut() {
            filter.delete(&key(repo, digest));
        }
    }

    /// Whether the blob *might* be present. `false` is authoritative (definite
    /// absence → skip the syscall); `true` means "maybe" and the caller MUST
    /// verify against the filesystem. A disabled filter always returns `true`.
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
        // Nothing inserted → definite absence.
        assert!(!f.maybe_present("r", "sha256:aa"));
        f.insert("r", "sha256:aa");
        // Inserted → reported as maybe-present.
        assert!(f.maybe_present("r", "sha256:aa"));
        // A different key is still definitely absent (barring a rare false
        // positive, which only costs an extra stat, never a wrong 404).
        assert!(!f.maybe_present("r", "sha256:zz"));
        // Repo isolation: same digest, different repo, is a distinct key.
        assert!(!f.maybe_present("other", "sha256:aa"));
    }

    #[test]
    fn remove_clears_membership() {
        let f = BlobPresenceFilter::new();
        f.insert("r", "sha256:aa");
        assert!(f.maybe_present("r", "sha256:aa"));
        f.remove("r", "sha256:aa");
        assert!(!f.maybe_present("r", "sha256:aa"));
        // Removing an absent key is a harmless no-op.
        f.remove("r", "sha256:absent");
    }

    #[test]
    fn disabled_filter_reports_maybe_present() {
        let f = BlobPresenceFilter::new();
        // Simulate a full-filter overflow by forcing the disabled state.
        {
            let mut inner = f.inner.lock().unwrap();
            inner.filter = None;
        }
        // Every lookup is now conservatively "maybe present" (no false negative).
        assert!(f.maybe_present("r", "sha256:anything"));
        // insert/remove on a disabled filter are no-ops that must not panic.
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
        // A tiny-capacity cuckoo filter fills quickly; a failed insert must
        // disable the filter (exercising the fail-open branch in `insert`), so
        // every subsequent lookup conservatively reports "maybe present".
        let f = BlobPresenceFilter::with_capacity(1);
        for i in 0..10_000 {
            f.insert("r", &format!("sha256:{i:064x}"));
        }
        // Once disabled, a key never inserted still reports maybe-present (no
        // false negative) — this can only be true if the filter is disabled.
        assert!(f.maybe_present("r", "sha256:definitely-never-inserted"));
    }
}
