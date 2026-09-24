//! The dedupe cache: `digest → location` (ARCHITECTURE §Storage trait &
//! backends, zot `cacheDriver`). When a blob arrives in one repository while
//! an identical one is already stored in another, the backend links the
//! existing copy (reflink → hard link) instead of keeping a second one.
//!
//! One canonical location per digest keeps the index O(unique digests); when
//! that copy goes, the entry is dropped and the next arrival becomes the new
//! canonical location (a missed dedupe is a space cost, never a correctness
//! one). The index is never an authority for reads: a located source is
//! re-validated beneath the store root before it is linked, and a repository
//! still serves only blobs it holds itself (SECURITY inv. 10).

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct DedupeIndex {
    enabled: bool,
    /// `digest → repo` holding the canonical copy.
    by_digest: Mutex<HashMap<String, String>>,
}

impl DedupeIndex {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            by_digest: Mutex::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Record that `repo` holds `digest` (kept only if no location is known).
    pub fn insert(&self, repo: &str, digest: &str) {
        if !self.enabled {
            return;
        }
        self.by_digest
            .lock()
            .expect("dedupe lock poisoned")
            .entry(digest.to_string())
            .or_insert_with(|| repo.to_string());
    }

    /// `repo` no longer holds `digest`: drop the entry if it pointed there.
    pub fn remove(&self, repo: &str, digest: &str) {
        let mut map = self.by_digest.lock().expect("dedupe lock poisoned");
        if map.get(digest).is_some_and(|r| r == repo) {
            map.remove(digest);
        }
    }

    /// A repository other than `repo` known to hold `digest`.
    pub fn locate(&self, digest: &str, repo: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let map = self.by_digest.lock().expect("dedupe lock poisoned");
        map.get(digest).filter(|r| *r != repo).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_location_is_canonical_and_excludes_the_asking_repo() {
        let d = DedupeIndex::new(true);
        d.insert("a", "sha256:x");
        d.insert("b", "sha256:x");
        assert_eq!(d.locate("sha256:x", "c").as_deref(), Some("a"));
        // The canonical holder asking for itself has nothing to link from.
        assert_eq!(d.locate("sha256:x", "a"), None);
        // Removing a non-canonical holder leaves the entry.
        d.remove("b", "sha256:x");
        assert_eq!(d.locate("sha256:x", "c").as_deref(), Some("a"));
        // Removing the canonical holder frees the slot for the next arrival.
        d.remove("a", "sha256:x");
        assert_eq!(d.locate("sha256:x", "c"), None);
        d.insert("b", "sha256:x");
        assert_eq!(d.locate("sha256:x", "c").as_deref(), Some("b"));
    }

    #[test]
    fn disabled_index_records_and_locates_nothing() {
        let d = DedupeIndex::new(false);
        d.insert("a", "sha256:x");
        assert!(!d.enabled());
        assert_eq!(d.locate("sha256:x", "b"), None);
    }
}
