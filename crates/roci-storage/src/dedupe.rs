//! Dedupe cache: `digest → location` (ARCHITECTURE §Storage trait, SECURITY
//! inv. 10). Links identical blobs across repos instead of duplicating.

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct DedupeIndex {
    enabled: bool,
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

    /// Record that `repo` holds `digest`.
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

    /// Remove entry if `repo` was the canonical holder.
    pub fn remove(&self, repo: &str, digest: &str) {
        let mut map = self.by_digest.lock().expect("dedupe lock poisoned");
        if map.get(digest).is_some_and(|r| r == repo) {
            map.remove(digest);
        }
    }

    /// A repo other than `repo` known to hold `digest`.
    pub fn locate(&self, digest: &str, repo: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let map = self.by_digest.lock().expect("dedupe lock poisoned");
        map.get(digest).filter(|r| *r != repo).cloned()
    }

    /// `(digest, repo)` snapshot for fast-restart.
    pub fn entries(&self) -> Vec<(String, String)> {
        self.by_digest
            .lock()
            .expect("dedupe lock poisoned")
            .iter()
            .map(|(d, r)| (d.clone(), r.clone()))
            .collect()
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
        assert_eq!(d.locate("sha256:x", "a"), None);
        d.remove("b", "sha256:x");
        assert_eq!(d.locate("sha256:x", "c").as_deref(), Some("a"));
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
