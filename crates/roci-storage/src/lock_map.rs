//! Keyed async locks: `(a, b) → Arc<Mutex<V>>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[allow(clippy::type_complexity)]
pub struct LockMap<V>(Mutex<HashMap<(String, String), Arc<tokio::sync::Mutex<V>>>>);

impl<V> Default for LockMap<V> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<V: Default> LockMap<V> {
    pub fn get(&self, a: &str, b: &str) -> Arc<tokio::sync::Mutex<V>> {
        Arc::clone(
            self.0
                .lock()
                .expect("lock map poisoned")
                .entry((a.to_string(), b.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(V::default()))),
        )
    }
}

impl<V> LockMap<V> {
    pub fn remove(&self, a: &str, b: &str) {
        self.0
            .lock()
            .expect("lock map poisoned")
            .remove(&(a.to_string(), b.to_string()));
    }

    /// Remove only if no other holder references it.
    pub fn release(&self, a: &str, b: &str) {
        let mut map = self.0.lock().expect("lock map poisoned");
        let key = (a.to_string(), b.to_string());
        if map.get(&key).is_some_and(|l| Arc::strong_count(l) <= 2) {
            map.remove(&key);
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, a: &str, b: &str) -> bool {
        self.0
            .lock()
            .expect("lock map poisoned")
            .contains_key(&(a.to_string(), b.to_string()))
    }
}
