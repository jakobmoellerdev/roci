//! Short-lived cache of successful Basic authentications, so a client that
//! resends credentials on every request pays the bcrypt / LDAP cost once per
//! TTL. Keyed by a SHA-256 of `user ‖ 0x00 ‖ password`: the password itself
//! is never stored, and a changed password misses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::{AuthMethod, Principal};

/// Entries held before the map is cleared wholesale (bounded memory).
const CAPACITY: usize = 4096;

struct CachedUser {
    name: Arc<str>,
    ldap_groups: Arc<[String]>,
    method: AuthMethod,
    expires: Instant,
}

pub(crate) struct CredentialCache {
    ttl: Duration,
    map: Mutex<HashMap<[u8; 32], CachedUser>>,
}

fn key(user: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(user.as_bytes());
    h.update([0]);
    h.update(password.as_bytes());
    h.finalize().into()
}

impl CredentialCache {
    /// `ttl == 0` disables caching.
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn get(&self, user: &str, password: &str) -> Option<Principal> {
        if self.ttl.is_zero() {
            return None;
        }
        let k = key(user, password);
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        let hit = map.get(&k)?;
        if hit.expires <= Instant::now() {
            map.remove(&k);
            return None;
        }
        Some(Principal::User {
            name: Arc::clone(&hit.name),
            ldap_groups: Arc::clone(&hit.ldap_groups),
            method: hit.method,
        })
    }

    /// Record a successful authentication and return its principal.
    pub(crate) fn insert(
        &self,
        user: &str,
        password: &str,
        ldap_groups: Vec<String>,
        method: AuthMethod,
    ) -> Principal {
        let name: Arc<str> = Arc::from(user);
        let ldap_groups: Arc<[String]> = ldap_groups.into();
        if !self.ttl.is_zero() {
            let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
            if map.len() >= CAPACITY {
                map.clear();
            }
            map.insert(
                key(user, password),
                CachedUser {
                    name: Arc::clone(&name),
                    ldap_groups: Arc::clone(&ldap_groups),
                    method,
                    expires: Instant::now() + self.ttl,
                },
            );
        }
        Principal::User {
            name,
            ldap_groups,
            method,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_user(p: Option<Principal>, want: &str) -> bool {
        matches!(p, Some(Principal::User { ref name, .. }) if &**name == want)
    }

    #[test]
    fn hit_miss_expiry_and_capacity() {
        let c = CredentialCache::new(Duration::from_secs(60));
        c.insert("alice", "pw", vec!["g".into()], AuthMethod::Htpasswd);
        assert!(is_user(c.get("alice", "pw"), "alice"));
        // A different password (or a user/password split shift) misses.
        assert!(c.get("alice", "other").is_none());
        assert!(c.get("alicep", "w").is_none());
        // Filling to capacity clears the map before the next insert.
        for i in 0..CAPACITY {
            c.insert(&format!("u{i}"), "pw", vec![], AuthMethod::Htpasswd);
        }
        assert!(c.get("alice", "pw").is_none());
        assert!(is_user(c.get("u4095", "pw"), "u4095"));

        let short = CredentialCache::new(Duration::from_millis(1));
        short.insert("bob", "pw", vec![], AuthMethod::Htpasswd);
        std::thread::sleep(Duration::from_millis(5));
        assert!(short.get("bob", "pw").is_none());
        assert!(short.map.lock().unwrap().is_empty());

        let off = CredentialCache::new(Duration::ZERO);
        off.insert("carol", "pw", vec![], AuthMethod::Htpasswd);
        assert!(off.get("carol", "pw").is_none());
    }
}
