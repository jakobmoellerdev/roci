//! Short-lived cache of successful Basic authentications (SHA-256 keyed).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::{AuthMethod, Principal};

pub(super) const CAPACITY: usize = 4096;

pub(super) struct CachedUser {
    name: Arc<str>,
    ldap_groups: Arc<[String]>,
    method: AuthMethod,
    expires: Instant,
}

pub(crate) struct CredentialCache {
    ttl: Duration,
    pub(super) map: Mutex<HashMap<[u8; 32], CachedUser>>,
}

fn key(user: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(user.as_bytes());
    h.update([0]);
    h.update(password.as_bytes());
    h.finalize().into()
}

impl CredentialCache {
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
