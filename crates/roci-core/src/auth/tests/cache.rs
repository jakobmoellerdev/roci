//! Credential cache: hits, misses, expiry, capacity, and the disabled mode.

use std::time::Duration;

use crate::auth::cache::{CredentialCache, CAPACITY};
use crate::auth::{AuthMethod, Principal};

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
