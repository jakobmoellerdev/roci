//! Unit tests for the auth module. Those using fixed test credentials live
//! here, under a `tests/` directory, which the CodeQL configuration excludes
//! (`.github/codeql/config.yml` `paths-ignore`) like every other test file.

mod cache;
mod htpasswd;

use super::*;

#[test]
fn action_set_algebra() {
    let s = ActionSet::from_actions(&[Action::Pull, Action::Delete]);
    assert!(s.contains(Action::Pull) && s.contains(Action::Delete));
    assert!(!s.contains(Action::Push));
    assert_eq!(s.union(ActionSet::of(Action::Push)), ActionSet::ALL);
    assert_eq!(ActionSet::from_actions(&[]), ActionSet::NONE);
}

#[test]
fn no_auth_config_means_no_engine() {
    assert!(Auth::from_config(&Config::default()).unwrap().is_none());
    let c = Config {
        access_control: Some(AccessControlConfig::default()),
        ..Config::default()
    };
    assert!(Auth::from_config(&c).unwrap().is_some());
}

#[cfg(not(feature = "ldap"))]
#[test]
fn ldap_without_feature_fails_startup() {
    let mut c = Config::default();
    c.auth.ldap = Some(roci_config::LdapConfig {
        url: "ldaps://d".into(),
        start_tls: false,
        bind_dn: "cn=a".into(),
        bind_password_file: "/nonexistent".into(),
        base_dn: "dc=x".into(),
        user_attribute: "uid".into(),
        user_filter: None,
        group_attribute: None,
        ca_file: None,
        timeout_secs: 5,
    });
    let err = Auth::from_config(&c).err().unwrap().to_string();
    assert!(err.contains("`ldap` feature"), "{err}");
}
