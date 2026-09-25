//! htpasswd parsing and verification.

use std::path::Path;

use crate::auth::htpasswd::{Htpasswd, HtpasswdResult};

#[test]
fn parse_rejects_with_line_numbers() {
    let h = bcrypt::hash("pw", 4).unwrap();
    for (text, needle) in [
        ("alice:{SHA}abc".to_string(), "line 1: only bcrypt"),
        ("\n# c\nalice:$apr1$x$y".to_string(), "line 3: only bcrypt"),
        ("alice:$2y$xx$abc".to_string(), "line 1: only bcrypt"),
        ("nocolon".to_string(), "line 1: expected"),
        (":{h}".to_string(), "line 1: expected"),
        (format!("a:{h}\nb:{h}\na:{h}"), "line 3: duplicate user `a`"),
        (
            "a:$2b$99$abcdefghijklmnopqrstuv".to_string(),
            "bcrypt cost 99",
        ),
    ] {
        let err = Htpasswd::parse(&text).err().expect(&text);
        assert!(err.contains(needle), "{text:?} → {err}");
    }
    assert!(Htpasswd::load(Path::new("/nonexistent/htpasswd"))
        .err()
        .unwrap()
        .contains("reading"));
}

#[tokio::test]
async fn verify_outcomes() {
    let h = bcrypt::hash("pw", 4).unwrap();
    let file = Htpasswd::parse(&format!("# users\n\nalice:{h}\n")).unwrap();
    assert!(file.dummy.starts_with("$2b$04$"));
    assert!(matches!(
        file.verify("alice", "pw").await,
        HtpasswdResult::Ok
    ));
    assert!(matches!(
        file.verify("alice", "nope").await,
        HtpasswdResult::BadPassword
    ));
    assert!(matches!(
        file.verify("mallory", "pw").await,
        HtpasswdResult::UnknownUser
    ));
    // An empty file still yields a dummy hash at the default cost.
    assert!(Htpasswd::parse("").unwrap().dummy.starts_with("$2b$10$"));
}
