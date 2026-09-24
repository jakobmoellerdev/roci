use roci_storage::*;
use std::io;

#[test]
fn digest_parse_rejects_bad_input() {
    assert!(Digest::parse("sha256:zz").is_err());
    assert!(Digest::parse("nope").is_err());
    assert!(Digest::parse(&format!("sha256:{}", "a".repeat(64))).is_ok());
}

#[test]
fn ct_eq_matches_equal_and_rejects_differences() {
    let a = sha256_of(b"payload");
    let b = sha256_of(b"payload");
    assert!(a.ct_eq(&b));
    let c = sha256_of(b"other");
    assert!(!a.ct_eq(&c));
    // Differing algorithm never matches.
    let s512 = Digest::parse(&format!("sha512:{}", "a".repeat(128))).unwrap();
    let s256 = Digest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
    assert!(!s512.ct_eq(&s256));
}

#[test]
fn sha512_digest_parses_and_displays() {
    let d = Digest::parse(&format!("sha512:{}", "b".repeat(128))).unwrap();
    assert_eq!(d.to_string(), format!("sha512:{}", "b".repeat(128)));
    assert_eq!(d.as_string(), d.to_string());
}

#[test]
fn error_messages_render() {
    // Exercise the Display arms of every StorageError variant.
    assert_eq!(StorageError::NotFound.to_string(), "not found");
    assert_eq!(
        StorageError::BadDigest("x".into()).to_string(),
        "malformed digest: x"
    );
    assert_eq!(
        StorageError::DigestMismatch {
            expected: "a".into(),
            actual: "b".into()
        }
        .to_string(),
        "digest mismatch: expected a, got b"
    );
    let io = StorageError::Io(io::Error::other("boom"));
    assert!(io.to_string().contains("boom"));
}

#[test]
fn sha512_bad_hex_rejected() {
    // Correct length, non-hex char → BadDigest (covers the hex guard).
    assert!(Digest::parse(&format!("sha512:{}", "z".repeat(128))).is_err());
    // Unknown algorithm → BadDigest (covers the match's fallback arm).
    assert!(Digest::parse("md5:abcdef").is_err());
}
