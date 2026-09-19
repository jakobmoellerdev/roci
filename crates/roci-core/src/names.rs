//! Validated repository-name type.
//!
//! Every `/v2/<name>/…` path has its repository name validated against the
//! dist-spec grammar *before* any handler logic or filesystem path is
//! constructed (Phase 0 correctness gate; SECURITY.md inv. 8, path-traversal
//! CVE class). The manifest *reference* is intentionally not grammar-rejected
//! here — an unknown or syntactically-invalid reference resolves to 404
//! `MANIFEST_UNKNOWN` at the storage layer, per the dist-spec conformance suite.
//!
//! Grammar (`spec/distribution-spec/spec.md`):
//! - name: `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*`, ≤255 chars.
//!
//! The validator is a hand-written byte-class check — no `regex` dependency
//! (footprint discipline, PLAN.md §Guiding constraints).

use crate::error::ApiError;

/// Maximum repository-name length (dist-spec implementers' note).
const MAX_NAME: usize = 255;

/// A validated repository name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryName(String);

impl RepositoryName {
    /// Parse and validate a repository name against the dist-spec grammar.
    /// Rejects with `NAME_INVALID` on any grammar or safety violation.
    pub fn parse(s: &str) -> Result<Self, ApiError> {
        if s.is_empty() || s.len() > MAX_NAME {
            return Err(ApiError::name_invalid(
                "repository name length out of range",
            ));
        }
        // Each `/`-separated path component must match
        // `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*` and be neither empty nor `.`/`..`,
        // with no embedded NUL. Leading/trailing `/` yields an empty component
        // and is thus rejected.
        for component in s.split('/') {
            validate_name_component(component)?;
        }
        Ok(RepositoryName(s.to_string()))
    }

    /// The canonical name string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RepositoryName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RepositoryName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A single `/`-separated name component: `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn validate_name_component(c: &str) -> Result<(), ApiError> {
    if c.is_empty() || c == "." || c == ".." {
        return Err(ApiError::name_invalid("empty or dot repository component"));
    }
    let bytes = c.as_bytes();
    // Must start and end with an alphanumeric [a-z0-9].
    if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[bytes.len() - 1]) {
        return Err(ApiError::name_invalid(
            "repository component must start and end with [a-z0-9]",
        ));
    }
    // Between alphanumerics, only single separators from the set
    // {`.`, `_`, `__`, `-`+} are permitted; two separators may not be adjacent
    // except the `__` and `-`+ forms. We enforce: a separator run may be `.`,
    // `_`, `__`, or one-or-more `-`; any other run is invalid.
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if is_lower_alnum(b) {
            i += 1;
            continue;
        }
        // Start of a separator run.
        let run_start = i;
        while i < bytes.len() && is_separator(bytes[i]) {
            i += 1;
        }
        let run = &bytes[run_start..i];
        if !valid_separator_run(run) {
            return Err(ApiError::name_invalid("invalid repository name separator"));
        }
        // A separator run may not be trailing (already guaranteed by the
        // end-char check) and must be followed by an alphanumeric.
        if i >= bytes.len() || !is_lower_alnum(bytes[i]) {
            return Err(ApiError::name_invalid("separator not followed by [a-z0-9]"));
        }
    }
    Ok(())
}

fn is_lower_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn is_separator(b: u8) -> bool {
    b == b'.' || b == b'_' || b == b'-'
}

/// A valid separator run is exactly `.`, `_`, `__`, or one-or-more `-`.
fn valid_separator_run(run: &[u8]) -> bool {
    match run {
        [b'.'] => true,
        [b'_'] => true,
        [b'_', b'_'] => true,
        _ => run.iter().all(|&b| b == b'-'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for ok in [
            "library/alpine",
            "alpine",
            "a",
            "foo.bar",
            "foo_bar",
            "foo__bar",
            "foo--bar",
            "a/b/c/d",
            "my-repo.name_1/sub__part",
        ] {
            assert!(RepositoryName::parse(ok).is_ok(), "should accept {ok}");
        }
    }

    #[test]
    fn repository_name_accessors() {
        let n = RepositoryName::parse("library/alpine").unwrap();
        assert_eq!(n.as_str(), "library/alpine");
        assert_eq!(n.to_string(), "library/alpine");
        assert_eq!(AsRef::<str>::as_ref(&n), "library/alpine");
    }

    #[test]
    fn rejects_invalid_names() {
        for bad in [
            "",
            "UPPER",
            "Foo",
            "/leading",
            "trailing/",
            "double//slash",
            "..",
            ".",
            "a/../b",
            "a/./b",
            "-startdash",
            "enddash-",
            ".dot",
            "under_",
            "a b",
            "foo\0bar",
            "foo...bar",
        ] {
            assert!(RepositoryName::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn name_length_capped() {
        let long = "a".repeat(256);
        assert!(RepositoryName::parse(&long).is_err());
        let ok = "a".repeat(255);
        assert!(RepositoryName::parse(&ok).is_ok());
    }
}
