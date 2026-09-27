//! Validated repository-name type (dist-spec grammar, SECURITY.md inv. 8).
//! Hand-written byte-class check; no `regex` dependency.

use crate::error::ApiError;

const MAX_NAME: usize = 255;

/// A validated repository name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryName(String);

impl RepositoryName {
    /// Validate a repository name against the dist-spec grammar.
    pub fn parse(s: &str) -> Result<Self, ApiError> {
        if s.is_empty() || s.len() > MAX_NAME {
            return Err(ApiError::name_invalid(
                "repository name length out of range",
            ));
        }
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

fn validate_name_component(c: &str) -> Result<(), ApiError> {
    if c.is_empty() || c == "." || c == ".." {
        return Err(ApiError::name_invalid("empty or dot repository component"));
    }
    let bytes = c.as_bytes();
    if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[bytes.len() - 1]) {
        return Err(ApiError::name_invalid(
            "repository component must start and end with [a-z0-9]",
        ));
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if is_lower_alnum(b) {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < bytes.len() && is_separator(bytes[i]) {
            i += 1;
        }
        let run = &bytes[run_start..i];
        if !valid_separator_run(run) {
            return Err(ApiError::name_invalid("invalid repository name separator"));
        }
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
