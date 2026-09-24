//! Object key construction and validation. Every untrusted component (repo
//! name, digest) is validated before reaching an object key, mirroring the
//! filesystem backend's `SafeComponent` discipline (SECURITY inv. 8).

use roci_storage::{Digest, StorageError};

/// Validate a repository name component (no `.`, `..`, NUL, backslash).
fn validate_component(s: &str) -> Result<(), StorageError> {
    if s.is_empty() || s == "." || s == ".." || s.bytes().any(|b| b == b'\\' || b == 0) {
        return Err(StorageError::BadPath(s.to_string()));
    }
    Ok(())
}

/// Validate every `/`-component of a repo name.
pub(crate) fn validate_repo(repo: &str) -> Result<(), StorageError> {
    for c in repo.split('/') {
        validate_component(c)?;
    }
    Ok(())
}

/// The object-key prefix for a repository: `<prefix>/<repo>` (no leading `/`).
pub(crate) fn repo_prefix(prefix: &str, repo: &str) -> Result<String, StorageError> {
    validate_repo(repo)?;
    if prefix.is_empty() {
        Ok(repo.to_string())
    } else {
        Ok(format!("{prefix}/{repo}"))
    }
}

/// Object key for a blob: `<prefix>/<repo>/blobs/<alg>/<hex>`.
pub(crate) fn blob_key(prefix: &str, repo: &str, digest: &Digest) -> Result<String, StorageError> {
    let rp = repo_prefix(prefix, repo)?;
    // Digest is already validated by Digest::parse (alg + hex only).
    Ok(format!(
        "{rp}/blobs/{}/{}",
        digest.algorithm(),
        digest.hex()
    ))
}

/// Object key for `index.json`: `<prefix>/<repo>/index.json`.
pub(crate) fn index_key(prefix: &str, repo: &str) -> Result<String, StorageError> {
    let rp = repo_prefix(prefix, repo)?;
    Ok(format!("{rp}/index.json"))
}

/// Object key for `oci-layout`: `<prefix>/<repo>/oci-layout`.
pub(crate) fn layout_key(prefix: &str, repo: &str) -> Result<String, StorageError> {
    let rp = repo_prefix(prefix, repo)?;
    Ok(format!("{rp}/oci-layout"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_key_format() {
        let d = Digest::parse(
            "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        .unwrap();
        assert_eq!(
            blob_key("pfx", "myrepo", &d).unwrap(),
            "pfx/myrepo/blobs/sha256/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        );
    }

    #[test]
    fn blob_key_no_prefix() {
        let d = Digest::parse(
            "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        .unwrap();
        assert_eq!(
            blob_key("", "myrepo", &d).unwrap(),
            "myrepo/blobs/sha256/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        );
    }

    #[test]
    fn nested_repo_key() {
        let d = Digest::parse(
            "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        .unwrap();
        assert_eq!(
            blob_key("", "org/team/app", &d).unwrap(),
            "org/team/app/blobs/sha256/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
        );
    }

    #[test]
    fn rejects_traversal() {
        assert!(validate_repo("..").is_err());
        assert!(validate_repo("a/../b").is_err());
        assert!(validate_repo("a/./b").is_err());
    }

    #[test]
    fn index_and_layout_keys() {
        assert_eq!(index_key("pfx", "repo").unwrap(), "pfx/repo/index.json");
        assert_eq!(layout_key("pfx", "repo").unwrap(), "pfx/repo/oci-layout");
    }
}
