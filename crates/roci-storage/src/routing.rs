//! Multi-backend routing: [`Routed`] dispatches every [`Storage`] /
//! [`StorageBackend`] call to the backend whose prefix is the longest
//! component-boundary match for the repo name — like zot `subPaths`.

use crate::metadata::{Page, Referrer};
use crate::storage::{BlobRead, ManifestLinks, ManifestRef, Storage, StorageBackend};
use crate::{Digest, StorageError};
use tokio::sync::watch;

/// A sorted route entry: `(prefix, backend)`, matched on a `/`-component
/// boundary.  Sorted longest-first so the first match wins.
#[derive(Clone)]
pub struct Routed<B> {
    /// The default backend used for repos matching no prefix.
    default: B,
    /// Routes sorted by descending prefix length (longest match first).
    routes: Vec<(String, B)>,
}

impl<B> std::fmt::Debug for Routed<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Routed")
            .field(
                "routes",
                &self
                    .routes
                    .iter()
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl<B: StorageBackend + Clone> Routed<B> {
    /// Build a routing table from a default backend and
    /// `(prefix, backend)` entries.  Prefixes must be valid repository-name
    /// component sequences (validated upstream in `roci-config`); empty entries
    /// are silently ignored.  Routes are sorted longest-first.
    pub fn new(default: B, mut routes: Vec<(String, B)>) -> Self {
        routes.sort_by_key(|r| std::cmp::Reverse(r.0.len()));
        Self { default, routes }
    }

    /// Return the backend that should serve `repo`, plus the index (None =
    /// default).  Longest matching prefix wins; match means `repo == prefix`
    /// or `repo` starts with `prefix` followed by `/`.
    fn backend_for(&self, repo: &str) -> &B {
        for (prefix, backend) in &self.routes {
            if matches_prefix(repo, prefix) {
                return backend;
            }
        }
        &self.default
    }

    /// Whether `from_repo` and `to_repo` resolve to the same backend instance.
    /// True only when the route index is identical (same entry or both default).
    fn same_backend(&self, from_repo: &str, to_repo: &str) -> bool {
        self.route_index(from_repo) == self.route_index(to_repo)
    }

    /// None = default; Some(i) = the i-th route entry.
    fn route_index(&self, repo: &str) -> Option<usize> {
        for (i, (prefix, _)) in self.routes.iter().enumerate() {
            if matches_prefix(repo, prefix) {
                return Some(i);
            }
        }
        None
    }
}

/// `repo` matches `prefix` when it equals the prefix exactly or starts with
/// the prefix followed by `/` (component-boundary match). Allocation-free.
#[inline]
fn matches_prefix(repo: &str, prefix: &str) -> bool {
    repo == prefix
        || (repo.len() > prefix.len()
            && repo.as_bytes()[prefix.len()] == b'/'
            && repo.as_bytes().starts_with(prefix.as_bytes()))
}

impl<B: StorageBackend + Clone> Storage for Routed<B> {
    async fn blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError> {
        self.backend_for(repo).blob_size(repo, digest).await
    }

    async fn blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        self.backend_for(repo).blob_exists(repo, digest).await
    }

    async fn read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError> {
        self.backend_for(repo).read_blob(repo, digest).await
    }

    async fn open_blob(&self, repo: &str, digest: &Digest) -> Result<BlobRead, StorageError> {
        self.backend_for(repo).open_blob(repo, digest).await
    }

    async fn begin_upload(&self, repo: &str) -> Result<String, StorageError> {
        self.backend_for(repo).begin_upload(repo).await
    }

    async fn append_upload(
        &self,
        repo: &str,
        id: &str,
        chunk: &[u8],
        expected_offset: Option<u64>,
    ) -> Result<u64, StorageError> {
        self.backend_for(repo)
            .append_upload(repo, id, chunk, expected_offset)
            .await
    }

    async fn upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError> {
        self.backend_for(repo).upload_size(repo, id).await
    }

    async fn abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError> {
        self.backend_for(repo).abort_upload(repo, id).await
    }

    async fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        // Cross-backend mount is not supported: the client falls back to a
        // normal upload session.  Within the same backend, delegate normally.
        if !self.same_backend(from_repo, to_repo) {
            return Ok(false);
        }
        self.backend_for(to_repo)
            .mount_blob(from_repo, to_repo, digest)
            .await
    }

    async fn finish_upload(
        &self,
        repo: &str,
        id: &str,
        expected: &Digest,
        max_size: u64,
        trailing: &[u8],
    ) -> Result<(), StorageError> {
        self.backend_for(repo)
            .finish_upload(repo, id, expected, max_size, trailing)
            .await
    }

    async fn put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError> {
        self.backend_for(repo).put_blob(repo, digest, data).await
    }

    async fn delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        self.backend_for(repo).delete_blob(repo, digest).await
    }

    async fn put_manifest(
        &self,
        repo: &str,
        tag: Option<&str>,
        digest: &Digest,
        media_type: &str,
        data: &[u8],
        links: ManifestLinks<'_>,
    ) -> Result<(), StorageError> {
        self.backend_for(repo)
            .put_manifest(repo, tag, digest, media_type, data, links)
            .await
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError> {
        self.backend_for(repo).get_manifest(repo, reference).await
    }

    async fn delete_manifest(&self, repo: &str, digest: &Digest) -> Result<(), StorageError> {
        self.backend_for(repo).delete_manifest(repo, digest).await
    }

    async fn list_tags(
        &self,
        repo: &str,
        last: Option<&str>,
        limit: usize,
    ) -> Result<Page<String>, StorageError> {
        self.backend_for(repo).list_tags(repo, last, limit).await
    }

    async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
        artifact_type: Option<&str>,
        last: Option<&str>,
        limit: usize,
    ) -> Result<Page<Referrer>, StorageError> {
        self.backend_for(repo)
            .list_referrers(repo, subject, artifact_type, last, limit)
            .await
    }
}

impl<B: StorageBackend + Clone> StorageBackend for Routed<B> {
    async fn recover(&self) {
        self.default.recover().await;
        for (_, backend) in &self.routes {
            backend.recover().await;
        }
    }

    fn start_maintenance(&self, shutdown: watch::Receiver<bool>) {
        self.default.start_maintenance(shutdown.clone());
        for (_, backend) in &self.routes {
            backend.start_maintenance(shutdown.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsStorage;

    #[test]
    fn prefix_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);
        // exact match
        assert_eq!(routed.route_index("team"), Some(0));
        // under the prefix
        assert_eq!(routed.route_index("team/app"), Some(0));
    }

    #[test]
    fn prefix_component_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);
        // "teams/x" must NOT match "team" — component boundary check
        assert_eq!(routed.route_index("teams/x"), None);
        assert_eq!(routed.route_index("teamster"), None);
    }

    #[test]
    fn longest_prefix_wins() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let org = FsStorage::new(dir.path().join("org")).unwrap();
        let org_team = FsStorage::new(dir.path().join("org_team")).unwrap();
        let routed = Routed::new(
            default,
            vec![("org".into(), org), ("org/team".into(), org_team)],
        );
        // "org/team/app" matches the longer "org/team" prefix
        assert_eq!(routed.route_index("org/team/app"), Some(0)); // sorted longest-first
        assert_eq!(routed.route_index("org/team"), Some(0));
        // "org/other" matches "org"
        assert_eq!(routed.route_index("org/other"), Some(1));
        // "unrelated" falls to default
        assert_eq!(routed.route_index("unrelated"), None);
    }

    #[test]
    fn default_when_no_routes() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let routed: Routed<FsStorage> = Routed::new(default, vec![]);
        assert_eq!(routed.route_index("anything"), None);
        assert_eq!(routed.route_index("a/b/c"), None);
    }

    #[test]
    fn same_backend_detection() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);
        // Same backend (both under "team")
        assert!(routed.same_backend("team/a", "team/b"));
        // Same backend (both default)
        assert!(routed.same_backend("other/a", "other/b"));
        // Different backends
        assert!(!routed.same_backend("team/a", "other/b"));
        assert!(!routed.same_backend("other/a", "team/b"));
    }

    #[tokio::test]
    async fn delegation_blobs_land_in_correct_root() {
        let dir = tempfile::tempdir().unwrap();
        let default_root = dir.path().join("default");
        let team_root = dir.path().join("team");
        let default = FsStorage::new(&default_root).unwrap();
        let team = FsStorage::new(&team_root).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);

        let data = b"hello world";
        let digest = crate::sha256_of(data);

        // Put a blob into "team/app" → should go into the team root
        routed.put_blob("team/app", &digest, data).await.unwrap();
        assert!(team_root
            .join(format!("team/app/blobs/sha256/{}", digest.hex()))
            .exists());
        assert!(!default_root
            .join(format!("team/app/blobs/sha256/{}", digest.hex()))
            .exists());

        // Put a blob into "other/app" → should go into the default root
        routed.put_blob("other/app", &digest, data).await.unwrap();
        assert!(default_root
            .join(format!("other/app/blobs/sha256/{}", digest.hex()))
            .exists());
    }

    #[tokio::test]
    async fn delegation_manifests_in_correct_root() {
        let dir = tempfile::tempdir().unwrap();
        let default_root = dir.path().join("default");
        let team_root = dir.path().join("team");
        let default = FsStorage::new(&default_root).unwrap();
        let team = FsStorage::new(&team_root).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);

        // A minimal manifest (just enough to be valid JSON with a config blob
        // and zero layers).
        let config_data = b"{}";
        let config_digest = crate::sha256_of(config_data);

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.as_string(),
                "size": config_data.len()
            },
            "layers": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_digest = crate::sha256_of(&manifest_bytes);

        // Store config blob first
        routed
            .put_blob("team/myrepo", &config_digest, config_data)
            .await
            .unwrap();

        // Store manifest in "team/myrepo" → team root
        let refs: Vec<Digest> = vec![config_digest.clone()];
        let links = ManifestLinks {
            references: &refs,
            subject: None,
        };
        routed
            .put_manifest(
                "team/myrepo",
                Some("latest"),
                &manifest_digest,
                "application/vnd.oci.image.manifest.v1+json",
                &manifest_bytes,
                links,
            )
            .await
            .unwrap();

        // The manifest blob lives in the team root
        assert!(team_root
            .join(format!(
                "team/myrepo/blobs/sha256/{}",
                manifest_digest.hex()
            ))
            .exists());

        // Tag resolution works via the routed storage
        let resolved = routed.get_manifest("team/myrepo", "latest").await.unwrap();
        assert_eq!(resolved.digest, manifest_digest);
    }

    #[tokio::test]
    async fn delegation_tags_in_correct_root() {
        let dir = tempfile::tempdir().unwrap();
        let default_root = dir.path().join("default");
        let team_root = dir.path().join("team");
        let default = FsStorage::new(&default_root).unwrap();
        let team = FsStorage::new(&team_root).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);

        // Put a minimal manifest so list_tags has something to return
        let config_data = b"{}";
        let config_digest = crate::sha256_of(config_data);
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.as_string(),
                "size": config_data.len()
            },
            "layers": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_digest = crate::sha256_of(&manifest_bytes);

        routed
            .put_blob("team/app", &config_digest, config_data)
            .await
            .unwrap();
        routed
            .put_manifest(
                "team/app",
                Some("v1"),
                &manifest_digest,
                "application/vnd.oci.image.manifest.v1+json",
                &manifest_bytes,
                ManifestLinks {
                    references: &[config_digest],
                    subject: None,
                },
            )
            .await
            .unwrap();

        let page = routed.list_tags("team/app", None, 100).await.unwrap();
        assert_eq!(page.items, vec!["v1".to_string()]);

        // An unrelated repo in the default root has no tags
        let page = routed.list_tags("unrelated/app", None, 100).await.unwrap();
        assert!(page.items.is_empty());
    }

    #[tokio::test]
    async fn cross_backend_mount_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);

        let data = b"cross-mount-test";
        let digest = crate::sha256_of(data);

        // Put a blob in the default backend
        routed.put_blob("lib/base", &digest, data).await.unwrap();

        // Cross-backend mount from default to "team/app" should return false
        let mounted = routed
            .mount_blob("lib/base", "team/app", &digest)
            .await
            .unwrap();
        assert!(!mounted);
    }

    #[tokio::test]
    async fn same_backend_mount_works() {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);

        let data = b"same-mount-test";
        let digest = crate::sha256_of(data);

        // Put a blob in "team/src"
        routed.put_blob("team/src", &digest, data).await.unwrap();

        // Mount within the same backend → should succeed
        let mounted = routed
            .mount_blob("team/src", "team/dst", &digest)
            .await
            .unwrap();
        assert!(mounted);

        // The blob should be accessible in the destination
        let size = routed.blob_size("team/dst", &digest).await.unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn recover_fans_out() {
        // Just verifies recover completes without panic on multiple backends.
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);
        routed.recover().await;
    }

    #[tokio::test]
    async fn start_maintenance_fans_out() {
        // Verifies start_maintenance completes without panic and tasks stop.
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        let routed = Routed::new(default, vec![("team".into(), team)]);
        let (tx, rx) = watch::channel(false);
        routed.start_maintenance(rx);
        // Signal shutdown so the tasks don't leak.
        let _ = tx.send(true);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
