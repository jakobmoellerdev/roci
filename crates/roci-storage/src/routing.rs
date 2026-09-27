//! Multi-backend routing: dispatches to the longest component-prefix match.

use crate::metadata::{Page, Referrer};
use crate::storage::{BlobRead, ManifestLinks, ManifestRef, Storage, StorageBackend};
use crate::{Digest, StorageError};
use tokio::sync::watch;

/// Sorted route table: `(prefix, backend)`, longest-first.
#[derive(Clone)]
pub struct Routed<B> {
    default: B,
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
    /// Build a routing table; routes sorted longest-first.
    pub fn new(default: B, mut routes: Vec<(String, B)>) -> Self {
        routes.sort_by_key(|r| std::cmp::Reverse(r.0.len()));
        Self { default, routes }
    }

    /// Return the backend serving `repo` (longest matching prefix).
    fn backend_for(&self, repo: &str) -> &B {
        for (prefix, backend) in &self.routes {
            if matches_prefix(repo, prefix) {
                return backend;
            }
        }
        &self.default
    }

    /// Whether both repos resolve to the same backend.
    fn same_backend(&self, from_repo: &str, to_repo: &str) -> bool {
        self.route_index(from_repo) == self.route_index(to_repo)
    }

    fn route_index(&self, repo: &str) -> Option<usize> {
        for (i, (prefix, _)) in self.routes.iter().enumerate() {
            if matches_prefix(repo, prefix) {
                return Some(i);
            }
        }
        None
    }
}

/// Component-boundary prefix match, allocation-free.
#[inline]
fn matches_prefix(repo: &str, prefix: &str) -> bool {
    repo == prefix
        || (repo.len() > prefix.len()
            && repo.as_bytes()[prefix.len()] == b'/'
            && repo.as_bytes().starts_with(prefix.as_bytes()))
}

macro_rules! route {
    ($method:ident(&self, repo: &str $(, $arg:ident : $ty:ty)*) -> $ret:ty) => {
        async fn $method(&self, repo: &str $(, $arg: $ty)*) -> $ret {
            self.backend_for(repo).$method(repo $(, $arg)*).await
        }
    };
}

impl<B: StorageBackend + Clone> Storage for Routed<B> {
    route!(blob_size(&self, repo: &str, digest: &Digest) -> Result<u64, StorageError>);
    route!(blob_exists(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError>);
    route!(read_blob(&self, repo: &str, digest: &Digest) -> Result<Vec<u8>, StorageError>);
    route!(open_blob(&self, repo: &str, digest: &Digest) -> Result<BlobRead, StorageError>);
    route!(begin_upload(&self, repo: &str) -> Result<String, StorageError>);
    route!(append_upload(&self, repo: &str, id: &str, body: crate::UploadBody, expected_offset: Option<u64>, limit: u64) -> Result<u64, StorageError>);
    route!(upload_size(&self, repo: &str, id: &str) -> Result<u64, StorageError>);
    route!(abort_upload(&self, repo: &str, id: &str) -> Result<bool, StorageError>);

    async fn mount_blob(
        &self,
        from_repo: &str,
        to_repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        if !self.same_backend(from_repo, to_repo) {
            return Ok(false);
        }
        self.backend_for(to_repo)
            .mount_blob(from_repo, to_repo, digest)
            .await
    }

    route!(finish_upload(&self, repo: &str, id: &str, expected: &Digest, max_size: u64, trailing: crate::UploadBody, limit: u64) -> Result<(), StorageError>);
    route!(put_blob(&self, repo: &str, digest: &Digest, data: &[u8]) -> Result<(), StorageError>);
    route!(delete_blob(&self, repo: &str, digest: &Digest) -> Result<(), StorageError>);
    route!(put_manifest(&self, repo: &str, tag: Option<&str>, digest: &Digest, media_type: &str, data: &[u8], links: ManifestLinks<'_>) -> Result<(), StorageError>);
    route!(get_manifest(&self, repo: &str, reference: &str) -> Result<ManifestRef, StorageError>);
    route!(delete_manifest(&self, repo: &str, digest: &Digest) -> Result<(), StorageError>);
    route!(list_tags(&self, repo: &str, last: Option<&str>, limit: usize) -> Result<Page<String>, StorageError>);
    route!(list_referrers(&self, repo: &str, subject: &Digest, artifact_type: Option<&str>, last: Option<&str>, limit: usize) -> Result<Page<Referrer>, StorageError>);
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

    fn on_shutdown(&self) {
        self.default.on_shutdown();
        for (_, backend) in &self.routes {
            backend.on_shutdown();
        }
    }

    async fn ready(&self) -> Result<(), StorageError> {
        self.default.ready().await?;
        for (_, backend) in &self.routes {
            backend.ready().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsStorage;

    fn routed_fixture() -> (tempfile::TempDir, Routed<FsStorage>) {
        let dir = tempfile::tempdir().unwrap();
        let default = FsStorage::new(dir.path().join("default")).unwrap();
        let team = FsStorage::new(dir.path().join("team")).unwrap();
        (dir, Routed::new(default, vec![("team".into(), team)]))
    }

    #[test]
    fn prefix_matching_rules() {
        let (_dir, routed) = routed_fixture();
        assert_eq!(routed.route_index("team"), Some(0), "exact match");
        assert_eq!(routed.route_index("team/app"), Some(0), "under prefix");
        assert_eq!(
            routed.route_index("teams/x"),
            None,
            "no partial component match"
        );
        assert_eq!(
            routed.route_index("teamster"),
            None,
            "no partial component match 2"
        );
        let dir2 = tempfile::tempdir().unwrap();
        let default2 = FsStorage::new(dir2.path().join("default")).unwrap();
        let empty: Routed<FsStorage> = Routed::new(default2, vec![]);
        assert_eq!(empty.route_index("anything"), None, "empty routes");
        assert_eq!(empty.route_index("a/b/c"), None, "empty routes nested");
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
        assert_eq!(routed.route_index("org/team/app"), Some(0));
        assert_eq!(routed.route_index("org/team"), Some(0));
        assert_eq!(routed.route_index("org/other"), Some(1));
        assert_eq!(routed.route_index("unrelated"), None);
    }

    #[test]
    fn same_backend_detection() {
        let (_dir, routed) = routed_fixture();
        assert!(routed.same_backend("team/a", "team/b"));
        assert!(routed.same_backend("other/a", "other/b"));
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

        routed.put_blob("team/app", &digest, data).await.unwrap();
        assert!(team_root
            .join(format!("team/app/blobs/sha256/{}", digest.hex()))
            .exists());
        assert!(!default_root
            .join(format!("team/app/blobs/sha256/{}", digest.hex()))
            .exists());

        routed.put_blob("other/app", &digest, data).await.unwrap();
        assert!(default_root
            .join(format!("other/app/blobs/sha256/{}", digest.hex()))
            .exists());
    }

    #[tokio::test]
    async fn cross_backend_mount_returns_false() {
        let (_dir, routed) = routed_fixture();

        let data = b"cross-mount-test";
        let digest = crate::sha256_of(data);
        routed.put_blob("lib/base", &digest, data).await.unwrap();

        let mounted = routed
            .mount_blob("lib/base", "team/app", &digest)
            .await
            .unwrap();
        assert!(!mounted);
    }

    #[tokio::test]
    async fn same_backend_mount_works() {
        let (_dir, routed) = routed_fixture();

        let data = b"same-mount-test";
        let digest = crate::sha256_of(data);
        routed.put_blob("team/src", &digest, data).await.unwrap();

        let mounted = routed
            .mount_blob("team/src", "team/dst", &digest)
            .await
            .unwrap();
        assert!(mounted);
        let size = routed.blob_size("team/dst", &digest).await.unwrap();
        assert_eq!(size, data.len() as u64);
    }
}
