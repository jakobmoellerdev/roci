//! Storage quotas and upload-session cap (SECURITY §Storage boundary
//! "Quota / exhaustion"). Logical accounting: per-repo + registry-wide.

use crate::error::{QuotaScope, StorageError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Configured caps; `0` means unlimited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaLimits {
    pub max_repo_bytes: u64,
    pub max_total_bytes: u64,
    pub max_upload_sessions: usize,
}

/// Byte + session accounting enforcing [`QuotaLimits`].
#[derive(Debug, Default)]
pub struct QuotaTracker {
    limits: QuotaLimits,
    bytes: Mutex<Bytes>,
    sessions: AtomicUsize,
}

#[derive(Debug, Default)]
struct Bytes {
    per_repo: HashMap<String, u64>,
    total: u64,
}

impl QuotaTracker {
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    pub fn tracks_bytes(&self) -> bool {
        self.limits.max_repo_bytes > 0 || self.limits.max_total_bytes > 0
    }

    /// Reserve `size` bytes, failing atomically if either cap is exceeded.
    pub fn admit(&self, repo: &str, size: u64) -> Result<(), StorageError> {
        if !self.tracks_bytes() {
            return Ok(());
        }
        let mut b = self.bytes.lock().expect("quota lock poisoned");
        let repo_now = b.per_repo.get(repo).copied().unwrap_or(0);
        let checks = [
            (QuotaScope::Repository, self.limits.max_repo_bytes, repo_now),
            (QuotaScope::Total, self.limits.max_total_bytes, b.total),
        ];
        for (scope, limit, used) in checks {
            if limit > 0 && used.saturating_add(size) > limit {
                roci_telemetry::record_quota_rejection(scope_label(scope));
                return Err(StorageError::QuotaExceeded {
                    scope,
                    limit,
                    requested: size,
                });
            }
        }
        b.charge(repo, size);
        Ok(())
    }

    /// Count an already-stored blob (startup); no cap check.
    pub fn seed(&self, repo: &str, size: u64) {
        if self.tracks_bytes() {
            self.bytes
                .lock()
                .expect("quota lock poisoned")
                .charge(repo, size);
        }
    }

    /// Return `size` bytes (capped at what `repo` holds).
    pub fn release(&self, repo: &str, size: u64) {
        if !self.tracks_bytes() {
            return;
        }
        let mut b = self.bytes.lock().expect("quota lock poisoned");
        let Some(used) = b.per_repo.get_mut(repo) else {
            return; // unknown repo → no-op
        };
        let actual = size.min(*used);
        *used = used.saturating_sub(actual);
        if *used == 0 {
            b.per_repo.remove(repo);
        }
        b.total = b.total.saturating_sub(actual);
    }

    pub fn repo_bytes(&self, repo: &str) -> u64 {
        let b = self.bytes.lock().expect("quota lock poisoned");
        b.per_repo.get(repo).copied().unwrap_or(0)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes.lock().expect("quota lock poisoned").total
    }

    pub fn begin_session(&self) -> Result<(), StorageError> {
        let limit = self.limits.max_upload_sessions;
        let admitted = self
            .sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (limit == 0 || n < limit).then_some(n + 1)
            });
        match admitted {
            Ok(_) => {
                roci_telemetry::record_upload_active(1);
                Ok(())
            }
            Err(_) => {
                roci_telemetry::record_quota_rejection("sessions");
                Err(StorageError::TooManySessions { limit })
            }
        }
    }

    pub fn seed_sessions(&self, n: usize) {
        self.sessions.fetch_add(n, Ordering::AcqRel);
        roci_telemetry::record_upload_active(i64::try_from(n).unwrap_or(i64::MAX));
    }

    pub fn end_session(&self) {
        let closed = self
            .sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        if closed.is_ok() {
            roci_telemetry::record_upload_active(-1);
        }
    }

    pub fn sessions(&self) -> usize {
        self.sessions.load(Ordering::Acquire)
    }
    /// Per-repo byte snapshot for fast-restart.
    pub fn per_repo_bytes(&self) -> Vec<(String, u64)> {
        self.bytes
            .lock()
            .expect("quota lock poisoned")
            .per_repo
            .iter()
            .map(|(r, b)| (r.clone(), *b))
            .collect()
    }
}

impl Bytes {
    fn charge(&mut self, repo: &str, size: u64) {
        self.total = self.total.saturating_add(size);
        let used = self.per_repo.entry(repo.to_string()).or_insert(0);
        *used = used.saturating_add(size);
    }
}

fn scope_label(scope: QuotaScope) -> &'static str {
    match scope {
        QuotaScope::Repository => "repository",
        QuotaScope::Total => "total",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(repo: u64, total: u64, sessions: usize) -> QuotaTracker {
        QuotaTracker::new(QuotaLimits {
            max_repo_bytes: repo,
            max_total_bytes: total,
            max_upload_sessions: sessions,
        })
    }

    #[test]
    fn repo_cap_is_checked_before_total_and_admission_is_all_or_nothing() {
        let q = limits(10, 15, 0);
        q.admit("a", 10).unwrap();
        let err = q.admit("a", 1).unwrap_err();
        assert!(matches!(
            err,
            StorageError::QuotaExceeded {
                scope: QuotaScope::Repository,
                limit: 10,
                requested: 1
            }
        ));
        assert_eq!((q.repo_bytes("a"), q.total_bytes()), (10, 10));
        q.admit("b", 5).unwrap();
        assert!(matches!(
            q.admit("c", 1),
            Err(StorageError::QuotaExceeded {
                scope: QuotaScope::Total,
                ..
            })
        ));
        q.release("a", 10);
        assert_eq!(q.repo_bytes("a"), 0);
        q.admit("c", 1).unwrap();
        assert_eq!(q.total_bytes(), 6);
    }

    #[test]
    fn exact_fit_is_admitted() {
        let q = limits(4, 0, 0);
        q.admit("a", 4).unwrap();
        assert!(q.admit("a", 1).is_err());
    }

    #[test]
    fn unlimited_tracks_nothing() {
        let q = limits(0, 0, 0);
        assert!(!q.tracks_bytes());
        q.admit("a", u64::MAX).unwrap();
        q.seed("a", 5);
        assert_eq!(q.total_bytes(), 0);
    }

    #[test]
    fn seed_bypasses_caps_and_release_saturates() {
        let q = limits(1, 1, 0);
        q.seed("a", 5);
        assert_eq!(q.total_bytes(), 5);
        q.release("a", 50);
        assert_eq!((q.repo_bytes("a"), q.total_bytes()), (0, 0));
    }

    #[test]
    fn release_unknown_repo_is_noop() {
        let q = limits(100, 200, 0);
        q.admit("a", 10).unwrap();
        q.release("unknown", 10);
        assert_eq!(q.total_bytes(), 10);
        assert_eq!(q.repo_bytes("a"), 10);
    }

    #[test]
    fn release_caps_at_repo_holding() {
        let q = limits(100, 200, 0);
        q.admit("a", 10).unwrap();
        q.admit("b", 20).unwrap();
        q.release("a", 50);
        assert_eq!(q.repo_bytes("a"), 0);
        assert_eq!(q.total_bytes(), 20); // only b's 20 remain
    }

    #[test]
    fn double_release_does_not_undercount_total() {
        let q = limits(100, 200, 0);
        q.admit("a", 10).unwrap();
        q.release("a", 10);
        q.release("a", 10);
        assert_eq!(q.total_bytes(), 0);
    }

    #[test]
    fn session_cap_admits_up_to_limit_and_end_never_underflows() {
        let q = limits(0, 0, 2);
        q.begin_session().unwrap();
        q.begin_session().unwrap();
        assert!(matches!(
            q.begin_session(),
            Err(StorageError::TooManySessions { limit: 2 })
        ));
        q.end_session();
        q.begin_session().unwrap();
        for _ in 0..5 {
            q.end_session();
        }
        assert_eq!(q.sessions(), 0);
        q.seed_sessions(2);
        assert!(q.begin_session().is_err());
        let u = limits(0, 0, 0);
        for _ in 0..100 {
            u.begin_session().unwrap();
        }
    }
}
