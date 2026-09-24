//! Storage quotas and the concurrent upload-session cap (SECURITY §Storage
//! boundary "Quota / exhaustion"). One [`QuotaTracker`] is shared by every
//! backend of a registry, so the registry-wide cap spans all subpaths while a
//! repository — routed to exactly one backend — is capped on its own.
//!
//! Accounting is **logical**: a blob counts once per repository that holds it,
//! whether it is stored as its own file or deduplicated via reflink/hard link.
//! That over-approximates physical usage under dedupe, so a cap never admits
//! more than the configured bytes. Byte tracking is only kept when a byte cap
//! is configured (no per-blob `stat` at startup otherwise).

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

    /// Whether byte usage is tracked (some byte cap is configured).
    pub fn tracks_bytes(&self) -> bool {
        self.limits.max_repo_bytes > 0 || self.limits.max_total_bytes > 0
    }

    /// Reserve `size` bytes for a blob entering `repo`, failing without any
    /// change when either cap would be exceeded. Check and charge are one
    /// critical section, so concurrent finalizes cannot jointly overshoot.
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

    /// Count an already-stored blob (startup accounting): no cap check.
    pub fn seed(&self, repo: &str, size: u64) {
        if self.tracks_bytes() {
            self.bytes
                .lock()
                .expect("quota lock poisoned")
                .charge(repo, size);
        }
    }

    /// Return `size` bytes: a blob left `repo`, or an admitted blob was not
    /// stored after all (failed promote / it was already present). An unknown
    /// repo is a no-op, and at most what the repo currently holds is released
    /// from both the per-repo and total counters (prevents undercount from
    /// stale/double cleanup).
    pub fn release(&self, repo: &str, size: u64) {
        if !self.tracks_bytes() {
            return;
        }
        let mut b = self.bytes.lock().expect("quota lock poisoned");
        // Only release what the repo actually holds.
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

    /// Bytes currently accounted to `repo`.
    pub fn repo_bytes(&self, repo: &str) -> u64 {
        let b = self.bytes.lock().expect("quota lock poisoned");
        b.per_repo.get(repo).copied().unwrap_or(0)
    }

    /// Bytes currently accounted registry-wide.
    pub fn total_bytes(&self) -> u64 {
        self.bytes.lock().expect("quota lock poisoned").total
    }

    /// Open one upload session, failing at the concurrent-session cap.
    pub fn begin_session(&self) -> Result<(), StorageError> {
        let limit = self.limits.max_upload_sessions;
        let admitted = self
            .sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (limit == 0 || n < limit).then_some(n + 1)
            });
        match admitted {
            Ok(_) => Ok(()),
            Err(_) => {
                roci_telemetry::record_quota_rejection("sessions");
                Err(StorageError::TooManySessions { limit })
            }
        }
    }

    /// Count sessions found staged at startup: no cap check.
    pub fn seed_sessions(&self, n: usize) {
        self.sessions.fetch_add(n, Ordering::AcqRel);
    }

    /// Close one upload session (its staging file is gone).
    pub fn end_session(&self) {
        let _ = self
            .sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
    }

    /// Upload sessions currently open.
    pub fn sessions(&self) -> usize {
        self.sessions.load(Ordering::Acquire)
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
        // A rejected admission charged nothing.
        assert_eq!((q.repo_bytes("a"), q.total_bytes()), (10, 10));
        q.admit("b", 5).unwrap();
        assert!(matches!(
            q.admit("c", 1),
            Err(StorageError::QuotaExceeded {
                scope: QuotaScope::Total,
                ..
            })
        ));
        // Releasing makes room again; an emptied repo drops out.
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
        // Releasing from an unknown repo changes nothing.
        q.release("unknown", 10);
        assert_eq!(q.total_bytes(), 10);
        assert_eq!(q.repo_bytes("a"), 10);
    }

    #[test]
    fn release_caps_at_repo_holding() {
        let q = limits(100, 200, 0);
        q.admit("a", 10).unwrap();
        q.admit("b", 20).unwrap();
        // Release more than repo "a" holds: only 10 released from total.
        q.release("a", 50);
        assert_eq!(q.repo_bytes("a"), 0);
        assert_eq!(q.total_bytes(), 20); // only b's 20 remain
    }

    #[test]
    fn double_release_does_not_undercount_total() {
        let q = limits(100, 200, 0);
        q.admit("a", 10).unwrap();
        q.release("a", 10);
        // Second release: repo "a" is gone → no-op.
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
        // Seeded (pre-existing) sessions count against the cap.
        q.seed_sessions(2);
        assert!(q.begin_session().is_err());
        // Zero means unlimited.
        let u = limits(0, 0, 0);
        for _ in 0..100 {
            u.begin_session().unwrap();
        }
    }
}
