//! Tests for the zot-style fast-restart stamp: write on graceful shutdown,
//! restore on startup, skip the CAS walk.

use super::*;
use crate::quota::{QuotaLimits, QuotaTracker};
use crate::storage::{Storage, StorageBackend};
use roci_config::{GcConfig, StorageConfig};
use std::sync::Arc;

/// Create a store with fast_restart enabled and GC enabled.
fn fr_store() -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig {
        fast_restart: true,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    (dir, s)
}

/// Create a store with fast_restart enabled and byte quotas.
fn fr_store_with_quota() -> (tempfile::TempDir, FsStorage) {
    let dir = tempfile::tempdir().unwrap();
    let quota = QuotaTracker::new(QuotaLimits {
        max_repo_bytes: 10_000_000,
        max_total_bytes: 100_000_000,
        max_upload_sessions: 1024,
    });
    let config = StorageConfig {
        fast_restart: true,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(quota)).unwrap();
    (dir, s)
}

/// Reopen a store at the same root with fast_restart enabled.
fn reopen(dir: &std::path::Path, with_quota: bool) -> FsStorage {
    let quota = if with_quota {
        QuotaTracker::new(QuotaLimits {
            max_repo_bytes: 10_000_000,
            max_total_bytes: 100_000_000,
            max_upload_sessions: 1024,
        })
    } else {
        QuotaTracker::default()
    };
    let config = StorageConfig {
        fast_restart: true,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    FsStorage::with_config(dir, &config, Arc::new(quota)).unwrap()
}

/// Reopen without fast_restart.
fn reopen_cold(dir: &std::path::Path) -> FsStorage {
    let config = StorageConfig {
        fast_restart: false,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    FsStorage::with_config(dir, &config, Arc::new(QuotaTracker::default())).unwrap()
}

// ── happy path ────────────────────────────────────────────────────────

#[tokio::test]
async fn fast_restart_restores_presence_and_dedupe() {
    let (dir, s) = fr_store();

    // Push a blob.
    let data = b"layer content A";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();

    // Write the stamp and drop the store.
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    // Reopen with fast_restart: the blob should be present (presence filter
    // seeded from the stamp, not from a CAS walk).
    let s2 = reopen(dir.path(), false);
    assert!(s2.presence.maybe_present("repo", &d.as_string()));
    // Dedupe should know about it too.
    assert!(s2.dedupe.locate(&d.as_string(), "other").is_some());
}

#[tokio::test]
async fn fast_restart_restores_quota_bytes() {
    let (dir, s) = fr_store_with_quota();

    let data = b"12345678"; // 8 bytes
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();

    let repo_bytes = s.quota.repo_bytes("repo");
    assert!(repo_bytes > 0);
    let total = s.quota.total_bytes();

    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let s2 = reopen(dir.path(), true);
    assert_eq!(s2.quota.repo_bytes("repo"), repo_bytes);
    assert_eq!(s2.quota.total_bytes(), total);
}

#[tokio::test]
async fn fast_restart_restores_gc_candidates_and_roots() {
    let (dir, s) = fr_store();

    // Push an unreferenced blob → GC candidate.
    let data = b"candidate blob";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    assert!(!s.gc.is_empty(), "blob should be a GC candidate");

    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let s2 = reopen(dir.path(), false);
    // GC should be ready (set by apply_stamp).
    assert!(s2.gc.is_ready());
    // The candidate should be restored.
    assert!(!s2.gc.is_empty());
}

#[tokio::test]
async fn fast_restart_skip_proof_oob_blob_not_seen() {
    let (dir, s) = fr_store();

    let data = b"original blob";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();

    s.write_fast_restart_stamp().unwrap();
    drop(s);

    // Plant an out-of-band blob in the CAS between runs.
    let oob_data = b"oob blob content";
    let oob_d = sha256_of(oob_data);
    let oob_dir = dir.path().join("repo").join("blobs").join("sha256");
    std::fs::create_dir_all(&oob_dir).unwrap();
    let hex = oob_d
        .as_string()
        .strip_prefix("sha256:")
        .unwrap()
        .to_string();
    std::fs::write(oob_dir.join(&hex), oob_data).unwrap();

    // Reopen with fast_restart: the OOB blob should NOT be in the presence
    // filter (proves the walk was skipped).
    let s2 = reopen(dir.path(), false);
    assert!(
        !s2.presence.maybe_present("repo", &oob_d.as_string()),
        "OOB blob should not be seen on fast restart"
    );

    // Reopen WITHOUT fast_restart: the OOB blob IS seen (full walk).
    let s3 = reopen_cold(dir.path());
    assert!(
        s3.presence.maybe_present("repo", &oob_d.as_string()),
        "OOB blob should be seen on cold start"
    );
}

// ── fallback paths ────────────────────────────────────────────────────

#[tokio::test]
async fn missing_stamp_falls_back_to_full_walk() {
    let (dir, s) = fr_store();

    let data = b"some data";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    // Do NOT write a stamp.
    drop(s);

    // Reopen: should still find the blob via full walk.
    let s2 = reopen(dir.path(), false);
    assert!(s2.presence.maybe_present("repo", &d.as_string()));
}

#[tokio::test]
async fn corrupted_stamp_falls_back_to_full_walk() {
    let (dir, s) = fr_store();

    let data = b"payload";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    // Corrupt the stamp file.
    let stamp_path = dir.path().join(".roci-fast-restart");
    let mut bytes = std::fs::read(&stamp_path).unwrap();
    if let Some(b) = bytes.last_mut() {
        *b ^= 0xFF;
    }
    std::fs::write(&stamp_path, &bytes).unwrap();

    // Reopen: the stamp should be rejected and the blob found via full walk.
    let s2 = reopen(dir.path(), false);
    assert!(s2.presence.maybe_present("repo", &d.as_string()));
    // The stamp file should be consumed (removed).
    assert!(!stamp_path.exists());
}

#[tokio::test]
async fn config_mismatch_falls_back_to_full_walk() {
    let dir = tempfile::tempdir().unwrap();
    let config1 = StorageConfig {
        fast_restart: true,
        dedupe: true,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s =
        FsStorage::with_config(dir.path(), &config1, Arc::new(QuotaTracker::default())).unwrap();
    let data = b"config test";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    // Reopen with a different config (dedupe toggled).
    let config2 = StorageConfig {
        fast_restart: true,
        dedupe: false,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s2 =
        FsStorage::with_config(dir.path(), &config2, Arc::new(QuotaTracker::default())).unwrap();
    // Blob should still be found (fell back to full walk).
    assert!(s2.presence.maybe_present("repo", &d.as_string()));
}

#[tokio::test]
async fn stamp_consumed_on_start_crash_forces_full_walk() {
    let (dir, s) = fr_store();

    let data = b"crash test";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let stamp_path = dir.path().join(".roci-fast-restart");
    assert!(stamp_path.exists());

    // First reopen: consumes the stamp.
    let s2 = reopen(dir.path(), false);
    drop(s2);

    // Stamp should be gone.
    assert!(!stamp_path.exists());

    // Plant an OOB blob.
    let oob_data = b"oob after crash";
    let oob_d = sha256_of(oob_data);
    let oob_dir = dir.path().join("repo").join("blobs").join("sha256");
    let hex = oob_d
        .as_string()
        .strip_prefix("sha256:")
        .unwrap()
        .to_string();
    std::fs::write(oob_dir.join(&hex), oob_data).unwrap();

    // Second reopen (no stamp → full walk): OOB blob IS seen.
    let s3 = reopen(dir.path(), false);
    assert!(s3.presence.maybe_present("repo", &oob_d.as_string()));
}

#[tokio::test]
async fn hmac_tampered_stamp_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("hmac.key");
    std::fs::write(&key_path, [0xABu8; 64]).unwrap();

    let config = StorageConfig {
        fast_restart: true,
        metadata: roci_config::MetadataConfig {
            hmac_key_file: Some(key_path.clone()),
            ..roci_config::MetadataConfig::default()
        },
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    let data = b"hmac test";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    // Tamper with the stamp.
    let stamp_path = dir.path().join(".roci-fast-restart");
    let mut bytes = std::fs::read(&stamp_path).unwrap();
    bytes[10] ^= 0xFF;
    std::fs::write(&stamp_path, &bytes).unwrap();

    // Reopen: HMAC check fails, falls back to full walk.
    let s2 =
        FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    assert!(s2.presence.maybe_present("repo", &d.as_string()));
}

// ── on_shutdown integration ───────────────────────────────────────────

#[tokio::test]
async fn on_shutdown_writes_stamp_when_enabled() {
    let (dir, s) = fr_store();
    let data = b"shutdown test";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();

    s.on_shutdown();

    let stamp_path = dir.path().join(".roci-fast-restart");
    assert!(stamp_path.exists());
}

#[tokio::test]
async fn on_shutdown_skips_stamp_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let config = StorageConfig {
        fast_restart: false,
        ..StorageConfig::default()
    };
    let s = FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
    s.on_shutdown();

    let stamp_path = dir.path().join(".roci-fast-restart");
    assert!(!stamp_path.exists());
}
