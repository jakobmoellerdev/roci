use super::*;
use crate::quota::{QuotaLimits, QuotaTracker};
use crate::storage::{Storage, StorageBackend};
use roci_config::{GcConfig, StorageConfig};
use std::sync::Arc;

fn fr_store(quota: QuotaLimits) -> (tempfile::TempDir, FsStorage) {
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
    let s =
        FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::new(quota))).unwrap();
    (dir, s)
}

fn reopen(dir: &std::path::Path, quota: QuotaLimits) -> FsStorage {
    let config = StorageConfig {
        fast_restart: true,
        gc: GcConfig {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        },
        ..StorageConfig::default()
    };
    FsStorage::with_config(dir, &config, Arc::new(QuotaTracker::new(quota))).unwrap()
}

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

const QUOTA: QuotaLimits = QuotaLimits {
    max_repo_bytes: 10_000_000,
    max_total_bytes: 100_000_000,
    max_upload_sessions: 1024,
};

#[tokio::test]
async fn fast_restart_restores_all_state() {
    let (dir, s) = fr_store(QuotaLimits::default());
    let data = b"layer content A";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    assert!(!s.gc.is_empty(), "blob should be a GC candidate");

    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let s2 = reopen(dir.path(), QuotaLimits::default());
    // Presence + dedupe restored.
    assert!(s2.presence.maybe_present("repo", &d.as_string()));
    assert!(s2.dedupe.locate(&d.as_string(), "other").is_some());
    // GC candidates + roots restored.
    assert!(s2.gc.is_ready());
    assert!(!s2.gc.is_empty());
}

#[tokio::test]
async fn fast_restart_restores_quota_bytes() {
    let (dir, s) = fr_store(QUOTA);
    let data = b"12345678";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    let repo_bytes = s.quota.repo_bytes("repo");
    assert!(repo_bytes > 0);
    let total = s.quota.total_bytes();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let s2 = reopen(dir.path(), QUOTA);
    assert_eq!(s2.quota.repo_bytes("repo"), repo_bytes);
    assert_eq!(s2.quota.total_bytes(), total);
}

#[tokio::test]
async fn fast_restart_skip_proof_oob_blob_not_seen() {
    let (dir, s) = fr_store(QuotaLimits::default());
    let data = b"original blob";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let oob_data = b"oob blob content";
    let oob_d = sha256_of(oob_data);
    let oob_dir = dir.path().join("repo/blobs/sha256");
    std::fs::create_dir_all(&oob_dir).unwrap();
    std::fs::write(oob_dir.join(oob_d.hex()), oob_data).unwrap();

    let s2 = reopen(dir.path(), QuotaLimits::default());
    assert!(
        !s2.presence.maybe_present("repo", &oob_d.as_string()),
        "OOB blob should not be seen on fast restart"
    );

    let s3 = reopen_cold(dir.path());
    assert!(
        s3.presence.maybe_present("repo", &oob_d.as_string()),
        "OOB blob should be seen on cold start"
    );
}

#[tokio::test]
async fn stamp_fallback_paths() {
    struct Row {
        label: &'static str,
        write_stamp: bool,
        corrupt: Option<fn(&mut Vec<u8>)>,
        hmac_key: bool,
        changed_dedupe: bool,
    }
    let cases = [
        Row {
            label: "missing_stamp",
            write_stamp: false,
            corrupt: None,
            hmac_key: false,
            changed_dedupe: false,
        },
        Row {
            label: "corrupted_stamp",
            write_stamp: true,
            corrupt: Some(|b: &mut Vec<u8>| {
                if let Some(last) = b.last_mut() {
                    *last ^= 0xFF;
                }
            }),
            hmac_key: false,
            changed_dedupe: false,
        },
        Row {
            label: "config_mismatch",
            write_stamp: true,
            corrupt: None,
            hmac_key: false,
            changed_dedupe: true,
        },
        Row {
            label: "hmac_tampered",
            write_stamp: true,
            corrupt: Some(|b: &mut Vec<u8>| {
                b[10] ^= 0xFF;
            }),
            hmac_key: true,
            changed_dedupe: false,
        },
    ];
    for row in &cases {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("hmac.key");
        if row.hmac_key {
            std::fs::write(&key_path, [0xABu8; 64]).unwrap();
        }
        let config = StorageConfig {
            fast_restart: true,
            dedupe: !row.changed_dedupe,
            metadata: roci_config::MetadataConfig {
                hmac_key_file: if row.hmac_key {
                    Some(key_path.clone())
                } else {
                    None
                },
                ..roci_config::MetadataConfig::default()
            },
            gc: GcConfig {
                enabled: true,
                delay_secs: 3600,
                interval_secs: 3600,
            },
            ..StorageConfig::default()
        };
        let s =
            FsStorage::with_config(dir.path(), &config, Arc::new(QuotaTracker::default())).unwrap();
        let data = b"payload";
        let d = sha256_of(data);
        s.put_blob("repo", &d, data).await.unwrap();
        if row.write_stamp {
            s.write_fast_restart_stamp().unwrap();
        }
        drop(s);

        let stamp_path = dir.path().join(".roci-fast-restart");
        if let Some(corrupt_fn) = row.corrupt {
            let mut bytes = std::fs::read(&stamp_path).unwrap();
            corrupt_fn(&mut bytes);
            std::fs::write(&stamp_path, &bytes).unwrap();
        }

        // Reopen with potentially changed config → falls back to full walk.
        let config2 = StorageConfig {
            fast_restart: true,
            dedupe: true, // for config_mismatch this differs from the original
            metadata: roci_config::MetadataConfig {
                hmac_key_file: if row.hmac_key { Some(key_path) } else { None },
                ..roci_config::MetadataConfig::default()
            },
            gc: GcConfig {
                enabled: true,
                delay_secs: 3600,
                interval_secs: 3600,
            },
            ..StorageConfig::default()
        };
        let s2 = FsStorage::with_config(dir.path(), &config2, Arc::new(QuotaTracker::default()))
            .unwrap();
        assert!(
            s2.presence.maybe_present("repo", &d.as_string()),
            "{}",
            row.label
        );
        if row.corrupt.is_some() {
            assert!(
                !stamp_path.exists(),
                "{}: corrupted stamp should be consumed",
                row.label
            );
        }
    }
}

#[tokio::test]
async fn stamp_consumed_on_start_crash_forces_full_walk() {
    let (dir, s) = fr_store(QuotaLimits::default());
    let data = b"crash test";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.write_fast_restart_stamp().unwrap();
    drop(s);

    let stamp_path = dir.path().join(".roci-fast-restart");
    assert!(stamp_path.exists());
    let s2 = reopen(dir.path(), QuotaLimits::default());
    drop(s2);
    assert!(!stamp_path.exists());

    let oob_data = b"oob after crash";
    let oob_d = sha256_of(oob_data);
    let oob_dir = dir.path().join("repo/blobs/sha256");
    std::fs::write(oob_dir.join(oob_d.hex()), oob_data).unwrap();

    let s3 = reopen(dir.path(), QuotaLimits::default());
    assert!(s3.presence.maybe_present("repo", &oob_d.as_string()));
}

#[tokio::test]
async fn on_shutdown_writes_stamp_when_enabled() {
    let (dir, s) = fr_store(QuotaLimits::default());
    let data = b"shutdown test";
    let d = sha256_of(data);
    s.put_blob("repo", &d, data).await.unwrap();
    s.on_shutdown();
    assert!(dir.path().join(".roci-fast-restart").exists());
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
    assert!(!dir.path().join(".roci-fast-restart").exists());
}
