//! Background task scheduler (ARCHITECTURE §Background task scheduler).

use super::super::FsStorage;
use crate::storage::{spawn_periodic, StorageBackend};
use std::time::Duration;
use tokio::sync::watch;

/// Metadata upkeep period (compaction/snapshot check).
const METADATA_UPKEEP_PERIOD: Duration = Duration::from_secs(30);
impl StorageBackend for FsStorage {
    /// Recover referrers and reconcile `index.json` (write-behind crash recovery).
    async fn recover(&self) {
        self.warm_referrers_from_layout().await;
        self.reconcile_index_json().await;
    }

    fn start_maintenance(&self, shutdown: watch::Receiver<bool>) {
        FsStorage::start_maintenance(self, shutdown);
    }

    fn on_shutdown(&self) {
        if self.config.fast_restart {
            if let Err(e) = self.write_fast_restart_stamp() {
                tracing::warn!(error = %e, "fast restart: failed to write stamp");
            } else {
                tracing::info!("fast restart: stamp written");
            }
        }
    }
}

impl FsStorage {
    /// Start enabled background subsystems; call once after recovery.
    pub fn start_maintenance(&self, shutdown: watch::Receiver<bool>) {
        tracing::info!(
            root = %self.root.display(),
            gc = self.config.gc.enabled,
            scrub = self.config.scrub.enabled,
            dedupe = self.config.dedupe,
            "storage maintenance started"
        );
        spawn_periodic(
            self.clone(),
            "metadata.maintain",
            METADATA_UPKEEP_PERIOD,
            shutdown.clone(),
            |s| async move {
                let meta = s.meta.clone();
                let span = tracing::Span::current();
                match tokio::task::spawn_blocking(move || {
                    let _guard = span.enter();
                    meta.maintain()
                })
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!(error = %e, "metadata upkeep failed"),
                    Err(e) => tracing::warn!(error = %e, "metadata upkeep panicked"),
                }
            },
        );
        if self.gc.enabled() {
            self.start_gc(shutdown.clone());
        }
        if self.config.scrub.enabled {
            self.start_scrub(shutdown.clone());
        }
    }
}
