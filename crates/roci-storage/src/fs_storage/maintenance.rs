//! The background task scheduler (ARCHITECTURE §Background task scheduler):
//! one place that owns every periodic storage task — metadata upkeep (log
//! compaction / snapshot cut), GC sweeps, scrub passes. Each task is a single
//! Tokio task (a bounded pool by construction: one per subsystem), runs its
//! blocking filesystem work off the async workers, is its own span tree, and
//! exits when the shutdown signal flips.

use super::super::FsStorage;
use crate::storage::StorageBackend;
use std::future::Future;
use std::time::Duration;
use tokio::sync::watch;
use tracing::Instrument;

/// How often the metadata engine is offered upkeep (it decides whether any
/// compaction/snapshot is actually due, so a tick is cheap).
const METADATA_UPKEEP_PERIOD: Duration = Duration::from_secs(30);

impl StorageBackend for FsStorage {
    /// Register pre-existing `subject` links (referrers upgrade), then
    /// reconcile `index.json` with the replayed metadata log (write-behind
    /// crash recovery, foreign-tag import).
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
    /// Start the enabled background subsystems. Call once, after startup
    /// recovery (`warm_referrers_from_layout`, `reconcile_index_json`) and
    /// before serving; every task stops when `shutdown` becomes `true`.
    pub fn start_maintenance(&self, shutdown: watch::Receiver<bool>) {
        tracing::info!(
            root = %self.root.display(),
            gc = self.config.gc.enabled,
            scrub = self.config.scrub.enabled,
            dedupe = self.config.dedupe,
            "storage maintenance started"
        );
        self.spawn_periodic(
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

    /// Run `task` every `period` (first run one period after start) until
    /// `shutdown` flips. A slow run delays the next tick instead of bursting.
    pub(super) fn spawn_periodic<F, Fut>(
        &self,
        name: &'static str,
        period: Duration,
        mut shutdown: watch::Receiver<bool>,
        task: F,
    ) where
        F: Fn(FsStorage) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticks.tick() => {
                        task(store.clone())
                            .instrument(tracing::info_span!("storage.maintenance", task = name))
                            .await;
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }
}
