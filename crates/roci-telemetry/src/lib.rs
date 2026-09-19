//! Telemetry setup for roci: tracing/log/metric initialization helpers.
#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

/// Initialize a tracing subscriber honoring `RUST_LOG` (defaulting to `info`).
/// Idempotent-safe: a second call is a no-op if a subscriber is already set.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        // Two calls must not panic; the second is a no-op.
        init();
        init();
    }
}
