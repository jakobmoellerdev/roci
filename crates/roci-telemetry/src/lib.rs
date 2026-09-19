//! Telemetry setup for roci: tracing/log/metric initialization helpers.
//!
//! The always-on path is a structured `fmt` subscriber honoring `RUST_LOG`.
//! With the `otel` feature, [`init`] additionally installs an OpenTelemetry
//! `tracing` layer (Phase 0 spine). The exporter is a no-op for now — OTLP
//! export lands in Phase 4 (PLAN.md). The feature is off in the minimal build,
//! so the OpenTelemetry dependency tree compiles out entirely
//! (ARCHITECTURE.md build-flavor invariants 1 & 2).
#![forbid(unsafe_code)]

use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Initialize the tracing subscriber honoring `RUST_LOG` (defaulting to
/// `info`). With the `otel` feature, an OpenTelemetry span layer is composed in.
/// Idempotent-safe: a second call is a no-op if a subscriber is already set.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer());
    #[cfg(feature = "otel")]
    let registry = registry.with(otel_layer());
    let _ = registry.try_init();
}

/// Build the OpenTelemetry `tracing` layer. Backed by a no-op tracer provider
/// (no exporter) so it is dependency-light and side-effect-free; Phase 4
/// swaps in an OTLP-exporting provider.
#[cfg(feature = "otel")]
fn otel_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    let provider = opentelemetry::trace::noop::NoopTracerProvider::new();
    tracing_opentelemetry::layer().with_tracer(provider.tracer("roci"))
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

    #[cfg(feature = "otel")]
    #[test]
    fn otel_layer_builds() {
        // Constructing the OpenTelemetry layer exercises the feature-gated path.
        let _layer = otel_layer::<tracing_subscriber::Registry>();
    }
}
