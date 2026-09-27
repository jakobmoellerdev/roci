//! Telemetry: tracing / logging / metrics initialization.
//! Minimal build = `fmt` subscriber; `otel` feature adds OTLP export +
//! Prometheus scrape.
#![forbid(unsafe_code)]

use roci_config::{Config, LogFormat};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "otel")]
mod metrics;

#[cfg(feature = "otel")]
pub use metrics::{
    record_auth_decision, record_blocking_hop, record_dedupe_link, record_error,
    record_gc_collected, record_meta_compaction, record_meta_snapshot, record_meta_wal_append,
    record_meta_wal_batch_size, record_quota_rejection, record_request, record_scrub,
    record_upload_active, record_upload_bytes, record_upload_finalize,
};

/// No-op metric recorders for builds without `otel`.
macro_rules! noop {
    ($($name:ident($($arg:ty),*));* $(;)?) => {
        $(
            #[cfg(not(feature = "otel"))]
            #[inline(always)]
            #[allow(clippy::too_many_arguments)]
            pub fn $name($(_: $arg),*) {}
        )*
    }
}

noop! {
    record_request(&str, &str, u16, std::time::Duration);
    record_error(&str);
    record_gc_collected(&str, u64);
    record_scrub(&str, u64);
    record_dedupe_link(&str, &str);
    record_quota_rejection(&str);
    record_blocking_hop(&'static str);
    record_auth_decision(&str, &str);
    record_meta_wal_append();
    record_meta_wal_batch_size(u64);
    record_meta_compaction(&str);
    record_meta_snapshot(&str);
    record_upload_active(i64);
    record_upload_bytes(u64);
    record_upload_finalize(&str);
}

/// OTel provider guard; flushes on drop. Zero-size without `otel`.
pub struct TelemetryGuard {
    #[cfg(feature = "otel")]
    _trace_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    #[cfg(feature = "otel")]
    _meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
    #[cfg(feature = "otel")]
    _log_provider: Option<opentelemetry_sdk::logs::SdkLoggerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        {
            if let Some(ref tp) = self._trace_provider {
                let _ = tp.shutdown();
            }
            if let Some(ref mp) = self._meter_provider {
                let _ = mp.shutdown();
            }
            if let Some(ref lp) = self._log_provider {
                let _ = lp.shutdown();
            }
        }
    }
}

/// Initialize tracing subscriber and optional OTel providers.
/// Returns a [`TelemetryGuard`] whose drop flushes providers.
pub fn init(config: &Config) -> anyhow::Result<TelemetryGuard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));

    // Warn on minimal builds when OTel config is present.
    #[cfg(not(feature = "otel"))]
    {
        if config.telemetry.otlp.is_some() {
            tracing::warn!(
                "telemetry.otlp is configured but this build lacks the `otel` feature — \
                 OTLP export is unavailable"
            );
        }
        if config.telemetry.metrics.enabled {
            tracing::warn!(
                "telemetry.metrics.enabled is set but this build lacks the `otel` feature — \
                 metrics endpoint is unavailable"
            );
        }
    }

    #[cfg(feature = "otel")]
    {
        init_otel(config, filter)
    }

    #[cfg(not(feature = "otel"))]
    {
        init_minimal(config, filter)
    }
}

/// Minimal init: fmt subscriber only.
#[cfg(not(feature = "otel"))]
fn init_minimal(config: &Config, filter: EnvFilter) -> anyhow::Result<TelemetryGuard> {
    let registry = tracing_subscriber::registry().with(filter);
    match config.log.format {
        LogFormat::Text => registry.with(tracing_subscriber::fmt::layer()).try_init(),
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .try_init(),
    }
    .map_err(|e| anyhow::anyhow!("failed to set global subscriber: {e}"))?;
    Ok(TelemetryGuard {})
}

/// Full init: fmt + OTel tracing layer + OTel log appender + metrics.
#[cfg(feature = "otel")]
fn init_otel(config: &Config, filter: EnvFilter) -> anyhow::Result<TelemetryGuard> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::Resource;

    // Register the W3C TraceContext propagator so roci-core's request_span
    // middleware can extract `traceparent` headers via the global propagator.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let resource = Resource::builder_empty()
        .with_attribute(KeyValue::new("service.name", "roci"))
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();

    // ── Trace provider ──────────────────────────────────────────────
    let trace_provider = build_trace_provider(config, resource.clone())?;
    let tracer = trace_provider.tracer("roci");

    // ── Meter provider ──────────────────────────────────────────────
    let meter_provider = build_meter_provider(config, resource.clone())?;
    metrics::install(meter_provider.clone());

    // ── Log provider ────────────────────────────────────────────────
    let log_provider = build_log_provider(config, resource)?;

    let otel_trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let otel_log_layer =
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&log_provider);

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(otel_trace_layer)
        .with(otel_log_layer);

    match config.log.format {
        LogFormat::Text => registry.with(tracing_subscriber::fmt::layer()).try_init(),
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .try_init(),
    }
    .map_err(|e| anyhow::anyhow!("failed to set global subscriber: {e}"))?;

    Ok(TelemetryGuard {
        _trace_provider: Some(trace_provider),
        _meter_provider: Some(meter_provider),
        _log_provider: Some(log_provider),
    })
}

#[cfg(feature = "otel")]
fn build_trace_provider(
    config: &Config,
    resource: opentelemetry_sdk::Resource,
) -> anyhow::Result<opentelemetry_sdk::trace::SdkTracerProvider> {
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
        config.telemetry.sample_ratio,
    )));

    let mut builder = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(sampler);

    if let Some(ref otlp) = config.telemetry.otlp {
        let exporter = otlp_trace_exporter(otlp)?;
        builder = builder.with_batch_exporter(exporter);
    }

    Ok(builder.build())
}

#[cfg(feature = "otel")]
fn build_meter_provider(
    config: &Config,
    resource: opentelemetry_sdk::Resource,
) -> anyhow::Result<opentelemetry_sdk::metrics::SdkMeterProvider> {
    use opentelemetry_sdk::metrics::SdkMeterProvider;

    let mut builder = SdkMeterProvider::builder().with_resource(resource);

    // SharedReader wraps ManualReader for pull-based Prometheus scrape — always
    // installed when otel is on so the /metrics endpoint can serve even without
    // an OTLP push target.
    let shared_reader = metrics::SharedReader::new();
    metrics::set_reader(shared_reader.clone());
    builder = builder.with_reader(shared_reader);

    if let Some(ref otlp) = config.telemetry.otlp {
        let exporter = otlp_metrics_exporter(otlp)?;
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build();
        builder = builder.with_reader(reader);
    }

    Ok(builder.build())
}

#[cfg(feature = "otel")]
fn build_log_provider(
    config: &Config,
    resource: opentelemetry_sdk::Resource,
) -> anyhow::Result<opentelemetry_sdk::logs::SdkLoggerProvider> {
    use opentelemetry_sdk::logs::SdkLoggerProvider;

    let mut builder = SdkLoggerProvider::builder().with_resource(resource);

    if let Some(ref otlp) = config.telemetry.otlp {
        let exporter = otlp_log_exporter(otlp)?;
        builder = builder.with_batch_exporter(exporter);
    }

    Ok(builder.build())
}

#[cfg(feature = "otel")]
fn otlp_trace_exporter(
    otlp: &roci_config::OtlpConfig,
) -> anyhow::Result<opentelemetry_otlp::SpanExporter> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};

    let exporter = match otlp.protocol {
        roci_config::OtlpProtocol::Grpc => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&otlp.endpoint)
            .build()?,
        roci_config::OtlpProtocol::Http => SpanExporter::builder()
            .with_http()
            .with_endpoint(http_signal_url(&otlp.endpoint, "traces"))
            .build()?,
    };
    Ok(exporter)
}

#[cfg(feature = "otel")]
fn otlp_metrics_exporter(
    otlp: &roci_config::OtlpConfig,
) -> anyhow::Result<opentelemetry_otlp::MetricExporter> {
    use opentelemetry_otlp::{MetricExporter, WithExportConfig};

    let exporter = match otlp.protocol {
        roci_config::OtlpProtocol::Grpc => MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&otlp.endpoint)
            .build()?,
        roci_config::OtlpProtocol::Http => MetricExporter::builder()
            .with_http()
            .with_endpoint(http_signal_url(&otlp.endpoint, "metrics"))
            .build()?,
    };
    Ok(exporter)
}

#[cfg(feature = "otel")]
fn otlp_log_exporter(
    otlp: &roci_config::OtlpConfig,
) -> anyhow::Result<opentelemetry_otlp::LogExporter> {
    use opentelemetry_otlp::{LogExporter, WithExportConfig};

    let exporter = match otlp.protocol {
        roci_config::OtlpProtocol::Grpc => LogExporter::builder()
            .with_tonic()
            .with_endpoint(&otlp.endpoint)
            .build()?,
        roci_config::OtlpProtocol::Http => LogExporter::builder()
            .with_http()
            .with_endpoint(http_signal_url(&otlp.endpoint, "logs"))
            .build()?,
    };
    Ok(exporter)
}

/// Append `/v1/{signal}` to the base OTLP endpoint (OTLP spec).
#[cfg(feature = "otel")]
fn http_signal_url(base: &str, signal: &str) -> String {
    format!("{}/v1/{signal}", base.trim_end_matches('/'))
}

/// Prometheus text scrape router; empty without `otel` or when disabled.
pub fn metrics_router(config: &Config) -> axum::Router {
    #[cfg(feature = "otel")]
    {
        if config.telemetry.metrics.enabled {
            let path = config.telemetry.metrics.path.clone();
            return axum::Router::new()
                .route(&path, axum::routing::get(metrics::prometheus_handler));
        }
    }
    #[cfg(not(feature = "otel"))]
    {
        let _ = config;
    }
    axum::Router::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_init_text_format() {
        let config = Config::default();
        let guard = init(&config);
        if let Ok(_g) = guard {}
    }
}
