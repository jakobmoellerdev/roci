//! OTel metric instruments and the Prometheus scrape handler.
//!
//! Instruments are created once from a global `MeterProvider` and cached in
//! `OnceLock`s. The `record_*` functions are the public API called from
//! `roci-core` middleware; they are no-ops before `install()`.
//!
//! The Prometheus text exposition is implemented directly over the SDK's
//! `ManualReader` + `ResourceMetrics`, avoiding third-party exporter crates
//! (supply-chain minimisation).

use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::ManualReader;
use std::fmt::Write as _;
use std::sync::{Arc, OnceLock};

// ── Cloneable ManualReader wrapper ──────────────────────────────────────

/// A thin wrapper around `Arc<ManualReader>` that implements `MetricReader`
/// so one clone can be registered with the `SdkMeterProvider` and another
/// stored in a `OnceLock` for on-demand Prometheus scrape.
#[derive(Clone, Debug)]
pub(crate) struct SharedReader(Arc<ManualReader>);

impl SharedReader {
    pub(crate) fn new() -> Self {
        Self(Arc::new(ManualReader::default()))
    }
}

impl MetricReader for SharedReader {
    fn register_pipeline(&self, pipeline: std::sync::Weak<opentelemetry_sdk::metrics::Pipeline>) {
        self.0.register_pipeline(pipeline);
    }
    fn collect(&self, rm: &mut ResourceMetrics) -> opentelemetry_sdk::error::OTelSdkResult {
        self.0.collect(rm)
    }
    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.0.force_flush()
    }
    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }
    fn temporality(
        &self,
        kind: opentelemetry_sdk::metrics::InstrumentKind,
    ) -> opentelemetry_sdk::metrics::Temporality {
        self.0.temporality(kind)
    }
}

// ── Singleton instrument handles ────────────────────────────────────────

static REQUEST_DURATION: OnceLock<Histogram<f64>> = OnceLock::new();
static ERROR_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
static PROM_READER: OnceLock<SharedReader> = OnceLock::new();

pub(crate) fn set_reader(reader: SharedReader) {
    let _ = PROM_READER.set(reader);
}

/// Register instruments on the given meter provider. Called once from `init_otel`.
pub(crate) fn install(provider: opentelemetry_sdk::metrics::SdkMeterProvider) {
    use opentelemetry::metrics::MeterProvider as _;
    let meter: Meter = provider.meter("roci");
    let duration = meter
        .f64_histogram("http.server.request.duration")
        .with_description("Duration of HTTP server requests")
        .with_unit("s")
        .with_boundaries(vec![
            0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
        ])
        .build();
    let _ = REQUEST_DURATION.set(duration);
    let errors = meter
        .u64_counter("registry.request.errors")
        .with_description("Count of registry request errors by error code")
        .build();
    let _ = ERROR_COUNTER.set(errors);
}

// ── Recording API ───────────────────────────────────────────────────────

/// Record a completed HTTP request: duration histogram with
/// `{endpoint, method, status_class}` labels.
pub fn record_request(endpoint: &str, method: &str, status: u16, duration: std::time::Duration) {
    if let Some(hist) = REQUEST_DURATION.get() {
        let status_class = match status {
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            _ => "5xx",
        };
        hist.record(
            duration.as_secs_f64(),
            &[
                KeyValue::new("endpoint", endpoint.to_string()),
                KeyValue::new("method", method.to_string()),
                KeyValue::new("status_class", status_class),
            ],
        );
    }
}

/// Increment the error counter with `{error_code}`.
pub fn record_error(error_code: &str) {
    if let Some(counter) = ERROR_COUNTER.get() {
        counter.add(1, &[KeyValue::new("error_code", error_code.to_string())]);
    }
}

// ── Prometheus text exposition ──────────────────────────────────────────

/// Axum handler: collects metrics from the `ManualReader` and encodes them in
/// Prometheus text exposition format.
pub(crate) async fn prometheus_handler() -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    let Some(reader) = PROM_READER.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "metrics not initialized").into_response();
    };
    let mut rm = ResourceMetrics::default();
    let _ = reader.collect(&mut rm);
    let text = encode_prometheus(&rm);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

fn encode_prometheus(rm: &ResourceMetrics) -> String {
    let mut out = String::with_capacity(4096);
    for sm in rm.scope_metrics() {
        for metric in sm.metrics() {
            let prom_name = prom_metric_name(metric.name(), metric.unit());
            let desc = metric.description();
            encode_metric(&mut out, &prom_name, desc, metric.data());
        }
    }
    out
}

fn encode_metric(out: &mut String, prom_name: &str, desc: &str, data: &AggregatedMetrics) {
    // roci emits only f64 histograms and u64 monotonic counters.
    if let AggregatedMetrics::F64(MetricData::Histogram(hist)) = data {
        write_help_type(out, prom_name, desc, "histogram");
        for dp in hist.data_points() {
            let base_labels = collect_labels(dp.attributes());
            let mut cumulative: u64 = 0;
            let bounds: Vec<f64> = dp.bounds().collect();
            let counts: Vec<u64> = dp.bucket_counts().collect();
            for (i, count) in counts.iter().enumerate() {
                cumulative += count;
                let le = if i < bounds.len() {
                    format!("{}", bounds[i])
                } else {
                    "+Inf".to_string()
                };
                let labels = format_labels_with(&base_labels, "le", &le);
                let _ = writeln!(out, "{prom_name}_bucket{labels} {cumulative}");
            }
            let labels = format_labels(dp.attributes());
            let _ = writeln!(out, "{prom_name}_sum{labels} {}", dp.sum());
            let _ = writeln!(out, "{prom_name}_count{labels} {}", dp.count());
        }
    } else if let AggregatedMetrics::U64(MetricData::Sum(sum)) = data {
        encode_u64_sum(out, prom_name, desc, sum);
    }
}

fn encode_u64_sum(
    out: &mut String,
    prom_name: &str,
    desc: &str,
    sum: &opentelemetry_sdk::metrics::data::Sum<u64>,
) {
    let full = format!("{prom_name}_total");
    write_help_type(out, &full, desc, "counter");
    for dp in sum.data_points() {
        let labels = format_labels(dp.attributes());
        let _ = writeln!(out, "{full}{labels} {}", dp.value());
    }
}

fn prom_metric_name(name: &str, unit: &str) -> String {
    let base: String = name.replace('.', "_");
    if unit == "s" {
        format!("{base}_seconds")
    } else {
        base
    }
}

fn write_help_type(out: &mut String, name: &str, desc: &str, typ: &str) {
    if !desc.is_empty() {
        let _ = writeln!(out, "# HELP {name} {desc}");
    }
    let _ = writeln!(out, "# TYPE {name} {typ}");
}

fn collect_labels<'a>(attrs: impl Iterator<Item = &'a KeyValue>) -> Vec<(String, String)> {
    attrs
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect()
}

fn format_labels<'a>(attrs: impl Iterator<Item = &'a KeyValue>) -> String {
    let pairs: Vec<String> = attrs
        .map(|kv| {
            format!(
                "{}=\"{}\"",
                kv.key,
                escape_label_value(&kv.value.to_string())
            )
        })
        .collect();
    // `name{} v` is valid exposition, so an (unused) unlabelled series needs no branch.
    format!("{{{}}}", pairs.join(","))
}

fn format_labels_with(base: &[(String, String)], extra_key: &str, extra_val: &str) -> String {
    let mut pairs: Vec<String> = base
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
        .collect();
    pairs.push(format!("{extra_key}=\"{}\"", escape_label_value(extra_val)));
    format!("{{{}}}", pairs.join(","))
}

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise SharedReader trait methods that the SDK doesn't call in our
    /// usage path: `force_flush` (ManualReader no-op) and the full
    /// `collect → encode` pipeline.
    #[test]
    fn shared_reader_force_flush_and_encode() {
        use opentelemetry::metrics::MeterProvider as _;
        use opentelemetry_sdk::metrics::SdkMeterProvider;

        let reader = SharedReader::new();
        let provider = SdkMeterProvider::builder()
            .with_reader(reader.clone())
            .build();

        // force_flush is a no-op on ManualReader but must not fail.
        reader.force_flush().expect("force_flush ok");

        // Create and record an f64 histogram and a u64 counter.
        let meter = provider.meter("test");
        let hist = meter
            .f64_histogram("test.duration")
            .with_unit("s")
            .with_description("d")
            .with_boundaries(vec![0.1, 1.0])
            .build();
        hist.record(0.05, &[KeyValue::new("k", "v")]);

        let ctr = meter
            .u64_counter("test.errors")
            .with_description("e")
            .build();
        ctr.add(1, &[KeyValue::new("code", "X")]);

        // Collect and encode.
        let mut rm = ResourceMetrics::default();
        reader.collect(&mut rm).expect("collect ok");
        let text = encode_prometheus(&rm);

        assert!(
            text.contains("test_duration_seconds_bucket"),
            "histogram bucket: {text}"
        );
        assert!(
            text.contains("test_duration_seconds_sum"),
            "histogram sum: {text}"
        );
        assert!(
            text.contains("test_duration_seconds_count"),
            "histogram count: {text}"
        );
        assert!(text.contains("test_errors_total"), "counter total: {text}");
        assert!(text.contains("code=\"X\""), "counter label: {text}");
    }
}
