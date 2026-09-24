//! Test: `init` with OTel + HTTP OTLP + JSON log format.
//! Exercises the http-proto exporter path (reqwest-blocking-client).
#![cfg(feature = "otel")]

use roci_config::{Config, LogFormat, OtlpConfig, OtlpProtocol};

#[test]
fn init_otel_http_json() {
    let mut config = Config::default();
    config.telemetry.otlp = Some(OtlpConfig {
        endpoint: "http://127.0.0.1:14318".into(), // unused port; exporters are lazy
        protocol: OtlpProtocol::Http,
    });
    config.log.format = LogFormat::Json;
    config.telemetry.sample_ratio = 1.0;

    let guard = roci_telemetry::init(&config).expect("init with otel http json");
    drop(guard);
}
