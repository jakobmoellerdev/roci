//! Test: `init` with OTel + gRPC OTLP + text log format.
#![cfg(feature = "otel")]

use roci_config::{Config, OtlpConfig, OtlpProtocol};

#[test]
fn init_otel_grpc_text() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _enter = rt.enter();

    let mut config = Config::default();
    config.telemetry.otlp = Some(OtlpConfig {
        endpoint: "http://127.0.0.1:14317".into(), // unused port; exporters are lazy
        protocol: OtlpProtocol::Grpc,
    });
    config.telemetry.sample_ratio = 0.5;

    let guard = roci_telemetry::init(&config).expect("init with otel grpc text");
    drop(guard); // exercises TelemetryGuard::drop → provider shutdowns
}
