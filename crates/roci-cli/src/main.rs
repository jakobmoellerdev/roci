//! roci — a single-binary OCI registry. Thin entrypoint over the library
//! (`roci_cli::serve`); parses args and runs until Ctrl-C. This shim is
//! excluded from the coverage gate (`--ignore-filename-regex main.rs`) because
//! `Args::parse()` reads the real process argv and only runs in the binary.
#![forbid(unsafe_code)]

use clap::Parser;
use roci_cli::{resolve_config, serve, Args};
use roci_config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    roci_telemetry::init();
    let config = resolve_config(Args::parse(), Config::default());
    serve(config, |_| {}, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
