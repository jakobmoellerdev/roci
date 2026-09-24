//! roci — a single-binary OCI registry. Thin entrypoint over the library
//! (`roci_cli::serve`); parses args and runs until Ctrl-C. This shim is
//! excluded from the coverage gate (`--ignore-filename-regex main.rs`) because
//! `Args::parse()` reads the real process argv and only runs in the binary.
#![forbid(unsafe_code)]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use roci_cli::{resolve_config, serve, Args};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = resolve_config(&args)
        .map_err(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        })
        .unwrap();
    let _telemetry = roci_telemetry::init(&config)?;
    serve(config, |_| {}, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
