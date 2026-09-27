//! roci entrypoint: parses args, runs until signal.
#![forbid(unsafe_code)]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use roci_cli::{resolve_config, serve, Args};

/// Blocking-pool threads per async worker.
const BLOCKING_THREADS_PER_WORKER: usize = 8;

fn main() -> anyhow::Result<()> {
    // Opt out of THP: roci's heap is small, THP wastes RSS.
    #[cfg(target_os = "linux")]
    let _ = rustix::thread::disable_transparent_huge_pages(true);
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(workers * BLOCKING_THREADS_PER_WORKER)
        .thread_keep_alive(std::time::Duration::from_secs(2))
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = resolve_config(&args)
        .map_err(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        })
        .unwrap();
    let _telemetry = roci_telemetry::init(&config)?;
    serve(config, args.config.clone(), |_| {}, shutdown_signal()).await
}

/// Resolves on SIGINT or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
