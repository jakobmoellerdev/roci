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

/// Blocking-pool threads per async worker. Every blob read/write batch and
/// filesystem metadata call is a short blocking task, so a small pool keeps up;
/// tokio's default cap (512) let load bursts grow ~100 threads, each keeping
/// its own allocator heap resident. Excess tasks queue instead.
const BLOCKING_THREADS_PER_WORKER: usize = 8;

fn main() -> anyhow::Result<()> {
    // Opt out of transparent huge pages before the first allocation. Under THP
    // `always` (common kernel default) each first touch of a fresh allocator
    // region commits a 2 MiB page: measured ~115 MiB of anon RSS for 8
    // concurrent 10 MB pushes. roci's heap is small, so THP buys no TLB win.
    #[cfg(target_os = "linux")]
    let _ = rustix::thread::disable_transparent_huge_pages(true);
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(workers * BLOCKING_THREADS_PER_WORKER)
        // Idle blocking threads exit (freeing their heaps) after 2 s, not 10 s.
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
    serve(config, args.config.clone(), |_| {}, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
