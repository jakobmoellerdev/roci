//! roci CLI library: argument parsing, config resolution, and the server bind
//! loop. The top-level `run`/`main` entrypoint lives in the binary shim
//! `main.rs` (excluded from coverage) because it calls `Args::parse()` on the
//! real process argv; everything here is unit-testable and fully covered.
#![forbid(unsafe_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use roci_config::Config;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;

/// Command-line arguments. These override the corresponding config defaults.
#[derive(Debug, Parser)]
#[command(name = "roci", version, about = "A Rust OCI Distribution registry")]
pub struct Args {
    /// Address to bind the HTTP server to.
    #[arg(long)]
    pub listen: Option<SocketAddr>,
    /// Root directory of the content-addressable store.
    #[arg(long)]
    pub storage_root: Option<PathBuf>,
}

/// Apply CLI overrides onto a base config, producing the effective config.
pub fn resolve_config(args: Args, mut config: Config) -> Config {
    if let Some(listen) = args.listen {
        config.listen = listen;
    }
    if let Some(root) = args.storage_root {
        config.storage_root = root;
    }
    config
}

/// Bind and serve the registry until `shutdown` resolves. Reports the bound
/// address via `on_bind` (so tests can drive a request against an ephemeral
/// port) before entering the serve loop.
pub async fn serve(
    config: Config,
    on_bind: impl FnOnce(SocketAddr),
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let storage = FsStorage::new(&config.storage_root)?;
    let app = build_router(AppState::new_with(storage.clone(), config.clone()));
    // Startup recovery before accepting requests: register pre-existing
    // `subject` links (referrers upgrade) and reconcile `index.json` with the
    // replayed metadata log (write-behind crash recovery, foreign-tag import).
    storage.warm_referrers_from_layout().await;
    storage.reconcile_index_json().await;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local = listener.local_addr()?;
    tracing::info!(addr = %local, root = %config.storage_root.display(), "roci listening");
    on_bind(local);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_apply_over_base() {
        let args = Args {
            listen: Some("0.0.0.0:1234".parse().unwrap()),
            storage_root: Some(PathBuf::from("/tmp/x")),
        };
        let cfg = resolve_config(args, Config::default());
        assert_eq!(cfg.listen.port(), 1234);
        assert_eq!(cfg.storage_root, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn absent_args_keep_base_defaults() {
        let base = Config::default();
        let cfg = resolve_config(
            Args {
                listen: None,
                storage_root: None,
            },
            base.clone(),
        );
        assert_eq!(cfg.listen, base.listen);
        assert_eq!(cfg.storage_root, base.storage_root);
    }

    #[tokio::test]
    async fn serve_binds_answers_then_shuts_down() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            storage_root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let (bind_tx, bind_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            serve(
                config,
                move |addr| {
                    let _ = bind_tx.send(addr);
                },
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });
        let addr = bind_rx.await.unwrap();
        assert_eq!(http_get(&format!("http://{addr}/v2/")).await, "{}");
        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_returns_err_on_bind_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            listen: taken,
            storage_root: dir.path().to_path_buf(),
            ..Default::default()
        };
        let result = serve(config, |_| {}, std::future::pending()).await;
        assert!(result.is_err());
    }

    // Minimal dependency-free HTTP GET so the test needs no extra crate.
    async fn http_get(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let url = url.strip_prefix("http://").unwrap();
        let (host, path) = url.split_once('/').unwrap();
        let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
        stream
            .write_all(
                format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = String::new();
        stream.read_to_string(&mut buf).await.unwrap();
        buf.rsplit("\r\n\r\n").next().unwrap().trim().to_string()
    }
}
