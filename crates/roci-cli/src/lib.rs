//! roci CLI library: argument parsing, config resolution, and the server bind
//! loop. The top-level `run`/`main` entrypoint lives in the binary shim
//! `main.rs` (excluded from coverage) because it calls `Args::parse()` on the
//! real process argv; everything here is unit-testable and fully covered.
#![forbid(unsafe_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use roci_config::{Config, ConfigError};
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use tokio::net::TcpListener;
use tower::Service;

/// Command-line arguments. These override the corresponding config defaults.
#[derive(Debug, Parser)]
#[command(name = "roci", version, about = "A Rust OCI Distribution registry")]
pub struct Args {
    /// Path to a TOML configuration file. When omitted, all defaults apply
    /// (zero-config).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Address to bind the HTTP server to (overrides `http.listen` in config).
    #[arg(long)]
    pub listen: Option<SocketAddr>,
    /// Root directory of the content-addressable store (overrides
    /// `storage.root` in config).
    #[arg(long)]
    pub storage_root: Option<PathBuf>,
}

/// Load a config file (if given) and apply CLI overrides.
pub fn resolve_config(args: &Args) -> Result<Config, ConfigError> {
    let mut config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    if let Some(listen) = args.listen {
        config.http.listen = listen;
    }
    if let Some(ref root) = args.storage_root {
        config.storage.root = root.clone();
    }
    // Re-validate after overrides (e.g. a CLI-specified path may interact with
    // other fields).
    config.validate()?;
    Ok(config)
}

/// Bind and serve the registry until `shutdown` resolves. Reports the bound
/// address via `on_bind` (so tests can drive a request against an ephemeral
/// port) before entering the serve loop.
pub async fn serve(
    config: Config,
    on_bind: impl FnOnce(SocketAddr),
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let storage =
        FsStorage::with_cache_capacity(&config.storage.root, config.storage.cache_max_bytes)?;
    let app = build_router(AppState::new_with(storage.clone(), config.clone()))
        .merge(roci_telemetry::metrics_router(&config));
    // Startup recovery before accepting requests: register pre-existing
    // `subject` links (referrers upgrade) and reconcile `index.json` with the
    // replayed metadata log (write-behind crash recovery, foreign-tag import).
    storage.warm_referrers_from_layout().await;
    storage.reconcile_index_json().await;

    let listener = TcpListener::bind(config.http.listen).await?;
    let local = listener.local_addr()?;
    tracing::info!(addr = %local, root = %config.storage.root.display(), "roci listening");
    on_bind(local);

    let tls_acceptor = match &config.http.tls {
        Some(tls) => Some(build_tls_acceptor(tls)?),
        None => None,
    };

    // Build the hyper-util auto server builder (HTTP/1.1 + h2c / h2+h1.1 under TLS).
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(config.http.timeouts.read_header_secs))
        .keep_alive(true);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .max_concurrent_streams(Some(256));
    let builder = Arc::new(builder);

    let idle_timeout = Duration::from_secs(config.http.timeouts.idle_secs);

    // Graceful-shutdown tracking.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn the shutdown watcher.
    tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    });

    loop {
        tokio::select! {
            accept = listener.accept() => {
                // OS accept errors (EMFILE, ECONNABORTED, …) are transient:
                // skip and keep serving.
                let Some((tcp, _peer)) = accept.ok() else { continue };
                let _ = tcp.set_nodelay(true);

                let builder = Arc::clone(&builder);
                let tls_acceptor = tls_acceptor.clone();
                let app = app.clone();
                let mut shutdown_rx = shutdown_rx.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_conn(
                        tcp, builder, tls_acceptor, app, &mut shutdown_rx, idle_timeout,
                    )
                    .await
                    {
                        tracing::debug!(error = %e, "connection error");
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                tracing::info!("shutting down listener");
                break;
            }
        }
    }

    Ok(())
}

/// Drive a single accepted TCP connection through optional TLS and the
/// hyper-util auto-builder until it completes, is shut down, or idles out.
async fn handle_conn(
    tcp: tokio::net::TcpStream,
    builder: Arc<AutoBuilder<TokioExecutor>>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    app: axum::Router,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    idle_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match tls_acceptor {
        Some(acceptor) => {
            let tls_stream = acceptor.accept(tcp).await.map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("TLS handshake failed: {e}").into()
                },
            )?;
            let io = TokioIo::new(tls_stream);
            let conn =
                builder.serve_connection_with_upgrades(io, TowerToHyperService { service: app });
            tokio::pin!(conn);
            tokio::select! {
                res = &mut conn => res?,
                _ = shutdown_rx.changed() => {
                    conn.as_mut().graceful_shutdown();
                    conn.await?
                }
                _ = tokio::time::sleep(idle_timeout) => {}
            }
        }
        None => {
            let io = TokioIo::new(tcp);
            let conn =
                builder.serve_connection_with_upgrades(io, TowerToHyperService { service: app });
            tokio::pin!(conn);
            tokio::select! {
                res = &mut conn => res?,
                _ = shutdown_rx.changed() => {
                    conn.as_mut().graceful_shutdown();
                    conn.await?
                }
                _ = tokio::time::sleep(idle_timeout) => {}
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn build_tls_acceptor(tls: &roci_config::TlsConfig) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;

    let cert_pem = std::fs::read(&tls.cert)
        .map_err(|e| anyhow::anyhow!("reading TLS cert {}: {e}", tls.cert.display()))?;
    let key_pem = std::fs::read(&tls.key)
        .map_err(|e| anyhow::anyhow!("reading TLS key {}: {e}", tls.key.display()))?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing TLS cert chain: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!(
            "TLS cert file {} contains no certificates",
            tls.cert.display()
        );
    }

    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| anyhow::anyhow!("parsing TLS key {}: {e}", tls.key.display()))?;

    let mut sc = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("building TLS config: {e}"))?;

    // ALPN: h2 preferred, then http/1.1.
    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Session resumption: stateless tickets (no server-side session cache needed)
    // plus a fixed-size session cache for TLS 1.2 resumption.
    sc.ticketer = rustls::crypto::ring::Ticketer::new()
        .map_err(|e| anyhow::anyhow!("creating TLS ticketer: {e}"))?;
    sc.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);

    // No 0-RTT early data: rustls/hyper cannot honor RFC 8470 `425` semantics.
    sc.max_early_data_size = 0;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(sc)))
}

// ---------------------------------------------------------------------------
// Tower → Hyper service adapter
// ---------------------------------------------------------------------------

/// Minimal adapter: wraps an `axum::Router` (a Tower `Service`) so hyper-util
/// can drive it. Converts `hyper::body::Incoming` → `axum::body::Body`.
#[derive(Clone)]
struct TowerToHyperService<S> {
    service: S,
}

impl<S> hyper::service::Service<hyper::Request<Incoming>> for TowerToHyperService<S>
where
    S: Service<axum::extract::Request, Response = axum::response::Response>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = axum::response::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        let req = req.map(axum::body::Body::new);
        self.service.clone().call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roci_config::LimitsConfig;
    use rustls::pki_types::pem::PemObject as _;

    #[test]
    fn resolve_config_defaults_when_no_file() {
        let args = Args {
            config: None,
            listen: None,
            storage_root: None,
        };
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn resolve_config_applies_cli_overrides() {
        let args = Args {
            config: None,
            listen: Some("0.0.0.0:1234".parse().unwrap()),
            storage_root: Some(PathBuf::from("/tmp/x")),
        };
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.http.listen.port(), 1234);
        assert_eq!(cfg.storage.root, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn resolve_config_absent_args_keep_defaults() {
        let args = Args {
            config: None,
            listen: None,
            storage_root: None,
        };
        let base = Config::default();
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.http.listen, base.http.listen);
        assert_eq!(cfg.storage.root, base.storage.root);
    }

    #[test]
    fn resolve_config_loads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(
            &path,
            r#"
[http]
listen = "0.0.0.0:9876"

[storage]
root = "/tmp/roci-test"
"#,
        )
        .unwrap();
        let args = Args {
            config: Some(path),
            listen: None,
            storage_root: None,
        };
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.http.listen.port(), 9876);
        assert_eq!(cfg.storage.root, PathBuf::from("/tmp/roci-test"));
    }

    #[test]
    fn resolve_config_cli_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(
            &path,
            r#"
[http]
listen = "0.0.0.0:9876"
"#,
        )
        .unwrap();
        let args = Args {
            config: Some(path),
            listen: Some("127.0.0.1:1111".parse().unwrap()),
            storage_root: None,
        };
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.http.listen.port(), 1111);
    }

    #[test]
    fn resolve_config_invalid_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "not valid toml {{{{").unwrap();
        let args = Args {
            config: Some(path),
            listen: None,
            storage_root: None,
        };
        assert!(resolve_config(&args).is_err());
    }

    #[test]
    fn resolve_config_missing_file_returns_error() {
        let args = Args {
            config: Some(PathBuf::from("/nonexistent/config.toml")),
            listen: None,
            storage_root: None,
        };
        let err = resolve_config(&args).unwrap_err();
        assert!(err.to_string().contains("reading config"));
    }

    #[test]
    fn resolve_config_invalid_values_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        std::fs::write(
            &path,
            r#"
[limits]
max_body = 0
"#,
        )
        .unwrap();
        let args = Args {
            config: Some(path),
            listen: None,
            storage_root: None,
        };
        let err = resolve_config(&args).unwrap_err();
        assert!(err.to_string().contains("limits.max_body"));
    }

    #[tokio::test]
    async fn serve_binds_answers_then_shuts_down() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().to_path_buf();

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
        let mut config = Config::default();
        config.http.listen = taken;
        config.storage.root = dir.path().to_path_buf();
        let result = serve(config, |_| {}, std::future::pending()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn serve_with_custom_limits() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().to_path_buf();
        config.limits = LimitsConfig {
            max_body: 1024,
            max_upload: 2048,
            max_manifest: 512,
            max_page: 50,
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
        // The registry still serves /v2/
        assert_eq!(http_get(&format!("http://{addr}/v2/")).await, "{}");
        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_h2c_prior_knowledge() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().to_path_buf();

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

        // Send an h2c prior-knowledge request using hyper client.
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get("/v2/")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_tls_http1_and_h2() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        // Generate a self-signed certificate with rcgen.
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().join("data");
        config.http.tls = Some(roci_config::TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
        });

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

        // Build a rustls client that trusts our self-signed cert.
        let cert_pem = std::fs::read(&cert_path).unwrap();
        let cert_der: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for c in &cert_der {
            root_store.add(c.clone()).unwrap();
        }

        // ---- TLS + HTTP/1.1 ----
        {
            let mut cc = rustls::ClientConfig::builder()
                .with_root_certificates(root_store.clone())
                .with_no_client_auth();
            cc.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls_stream = connector.connect(domain, tcp).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(conn);
            let req = hyper::Request::get("/v2/")
                .header("host", "localhost")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
            let resp = sender.send_request(req).await.unwrap();
            assert_eq!(resp.status(), 200);
        }

        // ---- TLS + HTTP/2 ----
        {
            let mut cc = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cc.alpn_protocols = vec![b"h2".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls_stream = connector.connect(domain, tcp).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .unwrap();
            tokio::spawn(conn);
            let req = hyper::Request::get("/v2/")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
            let resp = sender.send_request(req).await.unwrap();
            assert_eq!(resp.status(), 200);
        }

        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_tls_invalid_cert_fails_early() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "not a cert").unwrap();
        std::fs::write(&key_path, "not a key").unwrap();

        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().join("data");
        config.http.tls = Some(roci_config::TlsConfig {
            cert: cert_path,
            key: key_path,
        });
        let result = serve(config, |_| {}, std::future::pending()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn serve_rootless_unprivileged_port() {
        // Default port 5000 is unprivileged; verify serve works as non-root
        // with a tempdir root on an ephemeral port.
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().to_path_buf();

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
        // Works as the current (non-root) user.
        assert_eq!(http_get(&format!("http://{addr}/v2/")).await, "{}");
        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
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

    /// Generate a self-signed cert+key pair, returning (cert_path, key_path).
    fn gen_tls(dir: &std::path::Path) -> (PathBuf, PathBuf) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    #[tokio::test]
    async fn tls_handshake_failure_plaintext_client() {
        // A plaintext HTTP client connecting to a TLS port triggers the
        // handshake-failure branch (lines 134-135).
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = gen_tls(dir.path());

        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().join("data");
        config.http.tls = Some(roci_config::TlsConfig {
            cert: cert_path,
            key: key_path,
        });

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

        // Send plaintext HTTP to the TLS port — the server should handle the
        // handshake error gracefully (not crash, not hang).
        {
            use tokio::io::AsyncWriteExt;
            let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _ = tcp
                .write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await;
            drop(tcp);
        }
        // Give the server a moment to process the handshake failure.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The server is still alive and accepts proper TLS connections.
        let cert_pem = std::fs::read(dir.path().join("cert.pem")).unwrap();
        let cert_der: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for c in &cert_der {
            root_store.add(c.clone()).unwrap();
        }
        let cc = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_stream = connector.connect(domain, tcp).await.unwrap();
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get("/v2/")
            .header("host", "localhost")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);

        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tls_empty_key_file_fails() {
        // A key file containing no private key PEM section triggers the
        // "no items found" error from PrivateKeyDer::from_pem_slice.
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, _key_path) = gen_tls(dir.path());
        let empty_key = dir.path().join("empty.pem");
        // Write something that parses as PEM but contains no private key.
        std::fs::write(&empty_key, "# no key here\n").unwrap();

        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().join("data");
        config.http.tls = Some(roci_config::TlsConfig {
            cert: cert_path,
            key: empty_key,
        });
        let result = serve(config, |_| {}, std::future::pending()).await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("parsing TLS key"),
            "expected TLS key parse error, got: {err}"
        );
    }

    #[tokio::test]
    async fn tls_empty_cert_file_fails() {
        // A cert file containing no certificates triggers the "no certificates"
        // error (line 202-205).
        let dir = tempfile::tempdir().unwrap();
        let (_cert_path, key_path) = gen_tls(dir.path());
        let empty_cert = dir.path().join("empty_cert.pem");
        std::fs::write(&empty_cert, "# no cert here\n").unwrap();

        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().join("data");
        config.http.tls = Some(roci_config::TlsConfig {
            cert: empty_cert,
            key: key_path,
        });
        let result = serve(config, |_| {}, std::future::pending()).await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no certificates"),
            "expected 'no certificates' error, got: {err}"
        );
    }

    #[tokio::test]
    async fn idle_timeout_closes_connection() {
        // With a very short idle timeout, an idle connection is closed by the
        // server without crashing (covers line 166).
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().to_path_buf();
        config.http.timeouts.idle_secs = 1;

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

        // Open a keep-alive connection but don't send any request on it.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Wait for the idle timeout to fire (1 second + margin).
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // After idle timeout the server should have closed the connection.
        // Verify the server is still alive by making a fresh request.
        assert_eq!(http_get(&format!("http://{addr}/v2/")).await, "{}");
        drop(tcp);

        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connection_error_is_handled() {
        // A client that sends invalid h2 frames triggers the connection-error
        // branch (`if let Err`).
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.http.listen = "127.0.0.1:0".parse().unwrap();
        config.storage.root = dir.path().to_path_buf();

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

        // Send the h2 client connection preface followed by garbage bytes.
        // This triggers a protocol error in hyper's h2 codec.
        {
            use tokio::io::AsyncWriteExt;
            let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Full h2 client connection preface.
            let _ = tcp.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
            // Invalid h2 frame: 9 bytes of 0xFF cannot be a valid frame header.
            let _ = tcp.write_all(&[0xFF; 9]).await;
            // Keep connection open briefly so hyper processes the bad frame.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The server is still alive.
        assert_eq!(http_get(&format!("http://{addr}/v2/")).await, "{}");

        let _ = stop_tx.send(());
        handle.await.unwrap().unwrap();
    }
}
