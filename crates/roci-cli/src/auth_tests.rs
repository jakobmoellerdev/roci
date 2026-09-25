//! Serve-level auth tests: mTLS handshakes and identity propagation, leaf
//! pinning, and `[access_control]` live reload.

use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A CA, a server cert for `localhost`, and a client cert (CN `alice`,
/// EKU clientAuth) issued by the CA — all written under `dir`.
struct Pki {
    server_cert: PathBuf,
    server_key: PathBuf,
    ca_pem: PathBuf,
    client_der: CertificateDer<'static>,
    client_key: Vec<u8>,
}

fn pki(dir: &std::path::Path) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "roci test CA");
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let server = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&server_key)
        .unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
    client.distinguished_name.push(DnType::CommonName, "alice");
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = client.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    let p = Pki {
        server_cert: dir.join("server.pem"),
        server_key: dir.join("server.key"),
        ca_pem: dir.join("ca.pem"),
        client_der: client.der().clone(),
        client_key: client_key.serialize_der(),
    };
    std::fs::write(&p.server_cert, server.pem()).unwrap();
    std::fs::write(&p.server_key, server_key.serialize_pem()).unwrap();
    std::fs::write(&p.ca_pem, ca_cert.pem()).unwrap();
    p
}

fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

fn mtls_config(dir: &std::path::Path, p: &Pki, mode: ClientAuth, pins: Vec<String>) -> Config {
    let mut config: Config = toml::from_str("[access_control]\nadmins = [\"alice\"]\n").unwrap();
    config.http.listen = "127.0.0.1:0".parse().unwrap();
    config.storage.root = dir.join("data");
    config.http.tls = Some(roci_config::TlsConfig {
        cert: p.server_cert.clone(),
        key: p.server_key.clone(),
        client_auth: mode,
        client_ca: Some(p.ca_pem.clone()),
        client_cert_sha256: pins,
    });
    config.validate().unwrap();
    config
}

/// Run `serve` in the background; returns its address and a stop handle.
async fn start(
    config: Config,
    config_path: Option<PathBuf>,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (bind_tx, bind_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve(
        config,
        config_path,
        move |addr| {
            let _ = bind_tx.send(addr);
        },
        async move {
            let _ = stop_rx.await;
        },
    ));
    (bind_rx.await.unwrap(), stop_tx, handle)
}

fn client_config(p: &Pki, with_cert: bool, tls12_only: bool) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let server_pem = std::fs::read(&p.server_cert).unwrap();
    use rustls::pki_types::pem::PemObject as _;
    for c in CertificateDer::pem_slice_iter(&server_pem) {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider);
    let builder = if tls12_only {
        builder.with_protocol_versions(&[&rustls::version::TLS12])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .unwrap()
    .with_root_certificates(roots);
    if with_cert {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.client_key.clone()));
        builder
            .with_client_auth_cert(vec![p.client_der.clone()], key)
            .unwrap()
    } else {
        builder.with_no_client_auth()
    }
}

/// One HTTP/1.1 request over TLS; `Err` on a handshake or connection failure.
async fn tls_request(
    addr: SocketAddr,
    cc: rustls::ClientConfig,
    method: &str,
    path: &str,
) -> Result<(u16, String), BoxError> {
    use http_body_util::BodyExt as _;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cc));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let tls = connector
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(conn);
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
async fn mtls_required_propagates_identity_and_rejects_certless_clients() {
    let dir = tempfile::tempdir().unwrap();
    let p = pki(dir.path());
    let (addr, stop, handle) = start(
        mtls_config(dir.path(), &p, ClientAuth::Required, vec![]),
        None,
    )
    .await;

    let with_cert = || client_config(&p, true, false);
    assert_eq!(
        tls_request(addr, with_cert(), "GET", "/v2/")
            .await
            .unwrap()
            .0,
        200
    );
    // `alice` is an admin only via the certificate's CN: push is allowed.
    assert_eq!(
        tls_request(addr, with_cert(), "POST", "/v2/r/blobs/uploads/")
            .await
            .unwrap()
            .0,
        202
    );
    assert!(
        tls_request(addr, client_config(&p, false, false), "GET", "/v2/")
            .await
            .is_err()
    );

    let _ = stop.send(());
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn mtls_optional_without_certificate_is_anonymous() {
    let dir = tempfile::tempdir().unwrap();
    let p = pki(dir.path());
    let (addr, stop, handle) = start(
        mtls_config(dir.path(), &p, ClientAuth::Optional, vec![]),
        None,
    )
    .await;
    let anon = || client_config(&p, false, false);
    assert_eq!(
        tls_request(addr, anon(), "GET", "/v2/").await.unwrap().0,
        200
    );
    let (status, body) = tls_request(addr, anon(), "GET", "/v2/team/app/tags/list")
        .await
        .unwrap();
    assert_eq!(status, 403);
    assert!(
        body.contains("authentication required: present a trusted client certificate"),
        "{body}"
    );
    let _ = stop.send(());
    handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn mtls_pins_gate_the_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let p = pki(dir.path());
    // Upper-case pin: fingerprints compare case-insensitively.
    let pinned = mtls_config(
        dir.path(),
        &p,
        ClientAuth::Required,
        vec![fingerprint(&p.client_der)],
    );
    let (addr, stop, handle) = start(pinned, None).await;
    for tls12 in [false, true] {
        let cc = client_config(&p, true, tls12);
        assert_eq!(
            tls_request(addr, cc, "GET", "/v2/").await.unwrap().0,
            200,
            "tls12={tls12}"
        );
    }
    let _ = stop.send(());
    handle.await.unwrap().unwrap();

    let other = mtls_config(dir.path(), &p, ClientAuth::Required, vec!["00".repeat(32)]);
    let (addr, stop, handle) = start(other, None).await;
    assert!(
        tls_request(addr, client_config(&p, true, false), "GET", "/v2/")
            .await
            .is_err()
    );
    let _ = stop.send(());
    handle.await.unwrap().unwrap();
}

#[test]
fn client_verifier_config_errors() {
    let dir = tempfile::tempdir().unwrap();
    let p = pki(dir.path());
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(
        &bad_pem,
        "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let bad_der = dir.path().join("bad-der.pem");
    std::fs::write(
        &bad_der,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    for (ca, needle) in [
        (None, "http.tls.client_ca"),
        (
            Some(dir.path().join("missing.pem")),
            "reading TLS client_ca",
        ),
        (Some(empty), "contains no certificates"),
        (Some(bad_pem), "parsing TLS client_ca"),
        (Some(bad_der), "TLS client_ca"),
    ] {
        let tls = roci_config::TlsConfig {
            cert: p.server_cert.clone(),
            key: p.server_key.clone(),
            client_auth: ClientAuth::Required,
            client_ca: ca,
            client_cert_sha256: vec![],
        };
        let err = build_tls_acceptor(&tls).err().unwrap().to_string();
        assert!(err.contains(needle), "{needle}: {err}");
    }
}

/// Serve through the in-process router (no socket).
async fn status(app: &axum::Router, uri: &str) -> u16 {
    let req = axum::http::Request::get(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    app.clone().call(req).await.unwrap().status().as_u16()
}

/// Poll until `uri` answers `want` (reload applies within a few intervals).
async fn eventually(app: &axum::Router, uri: &str, want: u16) {
    let mut last = 0;
    for _ in 0..100 {
        last = status(app, uri).await;
        if last == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(last, want, "{uri}");
}

#[tokio::test]
async fn access_control_reload_applies_valid_changes_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("roci.toml");
    let open = "[[access_control.repositories]]\npattern = \"team/**\"\nanonymous = [\"pull\"]\n";
    let closed = "[[access_control.repositories]]\npattern = \"team/**\"\n";
    std::fs::write(&path, open).unwrap();
    let config = Config::load(&path).unwrap();
    let auth = Auth::from_config(&config).unwrap().unwrap();
    let storage = FsStorage::new(dir.path().join("data")).unwrap();
    let app = build_router(
        AppState::new_with(storage, config.clone()).with_auth(Some(Arc::clone(&auth))),
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_access_control_reload(
        path.clone(),
        auth,
        config,
        Duration::from_millis(20),
        stop_rx,
    );
    let uri = "/v2/team/app/tags/list";
    assert_eq!(status(&app, uri).await, 200);

    // Invalid TOML: rejected, the open policy stays.
    std::fs::write(&path, "[[access_control.repositories]\n").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(status(&app, uri).await, 200);

    std::fs::write(&path, closed).unwrap();
    eventually(&app, uri, 403).await;
    std::fs::write(&path, open).unwrap();
    eventually(&app, uri, 200).await;

    // A change outside [access_control] is reported, not applied.
    std::fs::write(&path, format!("[log]\nlevel = \"debug\"\n{open}")).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(status(&app, uri).await, 200);

    // Section removed: anonymous requests are denied.
    std::fs::write(&path, "[log]\nlevel = \"debug\"\n").unwrap();
    eventually(&app, uri, 403).await;

    // An unreadable file is skipped.
    std::fs::remove_file(&path).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(status(&app, uri).await, 403);

    stop_tx.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn serve_enables_auth_and_starts_reload_from_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let htpasswd = dir.path().join("htpasswd");
    std::fs::write(&htpasswd, format!("u:{}\n", bcrypt_hash())).unwrap();
    let path = dir.path().join("roci.toml");
    std::fs::write(
        &path,
        format!(
            "[auth.htpasswd]\npath = {:?}\n",
            htpasswd.display().to_string()
        ),
    )
    .unwrap();
    let mut config = Config::load(&path).unwrap();
    config.http.listen = "127.0.0.1:0".parse().unwrap();
    config.storage.root = dir.path().join("data");
    let (addr, stop, handle) = start(config, Some(path)).await;
    let head = raw_get_head(addr).await;
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("www-authenticate: basic realm=\"roci\""),
        "{head}"
    );
    let _ = stop.send(());
    handle.await.unwrap().unwrap();

    // An unreadable htpasswd file aborts startup, naming the field.
    let mut bad = Config::default();
    bad.auth.htpasswd = Some(roci_config::HtpasswdConfig {
        path: dir.path().join("missing"),
    });
    let err = serve(bad, None, |_| {}, std::future::pending())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("invalid auth config: auth.htpasswd.path"),
        "{err}"
    );
}

/// A well-formed bcrypt hash; never verified by these tests (roci-cli has no
/// bcrypt dependency to generate one).
fn bcrypt_hash() -> &'static str {
    "$2b$04$KrtIV3GgqVN/zsz4cvWpFONOe0YjMr10VKF/qRxoPHtwSikBShbSm"
}

/// Plaintext `GET /v2/`; returns the response head.
async fn raw_get_head(addr: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    text.split("\r\n\r\n").next().unwrap().to_string()
}
