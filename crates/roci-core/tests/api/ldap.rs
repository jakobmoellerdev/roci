use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, StatusCode};
use futures::{SinkExt, StreamExt};
use ldap3_proto::{LdapCodec, LdapFilter, LdapPartialAttribute, LdapSearchResultEntry, ServerOps};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use roci_config::Config;
use roci_core::auth::Auth;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;

use super::common::*;

struct CertBundle {
    acceptor: TlsAcceptor,
    ca_pem: String,
}

/// Self-signed CA + server cert for `localhost`.
fn tls_bundle() -> CertBundle {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-ca");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let srv_key = KeyPair::generate().unwrap();
    let srv_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(srv_key.serialize_der());
    let cert_der = rustls::pki_types::CertificateDer::from(srv_cert.der().to_vec());

    let tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der.into())
    .unwrap();

    CertBundle {
        acceptor: TlsAcceptor::from(Arc::new(tls_cfg)),
        ca_pem: ca_cert.pem(),
    }
}

/// Mock LDAP server settings.
#[derive(Clone)]
struct MockConfig {
    service_dn: String,
    service_pw: String,
    accept_service_bind: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            service_dn: "cn=svc,dc=x".into(),
            service_pw: "svcpw".into(),
            accept_service_bind: true,
        }
    }
}

struct MockServer {
    port: u16,
    bind_count: Arc<AtomicUsize>,
    user_bind_count: Arc<AtomicUsize>,
}

fn extract_uid(filter: &LdapFilter) -> Option<String> {
    match filter {
        LdapFilter::And(children) => children.iter().find_map(extract_uid),
        LdapFilter::Equality(attr, val) if attr.eq_ignore_ascii_case("uid") => Some(val.clone()),
        _ => None,
    }
}

/// Start a mock LDAPS server.
async fn start_mock(bundle: &CertBundle, cfg: MockConfig) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = bundle.acceptor.clone();
    let bind_count = Arc::new(AtomicUsize::new(0));
    let user_bind_count = Arc::new(AtomicUsize::new(0));
    let bc = Arc::clone(&bind_count);
    let ubc = Arc::clone(&user_bind_count);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acc = acceptor.clone();
            let cfg = cfg.clone();
            let bc = Arc::clone(&bc);
            let ubc = Arc::clone(&ubc);
            tokio::spawn(async move {
                let Ok(tls) = acc.accept(stream).await else {
                    return;
                };
                let mut framed = Framed::new(tls, LdapCodec::default());
                let mut service_bound = false;
                while let Some(Ok(msg)) = framed.next().await {
                    let Ok(op) = ServerOps::try_from(msg) else {
                        continue;
                    };
                    match op {
                        ServerOps::SimpleBind(req) => {
                            bc.fetch_add(1, Ordering::Relaxed);
                            let resp = if !service_bound
                                && req.dn == cfg.service_dn
                                && req.pw == cfg.service_pw
                            {
                                if cfg.accept_service_bind {
                                    service_bound = true;
                                    req.gen_success()
                                } else {
                                    req.gen_invalid_cred()
                                }
                            } else {
                                ubc.fetch_add(1, Ordering::Relaxed);
                                if req.dn == "uid=alice,ou=people,dc=x" && req.pw == "secret" {
                                    req.gen_success()
                                } else {
                                    req.gen_invalid_cred()
                                }
                            };
                            let _ = framed.send(resp).await;
                        }
                        ServerOps::Search(req) => {
                            let uid = extract_uid(&req.filter);
                            if uid.as_deref() == Some("alice") {
                                let entry = LdapSearchResultEntry {
                                    dn: "uid=alice,ou=people,dc=x".into(),
                                    attributes: vec![LdapPartialAttribute {
                                        atype: "memberOf".into(),
                                        vals: vec![b"cn=devs,dc=x".to_vec()],
                                    }],
                                };
                                let _ = framed.send(req.gen_result_entry(entry)).await;
                            }
                            let _ = framed.send(req.gen_success()).await;
                        }
                        ServerOps::Unbind(_) => break,
                        _ => {}
                    }
                }
            });
        }
    });

    MockServer {
        port,
        bind_count,
        user_bind_count,
    }
}

/// Silent TLS server for timeout testing.
async fn start_silent_server(bundle: &CertBundle) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = bundle.acceptor.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acc = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acc.accept(stream).await {
                    let _framed = Framed::new(tls, LdapCodec::default());
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                }
            });
        }
    });
    port
}

fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

fn ldap_config(dir: &Path, port: u16, ca_pem: &str, tail: &str) -> Config {
    let pw_file = write_file(dir, "svc.pw", "svcpw");
    let ca_file = write_file(dir, "ca.pem", ca_pem);
    let text = format!(
        r#"
[auth.ldap]
url = "ldaps://localhost:{port}"
bind_dn = "cn=svc,dc=x"
bind_password_file = "{pw_file}"
base_dn = "dc=x"
user_attribute = "uid"
group_attribute = "memberOf"
ca_file = "{ca_file}"
{tail}
"#,
        pw_file = pw_file.display(),
        ca_file = ca_file.display(),
    );
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    config
}

fn ldap_config_with_timeout(dir: &Path, port: u16, ca_pem: &str, timeout_secs: u64) -> Config {
    ldap_config(dir, port, ca_pem, &format!("timeout_secs = {timeout_secs}"))
}

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn correct_password_returns_200() {
    let bundle = tls_bundle();
    let mock = start_mock(&bundle, MockConfig::default()).await;
    let dir = tempfile::tempdir().unwrap();
    // No group_attribute: the search requests no attributes ("1.1").
    let mut config = ldap_config(dir.path(), mock.port, &bundle.ca_pem, "");
    config.auth.ldap.as_mut().unwrap().group_attribute = None;
    let (app, _auth, _dir) = app_with_auth(config);

    let resp = send(
        &app,
        as_user(
            Method::GET,
            "/v2/",
            &basic("alice", "secret"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn group_policy_grants_push() {
    let bundle = tls_bundle();
    let mock = start_mock(&bundle, MockConfig::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let config = ldap_config(
        dir.path(),
        mock.port,
        &bundle.ca_pem,
        r#"
[access_control]
[[access_control.repositories]]
pattern = "team/**"
policies = [{ groups = ["cn=devs,dc=x"], actions = ["pull", "push"] }]
"#,
    );
    let (app, _auth, _dir) = app_with_auth(config);

    let resp = send(
        &app,
        as_user(
            Method::POST,
            "/v2/team/app/blobs/uploads/",
            &basic("alice", "secret"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn bad_credential_variants_return_401() {
    let bundle = tls_bundle();
    let mock = start_mock(&bundle, MockConfig::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let config = ldap_config(dir.path(), mock.port, &bundle.ca_pem, "");
    let (app, _auth, _dir) = app_with_auth(config);

    for (label, user, pw) in [
        ("wrong password", "alice", "wrong"),
        ("unknown user", "nobody", "secret"),
    ] {
        let resp = send(
            &app,
            as_user(Method::GET, "/v2/", &basic(user, pw), Body::empty()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{label}");
    }

    // The empty-password guard fires before contacting the server.
    let binds_before = mock.bind_count.load(Ordering::Relaxed);
    let resp = send(
        &app,
        as_user(Method::GET, "/v2/", &basic("alice", ""), Body::empty()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "empty password");
    assert_eq!(
        mock.bind_count.load(Ordering::Relaxed),
        binds_before,
        "empty password must not trigger a bind"
    );
}

#[tokio::test]
async fn timeout_returns_401_within_budget() {
    let bundle = tls_bundle();
    let port = start_silent_server(&bundle).await;
    let dir = tempfile::tempdir().unwrap();
    let config = ldap_config_with_timeout(dir.path(), port, &bundle.ca_pem, 1);
    let (app, _auth, _dir) = app_with_auth(config);

    let start = std::time::Instant::now();
    let resp = send(
        &app,
        as_user(
            Method::GET,
            "/v2/",
            &basic("alice", "secret"),
            Body::empty(),
        ),
    )
    .await;
    let elapsed = start.elapsed();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "expected < 3 s, got {elapsed:?}"
    );
}

#[test]
fn loader_config_error_cases() {
    let dir = tempfile::tempdir().unwrap();
    let pw_file = write_file(dir.path(), "svc.pw", "pw");
    let ca_file = write_file(dir.path(), "empty.pem", "not a cert\n");

    let cases: &[(&str, String, &str)] = &[
        (
            "missing bind_password_file",
            r#"
[auth.ldap]
url = "ldaps://localhost:636"
bind_dn = "cn=svc,dc=x"
bind_password_file = "/nonexistent/pw"
base_dn = "dc=x"
"#
            .to_string(),
            "auth.ldap.bind_password_file",
        ),
        (
            "missing ca_file",
            format!(
                r#"
[auth.ldap]
url = "ldaps://localhost:636"
bind_dn = "cn=svc,dc=x"
bind_password_file = "{pw_file}"
base_dn = "dc=x"
ca_file = "/nonexistent/ca.pem"
"#,
                pw_file = pw_file.display(),
            ),
            "auth.ldap.ca_file",
        ),
        (
            "ca_file with no certificates",
            format!(
                r#"
[auth.ldap]
url = "ldaps://localhost:636"
bind_dn = "cn=svc,dc=x"
bind_password_file = "{pw_file}"
base_dn = "dc=x"
ca_file = "{ca_file}"
"#,
                pw_file = pw_file.display(),
                ca_file = ca_file.display(),
            ),
            "auth.ldap.ca_file",
        ),
    ];

    for (label, toml_text, expected_field) in cases {
        let config: Config = toml::from_str(toml_text).unwrap();
        config.validate().unwrap();
        let err = match Auth::from_config(&config) {
            Err(e) => e,
            Ok(_) => panic!("{label}: expected Err"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains(expected_field),
            "{label}: expected '{expected_field}' in error: {msg}"
        );
    }
}

#[test]
fn loader_without_ca_file_uses_system_roots() {
    let dir = tempfile::tempdir().unwrap();
    let pw_file = write_file(dir.path(), "svc.pw", "pw");
    let text = format!(
        r#"
[auth.ldap]
url = "ldaps://localhost:636"
bind_dn = "cn=svc,dc=x"
bind_password_file = "{pw_file}"
base_dn = "dc=x"
"#,
        pw_file = pw_file.display(),
    );
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    let result = Auth::from_config(&config);
    assert!(result.is_ok(), "expected Ok, got Err");
}

#[tokio::test]
async fn htpasswd_user_wrong_password_does_not_fall_to_ldap() {
    let bundle = tls_bundle();
    let mock = start_mock(&bundle, MockConfig::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let hp = htpasswd(dir.path(), &[("alice", "htpw")]);
    let pw_file = write_file(dir.path(), "svc.pw", "svcpw");
    let ca_file = write_file(dir.path(), "ca.pem", &bundle.ca_pem);
    let text = format!(
        r#"
[auth.htpasswd]
path = "{hp}"

[auth.ldap]
url = "ldaps://localhost:{port}"
bind_dn = "cn=svc,dc=x"
bind_password_file = "{pw_file}"
base_dn = "dc=x"
group_attribute = "memberOf"
ca_file = "{ca_file}"
"#,
        hp = hp.display(),
        port = mock.port,
        pw_file = pw_file.display(),
        ca_file = ca_file.display(),
    );
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    let (app, _auth, _dir) = app_with_auth(config);

    let resp = send(
        &app,
        as_user(Method::GET, "/v2/", &basic("alice", "wrong"), Body::empty()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        mock.user_bind_count.load(Ordering::Relaxed),
        0,
        "htpasswd user with bad password must not fall through to LDAP"
    );
}

#[tokio::test]
async fn unknown_htpasswd_user_authenticates_via_ldap() {
    let bundle = tls_bundle();
    let mock = start_mock(&bundle, MockConfig::default()).await;
    let dir = tempfile::tempdir().unwrap();
    let hp = htpasswd(dir.path(), &[("bob", "htpw")]);
    let pw_file = write_file(dir.path(), "svc.pw", "svcpw");
    let ca_file = write_file(dir.path(), "ca.pem", &bundle.ca_pem);
    let text = format!(
        r#"
[auth.htpasswd]
path = "{hp}"

[auth.ldap]
url = "ldaps://localhost:{port}"
bind_dn = "cn=svc,dc=x"
bind_password_file = "{pw_file}"
base_dn = "dc=x"
group_attribute = "memberOf"
ca_file = "{ca_file}"
"#,
        hp = hp.display(),
        port = mock.port,
        pw_file = pw_file.display(),
        ca_file = ca_file.display(),
    );
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    let (app, _auth, _dir) = app_with_auth(config);

    let resp = send(
        &app,
        as_user(
            Method::GET,
            "/v2/",
            &basic("alice", "secret"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn service_bind_rejected_returns_401() {
    let bundle = tls_bundle();
    let cfg = MockConfig {
        accept_service_bind: false,
        ..MockConfig::default()
    };
    let mock = start_mock(&bundle, cfg).await;
    let dir = tempfile::tempdir().unwrap();
    let config = ldap_config(dir.path(), mock.port, &bundle.ca_pem, "");
    let (app, _auth, _dir) = app_with_auth(config);

    let resp = send(
        &app,
        as_user(
            Method::GET,
            "/v2/",
            &basic("alice", "secret"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
