//! Authorization refusals are logged with the subject but never with the
//! credential (SECURITY: no passwords, tokens, or `Authorization` values in
//! logs). Its own test binary: it installs the process-wide `DEBUG`
//! subscriber, which a shared binary's concurrent tests would race.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use roci_config::Config;
use roci_core::auth::Auth;
use roci_core::{build_router, AppState};
use roci_storage::FsStorage;
use serde_json::json;
use tower::ServiceExt;

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

/// An ES256-signed bearer token for `issuer`/`registry` granting `pull` on
/// `team/app`, plus the PEM of its verification key.
fn token() -> (String, String) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &kp.serialize_der(), &rng)
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": "issuer", "aud": "registry", "sub": "ci-bot", "exp": now + 300,
        "access": [{ "type": "repository", "name": "team/app", "actions": ["pull"] }],
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(json!({ "alg": "ES256" }).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let sig = key.sign(&rng, input.as_bytes()).unwrap();
    (
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())),
        kp.public_key_pem(),
    )
}

#[tokio::test]
async fn refusal_logs_name_the_subject_but_never_credentials() {
    let logs = LogBuf::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let secret = "s3cr3t-Pa55word";
    let htpasswd = dir.path().join("htpasswd");
    std::fs::write(
        &htpasswd,
        format!("bob:{}", bcrypt::hash(secret, 4).unwrap()),
    )
    .unwrap();
    let (token, key_pem) = token();
    let key_file = dir.path().join("jwt.pem");
    std::fs::write(&key_file, key_pem).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
[auth.htpasswd]
path = {htpasswd:?}
[auth.bearer]
realm = "https://auth.example/token"
service = "registry"
issuer = "issuer"
verify_key_file = {key_file:?}
[[access_control.repositories]]
pattern = "team/**"
anonymous = ["pull"]
"#,
        htpasswd = htpasswd.display().to_string(),
        key_file = key_file.display().to_string(),
    ))
    .unwrap();
    let auth = Auth::from_config(&config).unwrap();
    let storage = FsStorage::new(dir.path().join("data")).unwrap();
    let app = build_router(AppState::new_with(storage, config).with_auth(auth));

    let basic = |pw: &str| format!("Basic {}", STANDARD.encode(format!("bob:{pw}")));
    let bearer = format!("Bearer {token}");
    for (method, uri, authz, want) in [
        // User, token, and anonymous refusals, then invalid credentials.
        (
            Method::POST,
            "/v2/team/app/blobs/uploads/",
            Some(basic(secret)),
            StatusCode::FORBIDDEN,
        ),
        (
            Method::POST,
            "/v2/team/app/blobs/uploads/",
            Some(bearer.clone()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::POST,
            "/v2/team/app/blobs/uploads/",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            Method::GET,
            "/v2/",
            Some(basic("wrong-Pa55")),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(a) = &authz {
            req = req.header(header::AUTHORIZATION, a);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), want, "{uri}");
    }

    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("authorization refused").count(), 3, "{text}");
    assert!(text.contains("bob") && text.contains("ci-bot"), "{text}");
    for leaked in [secret, "wrong-Pa55", token.as_str(), basic(secret).as_str()] {
        assert!(
            !text.contains(leaked),
            "credential leaked into logs: {text}"
        );
    }
}
