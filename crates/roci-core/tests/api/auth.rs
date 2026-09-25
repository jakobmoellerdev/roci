//! Authentication / authorization through the HTTP surface (Phase 6).

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{header, HeaderName, Method, Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
};
use roci_config::Config;
use roci_core::auth::ClientCertIdentity;
use serde_json::json;

use super::common::*;

const ROCI_BASIC: &str = "Basic realm=\"roci\"";

/// Write an htpasswd file (bcrypt cost 4) for `users`.
fn htpasswd(dir: &Path, users: &[(&str, &str)]) -> PathBuf {
    let path = dir.join("htpasswd");
    let lines: Vec<String> = users
        .iter()
        .map(|(u, p)| format!("{u}:{}", bcrypt::hash(p, 4).unwrap()))
        .collect();
    std::fs::write(&path, lines.join("\n")).unwrap();
    path
}

/// A config with htpasswd users `alice:pw`, `bob:pw`, `admin:pw` plus the
/// extra TOML `tail` (e.g. an `[access_control]` section).
fn htpasswd_config(dir: &Path, tail: &str) -> Config {
    let path = htpasswd(dir, &[("alice", "pw"), ("bob", "pw"), ("admin", "pw")]);
    let text = format!(
        "[auth.htpasswd]\npath = {:?}\n{tail}",
        path.display().to_string()
    );
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    config
}

fn basic(user: &str, pw: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pw}")))
}

fn as_user(
    method: Method,
    uri: impl AsRef<str>,
    auth: &str,
    body: impl Into<Body>,
) -> Request<Body> {
    request(method, uri, &[(header::AUTHORIZATION, auth)], body)
}

async fn error_code(resp: axum::response::Response) -> (String, String) {
    let v = json_body(resp).await;
    (
        v["errors"][0]["code"].as_str().unwrap().to_string(),
        v["errors"][0]["message"].as_str().unwrap().to_string(),
    )
}

const TEAM_POLICY: &str = r#"
[[access_control.repositories]]
pattern = "team/**"
anonymous = ["pull"]
policies = [{ users = ["alice"], actions = ["pull", "push"] }]
"#;

#[tokio::test]
async fn without_auth_config_registry_stays_open() {
    let (app, _d) = app();
    assert_eq!(status_of(&app, get("/v2/")).await, StatusCode::OK);
    let d = push_blob(&app, "r", b"data").await;
    let resp = send(&app, get(format!("/v2/r/blobs/{d}"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"data");
}

#[tokio::test]
async fn htpasswd_challenge_and_credential_checks() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _auth, _d) = app_with_auth(htpasswd_config(dir.path(), ""));

    let resp = send(&app, get("/v2/")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(ROCI_BASIC));
    assert_eq!(error_code(resp).await.0, "UNAUTHORIZED");

    let ok = as_user(Method::GET, "/v2/", &basic("alice", "pw"), Body::empty());
    assert_eq!(status_of(&app, ok).await, StatusCode::OK);
    // Cached on the second request: still accepted.
    let ok = as_user(Method::GET, "/v2/", &basic("alice", "pw"), Body::empty());
    assert_eq!(status_of(&app, ok).await, StatusCode::OK);

    for bad in [
        basic("alice", "wrong"),
        basic("mallory", "pw"),
        basic("", "pw"),
        "Basic !!!".to_string(),
        format!("Basic {}", STANDARD.encode("no-colon")),
        format!("Basic {}", STANDARD.encode([0xff, b':', b'x'])),
        "Digest username=alice".to_string(),
        "Bearer abc.def.ghi".to_string(),
        "garbage".to_string(),
    ] {
        let resp = send(&app, as_user(Method::GET, "/v2/", &bad, Body::empty())).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{bad}");
        assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(ROCI_BASIC));
        assert_eq!(
            error_code(resp).await,
            ("UNAUTHORIZED".into(), "invalid credentials".into())
        );
    }
    // A non-ASCII header value is invalid too.
    let mut req = get("/v2/");
    req.headers_mut().insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_bytes(b"Basic \xff").unwrap(),
    );
    assert_eq!(status_of(&app, req).await, StatusCode::UNAUTHORIZED);

    // No `[access_control]`: any authenticated user may do everything,
    // anonymous nothing.
    let push = as_user(
        Method::POST,
        "/v2/any/blobs/uploads/",
        &basic("bob", "pw"),
        Body::empty(),
    );
    assert_eq!(status_of(&app, push).await, StatusCode::ACCEPTED);
    let resp = send(&app, get("/v2/any/tags/list")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(ROCI_BASIC));
}

#[tokio::test]
async fn repository_policy_grants_and_denials() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _auth, _d) = app_with_auth(htpasswd_config(dir.path(), TEAM_POLICY));
    let alice = basic("alice", "pw");

    // Anonymous pull passes authorization (an unknown repo lists no tags).
    assert_eq!(
        status_of(&app, get("/v2/team/app/tags/list")).await,
        StatusCode::OK
    );
    // An empty Basic pair (containers/image without credentials) is anonymous.
    let empty = basic("", "");
    let pull = as_user(Method::GET, "/v2/team/app/tags/list", &empty, Body::empty());
    assert_eq!(status_of(&app, pull).await, StatusCode::OK);
    let resp = send(&app, as_user(Method::GET, "/v2/", &empty, Body::empty())).await;
    assert_eq!(
        error_code(resp).await,
        ("UNAUTHORIZED".into(), "authentication required".into())
    );

    // Anonymous push → 401 challenge.
    let resp = send(&app, post("/v2/team/app/blobs/uploads/", Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(ROCI_BASIC));
    assert_eq!(
        error_code(resp).await,
        ("UNAUTHORIZED".into(), "authentication required".into())
    );

    // A full chunked upload: every session endpoint requires push.
    let start = as_user(
        Method::POST,
        "/v2/team/app/blobs/uploads/",
        &alice,
        Body::empty(),
    );
    let resp = send(&app, start).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let loc = location(&resp);
    let chunk = as_user(Method::PATCH, &loc, &alice, "chunk");
    assert_eq!(status_of(&app, chunk).await, StatusCode::ACCEPTED);
    let probe = as_user(Method::GET, &loc, &basic("bob", "pw"), Body::empty());
    assert_eq!(status_of(&app, probe).await, StatusCode::FORBIDDEN);
    let status = as_user(Method::GET, &loc, &alice, Body::empty());
    assert_eq!(status_of(&app, status).await, StatusCode::NO_CONTENT);
    let d = roci_storage::sha256_of(b"chunk");
    let finish = as_user(
        Method::PUT,
        format!("{loc}?digest={d}"),
        &alice,
        Body::empty(),
    );
    assert_eq!(status_of(&app, finish).await, StatusCode::CREATED);

    // bob authenticates but holds no push grant → 403, not 401.
    let push = as_user(
        Method::POST,
        "/v2/team/app/blobs/uploads/",
        &basic("bob", "pw"),
        Body::empty(),
    );
    let resp = send(&app, push).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        error_code(resp).await,
        ("DENIED".into(), "access denied".into())
    );

    let del = as_user(
        Method::DELETE,
        "/v2/team/app/manifests/v1",
        &alice,
        Body::empty(),
    );
    assert_eq!(status_of(&app, del).await, StatusCode::FORBIDDEN);
    let other = as_user(
        Method::POST,
        "/v2/other/x/blobs/uploads/",
        &alice,
        Body::empty(),
    );
    assert_eq!(status_of(&app, other).await, StatusCode::FORBIDDEN);

    // Unknown shapes keep NAME_UNKNOWN without an authorization decision.
    let resp = send(&app, post("/v2/team/app/tags/list", Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn most_specific_rule_removes_broader_grants() {
    let dir = tempfile::tempdir().unwrap();
    let tail =
        format!("{TEAM_POLICY}\n[[access_control.repositories]]\npattern = \"team/secret\"\n");
    let (app, _auth, _d) = app_with_auth(htpasswd_config(dir.path(), &tail));
    let alice = basic("alice", "pw");
    let push = as_user(
        Method::POST,
        "/v2/team/secret/blobs/uploads/",
        &alice,
        Body::empty(),
    );
    assert_eq!(status_of(&app, push).await, StatusCode::FORBIDDEN);
    let pull = as_user(
        Method::GET,
        "/v2/team/secret/tags/list",
        &alice,
        Body::empty(),
    );
    assert_eq!(status_of(&app, pull).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cross_repo_mount_requires_pull_on_source() {
    let dir = tempfile::tempdir().unwrap();
    let policy = |src_actions: &str| {
        format!(
            r#"
[access_control]
admins = ["admin"]
[[access_control.repositories]]
pattern = "dst"
policies = [{{ users = ["alice"], actions = ["pull", "push"] }}]
[[access_control.repositories]]
pattern = "src"
policies = [{{ users = ["alice"], actions = [{src_actions}] }}]
"#
        )
    };
    let config = htpasswd_config(dir.path(), &policy("\"delete\""));
    let (app, auth, _d) = app_with_auth(config);
    let admin = basic("admin", "pw");
    let alice = basic("alice", "pw");

    let data = b"mount me";
    let d = roci_storage::sha256_of(data);
    let seed = as_user(
        Method::POST,
        format!("/v2/src/blobs/uploads/?digest={d}"),
        &admin,
        data.to_vec(),
    );
    assert_eq!(status_of(&app, seed).await, StatusCode::CREATED);

    let mount = |from: &str| {
        as_user(
            Method::POST,
            format!("/v2/dst/blobs/uploads/?mount={d}&from={from}"),
            &alice,
            Body::empty(),
        )
    };
    // No pull on `src`: a plain session, no mount, no existence oracle.
    assert_eq!(status_of(&app, mount("src")).await, StatusCode::ACCEPTED);
    let probe = || {
        as_user(
            Method::HEAD,
            format!("/v2/dst/blobs/{d}"),
            &admin,
            Body::empty(),
        )
    };
    assert_eq!(status_of(&app, probe()).await, StatusCode::NOT_FOUND);
    // A malformed source name falls through the same way.
    assert_eq!(status_of(&app, mount("Bad!")).await, StatusCode::ACCEPTED);

    let granted: Config = toml::from_str(&policy("\"pull\"")).unwrap();
    auth.reload_access_control(granted.access_control.as_ref());
    assert_eq!(status_of(&app, mount("src")).await, StatusCode::CREATED);
    assert_eq!(status_of(&app, probe()).await, StatusCode::OK);
}

/// ES256 + RS256 signers whose public keys share one `verify_key_file`.
struct Issuer {
    es: EcdsaKeyPair,
    rs: RsaKeyPair,
    key_file: PathBuf,
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn issuer(dir: &Path) -> Issuer {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let es = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &kp.serialize_der(),
        &SystemRandom::new(),
    )
    .unwrap();
    let rs_pem = std::fs::read_to_string(format!("{FIXTURES}/rsa2048.pk8.pem")).unwrap();
    let rs_der = STANDARD
        .decode(
            rs_pem
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap();
    let rs = RsaKeyPair::from_pkcs8(&rs_der).unwrap();
    let rs_pub = std::fs::read_to_string(format!("{FIXTURES}/rsa2048.pub.pem")).unwrap();
    let key_file = dir.join("jwt.pem");
    std::fs::write(&key_file, format!("{}{rs_pub}", kp.public_key_pem())).unwrap();
    Issuer { es, rs, key_file }
}

impl Issuer {
    fn token(
        &self,
        alg: &str,
        header_extra: serde_json::Value,
        claims: serde_json::Value,
    ) -> String {
        let mut header = json!({ "alg": alg, "typ": "JWT" });
        header
            .as_object_mut()
            .unwrap()
            .extend(header_extra.as_object().unwrap().clone());
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let rng = SystemRandom::new();
        let sig = if alg == "RS256" {
            let mut sig = vec![0; self.rs.public().modulus_len()];
            self.rs
                .sign(&RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut sig)
                .unwrap();
            sig
        } else {
            self.es
                .sign(&rng, input.as_bytes())
                .unwrap()
                .as_ref()
                .to_vec()
        };
        format!("Bearer {input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(access: serde_json::Value) -> serde_json::Value {
    json!({
        "iss": "token-issuer",
        "aud": "registry",
        "sub": "ci-bot",
        "exp": now() + 300,
        "nbf": now() - 5,
        "access": access,
    })
}

const BEARER_CHALLENGE: &str = "Bearer realm=\"https://auth.example/token\",service=\"registry\"";

fn bearer_config(dir: &Path, key_file: &Path, htpasswd_users: bool) -> Config {
    let mut text = format!(
        "[auth.bearer]\nrealm = \"https://auth.example/token\"\nservice = \"registry\"\n\
         issuer = \"token-issuer\"\nverify_key_file = {:?}\n",
        key_file.display().to_string()
    );
    if htpasswd_users {
        let path = htpasswd(dir, &[("alice", "pw")]);
        text.push_str(&format!(
            "[auth.htpasswd]\npath = {:?}\n",
            path.display().to_string()
        ));
    }
    let config: Config = toml::from_str(&text).unwrap();
    config.validate().unwrap();
    config
}

#[tokio::test]
async fn bearer_tokens_authorize_by_access_claims() {
    let dir = tempfile::tempdir().unwrap();
    let iss = issuer(dir.path());
    let (app, _auth, _d) = app_with_auth(bearer_config(dir.path(), &iss.key_file, false));

    let resp = send(&app, get("/v2/")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(BEARER_CHALLENGE));

    let access = json!([{ "type": "repository", "name": "team/app", "actions": ["pull", "push"] }]);
    for alg in ["ES256", "RS256"] {
        let token = iss.token(alg, json!({ "kid": "k1" }), claims(access.clone()));
        let ok = as_user(
            Method::POST,
            "/v2/team/app/blobs/uploads/",
            &token,
            Body::empty(),
        );
        assert_eq!(status_of(&app, ok).await, StatusCode::ACCEPTED, "{alg}");
        let base = as_user(Method::GET, "/v2/", &token, Body::empty());
        assert_eq!(status_of(&app, base).await, StatusCode::OK);
    }

    // Outside the token's scope → 401 insufficient_scope (a new token helps).
    let token = iss.token("ES256", json!({}), claims(access.clone()));
    let resp = send(
        &app,
        as_user(
            Method::POST,
            "/v2/team/other/blobs/uploads/",
            &token,
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        hv(&resp, header::WWW_AUTHENTICATE),
        Some(
            "Bearer realm=\"https://auth.example/token\",service=\"registry\",\
             scope=\"repository:team/other:pull,push\",error=\"insufficient_scope\""
        )
    );
    assert_eq!(error_code(resp).await.1, "insufficient scope");
    let del = as_user(
        Method::DELETE,
        "/v2/team/app/manifests/v1",
        &token,
        Body::empty(),
    );
    let resp = send(&app, del).await;
    assert!(hv(&resp, header::WWW_AUTHENTICATE)
        .unwrap()
        .contains("scope=\"repository:team/app:delete\""));

    // Anonymous pull: challenge scope asks for `pull` only.
    let resp = send(&app, get("/v2/team/app/tags/list")).await;
    assert!(hv(&resp, header::WWW_AUTHENTICATE)
        .unwrap()
        .ends_with("scope=\"repository:team/app:pull\""));
    // Anonymous push: challenge carries the needed scope.
    let resp = send(&app, post("/v2/team/app/blobs/uploads/", Body::empty())).await;
    assert_eq!(
        hv(&resp, header::WWW_AUTHENTICATE),
        Some(
            "Bearer realm=\"https://auth.example/token\",service=\"registry\",\
             scope=\"repository:team/app:pull,push\""
        )
    );

    // Invalid tokens: 401 + a scope-less challenge.
    let mut expired = claims(access.clone());
    expired["exp"] = json!(now() - 3600);
    let mut wrong_iss = claims(access.clone());
    wrong_iss["iss"] = json!("evil");
    let mut wrong_aud = claims(access.clone());
    wrong_aud["aud"] = json!(["other"]);
    let good = iss.token("ES256", json!({}), claims(access.clone()));
    // Flip the signature's first character (always a full 6 data bits).
    let sig_at = good.rfind('.').unwrap() + 1;
    let flipped = if &good[sig_at..=sig_at] == "A" {
        "B"
    } else {
        "A"
    };
    let tampered = format!("{}{flipped}{}", &good[..sig_at], &good[sig_at + 1..]);
    let alg_none = {
        let t = iss.token("ES256", json!({}), claims(access.clone()));
        let parts: Vec<&str> = t["Bearer ".len()..].split('.').collect();
        format!(
            "Bearer {}.{}.",
            URL_SAFE_NO_PAD.encode(json!({ "alg": "none" }).to_string()),
            parts[1]
        )
    };
    for bad in [
        iss.token("ES256", json!({}), expired),
        iss.token("ES256", json!({}), wrong_iss),
        iss.token("ES256", json!({}), wrong_aud),
        iss.token(
            "ES256",
            json!({ "jwk": { "kty": "EC" } }),
            claims(access.clone()),
        ),
        tampered,
        alg_none,
    ] {
        let resp = send(&app, as_user(Method::GET, "/v2/", &bad, Body::empty())).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(BEARER_CHALLENGE));
        assert_eq!(error_code(resp).await.1, "invalid credentials");
    }
}

#[tokio::test]
async fn bearer_challenge_wins_but_basic_still_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let iss = issuer(dir.path());
    let (app, _auth, _d) = app_with_auth(bearer_config(dir.path(), &iss.key_file, true));
    let resp = send(&app, get("/v2/")).await;
    assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), Some(BEARER_CHALLENGE));
    let push = as_user(
        Method::POST,
        "/v2/r/blobs/uploads/",
        &basic("alice", "pw"),
        Body::empty(),
    );
    assert_eq!(status_of(&app, push).await, StatusCode::ACCEPTED);
}

fn with_cert(mut req: Request<Body>, name: &str) -> Request<Body> {
    req.extensions_mut().insert(ClientCertIdentity(name.into()));
    req
}

#[tokio::test]
async fn client_certificate_identity_and_header_precedence() {
    let config: Config = toml::from_str("[access_control]\nadmins = [\"alice\"]\n").unwrap();
    let (app, _auth, _d) = app_with_auth(config);

    let push = with_cert(post("/v2/r/blobs/uploads/", Body::empty()), "alice");
    assert_eq!(status_of(&app, push).await, StatusCode::ACCEPTED);
    // No header mechanism: anonymous `/v2/` is open, anonymous repo access
    // denied by policy (403, nothing to challenge for).
    assert_eq!(status_of(&app, get("/v2/")).await, StatusCode::OK);
    let resp = send(&app, get("/v2/r/tags/list")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        error_code(resp).await,
        ("DENIED".into(), "anonymous access denied by policy".into())
    );
    // A present Authorization header decides, even beside a valid cert.
    let req = with_cert(
        as_user(
            Method::POST,
            "/v2/r/blobs/uploads/",
            &basic("alice", "x"),
            Body::empty(),
        ),
        "alice",
    );
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::WWW_AUTHENTICATE), None);
    // A certificate identity outside the policy is an authenticated user.
    let push = with_cert(post("/v2/r/blobs/uploads/", Body::empty()), "carol");
    assert_eq!(status_of(&app, push).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn early_data_refuses_unsafe_methods() {
    let (app, _d) = app();
    let early: (HeaderName, &str) = (HeaderName::from_static("early-data"), "1");
    let resp = send(
        &app,
        request(
            Method::POST,
            "/v2/r/blobs/uploads/",
            std::slice::from_ref(&early),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 425);
    assert_eq!(
        error_code(resp).await,
        (
            "DENIED".into(),
            "request sent in TLS early data; retry after the handshake completes".into()
        )
    );
    let resp = send(&app, request(Method::GET, "/v2/", &[early], Body::empty())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let other = (HeaderName::from_static("early-data"), "0");
    let resp = send(
        &app,
        request(
            Method::POST,
            "/v2/r/blobs/uploads/",
            &[other],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn access_control_reload_takes_effect_on_the_same_router() {
    let dir = tempfile::tempdir().unwrap();
    let (app, auth, _d) = app_with_auth(htpasswd_config(dir.path(), TEAM_POLICY));
    let anon_pull = || get("/v2/team/app/tags/list");
    assert_eq!(status_of(&app, anon_pull()).await, StatusCode::OK);

    let tightened: Config = toml::from_str(
        "[[access_control.repositories]]\npattern = \"team/**\"\n\
         policies = [{ users = [\"alice\"], actions = [\"pull\"] }]\n",
    )
    .unwrap();
    auth.reload_access_control(tightened.access_control.as_ref());
    assert_eq!(status_of(&app, anon_pull()).await, StatusCode::UNAUTHORIZED);
    let push = || {
        as_user(
            Method::POST,
            "/v2/team/app/blobs/uploads/",
            &basic("alice", "pw"),
            Body::empty(),
        )
    };
    assert_eq!(status_of(&app, push()).await, StatusCode::FORBIDDEN);

    // Section removed: authenticated users may do everything again.
    auth.reload_access_control(None);
    assert_eq!(status_of(&app, push()).await, StatusCode::ACCEPTED);
    assert_eq!(status_of(&app, anon_pull()).await, StatusCode::UNAUTHORIZED);
}

/// An upload rejected before its body is read must announce `Connection:
/// close` on HTTP/1: hyper closes the socket anyway, and a client that pooled
/// it would send its authenticated retry into a dead connection (EOF).
#[tokio::test]
async fn unread_request_body_closes_http1_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _auth, _d) = app_with_auth(htpasswd_config(dir.path(), ""));
    let data = b"layer bytes".to_vec();
    let upload = format!(
        "/v2/r/blobs/uploads/?digest={}",
        roci_storage::sha256_of(&data)
    );

    // Anonymous upload: 401 before the body is read.
    let resp = send(&app, post(&upload, data.clone())).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::CONNECTION), Some("close"));

    // Same rejection over HTTP/2: the header is illegal there, never sent.
    let mut h2 = post(&upload, data.clone());
    *h2.version_mut() = axum::http::Version::HTTP_2;
    let resp = send(&app, h2).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::CONNECTION), None);

    // A body-less rejection leaves nothing unread: keep-alive stays.
    let resp = send(&app, get("/v2/r/tags/list")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hv(&resp, header::CONNECTION), None);

    // The authenticated upload consumes its body: keep-alive stays.
    let ok = as_user(Method::POST, &upload, &basic("alice", "pw"), data);
    let resp = send(&app, ok).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(hv(&resp, header::CONNECTION), None);
}
