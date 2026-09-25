//! Docker v2 bearer-token verification (distribution token spec).
//!
//! roci does not issue tokens: an external token server signs a JWS, and
//! roci verifies it against configured public keys. Verification is a small
//! hand-rolled JWS check over `ring` (ES256 / RS256 only) rather than a JWT
//! crate, keeping the dependency tree free of the `rsa` crate (RUSTSEC-2023-0071).
//! Key-carrying headers (`jwk`, `jku`, `x5u`) are refused: the key set is
//! fixed by configuration, never chosen by the token.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256};
use roci_config::{Action, BearerConfig};
use serde::de::IgnoredAny;
use serde::Deserialize;
use x509_parser::der_parser::oid::Oid;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION};
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::ActionSet;

/// Longest accepted token (bounded parse work per request).
const MAX_TOKEN_LEN: usize = 8192;
/// Most `access` entries accepted in one token.
const MAX_ACCESS_ENTRIES: usize = 64;
/// Clock skew tolerated on `exp` / `nbf`.
const LEEWAY_SECS: u64 = 30;

#[derive(Debug)]
enum VerifyKey {
    /// Uncompressed P-256 point.
    Es256(Vec<u8>),
    /// DER `RSAPublicKey`.
    Rs256(Vec<u8>),
}

pub(crate) struct BearerVerifier {
    issuer: String,
    service: String,
    keys: Vec<VerifyKey>,
}

/// A verified token's identity and repository grants.
pub(crate) struct Verified {
    pub(crate) subject: Option<String>,
    pub(crate) grants: Vec<(String, ActionSet)>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    jwk: Option<IgnoredAny>,
    jku: Option<IgnoredAny>,
    x5u: Option<IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: u64,
    nbf: Option<u64>,
    sub: Option<String>,
    #[serde(default)]
    access: Vec<AccessEntry>,
}

#[derive(Deserialize)]
struct AccessEntry {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    #[serde(default)]
    actions: Vec<String>,
}

fn key_from_spki(spki: &SubjectPublicKeyInfo<'_>) -> Result<VerifyKey, String> {
    let alg = &spki.algorithm;
    let data = spki.subject_public_key.data.to_vec();
    if alg.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = alg.parameters.as_ref().and_then(|p| Oid::try_from(p).ok());
        if curve.as_ref() == Some(&OID_EC_P256) {
            return Ok(VerifyKey::Es256(data));
        }
        return Err("unsupported key algorithm (EC keys must be P-256)".into());
    }
    if alg.algorithm == OID_PKCS1_RSAENCRYPTION {
        return Ok(VerifyKey::Rs256(data));
    }
    Err("unsupported key algorithm".into())
}

impl BearerVerifier {
    /// Load the verification keys: every `PUBLIC KEY` / `CERTIFICATE` PEM
    /// block of `verify_key_file`.
    pub(crate) fn load(cfg: &BearerConfig) -> Result<Self, String> {
        let path = &cfg.verify_key_file;
        let pem = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let mut keys = Vec::new();
        for block in Pem::iter_from_buffer(&pem) {
            let block = block.map_err(|e| format!("invalid PEM: {e}"))?;
            let key = match block.label.as_str() {
                "CERTIFICATE" => {
                    let cert = block
                        .parse_x509()
                        .map_err(|e| format!("invalid certificate: {e}"))?;
                    key_from_spki(cert.public_key())?
                }
                "PUBLIC KEY" => {
                    let (_, spki) = SubjectPublicKeyInfo::from_der(&block.contents)
                        .map_err(|e| format!("invalid public key: {e}"))?;
                    key_from_spki(&spki)?
                }
                other => return Err(format!("unexpected PEM block `{other}`")),
            };
            keys.push(key);
        }
        if keys.is_empty() {
            return Err("no public keys found".into());
        }
        Ok(Self {
            issuer: cfg.issuer.clone(),
            service: cfg.service.clone(),
            keys,
        })
    }

    /// Verify `token` at `now` (Unix seconds). The `Err` reason is for debug
    /// logs only; clients always see "invalid credentials".
    pub(crate) fn verify(&self, token: &str, now: u64) -> Result<Verified, &'static str> {
        if token.len() > MAX_TOKEN_LEN {
            return Err("token too long");
        }
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("not a three-segment JWS");
        };
        let header: Header = decode_json(h)?;
        if header.jwk.is_some() || header.jku.is_some() || header.x5u.is_some() {
            return Err("key-carrying header");
        }
        let es256 = match header.alg.as_str() {
            "ES256" => true,
            "RS256" => false,
            _ => return Err("unsupported alg"),
        };
        let sig = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| "bad signature encoding")?;
        let signed = &token.as_bytes()[..h.len() + 1 + p.len()];
        let verified = self.keys.iter().any(|k| match (k, es256) {
            (VerifyKey::Es256(pk), true) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk)
                .verify(signed, &sig)
                .is_ok(),
            (VerifyKey::Rs256(pk), false) => {
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pk)
                    .verify(signed, &sig)
                    .is_ok()
            }
            _ => false,
        });
        if !verified {
            return Err("signature mismatch");
        }
        let claims: Claims = decode_json(p)?;
        if claims.iss != self.issuer {
            return Err("issuer mismatch");
        }
        let aud_ok = match &claims.aud {
            Audience::One(a) => *a == self.service,
            Audience::Many(v) => v.contains(&self.service),
        };
        if !aud_ok {
            return Err("audience mismatch");
        }
        if now > claims.exp.saturating_add(LEEWAY_SECS) {
            return Err("expired");
        }
        if claims
            .nbf
            .is_some_and(|nbf| nbf > now.saturating_add(LEEWAY_SECS))
        {
            return Err("not yet valid");
        }
        if claims.access.len() > MAX_ACCESS_ENTRIES {
            return Err("too many access entries");
        }
        let grants = claims
            .access
            .into_iter()
            .filter(|e| e.kind == "repository")
            .map(|e| {
                let set = e.actions.iter().fold(ActionSet::NONE, |s, a| {
                    s.union(match a.as_str() {
                        "pull" => ActionSet::of(Action::Pull),
                        "push" => ActionSet::of(Action::Push),
                        "delete" => ActionSet::of(Action::Delete),
                        "*" => ActionSet::ALL,
                        _ => ActionSet::NONE,
                    })
                });
                (e.name, set)
            })
            .collect();
        Ok(Verified {
            subject: claims.sub,
            grants,
        })
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, &'static str> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| "bad base64url segment")?;
    serde_json::from_slice(&bytes).map_err(|_| "bad JSON segment")
}

/// Whether the token grants include `action` on `repo`. Names compare in
/// constant time for equal lengths (no byte-by-byte timing oracle).
pub(crate) fn grants_allow(grants: &[(String, ActionSet)], repo: &str, action: Action) -> bool {
    grants
        .iter()
        .any(|(name, set)| ct_eq(name.as_bytes(), repo.as_bytes()) && set.contains(action))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::json;

    struct Signer {
        key: EcdsaKeyPair,
        verifier: BearerVerifier,
        _dir: tempfile::TempDir,
    }

    fn signer() -> Signer {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pem");
        std::fs::write(&path, kp.public_key_pem()).unwrap();
        let cfg = BearerConfig {
            realm: "https://auth.example/token".into(),
            service: "roci".into(),
            issuer: "issuer".into(),
            verify_key_file: path,
        };
        let key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &kp.serialize_der(),
            &SystemRandom::new(),
        )
        .unwrap();
        Signer {
            key,
            verifier: BearerVerifier::load(&cfg).unwrap(),
            _dir: dir,
        }
    }

    impl Signer {
        fn sign(&self, header: serde_json::Value, claims: serde_json::Value) -> String {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let sig = self
                .key
                .sign(&SystemRandom::new(), input.as_bytes())
                .unwrap();
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }
    }

    fn claims(aud: serde_json::Value, access: serde_json::Value) -> serde_json::Value {
        json!({ "iss": "issuer", "aud": aud, "exp": 2000, "sub": "ci", "access": access })
    }

    #[test]
    fn audience_forms_and_action_parsing() {
        let s = signer();
        let es = json!({ "alg": "ES256", "kid": "ignored", "x5c": ["ignored"] });
        let access = json!([
            { "type": "repository", "name": "a", "actions": ["pull", "bogus"] },
            { "type": "repository", "name": "b", "actions": ["*"] },
            { "type": "registry", "name": "catalog", "actions": ["*"] },
        ]);
        for aud in [json!("roci"), json!(["other", "roci"])] {
            let v = s
                .verifier
                .verify(&s.sign(es.clone(), claims(aud, access.clone())), 1000)
                .unwrap();
            assert_eq!(v.subject.as_deref(), Some("ci"));
            assert!(grants_allow(&v.grants, "a", Action::Pull));
            assert!(!grants_allow(&v.grants, "a", Action::Push));
            assert!(grants_allow(&v.grants, "b", Action::Delete));
            assert!(!grants_allow(&v.grants, "catalog", Action::Pull));
            assert!(!grants_allow(&v.grants, "ab", Action::Pull));
        }
        let wrong = s.sign(es, claims(json!(["other"]), json!([])));
        assert_eq!(
            s.verifier.verify(&wrong, 1000).err(),
            Some("audience mismatch")
        );
    }

    #[test]
    fn rejections() {
        let s = signer();
        let es = json!({ "alg": "ES256" });
        let good = claims(json!("roci"), json!([]));
        let many: Vec<_> = (0..65)
            .map(|i| json!({ "type": "repository", "name": format!("r{i}"), "actions": ["pull"] }))
            .collect();
        let ok = s.sign(es.clone(), good.clone());
        assert!(s.verifier.verify(&ok, 2030).is_ok(), "within leeway");
        let mut tampered = ok.clone().into_bytes();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        let mut nbf = good.clone();
        nbf["nbf"] = json!(1100);
        let mut iss = good.clone();
        iss["iss"] = json!("evil");
        let mut no_exp = good.clone();
        no_exp.as_object_mut().unwrap().remove("exp");
        for (token, now, why) in [
            (ok.clone(), 2031, "expired"),
            (s.sign(es.clone(), nbf), 1000, "not yet valid"),
            (s.sign(es.clone(), iss), 1000, "issuer mismatch"),
            (s.sign(es.clone(), no_exp), 1000, "bad JSON segment"),
            (
                s.sign(es.clone(), claims(json!("roci"), json!(many))),
                1000,
                "too many access entries",
            ),
            (tampered, 1000, "signature mismatch"),
            (
                s.sign(json!({ "alg": "none" }), good.clone()),
                1000,
                "unsupported alg",
            ),
            (
                s.sign(json!({ "alg": "ES256", "jwk": {} }), good.clone()),
                1000,
                "key-carrying header",
            ),
            (
                s.sign(json!({ "alg": "ES256", "jku": "https://x" }), good.clone()),
                1000,
                "key-carrying header",
            ),
            (
                s.sign(json!({ "alg": "ES256", "x5u": "https://x" }), good.clone()),
                1000,
                "key-carrying header",
            ),
            // An ES256 key never verifies an RS256-labelled token.
            (
                s.sign(json!({ "alg": "RS256" }), good.clone()),
                1000,
                "signature mismatch",
            ),
            ("a.b".into(), 1000, "not a three-segment JWS"),
            ("a.b.c.d".into(), 1000, "not a three-segment JWS"),
            ("!.b.c".into(), 1000, "bad base64url segment"),
            (
                format!("{}.b.c", URL_SAFE_NO_PAD.encode("[]")),
                1000,
                "bad JSON segment",
            ),
            (
                format!("{}.b.!", URL_SAFE_NO_PAD.encode(es.to_string())),
                1000,
                "bad signature encoding",
            ),
            ("x".repeat(MAX_TOKEN_LEN + 1), 1000, "token too long"),
        ] {
            assert_eq!(s.verifier.verify(&token, now).err(), Some(why), "{why}");
        }
    }

    #[test]
    fn key_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = |name: &str, content: Option<&str>| {
            let path = dir.path().join(name);
            if let Some(c) = content {
                std::fs::write(&path, c).unwrap();
            }
            BearerConfig {
                realm: "https://a".into(),
                service: "s".into(),
                issuer: "i".into(),
                verify_key_file: path,
            }
        };
        let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let bad_block = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let bad_cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let bad_pem = "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n";
        for (c, needle) in [
            (cfg("missing", None), "reading"),
            (cfg("empty", Some("")), "no public keys found"),
            (
                cfg("ed", Some(&ed.public_key_pem())),
                "unsupported key algorithm",
            ),
            (cfg("p384", Some(&p384.public_key_pem())), "must be P-256"),
            (
                cfg("priv", Some(&ed.serialize_pem())),
                "unexpected PEM block",
            ),
            (cfg("badkey", Some(bad_block)), "invalid public key"),
            (cfg("badcert", Some(bad_cert)), "invalid certificate"),
            (cfg("badpem", Some(bad_pem)), "invalid PEM"),
        ] {
            let err = BearerVerifier::load(&c).err().unwrap();
            assert!(err.contains(needle), "{needle}: {err}");
        }
        // A certificate's SubjectPublicKeyInfo is accepted as a key.
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["issuer".into()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        let v = BearerVerifier::load(&cfg("cert", Some(&cert.pem()))).unwrap();
        assert!(matches!(v.keys[..], [VerifyKey::Es256(_)]));
    }
}
