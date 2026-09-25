//! Authentication and authorization (SECURITY.md §AuthN/AuthZ).
//!
//! [`Auth`] resolves each request to a [`Principal`] — from the
//! `Authorization` header (htpasswd / LDAP Basic, or an externally issued
//! Docker v2 bearer token), else a verified mTLS client certificate, else
//! Anonymous — and decides whether that principal may perform a repository
//! [`Action`]. The decision runs in `routes::dispatch` between path parsing
//! and the handler, so no `Storage` call precedes it (ARCHITECTURE inv. 3,
//! SECURITY inv. 1).
//!
//! Credentials, tokens, and `Authorization` values are never logged.

mod bearer;
mod cache;
mod htpasswd;
mod identity;
#[cfg(feature = "ldap")]
mod ldap;
pub(crate) mod middleware;
mod policy;

use std::fmt::Write as _;
use std::sync::{Arc, PoisonError, RwLock};

use axum::http::{header, HeaderMap, HeaderValue};
use base64::Engine as _;
use roci_config::{AccessControlConfig, Action, ClientAuth, Config};

use crate::error::{ApiError, ErrorCode};
use bearer::BearerVerifier;
use cache::CredentialCache;
use htpasswd::{Htpasswd, HtpasswdResult};
pub use identity::client_cert_identity;
use policy::AccessPolicy;

/// A set of [`Action`]s as a bitmask.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ActionSet(u8);

impl ActionSet {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const ALL: Self = Self(0b111);

    pub(crate) fn of(a: Action) -> Self {
        Self(match a {
            Action::Pull => 1,
            Action::Push => 2,
            Action::Delete => 4,
        })
    }

    pub(crate) fn from_actions(actions: &[Action]) -> Self {
        actions
            .iter()
            .fold(Self::NONE, |s, a| s.union(Self::of(*a)))
    }

    pub(crate) fn contains(self, a: Action) -> bool {
        self.0 & Self::of(a).0 != 0
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The token-scope action list a client must request for `action` (a push
/// session also reads, so clients ask for `pull,push`).
fn challenge_actions(action: Action) -> &'static str {
    match action {
        Action::Pull => "pull",
        Action::Push => "pull,push",
        Action::Delete => "delete",
    }
}

/// How a [`Principal::User`] proved its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMethod {
    Htpasswd,
    #[cfg(feature = "ldap")]
    Ldap,
    Mtls,
}

impl AuthMethod {
    fn label(self) -> &'static str {
        match self {
            AuthMethod::Htpasswd => "htpasswd",
            #[cfg(feature = "ldap")]
            AuthMethod::Ldap => "ldap",
            AuthMethod::Mtls => "mtls",
        }
    }
}

/// The authenticated caller of one request.
#[derive(Debug, Clone)]
pub(crate) enum Principal {
    Anonymous,
    /// A named user, authorized by the `[access_control]` policy.
    User {
        name: Arc<str>,
        /// Directory groups (LDAP only), matched against policy `groups`.
        ldap_groups: Arc<[String]>,
        method: AuthMethod,
    },
    /// A bearer token, authorized solely by its `access` claims.
    Token {
        subject: Option<Arc<str>>,
        grants: Arc<[(String, ActionSet)]>,
    },
}

static ANONYMOUS: Principal = Principal::Anonymous;

impl Principal {
    fn method_label(&self) -> &'static str {
        match self {
            Principal::Anonymous => "anonymous",
            Principal::User { method, .. } => method.label(),
            Principal::Token { .. } => "bearer",
        }
    }

    fn subject(&self) -> Option<&str> {
        match self {
            Principal::Anonymous => None,
            Principal::User { name, .. } => Some(name),
            Principal::Token { subject, .. } => subject.as_deref(),
        }
    }
}

/// The principal the auth middleware attached to a request; Anonymous when
/// none was attached.
pub(crate) fn principal_of(ext: &axum::http::Extensions) -> &Principal {
    ext.get::<Principal>().unwrap_or(&ANONYMOUS)
}

/// Identity from a verified mTLS client certificate, inserted into the
/// request extensions by the connection layer.
#[derive(Debug, Clone)]
pub struct ClientCertIdentity(pub Arc<str>);

/// Failure to build [`Auth`] from configuration, naming the config field.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("{field}: {reason}")]
    Load { field: String, reason: String },
}

fn load_err(field: &str, reason: impl Into<String>) -> AuthError {
    AuthError::Load {
        field: field.into(),
        reason: reason.into(),
    }
}

struct Bearer {
    verifier: BearerVerifier,
    realm: String,
    service: String,
}

/// The authentication mechanisms and access policy of one registry.
pub struct Auth {
    realm: String,
    htpasswd: Option<Htpasswd>,
    #[cfg(feature = "ldap")]
    ldap: Option<ldap::LdapAuthenticator>,
    bearer: Option<Bearer>,
    mtls: bool,
    cache: CredentialCache,
    policy: RwLock<Option<Arc<AccessPolicy>>>,
}

impl Auth {
    /// Build the auth engine, or `None` when nothing auth-related is
    /// configured (the registry then stays fully open, as before Phase 6).
    /// Reads the htpasswd file, bearer verification keys, and LDAP service
    /// password now, so a bad file fails startup.
    pub fn from_config(config: &Config) -> Result<Option<Arc<Auth>>, AuthError> {
        let a = &config.auth;
        let mtls = config
            .http
            .tls
            .as_ref()
            .is_some_and(|t| t.client_auth != ClientAuth::None);
        if a.htpasswd.is_none()
            && a.ldap.is_none()
            && a.bearer.is_none()
            && config.access_control.is_none()
            && !mtls
        {
            return Ok(None);
        }
        let htpasswd = a
            .htpasswd
            .as_ref()
            .map(|h| Htpasswd::load(&h.path).map_err(|r| load_err("auth.htpasswd.path", r)))
            .transpose()?;
        #[cfg(not(feature = "ldap"))]
        if a.ldap.is_some() {
            return Err(load_err(
                "auth.ldap",
                "requires a roci build with the `ldap` feature",
            ));
        }
        #[cfg(feature = "ldap")]
        let ldap = a
            .ldap
            .as_ref()
            .map(ldap::LdapAuthenticator::new)
            .transpose()?;
        let bearer = a
            .bearer
            .as_ref()
            .map(|b| {
                Ok::<_, AuthError>(Bearer {
                    verifier: BearerVerifier::load(b)
                        .map_err(|r| load_err("auth.bearer.verify_key_file", r))?,
                    realm: b.realm.clone(),
                    service: b.service.clone(),
                })
            })
            .transpose()?;
        Ok(Some(Arc::new(Auth {
            realm: a.realm.clone(),
            htpasswd,
            #[cfg(feature = "ldap")]
            ldap,
            bearer,
            mtls,
            cache: CredentialCache::new(std::time::Duration::from_secs(a.cache_ttl_secs)),
            policy: RwLock::new(config.access_control.as_ref().map(AccessPolicy::compile)),
        })))
    }

    /// Replace the access-control policy (live reload). `None` → every
    /// authenticated identity may do everything, anonymous nothing.
    pub fn reload_access_control(&self, ac: Option<&AccessControlConfig>) {
        let compiled = ac.map(AccessPolicy::compile);
        *self.policy.write().unwrap_or_else(PoisonError::into_inner) = compiled;
    }

    fn policy(&self) -> Option<Arc<AccessPolicy>> {
        self.policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn ldap_configured(&self) -> bool {
        #[cfg(feature = "ldap")]
        return self.ldap.is_some();
        #[cfg(not(feature = "ldap"))]
        false
    }

    /// Whether a mechanism carried in the `Authorization` header is
    /// configured — i.e. whether a challenge can lead the client anywhere.
    pub(crate) fn has_header_mechanism(&self) -> bool {
        self.htpasswd.is_some() || self.ldap_configured() || self.bearer.is_some()
    }

    /// Resolve the request's principal. A present `Authorization` header
    /// decides alone (invalid → `401`, never a silent anonymous fallback);
    /// otherwise a verified client certificate; otherwise Anonymous.
    ///
    /// `Basic` with an empty user *and* password carries no identity claim:
    /// containers/image clients (skopeo, podman, buildah) answer a Basic
    /// challenge that way when they hold no credentials, so it counts as no
    /// header rather than as invalid credentials.
    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
        cert: Option<&ClientCertIdentity>,
    ) -> Result<Principal, ApiError> {
        let presented = headers
            .get(header::AUTHORIZATION)
            .filter(|v| !is_empty_basic(v));
        if let Some(value) = presented {
            return self.authenticate_header(value).await.map_err(|method| {
                roci_telemetry::record_auth_decision(method, "invalid");
                ApiError::Unauthenticated {
                    message: "invalid credentials".into(),
                    challenge: self.challenge(None, false),
                }
            });
        }
        Ok(match cert {
            Some(id) => Principal::User {
                name: Arc::clone(&id.0),
                ldap_groups: Arc::from([]),
                method: AuthMethod::Mtls,
            },
            None => Principal::Anonymous,
        })
    }

    /// Authenticate an `Authorization` value; `Err` carries the metric
    /// method label of the failed attempt.
    async fn authenticate_header(&self, value: &HeaderValue) -> Result<Principal, &'static str> {
        let value = value.to_str().map_err(|_| "anonymous")?;
        let (scheme, cred) = value.split_once(' ').ok_or("anonymous")?;
        let cred = cred.trim();
        if scheme.eq_ignore_ascii_case("basic") {
            self.authenticate_basic(cred).await
        } else if scheme.eq_ignore_ascii_case("bearer") {
            let b = self.bearer.as_ref().ok_or("bearer")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let v = b.verifier.verify(cred, now).map_err(|reason| {
                tracing::debug!(reason, "bearer token rejected");
                "bearer"
            })?;
            Ok(Principal::Token {
                subject: v.subject.map(Arc::from),
                grants: v.grants.into(),
            })
        } else {
            Err("anonymous")
        }
    }

    async fn authenticate_basic(&self, cred: &str) -> Result<Principal, &'static str> {
        let label = if self.htpasswd.is_some() || !self.ldap_configured() {
            "htpasswd"
        } else {
            "ldap"
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(cred)
            .map_err(|_| label)?;
        let decoded = String::from_utf8(decoded).map_err(|_| label)?;
        let (user, password) = decoded.split_once(':').ok_or(label)?;
        if user.is_empty() {
            return Err(label);
        }
        if let Some(p) = self.cache.get(user, password) {
            return Ok(p);
        }
        if let Some(h) = &self.htpasswd {
            match h.verify(user, password).await {
                HtpasswdResult::Ok => {
                    return Ok(self
                        .cache
                        .insert(user, password, Vec::new(), AuthMethod::Htpasswd))
                }
                HtpasswdResult::BadPassword => return Err("htpasswd"),
                // Unknown locally: the directory may know the user.
                HtpasswdResult::UnknownUser => {}
            }
        }
        #[cfg(feature = "ldap")]
        if let Some(l) = &self.ldap {
            return match l.authenticate(user, password).await {
                Some(groups) => Ok(self.cache.insert(user, password, groups, AuthMethod::Ldap)),
                None => Err("ldap"),
            };
        }
        Err(label)
    }

    /// Whether `p` may perform `action` on `repo`, without error mapping.
    pub(crate) fn allows(&self, p: &Principal, repo: &str, action: Action) -> bool {
        match p {
            Principal::Token { grants, .. } => bearer::grants_allow(grants, repo, action),
            Principal::User {
                name, ldap_groups, ..
            } => self
                .policy()
                .is_none_or(|pol| pol.grants(Some(name), ldap_groups, repo).contains(action)),
            Principal::Anonymous => self
                .policy()
                .is_some_and(|pol| pol.grants(None, &[], repo).contains(action)),
        }
    }

    /// Authorize `p` for `action` on `repo`, mapping a denial to the
    /// response the principal can act on (`401` + challenge vs `403`).
    #[tracing::instrument(
        name = "authn.authorize",
        skip_all,
        fields(auth.method = p.method_label(), auth.result = tracing::field::Empty)
    )]
    pub(crate) fn authorize(
        &self,
        p: &Principal,
        repo: &str,
        action: Action,
    ) -> Result<(), ApiError> {
        let (result, outcome) = if self.allows(p, repo, action) {
            ("allowed", Ok(()))
        } else {
            match p {
                Principal::Token { .. } => (
                    "unauthenticated",
                    Err(ApiError::Unauthenticated {
                        message: "insufficient scope".into(),
                        challenge: self.challenge(Some((repo, action)), true),
                    }),
                ),
                Principal::User { .. } => (
                    "denied",
                    Err(ApiError::new(ErrorCode::Denied, "access denied")),
                ),
                Principal::Anonymous if self.has_header_mechanism() => (
                    "unauthenticated",
                    Err(ApiError::Unauthenticated {
                        message: "authentication required".into(),
                        challenge: self.challenge(Some((repo, action)), false),
                    }),
                ),
                Principal::Anonymous => (
                    "denied",
                    Err(ApiError::new(
                        ErrorCode::Denied,
                        if self.mtls {
                            "authentication required: present a trusted client certificate"
                        } else {
                            "anonymous access denied by policy"
                        },
                    )),
                ),
            }
        };
        tracing::Span::current().record("auth.result", result);
        if result != "allowed" {
            let subject = p.subject();
            tracing::debug!(subject, repo, ?action, result, "authorization refused");
        }
        roci_telemetry::record_auth_decision(p.method_label(), result);
        outcome
    }

    /// The `401` for an anonymous `GET /v2/` when a header mechanism exists.
    pub(crate) fn base_challenge(&self) -> ApiError {
        roci_telemetry::record_auth_decision("anonymous", "unauthenticated");
        ApiError::Unauthenticated {
            message: "authentication required".into(),
            challenge: self.challenge(None, false),
        }
    }

    /// The `WWW-Authenticate` value: `Bearer` when a token server is
    /// configured (Basic credentials are still accepted), else `Basic`;
    /// `None` when no header mechanism exists to challenge for.
    fn challenge(&self, scope: Option<(&str, Action)>, insufficient: bool) -> Option<HeaderValue> {
        let value = if let Some(b) = &self.bearer {
            let mut s = format!("Bearer realm=\"{}\",service=\"{}\"", b.realm, b.service);
            if let Some((repo, action)) = scope {
                let _ = write!(
                    s,
                    ",scope=\"repository:{repo}:{}\"",
                    challenge_actions(action)
                );
            }
            if insufficient {
                s.push_str(",error=\"insufficient_scope\"");
            }
            s
        } else if self.has_header_mechanism() {
            format!("Basic realm=\"{}\"", self.realm)
        } else {
            return None;
        };
        HeaderValue::from_str(&value).ok()
    }
}

/// Whether `value` is `Basic` over the empty pair `:`.
fn is_empty_basic(value: &HeaderValue) -> bool {
    value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .is_some_and(|(scheme, cred)| {
            scheme.eq_ignore_ascii_case("basic")
                && base64::engine::general_purpose::STANDARD
                    .decode(cred.trim())
                    .is_ok_and(|pair| pair == b":")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_set_algebra() {
        let s = ActionSet::from_actions(&[Action::Pull, Action::Delete]);
        assert!(s.contains(Action::Pull) && s.contains(Action::Delete));
        assert!(!s.contains(Action::Push));
        assert_eq!(s.union(ActionSet::of(Action::Push)), ActionSet::ALL);
        assert_eq!(ActionSet::from_actions(&[]), ActionSet::NONE);
    }

    #[test]
    fn no_auth_config_means_no_engine() {
        assert!(Auth::from_config(&Config::default()).unwrap().is_none());
        let c = Config {
            access_control: Some(AccessControlConfig::default()),
            ..Config::default()
        };
        assert!(Auth::from_config(&c).unwrap().is_some());
    }

    #[cfg(not(feature = "ldap"))]
    #[test]
    fn ldap_without_feature_fails_startup() {
        let mut c = Config::default();
        c.auth.ldap = Some(roci_config::LdapConfig {
            url: "ldaps://d".into(),
            start_tls: false,
            bind_dn: "cn=a".into(),
            bind_password_file: "/nonexistent".into(),
            base_dn: "dc=x".into(),
            user_attribute: "uid".into(),
            user_filter: None,
            group_attribute: None,
            ca_file: None,
            timeout_secs: 5,
        });
        let err = Auth::from_config(&c).err().unwrap().to_string();
        assert!(err.contains("`ldap` feature"), "{err}");
    }
}
