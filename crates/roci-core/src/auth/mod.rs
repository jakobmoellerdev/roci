//! Authentication and authorization (SECURITY.md §AuthN/AuthZ).
//! Resolves each request to a [`Principal`] before any storage call.
//! Credentials/tokens/`Authorization` values are never logged.

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

fn challenge_actions(action: Action) -> &'static str {
    match action {
        Action::Pull => "pull",
        Action::Push => "pull,push",
        Action::Delete => "delete",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMethod {
    Htpasswd,
    #[cfg(feature = "ldap")]
    Ldap,
    Mtls,
}

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
            Principal::User { method, .. } => match method {
                AuthMethod::Htpasswd => "htpasswd",
                #[cfg(feature = "ldap")]
                AuthMethod::Ldap => "ldap",
                AuthMethod::Mtls => "mtls",
            },
            Principal::Token { .. } => "bearer",
        }
    }

    pub(crate) fn subject(&self) -> Option<&str> {
        match self {
            Principal::Anonymous => None,
            Principal::User { name, .. } => Some(name),
            Principal::Token { subject, .. } => subject.as_deref(),
        }
    }
}

pub(crate) fn principal_of(ext: &axum::http::Extensions) -> &Principal {
    ext.get::<Principal>().unwrap_or(&ANONYMOUS)
}

#[derive(Debug, Clone)]
pub struct ClientCertIdentity(pub Arc<str>);

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
    /// Build the auth engine; `None` = fully open.
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

    /// Replace the access-control policy (live reload).
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

    /// Whether an `Authorization`-header mechanism is configured.
    pub(crate) fn has_header_mechanism(&self) -> bool {
        self.htpasswd.is_some() || self.ldap_configured() || self.bearer.is_some()
    }

    /// Resolve the principal from Authorization header, mTLS cert, or Anonymous.
    /// Empty Basic `user:` = anonymous (containers/image client convention).
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

    /// Authenticate an `Authorization` value.
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

    /// Authorize `p`; denial → 401+challenge or 403.
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

    /// `WWW-Authenticate` value: `Bearer` or `Basic`; `None` if no mechanism.
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
mod tests;
