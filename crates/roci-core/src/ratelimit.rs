//! Token-bucket rate limiter driven by `config.http.rate_limit`.
//!
//! Two layers:
//!
//! 1. **Global per-method** (`per_method` / `default`). Each HTTP method gets
//!    its own bucket or falls back to `default`. When neither is configured the
//!    method is unlimited. At most 7 fixed buckets exist (one per HTTP method in
//!    the OCI spec surface), so memory is bounded. Runs **before** authn to
//!    protect the server unconditionally.
//!
//! 2. **Per-client** (`per_client`). Keyed by the authenticated principal
//!    identity (htpasswd/LDAP username, bearer `sub`, mTLS cert identity) when
//!    authenticated, else the TCP peer IP (socket address, **not**
//!    `X-Forwarded-For`; behind a proxy, anonymous clients collapse onto the
//!    proxy IP). Keys are stored in a distinct enum so a username can never
//!    collide with an IP. The bucket map is capped at `max_clients` with LRU
//!    eviction; an evicted client restarts with a full bucket. Runs **after**
//!    authn so the principal is available.
//!
//! Exhausted buckets respond with `429 TOOMANYREQUESTS` (dist-spec error body)
//! plus a `Retry-After` header (seconds, ceiling). The existing
//! `registry.request.errors{error_code}` telemetry covers 429s; no per-client
//! labels are added (bounded cardinality).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use axum::extract::Request;
use axum::http::{header, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use lru::LruCache;
use roci_config::{Bucket, PerClientConfig, RateLimitConfig};

use crate::auth::principal_of;
use crate::error::{ApiError, ErrorCode};

// ---------------------------------------------------------------------------
// Token bucket (shared by both layers)
// ---------------------------------------------------------------------------

/// A single token bucket protected by a mutex.
///
/// Fields: `tokens` (f64 for sub-second precision), `last` (last refill
/// instant), `rate` (tokens/sec), `burst` (max tokens).
struct TokenBucket {
    tokens: f64,
    last: tokio::time::Instant,
    rate: f64,
    burst: f64,
}

impl TokenBucket {
    fn new(bucket: &Bucket) -> Self {
        Self {
            tokens: f64::from(bucket.burst),
            last: tokio::time::Instant::now(),
            rate: f64::from(bucket.rate),
            burst: f64::from(bucket.burst),
        }
    }

    fn from_per_client(cfg: &PerClientConfig) -> Self {
        Self {
            tokens: f64::from(cfg.burst),
            last: tokio::time::Instant::now(),
            rate: f64::from(cfg.rate),
            burst: f64::from(cfg.burst),
        }
    }

    /// Try to consume one token. Returns `Ok(())` if allowed, or
    /// `Err(retry_after_secs)` with the ceiling seconds until a token is
    /// available.
    fn try_acquire(&mut self) -> Result<(), u64> {
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + self.rate * elapsed).min(self.burst);
        self.last = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // How long until we have 1 token?
            let deficit = 1.0 - self.tokens;
            let wait = deficit / self.rate;
            Err(wait.ceil() as u64)
        }
    }
}

// ---------------------------------------------------------------------------
// Layer 1: global per-method rate limiter
// ---------------------------------------------------------------------------

/// Pre-built rate limiter: holds one `Mutex<TokenBucket>` per configured
/// method, plus an optional default bucket for unconfigured methods.
pub(crate) struct RateLimiter {
    per_method: HashMap<Method, Mutex<TokenBucket>>,
    default: Option<Mutex<TokenBucket>>,
}

impl RateLimiter {
    /// Build from config. Returns `None` when rate limiting is disabled (the
    /// layer is not installed at all → zero overhead).
    pub(crate) fn from_config(cfg: &RateLimitConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let mut per_method = HashMap::new();
        for (name, bucket) in &cfg.per_method {
            if let Ok(m) = Method::from_bytes(name.as_bytes()) {
                per_method.insert(m, Mutex::new(TokenBucket::new(bucket)));
            }
        }
        let default = cfg
            .default
            .as_ref()
            .map(|b| Mutex::new(TokenBucket::new(b)));
        Some(Self {
            per_method,
            default,
        })
    }

    /// Try to acquire a token for the given method.
    fn check(&self, method: &Method) -> Result<(), u64> {
        if let Some(bucket) = self.per_method.get(method) {
            return bucket
                .lock()
                .expect("rate-limit bucket poisoned")
                .try_acquire();
        }
        if let Some(bucket) = &self.default {
            return bucket
                .lock()
                .expect("rate-limit bucket poisoned")
                .try_acquire();
        }
        // No bucket configured for this method and no default → unlimited.
        Ok(())
    }
}

/// Axum middleware that enforces global rate limits.
pub(crate) async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<std::sync::Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    match limiter.check(req.method()) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => too_many_requests(retry_after),
    }
}

// ---------------------------------------------------------------------------
// Layer 2: per-client rate limiter
// ---------------------------------------------------------------------------

/// The TCP peer address of the accepted connection, inserted into request
/// extensions by the connection layer (`roci-cli`). Used as the anonymous
/// client key when no authenticated principal is available.
#[derive(Debug, Clone)]
pub struct PeerAddr(pub IpAddr);

/// The key identifying a single client for per-client rate limiting.
/// The enum ensures an authenticated username can never collide with a peer IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ClientKey {
    /// An authenticated principal (htpasswd/LDAP username, bearer `sub`, mTLS
    /// cert identity).
    Principal(String),
    /// The TCP peer IP for anonymous/unauthenticated clients.
    Ip(IpAddr),
}

/// Per-client rate limiter: an LRU map of `ClientKey → TokenBucket` capped at
/// `max_clients`. Thread-safe via a single `Mutex` (contention is bounded:
/// one lock/unlock per request, sub-microsecond critical section).
pub(crate) struct PerClientLimiter {
    map: Mutex<LruCache<ClientKey, TokenBucket>>,
    cfg: PerClientConfig,
}

impl PerClientLimiter {
    /// Build from config. Returns `None` when `per_client` is absent.
    pub(crate) fn from_config(cfg: &RateLimitConfig) -> Option<Self> {
        let pc = cfg.per_client.as_ref()?;
        let cap = std::num::NonZeroUsize::new(pc.max_clients as usize)
            .expect("validated: max_clients > 0");
        Some(Self {
            map: Mutex::new(LruCache::new(cap)),
            cfg: *pc,
        })
    }

    /// Try to acquire a per-client token for `key`. A new or evicted client
    /// starts with a full bucket.
    fn check(&self, key: ClientKey) -> Result<(), u64> {
        let mut map = self.map.lock().expect("per-client rate-limit map poisoned");
        let bucket = map.get_or_insert_mut(key, || TokenBucket::from_per_client(&self.cfg));
        bucket.try_acquire()
    }
}

/// Axum middleware that enforces per-client rate limits. Runs **after** authn
/// so the authenticated principal (if any) is available in extensions.
pub(crate) async fn per_client_rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<std::sync::Arc<PerClientLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let key = client_key_from(&req);
    match limiter.check(key) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => too_many_requests(retry_after),
    }
}

/// Derive the `ClientKey` from request extensions: authenticated principal
/// identity if present, else the TCP peer IP.
fn client_key_from(req: &Request) -> ClientKey {
    let principal = principal_of(req.extensions());
    if let Some(subject) = principal.subject() {
        return ClientKey::Principal(subject.to_owned());
    }
    // Anonymous: use peer IP.
    if let Some(peer) = req.extensions().get::<PeerAddr>() {
        return ClientKey::Ip(peer.0);
    }
    // Fallback when no peer addr is available (e.g. tests): use unspecified.
    ClientKey::Ip(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

// ---------------------------------------------------------------------------
// Shared 429 response builder
// ---------------------------------------------------------------------------

fn too_many_requests(retry_after: u64) -> Response {
    let err = ApiError::new(ErrorCode::TooManyRequests, "rate limit exceeded");
    let mut resp = err.into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, retry_after.into());
    resp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use roci_config::Bucket;

    #[test]
    fn token_bucket_allows_burst_then_denies() {
        let b = Bucket { rate: 1, burst: 2 };
        let mut tb = TokenBucket::new(&b);
        assert!(tb.try_acquire().is_ok());
        assert!(tb.try_acquire().is_ok());
        assert!(tb.try_acquire().is_err());
    }

    #[test]
    fn global_limiter_per_method_and_default() {
        let cfg = RateLimitConfig {
            enabled: true,
            default: Some(Bucket {
                rate: 100,
                burst: 1,
            }),
            per_method: [("GET".into(), Bucket { rate: 1, burst: 2 })]
                .into_iter()
                .collect(),
            per_client: None,
        };
        let rl = RateLimiter::from_config(&cfg).unwrap();
        // GET uses its own bucket (burst 2).
        assert!(rl.check(&Method::GET).is_ok());
        assert!(rl.check(&Method::GET).is_ok());
        assert!(rl.check(&Method::GET).is_err());
        // PUT falls back to default (burst 1).
        assert!(rl.check(&Method::PUT).is_ok());
        assert!(rl.check(&Method::PUT).is_err());
    }

    #[test]
    fn global_limiter_disabled_returns_none() {
        let cfg = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(RateLimiter::from_config(&cfg).is_none());
    }

    #[test]
    fn per_client_limiter_absent_returns_none() {
        let cfg = RateLimitConfig::default();
        assert!(PerClientLimiter::from_config(&cfg).is_none());
    }

    #[test]
    fn per_client_distinct_clients_independent() {
        let cfg = RateLimitConfig {
            enabled: true,
            per_client: Some(PerClientConfig {
                rate: 1,
                burst: 1,
                max_clients: 100,
            }),
            ..Default::default()
        };
        let limiter = PerClientLimiter::from_config(&cfg).unwrap();
        let alice = ClientKey::Principal("alice".into());
        let bob = ClientKey::Principal("bob".into());
        // Alice exhausts her bucket.
        assert!(limiter.check(alice.clone()).is_ok());
        assert!(limiter.check(alice).is_err());
        // Bob still has his own full bucket.
        assert!(limiter.check(bob).is_ok());
    }

    #[test]
    fn per_client_ip_vs_principal_no_collision() {
        let cfg = RateLimitConfig {
            enabled: true,
            per_client: Some(PerClientConfig {
                rate: 1,
                burst: 1,
                max_clients: 100,
            }),
            ..Default::default()
        };
        let limiter = PerClientLimiter::from_config(&cfg).unwrap();
        // "127.0.0.1" as a principal name and 127.0.0.1 as an IP are distinct.
        let principal = ClientKey::Principal("127.0.0.1".into());
        let ip = ClientKey::Ip("127.0.0.1".parse().unwrap());
        assert!(limiter.check(principal.clone()).is_ok());
        assert!(limiter.check(principal).is_err());
        // The IP key still has its own bucket.
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn per_client_lru_eviction_bounds_map_and_resets_bucket() {
        let cfg = RateLimitConfig {
            enabled: true,
            per_client: Some(PerClientConfig {
                rate: 1,
                burst: 1,
                max_clients: 2,
            }),
            ..Default::default()
        };
        let limiter = PerClientLimiter::from_config(&cfg).unwrap();
        let a = ClientKey::Principal("a".into());
        let b = ClientKey::Principal("b".into());
        let c = ClientKey::Principal("c".into());
        // Exhaust a and b.
        assert!(limiter.check(a.clone()).is_ok());
        assert!(limiter.check(a.clone()).is_err());
        assert!(limiter.check(b.clone()).is_ok());
        assert!(limiter.check(b).is_err());
        // Insert c → evicts a (LRU).
        assert!(limiter.check(c).is_ok());
        // a was evicted: it gets a fresh bucket.
        assert!(limiter.check(a).is_ok());
        // Map size is bounded at 2.
        let map = limiter.map.lock().unwrap();
        assert!(map.len() <= 2);
    }

    #[test]
    fn client_key_from_uses_principal_over_ip() {
        use crate::auth::Principal;
        use std::sync::Arc;

        let mut req = Request::builder()
            .uri("/v2/")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(PeerAddr("10.0.0.1".parse().unwrap()));
        req.extensions_mut().insert(Principal::User {
            name: Arc::from("alice"),
            ldap_groups: Arc::from([]),
            method: crate::auth::AuthMethod::Htpasswd,
        });
        match client_key_from(&req) {
            ClientKey::Principal(name) => assert_eq!(name, "alice"),
            _ => panic!("expected Principal key"),
        }
    }

    #[test]
    fn client_key_from_falls_back_to_ip() {
        let mut req = Request::builder()
            .uri("/v2/")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(PeerAddr("192.168.1.1".parse().unwrap()));
        // No principal inserted → Anonymous.
        match client_key_from(&req) {
            ClientKey::Ip(ip) => assert_eq!(ip, "192.168.1.1".parse::<IpAddr>().unwrap()),
            _ => panic!("expected Ip key"),
        }
    }

    #[test]
    fn client_key_from_bearer_subject() {
        use crate::auth::Principal;
        use std::sync::Arc;

        let mut req = Request::builder()
            .uri("/v2/")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(PeerAddr("10.0.0.2".parse().unwrap()));
        req.extensions_mut().insert(Principal::Token {
            subject: Some(Arc::from("bot")),
            grants: Arc::from([]),
        });
        match client_key_from(&req) {
            ClientKey::Principal(name) => assert_eq!(name, "bot"),
            _ => panic!("expected Principal key for bearer sub"),
        }
    }

    #[test]
    fn client_key_from_bearer_no_subject_uses_ip() {
        use crate::auth::Principal;
        use std::sync::Arc;

        let mut req = Request::builder()
            .uri("/v2/")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(PeerAddr("10.0.0.3".parse().unwrap()));
        req.extensions_mut().insert(Principal::Token {
            subject: None,
            grants: Arc::from([]),
        });
        match client_key_from(&req) {
            ClientKey::Ip(ip) => assert_eq!(ip, "10.0.0.3".parse::<IpAddr>().unwrap()),
            _ => panic!("expected Ip key for bearer without sub"),
        }
    }
}
