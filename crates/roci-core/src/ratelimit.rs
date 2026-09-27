//! Token-bucket rate limiter: global per-method and per-client layers.
//! Exhausted buckets respond `429` with `Retry-After`.

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

/// A single token bucket.
struct TokenBucket {
    tokens: f64,
    last: tokio::time::Instant,
    rate: f64,
    burst: f64,
}

impl TokenBucket {
    fn with(rate: u32, burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            last: tokio::time::Instant::now(),
            rate: f64::from(rate),
            burst: f64::from(burst),
        }
    }

    fn new(bucket: &Bucket) -> Self {
        Self::with(bucket.rate, bucket.burst)
    }

    fn from_per_client(cfg: &PerClientConfig) -> Self {
        Self::with(cfg.rate, cfg.burst)
    }

    /// Try to consume one token; `Err(retry_after_secs)` on exhaustion.
    fn try_acquire(&mut self) -> Result<(), u64> {
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + self.rate * elapsed).min(self.burst);
        self.last = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            let wait = deficit / self.rate;
            Err(wait.ceil() as u64)
        }
    }
}

/// Global per-method rate limiter.
pub(crate) struct RateLimiter {
    per_method: HashMap<Method, Mutex<TokenBucket>>,
    default: Option<Mutex<TokenBucket>>,
}

impl RateLimiter {
    /// Build from config; `None` when disabled.
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
        Ok(())
    }
}

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

/// TCP peer address for anonymous client identification.
#[derive(Debug, Clone)]
pub struct PeerAddr(pub IpAddr);

/// Rate-limit client key (principal name or peer IP).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ClientKey {
    Principal(String),
    Ip(IpAddr),
}

/// Per-client LRU rate limiter.
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

    /// Try to acquire a per-client token.
    fn check(&self, key: ClientKey) -> Result<(), u64> {
        let mut map = self.map.lock().expect("per-client rate-limit map poisoned");
        let bucket = map.get_or_insert_mut(key, || TokenBucket::from_per_client(&self.cfg));
        bucket.try_acquire()
    }
}

/// Per-client rate-limit middleware (runs after authn).
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

fn client_key_from(req: &Request) -> ClientKey {
    let principal = principal_of(req.extensions());
    if let Some(subject) = principal.subject() {
        return ClientKey::Principal(subject.to_owned());
    }
    if let Some(peer) = req.extensions().get::<PeerAddr>() {
        return ClientKey::Ip(peer.0);
    }
    ClientKey::Ip(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

fn too_many_requests(retry_after: u64) -> Response {
    let err = ApiError::new(ErrorCode::TooManyRequests, "rate limit exceeded");
    let mut resp = err.into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, retry_after.into());
    resp
}

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
        assert!(rl.check(&Method::GET).is_ok());
        assert!(rl.check(&Method::GET).is_ok());
        assert!(rl.check(&Method::GET).is_err());
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
        assert!(limiter.check(alice.clone()).is_ok());
        assert!(limiter.check(alice).is_err());
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
        let principal = ClientKey::Principal("127.0.0.1".into());
        let ip = ClientKey::Ip("127.0.0.1".parse().unwrap());
        assert!(limiter.check(principal.clone()).is_ok());
        assert!(limiter.check(principal).is_err());
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
        assert!(limiter.check(a.clone()).is_ok());
        assert!(limiter.check(a.clone()).is_err());
        assert!(limiter.check(b.clone()).is_ok());
        assert!(limiter.check(b).is_err());
        assert!(limiter.check(c).is_ok());
        assert!(limiter.check(a).is_ok());
        let map = limiter.map.lock().unwrap();
        assert!(map.len() <= 2);
    }

    #[test]
    fn client_key_from_dispatch() {
        use crate::auth::{AuthMethod, Principal};
        use std::sync::Arc;

        let cases: &[(&str, Option<Principal>, &str, ClientKey)] = &[
            (
                "principal over ip",
                Some(Principal::User {
                    name: Arc::from("alice"),
                    ldap_groups: Arc::from([]),
                    method: AuthMethod::Htpasswd,
                }),
                "10.0.0.1",
                ClientKey::Principal("alice".into()),
            ),
            (
                "no principal falls back to ip",
                None,
                "192.168.1.1",
                ClientKey::Ip("192.168.1.1".parse().unwrap()),
            ),
            (
                "bearer subject",
                Some(Principal::Token {
                    subject: Some(Arc::from("bot")),
                    grants: Arc::from([]),
                }),
                "10.0.0.2",
                ClientKey::Principal("bot".into()),
            ),
            (
                "bearer no subject uses ip",
                Some(Principal::Token {
                    subject: None,
                    grants: Arc::from([]),
                }),
                "10.0.0.3",
                ClientKey::Ip("10.0.0.3".parse().unwrap()),
            ),
        ];
        for (label, principal, ip, expected) in cases {
            let mut req = Request::builder()
                .uri("/v2/")
                .body(axum::body::Body::empty())
                .unwrap();
            req.extensions_mut().insert(PeerAddr(ip.parse().unwrap()));
            if let Some(p) = principal.clone() {
                req.extensions_mut().insert(p);
            }
            assert_eq!(&client_key_from(&req), expected, "{label}");
        }
    }
}
