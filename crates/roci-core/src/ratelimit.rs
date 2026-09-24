//! Global token-bucket rate limiter driven by `config.http.rate_limit`.
//!
//! Each HTTP method gets its own bucket (from `per_method`) or falls back to
//! `default`. When neither is configured, the method is unlimited. Exhausted
//! buckets respond with `429 TOOMANYREQUESTS` (dist-spec error body) plus a
//! `Retry-After` header (seconds, ceiling).
//!
//! Buckets are global (per method, not per client). At most 7 fixed buckets
//! exist (one per HTTP method in the OCI spec surface), so memory is bounded.
//! Per-client limiting is future work.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::extract::Request;
use axum::http::{header, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use roci_config::{Bucket, RateLimitConfig};

use crate::error::{ApiError, ErrorCode};

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
        Err(retry_after) => {
            let err = ApiError::new(ErrorCode::TooManyRequests, "rate limit exceeded");
            let mut resp = err.into_response();
            resp.headers_mut()
                .insert(header::RETRY_AFTER, retry_after.into());
            resp
        }
    }
}
