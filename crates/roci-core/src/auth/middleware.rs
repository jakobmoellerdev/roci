//! Request-path auth layers: TLS early-data refusal and authentication.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{Auth, ClientCertIdentity, Principal};
use crate::error::ApiError;

/// Refuse state-changing requests a TLS-terminating proxy forwarded from
/// 0-RTT early data (`Early-Data: 1`, RFC 8470 §5.1): early data is
/// replayable, so only safe methods may proceed. roci itself never accepts
/// early data (`max_early_data_size = 0`).
pub(crate) async fn early_data_middleware(req: Request, next: Next) -> Response {
    let replayable = req.headers().get("early-data").is_some_and(|v| v == "1");
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if replayable && !safe {
        return ApiError::TooEarly.into_response();
    }
    next.run(req).await
}

/// Resolve the request's [`Principal`] and attach it for `dispatch` to
/// authorize. Invalid credentials fail here; `GET /v2/` is answered with a
/// challenge for anonymous callers when a header mechanism is configured
/// (the dist-spec auth-discovery handshake).
pub(crate) async fn authn_middleware(
    State(auth): State<Arc<Auth>>,
    mut req: Request,
    next: Next,
) -> Response {
    let principal = match auth
        .authenticate(req.headers(), req.extensions().get::<ClientCertIdentity>())
        .await
    {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if req.uri().path() == "/v2/"
        && matches!(principal, Principal::Anonymous)
        && auth.has_header_mechanism()
    {
        return auth.base_challenge().into_response();
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}
