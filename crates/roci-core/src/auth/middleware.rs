//! Request-path auth layers: TLS early-data refusal and authentication.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{Auth, ClientCertIdentity, Principal};
use crate::error::ApiError;

/// Refuse state-changing requests from TLS 0-RTT early data (RFC 8470).
pub(crate) async fn early_data_middleware(req: Request, next: Next) -> Response {
    let replayable = req.headers().get("early-data").is_some_and(|v| v == "1");
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if replayable && !safe {
        return ApiError::TooEarly.into_response();
    }
    next.run(req).await
}

/// Resolve the principal and attach it for authorization in `dispatch`.
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
