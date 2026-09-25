//! `Connection: close` on HTTP/1 responses sent before the request body was
//! read to its end (authentication rejections, limit and validation errors).
//!
//! hyper cannot keep such a connection alive — the unread body bytes are still
//! in flight — so it closes the socket after the response, but without saying
//! so. A client that pools the connection once it has read the response (Go's
//! `net/http`, e.g. the OCI conformance suite retrying a `401` upload with
//! credentials) then writes its next request into the closed socket and fails
//! with `EOF`; behind NAT or a proxy (a Kubernetes Service) that race is lost
//! routinely. Announcing the close makes the client open a fresh connection.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Request;
use axum::http::{header, HeaderValue, Version};
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Frame, SizeHint};

/// Request body that records whether it was read to its end.
struct TrackedBody {
    inner: Body,
    done: Arc<AtomicBool>,
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(poll, Poll::Ready(None)) {
            self.done.store(true, Ordering::Relaxed);
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        let end = self.inner.is_end_stream();
        if end {
            self.done.store(true, Ordering::Relaxed);
        }
        end
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Mark HTTP/1 responses `Connection: close` when the handler (or an earlier
/// layer) left the request body unread. HTTP/2 multiplexes streams and forbids
/// the header, so it is left alone, as are requests without a body.
pub(crate) async fn close_on_unread_body(req: Request, next: Next) -> Response {
    let http1 = matches!(
        req.version(),
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    );
    if !http1 || req.body().is_end_stream() {
        return next.run(req).await;
    }
    let done = Arc::new(AtomicBool::new(false));
    let tracked = Arc::clone(&done);
    let req = req.map(|inner| {
        Body::new(TrackedBody {
            inner,
            done: tracked,
        })
    });
    let mut resp = next.run(req).await;
    if !done.load(Ordering::Relaxed) {
        resp.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    resp
}
