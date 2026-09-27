//! `Connection: close` on HTTP/1 responses sent before the body was read.
//! Without it, a client pooling the connection writes into a closed socket.

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

/// Mark HTTP/1 `Connection: close` when the body was left unread.
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
