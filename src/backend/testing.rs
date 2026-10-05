//! An in-memory [`HttpTransport`] for tests, so backend tests need no network.
//!
//! It records every request and answers from a caller-supplied handler, which
//! sees the full [`HttpRequest`] (method, URL with query, headers, body) and
//! returns a canned [`HttpResponse`]. That is enough to drive the management
//! client, the retry logic, and the cursor paginator entirely offline — the
//! handler can key off the `starting_after` query to serve page after page.

use std::sync::{Arc, Mutex};

use crate::error::TransportError;
use crate::http::{HttpRequest, HttpResponse, HttpTransport};
use crate::jwks::BoxFuture;

type Handler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

/// A canned, request-recording transport.
#[derive(Clone)]
pub struct FakeTransport {
    handler: Handler,
    recorded: Arc<Mutex<Vec<HttpRequest>>>,
}

impl FakeTransport {
    /// Build with a handler that maps a request to a response.
    pub fn new(handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) -> Self {
        FakeTransport {
            handler: Arc::new(handler),
            recorded: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Always answer with this JSON body and `200 OK` — the simplest fixture.
    pub fn json_ok(body: impl Into<String>) -> Self {
        let body = body.into();
        Self::new(move |_req| HttpResponse {
            status: 200,
            body: body.clone(),
        })
    }

    /// Every request received so far, in order. Lets a test assert the method,
    /// URL, headers (e.g. `idempotency-key`), and body the client produced.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.recorded.lock().unwrap().clone()
    }

    /// How many requests have been received — handy for asserting retries.
    pub fn request_count(&self) -> usize {
        self.recorded.lock().unwrap().len()
    }
}

impl HttpTransport for FakeTransport {
    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        let resp = (self.handler)(&req);
        self.recorded.lock().unwrap().push(req);
        Box::pin(async move { Ok(resp) })
    }
}
