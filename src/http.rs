//! The richer HTTP transport the `backend` and `client` features build on.
//!
//! The verification core only ever needs two verbs — a JWKS `GET` and the
//! API-key `POST` — so it ships the narrow [`crate::JwksSource`] / [`crate::HttpPost`]
//! traits. The management client and the native-client flows need the full set
//! of REST verbs, arbitrary headers (an idempotency key, a publishable key, a
//! form `content-type`), and a raw request/response pair. Rather than widen the
//! existing traits — and force every verification-only consumer to care — this
//! adds ONE object-safe transport trait, [`HttpTransport`], used only behind
//! those two features. The built-in [`crate::ReqwestTransport`] implements it
//! too, so a single client still backs the whole crate.
//!
//! The trait stays object-safe (a boxed future, no `async-trait`) so a caller
//! can inject a mock — the in-memory [`crate::backend::FakeTransport`] in tests
//! — exactly as they can for the verification traits.

use crate::error::TransportError;
use crate::jwks::BoxFuture;

// The raw response shape is shared with the API-key verifier, so there is one
// `(status, body)` pair across the crate rather than two that drift.
pub use crate::apikey::HttpResponse;

/// An HTTP method. A closed set — the BAPI and FAPI use only these five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Patch,
    Put,
    Delete,
}

impl HttpMethod {
    /// The uppercase method token, for logging and for a transport that takes a
    /// string.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// A fully-resolved HTTP request: the URL already carries its query string, and
/// every header (authorization, content-type, idempotency-key, publishable key)
/// is explicit, so a transport is a dumb pipe with no policy of its own. That is
/// the point — all of the "how is a BAPI call authenticated and serialized"
/// decisions live in one place (the client), and the transport, real or mock,
/// only moves bytes.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// A serialized body (JSON or form-urlencoded). `None` sends no body.
    pub body: Option<String>,
}

impl HttpRequest {
    /// Start a request with no headers and no body.
    pub fn new(method: HttpMethod, url: impl Into<String>) -> Self {
        HttpRequest {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Append a header. Chainable.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body. Chainable.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// Something that can perform an arbitrary [`HttpRequest`]. Implemented by the
/// built-in reqwest transport (behind `reqwest-transport`) and by any mock a
/// caller supplies (the tests' in-memory `FakeTransport`).
///
/// A transport NEVER decides success from the status code — it returns whatever
/// the server said, status and body, and lets the client map a non-2xx to a
/// typed error. A transport error is reserved for "the request did not complete"
/// (DNS, TLS, connection reset).
pub trait HttpTransport: Send + Sync {
    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, TransportError>>;
}

/// Percent-encode one URL path/query component (an id, slug, or provider name)
/// per RFC 3986 unreserved set. A tiny shared encoder so neither the backend nor
/// the client feature has to pull a URL crate just to escape a `sess_…` id.
#[allow(dead_code)]
pub(crate) fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
