//! An in-memory [`HttpTransport`] for tests, so backend tests need no network.
//!
//! It records every request and answers from a caller-supplied handler, which
//! sees the full [`HttpRequest`] (method, URL with query, headers, body) and
//! returns a canned [`HttpResponse`]. That is enough to drive the management
//! client, the retry logic, and the cursor paginator entirely offline — the
//! handler can key off the `starting_after` query to serve page after page.
//!
//! It can also play the JWKS endpoint: [`FakeTransport::with_jwks`] serves a
//! fixed key set, and [`FakeTransport::with_signing_key`] additionally lets the
//! fake mint tokens ([`FakeTransport::sign_token`]) that its own JWKS verifies,
//! so token-verification code can be tested end to end with no network.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::error::TransportError;
use crate::http::{HttpMethod, HttpRequest, HttpResponse, HttpTransport};
use crate::jwks::{BoxFuture, Jwks, JwksSource};

type Handler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync>;

/// An RSA signing key (PEM) plus its public JWK components.
struct SigningMaterial {
    kid: String,
    private_pem: Vec<u8>,
    n: String,
    e: String,
}

impl SigningMaterial {
    fn jwks_json(&self) -> Value {
        json!({ "keys": [{
            "kty": "RSA", "kid": self.kid, "alg": "RS256", "use": "sig",
            "n": self.n, "e": self.e,
        }]})
    }
}

/// A canned, request-recording transport.
#[derive(Clone)]
pub struct FakeTransport {
    handler: Handler,
    recorded: Arc<Mutex<Vec<HttpRequest>>>,
    signing: Option<Arc<SigningMaterial>>,
}

impl FakeTransport {
    /// Build with a handler that maps a request to a response.
    pub fn new(handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) -> Self {
        FakeTransport {
            handler: Arc::new(handler),
            recorded: Arc::new(Mutex::new(Vec::new())),
            signing: None,
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

    /// Serve this JWKS document (`{"keys":[...]}`) at any GET URL containing
    /// `jwks` (e.g. `/.well-known/jwks.json`); every other path is a 404. Use it
    /// as the [`JwksSource`] of an `AtlasBackend`, or feed it to a code path that
    /// does its own `GET`.
    pub fn with_jwks(jwks: Value) -> Self {
        let body = jwks.to_string();
        Self::new(move |req| {
            if req.method == HttpMethod::Get && req.url.contains("jwks") {
                HttpResponse { status: 200, body: body.clone() }
            } else {
                HttpResponse {
                    status: 404,
                    body: r#"{"errors":[{"code":"NOT_FOUND","message":"not found"}]}"#.to_string(),
                }
            }
        })
    }

    /// Install an RS256 signing key so tests can mint tokens the fake's own JWKS
    /// verifies. `private_pem` is the RSA private key in PEM; `n`/`e` are the
    /// matching base64url public modulus/exponent (what a JWK carries). The
    /// transport then serves that key as a JWKS (see [`Self::with_jwks`]) and
    /// [`Self::sign_token`] signs claims with it under `kid`.
    pub fn with_signing_key(
        kid: impl Into<String>,
        private_pem: impl Into<Vec<u8>>,
        n: impl Into<String>,
        e: impl Into<String>,
    ) -> Self {
        let signing = Arc::new(SigningMaterial {
            kid: kid.into(),
            private_pem: private_pem.into(),
            n: n.into(),
            e: e.into(),
        });
        let mut t = Self::with_jwks(signing.jwks_json());
        t.signing = Some(signing);
        t
    }

    /// The JWKS document this transport serves for its signing key (`None` when
    /// built without one).
    pub fn jwks_json(&self) -> Option<Value> {
        self.signing.as_ref().map(|s| s.jwks_json())
    }

    /// [`Self::jwks_json`] parsed into the crate's [`Jwks`] type, e.g. for
    /// `AtlasBackend::builder(..).static_jwks(..)`.
    pub fn jwks(&self) -> Option<Jwks> {
        self.jwks_json().and_then(|v| serde_json::from_value(v).ok())
    }

    /// Sign `claims` as an RS256 JWT carrying the installed key's `kid`. Returns
    /// `None` when no signing key was installed.
    pub fn sign_token(&self, claims: &Value) -> Option<String> {
        let s = self.signing.as_ref()?;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(s.kid.clone());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(&s.private_pem).ok()?;
        jsonwebtoken::encode(&header, claims, &key).ok()
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

impl JwksSource for FakeTransport {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
        let req = HttpRequest::new(HttpMethod::Get, url);
        let resp = (self.handler)(&req);
        self.recorded.lock().unwrap().push(req);
        Box::pin(async move {
            if !(200..300).contains(&resp.status) {
                return Err(TransportError::new(format!("JWKS fetch failed ({})", resp.status)));
            }
            serde_json::from_str::<Jwks>(&resp.body)
                .map_err(|e| TransportError::new(format!("JWKS is malformed: {e}")))
        })
    }
}

impl HttpTransport for FakeTransport {
    fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        let resp = (self.handler)(&req);
        self.recorded.lock().unwrap().push(req);
        Box::pin(async move { Ok(resp) })
    }
}
