//! Resource-server protection: a [`tower::Layer`] that requires an Atlas-issued
//! OAuth access token (Bearer, or DPoP with its proof) on every route beneath it.
//!
//! On success the [`AccessTokenResult`] is inserted into the request extensions
//! (read it back with `Extension<AccessTokenResult>`); on refusal the request is
//! answered with the verifier's status, the RFC 6750 / RFC 9449 / RFC 9728
//! `WWW-Authenticate` challenge and a JSON `{"error": …}` body, and the inner
//! service is never called. When the options carry a nonce source, every
//! response gets the `DPoP-Nonce` header.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::axum::extract::Request;
use ::axum::http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, HOST, WWW_AUTHENTICATE};
use ::axum::http::StatusCode;
use ::axum::response::{IntoResponse, Response};
use ::tower::{Layer, Service};

use crate::access_token::{AccessTokenOptions, AccessTokenResult, ResourceRequest};
use crate::verify::AtlasBackend;

/// A [`tower::Layer`] verifying an access token for your API on every request.
///
/// ```no_run
/// # #[cfg(feature = "reqwest-transport")]
/// # fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use axum::{routing::get, Extension, Router};
/// use atlasauth::{AccessTokenOptions, AccessTokenResult, AtlasBackend, axum::AtlasAccessTokenLayer};
///
/// let backend = Arc::new(AtlasBackend::new(
///     "https://your-instance-fapi.atlasauth.net",
///     "https://your-instance-fapi.atlasauth.net/.well-known/jwks.json",
/// )?);
/// let options = AccessTokenOptions {
///     audiences: vec!["https://api.example.com".into()],
///     required_scopes: vec!["docs:read".into()],
///     // The URL clients sign their DPoP proofs for (scheme + host), since a
///     // server only sees the path.
///     public_origin: Some("https://api.example.com".into()),
///     ..Default::default()
/// };
/// async fn docs(Extension(token): Extension<AccessTokenResult>) -> &'static str {
///     if token.is_ok() { "ok" } else { unreachable!() }
/// }
/// let api: Router = Router::new().route("/docs", get(docs)).layer(AtlasAccessTokenLayer::new(backend, options));
/// # let _ = api; Ok(()) }
/// ```
#[derive(Clone)]
pub struct AtlasAccessTokenLayer {
    backend: Arc<AtlasBackend>,
    options: Arc<AccessTokenOptions>,
}

impl AtlasAccessTokenLayer {
    /// Guard routes with `options`, verifying through the shared `backend`.
    /// Set `options.public_origin` so the DPoP `htu` check knows the public
    /// scheme and host (without it the `Host` header and `http` are used).
    pub fn new(backend: Arc<AtlasBackend>, options: AccessTokenOptions) -> Self {
        AtlasAccessTokenLayer { backend, options: Arc::new(options) }
    }
}

impl<S> Layer<S> for AtlasAccessTokenLayer {
    type Service = AtlasAccessToken<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AtlasAccessToken { inner, backend: self.backend.clone(), options: self.options.clone() }
    }
}

/// The [`Service`] produced by [`AtlasAccessTokenLayer`].
#[derive(Clone)]
pub struct AtlasAccessToken<S> {
    inner: S,
    backend: Arc<AtlasBackend>,
    options: Arc<AccessTokenOptions>,
}

impl<S> Service<Request> for AtlasAccessToken<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let backend = self.backend.clone();
        let options = self.options.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let result = {
                let headers = req.headers();
                let text = |v: &HeaderValue| v.to_str().ok().map(str::to_owned);
                let authorization = headers.get(AUTHORIZATION).and_then(text);
                let proofs: Vec<&HeaderValue> = headers.get_all("dpop").iter().collect();
                let dpop = if proofs.len() == 1 { text(proofs[0]) } else { None };
                let uri = req.uri();
                let path = uri.path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_else(|| "/".into());
                let url = if uri.scheme().is_some() && uri.authority().is_some() && options.public_origin.is_none() {
                    uri.to_string()
                } else if options.public_origin.is_some() {
                    path
                } else {
                    let host = headers.get(HOST).and_then(text).unwrap_or_default();
                    format!("http://{host}{path}")
                };
                let method = req.method().as_str().to_owned();
                backend
                    .verify_access_token_request(
                        &ResourceRequest {
                            method: &method,
                            url: &url,
                            authorization: authorization.as_deref(),
                            dpop: dpop.as_deref(),
                        },
                        &options,
                    )
                    .await
            };
            let nonce = result.dpop_nonce().and_then(|n| HeaderValue::from_str(n).ok());
            match result {
                AccessTokenResult::Refused { status, error, ref www_authenticate, .. } => {
                    let body = serde_json::json!({ "error": error.unwrap_or("unauthorized") }).to_string();
                    let mut res = (StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED), body).into_response();
                    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    if let Ok(v) = HeaderValue::from_str(www_authenticate) {
                        res.headers_mut().insert(WWW_AUTHENTICATE, v);
                    }
                    if let Some(n) = nonce {
                        res.headers_mut().insert("dpop-nonce", n);
                    }
                    Ok(res)
                }
                ok => {
                    req.extensions_mut().insert(ok);
                    let mut res = inner.call(req).await?;
                    if let Some(n) = nonce {
                        res.headers_mut().insert("dpop-nonce", n);
                    }
                    Ok(res)
                }
            }
        })
    }
}
