//! Router-level protection: a [`tower::Layer`] that gates every route beneath
//! it, plus a `from_fn`-style helper for callers who prefer that wiring.
//!
//! Both do the same work the [`super::AtlasClaims`] extractor does — verify the
//! request's credential through [`AtlasBackend::authenticate_request`] — but at
//! the `Router` boundary: on success the verified [`Claims`] are inserted into
//! the request's extensions (so a downstream handler can pull them back out with
//! `Extension<Claims>`), and on failure the request is short-circuited with a
//! `401` and the inner service is never called.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::axum::extract::{Request, State};
use ::axum::middleware::Next;
use ::axum::response::{IntoResponse, Response};
use ::tower::{Layer, Service};

use super::credentials_from_headers;
use super::rejection::AtlasRejection;
use crate::claims::Claims;
use crate::verify::AtlasBackend;

/// A [`tower::Layer`] that verifies the Atlas session on every request before it
/// reaches the routes it wraps.
///
/// ```no_run
/// # #[cfg(feature = "reqwest-transport")]
/// # fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use axum::{routing::get, Router};
/// use atlasauth::{AtlasBackend, Claims, axum::AtlasLayer};
///
/// let backend = Arc::new(AtlasBackend::new(
///     "https://your-instance-fapi.atlasauth.net",
///     "https://your-instance-fapi.atlasauth.net/.well-known/jwks.json",
/// )?);
///
/// // Everything under `/api` requires a valid session; the handler reads the
/// // claims the layer inserted via the `Extension` extractor.
/// async fn whoami(axum::Extension(claims): axum::Extension<Claims>) -> String {
///     claims.sub.clone()
/// }
/// let api = Router::new().route("/whoami", get(whoami)).layer(AtlasLayer::new(backend));
/// # let _: Router = api; Ok(()) }
/// ```
///
/// Carrying the verifier as an `Arc` is what makes the layer `Clone` (Axum
/// clones a layer's service per connection) while every clone keeps sharing the
/// one JWKS cache — see the module docs.
#[derive(Clone)]
pub struct AtlasLayer {
    backend: Arc<AtlasBackend>,
}

impl AtlasLayer {
    /// Wrap a shared verifier into a layer. Clone the same `Arc<AtlasBackend>`
    /// you put in your router state so the layer and the extractor share one
    /// cache.
    pub fn new(backend: Arc<AtlasBackend>) -> Self {
        AtlasLayer { backend }
    }
}

impl<S> Layer<S> for AtlasLayer {
    type Service = AtlasAuth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AtlasAuth {
            inner,
            backend: self.backend.clone(),
        }
    }
}

/// The [`Service`] produced by [`AtlasLayer`]. Verifies, inserts [`Claims`] into
/// the request extensions, then calls the inner service — or answers `401` and
/// stops.
#[derive(Clone)]
pub struct AtlasAuth<S> {
    inner: S,
    backend: Arc<AtlasBackend>,
}

impl<S> Service<Request> for AtlasAuth<S>
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

        // The standard tower "clone and swap" so the clone that runs in the
        // async task is the one we just confirmed is ready via `poll_ready`,
        // not a fresh (possibly not-ready) clone. See the tower docs on
        // `Service::call`.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            // Verify inside its own scope so the borrow the credential `&str`s
            // (and thus the verify future) take on `req` is released before we
            // mutate `req`'s extensions — a match scrutinee keeps its temporary
            // alive for the whole match, which would otherwise collide.
            let (had_credential, verified) = {
                let (authorization, cookie) = credentials_from_headers(req.headers());
                let had = authorization.is_some() || cookie.is_some();
                (had, backend.authenticate_request(authorization, cookie).await)
            };
            match verified {
                Ok(claims) => {
                    req.extensions_mut().insert(claims);
                    inner.call(req).await
                }
                Err(err) => {
                    Ok(AtlasRejection::from_verify_error(err, had_credential).into_response())
                }
            }
        })
    }
}

/// An [`axum::middleware::from_fn_with_state`]-style guard, for callers who
/// prefer that wiring to a bespoke [`AtlasLayer`]. Identical behaviour: verify,
/// insert [`Claims`] into extensions on success, `401` on failure.
///
/// ```no_run
/// # #[cfg(feature = "reqwest-transport")]
/// # fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// use std::sync::Arc;
/// use axum::{middleware, routing::get, Router};
/// use atlasauth::{AtlasBackend, axum::require_auth};
///
/// let backend = Arc::new(AtlasBackend::new(
///     "https://your-instance-fapi.atlasauth.net",
///     "https://your-instance-fapi.atlasauth.net/.well-known/jwks.json",
/// )?);
///
/// let app: Router = Router::new()
///     .route("/private", get(|| async { "secret" }))
///     .layer(middleware::from_fn_with_state(backend.clone(), require_auth));
/// # let _ = app; Ok(()) }
/// ```
pub async fn require_auth(
    State(backend): State<Arc<AtlasBackend>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Scope the credential borrow so it is released before `req` is mutated —
    // see the note in `AtlasAuth::call`.
    let (had_credential, verified) = {
        let (authorization, cookie) = credentials_from_headers(req.headers());
        let had = authorization.is_some() || cookie.is_some();
        (had, backend.authenticate_request(authorization, cookie).await)
    };
    match verified {
        Ok(claims) => {
            req.extensions_mut().insert::<Claims>(claims);
            next.run(req).await
        }
        Err(err) => AtlasRejection::from_verify_error(err, had_credential).into_response(),
    }
}
