//! The Better Auth session bridge for Axum (features `axum` + `backend`).
//!
//! During the migration window, a browser that still carries a Better Auth
//! session cookie is signed in to Atlas without a forced logout: on a `GET` /
//! `HEAD`, the layer exchanges the cookie once through the Backend API (secret
//! key, forwarding the end user's IP and user agent) and answers `307` to the
//! same URL with the Atlas session cookies set and the Better Auth cookies
//! cleared — the next request is signed in. A user who still owes a second
//! factor is redirected to your sign-in page with `__atlas_attempt` /
//! `__atlas_status`. Anything else (no Better Auth cookie, an Atlas session
//! already present, the bridge closed, Atlas unreachable) passes straight
//! through.
//!
//! ```no_run
//! # #[cfg(feature = "reqwest-transport")]
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use axum::{routing::get, Router};
//! use atlasauth::backend::{BackendClient, BetterAuthBridge};
//! use atlasauth::axum::BetterAuthBridgeLayer;
//!
//! let bridge = Arc::new(BetterAuthBridge::new(BackendClient::new("sk_live_…")?).sign_in_url("/sign-in"));
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "home" }))
//!     .layer(BetterAuthBridgeLayer::new(bridge));
//! # let _ = app; Ok(()) }
//! ```
//!
//! Or put it on the session layer: `AtlasLayer::new(backend).with_better_auth_bridge(bridge)`.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::axum::extract::{ConnectInfo, Request};
use ::axum::http::header::{COOKIE, LOCATION, SET_COOKIE, USER_AGENT};
use ::axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use ::axum::response::Response;
use ::tower::{Layer, Service};

use crate::backend::{client_ip_from_headers, BetterAuthBridge, BridgeAction};

/// Run the bridge for one request: `Some(response)` (a 307 carrying the
/// cookies) when it decided, `None` to carry on to the inner service.
///
/// It takes the request's parts rather than `&Request` so the future stays
/// `Send` (an Axum body is not `Sync`).
pub(crate) async fn bridge_response(
    bridge: &BetterAuthBridge,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<Response> {
    if *method != Method::GET && *method != Method::HEAD {
        return None;
    }
    let cookie = headers.get(COOKIE).and_then(|v| v.to_str().ok());
    // Cheap pre-check: no Better Auth cookie (or an Atlas session) means no network.
    bridge.token_from(cookie)?;
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let client_ip =
        client_ip_from_headers(header("x-forwarded-for"), header("x-real-ip")).or_else(|| peer.map(|a| a.ip().to_string()));
    let user_agent = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    let decision = bridge.decide(cookie, client_ip.as_deref(), user_agent).await;
    if !decision.should_redirect() {
        return None;
    }
    let here = uri.path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_else(|| "/".to_string());
    let location = if decision.action == BridgeAction::NeedsMfa {
        decision.continuation_url(bridge.sign_in_target().unwrap_or(&here))
    } else {
        here
    };
    let mut resp = Response::new(::axum::body::Body::empty());
    *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&location) {
        h.insert(LOCATION, v);
    }
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    for c in &decision.cookies {
        if let Ok(v) = HeaderValue::from_str(&c.to_set_cookie()) {
            h.append(SET_COOKIE, v);
        }
    }
    Some(resp)
}

/// A [`tower::Layer`] running the Better Auth session bridge in front of the
/// routes it wraps. Place it outermost (before the session layer) so the
/// redirect happens before any route demands a session.
#[derive(Clone)]
pub struct BetterAuthBridgeLayer {
    bridge: Arc<BetterAuthBridge>,
}

impl BetterAuthBridgeLayer {
    /// Wrap a configured bridge.
    pub fn new(bridge: Arc<BetterAuthBridge>) -> Self {
        BetterAuthBridgeLayer { bridge }
    }
}

impl<S> Layer<S> for BetterAuthBridgeLayer {
    type Service = BetterAuthBridgeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BetterAuthBridgeService { inner, bridge: self.bridge.clone() }
    }
}

/// The [`Service`] produced by [`BetterAuthBridgeLayer`].
#[derive(Clone)]
pub struct BetterAuthBridgeService<S> {
    inner: S,
    bridge: Arc<BetterAuthBridge>,
}

impl<S> Service<Request> for BetterAuthBridgeService<S>
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

    fn call(&mut self, req: Request) -> Self::Future {
        let bridge = self.bridge.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let peer = peer_addr(&req);
            if let Some(resp) = bridge_response(&bridge, req.method(), req.uri(), req.headers(), peer).await {
                return Ok(resp);
            }
            inner.call(req).await
        })
    }
}

/// The peer address, when the app serves with `into_make_service_with_connect_info`.
pub(crate) fn peer_addr(req: &Request) -> Option<SocketAddr> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0)
}
