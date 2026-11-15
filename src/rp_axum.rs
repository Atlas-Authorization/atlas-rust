//! Axum routes for the relying party (feature `rp-axum`): sign-in, callback and sign-out, as a
//! [`Router`] you merge into your app.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use atlasauth::rp::{BoxFuture, CallbackResult, RelyingParty, RpHooks};
//! struct Sessions;
//! impl RpHooks for Sessions {
//!     fn on_signed_in<'a>(&'a self, r: &'a CallbackResult) -> BoxFuture<'a, Result<Vec<String>, String>> {
//!         Box::pin(async move { Ok(vec![format!("app_session={}; Path=/; HttpOnly; Secure; SameSite=Lax", r.user.sub)]) })
//!     }
//! }
//! # fn demo(rp: Arc<RelyingParty>) {
//! let app: axum::Router = axum::Router::new().merge(atlasauth::rp_axum::router(rp, Arc::new(Sessions)));
//! # let _ = app; }
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;

use crate::rp::{RelyingParty, RpHooks, RpResponse, RpRoute, RpRoutes};

#[derive(Clone)]
struct RpState {
    rp: Arc<RelyingParty>,
    hooks: Arc<dyn RpHooks>,
}

/// The three routes at their default paths (see [`RpRoutes::for_config`]).
pub fn router<S>(rp: Arc<RelyingParty>, hooks: Arc<dyn RpHooks>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let routes = RpRoutes::for_config(rp.config());
    router_with_routes(rp, hooks, routes)
}

/// The three routes at the paths you choose.
pub fn router_with_routes<S>(rp: Arc<RelyingParty>, hooks: Arc<dyn RpHooks>, routes: RpRoutes) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(&routes.sign_in, get(sign_in))
        .route(&routes.callback, get(callback))
        .route(&routes.sign_out, any(sign_out))
        .with_state(RpState { rp, hooks })
}

fn cookie_of(headers: &HeaderMap) -> Option<&str> {
    headers.get(COOKIE).and_then(|v| v.to_str().ok())
}

fn into_response(r: RpResponse) -> Response {
    let mut b = Response::builder().status(StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)).header(CACHE_CONTROL, "no-store");
    if let Some(l) = &r.location {
        b = b.header(LOCATION, l.as_str());
    }
    if r.body.is_some() {
        b = b.header(CONTENT_TYPE, "text/plain; charset=utf-8");
    }
    for c in &r.set_cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            b = b.header(SET_COOKIE, v);
        }
    }
    b.body(Body::from(r.body.unwrap_or_default())).unwrap_or_else(|_| {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        resp
    })
}

async fn run(s: RpState, route: RpRoute, q: Option<String>, headers: HeaderMap) -> Response {
    into_response(s.rp.handle_route(route, s.hooks.as_ref(), q.as_deref().unwrap_or(""), cookie_of(&headers)).await)
}

async fn sign_in(State(s): State<RpState>, RawQuery(q): RawQuery, headers: HeaderMap) -> Response {
    run(s, RpRoute::SignIn, q, headers).await
}

async fn callback(State(s): State<RpState>, RawQuery(q): RawQuery, headers: HeaderMap) -> Response {
    run(s, RpRoute::Callback, q, headers).await
}

async fn sign_out(State(s): State<RpState>, RawQuery(q): RawQuery, headers: HeaderMap) -> Response {
    run(s, RpRoute::SignOut, q, headers).await
}
