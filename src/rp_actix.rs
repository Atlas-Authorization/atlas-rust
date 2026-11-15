//! actix-web routes for the relying party (feature `rp-actix`): sign-in, callback and sign-out, as a
//! `configure` function for `App::configure`.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use atlasauth::rp::{BoxFuture, CallbackResult, RelyingParty, RpHooks};
//! # struct Sessions;
//! # impl RpHooks for Sessions {
//! #     fn on_signed_in<'a>(&'a self, _: &'a CallbackResult) -> BoxFuture<'a, Result<Vec<String>, String>> { Box::pin(async { Ok(vec![]) }) }
//! # }
//! # fn demo(rp: Arc<RelyingParty>) {
//! let app = actix_web::App::new().configure(atlasauth::rp_actix::configure(rp, Arc::new(Sessions)));
//! # let _ = app; }
//! ```

use std::sync::Arc;

use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};

use crate::rp::{RelyingParty, RpHooks, RpResponse, RpRoute, RpRoutes};

#[derive(Clone)]
struct RpState {
    rp: Arc<RelyingParty>,
    hooks: Arc<dyn RpHooks>,
}

/// The three routes at their default paths (see [`RpRoutes::for_config`]).
pub fn configure(rp: Arc<RelyingParty>, hooks: Arc<dyn RpHooks>) -> impl FnOnce(&mut web::ServiceConfig) {
    let routes = RpRoutes::for_config(rp.config());
    configure_with_routes(rp, hooks, routes)
}

/// The three routes at the paths you choose.
pub fn configure_with_routes(rp: Arc<RelyingParty>, hooks: Arc<dyn RpHooks>, routes: RpRoutes) -> impl FnOnce(&mut web::ServiceConfig) {
    let state = RpState { rp, hooks };
    move |cfg: &mut web::ServiceConfig| {
        cfg.app_data(web::Data::new(state))
            .route(&routes.sign_in, web::get().to(sign_in))
            .route(&routes.callback, web::get().to(callback))
            .route(&routes.sign_out, web::route().to(sign_out));
    }
}

fn into_response(r: RpResponse) -> HttpResponse {
    let mut b = HttpResponse::build(StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    b.insert_header((CACHE_CONTROL, "no-store"));
    if let Some(l) = &r.location {
        b.insert_header((LOCATION, l.as_str()));
    }
    for c in &r.set_cookies {
        b.append_header((SET_COOKIE, c.as_str()));
    }
    match r.body {
        Some(text) => b.insert_header((CONTENT_TYPE, "text/plain; charset=utf-8")).body(text),
        None => b.finish(),
    }
}

async fn run(route: RpRoute, req: HttpRequest, s: web::Data<RpState>) -> HttpResponse {
    let cookie = req.headers().get(COOKIE).and_then(|v| v.to_str().ok());
    into_response(s.rp.handle_route(route, s.hooks.as_ref(), req.query_string(), cookie).await)
}

async fn sign_in(req: HttpRequest, s: web::Data<RpState>) -> HttpResponse {
    run(RpRoute::SignIn, req, s).await
}

async fn callback(req: HttpRequest, s: web::Data<RpState>) -> HttpResponse {
    run(RpRoute::Callback, req, s).await
}

async fn sign_out(req: HttpRequest, s: web::Data<RpState>) -> HttpResponse {
    run(RpRoute::SignOut, req, s).await
}
