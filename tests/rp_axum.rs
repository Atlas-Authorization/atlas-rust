//! The relying party's Axum routes, driven with `tower::ServiceExt::oneshot`. No network: the issuer is a
//! `FakeTransport` that serves discovery only.
#![cfg(all(feature = "rp-axum", feature = "backend"))]

use std::sync::Arc;

use atlasauth::backend::FakeTransport;
use atlasauth::rp::{BoxFuture, CallbackResult, RelyingParty, RelyingPartyConfig, RpHooks, SignOutOptions};
use atlasauth::{HttpMethod, HttpResponse};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

struct Hooks;

impl RpHooks for Hooks {
    fn on_signed_in<'a>(&'a self, _: &'a CallbackResult) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async { Ok(vec!["app_session=1; Path=/".to_string()]) })
    }
    fn on_sign_out<'a>(&'a self, _: Option<&'a str>) -> BoxFuture<'a, SignOutOptions> {
        Box::pin(async { SignOutOptions { set_cookies: vec!["app_session=; Max-Age=0".into()], ..Default::default() } })
    }
}

fn app() -> axum::Router {
    let transport = FakeTransport::new(|req| {
        assert_eq!(req.method, HttpMethod::Get);
        HttpResponse {
            status: 200,
            body: json!({
                "issuer": "https://auth.test",
                "authorization_endpoint": "https://auth.test/oauth2/authorize",
                "token_endpoint": "https://auth.test/oauth2/token",
                "jwks_uri": "https://auth.test/jwks.json",
                "end_session_endpoint": "https://auth.test/oauth2/logout",
            })
            .to_string(),
        }
    });
    let cfg = RelyingPartyConfig::new("https://auth.test", "client_1", "https://app.test/auth/callback", "0123456789abcdef0123456789abcdef");
    let rp = Arc::new(RelyingParty::with_transport(cfg, Arc::new(transport)).unwrap());
    atlasauth::rp_axum::router(rp, Arc::new(Hooks))
}

#[tokio::test]
async fn sign_in_redirects_to_the_authorize_endpoint_and_sets_the_flow_cookie() {
    let res = app().oneshot(Request::get("/auth/sign-in?return_to=/x").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(res.headers()[header::LOCATION].to_str().unwrap().starts_with("https://auth.test/oauth2/authorize?"));
    assert!(res.headers()[header::SET_COOKIE].to_str().unwrap().starts_with("atlas_oidc=s1."));
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn a_callback_without_the_flow_cookie_is_a_400_that_clears_it() {
    let res = app().oneshot(Request::get("/auth/callback?code=c&state=s").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(res.headers()[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
}

#[tokio::test]
async fn sign_out_runs_the_hook_and_redirects_to_the_end_session_endpoint() {
    let res = app().oneshot(Request::post("/auth/sign-out").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(res.headers()[header::LOCATION].to_str().unwrap().starts_with("https://auth.test/oauth2/logout?"));
    assert_eq!(res.headers()[header::SET_COOKIE], "app_session=; Max-Age=0");
}

#[tokio::test]
async fn other_paths_are_not_answered() {
    let res = app().oneshot(Request::get("/elsewhere").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
