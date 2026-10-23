//! The Better Auth session bridge in Axum: the standalone layer and the
//! `AtlasLayer` option, driven with `oneshot` against a fake Backend API.
#![cfg(all(feature = "axum", feature = "backend"))]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::{header, Method, StatusCode};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

use atlasauth::axum::{AtlasLayer, BetterAuthBridgeLayer};
use atlasauth::backend::{BackendClient, BetterAuthBridge, FakeTransport};
use atlasauth::{AtlasBackend, HttpRequest, HttpResponse, Jwks};

fn fake(status: u16, body: Value) -> FakeTransport {
    FakeTransport::new(move |_req: &HttpRequest| HttpResponse { status, body: body.to_string() })
}

fn bridge(f: &FakeTransport) -> Arc<BetterAuthBridge> {
    let client = BackendClient::builder("sk_test_secret").transport(Arc::new(f.clone())).build().unwrap();
    Arc::new(BetterAuthBridge::new(client).sign_in_url("/sign-in"))
}

fn tokens() -> Value {
    json!({ "object": "session_tokens", "session_id": "sess_1", "user_id": "user_1", "jwt": "eyJ.jwt", "refresh_token": "rt_1", "expires_in": 60 })
}

fn app(b: Arc<BetterAuthBridge>) -> Router {
    Router::new()
        .route("/dash", get(|| async { "dash" }).post(|| async { "posted" }))
        .layer(BetterAuthBridgeLayer::new(b))
}

fn req(method: Method, uri: &str, cookie: Option<&str>) -> Request {
    let mut r = Request::builder().method(method).uri(uri).header(header::USER_AGENT, "Browser/1");
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    r.body(Body::empty()).unwrap()
}

fn set_cookies(resp: &axum::response::Response) -> Vec<String> {
    resp.headers().get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn a_better_auth_cookie_is_exchanged_and_redirected_to_the_same_url() {
    let f = fake(200, tokens());
    let mut r = req(Method::GET, "/dash?tab=1", Some("better-auth.session_token=tok.sig"));
    r.headers_mut().insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
    let resp = app(bridge(&f)).oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(resp.headers()[header::LOCATION], "/dash?tab=1");
    let cookies = set_cookies(&resp);
    assert!(cookies.iter().any(|c| c.starts_with("__session=eyJ.jwt;")));
    assert!(cookies.iter().any(|c| c.starts_with("__atlas_rt=rt_1;") && c.contains("HttpOnly")));
    assert!(cookies.iter().any(|c| c.starts_with("better-auth.session_token=;") && c.contains("Max-Age=0")));
    let sent = &f.requests()[0];
    assert!(sent.url.ends_with("/v1/migrations/better_auth/exchange"));
    let h = |n: &str| sent.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(h("x-atlas-client-ip").as_deref(), Some("203.0.113.9"));
    assert_eq!(h("x-atlas-client-user-agent").as_deref(), Some("Browser/1"));
}

#[tokio::test]
async fn the_peer_address_is_used_without_proxy_headers() {
    let f = fake(200, tokens());
    let mut r = req(Method::GET, "/dash", Some("better-auth.session_token=t"));
    r.extensions_mut().insert(ConnectInfo("198.51.100.7:4444".parse::<SocketAddr>().unwrap()));
    let resp = app(bridge(&f)).oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let sent = &f.requests()[0];
    assert!(sent.headers.iter().any(|(k, v)| k == "x-atlas-client-ip" && v == "198.51.100.7"));
}

#[tokio::test]
async fn passes_through_without_a_cookie_on_post_with_an_atlas_session_or_when_closed() {
    let f = fake(200, tokens());
    for r in [
        req(Method::GET, "/dash", None),
        req(Method::POST, "/dash", Some("better-auth.session_token=t")),
        req(Method::GET, "/dash", Some("better-auth.session_token=t; __atlas_rt=rt")),
    ] {
        let resp = app(bridge(&f)).oneshot(r).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(f.request_count(), 0);

    let closed = fake(403, json!({ "errors": [{ "code": "FORBIDDEN", "message": "closed", "meta": { "bridge_outcome": "closed" } }] }));
    let resp = app(bridge(&closed)).oneshot(req(Method::GET, "/dash", Some("better-auth.session_token=t"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(set_cookies(&resp).is_empty());
}

#[tokio::test]
async fn a_final_refusal_clears_and_mfa_goes_to_sign_in() {
    let reused = fake(400, json!({ "errors": [{ "code": "INVALID", "message": "used", "meta": { "bridge_outcome": "reused" } }] }));
    let resp = app(bridge(&reused)).oneshot(req(Method::GET, "/dash", Some("better-auth.session_token=t"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(resp.headers()[header::LOCATION], "/dash");
    assert!(set_cookies(&resp).iter().all(|c| c.contains("Max-Age=0")));

    let mfa = fake(200, json!({ "object": "sign_in_attempt", "id": "sia_1", "status": "needs_second_factor" }));
    let resp = app(bridge(&mfa)).oneshot(req(Method::GET, "/dash", Some("better-auth.session_token=t"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(resp.headers()[header::LOCATION], "/sign-in?__atlas_attempt=sia_1&__atlas_status=needs_second_factor");
}

#[tokio::test]
async fn atlas_layer_runs_the_bridge_before_verifying() {
    let f = fake(200, tokens());
    let jwks: Jwks = serde_json::from_value(json!({ "keys": [] })).unwrap();
    let backend = Arc::new(AtlasBackend::builder("https://atlas.test").static_jwks(jwks).build().unwrap());
    let app = Router::new()
        .route("/dash", get(|| async { "dash" }))
        .layer(AtlasLayer::new(backend).with_better_auth_bridge(bridge(&f)));
    let resp = app.clone().oneshot(req(Method::GET, "/dash", Some("better-auth.session_token=t"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(set_cookies(&resp).iter().any(|c| c.starts_with("__session=eyJ.jwt;")));
    // Without a Better Auth cookie the session layer answers as usual.
    let resp = app.oneshot(req(Method::GET, "/dash", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
