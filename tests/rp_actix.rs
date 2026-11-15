//! The relying party's actix-web routes, driven with `actix_web::test`. No network.
#![cfg(all(feature = "rp-actix", feature = "backend"))]

use std::sync::Arc;

use actix_web::{test, App};
use atlasauth::backend::FakeTransport;
use atlasauth::rp::{BoxFuture, CallbackResult, RelyingParty, RelyingPartyConfig, RpHooks};
use atlasauth::HttpResponse;
use serde_json::json;

struct Hooks;

impl RpHooks for Hooks {
    fn on_signed_in<'a>(&'a self, _: &'a CallbackResult) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async { Ok(vec![]) })
    }
}

fn rp() -> Arc<RelyingParty> {
    let transport = FakeTransport::new(|_| HttpResponse {
        status: 200,
        body: json!({
            "issuer": "https://auth.test",
            "authorization_endpoint": "https://auth.test/oauth2/authorize",
            "token_endpoint": "https://auth.test/oauth2/token",
            "jwks_uri": "https://auth.test/jwks.json",
        })
        .to_string(),
    });
    let cfg = RelyingPartyConfig::new("https://auth.test", "client_1", "https://app.test/auth/callback", "0123456789abcdef0123456789abcdef");
    Arc::new(RelyingParty::with_transport(cfg, Arc::new(transport)).unwrap())
}

#[actix_web::test]
async fn sign_in_redirects_with_the_flow_cookie() {
    let app = test::init_service(App::new().configure(atlasauth::rp_actix::configure(rp(), Arc::new(Hooks)))).await;
    let res = test::call_service(&app, test::TestRequest::get().uri("/auth/sign-in").to_request()).await;
    assert_eq!(res.status(), 302);
    assert!(res.headers().get("location").unwrap().to_str().unwrap().starts_with("https://auth.test/oauth2/authorize?"));
    assert!(res.headers().get("set-cookie").unwrap().to_str().unwrap().starts_with("atlas_oidc=s1."));
}

#[actix_web::test]
async fn a_callback_without_the_flow_cookie_is_a_400() {
    let app = test::init_service(App::new().configure(atlasauth::rp_actix::configure(rp(), Arc::new(Hooks)))).await;
    let res = test::call_service(&app, test::TestRequest::get().uri("/auth/callback?code=c&state=s").to_request()).await;
    assert_eq!(res.status(), 400);
}
