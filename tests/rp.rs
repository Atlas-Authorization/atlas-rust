//! The hosted-redirect relying party against an in-memory issuer: start, callback, step-up, keep-alive
//! and sign-out. No network: discovery, JWKS, the token endpoint and the session endpoints are a
//! `FakeTransport` handler, and ID tokens are signed by an in-test ES256 key.
#![cfg(all(feature = "rp", feature = "backend"))]

mod support;

use std::sync::{Arc, Mutex};

use atlasauth::backend::FakeTransport;
use atlasauth::rp::{
    is_safe_return_to, EndedReason, OidcErrorCode, RelyingParty, RelyingPartyConfig, RpError, SignOutOptions, StartOverrides,
    TouchResult,
};
use atlasauth::{HttpMethod, HttpRequest, HttpResponse};
use serde_json::{json, Value};
use url::Url;

const ISSUER: &str = "https://auth.test";
const CLIENT: &str = "client_1";
const REDIRECT: &str = "https://app.test/auth/callback";
const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn json_resp(status: u16, v: Value) -> HttpResponse {
    HttpResponse { status, body: v.to_string() }
}

/// What the fake issuer should put in the next ID token, and how the session endpoints answer.
#[derive(Clone, Default)]
struct Script {
    nonce: Arc<Mutex<String>>,
    id_claims: Arc<Mutex<Value>>,
    session_status: Arc<Mutex<(u16, Value)>>,
}

fn issuer(script: Script) -> FakeTransport {
    FakeTransport::new(move |req: &HttpRequest| {
        let url = req.url.as_str();
        if url == format!("{ISSUER}/.well-known/openid-configuration") {
            return json_resp(200, json!({
                "issuer": ISSUER,
                "authorization_endpoint": format!("{ISSUER}/oauth2/authorize"),
                "token_endpoint": format!("{ISSUER}/oauth2/token"),
                "jwks_uri": format!("{ISSUER}/.well-known/jwks.json"),
                "end_session_endpoint": format!("{ISSUER}/oauth2/logout"),
            }));
        }
        if url.ends_with("/jwks.json") {
            return json_resp(200, support::keys().jwks.clone());
        }
        if url.ends_with("/oauth2/token") {
            let now = support::now_secs();
            let mut claims = json!({ "iss": ISSUER, "aud": CLIENT, "sub": "user_1", "iat": now, "exp": now + 300,
                "nonce": script.nonce.lock().unwrap().clone(), "sid": "sess_1", "email": "a@b.test",
                "email_verified": true, "auth_time": now });
            if let Some(extra) = script.id_claims.lock().unwrap().as_object() {
                claims.as_object_mut().unwrap().extend(extra.clone());
            }
            return json_resp(200, json!({ "id_token": support::es256(&claims, None), "access_token": "at_1", "expires_in": 3600 }));
        }
        if url.contains("/v1/sessions/") || url.contains("/oauth2/session/") || url.contains("/v1/oauth_clients/") {
            let (status, body) = script.session_status.lock().unwrap().clone();
            return json_resp(status, body);
        }
        json_resp(404, json!({}))
    })
}

fn cfg() -> RelyingPartyConfig {
    RelyingPartyConfig::new(ISSUER, CLIENT, REDIRECT, SECRET).client_secret("cs_1").forward_params(["ref"])
}

fn rp_with(cfg: RelyingPartyConfig) -> (RelyingParty, FakeTransport, Script) {
    let script = Script::default();
    *script.session_status.lock().unwrap() = (200, json!({}));
    let transport = issuer(script.clone());
    (RelyingParty::with_transport(cfg, Arc::new(transport.clone())).unwrap(), transport, script)
}

fn param(location: &str, name: &str) -> Option<String> {
    Url::parse(location).unwrap().query_pairs().find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

fn cookie_header(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn start_builds_a_pkce_authorize_redirect_and_a_sealed_flow_cookie() {
    let (rp, _, _) = rp_with(cfg());
    let r = rp.start("return_to=/billing&prompt=create&ref=friend&utm=dropped&login_hint=a%40b.test", StartOverrides::default()).await.unwrap();
    assert!(r.location.starts_with("https://auth.test/oauth2/authorize?"));
    assert_eq!(param(&r.location, "response_type").as_deref(), Some("code"));
    assert_eq!(param(&r.location, "client_id").as_deref(), Some(CLIENT));
    assert_eq!(param(&r.location, "redirect_uri").as_deref(), Some(REDIRECT));
    assert_eq!(param(&r.location, "code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(param(&r.location, "code_challenge").unwrap().len(), 43);
    assert_eq!(param(&r.location, "scope").as_deref(), Some("openid profile email"));
    assert_eq!(param(&r.location, "prompt").as_deref(), Some("create"));
    assert_eq!(param(&r.location, "login_hint").as_deref(), Some("a@b.test"));
    assert_eq!(param(&r.location, "ref").as_deref(), Some("friend"));
    assert!(param(&r.location, "utm").is_none(), "only listed forward_params pass through");
    assert!(param(&r.location, "return_to").is_none(), "return_to rides in the cookie, never the authorize URL");
    let cookie = &r.set_cookies[0];
    assert!(cookie.starts_with("atlas_oidc=s1."));
    for part in ["Path=/auth/callback", "Max-Age=600", "HttpOnly", "SameSite=Lax", "Secure"] {
        assert!(cookie.contains(part), "{part} in {cookie}");
    }
    // The state and nonce are not readable from the cookie value.
    assert!(!cookie.contains(&param(&r.location, "state").unwrap()));
}

#[tokio::test]
async fn an_unsafe_return_to_is_dropped_from_the_query() {
    let (rp, _, _) = rp_with(cfg());
    let r = rp.start("return_to=//evil.test", StartOverrides::default()).await.unwrap();
    assert_eq!(r.set_cookies.len(), 1, "a bad return_to is dropped, never an error page");
    for bad in ["//evil.test", "/\\evil.test", "https://evil.test", "evil", "/a\nb"] {
        assert!(!is_safe_return_to(bad), "{bad:?}");
    }
    for ok in ["/", "/billing?tab=1", "/a/b#c"] {
        assert!(is_safe_return_to(ok), "{ok:?}");
    }
    assert!(rp.start("", StartOverrides { return_to: Some("//evil.test".into()), ..Default::default() }).await.is_err());
}

async fn signed_in(rp: &RelyingParty, script: &Script, query: &str) -> (atlasauth::rp::CallbackResult, String) {
    let started = rp.start(query, StartOverrides::default()).await.unwrap();
    *script.nonce.lock().unwrap() = param(&started.location, "nonce").unwrap();
    let state = param(&started.location, "state").unwrap();
    let done = rp.callback(&format!("code=abc&state={state}&iss={ISSUER}"), Some(&cookie_header(&started.set_cookies[0]))).await.unwrap();
    (done, state)
}

#[tokio::test]
async fn callback_verifies_the_id_token_and_returns_the_user_and_a_clearing_redirect() {
    let (rp, transport, script) = rp_with(cfg());
    let (done, _) = signed_in(&rp, &script, "return_to=/billing").await;
    assert_eq!(done.user.sub, "user_1");
    assert_eq!(done.user.sid.as_deref(), Some("sess_1"));
    assert_eq!(done.user.email.as_deref(), Some("a@b.test"));
    assert!(done.user.email_verified);
    assert_eq!(done.identity.namespaced_sub, "https://auth.test#user_1");
    assert_eq!(done.tokens.access_token, "at_1");
    assert_eq!(done.redirect.location, "/billing");
    assert!(done.redirect.set_cookies[0].starts_with("atlas_oidc=;") && done.redirect.set_cookies[0].contains("Max-Age=0"));
    // The code exchange carried PKCE and Basic client authentication.
    let token_req = transport.requests().into_iter().find(|r| r.url.ends_with("/oauth2/token")).unwrap();
    assert_eq!(token_req.method, HttpMethod::Post);
    let body = token_req.body.unwrap();
    assert!(body.contains("grant_type=authorization_code") && body.contains("code_verifier=") && body.contains("code=abc"));
    assert!(token_req.headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Basic ")));
}

#[tokio::test]
async fn callback_without_a_return_path_goes_to_the_default_path() {
    let (rp, _, script) = rp_with(cfg().after_sign_in_path("/home"));
    let (done, _) = signed_in(&rp, &script, "").await;
    assert_eq!(done.redirect.location, "/home");
}

#[tokio::test]
async fn callback_refuses_a_wrong_state_a_missing_or_tampered_cookie_and_an_old_flow() {
    let (rp, _, script) = rp_with(cfg());
    let started = rp.start("", StartOverrides::default()).await.unwrap();
    *script.nonce.lock().unwrap() = param(&started.location, "nonce").unwrap();
    let cookie = cookie_header(&started.set_cookies[0]);
    let state = param(&started.location, "state").unwrap();

    let e = rp.callback("code=abc&state=wrong", Some(&cookie)).await.unwrap_err();
    assert_eq!(e.code, OidcErrorCode::StateMismatch);
    assert!(e.clear_cookie.is_some(), "a failed callback always clears the flow cookie");

    assert_eq!(rp.callback(&format!("code=abc&state={state}"), None).await.unwrap_err().code, OidcErrorCode::StateMismatch);

    let mut tampered = cookie.clone();
    tampered.pop();
    tampered.push('A');
    assert_eq!(rp.callback(&format!("code=abc&state={state}"), Some(&tampered)).await.unwrap_err().code, OidcErrorCode::StateMismatch);

    // A flow older than ten minutes.
    let late = RelyingParty::with_transport(cfg(), Arc::new(issuer(script.clone())))
        .unwrap()
        .with_clock(Arc::new(|| support::now_secs() as u64 * 1000 + 11 * 60_000));
    assert_eq!(late.callback(&format!("code=abc&state={state}"), Some(&cookie)).await.unwrap_err().code, OidcErrorCode::StateMismatch);

    let denied = rp.callback(&format!("error=access_denied&error_description=no&state={state}"), Some(&cookie)).await.unwrap_err();
    assert_eq!(denied.code, OidcErrorCode::AccessDenied);
    assert_eq!(denied.oauth_error.as_deref(), Some("access_denied"));

    let wrong_iss = rp.callback(&format!("code=abc&state={state}&iss=https://evil.test"), Some(&cookie)).await.unwrap_err();
    assert_eq!(wrong_iss.code, OidcErrorCode::IssuerMismatch);
}

#[tokio::test]
async fn callback_refuses_an_id_token_with_the_wrong_nonce_audience_or_issuer() {
    for (patch, why) in [
        (json!({ "nonce": "someone-elses" }), "nonce"),
        (json!({ "aud": "other_client" }), "audience"),
        (json!({ "iss": "https://evil.test" }), "issuer"),
        (json!({ "exp": support::now_secs() - 3600 }), "expiry"),
        (json!({ "aud": [CLIENT, "x"] }), "several audiences without azp"),
        (json!({ "azp": "other" }), "azp"),
        (json!({ "at_hash": "AAAAAAAAAAAAAAAAAAAAAA" }), "at_hash"),
    ] {
        let (rp, _, script) = rp_with(cfg());
        *script.id_claims.lock().unwrap() = patch;
        let started = rp.start("", StartOverrides::default()).await.unwrap();
        *script.nonce.lock().unwrap() = param(&started.location, "nonce").unwrap();
        // The patch may overwrite the nonce on purpose; the other cases need the real one.
        let state = param(&started.location, "state").unwrap();
        let e = rp.callback(&format!("code=abc&state={state}"), Some(&cookie_header(&started.set_cookies[0]))).await.unwrap_err();
        assert_eq!(e.code, OidcErrorCode::InvalidToken, "{why}: {e}");
    }
}

#[tokio::test]
async fn step_up_asks_the_same_user_again_and_the_callback_enforces_it() {
    let (rp, _, script) = rp_with(cfg());
    let now = support::now_secs();
    // Recent enough: no redirect.
    assert!(rp.require_recent_auth("/settings", 300, "user_1", Some(now - 10)).await.unwrap().is_none());
    // Too old: a redirect with max_age and an expected-sub flow.
    let r = rp.require_recent_auth("/settings?x=1", 300, "user_1", Some(now - 4000)).await.unwrap().unwrap();
    assert_eq!(param(&r.location, "max_age").as_deref(), Some("300"));
    assert!(param(&r.location, "prompt").is_none());
    // Zero forces a fresh sign-in and still passes inside the confirmation window.
    let zero = rp.require_recent_auth("/settings", 0, "user_1", Some(now - 4000)).await.unwrap().unwrap();
    assert_eq!(param(&zero.location, "prompt").as_deref(), Some("login"));
    assert!(rp.require_recent_auth("/settings", 0, "user_1", Some(now - 5)).await.unwrap().is_none());

    // A different user coming back is refused, an old auth_time is refused, the right user passes.
    *script.nonce.lock().unwrap() = param(&r.location, "nonce").unwrap();
    let state = param(&r.location, "state").unwrap();
    let cookie = cookie_header(&r.set_cookies[0]);
    *script.id_claims.lock().unwrap() = json!({ "sub": "user_2" });
    assert_eq!(rp.callback(&format!("code=abc&state={state}"), Some(&cookie)).await.unwrap_err().code, OidcErrorCode::SubjectMismatch);
    *script.id_claims.lock().unwrap() = json!({ "auth_time": now - 4000 });
    assert_eq!(rp.callback(&format!("code=abc&state={state}"), Some(&cookie)).await.unwrap_err().code, OidcErrorCode::ReauthenticationRequired);
    *script.id_claims.lock().unwrap() = json!({});
    let ok = rp.callback(&format!("code=abc&state={state}"), Some(&cookie)).await.unwrap();
    assert_eq!(ok.redirect.location, "/settings?x=1");
}

#[tokio::test]
async fn touch_if_due_skips_inside_the_interval_and_maps_session_state() {
    let (rp, transport, script) = rp_with(cfg().secret_key("sk_test_1"));
    let now = support::now_secs() as u64 * 1000;
    assert_eq!(rp.touch_if_due("sess_1", Some(now)).await.unwrap(), TouchResult::Skipped { last_touched_at: now });
    assert_eq!(transport.request_count(), 0, "a skipped touch sends nothing");

    *script.session_status.lock().unwrap() = (200, json!({ "idle_expires_at": "2030-01-01T00:00:00Z" }));
    match rp.touch_if_due("sess_1", None).await.unwrap() {
        TouchResult::Touched { idle_expires_at, .. } => assert_eq!(idle_expires_at.as_deref(), Some("2030-01-01T00:00:00Z")),
        other => panic!("{other:?}"),
    }
    let req = transport.requests().pop().unwrap();
    assert_eq!(req.url, "https://api.atlasauth.net/v1/sessions/sess_1/touch");
    assert!(req.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer sk_test_1"));

    *script.session_status.lock().unwrap() = (404, json!({ "errors": [{ "code": "NOT_FOUND", "message": "x" }] }));
    assert_eq!(rp.touch_if_due("sess_1", None).await.unwrap(), TouchResult::Ended { reason: EndedReason::NotFound });
    *script.session_status.lock().unwrap() = (409, json!({ "errors": [{ "code": "SESSION_REVOKED", "message": "x" }] }));
    assert_eq!(rp.touch_if_due("sess_1", None).await.unwrap(), TouchResult::Ended { reason: EndedReason::Revoked });
    *script.session_status.lock().unwrap() = (409, json!({ "errors": [{ "code": "SESSION_IDLE_EXPIRED", "message": "x" }] }));
    assert_eq!(rp.touch_if_due("sess_1", None).await.unwrap(), TouchResult::Ended { reason: EndedReason::IdleExpired });
    // A key or availability problem is not "signed out".
    *script.session_status.lock().unwrap() = (403, json!({ "errors": [{ "code": "FORBIDDEN", "message": "scope" }] }));
    assert!(matches!(rp.touch_if_due("sess_1", None).await, Err(RpError::Api { status: 403, .. })));
}

#[tokio::test]
async fn without_a_secret_key_touch_uses_the_app_client_credentials() {
    let (rp, transport, script) = rp_with(cfg());
    *script.session_status.lock().unwrap() = (200, json!({ "idle_expires_at": 1_893_456_000_000i64 }));
    match rp.touch_if_due("sess_1", None).await.unwrap() {
        TouchResult::Touched { idle_expires_at, .. } => assert_eq!(idle_expires_at.as_deref(), Some("2030-01-01T00:00:00.000Z")),
        other => panic!("{other:?}"),
    }
    let req = transport.requests().pop().unwrap();
    assert_eq!(req.url, "https://auth.test/oauth2/session/touch");
    assert!(req.headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Basic ")));
    assert_eq!(req.body.as_deref(), Some("sid=sess_1"));
    *script.session_status.lock().unwrap() = (404, json!({ "error": "session_not_found" }));
    assert_eq!(rp.touch_if_due("sess_1", None).await.unwrap(), TouchResult::Ended { reason: EndedReason::NotFound });
    assert!(!rp.end_app_session("sess_1").await.unwrap());

    // A public client with no secret key cannot touch.
    let (public, _, _) = rp_with(RelyingPartyConfig::new(ISSUER, CLIENT, REDIRECT, SECRET));
    assert!(matches!(public.touch_if_due("sess_1", None).await, Err(RpError::Config(_))));
}

#[tokio::test]
async fn sign_out_revokes_then_redirects_to_the_end_session_endpoint() {
    let (rp, transport, _) = rp_with(cfg().secret_key("sk_test_1").post_logout_redirect_uri("https://app.test/"));
    let r = rp
        .sign_out(SignOutOptions { sid: Some("sess_1".into()), id_token: Some("idt".into()), state: Some("s1".into()), set_cookies: vec!["app=; Max-Age=0".into()], ..Default::default() })
        .await
        .unwrap();
    assert!(r.location.starts_with("https://auth.test/oauth2/logout?"));
    assert_eq!(param(&r.location, "id_token_hint").as_deref(), Some("idt"));
    assert_eq!(param(&r.location, "post_logout_redirect_uri").as_deref(), Some("https://app.test/"));
    assert_eq!(param(&r.location, "state").as_deref(), Some("s1"));
    assert_eq!(r.set_cookies, vec!["app=; Max-Age=0".to_string()]);
    assert!(transport.requests().iter().any(|q| q.url == "https://api.atlasauth.net/v1/sessions/sess_1/revoke"));
}

#[tokio::test]
async fn server_sign_out_is_one_call_and_redirects_straight_to_the_post_logout_uri() {
    let (rp, transport, _) = rp_with(cfg().secret_key("sk_test_1").server_sign_out(true).post_logout_redirect_uri("/bye"));
    let r = rp.sign_out(SignOutOptions { sid: Some("sess_1".into()), state: Some("x".into()), ..Default::default() }).await.unwrap();
    assert_eq!(r.location, "/bye?state=x");
    let call = transport.requests().pop().unwrap();
    assert_eq!(call.url, "https://api.atlasauth.net/v1/oauth_clients/client_1/logout");
    assert_eq!(serde_json::from_str::<Value>(&call.body.unwrap()).unwrap(), json!({ "sid": "sess_1" }));
}

#[test]
fn the_config_is_validated_up_front() {
    let t: Arc<dyn atlasauth::HttpTransport> = Arc::new(FakeTransport::json_ok("{}"));
    assert!(RelyingParty::with_transport(RelyingPartyConfig::new(ISSUER, CLIENT, REDIRECT, "short"), t.clone()).is_err());
    assert!(RelyingParty::with_transport(RelyingPartyConfig::new(ISSUER, CLIENT, "http://app.test/cb", SECRET), t.clone()).is_err());
    assert!(RelyingParty::with_transport(RelyingPartyConfig::new(ISSUER, CLIENT, "http://localhost:3000/cb", SECRET), t.clone()).is_ok());
    assert!(RelyingParty::with_transport(cfg().forward_params(["state"]), t.clone()).is_err());
    assert!(RelyingParty::with_transport(cfg().after_sign_in_path("//x"), t).is_err());
}

#[test]
fn routes_map_methods_and_paths() {
    use atlasauth::rp::{RpRoute, RpRoutes};
    let routes = RpRoutes::for_config(&cfg());
    assert_eq!(routes.route_for("GET", "/auth/sign-in"), Some(RpRoute::SignIn));
    assert_eq!(routes.route_for("get", "/auth/callback"), Some(RpRoute::Callback));
    assert_eq!(routes.route_for("POST", "/auth/sign-out"), Some(RpRoute::SignOut));
    assert_eq!(routes.route_for("POST", "/auth/sign-in"), None);
    assert_eq!(routes.route_for("GET", "/other"), None);
}
