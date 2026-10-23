//! Opaque-token introspection, BotID attestations, device approval, the logout
//! hand-off, the new webhook event types and the auth_config shortcuts.
#![cfg(all(feature = "backend", feature = "client"))]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use atlasauth::backend::{
    BackendClient, EventType, FakeTransport, CAPTCHA_PROVIDERS, LINKING_TRUST_LEVELS,
};
use atlasauth::client::{
    format_user_code, user_code_from_url, SelfServiceClient, SessionLogout, StaticBearer,
};
use atlasauth::{
    create_botid_attestation, AccessTokenOptions, AccessTokenResult, AtlasBackend, Clock,
    HttpRequest, HttpResponse, HttpTransport, IntrospectionOptions, Introspector, Jwks,
    BOTID_ATTESTATION_PREFIX,
};

const ISSUER: &str = "https://issuer.test";
const AUD: &str = "https://api.test";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn form_value(body: &str, key: &str) -> String {
    body.split('&')
        .find_map(|p| p.strip_prefix(&format!("{key}=")))
        .unwrap_or("")
        .to_string()
}

struct Atlas {
    fake: FakeTransport,
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicBool>,
}

fn atlas() -> Atlas {
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicBool::new(true));
    let (c, a) = (calls.clone(), active.clone());
    let fake = FakeTransport::new(move |req: &HttpRequest| {
        c.fetch_add(1, Ordering::SeqCst);
        let body = req.body.clone().unwrap_or_default();
        let token = form_value(&body, "token");
        if token == "oat_down" {
            return HttpResponse {
                status: 500,
                body: String::new(),
            };
        }
        if !a.load(Ordering::SeqCst) || token == "oat_dead" {
            return HttpResponse {
                status: 200,
                body: r#"{"active":false}"#.into(),
            };
        }
        let iss = if token == "oat_foreign" {
            "https://other.test"
        } else {
            ISSUER
        };
        HttpResponse {
            status: 200,
            body: json!({ "active": true, "iss": iss, "sub": "u_1", "aud": AUD, "scope": "read",
                "client_id": "oc_1", "exp": now() + 3600 })
            .to_string(),
        }
    });
    Atlas {
        fake,
        calls,
        active,
    }
}

fn backend() -> AtlasBackend {
    let jwks: Jwks = serde_json::from_value(json!({ "keys": [] })).unwrap();
    AtlasBackend::builder(ISSUER)
        .static_jwks(jwks)
        .build()
        .unwrap()
}

fn options(introspector: Option<Arc<Introspector>>) -> AccessTokenOptions {
    AccessTokenOptions {
        audiences: vec![AUD.into()],
        introspection: introspector,
        ..Default::default()
    }
}

#[tokio::test]
async fn opaque_tokens_are_introspected_and_cached() {
    let a = atlas();
    let transport: Arc<dyn HttpTransport> = Arc::new(a.fake.clone());
    let introspector = Arc::new(
        Introspector::new(
            ISSUER,
            IntrospectionOptions::new("oc_api", "s3cret"),
            transport,
        )
        .unwrap(),
    );
    let b = backend();
    let opts = AccessTokenOptions {
        required_scopes: vec!["read".into()],
        ..options(Some(introspector.clone()))
    };
    match b.verify_access_token(Some("Bearer oat_live"), &opts).await {
        AccessTokenResult::Ok {
            subject, client_id, ..
        } => {
            assert_eq!(subject, "u_1");
            assert_eq!(client_id.as_deref(), Some("oc_1"));
        }
        other => panic!("opaque token refused: {other:?}"),
    }
    let req = &a.fake.requests()[0];
    assert_eq!(req.url, "https://issuer.test/oauth2/introspect");
    let auth = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .unwrap()
        .1
        .clone();
    assert_eq!(auth, format!("Basic {}", STANDARD.encode("oc_api:s3cret")));
    assert_eq!(
        form_value(req.body.as_deref().unwrap(), "token_type_hint"),
        "access_token"
    );

    b.verify_access_token(Some("Bearer oat_live"), &opts).await;
    assert_eq!(a.calls.load(Ordering::SeqCst), 1, "cached");
    let admin = AccessTokenOptions {
        required_scopes: vec!["admin".into()],
        ..options(Some(introspector.clone()))
    };
    match b.verify_access_token(Some("Bearer oat_live"), &admin).await {
        AccessTokenResult::Refused { status, error, .. } => {
            assert_eq!(status, 403);
            assert_eq!(error, Some("insufficient_scope"));
        }
        other => panic!("{other:?}"),
    }
    assert!(!b
        .verify_access_token(Some("Bearer oat_dead"), &opts)
        .await
        .is_ok());
    let n = a.calls.load(Ordering::SeqCst);
    b.verify_access_token(Some("Bearer oat_dead"), &opts).await;
    assert_eq!(a.calls.load(Ordering::SeqCst), n, "negative answer cached");
    match b
        .verify_access_token(Some("Bearer oat_foreign"), &opts)
        .await
    {
        AccessTokenResult::Refused { description, .. } => {
            assert!(description.contains("another authorization server"))
        }
        other => panic!("{other:?}"),
    }
    match b.verify_access_token(Some("Bearer oat_down"), &opts).await {
        AccessTokenResult::Refused { description, .. } => {
            assert!(description.contains("could not be validated"))
        }
        other => panic!("{other:?}"),
    }
    match b
        .verify_access_token(Some("Bearer oat_live"), &options(None))
        .await
    {
        AccessTokenResult::Refused { description, .. } => {
            assert!(description.contains("introspection"))
        }
        other => panic!("{other:?}"),
    }

    // introspect_jwts: a JWT is checked live too (here: revoked).
    let mut live = IntrospectionOptions::new("oc_api", "s3cret");
    live.introspect_jwts = true;
    let t2: Arc<dyn HttpTransport> = Arc::new(a.fake.clone());
    let live = Arc::new(Introspector::new(ISSUER, live, t2).unwrap());
    a.active.store(false, Ordering::SeqCst);
    assert!(!b
        .verify_access_token(Some("Bearer aaa.bbb.ccc"), &options(Some(live)))
        .await
        .is_ok());
    let t3: Arc<dyn HttpTransport> = Arc::new(a.fake.clone());
    assert!(Introspector::new(ISSUER, IntrospectionOptions::new("", ""), t3).is_err());
}

#[tokio::test]
async fn introspector_cache_is_bounded_and_never_outlives_exp() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let transport: Arc<dyn HttpTransport> =
        Arc::new(FakeTransport::new(move |_req: &HttpRequest| {
            h.fetch_add(1, Ordering::SeqCst);
            HttpResponse {
                status: 200,
                body: r#"{"active":true,"exp":1800000005}"#.into(),
            }
        }));
    let clock_ms = Arc::new(AtomicU64::new(1_800_000_000_000));
    let c = clock_ms.clone();
    let clock: Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let mut opts = IntrospectionOptions::new("a", "b");
    opts.cache_max = 2;
    let i = Introspector::with_clock(ISSUER, opts, transport, clock).unwrap();
    for t in ["t1", "t2", "t3"] {
        assert!(i.introspect(t).await.unwrap().is_some());
    }
    assert_eq!(i.cache_len(), 2);
    i.introspect("t3").await.unwrap();
    let n = hits.load(Ordering::SeqCst);
    clock_ms.fetch_add(6000, Ordering::SeqCst);
    i.introspect("t3").await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), n + 1, "never reused past exp");
}

#[test]
fn botid_attestation_format() {
    let secret = "k".repeat(32);
    let tok = create_botid_attestation(&secret, false, false, 3600, 1_800_000_000).unwrap();
    assert!(tok.starts_with(BOTID_ATTESTATION_PREFIX));
    let rest = &tok[BOTID_ATTESTATION_PREFIX.len()..];
    let (payload, sig) = rest.rsplit_once('.').unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{BOTID_ATTESTATION_PREFIX}{payload}").as_bytes());
    assert_eq!(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()), sig);
    let p: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(p["v"], 1);
    assert_eq!(p["is_bot"], false);
    assert_eq!(p["iat"], 1_800_000_000u64);
    assert_eq!(p["exp"].as_u64().unwrap() - p["iat"].as_u64().unwrap(), 300);
    assert!(p["jti"].as_str().unwrap().len() >= 20);
    assert!(create_botid_attestation("short", false, false, 60, 0).is_err());
}

fn self_service(status: Arc<std::sync::atomic::AtomicU16>) -> (SelfServiceClient, FakeTransport) {
    let fake = FakeTransport::new(move |req: &HttpRequest| {
        if req.url.contains("/v1/client/sessions/") {
            return HttpResponse {
                status: 200,
                body: r#"{"object":"session","upstream_logout_url":"https://idp.test/logout?x=1","saml_logout_url":"http://insecure.test/slo"}"#.into(),
            };
        }
        let s = status.load(Ordering::SeqCst);
        if s != 200 {
            return HttpResponse {
                status: s,
                body: r#"{"errors":[{"code":"STEP_UP_REQUIRED","message":"Re-authenticate."}]}"#
                    .into(),
            };
        }
        HttpResponse {
            status: 200,
            body: r#"{"object":"device_authorization","id":"da_1","user_code":"WDJB-MJHT","status":"pending","client":{"client_id":"oc_tv","name":"TV","first_party":true},"scopes":[{"scope":"openid","description":"Sign you in"}],"audience":null,"requires_step_up":true,"created_at":1,"expires_at":2}"#.into(),
        }
    });
    let bearer = Arc::new(StaticBearer {
        bearer: "sess_jwt".into(),
        publishable_key: "pk_x".into(),
    });
    (
        SelfServiceClient::new(Arc::new(fake.clone()), "https://fapi.test/", bearer),
        fake,
    )
}

#[tokio::test]
async fn device_approval_from_a_signed_in_app() {
    let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
    let (c, fake) = self_service(status.clone());
    let auth = c.lookup_device_authorization(" wdjb mjht ").await.unwrap();
    let req = fake.requests().last().cloned().unwrap();
    assert_eq!(
        req.url,
        "https://fapi.test/v1/client/me/device_authorizations/lookup"
    );
    assert!(req.body.as_deref().unwrap().contains("\"WDJB-MJHT\""));
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == "Bearer sess_jwt"));
    assert_eq!(auth.client.name, "TV");
    assert!(auth.requires_step_up);
    assert_eq!(auth.scopes[0].description, "Sign you in");
    c.approve_device_authorization(&auth).await.unwrap();
    assert_eq!(
        fake.requests().last().unwrap().url,
        "https://fapi.test/v1/client/me/device_authorizations/da_1/approve"
    );
    c.deny_device_authorization(&auth).await.unwrap();
    assert_eq!(
        fake.requests().last().unwrap().url,
        "https://fapi.test/v1/client/me/device_authorizations/da_1/deny"
    );
    status.store(403, Ordering::SeqCst);
    let err = c.approve_device_authorization(&auth).await.unwrap_err();
    assert!(err.needs_reverification());
    assert!(!err.is_invalid_code());
    assert_eq!(format_user_code("abc"), "abc");
    assert_eq!(
        user_code_from_url("https://x.test/d?user_code=wdjbmjht"),
        Some("WDJB-MJHT".into())
    );
    assert_eq!(user_code_from_url("nope"), None);
}

#[tokio::test]
async fn sign_out_hands_back_upstream_logout_urls() {
    let (c, fake) = self_service(Arc::new(std::sync::atomic::AtomicU16::new(200)));
    let out = c
        .revoke_session_for_logout("sess_1", Some("https://app.test/bye"))
        .await
        .unwrap();
    let req = fake.requests().last().cloned().unwrap();
    assert_eq!(
        req.url,
        "https://fapi.test/v1/client/sessions/sess_1/revoke"
    );
    let body: Value = serde_json::from_str(req.body.as_deref().unwrap()).unwrap();
    assert_eq!(body["return_url"], "https://app.test/bye");
    assert_eq!(
        out.upstream_logout_url.as_deref(),
        Some("https://idp.test/logout?x=1")
    );
    assert_eq!(out.saml_logout_url, None, "a non-https URL is dropped");
    assert_eq!(out.url(), Some("https://idp.test/logout?x=1"));
    assert_eq!(
        SessionLogout::from_response(&json!({})),
        SessionLogout::default()
    );
}

#[test]
fn new_webhook_event_types() {
    assert_eq!(
        EventType::from("session.updated"),
        EventType::SessionUpdated
    );
    assert_eq!(
        EventType::from("user.reactivated"),
        EventType::UserReactivated
    );
    assert_eq!(EventType::SessionUpdated.as_str(), "session.updated");
    assert_eq!(EventType::UserReactivated.as_str(), "user.reactivated");
}

#[tokio::test]
async fn auth_config_shortcuts() {
    let fake = FakeTransport::json_ok(r#"{"object":"instance","id":"ins_1"}"#);
    let client = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap();
    client
        .instance()
        .set_account_linking_trust(&[("google", "always"), ("custom_*", "never")])
        .await
        .unwrap();
    let body: Value =
        serde_json::from_str(fake.requests().last().unwrap().body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body["auth_config"]["accountLinkingTrust"]["custom_*"],
        "never"
    );
    client
        .instance()
        .set_captcha_config(json!({ "provider": "vercel_botid", "attestationUrl": "/api/botid" }))
        .await
        .unwrap();
    let body: Value =
        serde_json::from_str(fake.requests().last().unwrap().body.as_deref().unwrap()).unwrap();
    assert_eq!(
        body["auth_config"]["captcha"]["attestationUrl"],
        "/api/botid"
    );
    assert!(
        CAPTCHA_PROVIDERS.contains(&"captchafox") && CAPTCHA_PROVIDERS.contains(&"vercel_botid")
    );
    assert_eq!(LINKING_TRUST_LEVELS, &["always", "verified", "never"]);
}
