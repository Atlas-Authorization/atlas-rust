//! Hermetic tests for the 2026-10-30 additions: application webhooks (app
//! events, the event catalog, organizations' app webhook endpoints), the
//! Standard Webhooks verifier, browser tickets, the test sign-in URL, Sign in
//! with Atlas, hosted pages, the privacy integration, and the new model fields.
#![cfg(feature = "backend")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use atlasauth::backend::{
    types, AppEventTypeBody, BackendClient, CreateSessionBody, FakeTransport, PublishAppEventBody,
    Query, UpdateHostedPagesBody, UpdateWebhookEndpointBody, User, Webhook, WebhookError,
    PERMISSION_ORG_WEBHOOKS_MANAGE,
};
use atlasauth::{ApiKeyVerification, HttpMethod, HttpRequest};

fn client_with(body: &str) -> (BackendClient, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::json_ok(body));
    let client = BackendClient::builder("sk_test")
        .transport(transport.clone())
        .max_retries(0)
        .build()
        .unwrap();
    (client, transport)
}

fn last(t: &FakeTransport) -> HttpRequest {
    t.requests().pop().unwrap()
}

fn route(req: &HttpRequest) -> (HttpMethod, String) {
    (
        req.method,
        req.url.replace("https://api.atlasauth.net", ""),
    )
}

fn body_json(req: &HttpRequest) -> Value {
    serde_json::from_str(req.body.as_deref().expect("a JSON body")).unwrap()
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

const EVENT: &str = r#"{"object":"app_event","id":"evt_1","type":"call.completed","organization_id":"org_1","data":{"call_id":"c1"},"idempotency_key":"c1","created_at":1,"idempotent_replay":false,"deliveries_queued":2,"endpoint_ids":["whep_1","whep_2"]}"#;

#[tokio::test]
async fn app_events_publish_list_get() {
    let (c, t) = client_with(EVENT);
    let ev = c
        .app_events()
        .publish(
            &PublishAppEventBody::new("org_1", "call.completed", json!({ "call_id": "c1" }))
                .with_idempotency_key("c1"),
            Some("idem_1"),
        )
        .await
        .unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/app_events".to_string()));
    assert_eq!(header(&req, "idempotency-key"), Some("idem_1"));
    assert_eq!(
        body_json(&req),
        json!({ "organization_id": "org_1", "type": "call.completed", "data": { "call_id": "c1" }, "idempotency_key": "c1" })
    );
    assert_eq!(ev.event_type, "call.completed");
    assert!(!ev.idempotent_replay);
    assert_eq!(ev.deliveries_queued, Some(2));
    assert_eq!(ev.endpoint_ids, vec!["whep_1", "whep_2"]);

    let (c, t) = client_with(&format!(r#"{{"object":"list","data":[{EVENT}],"has_more":false}}"#));
    let page = c
        .app_events()
        .list("org_1", &Query::new().set("type", "call.completed"))
        .await
        .unwrap();
    assert_eq!(page.data[0].id, "evt_1");
    assert_eq!(
        route(&last(&t)),
        (
            HttpMethod::Get,
            "/v1/app_events?organization_id=org_1&type=call.completed".to_string()
        )
    );

    let (c, t) = client_with(EVENT);
    c.app_events().get("evt_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, "/v1/app_events/evt_1".to_string()));
}

#[tokio::test]
async fn app_event_types_crud_by_id_or_name() {
    let aet = r#"{"object":"app_event_type","id":"aet_1","type":"call.completed","description":"d","schema":null,"deprecated":false,"created_at":1,"updated_at":2}"#;
    let (c, t) = client_with(aet);
    let types = c.app_events().types();
    let created = types
        .create(&AppEventTypeBody::new("call.completed").with_description("d"), None)
        .await
        .unwrap();
    assert_eq!(created.id, "aet_1");
    assert_eq!(created.schema, None);
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/app_event_types".to_string()));
    assert_eq!(body_json(&req), json!({ "type": "call.completed", "description": "d" }));

    types.get("call.completed").await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/app_event_types/call.completed".to_string())
    );
    types
        .update("aet_1", &AppEventTypeBody::default().with_deprecated(true))
        .await
        .unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Patch, "/v1/app_event_types/aet_1".to_string()));
    assert_eq!(body_json(&req), json!({ "deprecated": true }));
    types.delete("aet_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Delete, "/v1/app_event_types/aet_1".to_string()));
    types.list(&Query::new()).await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, "/v1/app_event_types".to_string()));
}

#[tokio::test]
async fn app_webhook_endpoints_routes() {
    let (c, t) = client_with(r#"{"object":"webhook_endpoint","id":"whep_1"}"#);
    let ep = c.app_events().endpoints();
    let base = "/v1/organizations/org_1/app_webhook_endpoints";

    ep.list("org_1", &Query::new()).await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, base.to_string()));
    ep.create(
        "org_1",
        &types_ext_create().with_url("https://hooks.example.com/a").with_active(false),
        Some("k"),
    )
    .await
    .unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, base.to_string()));
    assert_eq!(body_json(&req), json!({ "url": "https://hooks.example.com/a", "active": false }));
    ep.get("org_1", "whep_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, format!("{base}/whep_1")));
    ep.update("org_1", "whep_1", &Default::default()).await.unwrap();
    assert_eq!(route(&last(&t)).0, HttpMethod::Patch);
    ep.delete("org_1", "whep_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Delete, format!("{base}/whep_1")));
    ep.rotate_secret("org_1", "whep_1", None).await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Post, format!("{base}/whep_1/rotate_secret")));
    ep.reveal_secret("org_1", "whep_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Post, format!("{base}/whep_1/reveal_secret")));
    ep.test("org_1", "whep_1", Some("5s")).await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Post, format!("{base}/whep_1/test?wait=5s")));
    ep.deliveries("org_1", "whep_1", &Query::new()).await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, format!("{base}/whep_1/deliveries")));
    ep.redeliver("org_1", "whep_1", "whd_1", None).await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Post, format!("{base}/whep_1/deliveries/whd_1/redeliver"))
    );
    ep.replay("org_1", "whep_1", &json!({ "since": 1 }), None).await.unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, format!("{base}/whep_1/replay")));
    assert_eq!(body_json(&req), json!({ "since": 1 }));
    ep.app_event_types("org_1", &Query::new()).await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/organizations/org_1/app_event_types".to_string())
    );
    assert_eq!(PERMISSION_ORG_WEBHOOKS_MANAGE, "org:webhooks:manage");
}

fn types_ext_create() -> atlasauth::backend::types_ext::OrganizationsWebhookEndpointsCreateBody {
    atlasauth::backend::types_ext::OrganizationsWebhookEndpointsCreateBody::new()
}

#[tokio::test]
async fn browser_ticket_and_test_sign_in_url() {
    let ticket = r#"{"object":"browser_ticket","id":"sit_1","user_id":"user_1","ticket":"t","url":"https://app.example.com/?__atlas_ticket=t","redirect_url":"https://app.example.com/","expires_in":60,"expires_at":"2026-10-30T00:01:00Z"}"#;
    let (c, t) = client_with(ticket);
    let bt = c
        .sessions()
        .create_browser_ticket("user_1", Some("https://app.example.com/"), Some(60))
        .await
        .unwrap();
    assert_eq!(bt.object, "browser_ticket");
    assert_eq!(bt.url.as_deref(), Some("https://app.example.com/?__atlas_ticket=t"));
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/sessions".to_string()));
    assert_eq!(
        body_json(&req),
        json!({ "user_id": "user_1", "mode": "browser_ticket", "redirect_url": "https://app.example.com/", "expires_in_seconds": 60 })
    );

    c.sessions()
        .create_with(&CreateSessionBody {
            user_id: "user_1".into(),
            mode: Some("browser_ticket".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(body_json(&last(&t)), json!({ "user_id": "user_1", "mode": "browser_ticket" }));

    let (c, t) = client_with(
        r#"{"object":"testing_sign_in_url","id":"sit_2","user_id":"user_1","ticket":"t","url":"http://localhost:3000/?__atlas_ticket=t","redirect_url":"http://localhost:3000/","expires_in":60,"expires_at":"x"}"#,
    );
    let url = c
        .testing()
        .create_sign_in_url("user_1", "http://localhost:3000/", None)
        .await
        .unwrap();
    assert_eq!(url.object, "testing_sign_in_url");
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/testing/sign_in_url".to_string()));
    assert_eq!(
        body_json(&req),
        json!({ "user_id": "user_1", "redirect_url": "http://localhost:3000/" })
    );
}

#[tokio::test]
async fn sign_in_with_atlas_hosted_pages_privacy_integration() {
    let (c, t) = client_with(
        r#"{"object":"sign_in_with_atlas","enabled":true,"connection_id":"sso_1","managed_via":"linked","available":true,"candidates":[]}"#,
    );
    let s = c.instance().get_sign_in_with_atlas().await.unwrap();
    assert!(s.enabled);
    assert_eq!(s.managed_via.as_deref(), Some("linked"));
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/instance/sign_in_with_atlas".to_string())
    );
    c.instance().update_sign_in_with_atlas(false, None).await.unwrap();
    let req = last(&t);
    assert_eq!(req.method, HttpMethod::Patch);
    assert_eq!(body_json(&req), json!({ "enabled": false }));

    let (c, t) = client_with(
        r#"{"object":"hosted_pages","sign_in_url":"https://app.example.com/sign-in","sign_up_url":null,"user_url":null,"hosted":{"sign_in":"x"}}"#,
    );
    let h = c.instance().get_hosted_pages().await.unwrap();
    assert_eq!(h.sign_in_url.as_deref(), Some("https://app.example.com/sign-in"));
    c.instance()
        .update_hosted_pages(&UpdateHostedPagesBody {
            sign_in_url: Some(None),
            ..Default::default()
        })
        .await
        .unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Patch, "/v1/instance/hosted_pages".to_string()));
    assert_eq!(body_json(&req), json!({ "sign_in_url": null }));

    let (c, t) = client_with(r#"{"object":"privacy_integration","connected":true}"#);
    let v = c
        .privacy()
        .connect_integration(&json!({ "preset": "custom" }), Some("idem"))
        .await
        .unwrap();
    assert_eq!(v["connected"], json!(true));
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Post, "/v1/instance/privacy_integrations/connect".to_string())
    );
    c.privacy().get_integration().await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/instance/privacy_integrations".to_string())
    );
}

#[tokio::test]
async fn webhook_endpoint_created_switched_off() {
    let (c, t) = client_with(r#"{"id":"whep_1","url":"https://hooks.example.com/a"}"#);
    c.webhook_endpoints()
        .create_with(
            &UpdateWebhookEndpointBody {
                url: Some("https://hooks.example.com/a".into()),
                active: Some(false),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/webhook_endpoints".to_string()));
    assert_eq!(body_json(&req), json!({ "url": "https://hooks.example.com/a", "active": false }));
}

#[test]
fn new_model_fields_decode() {
    let user: User = serde_json::from_value(json!({
        "id": "user_1",
        "external_accounts": [{ "object": "external_account", "id": "eac_1", "provider": "google",
            "provider_user_id": "g1", "provider_email": "a@example.com", "email_verified": true,
            "image_url": "https://img.example.com/a.png", "connected_at": 5 }]
    }))
    .unwrap();
    assert_eq!(user.external_accounts[0].provider, "google");
    assert_eq!(user.external_accounts[0].connected_at, 5);

    let verdict: ApiKeyVerification = serde_json::from_value(json!({
        "valid": true, "scopes": ["calls:write"], "effective_scopes": ["calls:write", "calls:read"]
    }))
    .unwrap();
    assert_eq!(verdict.effective_scopes, vec!["calls:write", "calls:read"]);

    let me: types::ManagedEmail = serde_json::from_value(json!({
        "object": "managed_email", "feedback_webhook_id": "whep_9", "feedback_webhook_error": null,
        "dns": { "provider": "cloudflare", "status": "verifying", "attempts": 2, "next_check_at": 9 }
    }))
    .unwrap();
    assert_eq!(me.feedback_webhook_id.as_deref(), Some("whep_9"));
    let dns = me.dns.expect("dns");
    assert_eq!(dns.status.as_deref(), Some("verifying"));
    assert_eq!(dns.attempts, Some(2));

    let body = serde_json::to_value(atlasauth::backend::CreateUserBody {
        email_address: "a@example.com".into(),
        image_url: Some("https://img.example.com/a.png".into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(body["image_url"], json!("https://img.example.com/a.png"));
    assert!(body.get("profile_image_url").is_none());
}

// ── Standard Webhooks ──────────────────────────────────────────────────────

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const NOW_SEC: i64 = 1_800_000_000;
const BODY: &[u8] = br#"{"type":"call.completed","data":{"call_id":"c1"}}"#;

fn secret(key: &[u8]) -> String {
    format!("whsec_{}", STANDARD.encode(key))
}

fn sign(key: &[u8], id: &str, ts: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(format!("{id}.{ts}.").as_bytes());
    mac.update(body);
    format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
}

fn headers(id: &str, ts: i64, sig: &str) -> Vec<(String, String)> {
    vec![
        ("webhook-id".to_string(), id.to_string()),
        ("Webhook-Timestamp".to_string(), ts.to_string()),
        ("webhook-signature".to_string(), sig.to_string()),
    ]
}

fn verifier() -> Webhook {
    Webhook::new(secret(KEY)).now_ms(NOW_SEC * 1000)
}

#[test]
fn standard_webhook_good_signature() {
    let h = headers("evt_1", NOW_SEC, &sign(KEY, "evt_1", NOW_SEC, BODY));
    let d = verifier().verify_standard(BODY, &h).unwrap();
    assert_eq!(d.id, "evt_1");
    assert_eq!(d.timestamp, NOW_SEC);
    assert_eq!(d.payload["data"]["call_id"], json!("c1"));
}

#[test]
fn standard_webhook_rotated_multi_signature() {
    let old = b"an-old-secret-key-bytes-00000000";
    let sig = format!(
        "{} {}",
        sign(old, "evt_1", NOW_SEC, BODY),
        sign(KEY, "evt_1", NOW_SEC, BODY)
    );
    assert!(verifier().verify_standard(BODY, &headers("evt_1", NOW_SEC, &sig)).is_ok());
    // A receiver still holding only the old secret also verifies.
    let old_verifier = Webhook::new(secret(old)).now_ms(NOW_SEC * 1000);
    assert!(old_verifier.verify_standard(BODY, &headers("evt_1", NOW_SEC, &sig)).is_ok());
}

#[test]
fn standard_webhook_bad_signature() {
    let h = headers("evt_1", NOW_SEC, &sign(b"wrong-key", "evt_1", NOW_SEC, BODY));
    assert_eq!(
        verifier().verify_standard(BODY, &h).unwrap_err(),
        WebhookError::SignatureMismatch
    );
    // A tampered body fails too.
    let h = headers("evt_1", NOW_SEC, &sign(KEY, "evt_1", NOW_SEC, BODY));
    assert_eq!(
        verifier().verify_standard(b"{}", &h).unwrap_err(),
        WebhookError::SignatureMismatch
    );
    let h = headers("evt_1", NOW_SEC, "v1");
    assert_eq!(
        verifier().verify_standard(BODY, &h).unwrap_err(),
        WebhookError::MalformedSignature
    );
}

#[test]
fn standard_webhook_stale_timestamp() {
    let ts = NOW_SEC - 301;
    let h = headers("evt_1", ts, &sign(KEY, "evt_1", ts, BODY));
    assert_eq!(
        verifier().verify_standard(BODY, &h).unwrap_err(),
        WebhookError::StaleTimestamp
    );
    let ts = NOW_SEC + 301;
    let h = headers("evt_1", ts, &sign(KEY, "evt_1", ts, BODY));
    assert_eq!(
        verifier().verify_standard(BODY, &h).unwrap_err(),
        WebhookError::StaleTimestamp
    );
    // Milliseconds are not seconds.
    let ms = NOW_SEC * 1000;
    let h = headers("evt_1", ms, &sign(KEY, "evt_1", ms, BODY));
    assert_eq!(
        verifier().verify_standard(BODY, &h).unwrap_err(),
        WebhookError::StaleTimestamp
    );
}

#[test]
fn standard_webhook_missing_headers() {
    let full = headers("evt_1", NOW_SEC, &sign(KEY, "evt_1", NOW_SEC, BODY));
    for skip in 0..3 {
        let h: Vec<(String, String)> = full
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, p)| p.clone())
            .collect();
        assert_eq!(
            verifier().verify_standard(BODY, &h).unwrap_err(),
            WebhookError::MissingHeaders
        );
    }
}
