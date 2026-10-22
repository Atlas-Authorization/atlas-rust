//! Hermetic tests for the 0.15.0 additions: referral attribution settings,
//! the connection test and call log, the user referral fields and the fraud
//! flag, the `user.referral_attributed` event and the referral error codes.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    codes, types, BackendClient, BackendError, CreateUserBody, CreateUserReferral, EventType,
    FakeTransport, Query, UpdateUserBody, UserReferralAttributedEvent,
};
use atlasauth::{HttpMethod, HttpRequest, HttpResponse};

const SETTINGS: &str = r#"{"object":"referral_settings","enabled":true,"provider":"webhook","endpoint_url":"https://referrals.example.com/atlas","program_id":null,"connection_id":null,"signing_secret_set":true,"api_key_set":false,"url_params":["ref","via","aff"],"context_cookie":null,"consent_category":"referrals","consent_fallback_category":"marketing","auto_enroll_users":true,"link_template":"https://app.example.com/join?ref={code}","timeout_ms":3000,"security":{"challenge_referred_signups":"always","on_high_risk":"flag","hold_until_email_verified":false,"max_referred_signups_per_ip_hour":5},"missing":[],"connection":{"last_test":{"ok":true,"at":1,"http_status":404,"error":null},"failed_calls_7d":2,"retrying_calls":1,"last_success_at":1},"providers":[{"id":"webhook","name":"Atlas referral protocol (any platform)","capabilities":{"signup":true,"erase":true,"export":true,"partner":true,"auto_enroll":true,"signal":true},"needs":["endpoint_url","signing_secret"],"default_context_cookie":null,"docs_url":null}],"updated_at":1}"#;
const CALL: &str = r#"{"object":"referral_call","id":"rfc_1","kind":"signup","status":"succeeded","outcome":"referred","customer_ref":"user_1","user_id":"user_1","http_status":200,"last_error":null,"attempts":2,"next_attempt_at":null,"risk":{"level":"low","score":5,"signals":[],"captcha":"passed","emailVerified":true},"payload":{"customerRef":"user_1"},"created_at":1,"updated_at":2}"#;

fn client_with(body: &str) -> (BackendClient, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::json_ok(body));
    let client = BackendClient::builder("sk_test")
        .transport(transport.clone())
        .max_retries(0)
        .build()
        .unwrap();
    (client, transport)
}

fn path(req: &HttpRequest) -> String {
    req.url.replace("https://api.atlasauth.net", "")
}

fn body_json(req: &HttpRequest) -> Value {
    serde_json::from_str(req.body.as_deref().expect("a JSON body")).unwrap()
}

#[tokio::test]
async fn referral_settings_get_update_and_test() {
    let (c, t) = client_with(SETTINGS);
    let view = c.instance().get_referrals().await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(path(&req), "/v1/instance/referrals");
    assert!(view.enabled);
    let security = view.security.expect("security");
    assert_eq!(security.on_high_risk, "flag");
    assert_eq!(security.max_referred_signups_per_ip_hour, 5);
    let connection = view.connection.expect("connection");
    assert_eq!(connection.failed_calls_7d, Some(2));
    assert_eq!(
        connection.last_test.expect("last test").http_status,
        Some(404)
    );

    let body = types::InstanceUpdateReferralsBody::new()
        .with_enabled(true)
        .with_signing_secret("x".repeat(32))
        .with_security(types::InstanceUpdateReferralsBodySecurity::new().with_on_high_risk("hold"))
        .clear_link_template();
    c.instance()
        .update_referrals(&body, Some("idem_1"))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Patch);
    assert_eq!(
        body_json(&req),
        json!({ "enabled": true, "signing_secret": "x".repeat(32), "link_template": null, "security": { "on_high_risk": "hold" } })
    );

    let (c, t) = client_with(
        r#"{"ok":false,"http_status":401,"latency_ms":12,"error":{"code":"signature_rejected","message":"m"}}"#,
    );
    let test = c.instance().test_referrals().await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        (req.method, path(&req)),
        (HttpMethod::Post, "/v1/instance/referrals/test".to_string())
    );
    assert!(!test.ok);
    assert_eq!(
        test.error.expect("error").code.as_deref(),
        Some("signature_rejected")
    );
}

#[tokio::test]
async fn referral_call_log_and_retry() {
    let (c, t) = client_with(&format!(
        r#"{{"object":"list","data":[{CALL}],"has_more":false}}"#
    ));
    let q = Query::new()
        .set("limit", 10)
        .set("status", "failed")
        .set("kind", "signup")
        .set("user_id", "user_1");
    let page = c.instance().list_referral_calls(&q).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        path(&req),
        "/v1/instance/referrals/calls?limit=10&status=failed&kind=signup&user_id=user_1"
    );
    assert!(page.data[0].risk.as_ref().expect("risk").email_verified);

    let (c, t) = client_with(CALL);
    let call = c
        .instance()
        .retry_referral_call("rfc_1", Some("idem_2"))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        (req.method, path(&req)),
        (
            HttpMethod::Post,
            "/v1/instance/referrals/calls/rfc_1/retry".to_string()
        )
    );
    assert_eq!(call.outcome.as_deref(), Some("referred"));
}

#[tokio::test]
async fn user_referral_fields_create_update_and_flag() {
    let (c, t) = client_with(
        r#"{"object":"user","id":"user_1","referral":{"partner_id":"pn_1","referrer_external_id":"cust_9","referrer_user_id":"user_9","matched_via":"code","status":"lead","risk_level":"low","flagged":false},"referral_code":"ada-1","referral_link":"https://app.example.com/join?ref=ada-1"}"#,
    );
    let created = c
        .users()
        .create(
            &CreateUserBody {
                email_address: "a@example.com".into(),
                referral: Some(CreateUserReferral {
                    code: Some("ACME10".into()),
                    click_id: Some("clk_123".into()),
                    ..Default::default()
                }),
                referral_code: Some("ada-1".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(&t.requests().pop().unwrap()),
        json!({ "email_address": "a@example.com", "referral": { "code": "ACME10", "click_id": "clk_123" }, "referral_code": "ada-1" })
    );
    let referral = created.referral.expect("referral");
    assert_eq!(referral.referrer_user_id.as_deref(), Some("user_9"));
    assert_eq!(created.referral_code.as_deref(), Some("ada-1"));

    c.users()
        .update(
            "user_1",
            &UpdateUserBody {
                referral_code: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(&t.requests().pop().unwrap()),
        json!({ "referral_code": null })
    );

    let (c, t) = client_with(
        r#"{"object":"user_referral","user_id":"user_1","status":"flagged","flagged":true,"flag_reason":"ring","flagged_at":5,"risk_level":"high"}"#,
    );
    let flag = c
        .users()
        .flag_referral("user_1", Some("ring"), Some("idem_3"))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        (req.method, path(&req)),
        (
            HttpMethod::Post,
            "/v1/users/user_1/referral/flag".to_string()
        )
    );
    assert_eq!(body_json(&req), json!({ "reason": "ring" }));
    assert!(flag.flagged);
    assert_eq!(flag.flagged_at, Some(5));
    c.users().flag_referral("user_1", None, None).await.unwrap();
    assert_eq!(body_json(&t.requests().pop().unwrap()), json!({}));
}

#[tokio::test]
async fn referral_code_taken() {
    let transport = Arc::new(FakeTransport::new(|_| {
        HttpResponse {
        status: 409,
        body: r#"{"errors":[{"code":"REFERRAL_CODE_TAKEN","message":"taken","param":"referral_code"}]}"#.to_string(),
    }
    }));
    let c = BackendClient::builder("sk_test")
        .transport(transport)
        .max_retries(0)
        .build()
        .unwrap();
    let err = c
        .users()
        .update(
            "user_1",
            &UpdateUserBody {
                referral_code: Some(Some("ada-1".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    match err {
        BackendError::Api(api) => {
            assert_eq!(api.status, 409);
            assert_eq!(api.code(), Some(codes::REFERRAL_CODE_TAKEN));
        }
        other => panic!("expected an API error, got {other:?}"),
    }
    assert_eq!(codes::REFERRALS_NOT_CONFIGURED, "REFERRALS_NOT_CONFIGURED");
}

#[test]
fn referral_attributed_event_type_and_data() {
    assert_eq!(
        EventType::from("user.referral_attributed"),
        EventType::UserReferralAttributed
    );
    assert_eq!(
        EventType::UserReferralAttributed.as_str(),
        "user.referral_attributed"
    );
    let data: UserReferralAttributedEvent = serde_json::from_str(
        r#"{"object":"user_referral","user_id":"user_1","attribution_status":"attributed","referral":{"partner_id":"pn_1","referrer_external_id":null,"referrer_user_id":null,"matched_via":"click","status":"attributed","partner_external_ref":"usr_77","referral_status":"active","notes":["coupon matched"]},"referral_code":null,"referral_link":null,"signed_up_at":1,"updated_at":2}"#,
    )
    .unwrap();
    assert_eq!(data.attribution_status, "attributed");
    assert_eq!(
        data.referral.expect("referral").matched_via.as_deref(),
        Some("click")
    );
}

#[test]
fn referral_resolved_event_type() {
    assert_eq!(
        EventType::from("user.referral_resolved"),
        EventType::UserReferralResolved
    );
    assert_eq!(
        EventType::UserReferralResolved.as_str(),
        "user.referral_resolved"
    );
}

#[test]
fn user_referral_v2_fields_decode() {
    let r: atlasauth::backend::types::UserReferral = serde_json::from_str(
        r#"{"status":"pending","partner_id":null,"partner_external_ref":null,"referrer_external_id":null,"referrer_user_id":null,"matched_via":null,"referral_status":null,"notes":[]}"#,
    )
    .unwrap();
    assert_eq!(r.status, "pending");
    assert!(r.notes.is_empty());
}

#[tokio::test]
async fn referral_inbound_two_way_sync_fields() {
    let (c, t) = client_with(
        r#"{"object":"referral_settings","enabled":true,"provider":"webhook","signing_secret_set":true,"api_key_set":false,"url_params":["ref"],"inbound":{"url":"https://api.example.test/v1/webhooks/referrals/ins_1","secret_set":true,"endpoint_id":"we_1","last_event":{"at":1700000000000,"type":"referral.updated","outcome":"applied"}},"providers":[{"id":"webhook","name":"Atlas referral protocol","capabilities":{"signup":true,"erase":true,"export":true,"partner":true,"auto_enroll":true,"signal":true,"inbound":true},"needs":["endpoint_url","signing_secret"],"default_context_cookie":null,"docs_url":null}]}"#,
    );
    let view = c.instance().get_referrals().await.unwrap();
    let inbound = view.inbound.expect("inbound");
    assert_eq!(
        inbound.url.as_deref(),
        Some("https://api.example.test/v1/webhooks/referrals/ins_1")
    );
    assert_eq!(inbound.secret_set, Some(true));
    assert_eq!(inbound.endpoint_id.as_deref(), Some("we_1"));
    let last = inbound.last_event.expect("last event");
    assert_eq!(last.at, Some(1_700_000_000_000));
    assert_eq!(last.r#type.as_deref(), Some("referral.updated"));
    assert_eq!(last.outcome.as_deref(), Some("applied"));
    assert_eq!(
        view.providers[0].capabilities.as_ref().and_then(|c| c.inbound),
        Some(true)
    );

    let body = types::InstanceUpdateReferralsBody::new()
        .with_inbound_secret(format!("whsec_{}", "y".repeat(32)))
        .with_inbound_endpoint_id("we_1");
    c.instance().update_referrals(&body, None).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        body_json(&req),
        json!({ "inbound_secret": format!("whsec_{}", "y".repeat(32)), "inbound_endpoint_id": "we_1" })
    );

    let body = types::InstanceUpdateReferralsBody::new()
        .clear_inbound_secret()
        .clear_inbound_endpoint_id();
    c.instance().update_referrals(&body, None).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        body_json(&req),
        json!({ "inbound_secret": null, "inbound_endpoint_id": null })
    );
}

#[tokio::test]
async fn referral_browser_capture_fields() {
    let (c, t) = client_with(
        r#"{"object":"referral_settings","enabled":true,"provider":"dub","signing_secret_set":false,"api_key_set":true,"url_params":["ref"],"browser_sources":["rewardful","dub"],"browser_sources_default":false,"consent_provider":"onetrust","providers":[]}"#,
    );
    let view = c.instance().get_referrals().await.unwrap();
    assert_eq!(view.browser_sources, vec!["rewardful", "dub"]);
    assert_eq!(view.browser_sources_default, Some(false));
    assert_eq!(view.consent_provider.as_deref(), Some("onetrust"));

    let body = types::InstanceUpdateReferralsBody::new()
        .with_browser_sources(vec!["rewardful".to_string(), "dub".to_string()])
        .with_consent_provider("app");
    c.instance().update_referrals(&body, None).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(
        body_json(&req),
        json!({ "browser_sources": ["rewardful", "dub"], "consent_provider": "app" })
    );

    let body = types::InstanceUpdateReferralsBody::new().clear_browser_sources();
    c.instance().update_referrals(&body, None).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(body_json(&req), json!({ "browser_sources": null }));
}
