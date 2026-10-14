//! API key spend caps and usage metering, session keep-alive, `notify` on user
//! create, and the new webhook event types — over the in-memory fake transport.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{
    codes, types, BackendClient, BackendError, CreateApiKeyBody, CreateUserBody, EventType,
    FakeTransport, UpdateApiKeyBody,
};
use atlasauth::{HttpMethod, HttpResponse};
use serde_json::Value;

const STATE: &str = r#"{"unit":"usd_cents","period":"month","amount":5000,"used":12,"remaining":4988,"window_start":1790000000000,"resets_at":1792000000000}"#;
const COUNTER: &str = r#"{"unit":"usd_cents","period":"month","used":12,"window_start":1790000000000,"resets_at":1792000000000}"#;

fn client_with(body: String) -> (BackendClient, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::json_ok(&body));
    let client = BackendClient::builder("sk_test").transport(transport.clone()).build().unwrap();
    (client, transport)
}

fn body_json(t: &FakeTransport) -> Value {
    let reqs = t.requests();
    serde_json::from_str(reqs.last().unwrap().body.as_deref().expect("a body")).unwrap()
}

#[tokio::test]
async fn create_sends_limits_and_get_decodes_usage() {
    let (client, t) = client_with(format!(
        r#"{{"object":"api_key","id":"eak_1","secret":"ak_x","limits":[{{"unit":"usd_cents","amount":5000,"period":"month"}}],"usage":[{STATE}]}}"#
    ));
    let body = CreateApiKeyBody {
        subject_type: "user".into(),
        subject_id: "user_1".into(),
        limits: Some(vec![types::ApiKeyLimit::new("usd_cents", 5000, "month")]),
        ..Default::default()
    };
    client.api_keys().create(&body, None).await.unwrap();
    let req = t.requests().last().cloned().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert!(req.url.ends_with("/v1/api_keys"));
    assert_eq!(
        body_json(&t)["limits"],
        serde_json::json!([{ "unit": "usd_cents", "amount": 5000, "period": "month" }])
    );

    let key = client.api_keys().get("eak_1").await.unwrap();
    let limits = key.limits.expect("limits");
    assert_eq!(limits[0].amount, 5000);
    assert_eq!(key.usage[0].remaining, 4988);
    assert_eq!(key.usage[0].resets_at, Some(1_792_000_000_000));
}

#[test]
fn create_omits_unset_limits() {
    let body = CreateApiKeyBody { subject_type: "user".into(), subject_id: "u".into(), ..Default::default() };
    assert!(serde_json::to_value(&body).unwrap().get("limits").is_none());
}

#[tokio::test]
async fn update_clears_limits_with_null() {
    let (client, t) = client_with(r#"{"object":"api_key","id":"eak_1","limits":null,"usage":[]}"#.into());
    let body = UpdateApiKeyBody { limits: Some(None), ..Default::default() };
    let key = client.api_keys().update("eak_1", &body).await.unwrap();
    assert_eq!(t.requests().last().unwrap().method, HttpMethod::Patch);
    assert_eq!(body_json(&t), serde_json::json!({ "limits": null }));
    assert!(key.limits.is_none());
    assert!(key.usage.is_empty());
}

#[tokio::test]
async fn record_usage_allowed_and_refused() {
    let (client, t) = client_with(format!(
        r#"{{"object":"api_key_usage_debit","key_id":"eak_1","unit":"usd_cents","amount":12,"allowed":false,"code":"LIMIT_EXCEEDED","exceeded":[{STATE}],"usage":[{STATE}],"counters":[{COUNTER}],"idempotent_replay":false}}"#
    ));
    let body = types::ApiKeysRecordUsageBody::new(12, "usd_cents").with_idempotency_key("req_1");
    let out = client.api_keys().record_usage("eak_1", &body).await.unwrap();
    let req = t.requests().last().cloned().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert!(req.url.ends_with("/v1/api_keys/eak_1/usage"));
    assert_eq!(
        body_json(&t),
        serde_json::json!({ "amount": 12, "unit": "usd_cents", "idempotency_key": "req_1" })
    );
    assert!(!out.allowed);
    assert_eq!(out.code.as_deref(), Some(codes::LIMIT_EXCEEDED));
    assert_eq!(out.exceeded.len(), 1);
    assert_eq!(out.counters[0].window_start, 1_790_000_000_000);
}

#[tokio::test]
async fn record_usage_idempotency_conflict_is_an_error() {
    let transport = Arc::new(FakeTransport::new(|_req| HttpResponse {
        status: 409,
        body: r#"{"errors":[{"code":"IDEMPOTENCY_CONFLICT","message":"reused","param":"idempotency_key"}]}"#.into(),
    }));
    let client = BackendClient::builder("sk_test").transport(transport).base_delay_ms(0).build().unwrap();
    let body = types::ApiKeysRecordUsageBody::new(1, "requests").with_idempotency_key("k");
    match client.api_keys().record_usage("eak_1", &body).await.unwrap_err() {
        BackendError::Api(api) => {
            assert_eq!(api.status, 409);
            assert!(api.has_code(codes::IDEMPOTENCY_CONFLICT));
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[tokio::test]
async fn get_usage_decodes_caps_and_counters() {
    let (client, t) = client_with(format!(
        r#"{{"object":"api_key_usage","key_id":"eak_1","limits":[{{"unit":"usd_cents","amount":5000,"period":"month"}}],"usage":[{STATE}],"counters":[{COUNTER}]}}"#
    ));
    let out = client.api_keys().get_usage("eak_1").await.unwrap();
    let req = t.requests().last().cloned().unwrap();
    assert_eq!(req.method, HttpMethod::Get);
    assert!(req.url.ends_with("/v1/api_keys/eak_1/usage"));
    assert!(req.body.is_none());
    assert_eq!(out.key_id, "eak_1");
    assert_eq!(out.limits.unwrap()[0].period, "month");
    assert_eq!(out.usage[0].used, 12);
}

#[tokio::test]
async fn session_touch_and_idle_expires_at() {
    let (client, t) = client_with(
        r#"{"object":"session","id":"sess_1","user_id":"user_1","status":"active","last_active_organization_id":null,"impersonated_by":null,"last_active_at":1,"expire_at":3,"abandon_at":2,"idle_expires_at":2,"created_at":0,"extended":true}"#.into(),
    );
    let s = client.sessions().touch("sess_1").await.unwrap();
    let req = t.requests().last().cloned().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert!(req.url.ends_with("/v1/sessions/sess_1/touch"));
    assert!(req.body.is_none());
    assert!(s.extended);
    assert_eq!(s.idle_expires_at, 2);

    let got = client.sessions().get("sess_1").await.unwrap();
    assert_eq!(got.idle_expires_at, Some(2));
}

#[tokio::test]
async fn session_touch_on_an_ended_session_is_an_error() {
    let transport = Arc::new(FakeTransport::new(|_req| HttpResponse {
        status: 409,
        body: r#"{"errors":[{"code":"SESSION_IDLE_EXPIRED","message":"timed out"}]}"#.into(),
    }));
    let client = BackendClient::builder("sk_test").transport(transport).base_delay_ms(0).build().unwrap();
    match client.sessions().touch("sess_1").await.unwrap_err() {
        BackendError::Api(api) => assert!(api.has_code(codes::SESSION_IDLE_EXPIRED)),
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[tokio::test]
async fn user_create_and_import_send_notify() {
    let (client, t) = client_with(r#"{"object":"user","id":"user_1"}"#.into());
    let body = CreateUserBody { email_address: "a@b.test".into(), notify: Some(false), ..Default::default() };
    client.users().create(&body, None).await.unwrap();
    assert_eq!(body_json(&t), serde_json::json!({ "email_address": "a@b.test", "notify": false }));

    let unset = CreateUserBody { email_address: "a@b.test".into(), ..Default::default() };
    assert!(serde_json::to_value(&unset).unwrap().get("notify").is_none());

    let import = types::ImportExportImportUsersBody::new().with_notify(true);
    assert_eq!(serde_json::to_value(&import).unwrap()["notify"], true);
}

#[test]
fn new_webhook_event_types_round_trip() {
    for (wire, ty) in [
        ("api_key.created", EventType::ApiKeyCreated),
        ("api_key.updated", EventType::ApiKeyUpdated),
        ("api_key.revoked", EventType::ApiKeyRevoked),
        ("api_key.limit_reached", EventType::ApiKeyLimitReached),
        ("entitlement.override.created", EventType::EntitlementOverrideCreated),
        ("entitlement.override.deleted", EventType::EntitlementOverrideDeleted),
        ("entitlement.override.expired", EventType::EntitlementOverrideExpired),
    ] {
        assert_eq!(EventType::from(wire), ty);
        assert_eq!(ty.as_str(), wire);
    }
}

#[test]
fn verify_result_decodes_policy_and_usage() {
    let v: atlasauth::ApiKeyVerification = serde_json::from_str(&format!(
        r#"{{"object":"api_key_verification","valid":true,"id":"eak_1","subject_type":"user","subject_id":"user_1","name":"CI","claims":{{}},"scopes":["read"],"constraints":{{"ip":["10.0.0.0/8"]}},"limits":[{{"unit":"usd_cents","amount":5000,"period":"month"}}],"usage":[{STATE}],"last_used_at":null,"expires_at":null}}"#
    ))
    .unwrap();
    assert_eq!(v.name.as_deref(), Some("CI"));
    assert_eq!(v.scopes.as_deref(), Some(&["read".to_string()][..]));
    assert_eq!(v.limits.unwrap()[0].amount, 5000);
    assert_eq!(v.usage[0].remaining, 4988);

    let invalid: atlasauth::ApiKeyVerification =
        serde_json::from_str(r#"{"object":"api_key_verification","valid":false}"#).unwrap();
    assert!(!invalid.valid && invalid.limits.is_none() && invalid.usage.is_empty());
}
