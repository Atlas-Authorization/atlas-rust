//! The typed catalog methods end to end: request structs serialize to the API's
//! JSON names (renames, `null` to clear, extra keys), and realistic responses
//! decode into typed structs through the client while unknown fields survive.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{types, BackendClient, FakeTransport, Query};
use atlasauth::{HttpMethod, HttpResponse};
use serde_json::{json, Value};

fn client_answering(body: &'static str) -> (BackendClient, FakeTransport) {
    let fake = FakeTransport::new(move |_| HttpResponse {
        status: 200,
        body: body.into(),
    });
    let c = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap();
    (c, fake)
}

fn sent_body(fake: &FakeTransport) -> Value {
    serde_json::from_str(fake.requests()[0].body.as_deref().unwrap()).unwrap()
}

#[tokio::test]
async fn nested_request_uses_the_wire_names() {
    let (c, fake) = client_answering(r#"{"object":"instance","id":"ins_1"}"#);
    let policy = types::InstanceUpdateBodyAuthConfigPasswordPolicy::new()
        .with_min_length(12)
        .with_require_number(true);
    let body = types::InstanceUpdateBody::new()
        .with_auth_config(types::InstanceUpdateBodyAuthConfig::new().with_password_policy(policy));
    c.instance().update(&body).await.unwrap();
    assert_eq!(
        sent_body(&fake),
        json!({"auth_config": {"passwordPolicy": {"minLength": 12, "requireNumber": true}}})
    );
}

#[tokio::test]
async fn unset_fields_are_omitted_and_clear_sends_null() {
    let (c, fake) = client_answering(r#"{"object":"billing_plan","id":"plan_1"}"#);
    let body = types::BillingUpdatePlanBody::new()
        .with_name("Pro")
        .clear_trial_days()
        .with_extra("added_later", json!({"x": 1}));
    c.billing().update_plan("plan_1", &body).await.unwrap();
    assert_eq!(
        sent_body(&fake),
        json!({"name": "Pro", "trial_days": null, "added_later": {"x": 1}})
    );
}

#[tokio::test]
async fn list_response_decodes_typed_items() {
    let (c, fake) = client_answering(
        r#"{"object":"list","data":[{"object":"data_subject_request","id":"dsr_1","type":"erasure",
            "status":"scheduled","user_id":"user_1","requested_by_type":"api","requested_by_id":null,
            "reason":null,"scheduled_for":1760000000000,"eta":1760000000000,"requested_at":1759000000000,
            "updated_at":1759000000000,"completed_at":null,"result":null,"subject_email":"a@b.co"}],
            "has_more":true,"next_cursor":"dsr_1"}"#,
    );
    let page = c
        .data_subject_requests()
        .list(&Query::new().set("limit", 1))
        .await
        .unwrap();
    assert_eq!(
        fake.requests()[0].url,
        "https://api.atlasauth.net/v1/data_subject_requests?limit=1"
    );
    assert!(page.has_more);
    assert_eq!(page.next_cursor.as_deref(), Some("dsr_1"));
    let dsr = &page.data[0];
    assert_eq!(dsr.r#type, "erasure");
    assert_eq!(dsr.status, "scheduled");
    assert_eq!(dsr.requested_by_id, None);
    assert_eq!(dsr.eta, Some(1_760_000_000_000));
    // A field newer than this crate is kept, not dropped.
    assert_eq!(dsr.extra.get("subject_email"), Some(&json!("a@b.co")));
}

#[tokio::test]
async fn absent_collections_read_as_empty() {
    let (c, _) = client_answering(r#"{"object":"list"}"#);
    let page = c.roles().list(&Query::new()).await.unwrap();
    assert!(page.data.is_empty());
}

#[tokio::test]
async fn fga_check_round_trip() {
    let (c, fake) = client_answering(
        r#"{"object":"fga_check","allowed":true,"authorization_model_id":"m_1","resolution_ms":3}"#,
    );
    let body = types::FgaCheckBody::new()
        .with_user("user:1")
        .with_relation("viewer")
        .with_object("doc:1");
    let res = c.fga().check("store_1", &body).await.unwrap();
    assert_eq!(
        sent_body(&fake),
        json!({"user": "user:1", "relation": "viewer", "object": "doc:1"})
    );
    assert!(res.allowed);
    assert_eq!(res.authorization_model_id, "m_1");
    assert_eq!(res.extra.get("resolution_ms"), Some(&json!(3)));
    assert_eq!(
        fake.requests()[0].url,
        "https://api.atlasauth.net/v1/fga/stores/store_1/check"
    );
}

#[tokio::test]
async fn no_content_route_returns_unit() {
    let fake = FakeTransport::new(|_| HttpResponse {
        status: 204,
        body: String::new(),
    });
    let c = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap();
    c.localizations().delete("loc_1").await.unwrap();
}

#[tokio::test]
async fn raw_json_escape_hatch() {
    let (c, fake) = client_answering(r#"{"object":"role","id":"role_1","brand_new":1}"#);
    let v = c
        .request_value(
            HttpMethod::Post,
            "/v1/roles",
            &[],
            Some(json!({"key": "editor", "name": "Editor"})),
        )
        .await
        .unwrap();
    assert_eq!(v["brand_new"], 1);
    assert_eq!(sent_body(&fake), json!({"key": "editor", "name": "Editor"}));
}
