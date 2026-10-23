//! Policy acceptance: the catalog resources, the CSV export, the `pol` claim,
//! the webhook event types and the policy source helpers.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{types, BackendClient, EventType, FakeTransport, Query};
use atlasauth::{
    sign_policy_source_event, verify_policy_feed_request, Claims, HttpMethod, PolicyFeedFailure, PolicyFeedRequest,
    PolicySourceEvent,
};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

#[tokio::test]
async fn policies_and_versions_hit_the_documented_routes() {
    let fake = FakeTransport::json_ok(r#"{"object":"policy","id":"pol_1","key":"tos"}"#);
    let c = client(&fake);

    c.policies()
        .create(&types::PoliciesCreateBody::default())
        .await
        .unwrap();
    c.policies().get("tos").await.unwrap();
    c.policies()
        .create_version("tos", &types::PoliciesCreateVersionBody::default())
        .await
        .unwrap();
    let mut publish = types::PoliciesPublishVersionBody::default();
    publish.effective_at = Some(json!(1_760_000_000_000i64));
    c.policies().publish_version("tos", "2026-10-24", &publish).await.unwrap();
    c.policies().retire_version("tos", "2026-10-24").await.unwrap();
    c.policies().delete_version("tos", "polv_2").await.unwrap();
    c.policies()
        .list_acceptances("tos", &Query::new().set("version", "2026-10-24").set("status", "all"))
        .await
        .unwrap();

    let reqs = fake.requests();
    let seen: Vec<(HttpMethod, String)> = reqs.iter().map(|r| (r.method, r.url.clone())).collect();
    assert_eq!(seen[0].0, HttpMethod::Post);
    assert!(seen[0].1.ends_with("/v1/policies"));
    assert!(seen[1].1.ends_with("/v1/policies/tos"));
    assert!(seen[2].1.ends_with("/v1/policies/tos/versions"));
    assert!(seen[3].1.ends_with("/v1/policies/tos/versions/2026-10-24/publish"));
    assert!(seen[4].1.ends_with("/v1/policies/tos/versions/2026-10-24/retire"));
    assert_eq!(seen[5].0, HttpMethod::Delete);
    assert!(seen[6].1.contains("/v1/policies/tos/acceptances?"));
    assert!(seen[6].1.contains("version=2026-10-24") && seen[6].1.contains("status=all"));
    let body: Value = serde_json::from_str(reqs[3].body.as_deref().unwrap()).unwrap();
    assert_eq!(body["effective_at"], 1_760_000_000_000i64);
}

#[tokio::test]
async fn csv_export_sets_the_format() {
    let fake = FakeTransport::json_ok("user_id,policy\nuser_1,tos\n");
    let c = client(&fake);
    let csv = c
        .policies()
        .export_acceptances_csv("tos", &Query::new().set("status", "accepted").set("format", "jsonl"))
        .await
        .unwrap();
    assert!(csv.starts_with("user_id,policy"));
    let url = fake.requests().last().unwrap().url.clone();
    assert!(url.contains("format=csv") && !url.contains("jsonl") && url.contains("status=accepted"));
}

#[tokio::test]
async fn policy_source_and_settings_routes() {
    let fake = FakeTransport::json_ok(r#"{"object":"policy_source","enabled":true,"signing_secret_set":true}"#);
    let c = client(&fake);
    let mut body = types::InstanceSetPolicySourceBody::default();
    body.enabled = Some(true);
    body.endpoint_url = Some(Some("https://cms.example.com/atlas".into()));
    body.signing_secret = Some(Some("whsec_test_secret_0123456789".into()));
    body.sync = Some("webhook".into());
    c.instance().set_policy_source(&body).await.unwrap();
    c.instance().get_policy_source().await.unwrap();
    c.instance().test_policy_source().await.unwrap();
    c.instance().sync_policy_source().await.unwrap();
    c.instance().delete_policy_source().await.unwrap();
    c.instance().list_policy_source_deliveries(&Query::new().set("kind", "fetch")).await.unwrap();
    c.instance().get_policy_settings().await.unwrap();
    let mut settings = types::InstanceUpdatePolicySettingsBody::default();
    settings.session_claim = Some(true);
    c.instance().update_policy_settings(&settings).await.unwrap();
    c.users().get_policies("user_1", &Query::new()).await.unwrap();

    let reqs = fake.requests();
    let sent: Value = serde_json::from_str(reqs[0].body.as_deref().unwrap()).unwrap();
    assert_eq!(sent["signing_secret"], "whsec_test_secret_0123456789");
    assert_eq!(reqs[0].method, HttpMethod::Put);
    assert!(reqs[2].url.ends_with("/v1/instance/policy_source/test"));
    assert!(reqs[3].url.ends_with("/v1/instance/policy_source/sync"));
    assert_eq!(reqs[4].method, HttpMethod::Delete);
    assert!(reqs[5].url.contains("/v1/instance/policy_source/deliveries?kind=fetch"));
    assert_eq!(reqs[7].method, HttpMethod::Patch);
    assert!(reqs[8].url.ends_with("/v1/users/user_1/policies"));
}

#[test]
fn pol_claim_and_event_types() {
    let claims: Claims = serde_json::from_value(json!({
        "iss": "https://issuer.test", "sub": "user_1", "exp": 1,
        "pol": { "tos": "2026-10-24", "privacy": "v3" }
    }))
    .unwrap();
    assert_eq!(claims.pol().get("tos"), Some(&"2026-10-24"));
    assert!(claims.has_accepted_policy("privacy", "v3"));
    assert!(!claims.has_accepted_policy("privacy", "v2"));
    let none: Claims = serde_json::from_value(json!({ "iss": "i", "sub": "s", "exp": 1 })).unwrap();
    assert!(none.pol().is_empty());

    assert_eq!(EventType::from("user.policy_accepted"), EventType::UserPolicyAccepted);
    assert_eq!(EventType::from("policy.version_published"), EventType::PolicyVersionPublished);
    assert_eq!(EventType::UserPolicyAccepted.as_str(), "user.policy_accepted");
    assert_eq!(EventType::PolicyVersionPublished.as_str(), "policy.version_published");
}

#[test]
fn policy_source_round_trip() {
    let secret = "whsec_test_secret_0123456789";
    let signed = sign_policy_source_event(
        &PolicySourceEvent::Retired { key: "tos".into() },
        secret,
    );
    // The same MAC scheme verifies a feed request signed the same way (GET\n{path+query}).
    let probe = atlasauth::sign_policy_source_body("GET\n/atlas/policies?key=tos", secret, Some("msg_9"), Some(1_760_000_000_000));
    let sig = probe.headers.iter().find(|(k, _)| k == "atlas-signature").unwrap().1.clone();
    assert!(signed.body.contains("policy.retired"));
    let lookup = |n: &str| match n {
        "atlas-id" => Some("msg_9".to_string()),
        "atlas-timestamp" => Some("1760000000000".to_string()),
        "atlas-signature" => Some(sig.clone()),
        _ => None,
    };
    let ok = verify_policy_feed_request(&PolicyFeedRequest {
        method: Some("GET"),
        path_and_query: "/atlas/policies?key=tos",
        header: &lookup,
        secret,
        now_ms: Some(1_760_000_000_000),
        tolerance_ms: None,
    });
    // Signing `GET\n{path+query}` as the payload yields exactly the MAC Atlas puts on a feed request.
    assert_eq!(ok.unwrap().key.as_deref(), Some("tos"));
    let wrong = |n: &str| if n == "atlas-signature" { Some("v1,AAAA".to_string()) } else { lookup(n) };
    assert_eq!(
        verify_policy_feed_request(&PolicyFeedRequest {
            method: Some("GET"),
            path_and_query: "/atlas/policies?key=tos",
            header: &wrong,
            secret,
            now_ms: Some(1_760_000_000_000),
            tolerance_ms: None,
        })
        .unwrap_err(),
        PolicyFeedFailure::SignatureMismatch
    );
}
