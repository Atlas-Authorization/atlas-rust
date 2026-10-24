//! Hermetic tests for the integrator-platform surface (0.23): every new route's
//! method, path, query and body, plus the helpers (key formats, traceparent,
//! dry run, error codes, webhook v2 signatures, event aliases, privacy-call
//! verification, back-channel logout answers).
#![cfg(feature = "backend")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use atlasauth::backend::{
    canonical_webhook_event, is_deprecated_webhook_event, metadata_query, new_traceparent, parse_traceparent,
    traceparent_from_headers, verify_privacy_call, webhook_event_spellings, BackendClient, BackendError,
    CreateSecretKeyBody, EventType, FakeTransport, ProvisioningInput, Query, UpdateWebhookEndpointBody, Webhook,
    WebhookError, WEBHOOK_EVENT_ALIASES,
};
use atlasauth::{
    is_access_token, is_partner_link_secret, is_platform_key, is_publishable_key, is_secret_key, is_webhook_secret,
    parse_key_prefix, BackchannelLogoutResponse, HttpMethod, HttpResponse, KeyKind, VerifyError,
};

const BASE: &str = "https://api.atlasauth.net";

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

fn ok_fake() -> FakeTransport {
    FakeTransport::json_ok(r#"{"object":"x","data":[],"changes":[],"results":[]}"#)
}

fn m() -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("product".into(), json!("x"));
    map
}

// ── wire surface ───────────────────────────────────────────────────────────

#[tokio::test]
async fn suite_spec_wire_surface() {
    let fake = ok_fake();
    let c = client(&fake);
    let mut expect: Vec<(HttpMethod, String)> = Vec::new();
    macro_rules! want {
        ($m:expr, $p:expr) => {
            expect.push(($m, $p.to_string()))
        };
    }

    // credentials
    c.whoami().await.unwrap();
    want!(HttpMethod::Get, "/v1/whoami");
    c.secret_keys()
        .create(
            &CreateSecretKeyBody {
                name: Some("ci".into()),
                scopes: vec!["read_only".into()],
                key_format: Some("legacy".into()),
                ..Default::default()
            },
            Some("idem-1"),
        )
        .await
        .unwrap();
    want!(HttpMethod::Post, "/v1/secret_keys");
    c.secret_keys().list().await.unwrap();
    want!(HttpMethod::Get, "/v1/secret_keys");
    c.secret_keys().get("key_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/secret_keys/key_1");
    c.secret_keys().update("key_1", &json!({"name":"x","owner":null})).await.unwrap();
    want!(HttpMethod::Patch, "/v1/secret_keys/key_1");
    c.secret_keys().rotate("key_1", Some(0), None, None).await.unwrap();
    want!(HttpMethod::Post, "/v1/secret_keys/key_1/rotate");
    c.secret_keys().revoke("key_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/secret_keys/key_1/revoke");
    c.keys().list().await.unwrap();
    want!(HttpMethod::Get, "/v1/keys");
    c.partner_links().create(&json!({"partner":"cookiemunch","scopes":["privacy:execute"]}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/partner_links");
    c.partner_links().list().await.unwrap();
    want!(HttpMethod::Get, "/v1/partner_links");
    c.partner_links().get("pl_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/partner_links/pl_1");
    c.partner_links().rotate_secret("pl_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/partner_links/pl_1/rotate_secret");
    c.partner_links().revoke("pl_1").await.unwrap();
    want!(HttpMethod::Delete, "/v1/partner_links/pl_1");
    c.partner_links().outbound().list().await.unwrap();
    want!(HttpMethod::Get, "/v1/partner_links/outbound");
    c.partner_links().outbound().save("cookiemunch", &json!({"client_id":"cid","client_secret":"sec"})).await.unwrap();
    want!(HttpMethod::Put, "/v1/partner_links/outbound/cookiemunch");
    c.partner_links().outbound().test("cookiemunch").await.unwrap();
    want!(HttpMethod::Post, "/v1/partner_links/outbound/cookiemunch/test");
    c.partner_links().outbound().remove("cookiemunch").await.unwrap();
    want!(HttpMethod::Delete, "/v1/partner_links/outbound/cookiemunch");
    c.atlas_id_grants().list_apps().await.unwrap();
    want!(HttpMethod::Get, "/v1/atlas_id_apps");
    c.atlas_id_grants().lookup("app_1", "a@b.com").await.unwrap();
    want!(HttpMethod::Get, "/v1/atlas_id_apps/app_1/users?email=a%40b.com");
    c.atlas_id_grants().revoke("app_1", "g_1").await.unwrap();
    want!(HttpMethod::Delete, "/v1/atlas_id_apps/app_1/grants/g_1");

    // platform
    let p = c.platform();
    p.whoami().await.unwrap();
    want!(HttpMethod::Get, "/v1/platform/whoami");
    p.list_keys(&Query::new().set("kind", "secret_key").set("status", "active")).await.unwrap();
    want!(HttpMethod::Get, "/v1/platform/keys?kind=secret_key&status=active");
    p.create_key(&json!({"scopes":["apps:read"],"key_format":"atlas"}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/platform/keys");
    p.update_key("k_1", &json!({"name":"n"})).await.unwrap();
    want!(HttpMethod::Patch, "/v1/platform/keys/k_1");
    p.revoke_key("k_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/platform/keys/k_1/revoke");
    p.audit_logs(&Query::new().set("action", "app.created").set("limit", 5)).await.unwrap();
    want!(HttpMethod::Get, "/v1/platform/audit_logs?action=app.created&limit=5");
    p.list_audit_streams().await.unwrap();
    want!(HttpMethod::Get, "/v1/platform/audit_streams");
    p.create_audit_stream(&json!({"url":"https://x.example.com/a","format":"cloudevents"})).await.unwrap();
    want!(HttpMethod::Post, "/v1/platform/audit_streams");
    p.update_audit_stream("s_1", &json!({"active":true})).await.unwrap();
    want!(HttpMethod::Patch, "/v1/platform/audit_streams/s_1");
    p.delete_audit_stream("s_1").await.unwrap();
    want!(HttpMethod::Delete, "/v1/platform/audit_streams/s_1");
    p.test_audit_stream("s_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/platform/audit_streams/s_1/test");
    p.apps().list(&metadata_query(&m())).await.unwrap();
    want!(HttpMethod::Get, "/v1/platform/apps?metadata%5Bproduct%5D=x");
    p.apps().create_secret_key("app_1", &json!({"name":"ci","external_ref":"k-1"}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/platform/apps/app_1/secret_keys");
    let mut env = Map::new();
    env.insert("env".into(), json!("ci"));
    p.apps().secret_keys_with("app_1", &metadata_query(&env)).await.unwrap();
    want!(HttpMethod::Get, "/v1/platform/apps/app_1/secret_keys?metadata%5Benv%5D=ci");
    p.apps().clone_config("app_1", &json!({"dry_run":true,"to_environment":"development"}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/platform/apps/app_1/clone_config");
    p.apps().sandbox_teardown(Some(&{
        let mut s = Map::new();
        s.insert("sandbox".into(), json!(true));
        s
    }), true)
    .await
    .unwrap();
    want!(HttpMethod::Post, "/v1/platform/apps/bulk_delete");

    // webhooks and delivery health
    let w = c.webhook_endpoints();
    w.get("we_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/webhook_endpoints/we_1");
    w.list_with(&Query::new().set("include_deprecated", "true")).await.unwrap();
    want!(HttpMethod::Get, "/v1/webhook_endpoints?include_deprecated=true");
    w.upsert_by_url(&json!({"url":"https://app.example.com/hook","signature_versions":["v1","v2"]}), Some("i")).await.unwrap();
    want!(HttpMethod::Put, "/v1/webhook_endpoints/by_url");
    w.test_now("we_1", "5s").await.unwrap();
    want!(HttpMethod::Post, "/v1/webhook_endpoints/we_1/test?wait=5s");
    w.redeliver_window("we_1", &json!({"since":5,"status":"failed"}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/webhook_endpoints/we_1/redeliver");
    w.replay("we_1", &json!({"since":9,"event_type":"user.created"}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/webhook_endpoints/we_1/replay");
    w.deliveries_with("we_1", &Query::new().set("status", "failed").set("limit", 500).set("since", 1)).await.unwrap();
    want!(HttpMethod::Get, "/v1/webhook_endpoints/we_1/deliveries?status=failed&limit=500&since=1");
    c.delivery().egress_ips().await.unwrap();
    want!(HttpMethod::Get, "/v1/meta/egress_ips");
    c.delivery().health(&Query::new().set("kind", "webhook_endpoint").set("state", "unhealthy")).await.unwrap();
    want!(HttpMethod::Get, "/v1/delivery_health?kind=webhook_endpoint&state=unhealthy");
    c.delivery().set_alert_contacts("webhook_endpoint", "we_1", &["a@b.com".to_string()]).await.unwrap();
    want!(HttpMethod::Put, "/v1/delivery_health/webhook_endpoint/we_1/alert_contacts");

    // list variants
    c.users()
        .list_query(&Query::new().set("updated_after", 100).set("updated_before", 200).set("order_by", "-updated_at"))
        .await
        .unwrap();
    want!(HttpMethod::Get, "/v1/users?updated_after=100&updated_before=200&order_by=-updated_at");
    c.organizations()
        .memberships("org_1")
        .list_query(&Query::new().set("limit", 2).set("starting_after", "c"))
        .await
        .unwrap();
    want!(HttpMethod::Get, "/v1/organizations/org_1/memberships?limit=2&starting_after=c");
    c.api_keys().list_revoked_query(&Query::new().set("starting_after", "c")).await.unwrap();
    want!(HttpMethod::Get, "/v1/api_keys/revoked?starting_after=c");
    c.messaging_providers().channel("email").await.unwrap();
    want!(HttpMethod::Get, "/v1/messaging_providers/email");

    // privacy executor
    let pv = c.privacy();
    pv.discover().await.unwrap();
    want!(HttpMethod::Get, "/v1/privacy");
    pv.preset("cookiemunch").await.unwrap();
    want!(HttpMethod::Get, "/v1/privacy/presets/cookiemunch");
    pv.lookup(&json!({"atlas":{"iss":"https://i","sub":"u1"},"emails":["a@b.com"]})).await.unwrap();
    want!(HttpMethod::Post, "/v1/privacy/lookup");
    pv.create_request(&json!({"subjectId":"u1","type":"deletion","caseId":"c1"}), Some("k")).await.unwrap();
    want!(HttpMethod::Post, "/v1/privacy/requests");
    pv.get_request("pr_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/privacy/requests/pr_1");
    pv.cancel_request("pr_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/privacy/requests/pr_1/cancel");
    pv.get_orchestrator().await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/privacy_orchestrator");
    pv.set_orchestrator(&json!({"provider":"cookiemunch","sign_requests":true,"cancel_url":null})).await.unwrap();
    want!(HttpMethod::Put, "/v1/instance/privacy_orchestrator");
    pv.delete_orchestrator().await.unwrap();
    want!(HttpMethod::Delete, "/v1/instance/privacy_orchestrator");

    // integrations
    let i = c.instance();
    i.list_integrations().await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/integrations");
    i.get_integration("chatly").await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/integrations/chatly");
    i.set_integration("acme", &json!({"enabled":true,"events_url":null}), None).await.unwrap();
    want!(HttpMethod::Put, "/v1/instance/integrations/acme");
    i.delete_integration("acme").await.unwrap();
    want!(HttpMethod::Delete, "/v1/instance/integrations/acme");
    i.integration_deliveries("acme", &Query::new().set("kind", "event").set("trace", "t1")).await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/integrations/acme/deliveries?kind=event&trace=t1");
    i.reveal_integration_events_secret("acme").await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/integrations/acme/events_secret");
    i.integration_atlas_id_token("acme", "at").await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/integrations/acme/atlas_id_tokens");
    c.sessions().get_integration_token("sess_1", "chatly").await.unwrap();
    want!(HttpMethod::Post, "/v1/sessions/sess_1/integration_tokens/chatly");
    c.integrations().report_verify_error(&json!({"integration":"chatly","error":"expired"})).await.unwrap();
    want!(HttpMethod::Post, "/v1/integrations/verify_errors");
    c.integrations().card("chatly", "u1", Some("https://i")).await.unwrap();
    want!(HttpMethod::Get, "/v1/integrations/chatly/card?iss=https%3A%2F%2Fi&sub=u1");
    c.integrations().revoke_sessions("chatly", "u1", None, Some(&json!({"name":"Ann"}))).await.unwrap();
    want!(HttpMethod::Post, "/v1/integrations/chatly/card/actions/revoke_sessions");
    c.integrations().instance_metadata("ins_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/public/instances/ins_1");

    // entitlements, notices, advisories, sub-processors, audit exports
    c.entitlements().get("org", "org_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/entitlements?subject_id=org_1&subject_type=org");
    c.notices().list(true).await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/notices?all=true");
    c.notices().acknowledge("n_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/notices/n_1/acknowledge");
    c.security_advisories().list().await.unwrap();
    want!(HttpMethod::Get, "/v1/security_advisories");
    c.security_advisories().acknowledge("a_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/security_advisories/a_1/acknowledge");
    c.security_advisories().catalog().await.unwrap();
    want!(HttpMethod::Get, "/v1/public/security_advisories");
    c.sub_processors().get().await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/sub_processors");
    let ae = c.audit_exports();
    ae.list().await.unwrap();
    want!(HttpMethod::Get, "/v1/audit_exports");
    ae.get("ae_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/audit_exports/ae_1");
    ae.create(&json!({"name":"siem","type":"webhook","destination":{"url":"https://siem.example.com"}}), None).await.unwrap();
    want!(HttpMethod::Post, "/v1/audit_exports");
    ae.update("ae_1", &json!({"action_filter":null,"enabled":true})).await.unwrap();
    want!(HttpMethod::Patch, "/v1/audit_exports/ae_1");
    ae.delete("ae_1").await.unwrap();
    want!(HttpMethod::Delete, "/v1/audit_exports/ae_1");
    ae.test("ae_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/audit_exports/ae_1/test");
    ae.rotate_secret("ae_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/audit_exports/ae_1/rotate_secret");

    // status
    let st = c.status();
    st.service().await.unwrap();
    want!(HttpMethod::Get, "/v1/status");
    st.get_subscription().await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/status_subscription");
    st.update_subscription(&json!({"component_ids":[],"min_impact":"major"})).await.unwrap();
    want!(HttpMethod::Put, "/v1/instance/status_subscription");
    st.disable_subscription().await.unwrap();
    want!(HttpMethod::Delete, "/v1/instance/status_subscription");
    st.rotate_feed().await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/status_subscription/rotate_feed");
    st.list_incidents(&Query::new().set("limit", 3).set("open", "true")).await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/status_incidents?limit=3&open=true");
    st.list_dependencies().await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/status_dependencies");
    st.create_dependency(&json!({"name":"Stripe","url":"https://status.stripe.com"})).await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/status_dependencies");
    st.get_dependency("d_1").await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/status_dependencies/d_1");
    st.update_dependency("d_1", &json!({"enabled":true})).await.unwrap();
    want!(HttpMethod::Patch, "/v1/instance/status_dependencies/d_1");
    st.delete_dependency("d_1").await.unwrap();
    want!(HttpMethod::Delete, "/v1/instance/status_dependencies/d_1");
    st.refresh_dependency("d_1").await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/status_dependencies/d_1/refresh");

    // instance extras
    i.preflight_with(&Query::new().set("min_severity", "warning").set("include_suppressed", "true")).await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/preflight?min_severity=warning&include_suppressed=true");
    i.unknown_fields_report(Some(7)).await.unwrap();
    want!(HttpMethod::Get, "/v1/instance/unknown_fields_report?days=7");
    i.openapi_diff("2026-10-01", Some("bapi")).await.unwrap();
    want!(HttpMethod::Get, "/v1/openapi/diff?since=2026-10-01&surface=bapi");
    i.integration_health(&Query::new().set("only", "webhooks,email").set("probe", "false")).await.unwrap();
    want!(HttpMethod::Get, "/v1/integration-health?only=webhooks%2Cemail&probe=false");
    i.integration_health_providers().await.unwrap();
    want!(HttpMethod::Get, "/v1/integration-health/providers");
    i.embed(&Query::new().set("instance", "ins_1").set("origin", "https://app.example.com").set("shape", "button"))
        .await
        .unwrap();
    want!(HttpMethod::Get, "/v1/embed?instance=ins_1&origin=https%3A%2F%2Fapp.example.com&shape=button");
    c.design().import_brand_url("https://brand.example.com/tokens.json").await.unwrap();
    want!(HttpMethod::Put, "/v1/instance/design");
    c.design().remove_brand().await.unwrap();
    want!(HttpMethod::Put, "/v1/instance/design");
    i.install_referral("referalli", &json!({"return_to":"https://app.example.com/done"})).await.unwrap();
    want!(HttpMethod::Post, "/v1/instance/referrals/referalli/install");

    let reqs = fake.requests();
    assert_eq!(reqs.len(), expect.len());
    for (req, (method, path)) in reqs.iter().zip(expect.iter()) {
        assert_eq!(req.method, *method, "{path}");
        assert_eq!(req.url, format!("{BASE}{path}"));
    }

    // bodies of a few representative writes
    let body_of = |n: usize| -> Value { serde_json::from_str(reqs[n].body.as_deref().unwrap()).unwrap() };
    assert_eq!(body_of(1), json!({"name":"ci","scopes":["read_only"],"key_format":"legacy"}));
    assert!(reqs[1].headers.iter().any(|(k, v)| k == "idempotency-key" && v == "idem-1"));
    assert_eq!(body_of(4), json!({"name":"x","owner":null}));
    assert_eq!(body_of(5), json!({"overlap_seconds":0}));
}

#[tokio::test]
async fn bodies_for_the_composed_calls() {
    let fake = ok_fake();
    let c = client(&fake);
    let mut tags = Map::new();
    tags.insert("sandbox".into(), json!(true));
    c.platform().apps().sandbox_teardown(Some(&tags), true).await.unwrap();
    c.delivery().set_alert_contacts("webhook_endpoint", "we_1", &["a@b.com".to_string()]).await.unwrap();
    c.integrations().revoke_sessions("chatly", "u1", Some("https://i"), Some(&json!({"name":"Ann"}))).await.unwrap();
    c.instance().integration_atlas_id_token("acme", "at").await.unwrap();
    c.design().remove_brand().await.unwrap();
    c.design().import_brand_url("https://b.example.com/t.json").await.unwrap();
    let reqs = fake.requests();
    let body = |n: usize| -> Value { serde_json::from_str(reqs[n].body.as_deref().unwrap()).unwrap() };
    assert_eq!(body(0), json!({"dry_run":true,"metadata":{"sandbox":true}}));
    assert_eq!(body(1), json!({"alert_contacts":["a@b.com"]}));
    assert_eq!(body(2), json!({"sub":"u1","iss":"https://i","agent":{"name":"Ann"}}));
    assert_eq!(body(3), json!({"access_token":"at"}));
    assert_eq!(body(4), json!({"brand":null}));
    assert_eq!(body(5), json!({"brand_url":"https://b.example.com/t.json"}));
}

#[tokio::test]
async fn typed_responses_decode_and_keep_unknown_fields() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"secret_key","id":"key_1","kind":"secret_key","format":"atlas","prefix":"atlas_live_sk_4fGq","name":"ci","owner":null,"scopes":["read_only"],"environment":"live","resource":{"type":"instance","id":"ins_1"},"expires_at":null,"status":"active","ip_allowlist":[],"origin_allowlist":[],"created_at":1,"allowed_ips":["10.0.0.0/8"],"rotated_from":"key_0","sealed_secret":"AAAA","note":"n","replaces":"key_0","previous_key_expires_at":99,"brand_new_field":7}"#,
    );
    let k = client(&fake).secret_keys().get("key_1").await.unwrap();
    assert_eq!(k.id, "key_1");
    assert_eq!(k.format, "atlas");
    assert_eq!(k.resource["type"], "instance");
    assert_eq!(k.sealed_secret.as_deref(), Some("AAAA"));
    assert_eq!(k.previous_key_expires_at, Some(99));
    assert_eq!(k.allowed_ips, vec!["10.0.0.0/8".to_string()]);
    assert!(k.extra.contains_key("brand_new_field"));

    let fake = FakeTransport::json_ok(
        r#"{"object":"webhook_test","delivery_id":"d","event_id":"e","status":"success","http_status":200,"latency_ms":41,"response_snippet":"ok","error":null,"signature_header_sent":"v1,x v2,y","will_retry":false}"#,
    );
    let t = client(&fake).webhook_endpoints().test_now("we_1", "10s").await.unwrap();
    assert_eq!((t.status.as_str(), t.http_status, t.latency_ms), ("success", Some(200), Some(41)));

    let fake = FakeTransport::json_ok(
        r#"{"id":"we_1","url":"https://x/h","signature_versions":["v1","v2"],"event_naming":"canonical","consecutive_failures":3,"success_rate_24h":0.5,"alert_contacts":["a@b.com"],"destination":{"type":"https"},"idempotent_replay":true,"last_failure":{"at":1,"status":500,"error":null}}"#,
    );
    let e = client(&fake).webhook_endpoints().get("we_1").await.unwrap();
    assert_eq!(e.signature_versions, vec!["v1".to_string(), "v2".to_string()]);
    assert_eq!(e.consecutive_failures, Some(3));
    assert!(e.idempotent_replay);
    assert_eq!(e.alert_contacts, vec!["a@b.com".to_string()]);
}

#[tokio::test]
async fn update_webhook_body_carries_the_new_fields() {
    let fake = FakeTransport::json_ok(r#"{"id":"we_1"}"#);
    let body = UpdateWebhookEndpointBody {
        event_naming: Some("canonical".into()),
        signature_versions: Some(vec!["v2".into()]),
        destination: Some(json!({"type":"aws_eventbridge","region":"us-east-1","event_bus_name":"default"})),
        destination_credentials: Some(json!({"access_key_id":"a","secret_access_key":"b"})),
        ..Default::default()
    };
    client(&fake).webhook_endpoints().update("we_1", &body).await.unwrap();
    let sent: Value = serde_json::from_str(fake.requests()[0].body.as_deref().unwrap()).unwrap();
    assert_eq!(sent["event_naming"], "canonical");
    assert_eq!(sent["destination"]["type"], "aws_eventbridge");
    assert!(sent.get("url").is_none());
}

// ── dry run, traceparent, provisioning ─────────────────────────────────────

#[tokio::test]
async fn dry_run_adds_the_flag_and_drops_the_idempotency_key() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"dry_run","dry_run":true,"mode":"plan","validated":false,"method":"PATCH","path":"/v1/platform/apps/ins_1","changes":[{"section":"name","before":"A","after":"New"}],"note":"n"}"#,
    );
    let c = client(&fake);
    let plan = c
        .dry_run(HttpMethod::Patch, "/v1/platform/apps/ins_1", Some(json!({"name":"New"})))
        .await
        .unwrap();
    assert!(plan.dry_run);
    assert_eq!(plan.mode, "plan");
    assert_eq!(plan.changes[0].section, "name");

    // a write through a dry-run client keeps its other query and drops the key
    c.with_dry_run(true)
        .secret_keys()
        .create(&CreateSecretKeyBody { scopes: vec!["a".into()], ..Default::default() }, Some("idem"))
        .await
        .unwrap();
    // a read is never a dry run
    c.with_dry_run(true).secret_keys().list().await.unwrap();
    let reqs = fake.requests();
    assert!(reqs[0].url.ends_with("/v1/platform/apps/ins_1?dry_run=true"));
    assert!(reqs[1].url.ends_with("/v1/secret_keys?dry_run=true"));
    assert!(!reqs[1].headers.iter().any(|(k, _)| k == "idempotency-key"));
    assert!(reqs[2].url.ends_with("/v1/secret_keys"));
}

#[tokio::test]
async fn traceparent_and_secret_recipient_headers() {
    let fake = ok_fake();
    let tp = new_traceparent();
    let c = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .traceparent(tp.clone())
        .secret_recipient("x25519:AAAA")
        .max_retries(0)
        .build()
        .unwrap();
    c.whoami().await.unwrap();
    c.with_traceparent(None).whoami().await.unwrap();
    let reqs = fake.requests();
    let header = |n: usize, name: &str| reqs[n].headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    assert_eq!(header(0, "traceparent"), Some(tp.clone()));
    assert_eq!(header(0, "x-secret-recipient").as_deref(), Some("x25519:AAAA"));
    assert_eq!(header(1, "traceparent"), None);

    let (trace, span, flags) = parse_traceparent(&tp).unwrap();
    assert_eq!((trace.len(), span.len(), flags.as_str()), (32, 16, "01"));
    assert!(parse_traceparent("00-00000000000000000000000000000000-0000000000000000-01").is_none());
    assert!(parse_traceparent("nope").is_none());
    assert!(parse_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01").is_some());

    let headers: Vec<(String, String)> = vec![("Traceparent".into(), tp.clone())];
    assert_eq!(traceparent_from_headers(&headers), Some(tp));
    let bad: Vec<(String, String)> = vec![("traceparent".into(), "zzz".into())];
    assert_eq!(traceparent_from_headers(&bad), None);
}

#[test]
fn provisioning_input_merges_into_a_body() {
    let input = ProvisioningInput { metadata: Some(m()), external_ref: Some("ref-1".into()) };
    let body = input.apply(json!({"name":"A"}));
    assert_eq!(body, json!({"name":"A","metadata":{"product":"x"},"external_ref":"ref-1"}));
    let mut env = Map::new();
    env.insert("env".into(), json!("ci"));
    env.insert("a".into(), json!(true));
    let q = metadata_query(&env);
    assert_eq!(q.pairs()[0], ("metadata[a]".to_string(), "true".to_string()));
    assert_eq!(q.pairs()[1], ("metadata[env]".to_string(), "ci".to_string()));
}

// ── key formats, error codes ───────────────────────────────────────────────

#[test]
fn key_formats_accept_both_the_suite_and_the_legacy_prefixes() {
    assert!(is_secret_key("atlas_live_sk_abc123"));
    assert!(is_secret_key("atlas_test_sk_abc123"));
    assert!(is_secret_key("sk_live_abc"));
    assert!(is_secret_key("sk_test_abc"));
    assert!(!is_secret_key("sk_abc"));
    assert!(!is_secret_key("atlas_prod_sk_abc"));
    assert!(is_platform_key("atlas_live_psk_abc"));
    assert!(is_platform_key("psk_abc"));
    assert!(is_platform_key("psk_live_abc"));
    assert!(is_publishable_key("pk_live_abc"));
    assert!(!is_publishable_key("atlas_live_pk_abc"));
    assert!(is_webhook_secret("whsec_abc"));
    assert!(is_webhook_secret("atlas_live_whsec_abc"));
    assert!(is_partner_link_secret("atlas_live_pl_abc"));
    assert!(is_access_token("atlas_live_at_abc"));
    assert!(!is_access_token("sk_live_abc"));
    let p = parse_key_prefix("atlas_test_psk_zzz").unwrap();
    assert_eq!((p.kind, p.environment, p.suite), (KeyKind::Platform, Some("test"), true));
    let p = parse_key_prefix("sk_live_zzz").unwrap();
    assert_eq!((p.kind, p.environment, p.suite), (KeyKind::Secret, Some("live"), false));
    assert!(parse_key_prefix("").is_none());
    assert!(parse_key_prefix("hello").is_none());
    assert!(parse_key_prefix("atlas_live_sk").is_none());
}

#[tokio::test]
async fn new_error_codes_and_helpers() {
    let fake = FakeTransport::new(|req| {
        let body = if req.url.contains("/scope") {
            r#"{"errors":[{"code":"INSUFFICIENT_SCOPE","message":"no","meta":{"required_scope":"apps:write","legacy_code":"SCOPE_MISSING"}}]}"#
        } else if req.url.contains("/old") {
            r#"{"errors":[{"code":"SCOPE_MISSING","message":"no","meta":{"required_scope":"x"}}]}"#
        } else if req.url.contains("/step") {
            r#"{"errors":[{"code":"STEP_UP_REQUIRED","message":"mfa"}]}"#
        } else {
            r#"{"errors":[{"code":"ROUTE_NOT_FOUND","message":"nope","did_you_mean":["/v1/users"],"allowed_methods":["GET"],"docs_url":"https://atlasauth.net/errors/ROUTE_NOT_FOUND"}]}"#
        };
        HttpResponse { status: if req.url.contains("/route") { 404 } else { 403 }, body: body.into() }
    });
    let c = client(&fake);
    let err = |r: Result<Value, BackendError>| match r.unwrap_err() {
        BackendError::Api(e) => e,
        other => panic!("{other:?}"),
    };
    let e = err(c.request_value(HttpMethod::Get, "/v1/scope", &[], None).await);
    assert!(e.is_insufficient_scope());
    assert_eq!(e.required_scope().as_deref(), Some("apps:write"));
    let e = err(c.request_value(HttpMethod::Get, "/v1/old", &[], None).await);
    assert!(e.is_insufficient_scope());
    assert_eq!(e.required_scope().as_deref(), Some("x"));
    let e = err(c.request_value(HttpMethod::Get, "/v1/step", &[], None).await);
    assert!(e.is_step_up_required() && !e.is_insufficient_scope());
    let e = err(c.request_value(HttpMethod::Get, "/v1/route", &[], None).await);
    assert!(e.is_route_not_found() && e.is_not_found());
    assert_eq!(e.did_you_mean(), vec!["/v1/users".to_string()]);
    assert_eq!(e.errors[0].allowed_methods, vec!["GET".to_string()]);
    assert_eq!(e.errors[0].docs_url.as_deref(), Some("https://atlasauth.net/errors/ROUTE_NOT_FOUND"));
    assert_eq!(atlasauth::backend::codes::INSUFFICIENT_SCOPE, "INSUFFICIENT_SCOPE");
}

// ── webhooks: v2 signatures, aliases, new events ───────────────────────────

fn hmac_b64(secret: &str, parts: &[&[u8]]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    for p in parts {
        mac.update(p);
    }
    STANDARD.encode(mac.finalize().into_bytes())
}

#[test]
fn webhook_v2_signatures_bind_the_url() {
    let secret = "atlas_live_whsec_test";
    let url = "https://app.example.com/hook";
    let body = br#"{"id":"evt_1","type":"user.created","timestamp":1,"data":{}}"#;
    let ts = "1700000000000";
    let v1 = hmac_b64(secret, &[b"msg_1", b".", ts.as_bytes(), b".", body]);
    let v2 = hmac_b64(secret, &[b"msg_1", b".", ts.as_bytes(), b".", url.as_bytes(), b".", body]);
    let both = format!("v1,{v1} v2,{v2} v9,future");
    let headers: Vec<(String, String)> = vec![
        ("atlas-id".into(), "msg_1".into()),
        ("atlas-timestamp".into(), ts.into()),
        ("atlas-signature".into(), both),
    ];
    let hook = Webhook::new(secret).now_ms(1_700_000_000_000);
    let d = hook.verify_url(body, &headers, url, true).unwrap();
    assert_eq!(d.delivery_id, "msg_1");
    assert_eq!(d.event.event_type, EventType::UserCreated);
    // another URL fails v2 (and require_v2 refuses the v1 entry)
    assert_eq!(hook.verify_url(body, &headers, "https://evil.example.com/hook", true).unwrap_err(), WebhookError::SignatureMismatch);
    // a v1-only delivery passes without require_v2 but not with it
    let v1_only: Vec<(String, String)> = vec![
        ("atlas-id".into(), "msg_1".into()),
        ("atlas-timestamp".into(), ts.into()),
        ("atlas-signature".into(), format!("v1,{v1}")),
    ];
    assert!(hook.verify_url(body, &v1_only, url, false).is_ok());
    assert_eq!(hook.verify_url(body, &v1_only, url, true).unwrap_err(), WebhookError::MalformedSignature);
    // plain verify still works on the v1 entry of the same header
    assert!(hook.verify(body, &headers).is_ok());
    // stale
    assert_eq!(
        Webhook::new(secret).now_ms(1_800_000_000_000).verify_url(body, &headers, url, true).unwrap_err(),
        WebhookError::StaleTimestamp
    );
}

#[test]
fn event_aliases_and_new_event_types() {
    assert!(is_deprecated_webhook_event("organizationMembership.created"));
    assert!(!is_deprecated_webhook_event("organization_membership.created"));
    assert_eq!(canonical_webhook_event("billing.subscription.created"), "billing_subscription.created");
    assert_eq!(canonical_webhook_event("user.created"), "user.created");
    assert_eq!(canonical_webhook_event("user.deletion_cancelled"), "user.deletion_canceled");
    let spellings = webhook_event_spellings("organization.membership.deleted");
    assert_eq!(spellings[0], "organization_membership.deleted");
    assert!(spellings.contains(&"organizationMembership.deleted".to_string()));
    assert!(spellings.contains(&"organization.membership.deleted".to_string()));
    assert!(WEBHOOK_EVENT_ALIASES.len() > 30);
    for name in [
        "webhook_endpoint.failing",
        "webhook_endpoint.disabled",
        "webhook_endpoint.recovered",
        "delivery_target.failing",
        "delivery_target.disabled",
        "delivery_target.recovered",
        "webhook.test",
        "secret_key.expiring",
        "secret_key.revoked",
        "privacy_request.updated",
        "privacy_request.completed",
        "user.deletion_scheduled",
        "user.deletion_canceled",
    ] {
        let t = EventType::from(name);
        assert!(!matches!(t, EventType::Other(_)), "{name}");
        assert_eq!(t.as_str(), name);
    }
}

#[test]
fn privacy_calls_verify_and_carry_the_traceparent() {
    let secret = "whsec_privacy";
    let ts = "1700000000000";
    let case = br#"{"subjectId":"u1","type":"deletion","caseId":"c1"}"#;
    let sig = hmac_b64(secret, &[b"msg_9", b".", ts.as_bytes(), b".", case]);
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let headers: Vec<(String, String)> = vec![
        ("atlas-id".into(), "msg_9".into()),
        ("atlas-timestamp".into(), ts.into()),
        ("atlas-signature".into(), format!("v1,{sig}")),
        ("traceparent".into(), tp.into()),
    ];
    // verify_privacy_call uses the wall clock: use a fresh timestamp
    let fresh = now_ms().to_string();
    let sig_fresh = hmac_b64(secret, &[b"msg_9", b".", fresh.as_bytes(), b".", case]);
    let headers_fresh: Vec<(String, String)> = vec![
        ("atlas-id".into(), "msg_9".into()),
        ("atlas-timestamp".into(), fresh),
        ("atlas-signature".into(), format!("v1,{sig_fresh}")),
        ("traceparent".into(), tp.into()),
    ];
    let call = verify_privacy_call(secret, case, &headers_fresh).unwrap();
    assert_eq!(call.delivery_id, "msg_9");
    assert_eq!(call.traceparent.as_deref(), Some(tp));
    assert!(call.event.is_none());
    assert_eq!(call.body, case.to_vec());
    // the same call with a stale timestamp is refused
    assert_eq!(verify_privacy_call(secret, case, &headers).unwrap_err(), WebhookError::StaleTimestamp);

    let ev = br#"{"id":"evt_2","type":"privacy_request.completed","timestamp":1,"data":{"id":"pr_1","status":"completed","subjectId":"u1","type":"deletion"}}"#;
    let fresh = now_ms().to_string();
    let sig = hmac_b64(secret, &[b"msg_10", b".", fresh.as_bytes(), b".", ev]);
    let h: Vec<(String, String)> = vec![
        ("atlas-id".into(), "msg_10".into()),
        ("atlas-timestamp".into(), fresh),
        ("atlas-signature".into(), format!("v1,{sig}")),
    ];
    let call = verify_privacy_call(secret, ev, &h).unwrap();
    let event = call.event.unwrap();
    assert_eq!(event.event_type, EventType::PrivacyRequestCompleted);
    let req = atlasauth::backend::privacy_request_from_event(&event).unwrap();
    assert_eq!((req.id.as_str(), req.status.as_str(), req.subject_id.as_str()), ("pr_1", "completed", "u1"));
    assert!(call.traceparent.is_none());
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

#[test]
fn backchannel_logout_answers() {
    let ok = BackchannelLogoutResponse::from_result(&Ok(atlasauth::LogoutTokenClaims {
        sub: Some("u".into()),
        sid: None,
        jti: "j".into(),
        iat: 1,
    }));
    assert_eq!((ok.status, ok.retry_after_seconds), (200, None));
    let retry = BackchannelLogoutResponse::from_result(&Err(VerifyError::NoKeys));
    assert_eq!(retry.status, 503);
    assert!(retry.retry_after_seconds.is_some());
    assert_eq!(BackchannelLogoutResponse::from_result(&Err(VerifyError::Invalid)).status, 400);
    assert_eq!(BackchannelLogoutResponse::from_result(&Err(VerifyError::Malformed)).status, 400);
}
