//! Round-3 server surface (0.25): partner platforms, per-call audience,
//! orchestrator fields, `include_deleted`, operator audiences and the new error code.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{codes, BackendClient, FakeTransport, Query, StorePartnerPlatformTokenBody};
use atlasauth::HttpMethod;

const PLATFORM: &str = r#"{"object":"partner_platform","id":"pp_1","partner":"acme","name":"Acme","preset":false,
"platform_id":"plat_1","enabled":true,"jwks_url":"https://p.example/jwks","signature_header":"x-sig","signature_scheme":"t_kid_ed25519",
"tolerance_seconds":300,"allowed_sources":["a"],"record_consents":true,"receiver_url":"https://r.example","receiver_url_template":null,
"serves_deployment":false,"registration":{"status":"registered","registered_at":5},"token_set":true,"token_prefix":"pt_ab",
"last_delivery_at":null,"last_delivery_error":null,"created_at":1,"updated_at":2}"#;

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

fn body(fake: &FakeTransport, i: usize) -> Value {
    serde_json::from_str(fake.requests()[i].body.as_ref().unwrap()).unwrap()
}

#[tokio::test]
async fn partner_platform_routes() {
    let fake = FakeTransport::json_ok(&format!(r#"{{"object":"list","data":[{PLATFORM}],"has_more":false,"presets":[{{"id":"x"}}]}}"#));
    let c = client(&fake);
    let list = c.partner_platforms().list().await.unwrap();
    assert_eq!(list.data[0].partner, "acme");
    assert_eq!(list.presets.len(), 1);
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Get);
    assert!(reqs[0].url.ends_with("/v1/partner_platforms"));

    let fake = FakeTransport::json_ok(PLATFORM);
    let c = client(&fake);
    let p = c.partner_platforms().get("acme").await.unwrap();
    assert_eq!(p.registration.status, "registered");
    assert!(p.token_set);
    c.partner_platforms().set("acme", &json!({"jwks_url":"https://p.example/jwks","record_consents":true,"name":null})).await.unwrap();
    let reqs = fake.requests();
    assert_eq!(reqs[1].method, HttpMethod::Put);
    assert!(reqs[1].url.ends_with("/v1/partner_platforms/acme"));
    assert_eq!(body(&fake, 1), json!({"jwks_url":"https://p.example/jwks","record_consents":true,"name":null}));

    let fake = FakeTransport::json_ok(r#"{"object":"partner_platform","partner":"acme","deleted":true}"#);
    let c = client(&fake);
    assert!(c.partner_platforms().remove("acme").await.unwrap().deleted);
    assert_eq!(fake.requests()[0].method, HttpMethod::Delete);

    let fake = FakeTransport::json_ok(
        r#"{"object":"partner_platform_registration","partner":"acme","platform_id":"plat_1","receiver_url":"https://r","receiver_url_is_template":false,
"external_id":null,"events":["consent.recorded"],"signature":{"header":"h","scheme":"s","format":"f","jwks_url":"j","tolerance_seconds":300},
"send_to":{"contact":"c","docs":"d"},"token_prefix":null,"next_step":"n"}"#,
    );
    let c = client(&fake);
    let reg = c.partner_platforms().registration("acme").await.unwrap();
    assert!(fake.requests()[0].url.ends_with("/v1/partner_platforms/acme/registration"));
    assert_eq!(reg.signature.tolerance_seconds, 300);
    assert_eq!(reg.send_to.unwrap().contact, "c");

    let fake = FakeTransport::json_ok(
        r#"{"object":"list","data":[{"object":"partner_delivery","event_id":"e","event_type":"t","outcome":"recorded","user_id":"u","received_at":9}],"has_more":false}"#,
    );
    let c = client(&fake);
    let d = c.partner_platforms().deliveries("acme", Some(5)).await.unwrap();
    let url = fake.requests()[0].url.clone();
    assert!(url.contains("/v1/partner_platforms/acme/deliveries"));
    assert!(url.contains("limit=5"));
    assert_eq!(d.data[0].outcome, "recorded");
}

#[tokio::test]
async fn token_is_sent_but_never_in_a_response_model_or_debug() {
    let secret = "pt_live_SUPERSECRETVALUE";
    let fake = FakeTransport::json_ok(PLATFORM);
    let c = client(&fake);
    let b = StorePartnerPlatformTokenBody::new(secret).rotate(true).api_base_url("https://p.example");
    let p = c.partner_platforms().store_token("acme", &b).await.unwrap();
    let r = &fake.requests()[0];
    assert_eq!(r.method, HttpMethod::Post);
    assert!(r.url.ends_with("/v1/partner_platforms/acme/token"));
    assert_eq!(body(&fake, 0), json!({"token":secret,"rotate":true,"api_base_url":"https://p.example"}));
    assert!(!format!("{b:?}").contains(secret));
    assert!(!format!("{p:?}").contains(secret));
    assert_eq!(p.token_prefix.as_deref(), Some("pt_ab"));
}

#[tokio::test]
async fn per_call_audience_orchestrator_and_include_deleted() {
    let fake = FakeTransport::json_ok("{}");
    let c = client(&fake);
    c.instance()
        .set_integration("acme", &json!({"per_call_audience":{"param":"site","template":"acme:{site}","allowed":["s1"],"any_matching":false}}), None)
        .await
        .unwrap();
    c.instance().set_integration("acme", &json!({"per_call_audience":null}), None).await.unwrap();
    assert_eq!(body(&fake, 1), json!({"per_call_audience":null}));

    c.sessions().get_integration_token_for("sess_1", "acme", None, &[("site", "s1")]).await.unwrap();
    let url = fake.requests()[2].url.clone();
    assert!(url.contains("/v1/sessions/sess_1/integration_tokens/acme"));
    assert!(url.ends_with("?site=s1"));
    c.sessions().get_integration_token_for("sess_1", "acme", Some("acme:s2"), &[]).await.unwrap();
    assert!(fake.requests()[3].url.ends_with("?audience=acme%3As2"));
    c.sessions().get_integration_token("sess_1", "acme").await.unwrap();
    assert!(!fake.requests()[4].url.contains('?'));

    c.privacy()
        .set_orchestrator(&json!({"site_id":"s1","partner_link_id":"pl_1","cancel_deletion_on_sign_in":true}))
        .await
        .unwrap();
    assert_eq!(body(&fake, 5), json!({"site_id":"s1","partner_link_id":"pl_1","cancel_deletion_on_sign_in":true}));

    let fake = FakeTransport::json_ok(r#"{"object":"list","data":[],"has_more":false}"#);
    let c = client(&fake);
    c.users().list_query(&Query::new().set("include_deleted", true)).await.unwrap();
    assert!(fake.requests()[0].url.ends_with("?include_deleted=true"));
}

#[test]
fn operator_audiences_and_error_code() {
    let cfg: atlasauth::client::OperatorConfiguration =
        serde_json::from_str(r#"{"issuer":"i","audiences":["a"],"access_token_claims":["sub"]}"#).unwrap();
    assert_eq!(cfg.audiences, vec!["a".to_string()]);
    assert_eq!(cfg.access_token_claims, vec!["sub".to_string()]);
    assert_eq!(codes::MANAGED_WAF_NOT_CONFIGURED, "MANAGED_WAF_NOT_CONFIGURED");
}
