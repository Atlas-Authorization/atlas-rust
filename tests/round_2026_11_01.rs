//! Hermetic tests for the 2026-11-01 additions: trusted-JWT connections,
//! organization create fields / filters / by-domain / policy / domain
//! verification methods, path mounts, webhook endpoint secrets and test
//! results, new webhook events, imported password hashes, the platform
//! initial-secret reveal and cookie-consent host aliases.
#![cfg(feature = "backend")]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    metadata_query, BackendClient, CreateOrganizationBody, CreateUserBody, EventType, FakeTransport,
    JwtConnectionBody, RotateWebhookSecretBody, UpdateOrganizationBody, UpdateWebhookEndpointBody,
    UserReferralAttributedEvent, WebhookTestResult,
};
use atlasauth::{HttpMethod, HttpRequest};

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
    (req.method, req.url.replace("https://api.atlasauth.net", ""))
}

fn body_json(req: &HttpRequest) -> Value {
    serde_json::from_str(req.body.as_deref().expect("a JSON body")).unwrap()
}

// ── trusted-JWT connections ────────────────────────────────────────────────

const JWT_CONN: &str = r#"{"object":"jwt_connection","id":"jwtc_1","organization_id":"org_1","status":"active","jwks_uri":"https://acme.example.com/jwks.json","issuer":"https://acme.example.com","audience":"atlas","email_claim":"email","max_age_seconds":300,"default_role_id":null,"login_url":"https://acme-fapi.atlasauth.net/v1/jwt_connections/jwtc_1/login","created_at":1,"updated_at":2}"#;

#[tokio::test]
async fn jwt_connections_crud() {
    let (c, t) = client_with(JWT_CONN);
    let body = JwtConnectionBody {
        organization_id: Some(Some("org_1".into())),
        status: Some("active".into()),
        jwks_uri: Some("https://acme.example.com/jwks.json".into()),
        default_role_id: Some(None),
        ..Default::default()
    };
    let conn = c.jwt_connections().create(&body, Some("idem_1")).await.unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/jwt_connections".to_string()));
    assert_eq!(
        body_json(&req),
        json!({ "organization_id": "org_1", "status": "active", "jwks_uri": "https://acme.example.com/jwks.json", "default_role_id": null })
    );
    assert_eq!(conn.id, "jwtc_1");
    assert_eq!(conn.max_age_seconds, 300);
    assert!(conn.login_url.ends_with("/login"));
    assert_eq!(conn.default_role_id, None);

    c.jwt_connections().get("jwtc_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, "/v1/jwt_connections/jwtc_1".to_string()));

    let patch = JwtConnectionBody { max_age_seconds: Some(60), ..Default::default() };
    c.jwt_connections().update("jwtc_1", &patch).await.unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Patch, "/v1/jwt_connections/jwtc_1".to_string()));
    assert_eq!(body_json(&req), json!({ "max_age_seconds": 60 }));

    let (c, t) = client_with(&format!(r#"{{"object":"list","data":[{JWT_CONN}],"has_more":false}}"#));
    let page = c.jwt_connections().list().await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, "/v1/jwt_connections".to_string()));
    assert_eq!(page.data.len(), 1);

    let (c, t) = client_with(r#"{"object":"jwt_connection","id":"jwtc_1","deleted":true}"#);
    let gone = c.jwt_connections().delete("jwtc_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Delete, "/v1/jwt_connections/jwtc_1".to_string()));
    assert!(gone.deleted);
}

// ── organizations ──────────────────────────────────────────────────────────

const ORG: &str = r#"{"object":"organization","id":"org_1","name":"Acme","slug":"acme","created_by":null,"external_id":"acme-1","role_mappings":{"org:admin":"owner"},"owner_invitation":{"object":"organization_invitation","id":"orginv_1","email":"it@acme.example.com","role":"org:admin","status":"pending","expires_at":5},"sso":{"connections":[{"id":"sso_1","type":"saml","status":"active"}],"scim_base_url":"https://acme-fapi.atlasauth.net/scim/v2/org_1"},"domain":{"object":"org_domain","id":"orgdom_1","domain":"acme.example.com","status":"verified","verified_at":7}}"#;

#[tokio::test]
async fn organization_create_fields_and_new_model() {
    let (c, t) = client_with(ORG);
    let mut mappings = HashMap::new();
    mappings.insert("org:admin".to_string(), "owner".to_string());
    let org = c
        .organizations()
        .create(
            &CreateOrganizationBody {
                name: "Acme".into(),
                slug: "acme".into(),
                external_id: Some("acme-1".into()),
                owner_email: Some("it@acme.example.com".into()),
                role_mappings: Some(mappings),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let body = body_json(&last(&t));
    assert!(body.get("created_by").is_none(), "an empty created_by is not sent");
    assert_eq!(body["external_id"], json!("acme-1"));
    assert_eq!(body["owner_email"], json!("it@acme.example.com"));
    assert_eq!(body["role_mappings"], json!({ "org:admin": "owner" }));

    assert_eq!(org.created_by, None);
    assert_eq!(org.external_id.as_deref(), Some("acme-1"));
    assert_eq!(org.role_mappings.as_ref().unwrap()["org:admin"], "owner");
    assert_eq!(org.owner_invitation.as_ref().unwrap().email, "it@acme.example.com");
    let sso = org.sso.as_ref().unwrap();
    assert_eq!(sso.connections[0].connection_type, "saml");
    assert!(sso.scim_base_url.ends_with("/org_1"));
    assert_eq!(org.domain.as_ref().unwrap().verified_at, Some(7));

    c.organizations()
        .update(
            "org_1",
            &UpdateOrganizationBody { external_id: Some(None), role_mappings: Some(None), ..Default::default() },
        )
        .await
        .unwrap();
    assert_eq!(body_json(&last(&t)), json!({ "external_id": null, "role_mappings": null }));
}

#[tokio::test]
async fn organization_filters_by_domain_and_policy() {
    let (c, t) = client_with(r#"{"object":"list","data":[],"has_more":false}"#);
    let mut filter = serde_json::Map::new();
    filter.insert("plan".into(), json!("pro"));
    c.organizations()
        .list_with(&metadata_query(&filter).set("external_id", "acme-1"))
        .await
        .unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/organizations?metadata%5Bplan%5D=pro&external_id=acme-1".to_string())
    );

    let (c, t) = client_with(ORG);
    let org = c.organizations().find_by_domain("acme.example.com", true).await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/organizations/by_domain/acme.example.com?include_unverified=true".to_string())
    );
    assert_eq!(org.domain.unwrap().status, "verified");
    c.organizations().find_by_domain("ada@acme.example.com", false).await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Get, "/v1/organizations/by_domain/ada%40acme.example.com".to_string())
    );

    let (c, t) = client_with(r#"{"organization_id":"org_1","policy":{"requireMfa":true}}"#);
    let policy = c.organizations().get_policy("org_1").await.unwrap();
    assert_eq!(route(&last(&t)), (HttpMethod::Get, "/v1/organizations/org_1/policy".to_string()));
    assert_eq!(policy.typed().unwrap().require_mfa, Some(true));
}

#[tokio::test]
async fn org_domain_verification_methods() {
    let domain = r#"{"object":"org_domain","id":"orgdom_1","organization_id":"org_1","domain":"acme.example.com","status":"pending","auto_join":false,"verification_methods":{"dns_txt":{"record_name":"_atlas.acme.example.com","record_type":"TXT","record_value":"v"},"well_known":{"url":"https://acme.example.com/.well-known/atlas-domain-verification.txt","body":"b","content_type":"text/plain"},"email":{"addresses":["admin@acme.example.com"],"sent_to":"admin@acme.example.com","expires_at":9}},"verification_method":"email","verified_at":null,"sent_to":"admin@acme.example.com"}"#;
    let (c, t) = client_with(domain);
    let d = c.organizations().domains("org_1").send_verification_email("orgdom_1", Some("admin")).await.unwrap();
    let req = last(&t);
    assert_eq!(
        route(&req),
        (HttpMethod::Post, "/v1/organizations/org_1/domains/orgdom_1/verification_email".to_string())
    );
    assert_eq!(body_json(&req), json!({ "address": "admin" }));
    assert_eq!(d.sent_to.as_deref(), Some("admin@acme.example.com"));
    let methods = d.verification_methods.unwrap();
    assert_eq!(methods.dns_txt.unwrap().record_type, "TXT");
    assert_eq!(methods.well_known.unwrap().content_type, "text/plain");
    assert_eq!(methods.email.unwrap().expires_at, Some(9));
    assert_eq!(d.verification_method.as_deref(), Some("email"));

    c.organizations().domains("org_1").verify_with("orgdom_1", "email", Some("123456")).await.unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/organizations/org_1/domains/orgdom_1/verify".to_string()));
    assert_eq!(body_json(&req), json!({ "method": "email", "code": "123456" }));

    // The plain verify still sends no body (the DNS check).
    c.organizations().domains("org_1").verify("orgdom_1").await.unwrap();
    assert!(last(&t).body.is_none());
}

// ── path mounts ────────────────────────────────────────────────────────────

#[tokio::test]
async fn domains_create_path_mount() {
    let (c, t) = client_with(
        r#"{"object":"custom_domain","id":"dom_1","role":"fapi","host":"app.example.com","status":"pending","live":false,"method":"path","cname_target":null,"base_path":"/__atlas","routing":null,"frontend_api_url":"https://app.example.com/__atlas","verification":{"method":"https_file","url":"https://app.example.com/__atlas/.well-known/atlas-domain.txt","token":"tok","content":"c","instructions":"Publish it."}}"#,
    );
    let d = c.domains().create_path_mount("app.example.com", None, Some("idem_1")).await.unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/domains".to_string()));
    assert_eq!(body_json(&req), json!({ "method": "path", "hostname": "app.example.com" }));
    assert_eq!(d.method.as_deref(), Some("path"));
    assert_eq!(d.cname_target, None);
    assert_eq!(d.base_path.as_deref(), Some("/__atlas"));
    assert_eq!(d.frontend_api_url.as_deref(), Some("https://app.example.com/__atlas"));
    assert_eq!(d.verification.unwrap().method, "https_file");
}

// ── webhook endpoints ──────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_endpoint_secrets_and_test_result() {
    let (c, t) = client_with(r#"{"id":"we_1","url":"https://acme.example.com/hook","secret":"whsec_x"}"#);
    let secret = format!("whsec_{}", "a".repeat(32));
    c.webhook_endpoints()
        .create_with(
            &UpdateWebhookEndpointBody {
                url: Some("https://acme.example.com/hook".into()),
                active: Some(false),
                secret: Some(secret.clone()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(&last(&t)),
        json!({ "url": "https://acme.example.com/hook", "active": false, "secret": secret })
    );

    c.webhook_endpoints()
        .rotate_secret_with("we_1", &RotateWebhookSecretBody::new().with_secret(secret.clone()))
        .await
        .unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Post, "/v1/webhook_endpoints/we_1/rotate_secret".to_string()));
    assert_eq!(body_json(&req), json!({ "secret": secret }));

    let r: WebhookTestResult = serde_json::from_value(json!({
        "delivery_id": "whd_1", "event_id": "evt_1", "event_type": "webhook.test", "status": "failed",
        "http_status": null, "error": "timed out", "error_kind": "timeout", "will_retry": false
    }))
    .unwrap();
    assert_eq!(r.event_type, "webhook.test");
    assert_eq!(r.error_kind.as_deref(), Some("timeout"));
}

#[test]
fn new_webhook_event_types_round_trip() {
    for (name, ty) in [
        ("sso_connection.activated", EventType::SsoConnectionActivated),
        ("sso_onboarding_ticket.completed", EventType::SsoOnboardingTicketCompleted),
        ("scim_group.created", EventType::ScimGroupCreated),
        ("scim_group.updated", EventType::ScimGroupUpdated),
        ("scim_group.deleted", EventType::ScimGroupDeleted),
        ("scim_group.member_added", EventType::ScimGroupMemberAdded),
        ("scim_group.member_removed", EventType::ScimGroupMemberRemoved),
    ] {
        assert_eq!(EventType::from(name), ty);
        assert_eq!(ty.as_str(), name);
    }

    let ev: UserReferralAttributedEvent = serde_json::from_value(json!({
        "object": "user_referral", "user_id": "user_1", "attribution_status": "attributed",
        "source": "sign_in_with_atlas", "atlas_id_sub": "aid_1", "atlas_id_app_id": "app_1"
    }))
    .unwrap();
    assert_eq!(ev.source.as_deref(), Some("sign_in_with_atlas"));
    assert_eq!(ev.atlas_id_sub.as_deref(), Some("aid_1"));
    assert_eq!(ev.atlas_id_app_id.as_deref(), Some("app_1"));
}

// ── users, platform, cookie consent ────────────────────────────────────────

#[test]
fn create_user_with_named_password_hash() {
    let mut params = serde_json::Map::new();
    params.insert("n".into(), json!(16384));
    let body = serde_json::to_value(CreateUserBody {
        email_address: "ada@example.com".into(),
        password_hash: Some("aGFzaA==".into()),
        password_hash_algorithm: Some("scrypt".into()),
        password_hash_params: Some(params),
        password_salt: Some("c2FsdA==".into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(body["password_hash_algorithm"], json!("scrypt"));
    assert_eq!(body["password_hash_params"], json!({ "n": 16384 }));
    assert_eq!(body["password_salt"], json!("c2FsdA=="));
    assert!(body.get("password_hasher").is_none());
}

#[tokio::test]
async fn platform_reveal_initial_secret() {
    let (c, t) = client_with(
        r#"{"object":"initial_secret","app_id":"app_1","instance_id":"ins_1","key_id":"sk_1","secret":"sk_live_x","sibling_instance":{"instance_id":"ins_2","key_id":"sk_2","secret":null,"note":"n"}}"#,
    );
    let s = c.platform().apps().reveal_initial_secret("app_1", false).await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Post, "/v1/platform/apps/app_1/initial_secret/reveal".to_string())
    );
    assert_eq!(s.secret.as_deref(), Some("sk_live_x"));
    assert_eq!(s.sibling_instance.unwrap().secret, None);

    c.platform().apps().reveal_initial_secret("app_1", true).await.unwrap();
    assert_eq!(
        route(&last(&t)),
        (HttpMethod::Post, "/v1/platform/apps/app_1/initial_secret/reveal?dry_run=true".to_string())
    );
}

#[tokio::test]
async fn cookie_consent_host_aliases() {
    let (c, t) = client_with(r#"{"enabled":true,"host_aliases":["acme-fapi.atlasauth.net"]}"#);
    let cc = c.instance().set_cookie_consent_host_aliases(&["acme-fapi.atlasauth.net"]).await.unwrap();
    let req = last(&t);
    assert_eq!(route(&req), (HttpMethod::Put, "/v1/instance/cookie_consent".to_string()));
    assert_eq!(body_json(&req), json!({ "host_aliases": ["acme-fapi.atlasauth.net"] }));
    assert_eq!(cc.host_aliases, vec!["acme-fapi.atlasauth.net"]);
}
