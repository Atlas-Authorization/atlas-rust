//! Round-2 server surface (0.24): SSO claims, instance app preflight, dry-run fields,
//! sealed `sealed_*` fields, the ORIGIN_NOT_ALLOWED helper and the OIDC claim readers.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Map, Value};

use atlasauth::backend::{types, BackendClient, DryRunResult, FakeTransport};
use atlasauth::{
    oidc_authorize_url_with_organization, oidc_organization_of, oidc_organizations_of, oidc_sso_of, Claims, HttpMethod,
};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn set_managed_by_sends_the_instance_and_null() {
    let fake = FakeTransport::json_ok(r#"{"object":"atlas_id_app","id":"app_1","client_id":"c","managed_via":"adopted","changed":true}"#);
    let c = client(&fake);
    let r = c
        .platform()
        .atlas_id_apps()
        .set_managed_by("app_1", &types::AtlasIdAppsSetManagedByBody::new("ins_1"))
        .await
        .unwrap();
    assert!(r.changed);
    assert_eq!(r.managed_via.as_deref(), Some("adopted"));
    c.platform()
        .atlas_id_apps()
        .set_managed_by("app_1", &types::AtlasIdAppsSetManagedByBody::release())
        .await
        .unwrap();
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Put);
    assert!(reqs[0].url.ends_with("/v1/platform/atlas_id_apps/app_1/managed_by"));
    assert_eq!(serde_json::from_str::<Value>(reqs[0].body.as_ref().unwrap()).unwrap(), json!({"instance_id":"ins_1"}));
    assert_eq!(serde_json::from_str::<Value>(reqs[1].body.as_ref().unwrap()).unwrap(), json!({"instance_id":null}));
}

#[tokio::test]
async fn instance_preflight_decodes_the_new_fields() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"preflight","app_id":"app_1","ok":true,"checked_at":1,"user_count":2,"findings":[],
        "button_rendered_origins":[{"origin":"https://a.example","last_seen_at":1,"requests":2}],
        "authorize_requests_7d":{"button":1,"js":0,"fedcm":0,"fallback":2,"unmarked":0},
        "fallback_origins":[],"homepage_includes_script":false}"#,
    );
    let p = client(&fake).atlas_id_grants().preflight("app_1").await.unwrap();
    let req = &fake.requests()[0];
    assert_eq!(req.method, HttpMethod::Get);
    assert!(req.url.ends_with("/v1/atlas_id_apps/app_1/preflight"));
    assert_eq!(p.button_rendered_origins[0].origin, "https://a.example");
    assert_eq!(p.authorize_requests_7d.unwrap().fallback, 2);
    assert_eq!(p.homepage_includes_script, Some(false));
}

#[test]
fn dry_run_result_decodes_the_round_two_fields() {
    let r: DryRunResult = serde_json::from_value(json!({
        "object":"dry_run","dry_run":true,"mode":"rollback","validated":true,"method":"POST","path":"/v1/users",
        "changes":[],"warnings":[{"code":"origin_still_referenced"}],"would_return_status":201,
        "suppressed":["email"],"validation_skipped":{"reason":"external_call","detail":"d"},"note":""
    }))
    .unwrap();
    assert_eq!(r.mode, "rollback");
    assert_eq!(r.would_return_status, Some(201));
    assert_eq!(r.suppressed, vec!["email".to_string()]);
    assert_eq!(r.warnings.len(), 1);
    assert_eq!(r.validation_skipped.unwrap().reason, "external_call");
}

#[test]
fn sealed_fields_decode_on_shown_once_responses() {
    let r: types::OAuthClientsRotateSecretResponse = serde_json::from_value(json!({
        "object":"oauth_client","id":"x","client_id":"x","sealed_client_secret":"AAAA",
        "secrets_sealed":{"algorithm":"x25519-sealed-box","recipient":"x25519:k","fields":["client_secret"]}
    }))
    .unwrap();
    assert_eq!(r.sealed_client_secret.as_deref(), Some("AAAA"));
    assert_eq!(r.secrets_sealed.unwrap().fields, vec!["client_secret".to_string()]);
}

#[test]
fn sso_claims_and_oidc_readers() {
    let c: Claims = serde_json::from_value(json!({
        "iss":"i","sub":"u","exp":1,"sso_connection_id":"sso_1","sso_organization_id":"org_1","sso_connection_type":"saml"
    }))
    .unwrap();
    assert_eq!(c.sso_connection_id.as_deref(), Some("sso_1"));
    assert_eq!(c.sso_organization_id.as_deref(), Some("org_1"));
    assert_eq!(c.sso_connection_type.as_deref(), Some("saml"));

    let claims = obj(json!({
        "org_id":"org_1","org_slug":"acme","org_role":"admin","org_permissions":["org:read",3],
        "orgs":[{"id":"org_1","slug":"acme","role":"admin"},{"slug":"x"}],
        "sso_connection_id":"sso_1","sso_organization_id":"org_1","sso_connection_type":"ldap"
    }));
    let org = oidc_organization_of(&claims).unwrap();
    assert_eq!(org.permissions, vec!["org:read".to_string()]);
    assert_eq!(oidc_organizations_of(&claims).unwrap().len(), 1);
    let sso = oidc_sso_of(&claims).unwrap();
    assert_eq!(sso.organization_id.as_deref(), Some("org_1"));
    assert_eq!(sso.connection_type, None);
    assert!(oidc_sso_of(&obj(json!({"sub":"u"}))).is_none());
    assert_eq!(
        oidc_authorize_url_with_organization("https://x.example/authorize?client_id=c&organization=old", "acme"),
        "https://x.example/authorize?client_id=c&organization=acme"
    );
}

#[tokio::test]
async fn origin_not_allowed_is_recognised() {
    let fake = FakeTransport::new(|_| atlasauth::HttpResponse {
        status: 403,
        body: r#"{"errors":[{"code":"ORIGIN_NOT_ALLOWED","message":"nope"}]}"#.to_string(),
    });
    let err = client(&fake).whoami().await.unwrap_err();
    match err {
        atlasauth::backend::BackendError::Api(e) => assert!(e.is_origin_not_allowed()),
        other => panic!("{other:?}"),
    }
}
