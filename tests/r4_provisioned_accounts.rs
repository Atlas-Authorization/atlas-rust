//! Test and review accounts, verified domains, the new app fields and error codes (0.26).
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    codes, BackendClient, CreateAtlasIdProvisionedAccountBody, FakeTransport, RotateAtlasIdProvisionedPasswordBody,
    UpdateAtlasIdAppBody,
};
use atlasauth::HttpMethod;

const ACCOUNT: &str = r#"{"object":"atlas_id_provisioned_account","id":"pa_1","sub":"sub_1","email":"rev@example.com",
"email_verified":true,"label":"reviewer","kind":"provisioned","provisioned_by":"app","app_ids":["aid_1"],
"apps":[{"id":"aid_1","client_id":"c1","name":"Acme"}],"any_app":false,"two_factor_exempt":false,"expires_at":null,
"expired":false,"developer_account_id":null,"created_by":{"type":"platform","id":"plat_1"},"last_sign_in_at":null,
"password_rotated_at":null,"created_at":1,"updated_at":2,"password":"hunter2-hunter2","sealed_password":"c2VhbGVk"}"#;

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("psk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

fn body(fake: &FakeTransport, i: usize) -> Value {
    serde_json::from_str(fake.requests()[i].body.as_ref().unwrap()).unwrap()
}

#[tokio::test]
async fn provisioned_account_routes() {
    let fake = FakeTransport::json_ok(&format!(r#"{{"object":"list","data":[{ACCOUNT}],"limit":25,"total":1}}"#));
    let c = client(&fake);
    let accts = c.platform().atlas_id_apps().provisioned_accounts();
    let list = accts.list("aid_1").await.unwrap();
    assert_eq!((list.limit, list.total), (25, 1));
    assert_eq!(list.data[0].apps[0].client_id, "c1");
    assert_eq!(fake.requests()[0].method, HttpMethod::Get);
    assert!(fake.requests()[0].url.ends_with("/v1/platform/atlas_id_apps/aid_1/provisioned_accounts"));

    let fake = FakeTransport::json_ok(ACCOUNT);
    let c = client(&fake);
    let accts = c.platform().atlas_id_apps().provisioned_accounts();
    let made = accts
        .create(
            "aid_1",
            &CreateAtlasIdProvisionedAccountBody {
                email: "rev@example.com".into(),
                label: "reviewer".into(),
                two_factor_exempt: Some(true),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(made.password.as_deref(), Some("hunter2-hunter2"));
    accts.get("aid_1", "pa_1").await.unwrap();
    accts.remove("aid_1", "pa_1").await.unwrap();
    accts.rotate_password("aid_1", "pa_1", None).await.unwrap();
    accts
        .rotate_password("aid_1", "pa_1", Some(&RotateAtlasIdProvisionedPasswordBody { password: Some("a-long-password-1".into()) }))
        .await
        .unwrap();
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert_eq!(body(&fake, 0), json!({"email":"rev@example.com","label":"reviewer","two_factor_exempt":true}));
    assert!(reqs[1].url.ends_with("/provisioned_accounts/pa_1"));
    assert_eq!(reqs[2].method, HttpMethod::Delete);
    assert_eq!(reqs[3].method, HttpMethod::Post);
    assert!(reqs[3].url.ends_with("/provisioned_accounts/pa_1/password"));
    assert!(reqs[3].body.is_none());
    assert_eq!(body(&fake, 4), json!({"password":"a-long-password-1"}));
}

#[tokio::test]
async fn sealed_password_and_no_plaintext_in_debug() {
    let fake = FakeTransport::json_ok(ACCOUNT);
    let c = client(&fake);
    let a = c.platform().atlas_id_apps().provisioned_accounts().get("aid_1", "pa_1").await.unwrap();
    assert_eq!(a.sealed_password.as_deref(), Some("c2VhbGVk"));
    let shown = format!("{a:?} {a:#?}");
    assert!(!shown.contains("hunter2-hunter2"));
    assert!(!shown.contains("c2VhbGVk"));

    let create = CreateAtlasIdProvisionedAccountBody {
        email: "e@example.com".into(),
        label: "l".into(),
        password: Some("super-secret-pw-1".into()),
        ..Default::default()
    };
    assert!(!format!("{create:?}").contains("super-secret-pw-1"));
    let rot = RotateAtlasIdProvisionedPasswordBody { password: Some("super-secret-pw-2".into()) };
    assert!(!format!("{rot:?}").contains("super-secret-pw-2"));
}

#[tokio::test]
async fn domain_routes() {
    let fake = FakeTransport::json_ok(r#"{"object":"account_domain","id":"dom_1","domain":"example.com"}"#);
    let c = client(&fake);
    let d = c.platform().domains();
    assert_eq!(d.claim("example.com").await.unwrap().domain, "example.com");
    d.check("dom_1").await.unwrap();
    d.verify("dom_1").await.unwrap();
    d.remove("dom_1").await.unwrap();
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert!(reqs[0].url.ends_with("/v1/platform/domains"));
    assert_eq!(body(&fake, 0), json!({"domain":"example.com"}));
    assert!(reqs[1].url.ends_with("/v1/platform/domains/dom_1/verify"));
    assert!(reqs[2].url.ends_with("/v1/platform/domains/dom_1/verify"));
    assert_eq!(reqs[3].method, HttpMethod::Delete);

    let fake = FakeTransport::json_ok(r#"{"object":"list","data":[{"id":"dom_1","domain":"example.com"}],"verified_domains":["example.com"]}"#);
    let l = client(&fake).platform().domains().list().await.unwrap();
    assert_eq!(l.verified_domains, vec!["example.com".to_string()]);
}

#[tokio::test]
async fn app_fields_and_codes() {
    let upd = UpdateAtlasIdAppBody { test_mode: Some(true), provisioned_verified_domains_only: Some(false), ..Default::default() };
    assert_eq!(serde_json::to_value(&upd).unwrap(), json!({"test_mode":true,"provisioned_verified_domains_only":false}));

    let fake = FakeTransport::json_ok(r#"{"id":"aid_1","test_mode":true,"provisioned_verified_domains_only":true}"#);
    let app = client(&fake).platform().atlas_id_apps().update("aid_1", &upd).await.unwrap();
    assert_eq!(app.test_mode, Some(true));
    assert_eq!(app.provisioned_verified_domains_only, Some(true));

    assert_eq!(codes::TEST_ACCOUNT_RESTRICTED, "TEST_ACCOUNT_RESTRICTED");
    assert_eq!(codes::PROVISIONED_ACCOUNT_LIMIT_REACHED, "PROVISIONED_ACCOUNT_LIMIT_REACHED");
    assert_eq!(codes::DOMAIN_NOT_VERIFIED, "DOMAIN_NOT_VERIFIED");
}
