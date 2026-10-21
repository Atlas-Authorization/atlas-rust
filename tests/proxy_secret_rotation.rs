//! Hermetic tests for the 0.14.0 additions: the trusted reverse proxy secret
//! and secret rotation with an overlap for webhook endpoints, per-instance
//! platform keys and Sign in with Atlas apps.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    types, BackendClient, FakeTransport, RotateAtlasIdAppSecretBody, RotatePlatformSecretBody,
    RotateWebhookSecretBody, WebhookEndpoint,
};
use atlasauth::{HttpMethod, HttpRequest};

fn client_with(body: &str) -> (BackendClient, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::json_ok(body));
    let client = BackendClient::builder("sk_test").transport(transport.clone()).max_retries(0).build().unwrap();
    (client, transport)
}

fn path(req: &HttpRequest) -> String {
    req.url.replace("https://api.atlasauth.net", "")
}

fn body_json(req: &HttpRequest) -> Value {
    serde_json::from_str(req.body.as_deref().expect("a JSON body")).unwrap()
}

#[tokio::test]
async fn proxy_secret_get_create_rotate_delete() {
    let (c, t) = client_with(
        r#"{"object":"proxy_secret","set":true,"created_at":1800000000000,"previous_expires_at":1800003600000,"secret_header":"X-Atlas-Proxy-Secret","client_ip_header":"X-Atlas-Client-IP","secret":"aps_1","rotated":true,"deleted":true}"#,
    );
    let view = c.instance().get_proxy_secret().await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(path(&req), "/v1/instance/proxy_secret");
    assert!(view.set);
    assert_eq!(view.created_at, Some(1_800_000_000_000));
    assert_eq!(view.client_ip_header, "X-Atlas-Client-IP");

    let created = c.instance().create_proxy_secret(&types::InstanceCreateProxySecretBody::new()).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(body_json(&req), json!({}));
    assert_eq!(created.secret, "aps_1");

    let rotated = c
        .instance()
        .create_proxy_secret(&types::InstanceCreateProxySecretBody::new().with_overlap_seconds(3600))
        .await
        .unwrap();
    assert_eq!(body_json(&t.requests().pop().unwrap()), json!({ "overlap_seconds": 3600 }));
    assert!(rotated.rotated);
    assert_eq!(rotated.previous_expires_at, Some(1_800_003_600_000));

    c.instance().delete_proxy_secret().await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Delete);
    assert_eq!(path(&req), "/v1/instance/proxy_secret");
}

#[tokio::test]
async fn webhook_rotate_secret_with_overlap() {
    let (c, t) = client_with(
        r#"{"object":"webhook_secret","secret":"whsec_new","overlap_seconds":600,"previous_secret_expires_at":1800000600000}"#,
    );
    let out = c
        .webhook_endpoints()
        .rotate_secret_with("whep_1", &RotateWebhookSecretBody::new().with_overlap_seconds(600))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(path(&req), "/v1/webhook_endpoints/whep_1/rotate_secret");
    assert_eq!(body_json(&req), json!({ "overlap_seconds": 600 }));
    assert_eq!(out.overlap_seconds, Some(600));
    assert_eq!(out.previous_secret_expires_at, Some(1_800_000_600_000));

    // The 0.13 call still sends no body (the server default: no overlap).
    c.webhook_endpoints().rotate_secret("whep_1").await.unwrap();
    assert!(t.requests().pop().unwrap().body.is_none());

    let ep: WebhookEndpoint =
        serde_json::from_str(r#"{"id":"whep_1","previous_secret_expires_at":1800000600000}"#).unwrap();
    assert_eq!(ep.previous_secret_expires_at, Some(1_800_000_600_000));
}

#[tokio::test]
async fn platform_instance_rotation_with_overlap() {
    let (pc, t) = client_with(
        r#"{"object":"app_secret","app_id":"app_1","instance_id":"ins_1","secret":"sk_x","overlap_seconds":0,"previous_keys_expire_at":null}"#,
    );
    let out = pc
        .platform()
        .apps()
        .rotate_instance_secret_with("app_1", "ins_1", &RotatePlatformSecretBody::new().with_overlap_seconds(0), Some("idem_1"))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(path(&req), "/v1/platform/apps/app_1/instances/ins_1/rotate_secret");
    assert_eq!(body_json(&req), json!({ "overlap_seconds": 0 }));
    assert!(req.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("idempotency-key") && v == "idem_1"));
    assert_eq!(out["instance_id"], "ins_1");

    // The 0.13 call: no body, so the server default (72 hours) applies.
    pc.platform().apps().rotate_instance_secret("app_1", "ins_1", None).await.unwrap();
    assert!(t.requests().pop().unwrap().body.is_none());
}

#[tokio::test]
async fn atlas_id_app_rotations_with_overlap() {
    let (pc, t) = client_with(
        r#"{"object":"atlas_id_app","id":"aia_1","client_secret":"cs_new","overlap_seconds":3600,"previous_secret_expires_at":1800003600000,"secret_issued_at":1800000000000,"webhook_secret":"whsec_new","webhook_previous_secret_expires_at":1800000600000}"#,
    );
    let app = pc
        .platform()
        .atlas_id_apps()
        .rotate_secret_with("aia_1", &RotateAtlasIdAppSecretBody::new().with_overlap_seconds(3600))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(path(&req), "/v1/platform/atlas_id_apps/aia_1/rotate_secret");
    assert_eq!(body_json(&req), json!({ "overlap_seconds": 3600 }));
    assert_eq!(app.secret_issued_at, Some(1_800_000_000_000));
    assert_eq!(app.previous_secret_expires_at, Some(1_800_003_600_000));
    assert_eq!(app.overlap_seconds, Some(3600));

    let hook = pc
        .platform()
        .atlas_id_apps()
        .rotate_webhook_secret_with("aia_1", &types::AtlasIdAppsRotateWebhookSecretBody::new().with_overlap_seconds(600))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(path(&req), "/v1/platform/atlas_id_apps/aia_1/webhook/rotate_secret");
    assert_eq!(body_json(&req), json!({ "overlap_seconds": 600 }));
    assert_eq!(hook.webhook_previous_secret_expires_at, Some(1_800_000_600_000));

    // The 0.13 call keeps compiling and sends the default (empty) body.
    pc.platform().atlas_id_apps().rotate_webhook_secret("aia_1").await.unwrap();
    assert_eq!(body_json(&t.requests().pop().unwrap()), json!({}));
}
