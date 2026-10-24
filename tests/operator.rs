//! Operator device-login helpers for CLIs: the RFC 8628 flow, the RFC 8693
//! token exchange, partner-link client credentials and leaked-key revocation.
#![cfg(all(feature = "client", feature = "backend"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use atlasauth::backend::FakeTransport;
use atlasauth::client::{
    backend_client_from_access_token, exchange_operator_token, get_operator_configuration, partner_link_token,
    poll_operator_login, revoke_leaked_keys, start_operator_login, OperatorOptions,
};
use atlasauth::{is_access_token, HttpMethod, HttpResponse, HttpTransport};

fn config_json() -> String {
    r#"{"issuer":"https://atlasauth.net","device_authorization_endpoint":"https://atlasauth.net/oauth2/device_authorization","token_endpoint":"https://atlasauth.net/oauth2/token","client_id":"atlas-cli","scope":"openid atlas:operator","token_exchange_endpoint":"https://api.atlasauth.net/v1/oauth/token","token_exchange_audience":"atlas","root_action_max_mfa_age_seconds":300}"#
        .to_string()
}

fn opts() -> OperatorOptions {
    OperatorOptions { api_url: None, poll_interval: Some(Duration::from_millis(1)) }
}

#[tokio::test]
async fn device_login_polls_through_pending_and_slow_down() {
    let polls = Arc::new(AtomicUsize::new(0));
    let polls2 = polls.clone();
    let fake = FakeTransport::new(move |req| {
        if req.url.ends_with("/v1/operator") {
            return HttpResponse { status: 200, body: config_json() };
        }
        if req.url.ends_with("/oauth2/device_authorization") {
            return HttpResponse {
                status: 200,
                body: r#"{"device_code":"dc","user_code":"ABCD-EFGH","verification_uri":"https://atlasauth.net/device","verification_uri_complete":"https://atlasauth.net/device?user_code=ABCD-EFGH","expires_in":600,"interval":1}"#.into(),
            };
        }
        if req.url.ends_with("/oauth2/token") {
            let n = polls2.fetch_add(1, Ordering::SeqCst);
            return match n {
                0 => HttpResponse { status: 400, body: r#"{"error":"authorization_pending"}"#.into() },
                1 => HttpResponse { status: 400, body: r#"{"error":"slow_down"}"#.into() },
                _ => HttpResponse { status: 200, body: r#"{"access_token":"op_tok","token_type":"Bearer","expires_in":3600}"#.into() },
            };
        }
        HttpResponse { status: 404, body: "{}".into() }
    });
    let transport: Arc<dyn HttpTransport> = Arc::new(fake.clone());

    let cfg = get_operator_configuration(&transport, &opts()).await.unwrap();
    assert_eq!(cfg.client_id, "atlas-cli");
    assert_eq!(cfg.root_action_max_mfa_age_seconds, 300);

    let start = start_operator_login(&transport, None, &opts()).await.unwrap();
    assert_eq!(start.user_code, "ABCD-EFGH");
    assert_eq!(start.config.token_endpoint, "https://atlasauth.net/oauth2/token");

    let token = poll_operator_login(&transport, &start, &opts()).await.unwrap();
    assert_eq!(token.access_token, "op_tok");
    assert_eq!(polls.load(Ordering::SeqCst), 3);

    let reqs = fake.requests();
    let device = reqs.iter().find(|r| r.url.ends_with("/device_authorization")).unwrap();
    assert_eq!(device.method, HttpMethod::Post);
    let body = device.body.as_deref().unwrap();
    assert!(body.contains("client_id=atlas-cli"));
    assert!(body.contains("scope=openid+atlas%3Aoperator"));
    let poll = reqs.iter().filter(|r| r.url.ends_with("/oauth2/token")).next().unwrap();
    assert!(poll.body.as_deref().unwrap().contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
}

#[tokio::test]
async fn device_login_surfaces_a_denial() {
    let fake = FakeTransport::new(|req| {
        if req.url.ends_with("/oauth2/token") {
            HttpResponse { status: 400, body: r#"{"error":"access_denied","error_description":"No."}"#.into() }
        } else {
            HttpResponse { status: 404, body: "{}".into() }
        }
    });
    let transport: Arc<dyn HttpTransport> = Arc::new(fake);
    let start = atlasauth::client::OperatorDeviceAuthorization {
        device_code: "dc".into(),
        expires_in: 600,
        interval: 1,
        config: atlasauth::client::OperatorConfiguration {
            token_endpoint: "https://atlasauth.net/oauth2/token".into(),
            client_id: "atlas-cli".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let err = poll_operator_login(&transport, &start, &opts()).await.unwrap_err();
    assert_eq!(err.code(), Some("access_denied"));
}

#[tokio::test]
async fn token_exchange_partner_token_and_leak_revocation() {
    let fake = FakeTransport::new(|req| {
        if req.url.ends_with("/v1/oauth/token") {
            let body = req.body.clone().unwrap_or_default();
            if body.contains("token-exchange") {
                if body.contains("resource=ins_deny") {
                    return HttpResponse {
                        status: 403,
                        body: r#"{"errors":[{"code":"STEP_UP_REQUIRED","message":"Sign in with a second factor."}]}"#.into(),
                    };
                }
                return HttpResponse {
                    status: 200,
                    body: r#"{"access_token":"atlas_live_at_xyz","token_type":"Bearer","expires_in":3600,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","resource":"ins_1","scope":"users:read"}"#.into(),
                };
            }
            return HttpResponse { status: 200, body: r#"{"access_token":"pl_tok","token_type":"Bearer","expires_in":600}"#.into() };
        }
        if req.url.ends_with("/v1/keys/revoke_leaked") {
            return HttpResponse { status: 200, body: r#"{"results":[{"index":0,"kind":"secret_key","outcome":"revoked"}]}"#.into() };
        }
        HttpResponse { status: 404, body: "{}".into() }
    });
    let transport: Arc<dyn HttpTransport> = Arc::new(fake.clone());

    let t = exchange_operator_token(&transport, "op_tok", "ins_1", &["users:read", "users:write"], &opts()).await.unwrap();
    assert!(is_access_token(&t.access_token));
    assert_eq!(t.resource.as_deref(), Some("ins_1"));
    let err = exchange_operator_token(&transport, "op_tok", "ins_deny", &["users:read"], &opts()).await.unwrap_err();
    assert!(err.is_step_up_required());

    let p = partner_link_token(&transport, "cid", "sec", "privacy:execute", &opts()).await.unwrap();
    assert_eq!(p.access_token, "pl_tok");

    let r = revoke_leaked_keys(&transport, &["sk_live_leak"], Some("https://github.com/x/y"), &opts()).await.unwrap();
    assert_eq!((r[0].index, r[0].outcome.as_str()), (0, "revoked"));

    let reqs = fake.requests();
    let ex = reqs[0].body.as_deref().unwrap();
    assert!(ex.contains("subject_token=op_tok"));
    assert!(ex.contains("audience=atlas"));
    assert!(ex.contains("resource=ins_1"));
    assert!(ex.contains("scope=users%3Aread+users%3Awrite"));
    let pl = reqs[2].body.as_deref().unwrap();
    assert!(pl.contains("grant_type=client_credentials") && pl.contains("client_id=cid") && pl.contains("scope=privacy%3Aexecute"));
    let leak: serde_json::Value = serde_json::from_str(reqs[3].body.as_deref().unwrap()).unwrap();
    assert_eq!(leak["secrets"][0], "sk_live_leak");
    assert_eq!(leak["url"], "https://github.com/x/y");

    // The one-hour token drives the Backend API.
    let backend = backend_client_from_access_token("atlas_live_at_xyz", None, Some(Arc::new(fake.clone()))).unwrap();
    let _ = backend.whoami().await;
    let last = fake.requests().last().unwrap().clone();
    assert!(last.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer atlas_live_at_xyz"));
}
