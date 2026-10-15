//! Hermetic tests for the 0.10.0 additions: OAuth client
//! `skip_logout_confirmation`, the cookie-consent settings link, forced email
//! provider removal (`EMAIL_PROVIDER_IN_USE`), and the session fields on
//! `users/{id}/sessions`.
#![cfg(feature = "backend")]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    codes, cookie_settings_link_presets as presets, types, BackendClient, BackendError,
    CookieSettingsLinkInput, DeleteMessagingProviderParams, FakeTransport, MessagingChannel, Query,
    SetCookieConsentBody,
};
use atlasauth::{HttpMethod, HttpRequest, HttpResponse};

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

const OAUTH_CLIENT: &str = r#"{"object":"oauth_client","id":"oc_1","client_id":"cl_1","name":"App","first_party":true,"skip_logout_confirmation":true,"redirect_uris":["https://app.example/cb"]}"#;

#[tokio::test]
async fn oauth_client_skip_logout_confirmation_is_sent_and_read() {
    let (c, t) = client_with(OAUTH_CLIENT);
    let created = c
        .oauth_clients()
        .create(
            &types::OAuthClientsCreateBody::new("App", vec!["https://app.example/cb".to_string()])
                .with_first_party(true)
                .with_skip_logout_confirmation(true),
            None,
        )
        .await
        .unwrap();
    assert_eq!(created.skip_logout_confirmation, Some(true));
    c.oauth_clients()
        .update("oc_1", &types::OAuthClientsUpdateBody::new().with_skip_logout_confirmation(false), None)
        .await
        .unwrap();
    let got = c.oauth_clients().get("oc_1").await.unwrap();
    assert_eq!(got.skip_logout_confirmation, Some(true));

    let reqs = t.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert_eq!(body_json(&reqs[0])["skip_logout_confirmation"], json!(true));
    assert_eq!((reqs[1].method, path(&reqs[1])), (HttpMethod::Patch, "/v1/oauth_clients/oc_1".into()));
    assert_eq!(body_json(&reqs[1]), json!({"skip_logout_confirmation": false}));

    // Unset: not sent at all.
    c.oauth_clients().update("oc_1", &types::OAuthClientsUpdateBody::new().with_name("A"), None).await.unwrap();
    assert_eq!(body_json(t.requests().last().unwrap()), json!({"name": "A"}));
}

#[tokio::test]
async fn cookie_consent_settings_link_round_trips() {
    let (c, t) = client_with(
        r#"{"object":"cookie_consent","enabled":true,"script_url":"https://cmp.example/s.js","extra_origins":[],
            "settings_link":{"label":"Cookie settings","preset":"cookiemunch","attributes":{"class":"footer-link"},
            "rendered_attributes":{"class":"footer-link","data-cc":"show-settings"}}}"#,
    );
    let mut attributes = HashMap::new();
    attributes.insert("class".to_string(), "footer-link".to_string());
    let cc = c
        .instance()
        .set_cookie_consent(&SetCookieConsentBody {
            script_url: "https://cmp.example/s.js".into(),
            settings_link: Some(CookieSettingsLinkInput {
                label: "Cookie settings".into(),
                preset: Some(presets::COOKIEMUNCH.into()),
                attributes: Some(attributes),
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let link = cc.settings_link.expect("a settings link");
    assert_eq!(link.label, "Cookie settings");
    assert_eq!(link.preset.as_deref(), Some(presets::COOKIEMUNCH));
    assert_eq!(link.attributes["class"], "footer-link");
    assert_eq!(link.rendered_attributes["data-cc"], "show-settings");

    let reqs = t.requests();
    assert_eq!((reqs[0].method, path(&reqs[0])), (HttpMethod::Put, "/v1/instance/cookie_consent".into()));
    assert_eq!(
        body_json(&reqs[0]),
        json!({"script_url": "https://cmp.example/s.js",
               "settings_link": {"label": "Cookie settings", "preset": "cookiemunch", "attributes": {"class": "footer-link"}}})
    );

    // A preset-only link omits attributes; no link omits the key.
    c.instance()
        .set_cookie_consent(&SetCookieConsentBody {
            script_url: "https://cmp.example/s.js".into(),
            settings_link: Some(CookieSettingsLinkInput {
                label: "Cookies".into(),
                preset: Some(presets::ONETRUST.into()),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(body_json(&t.requests()[1])["settings_link"], json!({"label": "Cookies", "preset": "onetrust"}));
    c.instance()
        .set_cookie_consent(&SetCookieConsentBody { script_url: "https://cmp.example/s.js".into(), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(body_json(&t.requests()[2]), json!({"script_url": "https://cmp.example/s.js"}));
    assert_eq!(
        [presets::COOKIEMUNCH, presets::COOKIEBOT, presets::ONETRUST, presets::CUSTOM],
        ["cookiemunch", "cookiebot", "onetrust", "custom"]
    );
}

#[tokio::test]
async fn cookie_consent_without_a_link_and_unknown_preset() {
    let (c, _) = client_with(r#"{"object":"cookie_consent","enabled":true,"script_url":"https://cmp.example/s.js","settings_link":null}"#);
    assert!(c.instance().get_cookie_consent().await.unwrap().settings_link.is_none());
    let (c, _) = client_with(
        r#"{"object":"cookie_consent","enabled":true,"settings_link":{"label":"x","preset":"newcmp","attributes":{},"rendered_attributes":{}}}"#,
    );
    let link = c.instance().get_cookie_consent().await.unwrap().settings_link.unwrap();
    assert_eq!(link.preset.as_deref(), Some("newcmp"));
    let (c, _) = client_with(r#"{"object":"cookie_consent","enabled":false}"#);
    assert!(c.instance().get_cookie_consent().await.unwrap().settings_link.is_none());
}

#[tokio::test]
async fn messaging_provider_delete_can_be_forced() {
    let (c, t) = client_with(r#"{"object":"messaging_provider","channel":"email","deleted":true}"#);
    c.messaging_providers().delete(MessagingChannel::Email).await.unwrap();
    c.messaging_providers()
        .delete_with(MessagingChannel::Email, &DeleteMessagingProviderParams { force: false })
        .await
        .unwrap();
    let out = c
        .messaging_providers()
        .delete_with(MessagingChannel::Email, &DeleteMessagingProviderParams { force: true })
        .await
        .unwrap();
    assert_eq!(out["deleted"], json!(true));
    let reqs = t.requests();
    assert_eq!((reqs[0].method, path(&reqs[0])), (HttpMethod::Delete, "/v1/messaging_providers/email".into()));
    assert_eq!(path(&reqs[1]), "/v1/messaging_providers/email");
    assert_eq!((reqs[2].method, path(&reqs[2])), (HttpMethod::Delete, "/v1/messaging_providers/email?force=true".into()));
}

#[tokio::test]
async fn messaging_provider_in_use_is_a_409_naming_the_features() {
    let transport = Arc::new(FakeTransport::new(|_req| HttpResponse {
        status: 409,
        body: r#"{"errors":[{"code":"EMAIL_PROVIDER_IN_USE","message":"in use","meta":{"features":["emailCode","passwordReset"]}}]}"#.into(),
    }));
    let c = BackendClient::builder("sk_test").transport(transport).max_retries(0).build().unwrap();
    match c.messaging_providers().delete(MessagingChannel::Email).await.unwrap_err() {
        BackendError::Api(e) => {
            assert_eq!(e.status, 409);
            assert!(e.has_code(codes::EMAIL_PROVIDER_IN_USE));
            assert_eq!(e.errors[0].meta.as_ref().unwrap()["features"], json!(["emailCode", "passwordReset"]));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(codes::EMAIL_PROVIDER_IN_USE, "EMAIL_PROVIDER_IN_USE");
    assert_eq!(codes::EMAIL_PROVIDER_REQUIRED, "EMAIL_PROVIDER_REQUIRED");
}

#[tokio::test]
async fn user_sessions_carry_idle_org_and_impersonation_fields() {
    let (c, t) = client_with(
        r#"{"object":"list","has_more":false,"data":[
            {"object":"session","id":"sess_1","user_id":"user_1","status":"active","last_active_organization_id":"org_1","impersonated_by":"user_admin","last_active_at":1,"expire_at":9,"abandon_at":5,"idle_expires_at":5,"created_at":0},
            {"object":"session","id":"sess_2","user_id":"user_1","status":"active","last_active_organization_id":null,"impersonated_by":null,"last_active_at":1,"expire_at":9,"abandon_at":5,"created_at":0}]}"#,
    );
    let page = c.users().list_sessions("user_1", &Query::new()).await.unwrap();
    assert_eq!(path(&t.requests()[0]), "/v1/users/user_1/sessions");
    assert_eq!(page.data[0].idle_expires_at, Some(5));
    assert_eq!(page.data[0].last_active_organization_id.as_deref(), Some("org_1"));
    assert_eq!(page.data[0].impersonated_by.as_deref(), Some("user_admin"));
    assert_eq!(page.data[1].idle_expires_at, None);
    assert!(page.data[1].last_active_organization_id.is_none());
    assert!(page.data[1].impersonated_by.is_none());

    // The hand-written session reads carry the same fields.
    let (c, _) = client_with(
        r#"{"object":"session","id":"sess_1","user_id":"user_1","status":"active","last_active_organization_id":"org_1","impersonated_by":"user_admin","idle_expires_at":5}"#,
    );
    let s = c.sessions().get("sess_1").await.unwrap();
    assert_eq!(s.idle_expires_at, Some(5));
    assert_eq!(s.last_active_organization_id.as_deref(), Some("org_1"));
    assert_eq!(s.impersonated_by.as_deref(), Some("user_admin"));
}

#[tokio::test]
async fn captcha_secret_is_bring_your_own_keys() {
    let (c, t) = client_with(
        r#"{"object":"captcha_secret","provider":"hcaptcha","deleted":true,"flows_turned_off":["signUp"]}"#,
    );
    c.instance()
        .set_captcha_secret(&types::InstanceSetCaptchaSecretBody::new().with_secret("s3cret").with_provider("turnstile"))
        .await
        .unwrap();
    c.instance()
        .delete_captcha_secret(&Query::new().set("provider", "hcaptcha").set("force", true))
        .await
        .unwrap();
    c.instance().delete_captcha_secret(&Query::new()).await.unwrap();
    let reqs = t.requests();
    assert_eq!((reqs[0].method, path(&reqs[0])), (HttpMethod::Put, "/v1/instance/captcha_secret".into()));
    assert_eq!(body_json(&reqs[0]), json!({"secret": "s3cret", "provider": "turnstile"}));
    assert_eq!(
        (reqs[1].method, path(&reqs[1])),
        (HttpMethod::Delete, "/v1/instance/captcha_secret?provider=hcaptcha&force=true".into())
    );
    assert_eq!(path(&reqs[2]), "/v1/instance/captcha_secret");
    assert_eq!(codes::CAPTCHA_KEYS_REQUIRED, "CAPTCHA_KEYS_REQUIRED");
    assert_eq!(codes::CAPTCHA_IN_USE, "CAPTCHA_IN_USE");
}
