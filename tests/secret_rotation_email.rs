//! Hermetic tests for the 0.13.0 additions: OAuth client secret rotation with
//! overlap, the development email sender, managed email on your own provider
//! account, origin integrations, issuer fields and the new error codes.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    codes, types, AllowedOriginEntry, BackendClient, CreatePlatformAppBody, EmailProviderConfig,
    FakeTransport, PlatformApp, Query, ResendConfig, UpdatePlatformAppBody,
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
async fn rotate_secret_sends_the_overlap_and_reads_the_expiry() {
    let (c, t) = client_with(
        r#"{"object":"oauth_client","id":"oc_1","client_id":"cl_1","client_secret":"cs_new","overlap_seconds":0,"previous_secret_expires_at":null}"#,
    );
    let out = c
        .oauth_clients()
        .rotate_secret_with("oc_1", &types::OAuthClientsRotateSecretBody::new().with_overlap_seconds(0), Some("idem_1"))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(path(&req), "/v1/oauth_clients/oc_1/rotate_secret");
    assert_eq!(body_json(&req), json!({ "overlap_seconds": 0 }));
    assert_eq!(out.client_secret, "cs_new");
    assert_eq!(out.overlap_seconds, 0);
    assert_eq!(out.previous_secret_expires_at, None);

    // The bodyless call keeps compiling and uses the default overlap.
    c.oauth_clients().rotate_secret("oc_1", None).await.unwrap();
    assert_eq!(body_json(&t.requests().pop().unwrap()), json!({}));
}

#[tokio::test]
async fn development_email_get_enable_disable() {
    let (c, t) = client_with(
        r#"{"object":"development_email","provider_id":"mp_1","enabled":true,"active":true,"transport":"resend","from_address":"onboarding@resend.dev","subject_prefix":"[Atlas test] ","footer":"f","templates":["magic_link"],"limits":{"daily":100,"per_recipient_hourly":10},"updated_at":5,"deleted":true,"mode":"standard"}"#,
    );
    let dev = c.messaging_providers().get_development_email().await.unwrap();
    assert_eq!(dev.limits.per_recipient_hourly, 10);
    assert_eq!(dev.subject_prefix, "[Atlas test] ");
    let req = t.requests().pop().unwrap();
    assert_eq!((req.method, path(&req)), (HttpMethod::Get, "/v1/messaging_providers/email/development".to_string()));

    c.messaging_providers()
        .enable_development_email(&types::MessagingProvidersEnableDevelopmentEmailBody::new().with_provider_id("mp_1"))
        .await
        .unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(body_json(&req), json!({ "provider_id": "mp_1" }));

    let gone = c.messaging_providers().disable_development_email().await.unwrap();
    assert_eq!(gone.mode, "standard");
    let req = t.requests().pop().unwrap();
    assert_eq!((req.method, path(&req)), (HttpMethod::Delete, "/v1/messaging_providers/email/development".to_string()));
}

#[tokio::test]
async fn managed_email_on_your_own_account_and_provider_mode() {
    let (c, t) = client_with(
        r#"{"object":"managed_email","id":"me_1","backend":"brevo","provider_id":"mp_2","limits":null,"reputation":"your_provider_account","feedback_webhook":"registered","channel":"email","transport":"resend","mode":"development"}"#,
    );
    let me = c
        .messaging_providers()
        .create_managed_email(
            &types::MessagingProvidersCreateManagedEmailBody::new("hi@acme.example")
                .with_transport("brevo")
                .with_config(types::MessagingProvidersCreateManagedEmailBodyConfig::new().with_api_key("xkeysib-x")),
        )
        .await
        .unwrap();
    assert_eq!(
        body_json(&t.requests().pop().unwrap()),
        json!({ "from_address": "hi@acme.example", "transport": "brevo", "config": { "api_key": "xkeysib-x" } })
    );
    assert_eq!(me.provider_id.as_deref(), Some("mp_2"));
    assert_eq!(me.feedback_webhook.as_deref(), Some("registered"));
    assert!(me.limits.is_null());

    let resend = EmailProviderConfig::Resend {
        from_address: None,
        config: ResendConfig { api_key: Some("re_x".into()) },
    };
    let p = c.messaging_providers().set_email_with_mode(&resend, Some("development")).await.unwrap();
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Put);
    assert_eq!(body_json(&req), json!({ "transport": "resend", "mode": "development", "config": { "api_key": "re_x" } }));
    assert_eq!(p.mode.as_deref(), Some("development"));
}

#[tokio::test]
async fn origin_entries_and_issuer_fields() {
    let (c, t) = client_with(
        r#"{"object":"instance","issuer":"https://auth.acme.example","discovery_url":"https://auth.acme.example/.well-known/openid-configuration","jwks_uri":"https://auth.acme.example/.well-known/jwks.json","allowed_origins":["https://app.acme.example"],"allowed_origin_integrations":{"https://app.acme.example":"redirect"},"auth_config":{}}"#,
    );
    let ins = c.instance().get().await.unwrap();
    assert_eq!(ins.issuer.as_deref(), Some("https://auth.acme.example"));
    assert_eq!(ins.allowed_origin_integrations["https://app.acme.example"], "redirect");

    let body = types::InstanceUpdateBody::new().with_allowed_origin_entries([
        AllowedOriginEntry::new("https://a.acme.example"),
        AllowedOriginEntry::with_integration("https://app.acme.example", AllowedOriginEntry::REDIRECT),
    ]);
    c.instance().update(&body, &Query::new()).await.unwrap();
    assert_eq!(
        body_json(&t.requests().pop().unwrap()),
        json!({ "allowed_origins": ["https://a.acme.example", { "origin": "https://app.acme.example", "integration": "redirect" }] })
    );

    let (pc, pt) = client_with(r#"{"id":"app_1","frontend_api_host":"auth.acme.example","issuer":"https://i","discovery_url":"https://d","jwks_uri":"https://j","allowed_origin_integrations":{"https://a":"embedded"}}"#);
    let update = UpdatePlatformAppBody {
        name: Some("x".into()),
        allowed_origin_entries: Some(vec![AllowedOriginEntry::with_integration("https://a", AllowedOriginEntry::AUTO)]),
        ..Default::default()
    };
    let app: PlatformApp = pc.platform().apps().update("app_1", &update).await.unwrap();
    assert_eq!(
        body_json(&pt.requests().pop().unwrap()),
        json!({ "name": "x", "allowed_origins": [{ "origin": "https://a", "integration": "auto" }] })
    );
    assert_eq!(app.frontend_api_host.as_deref(), Some("auth.acme.example"));
    assert_eq!(app.allowed_origin_integrations["https://a"], "embedded");

    let create = CreatePlatformAppBody { name: "y".into(), allowed_origins: Some(vec!["https://b".into()]), ..Default::default() };
    pc.platform().apps().create(&create, None).await.unwrap();
    assert_eq!(body_json(&pt.requests().pop().unwrap()), json!({ "name": "y", "allowed_origins": ["https://b"] }));
}

#[tokio::test]
async fn login_readiness_verification_and_codes() {
    let (c, _) = client_with(
        r#"{"object":"login_readiness","origin":"https://app.acme.example","live":false,"ready":true,"integration":{"assumed":"redirect","source":"declared","reason":"r"},"checks":[{"name":"cors","pass":false,"applies":false}]}"#,
    );
    let lr = c.diagnostics().login_readiness(&Query::new().set("origin", "https://app.acme.example")).await.unwrap();
    assert_eq!(lr.integration.unwrap().assumed, "redirect");
    assert_eq!(lr.checks[0].applies, Some(false));

    let ea: types::EmailAddress =
        serde_json::from_str(r#"{"id":"ea_1","object":"email_address","email_address":"a@acme.example","verified":false,"primary":true,"verification":{"status":"unverified","strategy":"skipped"}}"#).unwrap();
    assert_eq!(ea.verification.strategy.as_deref(), Some("skipped"));

    assert_eq!(codes::READ_ONLY_FIELD, "READ_ONLY_FIELD");
    assert_eq!(codes::DEVELOPMENT_EMAIL_NOT_ALLOWED, "DEVELOPMENT_EMAIL_NOT_ALLOWED");
    assert_eq!(codes::DEVELOPMENT_EMAIL_UNAVAILABLE, "DEVELOPMENT_EMAIL_UNAVAILABLE");
    assert_eq!(codes::DEVELOPMENT_EMAIL_LIMIT_REACHED, "DEVELOPMENT_EMAIL_LIMIT_REACHED");
    assert_eq!(codes::DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED, "DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED");
}
