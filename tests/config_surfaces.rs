//! Hermetic tests for the 0.7.0 surfaces: strict bodies + unknown-field
//! reporting, raw image uploads, design, Sign in with Atlas apps (platform
//! key), preflight, cookie consent, typed messaging providers, OAuth providers,
//! webhook endpoints, entitlement overrides, notification categories, the
//! typed org policy, and error codes.
#![cfg(feature = "backend")]

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use atlasauth::backend::{
    codes, AtlasDesign, AtlasIdAppBrandingInput, AtlasIdAppCopy, BackendClient, BackendError,
    CreateAtlasIdAppBody, CreateEntitlementOverrideBody, DesignAssetKind, DesignPalette,
    EmailProviderConfig, EndUserPoolPolicy, FakeTransport, MessagingChannel, NotificationCategoryBody,
    OAuthProviderFilter, OrgPolicyPatch, SetCookieConsentBody, SmsProviderConfig, SmtpConfig,
    AwsSnsConfig, UnknownFields, UpdateAtlasIdAppBody, UpdateWebhookEndpointBody,
    UpsertOAuthProviderBody, WalletSettings,
};
use atlasauth::{HttpMethod, HttpRequest, HttpResponse};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn body_json(req: &HttpRequest) -> Value {
    serde_json::from_str(req.body.as_deref().expect("a JSON body")).unwrap()
}

fn path(req: &HttpRequest) -> String {
    req.url.replace("https://api.atlasauth.net", "")
}

// ── strict bodies + unknown fields ────────────────────────────────────────

#[tokio::test]
async fn strict_header_goes_on_writes_only_and_can_be_overridden_per_call() {
    let fake = FakeTransport::json_ok(r#"{"id":"user_1"}"#);
    let strict = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .strict(true)
        .build()
        .unwrap();
    assert_eq!(strict.strict_mode(), Some(true));

    strict.users().get("user_1").await.unwrap();
    strict.users().ban("user_1").await.unwrap();
    strict.with_strict(Some(false)).users().unban("user_1").await.unwrap();
    strict.with_strict(None).users().lock("user_1", None).await.unwrap();

    let reqs = fake.requests();
    assert_eq!(header(&reqs[0], "Atlas-Strict"), None, "GET carries no strict header");
    assert_eq!(header(&reqs[1], "Atlas-Strict"), Some("true"));
    assert_eq!(header(&reqs[2], "Atlas-Strict"), Some("false"));
    assert_eq!(header(&reqs[3], "Atlas-Strict"), None);

    // The default client sends nothing.
    let plain = client(&fake);
    plain.users().ban("user_1").await.unwrap();
    assert_eq!(header(fake.requests().last().unwrap(), "Atlas-Strict"), None);
}

#[tokio::test]
async fn unknown_fields_header_reaches_the_hook() {
    let fake = FakeTransport::json_ok(r#"{"id":"user_1"}"#)
        .with_response_headers([("atlas-unknown-fields", "frist_name, profile.nick")]);
    let seen: Arc<Mutex<Vec<UnknownFields>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let c = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .on_unknown_fields(move |u| sink.lock().unwrap().push(u.clone()))
        .build()
        .unwrap();
    c.request_value(HttpMethod::Patch, "/v1/users/user_1", &[], Some(json!({"frist_name": "A"})))
        .await
        .unwrap();
    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].method, HttpMethod::Patch);
    assert_eq!(got[0].path, "/v1/users/user_1");
    assert_eq!(got[0].fields, vec!["frist_name".to_string(), "profile.nick".to_string()]);
}

#[tokio::test]
async fn strict_refusal_surfaces_the_unknown_field_code() {
    let fake = FakeTransport::new(|_| HttpResponse {
        status: 422,
        body: r#"{"errors":[{"code":"UNKNOWN_FIELD","message":"Unknown field","param":"frist_name"}]}"#.into(),
    });
    let err = client(&fake)
        .with_strict(Some(true))
        .request_value(HttpMethod::Post, "/v1/users", &[], Some(json!({"frist_name": "A"})))
        .await
        .unwrap_err();
    match err {
        BackendError::Api(e) => {
            assert!(e.has_code(codes::UNKNOWN_FIELD));
            assert_eq!(e.errors[0].param.as_deref(), Some("frist_name"));
        }
        other => panic!("{other:?}"),
    }
}

// ── raw uploads ───────────────────────────────────────────────────────────

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0xFF];

#[tokio::test]
async fn design_asset_uploads_send_raw_bytes_with_the_image_type() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"design_asset","asset_id":"dasset_1","kind":"logo","url":"https://x/y.webp","width":10,"height":20,"dominant_color":null,"bytes":12,"created_at":"2026-10-13T00:00:00Z"}"#,
    );
    let c = client(&fake);
    let asset = c.design().upload_asset(DesignAssetKind::Logo, PNG.to_vec(), None).await.unwrap();
    assert_eq!(asset.asset_id, "dasset_1");
    assert_eq!((asset.width, asset.height), (10, 20));

    c.platform()
        .upload_design_asset(DesignAssetKind::Background, b"\xFF\xD8\xFFrest".to_vec(), Some("image/jpeg"))
        .await
        .unwrap();

    let reqs = fake.requests();
    let raw = fake.raw_bodies();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert_eq!(path(&reqs[0]), "/v1/design/assets?kind=logo");
    assert_eq!(header(&reqs[0], "content-type"), Some("image/png"));
    assert!(reqs[0].body.is_none());
    assert_eq!(raw[0].as_deref(), Some(PNG));
    assert_eq!(path(&reqs[1]), "/v1/platform/design/assets?kind=background");
    assert_eq!(header(&reqs[1], "content-type"), Some("image/jpeg"));
    assert_eq!(raw[1].as_deref(), Some(&b"\xFF\xD8\xFFrest"[..]));

    // Undetectable bytes with no content type fail before any request.
    let err = c.design().upload_asset(DesignAssetKind::Logo, b"hello".to_vec(), None).await.unwrap_err();
    assert!(matches!(err, BackendError::Malformed(_)));
    assert_eq!(fake.request_count(), 2);
}

// ── design ────────────────────────────────────────────────────────────────

fn design_settings_body() -> &'static str {
    r##"{"object":"design","design":{"version":1,"preset":"glass","palette":{"primary":"#0F766E"}},
        "resolved":{"version":1,"preset":"glass","colorScheme":"auto","palette":{"primary":"#0F766E","primaryInk":"#FFFFFF"},
        "card":{"style":"glass","blur":12},"background":{"gradient":{"type":"linear","angle":135,"stops":[{"color":"#000000","at":0}]}}},
        "warnings":[{"code":"low_contrast","mode":"light","pair":["text","background"],"ratio":2.1,"required":4.5,"path":"palette.text","message":"Low contrast"}],
        "legacy":false}"##
}

#[tokio::test]
async fn design_settings_round_trip_typed() {
    let fake = FakeTransport::json_ok(design_settings_body());
    let c = client(&fake);

    let got = c.design().get().await.unwrap();
    assert_eq!(got.design.preset.as_deref(), Some("glass"));
    assert_eq!(got.resolved.card.as_ref().unwrap().blur, Some(12));
    let grad = got.resolved.background.as_ref().unwrap().gradient.as_ref().unwrap();
    assert_eq!(grad.kind.as_deref(), Some("linear"));
    assert_eq!(got.warnings[0].required, 4.5);

    let design = AtlasDesign {
        preset: Some("glass".into()),
        color_scheme: Some("dark".into()),
        palette: Some(DesignPalette { primary: Some("#0F766E".into()), ..Default::default() }),
        ..Default::default()
    };
    c.design().put(&design).await.unwrap();
    c.design().patch(json!({"palette": {"primary": null}})).await.unwrap();
    c.design().put_organization("org_1", &design).await.unwrap();
    c.design().get_organization("org_1").await.unwrap();
    c.design().patch_organization("org_1", json!({"logo": null})).await.unwrap();

    let reqs = fake.requests();
    assert_eq!((reqs[0].method, path(&reqs[0])), (HttpMethod::Get, "/v1/instance/design".into()));
    assert_eq!(reqs[1].method, HttpMethod::Put);
    assert_eq!(
        body_json(&reqs[1]),
        json!({"design": {"preset": "glass", "colorScheme": "dark", "palette": {"primary": "#0F766E"}}})
    );
    assert_eq!(reqs[2].method, HttpMethod::Patch);
    assert_eq!(body_json(&reqs[2]), json!({"design": {"palette": {"primary": null}}}));
    assert_eq!((reqs[3].method, path(&reqs[3])), (HttpMethod::Put, "/v1/organizations/org_1/design".into()));
    assert_eq!((reqs[4].method, path(&reqs[4])), (HttpMethod::Get, "/v1/organizations/org_1/design".into()));
    assert_eq!((reqs[5].method, path(&reqs[5])), (HttpMethod::Patch, "/v1/organizations/org_1/design".into()));
}

#[tokio::test]
async fn design_preview_assets_and_catalog() {
    let fake = FakeTransport::new(|req| {
        let body = if req.url.contains("preview") {
            r#"{"object":"design_preview","scope":".atlas-root","css":".atlas-root{}","data_attributes":{"data-x":"1"},"font_stylesheets":[],"resolved":{"preset":"minimal"},"warnings":[],"html":"<div></div>"}"#
        } else if req.url.contains("catalog") {
            r#"{"presets":[],"fonts":[]}"#
        } else {
            r#"{"object":"list","data":[{"asset_id":"dasset_1","kind":"logo"}]}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let c = client(&fake);
    let p = c.design().preview(&AtlasDesign::default()).await.unwrap();
    assert_eq!(p.html, "<div></div>");
    assert_eq!(p.resolved.preset.as_deref(), Some("minimal"));
    assert_eq!(c.design().list_assets().await.unwrap().data[0].asset_id, "dasset_1");
    c.design().delete_asset("dasset_1").await.unwrap();
    assert!(c.design().catalog().await.unwrap()["presets"].is_array());

    let got: Vec<(HttpMethod, String)> = fake.requests().iter().map(|r| (r.method, path(r))).collect();
    assert_eq!(got[0], (HttpMethod::Post, "/v1/instance/design/preview".into()));
    assert_eq!(body_json(&fake.requests()[0]), json!({"design": {}}));
    assert_eq!(got[1], (HttpMethod::Get, "/v1/design/assets".into()));
    assert_eq!(got[2], (HttpMethod::Delete, "/v1/design/assets/dasset_1".into()));
    assert_eq!(got[3], (HttpMethod::Get, "/v1/design/catalog".into()));
}

// ── Sign in with Atlas apps (platform key) ────────────────────────────────

const APP: &str = r##"{"object":"atlas_id_app","id":"aidapp_1","client_id":"aid_1","name":"Acme",
  "branding":{"theme":"dark","accent_color":"#112233","background_color":null,"privacy_policy_url":null,
  "terms_of_service_url":null,"copy":{"sign_in_title":"Hi {app}"},"design":null},
  "redirect_uris":["https://acme.example/cb"],"post_logout_redirect_uris":["https://acme.example/bye"],
  "backchannel_logout_uri":"https://acme.example/bcl","backchannel_logout_session_required":true,
  "frontchannel_logout_uri":null,"frontchannel_logout_session_required":false,
  "allowed_scopes":["openid","email"],"type":"confidential","created_at":1,"updated_at":2,
  "client_secret":"aidsec_once"}"##;

#[tokio::test]
async fn atlas_id_apps_crud_with_logout_uris_and_branding() {
    let fake = FakeTransport::new(|req| {
        let body = if req.method == HttpMethod::Get && req.url.ends_with("/atlas_id_apps") {
            format!(r#"{{"object":"list","data":[{APP}],"issuer":"https://atlasauth.net","discovery_url":"https://atlasauth.net/.well-known/openid-configuration","limit":25}}"#)
        } else {
            APP.to_string()
        };
        HttpResponse { status: 200, body }
    });
    let platform = BackendClient::builder("psk_test_x")
        .transport(Arc::new(fake.clone()))
        .build()
        .unwrap();
    let apps = platform.platform().atlas_id_apps();

    let created = apps
        .create(
            &CreateAtlasIdAppBody {
                name: "Acme".into(),
                redirect_uris: vec!["https://acme.example/cb".into()],
                post_logout_redirect_uris: Some(vec!["https://acme.example/bye".into()]),
                backchannel_logout_uri: Some("https://acme.example/bcl".into()),
                backchannel_logout_session_required: Some(true),
                branding: Some(AtlasIdAppBrandingInput {
                    theme: Some(Some("dark".into())),
                    copy: Some(Some(AtlasIdAppCopy {
                        sign_in_title: Some(Some("Hi {app}".into())),
                        ..Default::default()
                    })),
                    design: Some(Some(AtlasDesign { preset: Some("midnight".into()), ..Default::default() })),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Some("idem_app"),
        )
        .await
        .unwrap();
    assert_eq!(created.client_secret.as_deref(), Some("aidsec_once"));
    assert_eq!(created.app_type, "confidential");
    assert!(created.backchannel_logout_session_required);
    assert_eq!(created.branding.as_ref().unwrap().copy["sign_in_title"], "Hi {app}");

    let list = apps.list().await.unwrap();
    assert_eq!(list.issuer, "https://atlasauth.net");
    assert_eq!(list.data[0].post_logout_redirect_uris, vec!["https://acme.example/bye".to_string()]);

    apps.update(
        "aidapp_1",
        &UpdateAtlasIdAppBody {
            backchannel_logout_uri: Some(None),
            post_logout_redirect_uris: Some(vec![]),
            branding: Some(Some(AtlasIdAppBrandingInput {
                accent_color: Some(None),
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    apps.get("aidapp_1").await.unwrap();
    apps.rotate_secret("aidapp_1").await.unwrap();
    apps.delete("aidapp_1").await.unwrap();
    apps.preview_design(&AtlasDesign::default()).await.ok();
    platform.platform().list_design_assets().await.ok();
    platform.platform().delete_design_asset("dasset_9").await.ok();

    let reqs = fake.requests();
    assert_eq!(header(&reqs[0], "authorization"), Some("Bearer psk_test_x"));
    assert_eq!(header(&reqs[0], "idempotency-key"), Some("idem_app"));
    assert_eq!(
        body_json(&reqs[0]),
        json!({
            "name": "Acme",
            "redirect_uris": ["https://acme.example/cb"],
            "post_logout_redirect_uris": ["https://acme.example/bye"],
            "backchannel_logout_uri": "https://acme.example/bcl",
            "backchannel_logout_session_required": true,
            "branding": {
                "theme": "dark",
                "copy": {"sign_in_title": "Hi {app}"},
                "design": {"preset": "midnight"}
            }
        })
    );
    assert_eq!((reqs[1].method, path(&reqs[1])), (HttpMethod::Get, "/v1/platform/atlas_id_apps".into()));
    assert_eq!((reqs[2].method, path(&reqs[2])), (HttpMethod::Patch, "/v1/platform/atlas_id_apps/aidapp_1".into()));
    assert_eq!(
        body_json(&reqs[2]),
        json!({"post_logout_redirect_uris": [], "backchannel_logout_uri": null, "branding": {"accent_color": null}})
    );
    let rest: Vec<(HttpMethod, String)> = reqs[3..].iter().map(|r| (r.method, path(r))).collect();
    assert_eq!(
        rest,
        vec![
            (HttpMethod::Get, "/v1/platform/atlas_id_apps/aidapp_1".into()),
            (HttpMethod::Post, "/v1/platform/atlas_id_apps/aidapp_1/rotate_secret".into()),
            (HttpMethod::Delete, "/v1/platform/atlas_id_apps/aidapp_1".into()),
            (HttpMethod::Post, "/v1/platform/atlas_id_apps/design/preview".into()),
            (HttpMethod::Get, "/v1/platform/design/assets".into()),
            (HttpMethod::Delete, "/v1/platform/design/assets/dasset_9".into()),
        ]
    );
}

#[tokio::test]
async fn platform_apps_routes() {
    let fake = FakeTransport::json_ok(r#"{"object":"app","id":"ins_1","name":"A","environment":"production","publishable_key":"pk_1","allowed_origins":[],"tags":["t"],"archived":false,"archived_at":null,"disabled":false,"created_at":1,"updated_at":1}"#);
    let c = client(&fake);
    let apps = c.platform().apps();
    let app = apps.get("ins_1").await.unwrap();
    assert_eq!(app.tags, vec!["t".to_string()]);
    apps.archive("ins_1").await.unwrap();
    apps.rotate_secret("ins_1", Some(3600), Some("k")).await.unwrap();
    apps.bulk_delete(&["a", "b"]).await.unwrap();
    let reqs = fake.requests();
    assert_eq!(path(&reqs[1]), "/v1/platform/apps/ins_1/archive");
    assert_eq!(body_json(&reqs[2]), json!({"overlap_seconds": 3600}));
    assert_eq!(body_json(&reqs[3]), json!({"ids": ["a", "b"]}));
}

// ── preflight + cookie consent ────────────────────────────────────────────

#[tokio::test]
async fn preflight_findings_are_typed() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"preflight","ok":false,"checked_at":1760000000000,"findings":[
           {"severity":"error","code":"SOCIAL_PROVIDER_MISSING_CREDENTIALS","message":"Google is on without credentials","fix":"Add a client id","subject":{"provider":"google"}},
           {"severity":"info","code":"X","message":"m","fix":"f"}]}"#,
    );
    let pf = client(&fake).instance().preflight().await.unwrap();
    assert!(!pf.ok);
    assert_eq!(pf.findings.len(), 2);
    assert!(pf.findings[0].is_error());
    assert_eq!(pf.findings[0].subject.as_ref().unwrap()["provider"], "google");
    assert!(pf.findings[1].subject.is_none());
    assert_eq!(path(&fake.requests()[0]), "/v1/instance/preflight");
}

#[tokio::test]
async fn cookie_consent_get_set_delete() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"cookie_consent","enabled":true,"script_url":"https://cmp.example/s.js","script_id":null,"site_id":"s1","blocking_mode":"auto","extra_origins":["https://cdn.cmp.example"]}"#,
    );
    let c = client(&fake);
    let cc = c.instance().get_cookie_consent().await.unwrap();
    assert!(cc.enabled);
    assert_eq!(cc.extra_origins.len(), 1);
    c.instance()
        .set_cookie_consent(&SetCookieConsentBody {
            script_url: "https://cmp.example/s.js".into(),
            site_id: Some("s1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    c.instance().delete_cookie_consent().await.unwrap();
    let reqs = fake.requests();
    assert_eq!(reqs[1].method, HttpMethod::Put);
    assert_eq!(body_json(&reqs[1]), json!({"script_url": "https://cmp.example/s.js", "site_id": "s1"}));
    assert_eq!((reqs[2].method, path(&reqs[2])), (HttpMethod::Delete, "/v1/instance/cookie_consent".into()));
}

// ── messaging providers ───────────────────────────────────────────────────

#[tokio::test]
async fn messaging_providers_are_typed_per_transport() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"messaging_provider","channel":"email","transport":"smtp","from_address":"no-reply@acme.example","status":"active","config":{"host":"smtp.acme.example","port":587},"secrets_set":{"password":true},"updated_at":5}"#,
    );
    let c = client(&fake);
    let saved = c
        .messaging_providers()
        .set_email(&EmailProviderConfig::Smtp {
            from_address: Some("no-reply@acme.example".into()),
            config: SmtpConfig {
                host: Some("smtp.acme.example".into()),
                port: Some(587),
                username: Some("u".into()),
                password: Some("p".into()),
                ..Default::default()
            },
        })
        .await
        .unwrap();
    assert_eq!(saved.transport, "smtp");
    assert_eq!(saved.secrets_set["password"], true);
    c.messaging_providers()
        .set_sms(&SmsProviderConfig::AwsSns {
            from_address: None,
            config: AwsSnsConfig { region: Some("eu-west-1".into()), ..Default::default() },
        })
        .await
        .unwrap();
    c.messaging_providers().test(MessagingChannel::Sms, "+15550001111").await.unwrap();
    c.messaging_providers().delete(MessagingChannel::Email).await.unwrap();

    let reqs = fake.requests();
    assert_eq!((reqs[0].method, path(&reqs[0])), (HttpMethod::Put, "/v1/messaging_providers/email".into()));
    assert_eq!(
        body_json(&reqs[0]),
        json!({"transport": "smtp", "from_address": "no-reply@acme.example",
               "config": {"host": "smtp.acme.example", "port": 587, "username": "u", "password": "p"}})
    );
    assert_eq!(body_json(&reqs[1]), json!({"transport": "aws_sns", "config": {"region": "eu-west-1"}}));
    assert_eq!(path(&reqs[2]), "/v1/messaging_providers/sms/test");
    assert_eq!(body_json(&reqs[2]), json!({"to": "+15550001111"}));
    assert_eq!((reqs[3].method, path(&reqs[3])), (HttpMethod::Delete, "/v1/messaging_providers/email".into()));
}

#[tokio::test]
async fn messaging_providers_get_reads_both_channels() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"messaging_providers","email":{"channel":"email","transport":"resend","from_address":null,"status":"active","config":{},"secrets_set":{"api_key":true},"updated_at":1},"sms":null}"#,
    );
    let got = client(&fake).messaging_providers().get().await.unwrap();
    assert_eq!(got.email.unwrap().transport, "resend");
    assert!(got.sms.is_none());
}

// ── OAuth providers ───────────────────────────────────────────────────────

#[tokio::test]
async fn oauth_providers_filters_display_fields_and_wallet_settings() {
    let fake = FakeTransport::new(|req| {
        let body = if req.method == HttpMethod::Get && req.url.contains("/v1/oauth_providers?") {
            r#"{"object":"list","data":[{"object":"oauth_provider","provider":"google","display_name":"Google","configured":true,"enabled":true,"allow_sign_in":true,"allow_sign_up":true,"mode":"redirect","icon_url":"https://cdn/x.svg","setting_values":{}}],"has_more":false}"#
        } else {
            r#"{"object":"oauth_provider","provider":"siwe","configured":true,"enabled":false,"setting_values":{"domain":"acme.example"},"updated_fields":["settings.domain","settings.rpc_url"]}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let c = client(&fake);
    let page = c
        .oauth_providers()
        .list(&OAuthProviderFilter { provider: vec!["google".into(), "github".into()], configured: Some(true) })
        .await
        .unwrap();
    assert_eq!(page.data[0].mode.as_deref(), Some("redirect"));
    assert_eq!(page.data[0].icon_url.as_deref(), Some("https://cdn/x.svg"));

    let upd = c
        .oauth_providers()
        .upsert(
            "siwe",
            &UpsertOAuthProviderBody {
                display_name: Some("Ethereum".into()),
                settings: Some(
                    WalletSettings::new()
                        .domain(Some("acme.example"))
                        .chain_ids(Some(vec![1, 10]))
                        .rpc_url(None)
                        .build(),
                ),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(upd.setting_values["domain"], "acme.example");
    assert_eq!(upd.updated_fields.len(), 2);

    c.oauth_providers().set_enabled("google", true).await.unwrap();
    c.oauth_providers().set_scope("google", true, false).await.unwrap();
    c.oauth_providers().test("google").await.unwrap();
    c.oauth_providers().delete("google").await.unwrap();

    let reqs = fake.requests();
    assert_eq!(path(&reqs[0]), "/v1/oauth_providers?provider=google%2Cgithub&configured=true");
    assert_eq!((reqs[1].method, path(&reqs[1])), (HttpMethod::Put, "/v1/oauth_providers/siwe".into()));
    assert_eq!(
        body_json(&reqs[1]),
        json!({"settings": {"domain": "acme.example", "chain_ids": [1, 10], "rpc_url": null}, "display_name": "Ethereum"})
    );
    assert_eq!(body_json(&reqs[2]), json!({"enabled": true}));
    assert_eq!(path(&reqs[2]), "/v1/oauth_providers/google/enabled");
    assert_eq!(body_json(&reqs[3]), json!({"allow_sign_in": true, "allow_sign_up": false}));
    assert_eq!(path(&reqs[4]), "/v1/oauth_providers/google/test");
    assert_eq!(reqs[5].method, HttpMethod::Delete);
}

// ── webhook endpoints ─────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_endpoints_full_lifecycle() {
    let fake = FakeTransport::new(|req| {
        let body = if req.method == HttpMethod::Get && req.url.ends_with("/v1/webhook_endpoints") {
            r#"{"object":"list","data":[{"object":"webhook_endpoint","id":"we_1","url":"https://a/h","enabled_events":["*"],"active":true,"failing_since":null,"disabled_at":null,"created_at":1}],"available_events":["user.created"],"retry_schedule_ms":[1000,5000],"max_attempts":3}"#
        } else if req.url.contains("/deliveries?") {
            r#"{"object":"list","data":[{"id":"wd_1","event_id":"evt_1","event_type":"user.created","attempt_number":1,"max_attempts":3,"payload":{"a":1},"status":"failed","http_status":500,"response_snippet":"boom","next_retry_at":null,"delivered_at":null,"created_at":2}]}"#
        } else if req.url.ends_with("_secret") {
            r#"{"object":"webhook_secret","secret":"whsec_x"}"#
        } else if req.url.ends_with("/test") || req.url.ends_with("/redeliver") {
            r#"{"object":"webhook_delivery","id":"wd_2","event_id":"evt_2","status":"pending","note":"queued"}"#
        } else {
            r#"{"object":"webhook_endpoint","id":"we_1","url":"https://a/h","enabled_events":["user.created"],"active":true,"failing_since":null,"disabled_at":null,"created_at":1,"secret":"whsec_new"}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let c = client(&fake);
    let w = c.webhook_endpoints();
    let list = w.list().await.unwrap();
    assert_eq!(list.available_events, vec!["user.created".to_string()]);
    assert_eq!(list.retry_schedule_ms, vec![1000, 5000]);
    let created = w.create("https://a/h", Some(vec!["user.created".into()]), Some("idem_w")).await.unwrap();
    assert_eq!(created.secret.as_deref(), Some("whsec_new"));
    w.update("we_1", &UpdateWebhookEndpointBody { active: Some(false), ..Default::default() }).await.unwrap();
    assert_eq!(w.reveal_secret("we_1").await.unwrap().secret, "whsec_x");
    w.rotate_secret("we_1").await.unwrap();
    assert_eq!(w.test("we_1").await.unwrap().status, "pending");
    let d = w.deliveries("we_1", Some(10)).await.unwrap();
    assert_eq!(d.data[0].http_status, Some(500));
    w.redeliver("we_1", "wd_1").await.unwrap();
    w.delete("we_1").await.unwrap();

    let got: Vec<(HttpMethod, String)> = fake.requests().iter().map(|r| (r.method, path(r))).collect();
    assert_eq!(
        got,
        vec![
            (HttpMethod::Get, "/v1/webhook_endpoints".into()),
            (HttpMethod::Post, "/v1/webhook_endpoints".into()),
            (HttpMethod::Patch, "/v1/webhook_endpoints/we_1".into()),
            (HttpMethod::Post, "/v1/webhook_endpoints/we_1/reveal_secret".into()),
            (HttpMethod::Post, "/v1/webhook_endpoints/we_1/rotate_secret".into()),
            (HttpMethod::Post, "/v1/webhook_endpoints/we_1/test".into()),
            (HttpMethod::Get, "/v1/webhook_endpoints/we_1/deliveries?limit=10".into()),
            (HttpMethod::Post, "/v1/webhook_endpoints/we_1/deliveries/wd_1/redeliver".into()),
            (HttpMethod::Delete, "/v1/webhook_endpoints/we_1".into()),
        ]
    );
    let reqs = fake.requests();
    assert_eq!(body_json(&reqs[1]), json!({"url": "https://a/h", "enabled_events": ["user.created"]}));
    assert_eq!(header(&reqs[1], "idempotency-key"), Some("idem_w"));
    assert_eq!(body_json(&reqs[2]), json!({"active": false}));
}

// ── entitlement overrides ─────────────────────────────────────────────────

#[tokio::test]
#[allow(deprecated)]
async fn entitlement_override_get_lists_and_filters_since_there_is_no_get_route() {
    let fake = FakeTransport::new(|req| {
        let body = if req.method == HttpMethod::Post {
            r#"{"object":"entitlement_override","id":"eo_3","subject_type":"org","subject_id":"org_1","plan":"enterprise"}"#
        } else {
            r#"{"object":"list","data":[
            {"object":"entitlement_override","id":"eo_1","subject_type":"org","subject_id":"org_1","plan":"enterprise","features":null,"limits":null,"expires_at":null,"created_by":"ak_1","created_at":5},
            {"object":"entitlement_override","id":"eo_2","subject_type":"user","subject_id":"user_1","plan":null,"features":["sso"],"limits":{"seats":5},"expires_at":99,"created_by":"ak_1","created_at":6}],"has_more":false}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let c = client(&fake);
    let eo = c.entitlement_overrides().get("eo_2").await.unwrap();
    assert_eq!(eo.subject_id, "user_1");
    assert_eq!(eo.created_at, Some(6));
    let err = c.entitlement_overrides().get("eo_missing").await.unwrap_err();
    match err {
        BackendError::Api(e) => {
            assert_eq!(e.status, 404);
            assert!(e.has_code(codes::NOT_FOUND));
        }
        other => panic!("{other:?}"),
    }
    // Both lookups went to the LIST route — never to a non-existent /:id GET.
    for r in fake.requests() {
        assert_eq!((r.method, path(&r)), (HttpMethod::Get, "/v1/entitlement_overrides".into()));
    }

    c.entitlement_overrides()
        .create(
            &CreateEntitlementOverrideBody {
                subject_type: "org".into(),
                subject_id: "org_1".into(),
                plan: Some("enterprise".into()),
                ..Default::default()
            },
            Some("idem_eo"),
        )
        .await
        .unwrap();
    c.entitlement_overrides().list(Some("org"), Some("org_1")).await.unwrap();
    c.entitlement_overrides().delete("eo_1").await.unwrap();
    c.org_platform("org_1").entitlements().await.unwrap();
    let reqs = fake.requests();
    assert_eq!(body_json(&reqs[2]), json!({"subject_type": "org", "subject_id": "org_1", "plan": "enterprise"}));
    assert_eq!(path(&reqs[3]), "/v1/entitlement_overrides?subject_type=org&subject_id=org_1");
    assert_eq!((reqs[4].method, path(&reqs[4])), (HttpMethod::Delete, "/v1/entitlement_overrides/eo_1".into()));
    assert_eq!(path(&reqs[5]), "/v1/organizations/org_1/entitlements");
}

// ── notification categories ───────────────────────────────────────────────

#[tokio::test]
async fn notification_categories_send_key_and_label() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"list","data":[{"object":"notification_category","id":"nc_1","key":"digest","label":"Weekly digest","optional":true,"created_at":1}]}"#,
    );
    let c = client(&fake);
    c.notification_categories()
        .create(&NotificationCategoryBody { key: Some("digest".into()), label: Some("Weekly digest".into()), ..Default::default() })
        .await
        .ok();
    // The older field names still work, sent under the server's names.
    c.notification_categories()
        .create(&NotificationCategoryBody { name: Some("news".into()), description: Some("News".into()), ..Default::default() })
        .await
        .ok();
    c.notification_categories()
        .update("digest", &NotificationCategoryBody { key: Some("ignored".into()), label: Some("Digest".into()), ..Default::default() })
        .await
        .ok();
    let got = c.notification_categories().get("digest").await.unwrap();
    assert_eq!(got.label.as_deref(), Some("Weekly digest"));

    let reqs = fake.requests();
    assert_eq!(body_json(&reqs[0]), json!({"key": "digest", "label": "Weekly digest"}));
    assert_eq!(body_json(&reqs[1]), json!({"key": "news", "label": "News"}));
    assert_eq!((reqs[2].method, path(&reqs[2])), (HttpMethod::Put, "/v1/notification_categories/digest".into()));
    assert_eq!(body_json(&reqs[2]), json!({"label": "Digest"}));
    assert_eq!((reqs[3].method, path(&reqs[3])), (HttpMethod::Get, "/v1/notification_categories".into()));
}

// ── org policy ────────────────────────────────────────────────────────────

#[tokio::test]
async fn org_policy_is_typed_with_null_to_clear() {
    let fake = FakeTransport::json_ok(
        r#"{"object":"organization_policy","organization_id":"org_1","policy":{"requireMfa":true,"allowedSignInMethods":["password","oauth_google"],"maxSessionAgeSeconds":3600,"endUserPool":{"enabled":true,"requireApproval":true},"futureKey":1}}"#,
    );
    let c = client(&fake);
    let res = c
        .organizations()
        .patch_policy(
            "org_1",
            &OrgPolicyPatch {
                require_mfa: Some(Some(true)),
                ip_allowlist: Some(None),
                end_user_pool: Some(Some(EndUserPoolPolicy { enabled: true, require_approval: Some(true), allow_hosted_signup: None })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let typed = res.typed().unwrap();
    assert_eq!(typed.require_mfa, Some(true));
    assert_eq!(typed.max_session_age_seconds, Some(3600));
    assert_eq!(typed.end_user_pool.as_ref().unwrap().require_approval, Some(true));
    assert_eq!(typed.extra["futureKey"], 1);

    let req = &fake.requests()[0];
    assert_eq!((req.method, path(req)), (HttpMethod::Patch, "/v1/organizations/org_1/policy".into()));
    assert_eq!(
        body_json(req),
        json!({"requireMfa": true, "ipAllowlist": null, "endUserPool": {"enabled": true, "requireApproval": true}})
    );
}
