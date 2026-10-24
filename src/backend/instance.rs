//! Instance configuration surfaces: the setup preflight, the hosted-page
//! cookie-consent script, BYOK email/SMS delivery providers, social sign-in
//! (OAuth) providers, and webhook endpoints.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::pagination::Query;
use super::resources::{body_of, seg, ListPage};

// ── instance: preflight + cookie consent ──────────────────────────────────

/// One finding from [`Instance::preflight`].
#[derive(Debug, Clone, Deserialize)]
pub struct PreflightFinding {
    /// `error`, `warning`, or `info`.
    #[serde(default)]
    pub severity: String,
    /// A stable code to branch on.
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
    /// How to fix it.
    #[serde(default)]
    pub fix: String,
    /// What the finding is about (e.g. `{ "provider": "google" }`), when it
    /// concerns one object.
    #[serde(default)]
    pub subject: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PreflightFinding {
    /// Whether this finding is an error (blocks sign-in somewhere).
    pub fn is_error(&self) -> bool {
        self.severity == "error"
    }
}

/// The result of [`Instance::preflight`]. `ok` is true when no finding is an
/// error.
#[derive(Debug, Clone, Deserialize)]
pub struct Preflight {
    #[serde(default)]
    pub ok: bool,
    /// Epoch milliseconds.
    #[serde(default)]
    pub checked_at: i64,
    #[serde(default)]
    pub findings: Vec<PreflightFinding>,
    /// Atlas browser SDK versions seen in the last 7 days (newest first), each
    /// with the advisories that apply to it.
    #[serde(default)]
    pub sdk_versions_seen: Vec<SdkVersionSeen>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An Atlas browser SDK version that called the instance recently.
#[derive(Debug, Clone, Deserialize)]
pub struct SdkVersionSeen {
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub version: String,
    /// Epoch milliseconds.
    #[serde(default)]
    pub last_seen_at: i64,
    #[serde(default)]
    pub advisories: Vec<SdkAdvisory>,
}

/// An advisory published for an Atlas browser SDK version range.
#[derive(Debug, Clone, Deserialize)]
pub struct SdkAdvisory {
    #[serde(default)]
    pub package: String,
    /// The affected range, e.g. `<0.8.1`.
    #[serde(default)]
    pub affected: String,
    #[serde(default)]
    pub fixed_in: String,
    /// A stable code, e.g. `email_code_sign_in`.
    #[serde(default)]
    pub reason: String,
    /// `critical`, `high`, `medium` or `low`.
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub published_at: String,
}

/// The cookie-consent script injected into the hosted sign-in, sign-up and
/// account pages.
#[derive(Debug, Clone, Deserialize)]
pub struct CookieConsent {
    /// `false` when no script is set.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub script_url: Option<String>,
    #[serde(default)]
    pub script_id: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub blocking_mode: Option<String>,
    #[serde(default)]
    pub extra_origins: Vec<String>,
    /// The footer "Cookie settings" link; `None` when there is none.
    #[serde(default)]
    pub settings_link: Option<CookieSettingsLink>,
    /// `page` (the script tag carries the page language) or `browser`.
    #[serde(default)]
    pub culture: Option<String>,
    /// Every cookie and browser-storage key Atlas writes for this instance,
    /// for your cookie policy (all strictly necessary).
    #[serde(default)]
    pub declared_cookies: Vec<DeclaredCookie>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A cookie or browser-storage key Atlas writes for the instance.
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredCookie {
    /// The exact name, or `None` when `pattern` describes a family of keys.
    #[serde(default)]
    pub name: Option<String>,
    /// A `*` wildcard for keys with an id suffix, e.g. `atlasid:*`.
    #[serde(default)]
    pub pattern: Option<String>,
    /// `cookie`, `localStorage`, `sessionStorage` or `indexedDB`.
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub domain: String,
    /// `None` = browser session (cookie) or until cleared (storage).
    #[serde(default)]
    pub lifetime_seconds: Option<i64>,
    #[serde(default)]
    pub lifetime: String,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub written_when: String,
    /// `atlas_frontend_api` or `atlas_sdk`.
    #[serde(default)]
    pub set_by: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Known `settings_link.preset` values. A response's `preset` stays a plain
/// string, so a value added later still parses.
pub mod cookie_settings_link_presets {
    /// Adds `data-cc="show-settings"`.
    pub const COOKIEMUNCH: &str = "cookiemunch";
    /// Calls `Cookiebot.renew()`.
    pub const COOKIEBOT: &str = "cookiebot";
    /// Calls `OneTrust.ToggleInfoDisplay()`.
    pub const ONETRUST: &str = "onetrust";
    /// Adds nothing: set the trigger through `attributes`.
    pub const CUSTOM: &str = "custom";
}

/// The "Cookie settings" link rendered in the footer of the hosted sign-in,
/// sign-up and account pages and Sign in with Atlas pages, as returned on a
/// [`CookieConsent`].
#[derive(Debug, Clone, Deserialize)]
pub struct CookieSettingsLink {
    #[serde(default)]
    pub label: String,
    /// One of [`cookie_settings_link_presets`], or `None`.
    #[serde(default)]
    pub preset: Option<String>,
    /// The attributes you set.
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    /// The attributes the rendered link carries: yours plus the preset's
    /// trigger.
    #[serde(default)]
    pub rendered_attributes: HashMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `settings_link` on [`SetCookieConsentBody`]: a footer "Cookie settings"
/// link that reopens the consent preferences. Needs a `preset` or at least one
/// attribute (400 otherwise).
#[derive(Debug, Clone, Default, Serialize)]
pub struct CookieSettingsLinkInput {
    /// The link text, 1-60 characters, e.g. "Cookie settings".
    pub label: String,
    /// One of [`cookie_settings_link_presets`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Extra attributes: `data-*`, `aria-*`, `id`, `class` and `href` (an https
    /// URL or a `#fragment`); at most 10, values up to 200 characters. Event
    /// handlers, `style` and `data-atlas-*` are refused with a 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

/// Body for `PUT /v1/instance/cookie_consent` (replaces the whole setting).
/// `script_url` and every `extra_origins` entry must be https URLs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SetCookieConsentBody {
    pub script_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_origins: Option<Vec<String>>,
    /// A footer "Cookie settings" link; `None` (omitted) means no link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_link: Option<CookieSettingsLinkInput>,
    /// `page` (default: the script tag carries the page language) or `browser`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub culture: Option<String>,
}

/// The `/v1/instance` namespace. Reached via [`BackendClient::instance`].
pub struct Instance<'a> {
    pub(super) client: &'a BackendClient,
}

impl Instance<'_> {
    /// `GET /v1/instance/preflight` — check the instance setup in one call.
    pub async fn preflight(&self) -> Result<Preflight, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/preflight", &[], None, None).await
    }
    /// `GET /v1/instance/cookie_consent`.
    pub async fn get_cookie_consent(&self) -> Result<CookieConsent, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/cookie_consent", &[], None, None).await
    }
    /// `PUT /v1/instance/cookie_consent` — set (replace) the consent script.
    pub async fn set_cookie_consent(&self, body: &SetCookieConsentBody) -> Result<CookieConsent, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/instance/cookie_consent", &[], body_of(body)?, None)
            .await
    }
    /// `DELETE /v1/instance/cookie_consent` — turn the consent script off.
    pub async fn delete_cookie_consent(&self) -> Result<CookieConsent, BackendError> {
        self.client.request(HttpMethod::Delete, "/v1/instance/cookie_consent", &[], None, None).await
    }
}

// ── allowed origins with an integration ───────────────────────────────────

/// One `allowed_origins` entry that may also declare how the origin signs in.
/// With no integration it is sent as the plain origin string (which keeps the
/// hint the origin already had); otherwise as `{ "origin", "integration" }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedOriginEntry {
    pub origin: String,
    /// [`AllowedOriginEntry::REDIRECT`], [`AllowedOriginEntry::EMBEDDED`],
    /// [`AllowedOriginEntry::AUTO`] (clear the hint), or `None` (keep it).
    pub integration: Option<String>,
}

impl AllowedOriginEntry {
    /// Hosted-redirect OIDC: the app never runs the embedded components.
    pub const REDIRECT: &'static str = "redirect";
    /// The sign-in components run on the origin.
    pub const EMBEDDED: &'static str = "embedded";
    /// Clear the declared integration; Atlas infers it.
    pub const AUTO: &'static str = "auto";

    /// A plain origin: keeps its current hint.
    pub fn new(origin: impl Into<String>) -> Self {
        Self { origin: origin.into(), integration: None }
    }
    /// An origin with a declared integration.
    pub fn with_integration(origin: impl Into<String>, integration: impl Into<String>) -> Self {
        Self { origin: origin.into(), integration: Some(integration.into()) }
    }
}

impl From<&str> for AllowedOriginEntry {
    fn from(origin: &str) -> Self {
        Self::new(origin)
    }
}

impl From<String> for AllowedOriginEntry {
    fn from(origin: String) -> Self {
        Self::new(origin)
    }
}

impl From<AllowedOriginEntry> for Value {
    fn from(e: AllowedOriginEntry) -> Self {
        match e.integration {
            None => Value::String(e.origin),
            Some(i) => serde_json::json!({ "origin": e.origin, "integration": i }),
        }
    }
}

impl Serialize for AllowedOriginEntry {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Value::from(self.clone()).serialize(s)
    }
}

impl super::types::InstanceUpdateBody {
    /// Set `allowed_origins` from entries that may also declare how each origin
    /// signs in (strings work too: `["https://a.example".into()]`).
    pub fn with_allowed_origin_entries<I, E>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<AllowedOriginEntry>,
    {
        self.allowed_origins = Some(entries.into_iter().map(|e| Value::from(e.into())).collect());
        self
    }
}

// ── messaging providers ───────────────────────────────────────────────────

/// Resend config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ResendConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// Amazon SES config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SesConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// SMTP config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SmtpConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Brevo config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BrevoConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// Mailgun config. `region` is `us` or `eu`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MailgunConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// The email delivery provider for `PUT /v1/messaging_providers/email`, one
/// variant per transport. Secrets are write-only; on an update of the same
/// transport an omitted (`None`) secret keeps the stored one.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum EmailProviderConfig {
    Resend {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: ResendConfig,
    },
    Ses {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: SesConfig,
    },
    Smtp {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: SmtpConfig,
    },
    Brevo {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: BrevoConfig,
    },
    Mailgun {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: MailgunConfig,
    },
}

/// Twilio config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TwilioConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whatsapp_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice_from: Option<String>,
}

/// Vonage config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VonageConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// MessageBird config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MessagebirdConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Plivo config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PlivoConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Telnyx config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TelnyxConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Sinch config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SinchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Infobip config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InfobipConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// ClickSend config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClicksendConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Bandwidth config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BandwidthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Amazon SNS config.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AwsSnsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// The SMS delivery provider for `PUT /v1/messaging_providers/sms`, one variant
/// per transport. Secrets are write-only.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum SmsProviderConfig {
    Twilio {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: TwilioConfig,
    },
    Vonage {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: VonageConfig,
    },
    Messagebird {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: MessagebirdConfig,
    },
    Plivo {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: PlivoConfig,
    },
    Telnyx {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: TelnyxConfig,
    },
    Sinch {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: SinchConfig,
    },
    Infobip {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: InfobipConfig,
    },
    Clicksend {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: ClicksendConfig,
    },
    Bandwidth {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: BandwidthConfig,
    },
    AwsSns {
        #[serde(skip_serializing_if = "Option::is_none")]
        from_address: Option<String>,
        config: AwsSnsConfig,
    },
}

/// A configured delivery provider. Never carries a secret value —
/// `secrets_set` says which secret keys are stored.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagingProvider {
    /// The provider id: pass it as `provider_id` to managed email or the
    /// development sender.
    #[serde(default)]
    pub id: Option<String>,
    /// `email` or `sms`.
    #[serde(default)]
    pub channel: String,
    /// `standard`, `development` or `managed_domain`.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub from_address: Option<String>,
    #[serde(default)]
    pub status: String,
    /// Non-secret config.
    #[serde(default)]
    pub config: Map<String, Value>,
    #[serde(default)]
    pub secrets_set: Map<String, Value>,
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Both delivery providers (`None` when a channel is not configured).
#[derive(Debug, Clone, Deserialize)]
pub struct MessagingProviders {
    #[serde(default)]
    pub email: Option<MessagingProvider>,
    #[serde(default)]
    pub sms: Option<MessagingProvider>,
    /// The Atlas-managed sending domain summary (`from_address`, `domain`,
    /// `status`, `verified`), when one is set up.
    #[serde(default)]
    pub managed_email: Option<Value>,
    /// The email provider in development mode (`enabled`, `from_address`),
    /// when it is.
    #[serde(default)]
    pub development_email: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A delivery channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingChannel {
    Email,
    Sms,
}

impl MessagingChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessagingChannel::Email => "email",
            MessagingChannel::Sms => "sms",
        }
    }
}

/// Options for [`MessagingProvidersApi::delete_with`].
#[derive(Debug, Clone, Default)]
pub struct DeleteMessagingProviderParams {
    /// Send `?force=true`: remove the email provider even while
    /// email-dependent features are on.
    pub force: bool,
}

/// The `/v1/messaging_providers` namespace (bring-your-own email and SMS
/// delivery). Reached via [`BackendClient::messaging_providers`].
pub struct MessagingProvidersApi<'a> {
    pub(super) client: &'a BackendClient,
}

impl MessagingProvidersApi<'_> {
    /// `GET /v1/messaging_providers`.
    pub async fn get(&self) -> Result<MessagingProviders, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/messaging_providers", &[], None, None).await
    }
    /// `PUT /v1/messaging_providers/email`.
    pub async fn set_email(&self, provider: &EmailProviderConfig) -> Result<MessagingProvider, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/messaging_providers/email", &[], body_of(provider)?, None)
            .await
    }
    /// `PUT /v1/messaging_providers/email` with a provider mode: `development`
    /// lets a development instance send without a verified domain (409 on a
    /// production instance), `standard` sends normally, `None` keeps the
    /// stored mode.
    pub async fn set_email_with_mode(
        &self,
        provider: &EmailProviderConfig,
        mode: Option<&str>,
    ) -> Result<MessagingProvider, BackendError> {
        let mut body = body_of(provider)?.unwrap_or(Value::Null);
        if let (Some(m), Some(obj)) = (mode, body.as_object_mut()) {
            obj.insert("mode".into(), Value::String(m.into()));
        }
        self.client
            .request(HttpMethod::Put, "/v1/messaging_providers/email", &[], Some(body), None)
            .await
    }
    /// `PUT /v1/messaging_providers/sms`.
    pub async fn set_sms(&self, provider: &SmsProviderConfig) -> Result<MessagingProvider, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/messaging_providers/sms", &[], body_of(provider)?, None)
            .await
    }
    /// `DELETE /v1/messaging_providers/:channel`. Use
    /// [`delete_with`](Self::delete_with) to force the removal of an email
    /// provider that email-dependent features still need.
    pub async fn delete(&self, channel: MessagingChannel) -> Result<Value, BackendError> {
        self.delete_with(channel, &DeleteMessagingProviderParams::default()).await
    }
    /// `DELETE /v1/messaging_providers/:channel` with options.
    ///
    /// Removing the email provider is refused with `409`
    /// [`codes::EMAIL_PROVIDER_IN_USE`](crate::backend::codes::EMAIL_PROVIDER_IN_USE)
    /// while email-dependent features are on and nothing else would deliver
    /// email; the error's `meta.features` lists them (e.g. `emailCode`,
    /// `emailLink`, `emailVerification`, `passwordReset`). `force: true`
    /// removes it anyway.
    pub async fn delete_with(
        &self,
        channel: MessagingChannel,
        params: &DeleteMessagingProviderParams,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/messaging_providers/{}", channel.as_str());
        let mut q = Vec::new();
        if params.force {
            q.push(("force", "true".to_string()));
        }
        self.client.request(HttpMethod::Delete, &path, &q, None, None).await
    }
    /// `POST /v1/messaging_providers/:channel/test` — send a test message to
    /// `to` (an email address or phone number).
    pub async fn test(&self, channel: MessagingChannel, to: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/messaging_providers/{}/test", channel.as_str());
        let body = serde_json::json!({ "to": to });
        self.client.request(HttpMethod::Post, &path, &[], Some(body), None).await
    }
}

// ── OAuth providers ───────────────────────────────────────────────────────

/// A social sign-in provider: its catalog entry plus configured state. Never a
/// secret.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProvider {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_sign_in: bool,
    #[serde(default)]
    pub allow_sign_up: bool,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub has_secret: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub default_scopes: Vec<String>,
    /// `native` or `redirect`.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub native: Option<bool>,
    /// A custom button icon, when set.
    #[serde(default)]
    pub icon_url: Option<String>,
    /// Current settings values (e.g. a wallet provider's `domain`, `chain_ids`).
    #[serde(default)]
    pub setting_values: Map<String, Value>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub custom_redirect_uri: Option<String>,
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Filters for [`OAuthProviders::list`].
#[derive(Debug, Clone, Default)]
pub struct OAuthProviderFilter {
    /// Only these catalog keys (e.g. `google`, `github`).
    pub provider: Vec<String>,
    /// Only configured (`true`) or unconfigured (`false`) providers.
    pub configured: Option<bool>,
}

/// Body for `PUT /v1/oauth_providers/:provider`. Every field is optional:
/// credentials (`client_id`, `client_secret`, `scopes`, …), display-only
/// fields (`display_name`, `icon_url`, `mode`), or — for the wallet providers
/// (`siwe`, `siws`, `siwf`) — verifier `settings`. Saving does not enable the
/// provider; use [`OAuthProviders::set_enabled`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpsertOAuthProviderBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Write-only, stored encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Extra provider-specific credential values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Map<String, Value>>,
    /// Provider settings. For the wallets: siwe `domain`, `chain_ids`,
    /// `rpc_url`; siws `domain`, `networks`; siwf `domain`, `chain_ids`,
    /// `optimism_rpc_url`, `id_registry_address`. A `null` (or empty string)
    /// value clears that setting. See [`WalletSettings`] for a typed builder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native: Option<bool>,
    /// `native`, `redirect`, or `""` to clear the override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The button label shown everywhere Atlas draws this provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The button icon (https URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// A typed builder for wallet-provider `settings`
/// ([`UpsertOAuthProviderBody::settings`]). Each setter takes an `Option`:
/// `Some(v)` sets the value, `None` sends `null` to clear it; a setting never
/// touched is left out.
#[derive(Debug, Clone, Default)]
pub struct WalletSettings(Map<String, Value>);

impl WalletSettings {
    pub fn new() -> Self {
        WalletSettings::default()
    }
    fn put(mut self, key: &str, value: Option<Value>) -> Self {
        self.0.insert(key.to_string(), value.unwrap_or(Value::Null));
        self
    }
    /// The domain the sign-in message binds (siwe, siws, siwf).
    pub fn domain(self, v: Option<&str>) -> Self {
        self.put("domain", v.map(|s| Value::String(s.to_string())))
    }
    /// Allowed chain ids (siwe, siwf).
    pub fn chain_ids(self, v: Option<Vec<u64>>) -> Self {
        self.put("chain_ids", v.map(Value::from))
    }
    /// An https JSON-RPC URL (siwe).
    pub fn rpc_url(self, v: Option<&str>) -> Self {
        self.put("rpc_url", v.map(|s| Value::String(s.to_string())))
    }
    /// Solana networks, e.g. `mainnet`, `devnet` (siws).
    pub fn networks(self, v: Option<Vec<String>>) -> Self {
        self.put("networks", v.map(Value::from))
    }
    /// An https Optimism JSON-RPC URL (siwf).
    pub fn optimism_rpc_url(self, v: Option<&str>) -> Self {
        self.put("optimism_rpc_url", v.map(|s| Value::String(s.to_string())))
    }
    /// The Farcaster ID registry contract address (siwf).
    pub fn id_registry_address(self, v: Option<&str>) -> Self {
        self.put("id_registry_address", v.map(|s| Value::String(s.to_string())))
    }
    /// Finish: the `settings` map.
    pub fn build(self) -> Map<String, Value> {
        self.0
    }
}

/// The acknowledgement `PUT /v1/oauth_providers/:provider` returns.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProviderUpdate {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub setting_values: Map<String, Value>,
    #[serde(default)]
    pub updated_fields: Vec<String>,
    #[serde(default)]
    pub warning: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/v1/oauth_providers` namespace. Reached via
/// [`BackendClient::oauth_providers`].
pub struct OAuthProviders<'a> {
    pub(super) client: &'a BackendClient,
}

impl OAuthProviders<'_> {
    /// `GET /v1/oauth_providers` — the provider catalog with configured state,
    /// optionally filtered.
    pub async fn list(&self, filter: &OAuthProviderFilter) -> Result<ListPage<OAuthProvider>, BackendError> {
        let mut q: Vec<(&str, String)> = Vec::new();
        if !filter.provider.is_empty() {
            q.push(("provider", filter.provider.join(",")));
        }
        if let Some(c) = filter.configured {
            q.push(("configured", c.to_string()));
        }
        self.client.request(HttpMethod::Get, "/v1/oauth_providers", &q, None, None).await
    }
    /// `GET /v1/oauth_providers/:provider`.
    pub async fn get(&self, provider: &str) -> Result<OAuthProvider, BackendError> {
        let path = format!("/v1/oauth_providers/{}", seg(provider));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PUT /v1/oauth_providers/:provider` — set credentials, display fields,
    /// or settings.
    pub async fn upsert(
        &self,
        provider: &str,
        body: &UpsertOAuthProviderBody,
        idempotency_key: Option<&str>,
    ) -> Result<OAuthProviderUpdate, BackendError> {
        let path = format!("/v1/oauth_providers/{}", seg(provider));
        self.client.request(HttpMethod::Put, &path, &[], body_of(body)?, idempotency_key).await
    }
    /// `DELETE /v1/oauth_providers/:provider` — remove the credentials. Linked
    /// accounts are kept.
    pub async fn delete(&self, provider: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/oauth_providers/{}", seg(provider));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/oauth_providers/:provider/enabled` — turn the provider on/off.
    pub async fn set_enabled(&self, provider: &str, enabled: bool) -> Result<Value, BackendError> {
        let path = format!("/v1/oauth_providers/{}/enabled", seg(provider));
        let body = serde_json::json!({ "enabled": enabled });
        self.client.request(HttpMethod::Post, &path, &[], Some(body), None).await
    }
    /// `POST /v1/oauth_providers/:provider/scope` — allow it for sign-in,
    /// sign-up, or both.
    pub async fn set_scope(&self, provider: &str, allow_sign_in: bool, allow_sign_up: bool) -> Result<Value, BackendError> {
        let path = format!("/v1/oauth_providers/{}/scope", seg(provider));
        let body = serde_json::json!({ "allow_sign_in": allow_sign_in, "allow_sign_up": allow_sign_up });
        self.client.request(HttpMethod::Post, &path, &[], Some(body), None).await
    }
    /// `POST /v1/oauth_providers/:provider/test` — test the stored credentials
    /// against the provider's token endpoint.
    pub async fn test(&self, provider: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/oauth_providers/{}/test", seg(provider));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

// ── webhook endpoints ─────────────────────────────────────────────────────

/// A webhook endpoint and its health. Never carries the signing secret.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookEndpoint {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub enabled_events: Vec<String>,
    #[serde(default)]
    pub active: bool,
    /// When deliveries started failing (epoch ms), if they are.
    #[serde(default)]
    pub failing_since: Option<i64>,
    /// When Atlas disabled it after repeated failures (epoch ms).
    #[serde(default)]
    pub disabled_at: Option<i64>,
    /// While a secret rotation overlap is open: when the previous secret stops
    /// signing deliveries (epoch ms). Until then every delivery carries two
    /// signatures.
    #[serde(default)]
    pub previous_secret_expires_at: Option<i64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    /// The signing secret — present only on create.
    #[serde(default)]
    pub secret: Option<String>,
    /// Delivery health: consecutive failed deliveries.
    #[serde(default)]
    pub consecutive_failures: Option<i64>,
    /// Delivery health: share of the last 24 hours' attempts that succeeded.
    #[serde(default)]
    pub success_rate_24h: Option<f64>,
    /// Delivery health: the last failed attempt (`at`, `status`, `error`).
    #[serde(default)]
    pub last_failure: Option<Value>,
    /// Delivery health: `{ succeeded, failed }` over the last 24 hours.
    #[serde(default)]
    pub attempts_24h: Option<Value>,
    /// Who gets the failure emails (empty = the account's owners).
    #[serde(default)]
    pub alert_contacts: Vec<String>,
    /// Which signatures deliveries carry: `v1`, `v2` (also covers the URL).
    #[serde(default)]
    pub signature_versions: Vec<String>,
    /// `canonical` or `legacy` event names.
    #[serde(default)]
    pub event_naming: Option<String>,
    #[serde(default)]
    pub external: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    /// The event destination (`aws_eventbridge`, `gcp_pubsub`,
    /// `cloudflare_queue`) when the endpoint is not an HTTPS URL.
    #[serde(default)]
    pub destination: Option<Value>,
    /// Your idempotent-create key.
    #[serde(default)]
    pub external_ref: Option<String>,
    /// The provisioning tag bag.
    #[serde(default)]
    pub metadata: Option<Value>,
    /// `true` on a create that sent an `external_ref` and got the existing
    /// object back.
    #[serde(default)]
    pub idempotent_replay: bool,
    /// On an endpoint that was re-enabled: the replay call that re-sends what
    /// it missed.
    #[serde(default)]
    pub replay: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The endpoint list plus the subscribable events and retry schedule.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookEndpointList {
    #[serde(default)]
    pub data: Vec<WebhookEndpoint>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Every event type an endpoint can subscribe to.
    #[serde(default)]
    pub available_events: Vec<String>,
    /// The same events as `available_events`, each described: what it means
    /// and who should act on it (`relevant_for`).
    #[serde(default)]
    pub event_catalog: Vec<Value>,
    /// Every value `relevant_for` can hold.
    #[serde(default)]
    pub event_audiences: Vec<String>,
    #[serde(default)]
    pub retry_schedule_ms: Vec<u64>,
    #[serde(default)]
    pub max_attempts: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `PATCH /v1/webhook_endpoints/:id`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateWebhookEndpointBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_events: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// `canonical` or `legacy` event names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_naming: Option<String>,
    /// `v1`, `v2` (the HMAC also covers the URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_versions: Option<Vec<String>>,
    /// Up to 20 addresses for the failure emails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external: Option<bool>,
    /// An event destination instead of an HTTPS URL, e.g.
    /// `json!({"type":"aws_eventbridge","region":"us-east-1","event_bus_name":"default"})`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Value>,
    /// Your own credentials for the destination (write-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_credentials: Option<Value>,
    /// Replaces the provisioning tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// One delivery attempt record.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookDelivery {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub attempt_number: u32,
    #[serde(default)]
    pub max_attempts: u32,
    #[serde(default)]
    pub payload: Value,
    /// `pending`, `success`, or `failed`.
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub http_status: Option<u16>,
    /// Why the attempt failed: `webhook_redirect_not_followed` (see
    /// `location`), `webhook_http_error`, `webhook_timeout`,
    /// `webhook_network_error` or `webhook_url_blocked`.
    #[serde(default)]
    pub error: Option<String>,
    /// The absolute `Location` of a 3xx answer. Not followed.
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub response_snippet: Option<String>,
    /// How long the receiver took to answer (milliseconds).
    #[serde(default)]
    pub latency_ms: Option<i64>,
    #[serde(default)]
    pub next_retry_at: Option<i64>,
    #[serde(default)]
    pub delivered_at: Option<i64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The receipt for a test send or a redelivery.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookDeliveryReceipt {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A webhook signing secret.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookSecret {
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub warning: Option<String>,
    /// On a rotation: the overlap applied, in seconds.
    #[serde(default)]
    pub overlap_seconds: Option<u64>,
    /// On a rotation: when the previous secret stops signing deliveries
    /// (epoch ms), or `None` when it already has.
    #[serde(default)]
    pub previous_secret_expires_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The body of `POST /v1/webhook_endpoints/:id/rotate_secret`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RotateWebhookSecretBody {
    /// How long the previous secret keeps signing deliveries (as a second
    /// `atlas-signature` entry), in seconds. `None` or `0`: it stops at once
    /// (the default); at most 604800 (7 days). Set it only once every receiver
    /// verifies with a verifier that accepts several signatures (0.13.0+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_seconds: Option<u64>,
}

impl RotateWebhookSecretBody {
    /// A body with no overlap set (the server default applies).
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `overlap_seconds` (`0` stops the previous secret now).
    pub fn with_overlap_seconds(mut self, seconds: u64) -> Self {
        self.overlap_seconds = Some(seconds);
        self
    }
}

/// The `/v1/webhook_endpoints` namespace. Reached via
/// [`BackendClient::webhook_endpoints`]. (To verify incoming deliveries, use
/// [`super::Webhook`].)
pub struct WebhookEndpoints<'a> {
    pub(super) client: &'a BackendClient,
}

impl WebhookEndpoints<'_> {
    /// `GET /v1/webhook_endpoints`.
    pub async fn list(&self) -> Result<WebhookEndpointList, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/webhook_endpoints", &[], None, None).await
    }
    /// `POST /v1/webhook_endpoints` — register an endpoint. `enabled_events`
    /// `None` subscribes to every event. The signing secret is in the response.
    pub async fn create(
        &self,
        url: &str,
        enabled_events: Option<Vec<String>>,
        idempotency_key: Option<&str>,
    ) -> Result<WebhookEndpoint, BackendError> {
        let mut body = Map::new();
        body.insert("url".into(), Value::String(url.to_string()));
        if let Some(ev) = enabled_events {
            body.insert("enabled_events".into(), Value::from(ev));
        }
        self.client
            .request(HttpMethod::Post, "/v1/webhook_endpoints", &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    /// `PATCH /v1/webhook_endpoints/:id` — the secret is kept.
    pub async fn update(&self, id: &str, body: &UpdateWebhookEndpointBody) -> Result<WebhookEndpoint, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    /// `DELETE /v1/webhook_endpoints/:id`.
    pub async fn delete(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/webhook_endpoints/:id/reveal_secret` — show the current secret.
    pub async fn reveal_secret(&self, id: &str) -> Result<WebhookSecret, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/reveal_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/webhook_endpoints/:id/rotate_secret` — the new secret is shown
    /// once; the old one stops working immediately.
    pub async fn rotate_secret(&self, id: &str) -> Result<WebhookSecret, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/webhook_endpoints/:id/rotate_secret` with a chosen overlap:
    /// for `overlap_seconds` every delivery is signed with both secrets, so a
    /// verifier holding either passes. `previous_secret_expires_at` in the
    /// response says when the old one stops.
    pub async fn rotate_secret_with(&self, id: &str, body: &RotateWebhookSecretBody) -> Result<WebhookSecret, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], body_of(body)?, None).await
    }
    /// `POST /v1/webhook_endpoints/:id/test` — send a `webhook.test` event.
    pub async fn test(&self, id: &str) -> Result<WebhookDeliveryReceipt, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/test", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `GET /v1/webhook_endpoints/:id/deliveries` — newest first; `limit`
    /// defaults to 50 (max 100).
    pub async fn deliveries(&self, id: &str, limit: Option<u32>) -> Result<ListPage<WebhookDelivery>, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/deliveries", seg(id));
        let q = Query::new().set_opt("limit", limit);
        self.client.request(HttpMethod::Get, &path, &q.as_pairs(), None, None).await
    }
    /// `POST /v1/webhook_endpoints/:id/deliveries/:delivery_id/redeliver`.
    pub async fn redeliver(&self, id: &str, delivery_id: &str) -> Result<WebhookDeliveryReceipt, BackendError> {
        let path = format!(
            "/v1/webhook_endpoints/{}/deliveries/{}/redeliver",
            seg(id),
            seg(delivery_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

impl BackendClient {
    /// Instance settings: preflight, cookie consent, and more.
    pub fn instance(&self) -> Instance<'_> {
        Instance { client: self }
    }
    /// Bring-your-own email and SMS delivery providers.
    pub fn messaging_providers(&self) -> MessagingProvidersApi<'_> {
        MessagingProvidersApi { client: self }
    }
    /// Social sign-in (OAuth) providers.
    pub fn oauth_providers(&self) -> OAuthProviders<'_> {
        OAuthProviders { client: self }
    }
    /// Webhook endpoint management.
    pub fn webhook_endpoints(&self) -> WebhookEndpoints<'_> {
        WebhookEndpoints { client: self }
    }
}
