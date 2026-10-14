//! Instance configuration surfaces: the setup preflight, the hosted-page
//! cookie-consent script, BYOK email/SMS delivery providers, social sign-in
//! (OAuth) providers, and webhook endpoints.

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
    #[serde(flatten)]
    pub extra: Map<String, Value>,
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
    #[serde(flatten)]
    pub extra: Map<String, Value>,
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
    /// `email` or `sms`.
    #[serde(default)]
    pub channel: String,
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
    /// `PUT /v1/messaging_providers/sms`.
    pub async fn set_sms(&self, provider: &SmsProviderConfig) -> Result<MessagingProvider, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/messaging_providers/sms", &[], body_of(provider)?, None)
            .await
    }
    /// `DELETE /v1/messaging_providers/:channel`.
    pub async fn delete(&self, channel: MessagingChannel) -> Result<Value, BackendError> {
        let path = format!("/v1/messaging_providers/{}", channel.as_str());
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
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
    #[serde(default)]
    pub created_at: Option<i64>,
    /// The signing secret — present only on create.
    #[serde(default)]
    pub secret: Option<String>,
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
    #[serde(default)]
    pub response_snippet: Option<String>,
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
    #[serde(flatten)]
    pub extra: Map<String, Value>,
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
