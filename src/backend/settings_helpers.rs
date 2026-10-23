//! Typed shortcuts over `PATCH /v1/instance` for settings that live in
//! `auth_config`, plus the names the API accepts for them.

use serde_json::{Map, Value};

use super::error::BackendError;
use super::instance::Instance;
use super::pagination::Query;
use super::types;

/// Captcha providers (`auth_config.captcha.provider`). Captcha is
/// bring-your-own-keys: store the secret first. `vercel_botid` is secret-only:
/// set `attestationUrl` instead of a site key.
pub const CAPTCHA_PROVIDERS: &[&str] = &[
    "none",
    "atlas",
    "hcaptcha",
    "turnstile",
    "recaptcha",
    "recaptcha_v3",
    "recaptcha_enterprise",
    "funcaptcha",
    "friendly",
    "yandex",
    "geetest",
    "mcaptcha",
    "capy",
    "seon",
    "awswaf",
    "perimeterx",
    "akamai",
    "kasada",
    "incapsula",
    "captchafox",
    "vercel_botid",
];

/// `auth_config.accountLinkingTrust` values.
pub const LINKING_TRUST_LEVELS: &[&str] = &["always", "verified", "never"];

/// Billing providers an instance can sell end-user plans through (bring your own key).
pub const BILLING_PROVIDERS: &[&str] = &[
    "stripe",
    "polar",
    "dodo",
    "creem",
    "chargebee",
    "autumn",
    "commet",
];

/// Where the token-signing key can live.
pub const SIGNING_KEY_PROVIDERS: &[&str] = &["local", "aws_kms", "gcp_kms", "azure_key_vault"];

/// The security notice sent when a dormant account signs in again.
pub const EMAIL_TEMPLATE_ACCOUNT_REACTIVATED: &str = "account_reactivated";

impl Instance<'_> {
    fn auth_config_patch(key: &str, value: Value) -> types::InstanceUpdateBody {
        let mut extra = Map::new();
        extra.insert(key.to_owned(), value);
        let auth = types::InstanceUpdateBodyAuthConfig {
            extra,
            ..Default::default()
        };
        types::InstanceUpdateBody {
            auth_config: Some(auth),
            ..Default::default()
        }
    }

    /// Write `auth_config.accountLinkingTrust`: keys are an exact provider key, a
    /// `prefix*` or `*`; values `always` (vouch for the provider's email, for
    /// linking only), `verified` or `never` (refused with 409
    /// `IDENTITY_ALREADY_LINKED`). An account that never proved its email is
    /// never linked. `PATCH /v1/instance`.
    pub async fn set_account_linking_trust(
        &self,
        trust: &[(&str, &str)],
    ) -> Result<types::InstanceUpdateResponse, BackendError> {
        let map: Map<String, Value> = trust
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Value::String((*v).to_owned())))
            .collect();
        self.update(
            &Self::auth_config_patch("accountLinkingTrust", Value::Object(map)),
            &Query::new(),
        )
        .await
    }

    /// Merge `auth_config.captcha`: `provider` (see [`CAPTCHA_PROVIDERS`]),
    /// `siteKey`, `widget`, `minScore`, per-flow / per-action overrides and, for
    /// Vercel BotID, `attestationUrl` (https or a root-relative path). Keys are
    /// camelCase, as in `auth_config`. `PATCH /v1/instance`.
    pub async fn set_captcha_config(
        &self,
        captcha: Value,
    ) -> Result<types::InstanceUpdateResponse, BackendError> {
        self.update(&Self::auth_config_patch("captcha", captcha), &Query::new())
            .await
    }
}
