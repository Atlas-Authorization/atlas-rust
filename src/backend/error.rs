//! Errors for the management client.
//!
//! A failed BAPI call answers with the §9.1 envelope `{ errors: [{ code,
//! message, param?, meta? }] }`. `code` is the stable, machine-readable part of
//! that contract — integrators branch on it (`LAST_ADMIN`, `NOT_FOUND`,
//! `SCOPE_MISSING`, …) — so it is surfaced first-class here rather than buried
//! in a parsed body, mirroring `@atlasauth/backend`'s `AtlasApiError`.

use serde::Deserialize;
use thiserror::Error;

use crate::error::TransportError;

/// One entry in the §9.1 error envelope. `param`/`meta` carry the detail a
/// caller sometimes needs (a rate limit's `retry_after`, the offending field).
#[derive(Debug, Clone, Deserialize)]
pub struct AtlasErrorItem {
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
    /// The code's page in the error reference (`https://atlasauth.net/errors/<code>`).
    #[serde(default)]
    pub docs_url: Option<String>,
    /// On `ROUTE_NOT_FOUND` only: the closest documented paths.
    #[serde(default)]
    pub did_you_mean: Vec<String>,
    /// On `ROUTE_NOT_FOUND` only: the methods the path does support.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
}

/// A non-2xx BAPI response, carrying the HTTP status and the full error
/// envelope in order.
#[derive(Debug, Clone, Error)]
#[error("atlas api error (HTTP {status}): {}", first_message(.errors))]
pub struct AtlasApiError {
    pub status: u16,
    pub errors: Vec<AtlasErrorItem>,
}

fn first_message(errors: &[AtlasErrorItem]) -> String {
    errors
        .first()
        .map(|e| {
            if e.message.is_empty() {
                e.code.clone()
            } else {
                e.message.clone()
            }
        })
        .unwrap_or_else(|| "request failed".to_string())
}

impl AtlasApiError {
    /// The first error's stable code — the field callers branch on most.
    pub fn code(&self) -> Option<&str> {
        self.errors.first().map(|e| e.code.as_str())
    }

    /// Whether ANY error in the envelope carries the given stable code.
    pub fn has_code(&self, code: &str) -> bool {
        self.errors.iter().any(|e| e.code == code)
    }

    /// Whether the key lacked a scope the call needs. Accepts
    /// `INSUFFICIENT_SCOPE` and its former spelling `SCOPE_MISSING`.
    pub fn is_insufficient_scope(&self) -> bool {
        self.has_code(codes::INSUFFICIENT_SCOPE) || self.has_code(codes::SCOPE_MISSING)
    }

    /// The scope an `INSUFFICIENT_SCOPE` (or `SCOPE_MISSING`) error says the
    /// call needed (`meta.required_scope`), if any.
    pub fn required_scope(&self) -> Option<String> {
        self.errors
            .iter()
            .filter(|e| e.code == codes::INSUFFICIENT_SCOPE || e.code == codes::SCOPE_MISSING)
            .find_map(|e| {
                e.meta
                    .as_ref()
                    .and_then(|m| m.get("required_scope"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
    }

    /// Whether a multi-factor sign-in within the last five minutes is needed
    /// first (`STEP_UP_REQUIRED`).
    pub fn is_step_up_required(&self) -> bool {
        self.has_code(codes::STEP_UP_REQUIRED)
    }

    /// Whether no endpoint matched the method and path (`ROUTE_NOT_FOUND`).
    pub fn is_route_not_found(&self) -> bool {
        self.has_code(codes::ROUTE_NOT_FOUND)
    }

    /// The closest documented paths of a `ROUTE_NOT_FOUND` error (empty
    /// otherwise).
    pub fn did_you_mean(&self) -> Vec<String> {
        self.errors
            .iter()
            .find(|e| e.code == codes::ROUTE_NOT_FOUND)
            .map(|e| e.did_you_mean.clone())
            .unwrap_or_default()
    }

    /// Whether the error is a missing object (404 or `NOT_FOUND`).
    pub fn is_not_found(&self) -> bool {
        self.status == 404 || self.has_code(codes::NOT_FOUND)
    }
}

/// Every failure a management-client call can return.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The server answered with a non-2xx and the §9.1 error envelope.
    #[error(transparent)]
    Api(#[from] AtlasApiError),
    /// The request did not complete (DNS, TLS, connection), or a retry budget
    /// was exhausted on 5xx/429.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A 2xx with a body that did not parse into the expected type.
    #[error("atlas: malformed backend response: {0}")]
    Malformed(String),
}

/// Stable error codes worth branching on, for use with
/// [`AtlasApiError::code`] / [`AtlasApiError::has_code`]:
///
/// ```no_run
/// # async fn demo(atlas: &atlasauth::backend::BackendClient) {
/// use atlasauth::backend::{codes, BackendError};
/// if let Err(BackendError::Api(e)) = atlas.instance().preflight().await {
///     if e.has_code(codes::WRONG_KEY_SURFACE) { /* a psk_ was sent to an instance route */ }
/// }
/// # }
/// ```
pub mod codes {
    /// The instance has no email provider configured, so the email could not be sent.
    pub const EMAIL_DELIVERY_NOT_CONFIGURED: &str = "EMAIL_DELIVERY_NOT_CONFIGURED";
    /// The action needs an email provider to be configured first.
    pub const EMAIL_PROVIDER_REQUIRED: &str = "EMAIL_PROVIDER_REQUIRED";
    /// The email provider cannot be removed while email-dependent features are
    /// on (`meta.features` lists them); force the removal with
    /// `messaging_providers().delete_with(.., &DeleteMessagingProviderParams { force: true })`.
    pub const EMAIL_PROVIDER_IN_USE: &str = "EMAIL_PROVIDER_IN_USE";
    /// Captcha is bring-your-own-keys: turning it on (or switching provider) needs
    /// that provider's site key and secret stored first.
    pub const CAPTCHA_KEYS_REQUIRED: &str = "CAPTCHA_KEYS_REQUIRED";
    /// A captcha key a live flow uses cannot be removed (`meta.flows`); delete it
    /// with the `force=true` query to remove it anyway and turn those flows off.
    pub const CAPTCHA_IN_USE: &str = "CAPTCHA_IN_USE";
    /// Strict request bodies refused a field the endpoint does not accept.
    pub const UNKNOWN_FIELD: &str = "UNKNOWN_FIELD";
    /// The body set a field that is not writable on this endpoint (`param`
    /// names it; the message names the call that changes it).
    pub const READ_ONLY_FIELD: &str = "READ_ONLY_FIELD";
    /// The development email sender is not available on a production instance (409).
    pub const DEVELOPMENT_EMAIL_NOT_ALLOWED: &str = "DEVELOPMENT_EMAIL_NOT_ALLOWED";
    /// The development email sender is not available on this deployment (503).
    pub const DEVELOPMENT_EMAIL_UNAVAILABLE: &str = "DEVELOPMENT_EMAIL_UNAVAILABLE";
    /// The development sender's daily or per-recipient hourly cap is spent
    /// (429; `meta.window`, `meta.retry_after_seconds`).
    pub const DEVELOPMENT_EMAIL_LIMIT_REACHED: &str = "DEVELOPMENT_EMAIL_LIMIT_REACHED";
    /// The development sender sends only Atlas's own sign-in emails (422).
    pub const DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED: &str = "DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED";
    /// Referrals cannot be enabled until the provider's needs are set (422;
    /// `meta` names what is missing).
    pub const REFERRALS_NOT_CONFIGURED: &str = "REFERRALS_NOT_CONFIGURED";
    /// Another user on the instance already holds that referral code (409).
    pub const REFERRAL_CODE_TAKEN: &str = "REFERRAL_CODE_TAKEN";
    /// A billing plan still has subscribers and cannot be removed.
    pub const PLAN_IN_USE: &str = "PLAN_IN_USE";
    /// The key was sent to the wrong API surface (a `psk_` platform key on an
    /// instance route, or an `sk_` secret key on `/v1/platform/*`).
    pub const WRONG_KEY_SURFACE: &str = "WRONG_KEY_SURFACE";
    /// The key is unknown, revoked, or malformed.
    pub const INVALID_KEY: &str = "INVALID_KEY";
    /// The resource does not exist (or is not visible to this key).
    pub const NOT_FOUND: &str = "NOT_FOUND";
    /// A request field failed validation; the error's `param` names it.
    pub const VALIDATION_FAILED: &str = "VALIDATION_FAILED";
    /// The key lacks a scope this route needs (`meta.required_scope` names it).
    /// Replaces [`SCOPE_MISSING`]; use `AtlasApiError::is_insufficient_scope`,
    /// which accepts both.
    pub const INSUFFICIENT_SCOPE: &str = "INSUFFICIENT_SCOPE";
    /// The former spelling of [`INSUFFICIENT_SCOPE`] (the new envelope carries
    /// it as `meta.legacy_code`); still tolerated.
    pub const SCOPE_MISSING: &str = "SCOPE_MISSING";
    /// A root action (create an app or instance, mint a key) needs a
    /// multi-factor sign-in within the last five minutes (403).
    pub const STEP_UP_REQUIRED: &str = "STEP_UP_REQUIRED";
    /// No endpoint matches the method and path; the error carries
    /// `did_you_mean` and `allowed_methods`.
    pub const ROUTE_NOT_FOUND: &str = "ROUTE_NOT_FOUND";
    /// The call is for a live instance only.
    pub const NOT_A_LIVE_INSTANCE: &str = "NOT_A_LIVE_INSTANCE";
    /// The call is for a test-mode instance only.
    pub const TEST_MODE_ONLY: &str = "TEST_MODE_ONLY";
    /// Testing helpers are not available on this deployment.
    pub const TESTING_UNAVAILABLE: &str = "TESTING_UNAVAILABLE";
    /// The partner-link credential an integration needs is not available on
    /// this instance.
    pub const PARTNER_LINK_UNAVAILABLE: &str = "PARTNER_LINK_UNAVAILABLE";
    /// Too many requests; retry after the indicated delay.
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    /// The same idempotency key was reused with a different request.
    pub const IDEMPOTENCY_CONFLICT: &str = "IDEMPOTENCY_CONFLICT";
    /// A usage debit would exceed an API key's spend cap. `api_keys().record_usage`
    /// reports it as the debit's `code` (with `allowed: false`), not as an error.
    pub const LIMIT_EXCEEDED: &str = "LIMIT_EXCEEDED";
    /// The session was revoked (signed out) and cannot be kept alive.
    pub const SESSION_REVOKED: &str = "SESSION_REVOKED";
    /// The session already timed out from inactivity and cannot be kept alive.
    pub const SESSION_IDLE_EXPIRED: &str = "SESSION_IDLE_EXPIRED";
    /// The session is past its absolute expiry and cannot be kept alive.
    pub const SESSION_EXPIRED: &str = "SESSION_EXPIRED";
    /// The feature this call needs is not configured on the instance.
    pub const NOT_CONFIGURED: &str = "NOT_CONFIGURED";
}
