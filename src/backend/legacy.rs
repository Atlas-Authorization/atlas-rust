//! Types the published crate exposed that the API description no longer
//! carries (it now models the same data differently). They are kept, unchanged,
//! so existing code compiles: some public fields and methods of the generated
//! types still use them, and `BackendClient::instance()` keeps the Chatly /
//! Forumulate integration helpers. Re-exported from [`super::types`].
//!
//! Hand-written: `scripts/gen_catalog.py` never touches this file.

#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::derive_partial_eq_without_eq)]

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::error::BackendError;
use super::resources::body_of;
use super::types;
use super::Instance;
use crate::http::HttpMethod;

/// `Some(None)` for an explicit JSON `null`, so a decoded request keeps the
/// difference between "absent" and "clear".
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}


/// Instance auth configuration. Partial + additive on PATCH — omitted sections are untouched.
/// GET /v1/instance returns this resolved (defaults expanded) as auth_config_resolved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfig {
    /// Which first-factor sign-in methods are enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategies: Option<InstanceUpdateBodyAuthConfigStrategies>,
    #[serde(
        rename = "passwordPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub password_policy: Option<InstanceUpdateBodyAuthConfigPasswordPolicy>,
    /// Per-method code/link TTLs, lengths and resend limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<InstanceUpdateBodyAuthConfigVerification>,
    /// Session lifetime + token behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<InstanceUpdateBodyAuthConfigSession>,
    /// Known values: `off`, `optional`, `required`.
    #[serde(rename = "mfaPolicy", default, skip_serializing_if = "Option::is_none")]
    pub mfa_policy: Option<String>,
    /// public: anyone may sign up. waitlist: unknown addresses join a waitlist (403 WAITLISTED)
    /// until approved. restricted: invitation-only — only invited or waitlist-approved addresses
    /// may sign up (403 SIGN_UP_RESTRICTED otherwise).
    ///
    /// Known values: `public`, `waitlist`, `restricted`.
    #[serde(
        rename = "signUpMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sign_up_mode: Option<String>,
    /// On PATCH /v1/instance only branding.audiences is applied (per-audience hosted-page branding,
    /// merged per hint; see PATCH /v1/branding for the shape). Every other branding field is
    /// written with PATCH /v1/branding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<InstanceUpdateBodyAuthConfigBranding>,
    /// Strict writes for this instance's secret keys: a Backend API write that carries a body field
    /// the endpoint does not know is refused with 422 UNKNOWN_FIELD instead of being accepted and
    /// ignored. true for every instance created from 2026-10 on; older instances stay false
    /// (lenient: the ignored fields are named in the Atlas-Unknown-Fields response header) until
    /// set. One request overrides it with the Atlas-Strict: true | false header. Fields that look
    /// writable and have their own call (verified on an email address, banned, …) are refused with
    /// 422 READ_ONLY_FIELD either way; echoed id, object, created_at and updated_at are 422
    /// READ_ONLY_FIELD only when strict.
    #[serde(
        rename = "strictRequestBodies",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub strict_request_bodies: Option<bool>,
    /// Whether a password sign-up must prove the address with an emailed code before it completes.
    /// When false the sign-up completes at once, but the address stays unverified (verified,
    /// verification.status and email_verified report false) until the user proves it later.
    #[serde(
        rename = "requireEmailVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_email_verification: Option<bool>,
    /// DANGEROUS. When true, addresses that skipped proof because requireEmailVerification was
    /// false are reported as verified again in users, tokens, webhooks and exports (the old
    /// behaviour). Anyone can then sign up as any address and present a verified claim. Atlas still
    /// treats those addresses as unproven when linking social sign-ins, auto-joining organizations
    /// and accepting invitations. Preflight reports email_verified_unproven while this is on.
    #[serde(
        rename = "dangerouslyReportSkippedEmailsAsVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dangerously_report_skipped_emails_as_verified: Option<bool>,
    /// Atlas AS a SAML IdP — "Sign in with Atlas" over SAML for a downstream Service Provider
    /// (direct SAML; no OIDC/atlas_byo needed).
    #[serde(rename = "samlIdp", default, skip_serializing_if = "Option::is_none")]
    pub saml_idp: Option<InstanceUpdateBodyAuthConfigSamlIdp>,
    /// Trust JWTs minted by an EXTERNAL issuer as a sign-in credential (e.g. a legacy IdP or your
    /// own token service). The linked identity is stored under provider ext_jwt:&lt;id&gt;.
    #[serde(
        rename = "externalJwt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_jwt: Option<InstanceUpdateBodyAuthConfigExternalJwt>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfig {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `strategies`.
    pub fn with_strategies(mut self, v: impl Into<InstanceUpdateBodyAuthConfigStrategies>) -> Self {
        self.strategies = Some(v.into());
        self
    }
    /// Set `passwordPolicy`.
    pub fn with_password_policy(
        mut self,
        v: impl Into<InstanceUpdateBodyAuthConfigPasswordPolicy>,
    ) -> Self {
        self.password_policy = Some(v.into());
        self
    }
    /// Set `verification`.
    pub fn with_verification(
        mut self,
        v: impl Into<InstanceUpdateBodyAuthConfigVerification>,
    ) -> Self {
        self.verification = Some(v.into());
        self
    }
    /// Set `session`.
    pub fn with_session(mut self, v: impl Into<InstanceUpdateBodyAuthConfigSession>) -> Self {
        self.session = Some(v.into());
        self
    }
    /// Set `mfaPolicy`.
    pub fn with_mfa_policy(mut self, v: impl Into<String>) -> Self {
        self.mfa_policy = Some(v.into());
        self
    }
    /// Set `signUpMode`.
    pub fn with_sign_up_mode(mut self, v: impl Into<String>) -> Self {
        self.sign_up_mode = Some(v.into());
        self
    }
    /// Set `branding`.
    pub fn with_branding(mut self, v: impl Into<InstanceUpdateBodyAuthConfigBranding>) -> Self {
        self.branding = Some(v.into());
        self
    }
    /// Set `strictRequestBodies`.
    pub fn with_strict_request_bodies(mut self, v: impl Into<bool>) -> Self {
        self.strict_request_bodies = Some(v.into());
        self
    }
    /// Set `requireEmailVerification`.
    pub fn with_require_email_verification(mut self, v: impl Into<bool>) -> Self {
        self.require_email_verification = Some(v.into());
        self
    }
    /// Set `dangerouslyReportSkippedEmailsAsVerified`.
    pub fn with_dangerously_report_skipped_emails_as_verified(
        mut self,
        v: impl Into<bool>,
    ) -> Self {
        self.dangerously_report_skipped_emails_as_verified = Some(v.into());
        self
    }
    /// Set `samlIdp`.
    pub fn with_saml_idp(mut self, v: impl Into<InstanceUpdateBodyAuthConfigSamlIdp>) -> Self {
        self.saml_idp = Some(v.into());
        self
    }
    /// Set `externalJwt`.
    pub fn with_external_jwt(
        mut self,
        v: impl Into<InstanceUpdateBodyAuthConfigExternalJwt>,
    ) -> Self {
        self.external_jwt = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// Which first-factor sign-in methods are enabled.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigStrategies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    /// Email one-time code (passwordless).
    #[serde(rename = "emailCode", default, skip_serializing_if = "Option::is_none")]
    pub email_code: Option<bool>,
    /// Magic link.
    #[serde(rename = "emailLink", default, skip_serializing_if = "Option::is_none")]
    pub email_link: Option<bool>,
    /// WebAuthn passkeys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<bool>,
    /// SMS OTP (off by default).
    #[serde(rename = "phoneCode", default, skip_serializing_if = "Option::is_none")]
    pub phone_code: Option<bool>,
    /// Username as a login identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siwe: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siws: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siwf: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigStrategies {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `password`.
    pub fn with_password(mut self, v: impl Into<bool>) -> Self {
        self.password = Some(v.into());
        self
    }
    /// Set `emailCode`.
    pub fn with_email_code(mut self, v: impl Into<bool>) -> Self {
        self.email_code = Some(v.into());
        self
    }
    /// Set `emailLink`.
    pub fn with_email_link(mut self, v: impl Into<bool>) -> Self {
        self.email_link = Some(v.into());
        self
    }
    /// Set `passkey`.
    pub fn with_passkey(mut self, v: impl Into<bool>) -> Self {
        self.passkey = Some(v.into());
        self
    }
    /// Set `phoneCode`.
    pub fn with_phone_code(mut self, v: impl Into<bool>) -> Self {
        self.phone_code = Some(v.into());
        self
    }
    /// Set `username`.
    pub fn with_username(mut self, v: impl Into<bool>) -> Self {
        self.username = Some(v.into());
        self
    }
    /// Set `siwe`.
    pub fn with_siwe(mut self, v: impl Into<bool>) -> Self {
        self.siwe = Some(v.into());
        self
    }
    /// Set `siws`.
    pub fn with_siws(mut self, v: impl Into<bool>) -> Self {
        self.siws = Some(v.into());
        self
    }
    /// Set `siwf`.
    pub fn with_siwf(mut self, v: impl Into<bool>) -> Self {
        self.siwf = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigPasswordPolicy {
    #[serde(rename = "minLength", default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<i64>,
    #[serde(
        rename = "requireUppercase",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_uppercase: Option<bool>,
    #[serde(
        rename = "requireNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_number: Option<bool>,
    #[serde(
        rename = "requireSymbol",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_symbol: Option<bool>,
    /// Reject known-breached passwords (HIBP).
    #[serde(
        rename = "checkBreaches",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub check_breaches: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigPasswordPolicy {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `minLength`.
    pub fn with_min_length(mut self, v: impl Into<i64>) -> Self {
        self.min_length = Some(v.into());
        self
    }
    /// Set `requireUppercase`.
    pub fn with_require_uppercase(mut self, v: impl Into<bool>) -> Self {
        self.require_uppercase = Some(v.into());
        self
    }
    /// Set `requireNumber`.
    pub fn with_require_number(mut self, v: impl Into<bool>) -> Self {
        self.require_number = Some(v.into());
        self
    }
    /// Set `requireSymbol`.
    pub fn with_require_symbol(mut self, v: impl Into<bool>) -> Self {
        self.require_symbol = Some(v.into());
        self
    }
    /// Set `checkBreaches`.
    pub fn with_check_breaches(mut self, v: impl Into<bool>) -> Self {
        self.check_breaches = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// Per-method code/link TTLs, lengths and resend limits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigVerification {
    #[serde(rename = "emailCode", default, skip_serializing_if = "Option::is_none")]
    pub email_code: Option<Map<String, Value>>,
    #[serde(rename = "smsCode", default, skip_serializing_if = "Option::is_none")]
    pub sms_code: Option<Map<String, Value>>,
    #[serde(rename = "magicLink", default, skip_serializing_if = "Option::is_none")]
    pub magic_link: Option<Map<String, Value>>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigVerification {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `emailCode`.
    pub fn with_email_code(mut self, v: impl Into<Map<String, Value>>) -> Self {
        self.email_code = Some(v.into());
        self
    }
    /// Set `smsCode`.
    pub fn with_sms_code(mut self, v: impl Into<Map<String, Value>>) -> Self {
        self.sms_code = Some(v.into());
        self
    }
    /// Set `magicLink`.
    pub fn with_magic_link(mut self, v: impl Into<Map<String, Value>>) -> Self {
        self.magic_link = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// Session lifetime + token behaviour.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigSession {
    #[serde(rename = "idleMs", default, skip_serializing_if = "Option::is_none")]
    pub idle_ms: Option<i64>,
    #[serde(
        rename = "absoluteMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub absolute_ms: Option<i64>,
    #[serde(
        rename = "jwtTtlSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub jwt_ttl_seconds: Option<i64>,
    #[serde(
        rename = "crossSubdomainCookies",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cross_subdomain_cookies: Option<bool>,
    /// Add email/name to the session JWT.
    #[serde(
        rename = "includeEmailClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_email_claim: Option<bool>,
    /// Add the eu_orgs reader claim.
    #[serde(
        rename = "includeEndUserPoolClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_end_user_pool_claim: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigSession {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `idleMs`.
    pub fn with_idle_ms(mut self, v: impl Into<i64>) -> Self {
        self.idle_ms = Some(v.into());
        self
    }
    /// Set `absoluteMs`.
    pub fn with_absolute_ms(mut self, v: impl Into<i64>) -> Self {
        self.absolute_ms = Some(v.into());
        self
    }
    /// Set `jwtTtlSeconds`.
    pub fn with_jwt_ttl_seconds(mut self, v: impl Into<i64>) -> Self {
        self.jwt_ttl_seconds = Some(v.into());
        self
    }
    /// Set `crossSubdomainCookies`.
    pub fn with_cross_subdomain_cookies(mut self, v: impl Into<bool>) -> Self {
        self.cross_subdomain_cookies = Some(v.into());
        self
    }
    /// Set `includeEmailClaim`.
    pub fn with_include_email_claim(mut self, v: impl Into<bool>) -> Self {
        self.include_email_claim = Some(v.into());
        self
    }
    /// Set `includeEndUserPoolClaim`.
    pub fn with_include_end_user_pool_claim(mut self, v: impl Into<bool>) -> Self {
        self.include_end_user_pool_claim = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// On PATCH /v1/instance only branding.audiences is applied (per-audience hosted-page branding,
/// merged per hint; see PATCH /v1/branding for the shape). Every other branding field is
/// written with PATCH /v1/branding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigBranding {
    /// Audience hint (\[a-z0-9_-\]{1,32}) → { heading, subheading, logoUrl, primaryColor }, or null
    /// to delete that audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<HashMap<String, InstanceUpdateBodyAuthConfigBrandingAudiencesValue>>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigBranding {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `audiences`.
    pub fn with_audiences(
        mut self,
        v: impl Into<HashMap<String, InstanceUpdateBodyAuthConfigBrandingAudiencesValue>>,
    ) -> Self {
        self.audiences = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigBrandingAudiencesValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subheading: Option<String>,
    #[serde(rename = "logoUrl", default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(
        rename = "primaryColor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub primary_color: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigBrandingAudiencesValue {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `heading`.
    pub fn with_heading(mut self, v: impl Into<String>) -> Self {
        self.heading = Some(v.into());
        self
    }
    /// Set `subheading`.
    pub fn with_subheading(mut self, v: impl Into<String>) -> Self {
        self.subheading = Some(v.into());
        self
    }
    /// Set `logoUrl`.
    pub fn with_logo_url(mut self, v: impl Into<String>) -> Self {
        self.logo_url = Some(v.into());
        self
    }
    /// Set `primaryColor`.
    pub fn with_primary_color(mut self, v: impl Into<String>) -> Self {
        self.primary_color = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// Atlas AS a SAML IdP — "Sign in with Atlas" over SAML for a downstream Service Provider
/// (direct SAML; no OIDC/atlas_byo needed).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigSamlIdp {
    /// The SPs Atlas issues signed assertions to.
    #[serde(
        rename = "serviceProviders",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_providers: Option<Vec<InstanceUpdateBodyAuthConfigSamlIdpServiceProvidersItem>>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigSamlIdp {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `serviceProviders`.
    pub fn with_service_providers(
        mut self,
        v: impl Into<Vec<InstanceUpdateBodyAuthConfigSamlIdpServiceProvidersItem>>,
    ) -> Self {
        self.service_providers = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigSamlIdpServiceProvidersItem {
    /// Stable key used in the SSO URL + audit.
    #[serde(default)]
    pub id: String,
    /// The SP's SAML entityId (assertion audience).
    #[serde(rename = "entityId", default)]
    pub entity_id: String,
    /// The SP's Assertion Consumer Service URL (https) the Response is POSTed to.
    #[serde(rename = "acsUrl", default)]
    pub acs_url: String,
    /// User field for the NameID. Default email.
    ///
    /// Known values: `email`, `user_id`.
    #[serde(
        rename = "nameIdField",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub name_id_field: Option<String>,
    /// Extra attribute statements: SAML attribute name → user field / metadata key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigSamlIdpServiceProvidersItem {
    /// A value with the required fields set and every other field unset.
    pub fn new(
        id: impl Into<String>,
        entity_id: impl Into<String>,
        acs_url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            entity_id: entity_id.into(),
            acs_url: acs_url.into(),
            ..Default::default()
        }
    }
    /// Set `id`.
    pub fn with_id(mut self, v: impl Into<String>) -> Self {
        self.id = v.into();
        self
    }
    /// Set `entityId`.
    pub fn with_entity_id(mut self, v: impl Into<String>) -> Self {
        self.entity_id = v.into();
        self
    }
    /// Set `acsUrl`.
    pub fn with_acs_url(mut self, v: impl Into<String>) -> Self {
        self.acs_url = v.into();
        self
    }
    /// Set `nameIdField`.
    pub fn with_name_id_field(mut self, v: impl Into<String>) -> Self {
        self.name_id_field = Some(v.into());
        self
    }
    /// Set `attributes`.
    pub fn with_attributes(mut self, v: impl Into<HashMap<String, String>>) -> Self {
        self.attributes = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// Trust JWTs minted by an EXTERNAL issuer as a sign-in credential (e.g. a legacy IdP or your
/// own token service). The linked identity is stored under provider ext_jwt:&lt;id&gt;.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigExternalJwt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuers: Option<Vec<InstanceUpdateBodyAuthConfigExternalJwtIssuersItem>>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigExternalJwt {
    /// A value with the required fields set and every other field unset.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `issuers`.
    pub fn with_issuers(
        mut self,
        v: impl Into<Vec<InstanceUpdateBodyAuthConfigExternalJwtIssuersItem>>,
    ) -> Self {
        self.issuers = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateBodyAuthConfigExternalJwtIssuersItem {
    /// Stable key; the linked identity is stored under provider ext_jwt:&lt;id&gt;.
    #[serde(default)]
    pub id: String,
    /// The expected iss claim.
    #[serde(default)]
    pub issuer: String,
    /// The issuer's JWKS URL, used to verify the token signature.
    #[serde(rename = "jwksUri", default)]
    pub jwks_uri: String,
    /// The expected aud claim.
    #[serde(default)]
    pub audience: String,
    /// Claim to read the email from. Default email.
    #[serde(
        rename = "emailClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email_claim: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceUpdateBodyAuthConfigExternalJwtIssuersItem {
    /// A value with the required fields set and every other field unset.
    pub fn new(
        id: impl Into<String>,
        issuer: impl Into<String>,
        jwks_uri: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            issuer: issuer.into(),
            jwks_uri: jwks_uri.into(),
            audience: audience.into(),
            ..Default::default()
        }
    }
    /// Set `id`.
    pub fn with_id(mut self, v: impl Into<String>) -> Self {
        self.id = v.into();
        self
    }
    /// Set `issuer`.
    pub fn with_issuer(mut self, v: impl Into<String>) -> Self {
        self.issuer = v.into();
        self
    }
    /// Set `jwksUri`.
    pub fn with_jwks_uri(mut self, v: impl Into<String>) -> Self {
        self.jwks_uri = v.into();
        self
    }
    /// Set `audience`.
    pub fn with_audience(mut self, v: impl Into<String>) -> Self {
        self.audience = v.into();
        self
    }
    /// Set `emailClaim`.
    pub fn with_email_claim(mut self, v: impl Into<String>) -> Self {
        self.email_claim = Some(v.into());
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// The request body of `PUT /v1/instance/integrations/chatly`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetChatlyIntegrationBody {
    /// The chat channel public id (letters, digits, _ and -).
    #[serde(default)]
    pub channel: String,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceSetChatlyIntegrationBody {
    /// A value with the required fields set and every other field unset.
    pub fn new(channel: impl Into<String>) -> Self {
        Self {
            channel: channel.into(),
            ..Default::default()
        }
    }
    /// Set `channel`.
    pub fn with_channel(mut self, v: impl Into<String>) -> Self {
        self.channel = v.into();
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// The request body of `PUT /v1/instance/integrations/forumulate`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetForumulateIntegrationBody {
    /// Your Forumulate organization id.
    #[serde(default)]
    pub org_id: String,
    /// The spaces readers sign in to: space ids, or { id, redeem_url } where redeem_url is the
    /// space's jwtRedeemUrl on the host your readers read (its readerEndpoints in Forumulate).
    /// Without redeem_url the platform address is used, whose cookies only work on forumulate.com.
    #[serde(default)]
    pub spaces: Vec<Value>,
    /// The token aud (Forumulate clientId). Default forumulate:&lt;org_id&gt;.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "double_option"
    )]
    pub audience: Option<Option<String>>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


impl InstanceSetForumulateIntegrationBody {
    /// A value with the required fields set and every other field unset.
    pub fn new(org_id: impl Into<String>, spaces: impl Into<Vec<Value>>) -> Self {
        Self {
            org_id: org_id.into(),
            spaces: spaces.into(),
            ..Default::default()
        }
    }
    /// Set `org_id`.
    pub fn with_org_id(mut self, v: impl Into<String>) -> Self {
        self.org_id = v.into();
        self
    }
    /// Set `spaces`.
    pub fn with_spaces(mut self, v: impl Into<Vec<Value>>) -> Self {
        self.spaces = v.into();
        self
    }
    /// Set `audience`.
    pub fn with_audience(mut self, v: impl Into<String>) -> Self {
        self.audience = Some(Some(v.into()));
        self
    }
    /// Send `audience: null` to clear it.
    pub fn clear_audience(mut self) -> Self {
        self.audience = Some(None);
        self
    }
    /// Set a field this version of the crate does not know about.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}


/// The `RiskEvent` object: one risk-scored sign-in.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RiskEvent {
    /// Always `risk_event`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub user_id: String,
    /// Known values: `low`, `medium`, `high`.
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub score: f64,
    /// Names of the signals that fired.
    #[serde(default)]
    pub signals: Vec<String>,
    /// The action decided; in audit mode, what would have happened.
    #[serde(default)]
    pub action: String,
    /// Known values: `enforce`, `audit`.
    #[serde(default)]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Known values: `legit`, `fraud`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback_at: Option<String>,
    #[serde(default)]
    pub created_at: String,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The response of `POST /v1/fraud/lookup`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FraudLookupResponse {
    /// Always `fraud_lookup`.
    #[serde(default)]
    pub object: String,
    /// Known values: `allow`, `challenge`, `block`.
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Signals: country, ASN, datacenter, Tor, automation, client class, bot score, velocity.
    #[serde(default)]
    pub signals: Value,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The response of `GET /v1/billing/providers/{provider}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BillingGetProviderResponse {
    /// Always `billing_provider`.
    #[serde(default)]
    pub object: String,
    /// Known values: `stripe`, `polar`, `dodo`, `creem`.
    #[serde(default)]
    pub provider: String,
    /// Known values: `live`, `test`.
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub status: String,
    /// Public settings only (e.g. publishable_key).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, String>,
    /// Which secrets are stored (e.g. {"secret_key": true}); values are never returned.
    #[serde(default)]
    pub secrets_set: HashMap<String, bool>,
    /// Register this URL in the provider's dashboard.
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_webhook_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Instance auth configuration. Partial + additive on PATCH — omitted sections are untouched.
/// GET /v1/instance returns this resolved (defaults expanded) as auth_config_resolved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolved {
    /// Which first-factor sign-in methods are enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategies: Option<InstanceGetResponseAuthConfigResolvedStrategies>,
    #[serde(
        rename = "passwordPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub password_policy: Option<InstanceGetResponseAuthConfigResolvedPasswordPolicy>,
    /// Per-method code/link TTLs, lengths and resend limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<InstanceGetResponseAuthConfigResolvedVerification>,
    /// Session lifetime + token behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<InstanceGetResponseAuthConfigResolvedSession>,
    /// Known values: `off`, `optional`, `required`.
    #[serde(rename = "mfaPolicy", default, skip_serializing_if = "Option::is_none")]
    pub mfa_policy: Option<String>,
    /// public: anyone may sign up. waitlist: unknown addresses join a waitlist (403 WAITLISTED)
    /// until approved. restricted: invitation-only — only invited or waitlist-approved addresses
    /// may sign up (403 SIGN_UP_RESTRICTED otherwise).
    ///
    /// Known values: `public`, `waitlist`, `restricted`.
    #[serde(
        rename = "signUpMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sign_up_mode: Option<String>,
    /// On PATCH /v1/instance only branding.audiences is applied (per-audience hosted-page branding,
    /// merged per hint; see PATCH /v1/branding for the shape). Every other branding field is
    /// written with PATCH /v1/branding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<InstanceGetResponseAuthConfigResolvedBranding>,
    /// Strict writes for this instance's secret keys: a Backend API write that carries a body field
    /// the endpoint does not know is refused with 422 UNKNOWN_FIELD instead of being accepted and
    /// ignored. true for every instance created from 2026-10 on; older instances stay false
    /// (lenient: the ignored fields are named in the Atlas-Unknown-Fields response header) until
    /// set. One request overrides it with the Atlas-Strict: true | false header. Fields that look
    /// writable and have their own call (verified on an email address, banned, …) are refused with
    /// 422 READ_ONLY_FIELD either way; echoed id, object, created_at and updated_at are 422
    /// READ_ONLY_FIELD only when strict.
    #[serde(
        rename = "strictRequestBodies",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub strict_request_bodies: Option<bool>,
    /// Whether a password sign-up must prove the address with an emailed code before it completes.
    /// When false the sign-up completes at once, but the address stays unverified (verified,
    /// verification.status and email_verified report false) until the user proves it later.
    #[serde(
        rename = "requireEmailVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_email_verification: Option<bool>,
    /// DANGEROUS. When true, addresses that skipped proof because requireEmailVerification was
    /// false are reported as verified again in users, tokens, webhooks and exports (the old
    /// behaviour). Anyone can then sign up as any address and present a verified claim. Atlas still
    /// treats those addresses as unproven when linking social sign-ins, auto-joining organizations
    /// and accepting invitations. Preflight reports email_verified_unproven while this is on.
    #[serde(
        rename = "dangerouslyReportSkippedEmailsAsVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dangerously_report_skipped_emails_as_verified: Option<bool>,
    /// Atlas AS a SAML IdP — "Sign in with Atlas" over SAML for a downstream Service Provider
    /// (direct SAML; no OIDC/atlas_byo needed).
    #[serde(rename = "samlIdp", default, skip_serializing_if = "Option::is_none")]
    pub saml_idp: Option<InstanceGetResponseAuthConfigResolvedSamlIdp>,
    /// Trust JWTs minted by an EXTERNAL issuer as a sign-in credential (e.g. a legacy IdP or your
    /// own token service). The linked identity is stored under provider ext_jwt:&lt;id&gt;.
    #[serde(
        rename = "externalJwt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_jwt: Option<InstanceGetResponseAuthConfigResolvedExternalJwt>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Which first-factor sign-in methods are enabled.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedStrategies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    /// Email one-time code (passwordless).
    #[serde(rename = "emailCode", default, skip_serializing_if = "Option::is_none")]
    pub email_code: Option<bool>,
    /// Magic link.
    #[serde(rename = "emailLink", default, skip_serializing_if = "Option::is_none")]
    pub email_link: Option<bool>,
    /// WebAuthn passkeys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<bool>,
    /// SMS OTP (off by default).
    #[serde(rename = "phoneCode", default, skip_serializing_if = "Option::is_none")]
    pub phone_code: Option<bool>,
    /// Username as a login identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siwe: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siws: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siwf: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedPasswordPolicy {
    #[serde(rename = "minLength", default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<i64>,
    #[serde(
        rename = "requireUppercase",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_uppercase: Option<bool>,
    #[serde(
        rename = "requireNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_number: Option<bool>,
    #[serde(
        rename = "requireSymbol",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_symbol: Option<bool>,
    /// Reject known-breached passwords (HIBP).
    #[serde(
        rename = "checkBreaches",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub check_breaches: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Per-method code/link TTLs, lengths and resend limits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedVerification {
    #[serde(rename = "emailCode", default, skip_serializing_if = "Map::is_empty")]
    pub email_code: Map<String, Value>,
    #[serde(rename = "smsCode", default, skip_serializing_if = "Map::is_empty")]
    pub sms_code: Map<String, Value>,
    #[serde(rename = "magicLink", default, skip_serializing_if = "Map::is_empty")]
    pub magic_link: Map<String, Value>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Session lifetime + token behaviour.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedSession {
    #[serde(rename = "idleMs", default, skip_serializing_if = "Option::is_none")]
    pub idle_ms: Option<i64>,
    #[serde(
        rename = "absoluteMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub absolute_ms: Option<i64>,
    #[serde(
        rename = "jwtTtlSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub jwt_ttl_seconds: Option<i64>,
    #[serde(
        rename = "crossSubdomainCookies",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cross_subdomain_cookies: Option<bool>,
    /// Add email/name to the session JWT.
    #[serde(
        rename = "includeEmailClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_email_claim: Option<bool>,
    /// Add the eu_orgs reader claim.
    #[serde(
        rename = "includeEndUserPoolClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_end_user_pool_claim: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// On PATCH /v1/instance only branding.audiences is applied (per-audience hosted-page branding,
/// merged per hint; see PATCH /v1/branding for the shape). Every other branding field is
/// written with PATCH /v1/branding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedBranding {
    /// Audience hint (\[a-z0-9_-\]{1,32}) → { heading, subheading, logoUrl, primaryColor }, or null
    /// to delete that audience.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub audiences: HashMap<String, InstanceGetResponseAuthConfigResolvedBrandingAudiencesValue>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedBrandingAudiencesValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subheading: Option<String>,
    #[serde(rename = "logoUrl", default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(
        rename = "primaryColor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub primary_color: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Atlas AS a SAML IdP — "Sign in with Atlas" over SAML for a downstream Service Provider
/// (direct SAML; no OIDC/atlas_byo needed).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedSamlIdp {
    /// The SPs Atlas issues signed assertions to.
    #[serde(
        rename = "serviceProviders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub service_providers: Vec<InstanceGetResponseAuthConfigResolvedSamlIdpServiceProvidersItem>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedSamlIdpServiceProvidersItem {
    /// Stable key used in the SSO URL + audit.
    #[serde(default)]
    pub id: String,
    /// The SP's SAML entityId (assertion audience).
    #[serde(rename = "entityId", default)]
    pub entity_id: String,
    /// The SP's Assertion Consumer Service URL (https) the Response is POSTed to.
    #[serde(rename = "acsUrl", default)]
    pub acs_url: String,
    /// User field for the NameID. Default email.
    ///
    /// Known values: `email`, `user_id`.
    #[serde(
        rename = "nameIdField",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub name_id_field: Option<String>,
    /// Extra attribute statements: SAML attribute name → user field / metadata key.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Trust JWTs minted by an EXTERNAL issuer as a sign-in credential (e.g. a legacy IdP or your
/// own token service). The linked identity is stored under provider ext_jwt:&lt;id&gt;.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedExternalJwt {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<InstanceGetResponseAuthConfigResolvedExternalJwtIssuersItem>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetResponseAuthConfigResolvedExternalJwtIssuersItem {
    /// Stable key; the linked identity is stored under provider ext_jwt:&lt;id&gt;.
    #[serde(default)]
    pub id: String,
    /// The expected iss claim.
    #[serde(default)]
    pub issuer: String,
    /// The issuer's JWKS URL, used to verify the token signature.
    #[serde(rename = "jwksUri", default)]
    pub jwks_uri: String,
    /// The expected aud claim.
    #[serde(default)]
    pub audience: String,
    /// Claim to read the email from. Default email.
    #[serde(
        rename = "emailClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email_claim: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Instance auth configuration. Partial + additive on PATCH — omitted sections are untouched.
/// GET /v1/instance returns this resolved (defaults expanded) as auth_config_resolved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolved {
    /// Which first-factor sign-in methods are enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategies: Option<InstanceUpdateResponseAuthConfigResolvedStrategies>,
    #[serde(
        rename = "passwordPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub password_policy: Option<InstanceUpdateResponseAuthConfigResolvedPasswordPolicy>,
    /// Per-method code/link TTLs, lengths and resend limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<InstanceUpdateResponseAuthConfigResolvedVerification>,
    /// Session lifetime + token behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<InstanceUpdateResponseAuthConfigResolvedSession>,
    /// Known values: `off`, `optional`, `required`.
    #[serde(rename = "mfaPolicy", default, skip_serializing_if = "Option::is_none")]
    pub mfa_policy: Option<String>,
    /// public: anyone may sign up. waitlist: unknown addresses join a waitlist (403 WAITLISTED)
    /// until approved. restricted: invitation-only — only invited or waitlist-approved addresses
    /// may sign up (403 SIGN_UP_RESTRICTED otherwise).
    ///
    /// Known values: `public`, `waitlist`, `restricted`.
    #[serde(
        rename = "signUpMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sign_up_mode: Option<String>,
    /// On PATCH /v1/instance only branding.audiences is applied (per-audience hosted-page branding,
    /// merged per hint; see PATCH /v1/branding for the shape). Every other branding field is
    /// written with PATCH /v1/branding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<InstanceUpdateResponseAuthConfigResolvedBranding>,
    /// Strict writes for this instance's secret keys: a Backend API write that carries a body field
    /// the endpoint does not know is refused with 422 UNKNOWN_FIELD instead of being accepted and
    /// ignored. true for every instance created from 2026-10 on; older instances stay false
    /// (lenient: the ignored fields are named in the Atlas-Unknown-Fields response header) until
    /// set. One request overrides it with the Atlas-Strict: true | false header. Fields that look
    /// writable and have their own call (verified on an email address, banned, …) are refused with
    /// 422 READ_ONLY_FIELD either way; echoed id, object, created_at and updated_at are 422
    /// READ_ONLY_FIELD only when strict.
    #[serde(
        rename = "strictRequestBodies",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub strict_request_bodies: Option<bool>,
    /// Whether a password sign-up must prove the address with an emailed code before it completes.
    /// When false the sign-up completes at once, but the address stays unverified (verified,
    /// verification.status and email_verified report false) until the user proves it later.
    #[serde(
        rename = "requireEmailVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_email_verification: Option<bool>,
    /// DANGEROUS. When true, addresses that skipped proof because requireEmailVerification was
    /// false are reported as verified again in users, tokens, webhooks and exports (the old
    /// behaviour). Anyone can then sign up as any address and present a verified claim. Atlas still
    /// treats those addresses as unproven when linking social sign-ins, auto-joining organizations
    /// and accepting invitations. Preflight reports email_verified_unproven while this is on.
    #[serde(
        rename = "dangerouslyReportSkippedEmailsAsVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dangerously_report_skipped_emails_as_verified: Option<bool>,
    /// Atlas AS a SAML IdP — "Sign in with Atlas" over SAML for a downstream Service Provider
    /// (direct SAML; no OIDC/atlas_byo needed).
    #[serde(rename = "samlIdp", default, skip_serializing_if = "Option::is_none")]
    pub saml_idp: Option<InstanceUpdateResponseAuthConfigResolvedSamlIdp>,
    /// Trust JWTs minted by an EXTERNAL issuer as a sign-in credential (e.g. a legacy IdP or your
    /// own token service). The linked identity is stored under provider ext_jwt:&lt;id&gt;.
    #[serde(
        rename = "externalJwt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_jwt: Option<InstanceUpdateResponseAuthConfigResolvedExternalJwt>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Which first-factor sign-in methods are enabled.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedStrategies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
    /// Email one-time code (passwordless).
    #[serde(rename = "emailCode", default, skip_serializing_if = "Option::is_none")]
    pub email_code: Option<bool>,
    /// Magic link.
    #[serde(rename = "emailLink", default, skip_serializing_if = "Option::is_none")]
    pub email_link: Option<bool>,
    /// WebAuthn passkeys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<bool>,
    /// SMS OTP (off by default).
    #[serde(rename = "phoneCode", default, skip_serializing_if = "Option::is_none")]
    pub phone_code: Option<bool>,
    /// Username as a login identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siwe: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siws: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siwf: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedPasswordPolicy {
    #[serde(rename = "minLength", default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<i64>,
    #[serde(
        rename = "requireUppercase",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_uppercase: Option<bool>,
    #[serde(
        rename = "requireNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_number: Option<bool>,
    #[serde(
        rename = "requireSymbol",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub require_symbol: Option<bool>,
    /// Reject known-breached passwords (HIBP).
    #[serde(
        rename = "checkBreaches",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub check_breaches: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Per-method code/link TTLs, lengths and resend limits.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedVerification {
    #[serde(rename = "emailCode", default, skip_serializing_if = "Map::is_empty")]
    pub email_code: Map<String, Value>,
    #[serde(rename = "smsCode", default, skip_serializing_if = "Map::is_empty")]
    pub sms_code: Map<String, Value>,
    #[serde(rename = "magicLink", default, skip_serializing_if = "Map::is_empty")]
    pub magic_link: Map<String, Value>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Session lifetime + token behaviour.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedSession {
    #[serde(rename = "idleMs", default, skip_serializing_if = "Option::is_none")]
    pub idle_ms: Option<i64>,
    #[serde(
        rename = "absoluteMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub absolute_ms: Option<i64>,
    #[serde(
        rename = "jwtTtlSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub jwt_ttl_seconds: Option<i64>,
    #[serde(
        rename = "crossSubdomainCookies",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cross_subdomain_cookies: Option<bool>,
    /// Add email/name to the session JWT.
    #[serde(
        rename = "includeEmailClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_email_claim: Option<bool>,
    /// Add the eu_orgs reader claim.
    #[serde(
        rename = "includeEndUserPoolClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_end_user_pool_claim: Option<bool>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// On PATCH /v1/instance only branding.audiences is applied (per-audience hosted-page branding,
/// merged per hint; see PATCH /v1/branding for the shape). Every other branding field is
/// written with PATCH /v1/branding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedBranding {
    /// Audience hint (\[a-z0-9_-\]{1,32}) → { heading, subheading, logoUrl, primaryColor }, or null
    /// to delete that audience.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub audiences: HashMap<String, InstanceUpdateResponseAuthConfigResolvedBrandingAudiencesValue>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedBrandingAudiencesValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subheading: Option<String>,
    #[serde(rename = "logoUrl", default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(
        rename = "primaryColor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub primary_color: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Atlas AS a SAML IdP — "Sign in with Atlas" over SAML for a downstream Service Provider
/// (direct SAML; no OIDC/atlas_byo needed).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedSamlIdp {
    /// The SPs Atlas issues signed assertions to.
    #[serde(
        rename = "serviceProviders",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub service_providers: Vec<InstanceUpdateResponseAuthConfigResolvedSamlIdpServiceProvidersItem>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedSamlIdpServiceProvidersItem {
    /// Stable key used in the SSO URL + audit.
    #[serde(default)]
    pub id: String,
    /// The SP's SAML entityId (assertion audience).
    #[serde(rename = "entityId", default)]
    pub entity_id: String,
    /// The SP's Assertion Consumer Service URL (https) the Response is POSTed to.
    #[serde(rename = "acsUrl", default)]
    pub acs_url: String,
    /// User field for the NameID. Default email.
    ///
    /// Known values: `email`, `user_id`.
    #[serde(
        rename = "nameIdField",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub name_id_field: Option<String>,
    /// Extra attribute statements: SAML attribute name → user field / metadata key.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// Trust JWTs minted by an EXTERNAL issuer as a sign-in credential (e.g. a legacy IdP or your
/// own token service). The linked identity is stored under provider ext_jwt:&lt;id&gt;.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedExternalJwt {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<InstanceUpdateResponseAuthConfigResolvedExternalJwtIssuersItem>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceUpdateResponseAuthConfigResolvedExternalJwtIssuersItem {
    /// Stable key; the linked identity is stored under provider ext_jwt:&lt;id&gt;.
    #[serde(default)]
    pub id: String,
    /// The expected iss claim.
    #[serde(default)]
    pub issuer: String,
    /// The issuer's JWKS URL, used to verify the token signature.
    #[serde(rename = "jwksUri", default)]
    pub jwks_uri: String,
    /// The expected aud claim.
    #[serde(default)]
    pub audience: String,
    /// Claim to read the email from. Default email.
    #[serde(
        rename = "emailClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email_claim: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// enabled:false and nothing else when no Chatly connection is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetChatlyIntegrationResponse {
    /// Always `chatly_integration`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The name to pass to getToken({ template: 'chatly' }).
    ///
    /// Always `chatly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// chatly:&lt;channel&gt;
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The iss of every token (your Frontend API origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The JWKS to verify the tokens with (RS256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl_seconds: Option<i64>,
    /// What the chat channel's identity verification needs (no shared secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_verification: Option<InstanceGetChatlyIntegrationResponseIdentityVerification>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// What the chat channel's identity verification needs (no shared secret).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetChatlyIntegrationResponseIdentityVerification {
    /// Always `oidc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// enabled:false and nothing else when no Chatly connection is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetChatlyIntegrationResponse {
    /// Always `chatly_integration`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The name to pass to getToken({ template: 'chatly' }).
    ///
    /// Always `chatly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// chatly:&lt;channel&gt;
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The iss of every token (your Frontend API origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The JWKS to verify the tokens with (RS256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl_seconds: Option<i64>,
    /// What the chat channel's identity verification needs (no shared secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_verification: Option<InstanceSetChatlyIntegrationResponseIdentityVerification>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// What the chat channel's identity verification needs (no shared secret).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetChatlyIntegrationResponseIdentityVerification {
    /// Always `oidc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// enabled:false and nothing else when no Chatly connection is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceDeleteChatlyIntegrationResponse {
    /// Always `chatly_integration`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The name to pass to getToken({ template: 'chatly' }).
    ///
    /// Always `chatly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// chatly:&lt;channel&gt;
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The iss of every token (your Frontend API origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The JWKS to verify the tokens with (RS256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl_seconds: Option<i64>,
    /// What the chat channel's identity verification needs (no shared secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_verification: Option<InstanceDeleteChatlyIntegrationResponseIdentityVerification>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// What the chat channel's identity verification needs (no shared secret).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceDeleteChatlyIntegrationResponseIdentityVerification {
    /// Always `oidc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// enabled:false and nothing else when no Forumulate connection is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetForumulateIntegrationResponse {
    /// Always `forumulate_integration`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<InstanceGetForumulateIntegrationResponseSpacesItem>,
    /// The aud of every reader token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The iss of every token (your Frontend API origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The JWKS to verify the tokens with (RS256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl_seconds: Option<i64>,
    /// The external_jwt provider to store on each space in Forumulate (PUT
    /// /orgs/{orgId}/spaces/{spaceId}/reader-auth providers\[\]), so it accepts these tokens with
    /// no shared secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_auth_provider: Option<InstanceGetForumulateIntegrationResponseReaderAuthProvider>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetForumulateIntegrationResponseSpacesItem {
    #[serde(default)]
    pub id: String,
    /// Where the reader's browser redeems the token.
    #[serde(default)]
    pub redeem_url: String,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The external_jwt provider to store on each space in Forumulate (PUT
/// /orgs/{orgId}/spaces/{spaceId}/reader-auth providers\[\]), so it accepts these tokens with
/// no shared secret.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetForumulateIntegrationResponseReaderAuthProvider {
    /// Always `external_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<InstanceGetForumulateIntegrationResponseReaderAuthProviderConfig>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceGetForumulateIntegrationResponseReaderAuthProviderConfig {
    #[serde(rename = "jwksUrl", default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// enabled:false and nothing else when no Forumulate connection is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetForumulateIntegrationResponse {
    /// Always `forumulate_integration`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<InstanceSetForumulateIntegrationResponseSpacesItem>,
    /// The aud of every reader token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The iss of every token (your Frontend API origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The JWKS to verify the tokens with (RS256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl_seconds: Option<i64>,
    /// The external_jwt provider to store on each space in Forumulate (PUT
    /// /orgs/{orgId}/spaces/{spaceId}/reader-auth providers\[\]), so it accepts these tokens with
    /// no shared secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_auth_provider: Option<InstanceSetForumulateIntegrationResponseReaderAuthProvider>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetForumulateIntegrationResponseSpacesItem {
    #[serde(default)]
    pub id: String,
    /// Where the reader's browser redeems the token.
    #[serde(default)]
    pub redeem_url: String,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The external_jwt provider to store on each space in Forumulate (PUT
/// /orgs/{orgId}/spaces/{spaceId}/reader-auth providers\[\]), so it accepts these tokens with
/// no shared secret.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetForumulateIntegrationResponseReaderAuthProvider {
    /// Always `external_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<InstanceSetForumulateIntegrationResponseReaderAuthProviderConfig>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceSetForumulateIntegrationResponseReaderAuthProviderConfig {
    #[serde(rename = "jwksUrl", default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// enabled:false and nothing else when no Forumulate connection is set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceDeleteForumulateIntegrationResponse {
    /// Always `forumulate_integration`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<InstanceDeleteForumulateIntegrationResponseSpacesItem>,
    /// The aud of every reader token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The iss of every token (your Frontend API origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The JWKS to verify the tokens with (RS256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl_seconds: Option<i64>,
    /// The external_jwt provider to store on each space in Forumulate (PUT
    /// /orgs/{orgId}/spaces/{spaceId}/reader-auth providers\[\]), so it accepts these tokens with
    /// no shared secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reader_auth_provider: Option<InstanceDeleteForumulateIntegrationResponseReaderAuthProvider>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceDeleteForumulateIntegrationResponseSpacesItem {
    #[serde(default)]
    pub id: String,
    /// Where the reader's browser redeems the token.
    #[serde(default)]
    pub redeem_url: String,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The external_jwt provider to store on each space in Forumulate (PUT
/// /orgs/{orgId}/spaces/{spaceId}/reader-auth providers\[\]), so it accepts these tokens with
/// no shared secret.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceDeleteForumulateIntegrationResponseReaderAuthProvider {
    /// Always `external_jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<InstanceDeleteForumulateIntegrationResponseReaderAuthProviderConfig>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstanceDeleteForumulateIntegrationResponseReaderAuthProviderConfig {
    #[serde(rename = "jwksUrl", default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "clientId", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AtlasIdAppPreflightButtonRenderedOriginsItem {
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub last_seen_at: i64,
    #[serde(default)]
    pub requests: i64,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AtlasIdAppPreflightFallbackOriginsItem {
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub last_seen_at: i64,
    #[serde(default)]
    pub requests: i64,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The response of `GET /v1/platform/atlas_id_publisher`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AtlasIdPublisherGetResponse {
    /// Always `atlas_id_publisher`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<i64>,
    #[serde(default)]
    pub skip_consent: bool,
    #[serde(default)]
    pub verification: AtlasIdPublisherGetResponseVerification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AtlasIdPublisherGetResponseVerification {
    #[serde(default)]
    pub record_name: String,
    /// Always `TXT`.
    #[serde(default)]
    pub record_type: String,
    #[serde(default)]
    pub record_value: String,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


/// The response of `GET /v1/policies/{id}/acceptances`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoliciesListAcceptancesResponse {
    /// Always `list`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub data: Vec<PoliciesListAcceptancesResponseDataItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}


#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoliciesListAcceptancesResponseDataItem {
    /// Always `policy_acceptance`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub policy: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version_id: Option<String>,
    /// Known values: `accepted`, `withdrawn`.
    #[serde(default)]
    pub status: String,
    /// signup | signin | reaccept | api | import
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrolled_to_end: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub accepted_at: i64,
    /// Fields this version of the crate does not know about, kept verbatim.
    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// The Chatly / Forumulate integration routes are no longer in the API description; the
// methods stay for source compatibility.
impl Instance<'_> {
    /// `GET /v1/instance/integrations/chatly` — Read the Chatly connection: the channel, and the
    /// issuer / JWKS / audience the channel's identity verification uses for getToken({ template:
    /// 'chatly' }) tokens.
    ///
    /// Returns [`types::InstanceGetChatlyIntegrationResponse`].
    pub async fn get_chatly_integration(
        &self,
    ) -> Result<types::InstanceGetChatlyIntegrationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/instance/integrations/chatly",
                &[],
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/instance/integrations/chatly` — Connect a Chatly channel: getToken({ template:
    /// 'chatly' }) then mints a 120-second RS256 token with aud chatly:&lt;channel&gt;, sub (the
    /// Atlas user id), email, email_verified and name, verifiable against the instance JWKS. A
    /// stored jwt template named chatly takes precedence.
    ///
    /// Takes [`types::InstanceSetChatlyIntegrationBody`]. Returns [`types::InstanceSetChatlyIntegrationResponse`].
    pub async fn set_chatly_integration(
        &self,
        body: &types::InstanceSetChatlyIntegrationBody,
    ) -> Result<types::InstanceSetChatlyIntegrationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/instance/integrations/chatly",
                &[],
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/instance/integrations/chatly` — Remove the Chatly connection; getToken({
    /// template: 'chatly' }) answers 404 unless a stored template has that name.
    ///
    /// Returns [`types::InstanceDeleteChatlyIntegrationResponse`].
    pub async fn delete_chatly_integration(
        &self,
    ) -> Result<types::InstanceDeleteChatlyIntegrationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/instance/integrations/chatly",
                &[],
                None,
                None,
            )
            .await
    }
    /// `GET /v1/instance/integrations/forumulate` — Read the Forumulate connection: the org and
    /// spaces whose readers Atlas signs in, the token audience/issuer/JWKS, and the external_jwt
    /// provider config to store on each space.
    ///
    /// Returns [`types::InstanceGetForumulateIntegrationResponse`].
    pub async fn get_forumulate_integration(
        &self,
    ) -> Result<types::InstanceGetForumulateIntegrationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/instance/integrations/forumulate",
                &[],
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/instance/integrations/forumulate` — Connect Forumulate spaces: Atlas then mints
    /// reader tokens for the signed-in user (GET /v1/client/forumulate/reader_token), so your app
    /// needs no reader hand-off route. Store the returned reader_auth_provider on each space in
    /// Forumulate. Replaces the whole connection.
    ///
    /// Takes [`types::InstanceSetForumulateIntegrationBody`]. Returns [`types::InstanceSetForumulateIntegrationResponse`].
    pub async fn set_forumulate_integration(
        &self,
        body: &types::InstanceSetForumulateIntegrationBody,
    ) -> Result<types::InstanceSetForumulateIntegrationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/instance/integrations/forumulate",
                &[],
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/instance/integrations/forumulate` — Remove the Forumulate connection;
    /// reader_token answers 404 from then on.
    ///
    /// Returns [`types::InstanceDeleteForumulateIntegrationResponse`].
    pub async fn delete_forumulate_integration(
        &self,
    ) -> Result<types::InstanceDeleteForumulateIntegrationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/instance/integrations/forumulate",
                &[],
                None,
                None,
            )
            .await
    }
}
