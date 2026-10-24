//! The decoded payload of a verified Atlas session JWT.
//!
//! Known claims are typed; everything else is preserved in [`Claims::extra`].
//! Claim names and semantics match `@atlasauth/backend` (`SessionClaims`),
//! `atlas-go` (`SessionClaims`), and the Ruby verifier exactly.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::user::real_email;

/// A verified session's claims. Construct one only via
/// [`crate::AtlasBackend::verify`]; a bare `Claims` carries no proof.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Claims {
    /// Issuer — the instance's FAPI origin. Checked against the configured
    /// `issuer` during verification.
    pub iss: String,
    /// Subject — the Atlas user id (`user_…`).
    pub sub: String,
    /// Session id (`sess_…`). Optional only for robustness against legacy
    /// tokens; present on every current session.
    #[serde(default)]
    pub sid: Option<String>,
    /// Expiry, epoch seconds.
    pub exp: i64,
    /// Not-before, epoch seconds.
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Issued-at, epoch seconds.
    #[serde(default)]
    pub iat: Option<i64>,
    /// Authorized party (the origin the token was minted for).
    #[serde(default)]
    pub azp: Option<String>,
    /// Session format version.
    #[serde(default)]
    pub sv: Option<i64>,
    /// Whether the session satisfied MFA.
    #[serde(default)]
    pub mfa: Option<bool>,
    /// Active organization id.
    #[serde(default)]
    pub org_id: Option<String>,
    /// Active organization slug.
    #[serde(default)]
    pub org_slug: Option<String>,
    /// The subject's role in the active organization.
    #[serde(default)]
    pub org_role: Option<String>,
    /// The subject's permissions in the active organization.
    #[serde(default)]
    pub org_permissions: Option<Vec<String>>,
    /// The enterprise SSO connection the session was made through
    /// (`sso_connection_id`).
    #[serde(default)]
    pub sso_connection_id: Option<String>,
    /// The Atlas organization that owns the SSO connection
    /// (`sso_organization_id`); absent for an instance-wide connection.
    /// Independent of `org_id`: scope a per-organization "require SSO" rule on
    /// this, never on "signed in via SSO".
    #[serde(default)]
    pub sso_organization_id: Option<String>,
    /// The connection protocol (`sso_connection_type`): `saml` or `oidc`.
    #[serde(default)]
    pub sso_connection_type: Option<String>,
    /// §migration R3 — the subject's primary verified email, present only when
    /// the instance opted in (`session.includeEmailClaim`). A snapshot at mint
    /// time, not a live lookup.
    #[serde(default)]
    pub email: Option<String>,
    /// §migration R3 — the subject's `external_id`, when set.
    #[serde(default)]
    pub external_id: Option<String>,
    /// §13.1 OP token-confusion marker. A first-party session either omits this
    /// or carries `"session"`; anything else is an OP access/id token being
    /// replayed and is rejected during verification.
    #[serde(default)]
    pub token_use: Option<String>,
    /// Audience (S4). A first-party session token carries its instance id as
    /// `aud` by default. Verification checks it only when one or more expected
    /// audiences are configured (then `aud` must contain at least one); an
    /// unconfigured verifier ignores it. The OP token-confusion guard is the
    /// `token_use:"session"` marker, not the presence of `aud`.
    #[serde(default)]
    pub aud: Option<Value>,
    /// Every claim not modelled above (e.g. `act`, `pla`, `fea`, JWT-template
    /// custom claims).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Claims {
    /// Whether `org_role` equals `role`.
    pub fn has_role(&self, role: &str) -> bool {
        self.org_role.as_deref() == Some(role)
    }

    /// Whether `org_permissions` contains `permission`. Reading the claim rather
    /// than calling Atlas is the whole point of putting permissions in the
    /// token: a permission change takes effect within one token lifetime, the
    /// same bound as revocation.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.org_permissions
            .as_ref()
            .map(|ps| ps.iter().any(|p| p == permission))
            .unwrap_or(false)
    }

    /// The `app_roles` claim: the user's instance-wide app roles.
    pub fn app_roles(&self) -> Vec<&str> {
        claim_strings(&self.extra, "app_roles")
    }

    /// The `app_permissions` claim: the union of the user's app roles' permissions.
    pub fn app_permissions(&self) -> Vec<&str> {
        claim_strings(&self.extra, "app_permissions")
    }

    /// Whether the user holds the app role. Needs no active organization.
    pub fn has_app_role(&self, role: &str) -> bool {
        self.app_roles().contains(&role)
    }

    /// Whether the user's app roles grant the permission. Needs no active organization.
    pub fn has_app_permission(&self, permission: &str) -> bool {
        self.app_permissions().contains(&permission)
    }

    /// The `pol` claim: the accepted version of every required policy, keyed
    /// by policy key (for example `{"tos": "2026-10-24"}`). Present only when
    /// the instance turned on the policy session claim; empty otherwise.
    pub fn pol(&self) -> std::collections::BTreeMap<&str, &str> {
        self.extra
            .get("pol")
            .and_then(Value::as_object)
            .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.as_str(), v))).collect())
            .unwrap_or_default()
    }

    /// Whether the token records acceptance of `version` of the policy `key`.
    pub fn has_accepted_policy(&self, key: &str, version: &str) -> bool {
        self.pol().get(key).copied() == Some(version)
    }

    /// The subject's real email from the `email` claim, or `None` when the claim
    /// is absent, empty, or the `@no-email.invalid` placeholder Atlas seeds for a
    /// provider that shares no email.
    pub fn real_email(&self) -> Option<&str> {
        self.email.as_deref().and_then(real_email)
    }

    /// The RFC 8693 `act.sub` — the operator acting *as* this user — when this is
    /// an impersonation session, else `None`. Informational only; never an
    /// authorization input.
    pub fn actor(&self) -> Option<&str> {
        self.extra
            .get("act")
            .and_then(|v| v.get("sub"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }
}

fn claim_strings<'a>(extra: &'a Map<String, Value>, name: &str) -> Vec<&'a str> {
    extra
        .get(name)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}
