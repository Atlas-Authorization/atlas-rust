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
