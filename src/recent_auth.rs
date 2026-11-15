//! Step-up checks on a verified session token: how recently the user
//! authenticated, and whether they proved a second factor. Session and template
//! tokens carry `auth_time` (the first-factor sign-in, or the last step-up),
//! `amr` and `acr` (`urn:atlas:acr:basic`, `urn:atlas:acr:mfa`,
//! `urn:atlas:acr:step_up`). The peer of `authenticatedWithin` / `usedMultiFactor`
//! in `@atlasauth/backend`.
//!
//! ```
//! # fn demo(claims: &atlasauth::Claims) -> Result<(), &'static str> {
//! if !claims.authenticated_within(300) {
//!     // Ask the browser to step up, then retry the request.
//!     return Err("reauthentication_required");
//! }
//! # Ok(()) }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::claims::Claims;

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Whether `auth_time` (epoch seconds) is within `max_age_seconds` of `now_ms`.
/// A missing or non-finite `auth_time` is never recent.
pub fn authenticated_within(auth_time: Option<f64>, max_age_seconds: i64, now_ms_override: Option<i64>) -> bool {
    match auth_time {
        Some(at) if at.is_finite() => (now_ms_override.unwrap_or_else(now_ms) as f64) / 1000.0 - at <= max_age_seconds as f64,
        _ => false,
    }
}

/// Whether the claims prove a second factor: `acr` is `urn:atlas:acr:mfa`, or
/// `amr` includes `mfa`.
pub fn used_multi_factor(acr: Option<&str>, amr: Option<&[String]>) -> bool {
    acr == Some("urn:atlas:acr:mfa") || amr.is_some_and(|m| m.iter().any(|x| x == "mfa"))
}

/// The "requires MFA" rule: the server's `mfa_satisfied` verdict when present,
/// else `mfa == true`, else [`used_multi_factor`], else an enterprise SSO sign-in.
/// The same rule as [`Claims::mfa_satisfied`], over loose values.
pub fn mfa_satisfied(
    mfa_satisfied: Option<bool>,
    mfa: Option<bool>,
    acr: Option<&str>,
    amr: Option<&[String]>,
    sso_connection_id: Option<&str>,
) -> bool {
    if let Some(v) = mfa_satisfied {
        return v;
    }
    mfa == Some(true) || used_multi_factor(acr, amr) || sso_connection_id.is_some()
}

/// Whether the session meets the active organization's MFA policy: true when the
/// organization does not require MFA, or the token says `org_mfa_ok`. The claims
/// describe the ACTIVE organization only: pass `org` (its Atlas id or external id)
/// to also require that the token's active organization is that one.
pub fn mfa_org_satisfied(claims: &Claims, org: Option<&str>) -> bool {
    let flag = |k: &str| claims.extra.get(k).and_then(Value::as_bool);
    let required = flag("org_mfa_required") == Some(true);
    let ok = flag("org_mfa_ok") == Some(true);
    let Some(org) = org else { return !required || ok };
    let ext = claims.extra.get("org_external_id").and_then(Value::as_str);
    let matches = claims.org_id.as_deref() == Some(org) || ext == Some(org);
    if required {
        // Withheld claims carry no org_id: the MFA flags are then all the token says.
        return ok && (matches || claims.org_id.is_none());
    }
    matches
}

impl Claims {
    /// When the user last authenticated (`auth_time`, epoch seconds), when the token carries it.
    pub fn auth_time(&self) -> Option<f64> {
        self.extra.get("auth_time").and_then(Value::as_f64)
    }

    /// Whether the user authenticated within `max_age_seconds` of now. A token
    /// without `auth_time` never is.
    pub fn authenticated_within(&self, max_age_seconds: i64) -> bool {
        authenticated_within(self.auth_time(), max_age_seconds, None)
    }

    /// [`Claims::authenticated_within`] against an explicit clock (epoch milliseconds).
    pub fn authenticated_within_at(&self, max_age_seconds: i64, now_ms: i64) -> bool {
        authenticated_within(self.auth_time(), max_age_seconds, Some(now_ms))
    }

    /// Whether the session proved a second factor (`acr` is mfa, or `amr` includes `mfa`).
    pub fn used_multi_factor(&self) -> bool {
        used_multi_factor(self.acr.as_deref(), self.amr.as_deref())
    }

    /// Whether the session meets the active organization's MFA policy; see [`mfa_org_satisfied`].
    pub fn mfa_org_satisfied(&self, org: Option<&str>) -> bool {
        mfa_org_satisfied(self, org)
    }
}
