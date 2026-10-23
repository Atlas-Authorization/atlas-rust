//! OpenID Connect Back-Channel Logout 1.0: verify the `logout_token` Atlas
//! POSTs to your app's back-channel logout URI when a user signs out, so you
//! can end the matching local session(s).
//!
//! The token is verified locally against the same cached JWKS as session
//! tokens ([`AtlasBackend::verify_logout_token`]), with the §2.6 rules: RS256
//! only, `iss` equal to the configured issuer, `aud` containing your client id,
//! `iat` present (and not in the future), `exp` honoured when present, a `jti`,
//! the back-channel logout event, a `sid` and/or `sub`, no `nonce`, and a
//! `typ` header of `logout+jwt` when one is present.

use std::collections::HashMap;
use std::sync::Mutex;

use jsonwebtoken::{decode_header, Validation};
use serde_json::Value;

use crate::error::VerifyError;
use crate::jwks::FetchOutcome;
use crate::verify::{AtlasBackend, CLOCK_SKEW_SECONDS};

/// The `events` member a logout token must carry.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The JWT `typ` header a logout token carries.
pub const LOGOUT_TOKEN_TYPE: &str = "logout+jwt";

/// The claims of a verified logout token. At least one of `sub` / `sid` is
/// set: end every local session for `sid` when present, otherwise every
/// session of `sub`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutTokenClaims {
    /// The user whose session(s) ended.
    pub sub: Option<String>,
    /// The session that ended — the same `sid` your id_token carried.
    pub sid: Option<String>,
    /// The token's unique id (use it to refuse a replay).
    pub jti: String,
    /// Issued-at, epoch seconds.
    pub iat: i64,
}

impl AtlasBackend {
    /// Verify a back-channel `logout_token` (the `logout_token` form field of
    /// the POST Atlas sends) for the OIDC client `client_id`.
    ///
    /// Uses this verifier's issuer and JWKS: build the [`AtlasBackend`] with
    /// the issuer of the OpenID provider that registered your client (for Sign
    /// in with Atlas apps, `https://atlasauth.net`; for your instance's own
    /// OAuth clients, your instance issuer).
    ///
    /// Every failure is a [`VerifyError`] (`Malformed`, `Invalid`, or `NoKeys`).
    /// Answer `503` with `Retry-After` when [`VerifyError::is_retryable`] is
    /// true (the issuer's keys could not be fetched; Atlas retries), and `400`
    /// otherwise (Atlas never retries a `400`).
    ///
    /// ```no_run
    /// # async fn demo(atlas: &atlasauth::AtlasBackend, form_logout_token: &str) {
    /// match atlas.verify_logout_token(form_logout_token, "my_client_id").await {
    ///     Ok(claims) => { /* end sessions by claims.sid or claims.sub; reply 200 */ }
    ///     Err(e) if e.is_retryable() => { /* reply 503 + Retry-After */ }
    ///     Err(_) => { /* reply 400 */ }
    /// }
    /// # }
    /// ```
    pub async fn verify_logout_token(&self, token: &str, client_id: &str) -> Result<LogoutTokenClaims, VerifyError> {
        if token.is_empty() || token.split('.').count() != 3 {
            return Err(VerifyError::Malformed);
        }
        let header = decode_header(token).map_err(|_| VerifyError::Invalid)?;
        if !crate::jwks::SIGNING_ALGS.contains(&header.alg) {
            return Err(VerifyError::Invalid);
        }
        if let Some(typ) = header.typ.as_deref() {
            if !typ.eq_ignore_ascii_case(LOGOUT_TOKEN_TYPE)
                && !typ.eq_ignore_ascii_case("application/logout+jwt")
            {
                return Err(VerifyError::Invalid);
            }
        }
        let kid = header.kid.as_deref();
        let set = match self.jwks.get(kid).await {
            Some(s) if !s.keys.is_empty() => s,
            _ => return Err(VerifyError::NoKeys),
        };
        // A key Atlas just rotated to, whose refetch failed: temporary.
        if let Some(want) = kid {
            if self.jwks.last_outcome() == FetchOutcome::Failed
                && !set.keys.iter().any(|k| k.kid.as_deref() == Some(want))
            {
                return Err(VerifyError::NoKeys);
            }
        }

        // Signature + issuer here; time and the logout-specific claims below,
        // against this verifier's clock.
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.options.issuer.as_str()]);
        validation.set_required_spec_claims(&["iss"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let claims: Option<Value> = crate::jwks::decode_with_set(token, &set, kid, header.alg, &validation);
        let claims = claims.ok_or(VerifyError::Invalid)?;
        let now = ((self.clock)() / 1000) as i64;
        check_logout_claims(&claims, client_id, now)
    }
}

/// The §2.6 claim checks, separated from signature verification.
fn check_logout_claims(claims: &Value, client_id: &str, now: i64) -> Result<LogoutTokenClaims, VerifyError> {
    let skew = CLOCK_SKEW_SECONDS as i64;
    let obj = claims.as_object().ok_or(VerifyError::Invalid)?;

    // aud: a string or an array containing the client id.
    let aud_ok = match obj.get("aud") {
        Some(Value::String(s)) => s == client_id,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(VerifyError::Invalid);
    }

    let iat = obj.get("iat").and_then(Value::as_i64).ok_or(VerifyError::Invalid)?;
    if iat > now + skew {
        return Err(VerifyError::Invalid);
    }
    if let Some(exp) = obj.get("exp") {
        let exp = exp.as_i64().ok_or(VerifyError::Invalid)?;
        if exp + skew < now {
            return Err(VerifyError::Invalid);
        }
    }

    let jti = match obj.get("jti") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(VerifyError::Invalid),
    };

    let event_ok = obj
        .get("events")
        .and_then(Value::as_object)
        .and_then(|events| events.get(BACKCHANNEL_LOGOUT_EVENT))
        .map(Value::is_object)
        .unwrap_or(false);
    if !event_ok {
        return Err(VerifyError::Invalid);
    }

    // A logout token must never be mistaken for an id_token.
    if obj.contains_key("nonce") {
        return Err(VerifyError::Invalid);
    }

    let string_claim = |name: &str| -> Result<Option<String>, VerifyError> {
        match obj.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
            _ => Err(VerifyError::Invalid),
        }
    };
    let sub = string_claim("sub")?;
    let sid = string_claim("sid")?;
    if sub.is_none() && sid.is_none() {
        return Err(VerifyError::Invalid);
    }

    Ok(LogoutTokenClaims { sub, sid, jti, iat })
}

/// A small in-memory guard against a logout token being replayed: remember
/// each accepted `jti` until it can no longer verify, and refuse a repeat.
///
/// One process only — with several instances behind a load balancer, record
/// the `jti` in your shared store (e.g. a Redis `SET jti 1 NX EX 300`) instead.
///
/// ```
/// use atlasauth::LogoutTokenReplayCache;
/// let seen = LogoutTokenReplayCache::new(10_000, 300);
/// assert!(seen.check_and_remember("jti_1", 1_700_000_000));
/// assert!(!seen.check_and_remember("jti_1", 1_700_000_001)); // replay
/// ```
pub struct LogoutTokenReplayCache {
    max_entries: usize,
    ttl_seconds: i64,
    seen: Mutex<HashMap<String, i64>>,
}

impl LogoutTokenReplayCache {
    /// Remember up to `max_entries` ids, each for `ttl_seconds` (use at least
    /// the token lifetime; Atlas logout tokens live two minutes).
    pub fn new(max_entries: usize, ttl_seconds: u64) -> Self {
        LogoutTokenReplayCache {
            max_entries: max_entries.max(1),
            ttl_seconds: ttl_seconds as i64,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// `true` the first time `jti` is seen (and records it); `false` for a
    /// replay. `now` is epoch seconds.
    pub fn check_and_remember(&self, jti: &str, now: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, expires| *expires > now);
        if seen.contains_key(jti) {
            return false;
        }
        if seen.len() >= self.max_entries {
            // Drop the entry closest to expiry to make room.
            if let Some(oldest) = seen.iter().min_by_key(|(_, e)| **e).map(|(k, _)| k.clone()) {
                seen.remove(&oldest);
            }
        }
        seen.insert(jti.to_string(), now + self.ttl_seconds);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Value {
        json!({
            "iss": "https://atlasauth.net", "aud": "cid", "iat": 1000, "exp": 1120, "jti": "j1",
            "sid": "sess_1", "sub": "user_1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} }
        })
    }

    #[test]
    fn claim_rules() {
        assert!(check_logout_claims(&base(), "cid", 1000).is_ok());
        let mut v = base();
        v["aud"] = json!(["x", "cid"]);
        assert!(check_logout_claims(&v, "cid", 1000).is_ok());
        let mut v = base();
        v["events"][BACKCHANNEL_LOGOUT_EVENT] = json!("yes");
        assert!(check_logout_claims(&v, "cid", 1000).is_err());
        let mut v = base();
        v.as_object_mut().unwrap().remove("sid");
        v.as_object_mut().unwrap().remove("sub");
        assert!(check_logout_claims(&v, "cid", 1000).is_err());
        let mut v = base();
        v.as_object_mut().unwrap().remove("exp");
        assert!(check_logout_claims(&v, "cid", 5000).is_ok());
    }
}
