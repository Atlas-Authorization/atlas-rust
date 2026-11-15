//! Verifier for the signed session status list (`GET /v1/sessions/revocations/status-list`).
//!
//! The list is a JWT (`typ` `statuslist+jwt`) signed with the instance session key (RS256, PS256, ES256,
//! ES384 or EdDSA; the key type is checked against the algorithm). It carries the first `hash_bytes` bytes
//! of the SHA-256 of every session id revoked in its window, sorted, as one base64url string.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode_header, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::jwks::{decode_with_set, Jwks, JwksCache, JwksSource, SIGNING_ALGS};

/// Why a status list was refused. A list that fails is never used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StatusListError {
    #[error("invalid session status list: malformed")]
    Malformed,
    #[error("invalid session status list: unsupported")]
    Unsupported,
    #[error("invalid session status list: bad signature or no matching key")]
    BadSignature,
    #[error("invalid session status list: bad claims")]
    BadClaims,
    #[error("invalid session status list: expired")]
    Expired,
}

/// A verified list and its lookup.
#[derive(Debug, Clone)]
pub struct VerifiedStatusList {
    list: Vec<u8>,
    hash_bytes: usize,
    /// Sessions in the list.
    pub count: usize,
    /// More sessions were revoked than fit: a miss proves nothing, use the feed.
    pub truncated: bool,
    /// Epoch ms the list was issued.
    pub issued_at_ms: i64,
    /// Epoch ms the list stops being valid.
    pub expires_at_ms: i64,
    /// Epoch ms the list reaches back to.
    pub since_ms: i64,
}

impl VerifiedStatusList {
    /// True when the session id's hash is in the list.
    pub fn has(&self, sid: &str) -> bool {
        let digest = Sha256::digest(sid.as_bytes());
        let needle = &digest[..self.hash_bytes];
        let (mut lo, mut hi) = (0usize, self.count as isize - 1);
        while lo as isize <= hi {
            let mid = (lo as isize + hi) as usize / 2;
            match self.list[mid * self.hash_bytes..(mid + 1) * self.hash_bytes].cmp(needle) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid as isize - 1,
            }
        }
        false
    }
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    token_use: Option<String>,
    exp: f64,
    iat: f64,
    since: f64,
    hash_bytes: f64,
    count: f64,
    #[serde(default)]
    h: Option<String>,
    #[serde(default)]
    truncated: Option<bool>,
}

/// Verify the signed list against `jwks`. `issuer`, when given, must equal the list's `iss`. `now_ms` is the
/// clock; `skew_seconds` the allowed skew (30 in the other SDKs).
pub fn verify_status_list_token(
    token: &str,
    jwks: &Jwks,
    issuer: Option<&str>,
    now_ms: i64,
    skew_seconds: i64,
) -> Result<VerifiedStatusList, StatusListError> {
    if token.split('.').count() != 3 || token.len() > 4_000_000 {
        return Err(StatusListError::Malformed);
    }
    let header = decode_header(token).map_err(|_| StatusListError::Malformed)?;
    if header.typ.as_deref() != Some("statuslist+jwt") || !SIGNING_ALGS.contains(&header.alg) {
        return Err(StatusListError::Unsupported);
    }
    let mut v = Validation::new(header.alg);
    v.set_audience(&["atlas:session-status-list"]);
    v.set_required_spec_claims(&["aud"]);
    // The window is checked below against the injected clock.
    v.validate_exp = false;
    v.validate_nbf = false;
    let c: Claims = decode_with_set(token, jwks, header.kid.as_deref(), header.alg, &v).ok_or(StatusListError::BadSignature)?;
    if c.token_use.as_deref() != Some("session_status_list") {
        return Err(StatusListError::BadClaims);
    }
    if let Some(want) = issuer {
        if c.iss.as_deref() != Some(want) {
            return Err(StatusListError::BadClaims);
        }
    }
    let now_s = now_ms / 1000;
    if c.exp as i64 + skew_seconds < now_s {
        return Err(StatusListError::Expired);
    }
    if c.iat as i64 - skew_seconds > now_s {
        return Err(StatusListError::BadClaims);
    }
    let whole = |f: f64| (f.fract() == 0.0 && f >= 0.0).then_some(f as usize);
    let hash_bytes = whole(c.hash_bytes).filter(|h| (4..=32).contains(h)).ok_or(StatusListError::BadClaims)?;
    let count = whole(c.count).ok_or(StatusListError::BadClaims)?;
    let list = URL_SAFE_NO_PAD.decode(c.h.as_deref().ok_or(StatusListError::BadClaims)?).map_err(|_| StatusListError::Malformed)?;
    if list.len() != count * hash_bytes {
        return Err(StatusListError::BadClaims);
    }
    Ok(VerifiedStatusList {
        list,
        hash_bytes,
        count,
        truncated: c.truncated == Some(true),
        issued_at_ms: c.iat as i64 * 1000,
        expires_at_ms: c.exp as i64 * 1000,
        since_ms: c.since as i64,
    })
}

/// Where the signed list is verified against: the instance JWKS and the issuer the list must carry.
pub struct StatusListSource {
    pub(crate) jwks: JwksCache,
    pub(crate) issuer: Option<String>,
    pub(crate) window_seconds: Option<u64>,
}

impl StatusListSource {
    /// Fetch the instance JWKS from `jwks_url` through `source` (cached, with the usual kid-miss throttle).
    /// Strongly recommended: pass the `issuer`, or any key in the JWKS may vouch for any issuer.
    pub fn new(jwks_url: impl Into<String>, source: Arc<dyn JwksSource>, issuer: Option<String>) -> Self {
        StatusListSource { jwks: JwksCache::new(Some(jwks_url.into()), None, Some(source), None, None, None), issuer, window_seconds: None }
    }

    /// A fixed key set (hermetic: nothing is fetched), for tests and offline use.
    pub fn from_static(jwks: Jwks, issuer: Option<String>) -> Self {
        StatusListSource { jwks: JwksCache::new(None, Some(jwks), None, None, None, None), issuer, window_seconds: None }
    }

    /// How far back the list reaches (`window_seconds`); use at least your longest token lifetime.
    pub fn with_window_seconds(mut self, seconds: u64) -> Self {
        self.window_seconds = Some(seconds);
        self
    }
}
