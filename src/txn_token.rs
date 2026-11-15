//! Verify a Transaction Token (draft-ietf-oauth-transaction-tokens) a service
//! received: `typ` `txntoken+jwt`, signed by the issuer's keys, for THIS trust
//! domain, unexpired, with the required claims. A recipient must refuse a token
//! whose `aud` is not its own trust domain.

use jsonwebtoken::{decode_header, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::jwks::{decode_with_set, Jwks, SIGNING_ALGS};

/// The claims of a verified transaction token.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TxnTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Value,
    pub iat: i64,
    pub exp: i64,
    /// The transaction id.
    pub txn: String,
    /// Space-delimited scopes.
    pub scope: String,
    /// The request workload.
    pub req_wl: String,
    /// Transaction context.
    #[serde(default)]
    pub tctx: Option<Map<String, Value>>,
    /// Request context.
    #[serde(default)]
    pub rctx: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl TxnTokenClaims {
    /// The scopes, split on spaces.
    pub fn scopes(&self) -> Vec<&str> {
        self.scope.split(' ').filter(|s| !s.is_empty()).collect()
    }
}

/// What to verify a transaction token against.
#[derive(Debug, Clone)]
pub struct TxnTokenOptions {
    /// The issuer URL the token's `iss` must equal (a trailing slash is ignored).
    pub issuer: String,
    /// This service's trust domain: the token's `aud` must be exactly it.
    pub trust_domain: String,
    /// Epoch seconds to verify at; `None` reads the system clock.
    pub now_seconds: Option<i64>,
}

/// Verify `token` against the issuer's keys. Every failure is one coarse error
/// string; nothing is revealed about which check failed.
pub fn verify_transaction_token(token: &str, jwks: &Jwks, opts: &TxnTokenOptions) -> Result<TxnTokenClaims, &'static str> {
    const INVALID: &str = "The transaction token is invalid, expired, or for another trust domain.";
    let header = decode_header(token).map_err(|_| INVALID)?;
    if header.typ.as_deref() != Some("txntoken+jwt") || !SIGNING_ALGS.contains(&header.alg) {
        return Err(INVALID);
    }
    let issuer = opts.issuer.trim_end_matches('/');
    let mut v = Validation::new(header.alg);
    v.set_audience(&[opts.trust_domain.as_str()]);
    v.set_issuer(&[issuer]);
    v.leeway = 5;
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    if let Some(now) = opts.now_seconds {
        // jsonwebtoken reads the system clock: check the window ourselves for a pinned time.
        v.validate_exp = false;
        let claims: TxnTokenClaims = decode_with_set(token, jwks, header.kid.as_deref(), header.alg, &v).ok_or(INVALID)?;
        if claims.exp + 5 <= now {
            return Err(INVALID);
        }
        return Ok(claims);
    }
    decode_with_set(token, jwks, header.kid.as_deref(), header.alg, &v).ok_or(INVALID)
}
