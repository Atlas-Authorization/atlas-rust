//! §7.3 session-token verification by customer backends.
//!
//! The design constraint that matters is what this does NOT do: it never calls
//! Atlas on the hot path. A customer's API handling thousands of requests a
//! second cannot make an outbound call to verify each one — and a verifier that
//! did would make Atlas's availability the customer's availability. So the path
//! is local, against a cached JWKS, and the revocation window is bounded instead
//! by the short token lifetime.

use std::sync::Arc;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::claims::Claims;
use crate::clock::Clock;
use crate::error::{ConfigError, VerifyError};
use crate::jwks::{JwksCache, JwksSource};

/// §7.3: five seconds either side, matching the server's minting tolerance.
pub const CLOCK_SKEW_SECONDS: u64 = 5;

/// Configuration for an [`AtlasBackend`]. Build it with
/// [`AtlasBackend::builder`]; the raw struct is public so options read clearly.
#[derive(Clone)]
pub struct AtlasBackendOptions {
    /// Expected `iss`. Required — an unchecked issuer accepts any Atlas
    /// instance's tokens. This is your instance's FAPI origin, e.g.
    /// `https://your-instance-fapi.atlasauth.net`.
    pub issuer: String,
    /// Optional `azp` allowlist. When non-empty, a token minted for a different
    /// origin is refused — what stops a token issued to one of your apps being
    /// replayed against another.
    pub authorized_parties: Vec<String>,
    /// §S4 expected audiences. When non-empty, a verified token's `aud` must
    /// contain AT LEAST ONE of these (OR semantics — a verifier that serves
    /// several audiences accepts a token for any of them). When empty (the
    /// default), `aud` is not checked: a first-party session token carries its
    /// instance id as `aud` by default, so it still verifies. The OP
    /// token-confusion guard is the positive `token_use:"session"` marker, NOT
    /// the presence of `aud` (matching the TS/Go/Ruby peers).
    pub audiences: Vec<String>,
}

/// Builder for an [`AtlasBackend`]. Supply exactly one key source: a `jwks_url`
/// (fetched + cached — the production default) or a `static_jwks` (fully offline
/// — the hermetic path for CI).
pub struct AtlasBackendBuilder {
    issuer: String,
    jwks_url: Option<String>,
    static_jwks: Option<crate::jwks::Jwks>,
    authorized_parties: Vec<String>,
    audiences: Vec<String>,
    source: Option<Arc<dyn JwksSource>>,
    clock: Option<Clock>,
    ttl_ms: Option<u64>,
    refetch_interval_ms: Option<u64>,
}

impl AtlasBackendBuilder {
    fn new(issuer: impl Into<String>) -> Self {
        AtlasBackendBuilder {
            issuer: issuer.into(),
            jwks_url: None,
            static_jwks: None,
            authorized_parties: Vec::new(),
            audiences: Vec::new(),
            source: None,
            clock: None,
            ttl_ms: None,
            refetch_interval_ms: None,
        }
    }

    /// Fetch and cache keys from this JWKS URL (typically
    /// `https://your-instance-fapi.atlasauth.net/.well-known/jwks.json`).
    pub fn jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    /// Verify against a fixed key set with no network call — the hermetic CI
    /// path. Mutually exclusive with [`Self::jwks_url`].
    pub fn static_jwks(mut self, jwks: crate::jwks::Jwks) -> Self {
        self.static_jwks = Some(jwks);
        self
    }

    /// Refuse a token whose `azp` is not on this allowlist.
    pub fn authorized_parties<I, S>(mut self, parties: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.authorized_parties = parties.into_iter().map(Into::into).collect();
        self
    }

    /// §S4 require the token's `aud` to contain this audience. Call more than
    /// once, or use [`Self::audiences`], to accept a token for ANY of several
    /// audiences (OR).
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// §S4 require the token's `aud` to contain at least ONE of these audiences
    /// (OR). Use this when a single verifier serves tokens minted for several
    /// instances / resource servers. Appends to any already set via
    /// [`Self::audience`].
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.audiences.extend(audiences.into_iter().map(Into::into));
        self
    }

    /// Inject a custom JWKS fetch transport (a mock in tests, or a non-reqwest
    /// HTTP client). Requires a [`Self::jwks_url`] to know what URL to fetch.
    pub fn jwks_source(mut self, source: Arc<dyn JwksSource>) -> Self {
        self.source = Some(source);
        self
    }

    /// Inject a clock for the JWKS cache's TTL/throttle timing (tests).
    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Override the JWKS cache TTL (default 1 hour).
    pub fn ttl_ms(mut self, ttl_ms: u64) -> Self {
        self.ttl_ms = Some(ttl_ms);
        self
    }

    /// Override the kid-miss refetch interval (default 60 s).
    pub fn refetch_interval_ms(mut self, ms: u64) -> Self {
        self.refetch_interval_ms = Some(ms);
        self
    }

    /// Finish building. Fails when the key-source invariant is violated (exactly
    /// one of `jwks_url` / `static_jwks`) or when no fetch transport is available
    /// for a URL source (compile without the `reqwest-transport` feature and you
    /// must supply [`Self::jwks_source`]).
    pub fn build(self) -> Result<AtlasBackend, ConfigError> {
        if self.issuer.is_empty() {
            return Err(ConfigError::new(
                "AtlasBackend requires a non-empty issuer; an unchecked issuer accepts any Atlas instance's tokens.",
            ));
        }

        let has_url = self
            .jwks_url
            .as_deref()
            .map(|u| !u.is_empty())
            .unwrap_or(false);
        let has_static = self.static_jwks.is_some();
        if has_url == has_static {
            return Err(ConfigError::new(
                "AtlasBackend needs exactly one key source: pass `jwks_url` (fetch from the instance) OR `static_jwks` (offline), not both and not neither.",
            ));
        }

        // Resolve the fetch source for a URL-backed cache.
        let source: Option<Arc<dyn JwksSource>> = if has_static {
            None
        } else if let Some(s) = self.source {
            Some(s)
        } else {
            default_source()?
        };

        let cache = JwksCache::new(
            self.jwks_url,
            self.static_jwks,
            source,
            self.clock,
            self.ttl_ms,
            self.refetch_interval_ms,
        );

        Ok(AtlasBackend {
            options: AtlasBackendOptions {
                issuer: self.issuer,
                authorized_parties: self.authorized_parties,
                audiences: self.audiences,
            },
            jwks: cache,
        })
    }
}

#[cfg(feature = "reqwest-transport")]
fn default_source() -> Result<Option<Arc<dyn JwksSource>>, ConfigError> {
    Ok(Some(Arc::new(crate::transport::ReqwestTransport::new())))
}

#[cfg(not(feature = "reqwest-transport"))]
fn default_source() -> Result<Option<Arc<dyn JwksSource>>, ConfigError> {
    Err(ConfigError::new(
        "no JWKS transport: build with the `reqwest-transport` feature, or supply `.jwks_source(...)`.",
    ))
}

/// Verifies Atlas session JWTs locally against the instance JWKS, with caching.
pub struct AtlasBackend {
    options: AtlasBackendOptions,
    jwks: JwksCache,
}

impl AtlasBackend {
    /// The common case: fetch keys from `jwks_url`, pin `issuer`. Available with
    /// the `reqwest-transport` feature (on by default).
    #[cfg(feature = "reqwest-transport")]
    pub fn new(
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        Self::builder(issuer).jwks_url(jwks_url).build()
    }

    /// Start a builder for finer control (static JWKS, `azp` allowlist,
    /// audience, custom transport, cache tuning).
    pub fn builder(issuer: impl Into<String>) -> AtlasBackendBuilder {
        AtlasBackendBuilder::new(issuer)
    }

    /// The underlying JWKS cache — for `last_outcome()` / `snapshot()`
    /// assertions and diagnostics.
    pub fn jwks_cache(&self) -> &JwksCache {
        &self.jwks
    }

    /// Verify a session token locally. No network call unless the `kid` is
    /// unknown, and at most one of those a minute.
    ///
    /// RS256 ONLY — a token whose header says `alg: none`, `HS256`, or anything
    /// else is rejected before any key is touched.
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        if token.is_empty() || token.split('.').count() != 3 {
            return Err(VerifyError::Malformed);
        }

        // Read the header WITHOUT trusting it. `jsonwebtoken` only decodes with
        // the algorithms named in `Validation`, so an `alg: none` header fails
        // to even deserialize into `Algorithm` — but we also reject explicitly,
        // so the critical "RS256 only" rule is visible and never depends on a
        // default elsewhere.
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(_) => return Err(VerifyError::Invalid),
        };
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::Invalid);
        }
        let kid = header.kid.as_deref();

        let set = match self.jwks.get(kid).await {
            Some(s) if !s.keys.is_empty() => s,
            _ => return Err(VerifyError::NoKeys),
        };

        // Candidate keys: the kid match, or every RSA key when the header
        // carries no kid.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.options.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.leeway = CLOCK_SKEW_SECONDS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // We handle `aud` ourselves (reject-any vs require-expected), so turn off
        // jsonwebtoken's audience validation entirely.
        validation.validate_aud = false;

        let mut claims: Option<Claims> = None;
        for jwk in set.keys.iter() {
            if jwk.kty.as_deref() != Some("RSA") {
                continue;
            }
            if let Some(want) = kid {
                if jwk.kid.as_deref() != Some(want) {
                    continue;
                }
            }
            let (n, e) = match (jwk.n.as_deref(), jwk.e.as_deref()) {
                (Some(n), Some(e)) => (n, e),
                _ => continue,
            };
            let key = match DecodingKey::from_rsa_components(n, e) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Ok(data) = decode::<Claims>(token, &key, &validation) {
                claims = Some(data.claims);
                break;
            }
        }

        let claims = match claims {
            Some(c) => c,
            // Signature, expiry, nbf, issuer — any failure collapses to one
            // reason, and an unknown kid (no candidate matched) lands here too.
            None => return Err(VerifyError::Invalid),
        };

        self.post_checks(claims)
    }

    /// Verify whatever a request carries: an `Authorization: Bearer …` header
    /// wins over a `__session` cookie (a deliberately-set header should not be
    /// overridden by a stale cookie). Pass the raw header values.
    pub async fn authenticate_request(
        &self,
        authorization: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Claims, VerifyError> {
        let bearer = authorization
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::to_owned);
        let from_cookie = cookie.and_then(|c| read_cookie(c, "__session"));
        let token = bearer.or(from_cookie);
        match token {
            Some(t) => self.verify(&t).await,
            None => Err(VerifyError::Malformed),
        }
    }

    /// The claim-level checks applied after signature/exp/iss: token-confusion
    /// guard, audience, and `azp` allowlist.
    fn post_checks(&self, claims: Claims) -> Result<Claims, VerifyError> {
        // §13.1 token-confusion guard (matches the TS/Go/Ruby peers). An OP
        // access/id token is signed with the SAME per-instance RS256 key, issuer
        // and `typ:JWT` header as a session JWT. The discriminator is the POSITIVE
        // `token_use:"session"` marker — NOT the presence of `aud`, because a
        // first-party session token now carries `aud` (its instance id, S4):
        //   - `token_use` present and != "session"  → OP access token → reject
        //   - `aud` present but NOT session-marked   → id_token        → reject
        //   - neither `token_use` nor `aud`          → legacy session  → accept
        //   - `token_use:"session"` (with or without `aud`) → session  → accept
        let is_session_marked = claims.token_use.as_deref() == Some("session");
        if let Some(tu) = claims.token_use.as_deref() {
            if tu != "session" {
                return Err(VerifyError::Invalid);
            }
        }
        if claims.aud.is_some() && !is_session_marked {
            return Err(VerifyError::Invalid);
        }

        // Audience allowlist (S4). When one or more expected audiences are
        // configured, the token's `aud` must contain at least ONE of them (OR).
        // When none are configured, `aud` is not checked — a session token's
        // default instance-id audience still verifies.
        if !self.options.audiences.is_empty() {
            let ok = self
                .options
                .audiences
                .iter()
                .any(|expected| aud_contains(claims.aud.as_ref(), expected));
            if !ok {
                return Err(VerifyError::Invalid);
            }
        }

        if !self.options.authorized_parties.is_empty() {
            let ok = claims
                .azp
                .as_deref()
                .map(|azp| self.options.authorized_parties.iter().any(|p| p == azp))
                .unwrap_or(false);
            if !ok {
                return Err(VerifyError::UnauthorizedParty);
            }
        }

        Ok(claims)
    }
}

/// Whether a JWT `aud` value (a string or an array of strings) contains
/// `expected`.
fn aud_contains(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// Read one cookie value from a `Cookie:` header.
fn read_cookie(header: &str, name: &str) -> Option<String> {
    for part in header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}
