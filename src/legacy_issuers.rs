//! Accepting your OLD auth provider's JWTs during a cutover — today, Better
//! Auth's `jwt` plugin tokens.
//!
//! When you move to Atlas, API clients may still hold short-lived JWTs your
//! Better Auth app minted. With [`crate::AtlasBackendBuilder::legacy_issuer`], a
//! token whose `iss` is one of these issuers is verified against THAT issuer's
//! key set (the JWKS you imported into Atlas, or the old app's
//! `/api/auth/jwks`) for a bounded window, and its `sub` (the Better Auth user
//! id) is mapped to the Atlas user id — Atlas keeps the Better Auth id as the
//! user's `external_id`. After `until`, those tokens are refused like any other
//! foreign token. Atlas tokens are unaffected.
//!
//! **Algorithms.** Better Auth signs with EdDSA (Ed25519, its default), ES256,
//! ES512, RS256 or PS256. This crate verifies EdDSA, ES256, RS256 and PS256.
//! **ES512 (P-521) is not supported** — the signature backend this crate uses
//! (`jsonwebtoken`) has no P-521 — so an ES512 legacy token is refused, and
//! naming `ES512` in [`LegacyIssuer::algorithms`] is a build error. If your
//! Better Auth app signs with ES512, verify those tokens in a service with an
//! ES512-capable SDK during the window, or let them expire (they are
//! short-lived) and rely on the session bridge for browser sessions.

#[cfg(feature = "backend")]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "backend")]
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

use crate::claims::Claims;
use crate::clock::Clock;
use crate::error::ConfigError;
use crate::jwks::{BoxFuture, Jwk, Jwks, JwksCache, JwksSource};

/// Better Auth's `jwt` plugin algorithms this crate can verify (the default
/// for [`LegacyIssuer::algorithms`]). ES512 is the one Better Auth algorithm
/// missing — see the module docs.
pub const LEGACY_ISSUER_ALGS: [&str; 4] = ["EdDSA", "ES256", "RS256", "PS256"];

/// How long a resolved `sub` → Atlas id mapping is reused, in milliseconds.
pub const LEGACY_SUBJECT_TTL_MS: u64 = 5 * 60_000;

/// Cap on cached subjects, so a stream of distinct tokens cannot grow memory
/// without bound.
pub const LEGACY_SUBJECT_CACHE_MAX: usize = 10_000;

/// Maps a legacy token's `sub` (the old provider's user id) to the Atlas user
/// id. `None` refuses the token. Implemented for any
/// `Fn(&str, &Map<String, Value>) -> Option<String>` through
/// [`LegacyIssuer::resolve_subject`], and by [`BackendSubjectResolver`] (feature
/// `backend`), which looks the user up by `external_id`.
pub trait SubjectResolver: Send + Sync {
    /// Resolve `legacy_sub`; `claims` are the verified legacy token's claims.
    fn resolve<'a>(&'a self, legacy_sub: &'a str, claims: &'a Map<String, Value>) -> BoxFuture<'a, Option<String>>;
}

struct FnResolver<F>(F);

impl<F> SubjectResolver for FnResolver<F>
where
    F: Fn(&str, &Map<String, Value>) -> Option<String> + Send + Sync,
{
    fn resolve<'a>(&'a self, legacy_sub: &'a str, claims: &'a Map<String, Value>) -> BoxFuture<'a, Option<String>> {
        let out = (self.0)(legacy_sub, claims);
        Box::pin(async move { out })
    }
}

/// One old issuer accepted during the cutover.
///
/// ```
/// use atlasauth::{Jwks, LegacyIssuer};
/// # let jwks: Jwks = serde_json::from_str(r#"{"keys":[]}"#).unwrap();
/// let better_auth = LegacyIssuer::new("https://app.example.com", 1_798_761_600_000) // until, epoch ms
///     .jwks(jwks)                     // or .jwks_url("https://app.example.com/api/auth/jwks")
///     .resolve_subject(|sub, _claims| Some(format!("user_for_{sub}")));
/// # let _ = better_auth;
/// ```
#[derive(Clone)]
pub struct LegacyIssuer {
    pub(crate) issuer: String,
    pub(crate) until_ms: u64,
    pub(crate) jwks: Option<Jwks>,
    pub(crate) jwks_url: Option<String>,
    pub(crate) audiences: Vec<String>,
    pub(crate) algorithms: Option<Vec<String>>,
    pub(crate) resolver: Option<Arc<dyn SubjectResolver>>,
    pub(crate) kind: String,
}

impl LegacyIssuer {
    /// `issuer` is the `iss` the old tokens carry (Better Auth: its `baseURL`,
    /// unless `jwt.issuer` was set); `until_ms` ends the acceptance window
    /// (epoch milliseconds). A legacy issuer is never accepted forever. Use
    /// [`Self::until_rfc3339`] to give the end as a timestamp string.
    pub fn new(issuer: impl Into<String>, until_ms: u64) -> Self {
        LegacyIssuer {
            issuer: issuer.into(),
            until_ms,
            jwks: None,
            jwks_url: None,
            audiences: Vec::new(),
            algorithms: None,
            resolver: None,
            kind: "better_auth".to_string(),
        }
    }

    /// Like [`Self::new`] with the window end as an RFC 3339 timestamp
    /// (`2026-12-31T00:00:00Z`). An unparseable value fails the build.
    pub fn until_rfc3339(issuer: impl Into<String>, until: &str) -> Self {
        Self::new(issuer, parse_rfc3339_ms(until).unwrap_or(0))
    }

    /// The old app's key set, held in memory (e.g. the JWKS you exported).
    /// Exactly one of `jwks` / `jwks_url`.
    pub fn jwks(mut self, jwks: Jwks) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Fetch the old key set from this URL (e.g.
    /// `https://app.example.com/api/auth/jwks`, or your Atlas instance JWKS,
    /// which publishes the keys you imported), cached like the Atlas JWKS.
    pub fn jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = Some(url.into());
        self
    }

    /// Require `aud` to contain this audience (call again to accept any of
    /// several). Unchecked when none is set.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Accepted algorithms (default [`LEGACY_ISSUER_ALGS`]). `ES512` is refused
    /// at build time.
    pub fn algorithms<I, S>(mut self, algorithms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.algorithms = Some(algorithms.into_iter().map(Into::into).collect());
        self
    }

    /// Map the old `sub` to the Atlas user id yourself. Return `None` to refuse
    /// the token. Without one, the backend's default resolver is used
    /// ([`crate::AtlasBackendBuilder::legacy_subject_resolver`]).
    pub fn resolve_subject<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &Map<String, Value>) -> Option<String> + Send + Sync + 'static,
    {
        self.resolver = Some(Arc::new(FnResolver(f)));
        self
    }

    /// An async [`SubjectResolver`] for this issuer only.
    pub fn subject_resolver(mut self, resolver: Arc<dyn SubjectResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The `legacy.kind` reported on verified claims (default `better_auth`).
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = kind.into();
        self
    }

    /// The configured issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

enum KeySource {
    Static(Jwks),
    Cached(JwksCache),
}

struct Entry {
    config: LegacyIssuer,
    keys: KeySource,
    algorithms: Vec<Algorithm>,
}

/// Verifies legacy-issuer tokens (used by [`crate::AtlasBackend`]).
pub(crate) struct LegacyVerifier {
    entries: Vec<Entry>,
    default_resolver: Option<Arc<dyn SubjectResolver>>,
    clock: Clock,
    leeway: u64,
}

pub(crate) enum LegacyOutcome {
    Ok(Box<Claims>),
    NoKeys,
    Invalid,
}

fn parse_alg(name: &str) -> Option<Algorithm> {
    match name {
        "EdDSA" => Some(Algorithm::EdDSA),
        "ES256" => Some(Algorithm::ES256),
        "RS256" => Some(Algorithm::RS256),
        "PS256" => Some(Algorithm::PS256),
        _ => None,
    }
}

impl LegacyVerifier {
    pub(crate) fn new(
        issuers: Vec<LegacyIssuer>,
        atlas_issuer: &str,
        default_resolver: Option<Arc<dyn SubjectResolver>>,
        source: Option<Arc<dyn JwksSource>>,
        clock: Clock,
        leeway: u64,
    ) -> Result<Self, ConfigError> {
        let mut entries = Vec::new();
        for config in issuers {
            if config.issuer.is_empty() {
                return Err(ConfigError::new("legacy_issuers: every entry needs an `issuer`."));
            }
            if config.issuer == atlas_issuer {
                return Err(ConfigError::new("AtlasBackend: a legacy issuer cannot be the Atlas issuer itself."));
            }
            if config.until_ms == 0 {
                return Err(ConfigError::new(format!(
                    "legacy_issuers: \"{}\" needs a valid `until` (the end of the window).",
                    config.issuer
                )));
            }
            let has_url = config.jwks_url.as_deref().map(|u| !u.is_empty()).unwrap_or(false);
            if has_url == config.jwks.is_some() {
                return Err(ConfigError::new(format!(
                    "legacy_issuers: \"{}\" needs exactly one of `jwks` or `jwks_url`.",
                    config.issuer
                )));
            }
            if config.resolver.is_none() && default_resolver.is_none() {
                return Err(ConfigError::new(format!(
                    "legacy_issuers: \"{}\" maps its `sub` to an Atlas user, which needs a subject resolver: give the issuer \
                     `resolve_subject`, or the backend a `legacy_subject_resolver` (e.g. `BackendSubjectResolver` with your secret key).",
                    config.issuer
                )));
            }
            let names: Vec<String> = config
                .algorithms
                .clone()
                .unwrap_or_else(|| LEGACY_ISSUER_ALGS.iter().map(|s| s.to_string()).collect());
            let mut algorithms = Vec::new();
            for name in &names {
                match parse_alg(name) {
                    Some(a) => algorithms.push(a),
                    None if name == "ES512" => {
                        return Err(ConfigError::new(format!(
                            "legacy_issuers: \"{}\" names ES512, which this crate cannot verify (no P-521 support). \
                             Supported: EdDSA, ES256, RS256, PS256.",
                            config.issuer
                        )))
                    }
                    None => {
                        return Err(ConfigError::new(format!(
                            "legacy_issuers: \"{}\" names an unsupported algorithm \"{}\". Supported: EdDSA, ES256, RS256, PS256.",
                            config.issuer, name
                        )))
                    }
                }
            }
            let keys = if let Some(set) = config.jwks.clone() {
                KeySource::Static(set)
            } else {
                let source = match &source {
                    Some(s) => s.clone(),
                    None => {
                        return Err(ConfigError::new(
                            "legacy_issuers: a `jwks_url` needs a JWKS transport (the `reqwest-transport` feature, or `.jwks_source(...)`).",
                        ))
                    }
                };
                KeySource::Cached(JwksCache::new(config.jwks_url.clone(), None, Some(source), Some(clock.clone()), None, None))
            };
            entries.push(Entry { config, keys, algorithms });
        }
        Ok(LegacyVerifier { entries, default_resolver, clock, leeway })
    }

    /// The entry for this unverified `iss`, when its window is still open.
    fn matching(&self, iss: Option<&str>) -> Option<&Entry> {
        let iss = iss?;
        let entry = self.entries.iter().find(|e| e.config.issuer == iss)?;
        if entry.config.until_ms > (self.clock)() {
            Some(entry)
        } else {
            None
        }
    }

    /// `None` when the token is not from a configured legacy issuer inside its
    /// window (the caller verifies it as an Atlas token); otherwise the outcome.
    pub(crate) async fn verify(&self, token: &str) -> Option<LegacyOutcome> {
        let entry = self.matching(peek_issuer(token).as_deref())?;
        Some(self.verify_entry(token, entry).await)
    }

    async fn verify_entry(&self, token: &str, entry: &Entry) -> LegacyOutcome {
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(_) => return LegacyOutcome::Invalid,
        };
        if !entry.algorithms.contains(&header.alg) {
            return LegacyOutcome::Invalid;
        }
        let kid = header.kid.as_deref();
        let set = match &entry.keys {
            KeySource::Static(s) => Some(s.clone()),
            KeySource::Cached(cache) => cache.get(kid).await,
        };
        let set = match set {
            Some(s) if !s.keys.is_empty() => s,
            _ => return LegacyOutcome::NoKeys,
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[entry.config.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.leeway = self.leeway;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        if entry.config.audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            // A configured audience is required, not just checked when present.
            validation.set_required_spec_claims(&["exp", "iss", "aud"]);
            validation.set_audience(&entry.config.audiences);
        }

        let mut payload: Option<Map<String, Value>> = None;
        for jwk in set.keys.iter() {
            if let Some(want) = kid {
                if jwk.kid.as_deref() != Some(want) {
                    continue;
                }
            }
            let key = match legacy_decoding_key(jwk, header.alg) {
                Some(k) => k,
                None => continue,
            };
            if let Ok(data) = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation) {
                payload = Some(data.claims);
                break;
            }
        }
        let payload = match payload {
            Some(p) => p,
            None => return LegacyOutcome::Invalid,
        };
        // A legacy token without an expiry would outlive the window it is accepted in.
        if !payload.get("exp").map(Value::is_number).unwrap_or(false) {
            return LegacyOutcome::Invalid;
        }
        let legacy_sub = match payload.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => match payload.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                Some(s) => s.to_string(),
                None => return LegacyOutcome::Invalid,
            },
        };
        let resolver = match entry.config.resolver.as_ref().or(self.default_resolver.as_ref()) {
            Some(r) => r.clone(),
            None => return LegacyOutcome::Invalid,
        };
        let atlas_id = match resolver.resolve(&legacy_sub, &payload).await {
            Some(id) if !id.is_empty() => id,
            _ => return LegacyOutcome::Invalid,
        };

        let mut claims = payload;
        claims.insert("sub".into(), Value::String(atlas_id));
        claims.insert("external_id".into(), Value::String(legacy_sub.clone()));
        let mut legacy = Map::new();
        legacy.insert("kind".into(), Value::String(entry.config.kind.clone()));
        legacy.insert("issuer".into(), Value::String(entry.config.issuer.clone()));
        legacy.insert("sub".into(), Value::String(legacy_sub));
        claims.insert("legacy".into(), Value::Object(legacy));
        // Better Auth's `sid`, when present, is a string; anything else is dropped
        // so the typed `Claims::sid` never fails to decode.
        if claims.get("sid").map(|v| !v.is_string()).unwrap_or(false) {
            claims.remove("sid");
        }
        // Typed claims with a non-standard shape on a foreign token are dropped
        // rather than failing the whole token.
        for (name, ok) in [
            ("azp", claims.get("azp").map(Value::is_string)),
            ("email", claims.get("email").map(Value::is_string)),
            ("org_id", claims.get("org_id").map(Value::is_string)),
            ("token_use", claims.get("token_use").map(Value::is_string)),
        ] {
            if ok == Some(false) {
                claims.remove(name);
            }
        }
        match serde_json::from_value::<Claims>(Value::Object(claims)) {
            Ok(c) => LegacyOutcome::Ok(Box::new(c)),
            Err(_) => LegacyOutcome::Invalid,
        }
    }
}

/// The decoding key for `alg`, when this JWK can verify exactly that algorithm
/// (RSA → RS256/PS256, P-256 → ES256, Ed25519 → EdDSA) and its own `alg`, when
/// set, agrees.
fn legacy_decoding_key(jwk: &Jwk, alg: Algorithm) -> Option<DecodingKey> {
    if let Some(declared) = jwk.alg.as_deref() {
        if parse_alg(declared) != Some(alg) {
            return None;
        }
    }
    match (jwk.kty.as_deref(), jwk.crv.as_deref(), alg) {
        (Some("RSA"), _, Algorithm::RS256 | Algorithm::PS256) => {
            DecodingKey::from_rsa_components(jwk.n.as_deref()?, jwk.e.as_deref()?).ok()
        }
        (Some("EC"), Some("P-256"), Algorithm::ES256) => {
            DecodingKey::from_ec_components(jwk.x.as_deref()?, jwk.y.as_deref()?).ok()
        }
        (Some("OKP"), Some("Ed25519"), Algorithm::EdDSA) => DecodingKey::from_ed_components(jwk.x.as_deref()?).ok(),
        _ => None,
    }
}

/// The UNVERIFIED `iss` of a compact JWT, for routing only.
pub(crate) fn peek_issuer(token: &str) -> Option<String> {
    let segment = token.split('.').nth(1)?;
    let raw = URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()?;
    let payload: Value = serde_json::from_slice(&raw).ok()?;
    payload.get("iss").and_then(Value::as_str).map(str::to_owned)
}

/// Parse an RFC 3339 / ISO-8601 UTC or offset timestamp
/// (`2026-12-31T00:00:00Z`, `2026-12-31T00:00:00.5+02:00`) to epoch ms.
pub(crate) fn parse_rfc3339_ms(text: &str) -> Option<u64> {
    let t = text.trim();
    if t.len() < 19 {
        return None;
    }
    let b = t.as_bytes();
    let num = |s: &str| s.parse::<i64>().ok();
    if b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't' || b[10] == b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(&t[0..4])?, num(&t[5..7])?, num(&t[8..10])?);
    let (h, mi, s) = (num(&t[11..13])?, num(&t[14..16])?, num(&t[17..19])?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut rest = &t[19..];
    let mut millis = 0i64;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return None;
        }
        let padded = format!("{:0<3}", &digits[..digits.len().min(3)]);
        millis = num(&padded)?;
        rest = &frac[digits.len()..];
    }
    let offset_min = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) && &rest[3..4] == ":" => {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (num(&rest[1..3])? * 60 + num(&rest[4..6])?)
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + s - offset_min * 60;
    let ms = secs.checked_mul(1000)?.checked_add(millis)?;
    u64::try_from(ms).ok().filter(|v| *v > 0)
}

/// The default subject resolver: looks the user up by `external_id` through
/// the Backend API (`GET /v1/users?external_id=…`) with your secret key, and
/// caches the answer for five minutes (bounded at
/// [`LEGACY_SUBJECT_CACHE_MAX`] entries). A failed lookup is not cached, so a
/// transient error does not stick.
#[cfg(feature = "backend")]
pub struct BackendSubjectResolver {
    client: crate::backend::BackendClient,
    clock: Clock,
    cache: Mutex<HashMap<String, (Option<String>, u64)>>,
}

#[cfg(feature = "backend")]
impl BackendSubjectResolver {
    /// Resolve through this client (built with the instance secret key).
    pub fn new(client: crate::backend::BackendClient) -> Self {
        Self::with_clock(client, crate::clock::system_clock())
    }

    /// [`Self::new`] with an injected clock (tests).
    pub fn with_clock(client: crate::backend::BackendClient, clock: Clock) -> Self {
        BackendSubjectResolver { client, clock, cache: Mutex::new(HashMap::new()) }
    }
}

#[cfg(feature = "backend")]
impl SubjectResolver for BackendSubjectResolver {
    fn resolve<'a>(&'a self, legacy_sub: &'a str, _claims: &'a Map<String, Value>) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move {
            let now = (self.clock)();
            if let Some((hit, at)) = self.cache.lock().unwrap().get(legacy_sub) {
                if now.saturating_sub(*at) < LEGACY_SUBJECT_TTL_MS {
                    return hit.clone();
                }
            }
            let page = self
                .client
                .request_value(
                    crate::http::HttpMethod::Get,
                    "/v1/users",
                    &[("external_id", legacy_sub.to_string()), ("limit", "1".to_string())],
                    None,
                )
                .await
                .ok()?;
            let found = page
                .get("data")
                .and_then(Value::as_array)
                .and_then(|d| d.first())
                .and_then(|u| u.get("id"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let mut cache = self.cache.lock().unwrap();
            if cache.len() >= LEGACY_SUBJECT_CACHE_MAX {
                cache.clear();
            }
            cache.insert(legacy_sub.to_string(), (found.clone(), now));
            found
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_ms;

    #[test]
    fn parses_timestamps() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(parse_rfc3339_ms("2026-12-31T00:00:00Z"), Some(1_798_675_200_000));
        assert_eq!(parse_rfc3339_ms("2026-12-31T02:00:00.250+02:00"), Some(1_798_675_200_250));
        assert_eq!(parse_rfc3339_ms("not a date"), None);
        assert_eq!(parse_rfc3339_ms("2026-13-01T00:00:00Z"), None);
    }
}
