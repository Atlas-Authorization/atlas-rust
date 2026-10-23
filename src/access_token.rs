//! Access-token verification for your own API (an OAuth 2.0 resource server).
//!
//! Atlas, acting as your authorization server, issues access tokens for the APIs
//! you register as resource servers. [`AtlasBackend::verify_access_token`] checks
//! one locally against the instance JWKS (RS256 or ES256, nothing else): the
//! issuer, expiry, that it IS an access token, that its `aud` names your API
//! (RFC 8707), and the scopes a route needs. A refusal comes back with the
//! RFC 6750 / RFC 9728 `WWW-Authenticate` challenge to answer with.
//!
//! Sender-constrained tokens (RFC 9449 DPoP) are enforced by
//! [`AtlasBackend::verify_access_token_request`]: a token bound to a key
//! (`cnf.jkt`) is accepted only with the `DPoP` scheme and a valid DPoP proof
//! from that key, never as a plain Bearer token.

use std::fmt;
use std::sync::Arc;

use jsonwebtoken::{decode_header, Validation};
use serde_json::{json, Map, Value};

use crate::dpop::{check_proof, default_replay_store, DpopNonceSource, DpopReplayStore, ProofContext, DPOP_ALGS};

#[cfg(any(feature = "backend", feature = "client"))]
use crate::introspection::Introspector;
use crate::jwks::{decode_with_set, SIGNING_ALGS};
use crate::verify::{AtlasBackend, CLOCK_SKEW_SECONDS};

/// What an API requires of an access token.
#[derive(Clone, Default)]
pub struct AccessTokenOptions {
    /// Your API identifier(s) (the resource server identifier). The token's
    /// `aud` must contain one. Empty skips the audience check only when
    /// `any_audience` is set; otherwise every token is refused.
    pub audiences: Vec<String>,
    /// Skip the audience check (userinfo-style tokens).
    pub any_audience: bool,
    /// Scopes every request must carry.
    pub required_scopes: Vec<String>,
    /// Advertised in every challenge as `resource_metadata` (RFC 9728).
    pub resource_metadata_url: Option<String>,
    /// The `WWW-Authenticate` realm.
    pub realm: Option<String>,
    /// Refuse every token that is not DPoP-bound and challenge with the `DPoP` scheme.
    pub require_dpop: bool,
    /// This API's public origin (`https://api.example.com`), for the DPoP `htu`
    /// when the request URL is a path. Set it behind a proxy.
    pub public_origin: Option<String>,
    /// Where DPoP proof `jti`s are recorded; default a process-wide
    /// [`MemoryDpopReplayStore`](crate::MemoryDpopReplayStore). Share one store
    /// when the API runs on several instances.
    pub dpop_replay_store: Option<Arc<dyn DpopReplayStore>>,
    /// Require every DPoP proof to carry a nonce this source issued
    /// (`use_dpop_nonce` otherwise); every result then carries `dpop_nonce` for
    /// the `DPoP-Nonce` response header.
    pub dpop_nonces: Option<Arc<dyn DpopNonceSource>>,
    /// Validate opaque access tokens (and, with
    /// [`IntrospectionOptions::introspect_jwts`](crate::IntrospectionOptions),
    /// JWTs too) at Atlas's RFC 7662 introspection endpoint, cached briefly.
    /// Share one `Arc` across requests so the cache is reused. Needs the
    /// `backend` or `client` feature (the HTTP transport).
    #[cfg(any(feature = "backend", feature = "client"))]
    pub introspection: Option<Arc<Introspector>>,
}

impl fmt::Debug for AccessTokenOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("AccessTokenOptions");
        d.field("audiences", &self.audiences)
            .field("any_audience", &self.any_audience)
            .field("required_scopes", &self.required_scopes)
            .field("resource_metadata_url", &self.resource_metadata_url)
            .field("realm", &self.realm)
            .field("require_dpop", &self.require_dpop)
            .field("public_origin", &self.public_origin)
            .field("dpop_replay_store", &self.dpop_replay_store.is_some())
            .field("dpop_nonces", &self.dpop_nonces.is_some());
        #[cfg(any(feature = "backend", feature = "client"))]
        d.field("introspection", &self.introspection.is_some());
        d.finish()
    }
}

/// What verification reads from an HTTP request: the method and URL (absolute,
/// or a path resolved against [`AccessTokenOptions::public_origin`]) for the
/// DPoP `htu`, and the `Authorization` and `DPoP` header values.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub authorization: Option<&'a str>,
    /// The single `DPoP` header value; pass `None` when there were several.
    pub dpop: Option<&'a str>,
}

/// The verdict of [`AtlasBackend::verify_access_token`].
#[derive(Debug, Clone)]
pub enum AccessTokenResult {
    /// The token is valid for this API.
    Ok {
        claims: Map<String, Value>,
        scopes: Vec<String>,
        subject: String,
        client_id: Option<String>,
        /// Whether the token was DPoP-bound (and its proof checked).
        dpop_bound: bool,
        /// Set it as the `DPoP-Nonce` response header when present.
        dpop_nonce: Option<String>,
    },
    /// Refused: answer with `status` and set `www_authenticate` as the
    /// `WWW-Authenticate` header (and `dpop_nonce`, when present, as
    /// `DPoP-Nonce`). `error` is `None` when no token was sent.
    Refused {
        status: u16,
        error: Option<&'static str>,
        description: String,
        www_authenticate: String,
        dpop_nonce: Option<String>,
    },
}

impl AccessTokenResult {
    /// Whether the token was accepted.
    pub fn is_ok(&self) -> bool {
        matches!(self, AccessTokenResult::Ok { .. })
    }

    /// The `DPoP-Nonce` response header value, on success or refusal.
    pub fn dpop_nonce(&self) -> Option<&str> {
        match self {
            AccessTokenResult::Ok { dpop_nonce, .. } | AccessTokenResult::Refused { dpop_nonce, .. } => dpop_nonce.as_deref(),
        }
    }
}

impl AtlasBackend {
    /// Verify an `Authorization` header value as an access token for your API,
    /// with no DPoP proof: a DPoP-bound token is refused (use
    /// [`AtlasBackend::verify_access_token_request`] for DPoP). Never errors for
    /// a bad token: the refusal is in the result.
    pub async fn verify_access_token(&self, authorization: Option<&str>, options: &AccessTokenOptions) -> AccessTokenResult {
        self.verify_access_token_request(&ResourceRequest { method: "GET", url: "", authorization, dpop: None }, options)
            .await
    }

    /// Verify a request: its `Authorization` header (`Bearer` or `DPoP` scheme)
    /// and, for a DPoP-bound token, its `DPoP` proof (RFC 9449) against the
    /// method and URL. Never errors for a bad token: the refusal is in the result.
    pub async fn verify_access_token_request(&self, request: &ResourceRequest<'_>, options: &AccessTokenOptions) -> AccessTokenResult {
        let required = &options.required_scopes;
        let nonce = options.dpop_nonces.as_ref().map(|n| n.current());
        let default_scheme = if options.require_dpop { "DPoP" } else { "Bearer" };
        let refuse_as = |scheme: &str, status: u16, error: Option<&'static str>, description: &str| {
            let scope = if error.is_none() || error == Some("insufficient_scope") { Some(required.as_slice()) } else { None };
            AccessTokenResult::Refused {
                status,
                error,
                description: description.to_string(),
                www_authenticate: build_challenge(
                    scheme,
                    options.realm.as_deref(),
                    error,
                    Some(description),
                    scope,
                    options.resource_metadata_url.as_deref(),
                ),
                dpop_nonce: nonce.clone(),
            }
        };
        let refuse = |status: u16, error: Option<&'static str>, description: &str| refuse_as(default_scheme, status, error, description);
        let value = request.authorization.unwrap_or("").trim();
        if value.is_empty() {
            return refuse(401, None, "Authentication required.");
        }
        let (scheme, token) = match value.split_once(char::is_whitespace) {
            Some((s, t)) => (s, t.trim()),
            None => return refuse(400, Some("invalid_request"), "Malformed Authorization header."),
        };
        let presented_dpop = scheme.eq_ignore_ascii_case("dpop");
        if !(presented_dpop || scheme.eq_ignore_ascii_case("bearer"))
            || token.is_empty()
            || !token.chars().all(|c| c.is_ascii_alphanumeric() || "-._~+/=".contains(c))
        {
            return refuse(400, Some("invalid_request"), "Malformed Authorization header.");
        }
        let invalid = "The access token is invalid or expired.";
        let is_jwt = token.split('.').count() == 3;
        #[cfg(any(feature = "backend", feature = "client"))]
        let introspector = options.introspection.as_deref();
        #[cfg(not(any(feature = "backend", feature = "client")))]
        let introspector: Option<&NoIntrospector> = None;
        let claims: Map<String, Value> = if !is_jwt || introspector.map(|i| i.introspect_jwts()).unwrap_or(false) {
            // An opaque token (or a JWT the caller wants checked live) is validated
            // by Atlas itself.
            let introspector = match introspector {
                Some(i) => i,
                None => {
                    return refuse(
                        401,
                        Some("invalid_token"),
                        "The access token is not a JWT; configure `introspection` to accept opaque tokens.",
                    )
                }
            };
            let active = match introspector.introspect(token).await {
                Ok(Some(c)) => c,
                Ok(None) => return refuse(401, Some("invalid_token"), invalid),
                Err(_) => return refuse(401, Some("invalid_token"), "The access token could not be validated right now."),
            };
            if let Some(iss) = active.get("iss") {
                if iss.as_str().map(|s| s.trim_end_matches('/')) != Some(self.options.issuer.trim_end_matches('/')) {
                    return refuse(401, Some("invalid_token"), "The access token was issued by another authorization server.");
                }
            }
            let now = ((self.clock)() / 1000) as f64;
            if let Some(exp) = active.get("exp").and_then(Value::as_f64) {
                if exp + CLOCK_SKEW_SECONDS as f64 <= now {
                    return refuse(401, Some("invalid_token"), invalid);
                }
            }
            active
        } else {
            let header = match decode_header(token) {
                Ok(h) if SIGNING_ALGS.contains(&h.alg) => h,
                _ => return refuse(401, Some("invalid_token"), invalid),
            };
            let kid = header.kid.as_deref();
            let set = match self.jwks.get(kid).await {
                Some(s) if !s.keys.is_empty() => s,
                _ => return refuse(401, Some("invalid_token"), "No signing keys are available to verify the token."),
            };
            let mut validation = Validation::new(header.alg);
            validation.set_issuer(&[self.options.issuer.trim_end_matches('/')]);
            validation.set_required_spec_claims(&["exp", "iss"]);
            validation.leeway = CLOCK_SKEW_SECONDS;
            validation.validate_aud = false;
            let jwt_claims: Map<String, Value> = match decode_with_set(token, &set, kid, header.alg, &validation) {
                Some(c) => c,
                None => return refuse(401, Some("invalid_token"), invalid),
            };
            // Our own clock, so a test clock applies too.
            let now = ((self.clock)() / 1000) as i64;
            let skew = CLOCK_SKEW_SECONDS as i64;
            match jwt_claims.get("exp").and_then(Value::as_i64) {
                Some(exp) if now <= exp + skew => {}
                _ => return refuse(401, Some("invalid_token"), invalid),
            }
            if let Some(nbf) = jwt_claims.get("nbf").and_then(Value::as_i64) {
                if now + skew < nbf {
                    return refuse(401, Some("invalid_token"), invalid);
                }
            }
            jwt_claims
        };
        if let Some(tu) = claims.get("token_use") {
            if tu.as_str() != Some("access_token") {
                return refuse(401, Some("invalid_token"), "The token is not an access token.");
            }
        }
        if !options.any_audience {
            let ok = match claims.get("aud") {
                Some(Value::String(s)) => options.audiences.iter().any(|a| a == s),
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|s| options.audiences.iter().any(|a| a == s)),
                _ => false,
            };
            if !ok {
                return refuse(401, Some("invalid_token"), "The access token was not issued for this resource.");
            }
        }
        // Sender constraint (RFC 9449). A bound token is only ever a DPoP token.
        let jkt: Option<String> = match claims.get("cnf").and_then(Value::as_object).and_then(|c| c.get("jkt")) {
            None => None,
            Some(Value::String(j)) if !j.is_empty() => Some(j.clone()),
            Some(_) => return refuse(401, Some("invalid_token"), invalid),
        };
        if jkt.is_some() || options.require_dpop || presented_dpop {
            let jkt = match jkt.as_deref() {
                Some(j) => j,
                None => return refuse_as("DPoP", 401, Some("invalid_token"), "This resource requires a DPoP-bound access token."),
            };
            if !presented_dpop {
                return refuse_as("DPoP", 401, Some("invalid_token"), "A DPoP-bound access token must be sent with the DPoP scheme.");
            }
            let proof = request.dpop.unwrap_or("").trim();
            if proof.is_empty() {
                return refuse_as("DPoP", 401, Some("invalid_dpop_proof"), "A DPoP proof is required.");
            }
            let method = if request.method.is_empty() { "GET".to_owned() } else { request.method.to_ascii_uppercase() };
            let replay = options.dpop_replay_store.clone().unwrap_or_else(default_replay_store);
            let ctx = ProofContext {
                token,
                jkt,
                method: &method,
                url: request.url,
                public_origin: options.public_origin.as_deref(),
                now_ms: (self.clock)(),
                replay: replay.as_ref(),
                nonces: options.dpop_nonces.as_deref(),
            };
            if let Some(r) = check_proof(proof, &ctx) {
                return refuse_as("DPoP", 401, Some(r.error), r.description);
            }
        }
        let scopes: Vec<String> = claims
            .get("scope")
            .and_then(Value::as_str)
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let mut granted: Vec<&str> = scopes.iter().map(String::as_str).collect();
        if let Some(perms) = claims.get("permissions").and_then(Value::as_array) {
            granted.extend(perms.iter().filter_map(Value::as_str));
        }
        let missing: Vec<&str> = required.iter().map(String::as_str).filter(|s| !granted.contains(s)).collect();
        if !missing.is_empty() {
            let desc = format!("The access token is missing the required scope(s): {}.", missing.join(" "));
            return refuse(403, Some("insufficient_scope"), &desc);
        }
        let str_claim = |k: &str| claims.get(k).and_then(Value::as_str).map(str::to_owned);
        let subject = str_claim("sub").unwrap_or_default();
        let client_id = str_claim("client_id").or_else(|| str_claim("azp"));
        let dpop_bound = jkt.is_some();
        AccessTokenResult::Ok { claims, scopes, subject, client_id, dpop_bound, dpop_nonce: nonce }
    }
}

/// An RFC 6750 / RFC 9728 Bearer challenge. Without `error` it is the bare
/// "authentication required" challenge (no token was sent).
pub fn build_www_authenticate(
    realm: Option<&str>,
    error: Option<&str>,
    description: Option<&str>,
    scope: Option<&[String]>,
    resource_metadata_url: Option<&str>,
) -> String {
    build_challenge("Bearer", realm, error, description, scope, resource_metadata_url)
}

/// An RFC 6750 / RFC 9449 / RFC 9728 challenge for `scheme` `Bearer` or `DPoP`
/// (a DPoP challenge also lists the accepted proof algorithms).
pub fn build_challenge(
    scheme: &str,
    realm: Option<&str>,
    error: Option<&str>,
    description: Option<&str>,
    scope: Option<&[String]>,
    resource_metadata_url: Option<&str>,
) -> String {
    let q = |v: &str| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""));
    let mut parts = Vec::new();
    if let Some(r) = realm {
        parts.push(format!("realm={}", q(r)));
    }
    if let Some(e) = error {
        parts.push(format!("error={}", q(e)));
        if let Some(d) = description {
            parts.push(format!("error_description={}", q(d)));
        }
    }
    if let Some(s) = scope {
        if !s.is_empty() {
            parts.push(format!("scope={}", q(&s.join(" "))));
        }
    }
    if let Some(u) = resource_metadata_url {
        parts.push(format!("resource_metadata={}", q(u)));
    }
    let scheme = if scheme == "DPoP" { "DPoP" } else { "Bearer" };
    if scheme == "DPoP" {
        parts.push(format!("algs={}", q(&DPOP_ALGS.join(" "))));
    }
    if parts.is_empty() {
        scheme.to_string()
    } else {
        format!("{scheme} {}", parts.join(", "))
    }
}

/// The RFC 9728 protected-resource metadata document for your API.
pub fn protected_resource_metadata(resource: &str, issuer: &str, scopes_supported: &[&str]) -> Value {
    let mut doc = json!({
        "resource": resource,
        "authorization_servers": [issuer.trim_end_matches('/')],
        "bearer_methods_supported": ["header"],
    });
    if !scopes_supported.is_empty() {
        doc["scopes_supported"] = json!(scopes_supported);
    }
    doc["dpop_signing_alg_values_supported"] = json!(DPOP_ALGS);
    doc
}

/// [`protected_resource_metadata`] that also advertises
/// `dpop_bound_access_tokens_required` (pair it with `require_dpop`).
pub fn protected_resource_metadata_requiring_dpop(resource: &str, issuer: &str, scopes_supported: &[&str]) -> Value {
    let mut doc = protected_resource_metadata(resource, issuer, scopes_supported);
    doc["dpop_bound_access_tokens_required"] = json!(true);
    doc
}

/// The RFC 9728 well-known path for a resource identifier (path-inserted form).
pub fn protected_resource_metadata_path(resource: &str) -> String {
    let after_scheme = resource.split_once("://").map(|(_, r)| r).unwrap_or(resource);
    let path = after_scheme.find('/').map(|i| &after_scheme[i..]).unwrap_or("");
    let path = path.split(['?', '#']).next().unwrap_or("").trim_end_matches('/');
    format!("/.well-known/oauth-protected-resource{path}")
}

/// Stands in for the introspector when the HTTP transport is compiled out.
#[cfg(not(any(feature = "backend", feature = "client")))]
struct NoIntrospector;

#[cfg(not(any(feature = "backend", feature = "client")))]
impl NoIntrospector {
    fn introspect_jwts(&self) -> bool {
        false
    }

    async fn introspect(&self, _token: &str) -> Result<Option<Map<String, Value>>, ()> {
        Ok(None)
    }
}
