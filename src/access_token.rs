//! Access-token verification for your own API (an OAuth 2.0 resource server).
//!
//! Atlas, acting as your authorization server, issues access tokens for the APIs
//! you register as resource servers. [`AtlasBackend::verify_access_token`] checks
//! one locally against the instance JWKS (RS256 or ES256, nothing else): the
//! issuer, expiry, that it IS an access token, that its `aud` names your API
//! (RFC 8707), and the scopes a route needs. A refusal comes back with the
//! RFC 6750 / RFC 9728 `WWW-Authenticate` challenge to answer with.
//!
//! DPoP-bound tokens (`cnf.jkt`) are refused: this checks Bearer tokens only.

use jsonwebtoken::{decode_header, Validation};
use serde_json::{json, Map, Value};

use crate::jwks::{decode_with_set, SIGNING_ALGS};
use crate::verify::{AtlasBackend, CLOCK_SKEW_SECONDS};

/// What an API requires of an access token.
#[derive(Debug, Clone, Default)]
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
    },
    /// Refused: answer with `status` and set `www_authenticate` as the
    /// `WWW-Authenticate` header. `error` is `None` when no token was sent.
    Refused {
        status: u16,
        error: Option<&'static str>,
        description: String,
        www_authenticate: String,
    },
}

impl AccessTokenResult {
    /// Whether the token was accepted.
    pub fn is_ok(&self) -> bool {
        matches!(self, AccessTokenResult::Ok { .. })
    }
}

impl AtlasBackend {
    /// Verify an `Authorization` header value as an access token for your API.
    /// Never errors for a bad token: the refusal is in the result.
    pub async fn verify_access_token(&self, authorization: Option<&str>, options: &AccessTokenOptions) -> AccessTokenResult {
        let required = &options.required_scopes;
        let refuse = |status: u16, error: Option<&'static str>, description: &str| {
            let scope = if error.is_none() || error == Some("insufficient_scope") { Some(required.as_slice()) } else { None };
            AccessTokenResult::Refused {
                status,
                error,
                description: description.to_string(),
                www_authenticate: build_www_authenticate(
                    options.realm.as_deref(),
                    error,
                    Some(description),
                    scope,
                    options.resource_metadata_url.as_deref(),
                ),
            }
        };
        let value = authorization.unwrap_or("").trim();
        if value.is_empty() {
            return refuse(401, None, "Authentication required.");
        }
        let (scheme, token) = match value.split_once(char::is_whitespace) {
            Some((s, t)) => (s, t.trim()),
            None => return refuse(400, Some("invalid_request"), "Malformed Authorization header."),
        };
        if scheme.eq_ignore_ascii_case("dpop") {
            return refuse(401, Some("invalid_token"), "DPoP-bound access tokens are not accepted here.");
        }
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || !token.chars().all(|c| c.is_ascii_alphanumeric() || "-._~+/=".contains(c))
        {
            return refuse(400, Some("invalid_request"), "Malformed Authorization header.");
        }
        if token.split('.').count() != 3 {
            return refuse(401, Some("invalid_token"), "The access token is malformed.");
        }
        let invalid = "The access token is invalid or expired.";
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
        let claims: Map<String, Value> = match decode_with_set(token, &set, kid, header.alg, &validation) {
            Some(c) => c,
            None => return refuse(401, Some("invalid_token"), invalid),
        };
        // Our own clock, so a test clock applies too.
        let now = ((self.clock)() / 1000) as i64;
        let skew = CLOCK_SKEW_SECONDS as i64;
        match claims.get("exp").and_then(Value::as_i64) {
            Some(exp) if now <= exp + skew => {}
            _ => return refuse(401, Some("invalid_token"), invalid),
        }
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
            if now + skew < nbf {
                return refuse(401, Some("invalid_token"), invalid);
            }
        }
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
        if claims.get("cnf").and_then(Value::as_object).map(|c| c.contains_key("jkt")).unwrap_or(false) {
            return refuse(401, Some("invalid_token"), "DPoP-bound access tokens are not accepted here.");
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
        AccessTokenResult::Ok { claims, scopes, subject, client_id }
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
    if parts.is_empty() {
        "Bearer".to_string()
    } else {
        format!("Bearer {}", parts.join(", "))
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
    doc
}

/// The RFC 9728 well-known path for a resource identifier (path-inserted form).
pub fn protected_resource_metadata_path(resource: &str) -> String {
    let after_scheme = resource.split_once("://").map(|(_, r)| r).unwrap_or(resource);
    let path = after_scheme.find('/').map(|i| &after_scheme[i..]).unwrap_or("");
    let path = path.split(['?', '#']).next().unwrap_or("").trim_end_matches('/');
    format!("/.well-known/oauth-protected-resource{path}")
}
