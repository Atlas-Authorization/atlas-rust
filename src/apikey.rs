//! End-user API-key verification (`POST /v1/api_keys/verify`).
//!
//! A tenant mints `ak_` keys for its own users/organizations and later asks
//! Atlas to verify one a subject presented. Unlike session-token verification,
//! this is an ONLINE check — the key's validity (revoked? expired? subject
//! deleted?) lives server-side. To keep a busy API from making one outbound call
//! per request, results are cached — with SEPARATE positive and negative caches:
//!
//! * a **longer positive TTL**, because a key that just verified stays valid for
//!   its lifetime, so re-verifying it every request is waste;
//! * a **short negative TTL**, so a caller hammering a bad key is answered
//!   locally without hammering Atlas, yet a key that is fixed (minted, or its
//!   subject un-banned) starts working again within seconds.
//!
//! Every negative — unknown, malformed, revoked, expired, or a since-deleted
//! subject — resolves to the same `valid = false`, so a caller learns nothing
//! about which keys exist.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::clock::{system_clock, Clock};
use crate::error::{ApiKeyError, ConfigError, TransportError};
use crate::jwks::BoxFuture;

/// Default positive-cache TTL: five minutes.
pub const DEFAULT_POSITIVE_TTL_MS: u64 = 300_000;
/// Default negative-cache TTL: thirty seconds.
pub const DEFAULT_NEGATIVE_TTL_MS: u64 = 30_000;

/// The public API host. Override for self-hosted instances.
pub const DEFAULT_BASE_URL: &str = "https://api.atlasauth.net";

/// A raw HTTP response, as a [`HttpPost`] transport returns it.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Something that can POST a JSON body with a bearer token. Implemented by the
/// built-in reqwest transport (behind `reqwest-transport`) and by any mock.
pub trait HttpPost: Send + Sync {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
        body: String,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>>;
}

/// The verify verdict. A failed verification is `valid = false`, NOT an error;
/// an [`ApiKeyError`] means the endpoint could not be reached or did not parse.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyVerification {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub claims: Option<Map<String, Value>>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
}

#[derive(Clone)]
struct CacheEntry {
    verdict: ApiKeyVerification,
    stored_at: u64,
}

/// Verifies end-user API keys against Atlas with separate positive/negative
/// caches. Construct with [`ApiKeyVerifier::new`] (reqwest) or
/// [`ApiKeyVerifier::builder`].
pub struct ApiKeyVerifier {
    secret_key: String,
    base_url: String,
    transport: Arc<dyn HttpPost>,
    now: Clock,
    positive_ttl_ms: u64,
    negative_ttl_ms: u64,
    positive: Mutex<HashMap<String, CacheEntry>>,
    negative: Mutex<HashMap<String, CacheEntry>>,
}

/// Builder for an [`ApiKeyVerifier`].
pub struct ApiKeyVerifierBuilder {
    secret_key: String,
    base_url: String,
    transport: Option<Arc<dyn HttpPost>>,
    now: Option<Clock>,
    positive_ttl_ms: u64,
    negative_ttl_ms: u64,
}

impl ApiKeyVerifierBuilder {
    fn new(secret_key: impl Into<String>) -> Self {
        ApiKeyVerifierBuilder {
            secret_key: secret_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            transport: None,
            now: None,
            positive_ttl_ms: DEFAULT_POSITIVE_TTL_MS,
            negative_ttl_ms: DEFAULT_NEGATIVE_TTL_MS,
        }
    }

    /// Override the BAPI origin (default `https://api.atlasauth.net`).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Inject a custom HTTP transport (a mock in tests).
    pub fn transport(mut self, transport: Arc<dyn HttpPost>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Inject a clock for the cache TTLs (tests).
    pub fn clock(mut self, clock: Clock) -> Self {
        self.now = Some(clock);
        self
    }

    /// Override the positive-cache TTL (default 5 min).
    pub fn positive_ttl_ms(mut self, ms: u64) -> Self {
        self.positive_ttl_ms = ms;
        self
    }

    /// Override the negative-cache TTL (default 30 s).
    pub fn negative_ttl_ms(mut self, ms: u64) -> Self {
        self.negative_ttl_ms = ms;
        self
    }

    /// Finish building. Fails only when no transport is available (compile
    /// without `reqwest-transport` and you must supply [`Self::transport`]).
    pub fn build(self) -> Result<ApiKeyVerifier, ConfigError> {
        let transport = match self.transport {
            Some(t) => t,
            None => default_transport()?,
        };
        Ok(ApiKeyVerifier {
            secret_key: self.secret_key,
            base_url: self.base_url,
            transport,
            now: self.now.unwrap_or_else(system_clock),
            positive_ttl_ms: self.positive_ttl_ms,
            negative_ttl_ms: self.negative_ttl_ms,
            positive: Mutex::new(HashMap::new()),
            negative: Mutex::new(HashMap::new()),
        })
    }
}

#[cfg(feature = "reqwest-transport")]
fn default_transport() -> Result<Arc<dyn HttpPost>, ConfigError> {
    Ok(Arc::new(crate::transport::ReqwestTransport::new()))
}

#[cfg(not(feature = "reqwest-transport"))]
fn default_transport() -> Result<Arc<dyn HttpPost>, ConfigError> {
    Err(ConfigError::new(
        "no HTTP transport: build with the `reqwest-transport` feature, or supply `.transport(...)`.",
    ))
}

impl ApiKeyVerifier {
    /// The common case: verify against `https://api.atlasauth.net` using your
    /// instance secret key (`sk_live_…`). Available with the `reqwest-transport`
    /// feature (on by default).
    #[cfg(feature = "reqwest-transport")]
    pub fn new(secret_key: impl Into<String>) -> Result<Self, ConfigError> {
        Self::builder(secret_key).build()
    }

    /// Start a builder (custom base URL, transport, TTLs).
    pub fn builder(secret_key: impl Into<String>) -> ApiKeyVerifierBuilder {
        ApiKeyVerifierBuilder::new(secret_key)
    }

    /// Verify a presented `ak_` secret. Positive results are cached for the
    /// positive TTL, negatives for the (shorter) negative TTL; a cache hit makes
    /// no network call. A transport/auth failure is an [`ApiKeyError`], never a
    /// silent `valid = false`.
    pub async fn verify(&self, secret: &str) -> Result<ApiKeyVerification, ApiKeyError> {
        let now = (self.now)();

        if let Some(v) = self.cached(&self.positive, secret, now, self.positive_ttl_ms) {
            return Ok(v);
        }
        if let Some(v) = self.cached(&self.negative, secret, now, self.negative_ttl_ms) {
            return Ok(v);
        }

        let url = format!("{}/v1/api_keys/verify", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({ "secret": secret }).to_string();
        let resp = self
            .transport
            .post_json(&url, &self.secret_key, body)
            .await?;

        if !(200..300).contains(&resp.status) {
            // A non-2xx is a transport/config problem (e.g. a bad sk_ key → 401),
            // not a verdict about the presented key — surface it, and never cache
            // it as a negative.
            return Err(ApiKeyError::Transport(TransportError::new(format!(
                "api-key verify returned HTTP {}",
                resp.status
            ))));
        }

        let verdict: ApiKeyVerification =
            serde_json::from_str(&resp.body).map_err(|e| ApiKeyError::Malformed(e.to_string()))?;

        let entry = CacheEntry {
            verdict: verdict.clone(),
            stored_at: now,
        };
        if verdict.valid {
            self.positive
                .lock()
                .unwrap()
                .insert(secret.to_string(), entry);
        } else {
            self.negative
                .lock()
                .unwrap()
                .insert(secret.to_string(), entry);
        }

        Ok(verdict)
    }

    fn cached(
        &self,
        cache: &Mutex<HashMap<String, CacheEntry>>,
        secret: &str,
        now: u64,
        ttl_ms: u64,
    ) -> Option<ApiKeyVerification> {
        let mut map = cache.lock().unwrap();
        if let Some(entry) = map.get(secret) {
            if now.saturating_sub(entry.stored_at) < ttl_ms {
                return Some(entry.verdict.clone());
            }
            // Expired: drop it so the map does not grow unbounded with stale keys.
            map.remove(secret);
        }
        None
    }
}
