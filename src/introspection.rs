//! RFC 7662 token introspection at Atlas, for opaque (reference) access tokens.
//!
//! An API, client or instance set to the `opaque` access-token format gets
//! `oat_…` tokens only Atlas can read. An [`Introspector`] asks Atlas's
//! introspection endpoint with your API's own client credentials
//! (`client_secret_basic`) and caches the answer by the token's SHA-256 (the
//! token itself is never kept). The client must be a confidential client the API
//! lists in `introspection_client_ids` (or the client the tokens are issued to).
//!
//! Plug it into [`AccessTokenOptions::introspection`](crate::AccessTokenOptions)
//! and the access-token verifier validates non-JWT tokens through it.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::clock::{system_clock, Clock};
use crate::error::TransportError;
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

/// Configures an [`Introspector`].
#[derive(Clone)]
pub struct IntrospectionOptions {
    pub client_id: String,
    pub client_secret: String,
    /// Default `{issuer}/oauth2/introspect`.
    pub endpoint: Option<String>,
    /// How long an active answer is reused (default 60 s; never past the token's `exp`).
    pub cache_ttl: Duration,
    /// How long an inactive answer is reused (default 10 s; zero disables).
    pub negative_cache_ttl: Duration,
    /// Most answers kept (default 10 000).
    pub cache_max: usize,
    /// Also introspect JWT access tokens, so a revoked grant or a banned user is
    /// refused before the token expires. Off by default: JWTs are verified locally.
    pub introspect_jwts: bool,
}

impl IntrospectionOptions {
    /// Options with the defaults and the given client credentials.
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        IntrospectionOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            endpoint: None,
            cache_ttl: Duration::from_secs(60),
            negative_cache_ttl: Duration::from_secs(10),
            cache_max: 10_000,
            introspect_jwts: false,
        }
    }
}

impl fmt::Debug for IntrospectionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionOptions")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("cache_ttl", &self.cache_ttl)
            .field("negative_cache_ttl", &self.negative_cache_ttl)
            .field("cache_max", &self.cache_max)
            .field("introspect_jwts", &self.introspect_jwts)
            .finish()
    }
}

/// Atlas's introspection endpoint could not be reached, or did not answer 2xx
/// with JSON.
#[derive(Debug, Clone)]
pub struct IntrospectionError(pub String);

impl fmt::Display for IntrospectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IntrospectionError {}

impl From<TransportError> for IntrospectionError {
    fn from(e: TransportError) -> Self {
        IntrospectionError(format!("introspection request failed: {e}"))
    }
}

struct Cache {
    entries: HashMap<String, (Option<Map<String, Value>>, u64)>,
    order: VecDeque<String>,
}

/// RFC 7662 introspection with a small TTL cache keyed by the token's SHA-256.
pub struct Introspector {
    options: IntrospectionOptions,
    endpoint: String,
    basic: String,
    transport: Arc<dyn HttpTransport>,
    clock: Clock,
    cache: Mutex<Cache>,
}

impl fmt::Debug for Introspector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Introspector")
            .field("endpoint", &self.endpoint)
            .field("options", &self.options)
            .finish()
    }
}

fn form_encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl Introspector {
    /// Build an introspector for an issuer, over the given transport. Errors when
    /// the client id or secret is empty.
    pub fn new(
        issuer: &str,
        options: IntrospectionOptions,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, IntrospectionError> {
        Self::with_clock(issuer, options, transport, system_clock())
    }

    /// [`Introspector::new`] with the built-in reqwest transport.
    #[cfg(feature = "reqwest-transport")]
    pub fn with_default_transport(
        issuer: &str,
        options: IntrospectionOptions,
    ) -> Result<Self, IntrospectionError> {
        Self::new(
            issuer,
            options,
            Arc::new(crate::transport::ReqwestTransport::new()),
        )
    }

    /// [`Introspector::new`] with a clock override (epoch ms), for tests.
    pub fn with_clock(
        issuer: &str,
        options: IntrospectionOptions,
        transport: Arc<dyn HttpTransport>,
        clock: Clock,
    ) -> Result<Self, IntrospectionError> {
        if options.client_id.is_empty() || options.client_secret.is_empty() {
            return Err(IntrospectionError(
                "introspection needs a client id and secret".into(),
            ));
        }
        let endpoint = options
            .endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth2/introspect", issuer.trim_end_matches('/')));
        let creds = format!(
            "{}:{}",
            form_encode(&options.client_id),
            form_encode(&options.client_secret)
        );
        Ok(Introspector {
            options,
            endpoint,
            basic: format!("Basic {}", STANDARD.encode(creds)),
            transport,
            clock,
            cache: Mutex::new(Cache {
                entries: HashMap::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Whether JWT access tokens are introspected too.
    pub fn introspect_jwts(&self) -> bool {
        self.options.introspect_jwts
    }

    /// How many answers are cached.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.entries.len()).unwrap_or(0)
    }

    fn key(token: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    }

    /// The claims of an active access token, or `None` for an inactive one
    /// (also for a refresh token).
    pub async fn introspect(
        &self,
        token: &str,
    ) -> Result<Option<Map<String, Value>>, IntrospectionError> {
        let key = Self::key(token);
        {
            let mut c = self
                .cache
                .lock()
                .map_err(|_| IntrospectionError("cache poisoned".into()))?;
            if let Some((claims, until)) = c.entries.get(&key).cloned() {
                if until > (self.clock)() {
                    return Ok(claims);
                }
                c.entries.remove(&key);
                c.order.retain(|k| k != &key);
            }
        }
        let req = HttpRequest::new(HttpMethod::Post, self.endpoint.clone())
            .header("Authorization", self.basic.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "token={}&token_type_hint=access_token",
                form_encode(token)
            ));
        let res = self.transport.send(req).await?;
        if !(200..300).contains(&res.status) {
            return Err(IntrospectionError(format!(
                "introspection failed with HTTP {}",
                res.status
            )));
        }
        let body: Value = serde_json::from_str(&res.body)
            .map_err(|_| IntrospectionError("introspection answered with invalid JSON".into()))?;
        let claims = match body {
            Value::Object(m)
                if m.get("active") == Some(&Value::Bool(true))
                    && m.get("token_use").and_then(Value::as_str) != Some("refresh_token") =>
            {
                Some(m)
            }
            _ => None,
        };
        let now = (self.clock)();
        let ttl = if claims.is_some() {
            self.options.cache_ttl
        } else {
            self.options.negative_cache_ttl
        };
        let mut until = now + ttl.as_millis() as u64;
        if let Some(exp) = claims
            .as_ref()
            .and_then(|c| c.get("exp"))
            .and_then(Value::as_f64)
        {
            until = until.min((exp * 1000.0).max(0.0) as u64);
        }
        if until > now {
            if let Ok(mut c) = self.cache.lock() {
                if c.entries
                    .insert(key.clone(), (claims.clone(), until))
                    .is_some()
                {
                    c.order.retain(|k| k != &key);
                }
                c.order.push_back(key);
                if c.entries.len() > self.options.cache_max {
                    let expired: Vec<String> = c
                        .entries
                        .iter()
                        .filter(|(_, v)| v.1 <= now)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for k in expired {
                        c.entries.remove(&k);
                    }
                    let Cache { entries, order } = &mut *c;
                    order.retain(|k| entries.contains_key(k));
                    while entries.len() > self.options.cache_max {
                        match order.pop_front() {
                            Some(k) => {
                                entries.remove(&k);
                            }
                            None => break,
                        }
                    }
                }
            }
        }
        Ok(claims)
    }
}
