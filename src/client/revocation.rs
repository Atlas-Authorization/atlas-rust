//! §P1-8 scoped delegated tokens — the client half of `POST /v1/api_keys/token`
//! and `GET /v1/api_keys/revoked`.
//!
//! A long-lived `ak_` key is a bearer: handy, but it cannot be checked offline
//! and only revocation (an online call) stops it. The delegated-token flow fixes
//! both ends:
//!
//!  1. [`ApiKeyTokenClient`] mints a SHORT-LIVED, RS256-signed access JWT from an
//!     `ak_` key (`POST /v1/api_keys/token`). A resource server verifies that JWT
//!     offline against the instance JWKS (via [`crate::AtlasBackend`]) — no call
//!     to Atlas on the hot path.
//!  2. Because a minted token outlives a revocation of its parent key, a resource
//!     server polls [`RevokedKeyPoller`] (`GET /v1/api_keys/revoked`) to maintain a
//!     local [`DenyList`] of revoked key ids and reject a token whose key id (its
//!     JWT `sub`) is on the list, even while the token itself is still unexpired.
//!
//! AUTH: the mint/feed endpoints accept an `ak_` bearer (self-mint — the key
//! mints a token for itself) or a publishable-key + secret pair. Both are modelled
//! by [`TokenAuth`]; the caller picks.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::http::{HttpMethod, HttpRequest, HttpTransport};

/// How a token-mint / revoked-feed call authenticates.
#[derive(Debug, Clone)]
pub enum TokenAuth {
    /// Present a bearer directly — an `ak_` key self-minting, or an `sk_` key.
    /// Sent as `Authorization: Bearer <token>`.
    Bearer(String),
    /// Present a publishable key (header) plus the `ak_` secret (body). The
    /// secret identifies WHICH key to mint for over the pk-authenticated channel.
    PublishableKey { publishable_key: String, secret: String },
}

impl TokenAuth {
    fn apply(&self, mut req: HttpRequest) -> HttpRequest {
        match self {
            TokenAuth::Bearer(token) => req.header("authorization", format!("Bearer {token}")),
            TokenAuth::PublishableKey { publishable_key, .. } => {
                req = req.header("x-publishable-key", publishable_key.clone());
                req
            }
        }
    }

    /// The `ak_` secret to carry in the body, if this auth mode supplies one.
    fn body_secret(&self) -> Option<&str> {
        match self {
            TokenAuth::PublishableKey { secret, .. } => Some(secret),
            TokenAuth::Bearer(_) => None,
        }
    }
}

/// A failure of a token-mint or revoked-feed call.
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyTokenError {
    /// A non-2xx response; `body` is the raw error envelope.
    #[error("atlas api-key token: HTTP {status}")]
    Api { status: u16, body: String },
    /// The request did not complete.
    #[error(transparent)]
    Transport(#[from] crate::error::TransportError),
    /// A 2xx body that did not parse.
    #[error("atlas api-key token: malformed response: {0}")]
    Malformed(String),
}

/// Options for a token mint. `ttl_seconds` and `audience` are optional — the
/// server clamps the TTL to the key's policy and uses the issuer as the default
/// audience.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    pub ttl_seconds: Option<u64>,
    pub audience: Option<Vec<String>>,
}

/// The minted short-lived access token and its metadata (`POST /v1/api_keys/token`).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyToken {
    /// The signed access JWT (RS256, verifiable offline against the JWKS).
    pub token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    /// The token's unique id, so a resource server can reject a replay.
    #[serde(default)]
    pub jti: Option<String>,
    /// The parent `ak_` key's id — the JWT `sub`, and the [`DenyList`] key.
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// The issuer, so a verifier knows which JWKS to check without parsing.
    #[serde(default)]
    pub issuer: Option<String>,
}

/// Mints short-lived access tokens from `ak_` keys.
pub struct ApiKeyTokenClient {
    transport: Arc<dyn HttpTransport>,
    base_url: String,
}

impl ApiKeyTokenClient {
    /// Build over a transport and the BAPI/FAPI origin that serves
    /// `/v1/api_keys/token`.
    pub fn new(transport: Arc<dyn HttpTransport>, base_url: impl Into<String>) -> Self {
        ApiKeyTokenClient {
            transport,
            base_url: base_url.into(),
        }
    }

    /// Mint a short-lived access token. With [`TokenAuth::PublishableKey`] the
    /// `ak_` secret rides in the body; with [`TokenAuth::Bearer`] the bearer is
    /// the credential and the body carries only the options.
    pub async fn mint(
        &self,
        auth: &TokenAuth,
        opts: &MintOptions,
    ) -> Result<ApiKeyToken, ApiKeyTokenError> {
        let url = format!("{}/v1/api_keys/token", self.base_url.trim_end_matches('/'));
        let mut body = serde_json::Map::new();
        if let Some(secret) = auth.body_secret() {
            body.insert("secret".into(), serde_json::Value::String(secret.to_string()));
        }
        if let Some(ttl) = opts.ttl_seconds {
            body.insert("ttl_seconds".into(), serde_json::json!(ttl));
        }
        if let Some(aud) = &opts.audience {
            body.insert("audience".into(), serde_json::json!(aud));
        }
        let req = auth
            .apply(HttpRequest::new(HttpMethod::Post, url))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(serde_json::Value::Object(body).to_string());
        let resp = self.transport.send(req).await?;
        if !(200..300).contains(&resp.status) {
            return Err(ApiKeyTokenError::Api {
                status: resp.status,
                body: resp.body,
            });
        }
        serde_json::from_str(&resp.body).map_err(|e| ApiKeyTokenError::Malformed(e.to_string()))
    }
}

/// A local deny-list of revoked `ak_` key ids, maintained from the revoked feed.
///
/// Cheap to clone and share (`Arc` inside); every clone sees the same set. A
/// resource server consults it after verifying a token's signature: extract the
/// token's key id (its JWT `sub`, or [`ApiKeyToken::key_id`] from the mint) and
/// refuse the token when [`is_revoked`](Self::is_revoked) is true.
#[derive(Clone, Default)]
pub struct DenyList {
    set: Arc<Mutex<HashSet<String>>>,
}

impl DenyList {
    /// A fresh, empty deny-list.
    pub fn new() -> Self {
        Self::default()
    }
    /// Whether this key id has been revoked.
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.set.lock().unwrap().contains(key_id)
    }
    /// Add a key id. Returns true if it was newly inserted.
    pub fn insert(&self, key_id: impl Into<String>) -> bool {
        self.set.lock().unwrap().insert(key_id.into())
    }
    /// The number of revoked key ids currently held.
    pub fn len(&self) -> usize {
        self.set.lock().unwrap().len()
    }
    /// Whether the deny-list is empty.
    pub fn is_empty(&self) -> bool {
        self.set.lock().unwrap().is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct RevokedEnvelope {
    #[serde(default)]
    data: Vec<RevokedItem>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RevokedItem {
    #[serde(default)]
    id: String,
    // Present in the feed for a caller that wants revocation times; the poller
    // itself tracks position by the server's keyset cursor, not this field.
    #[serde(default)]
    #[allow(dead_code)]
    revoked_at: Option<i64>,
}

/// Polls `GET /v1/api_keys/revoked` and folds each revoked key id into a shared
/// [`DenyList`], tracking the keyset cursor so each poll resumes exactly where
/// the last one stopped (no gaps, no re-scan).
pub struct RevokedKeyPoller {
    transport: Arc<dyn HttpTransport>,
    base_url: String,
    auth: TokenAuth,
    deny_list: DenyList,
    cursor: Mutex<Option<String>>,
    page_limit: u32,
}

/// The result of one [`RevokedKeyPoller::poll`] — how many new ids were added and
/// whether the feed says more pages remain beyond what was fetched.
#[derive(Debug, Clone)]
pub struct PollResult {
    /// Key ids newly added to the deny-list on this poll.
    pub newly_revoked: Vec<String>,
    /// Whether the last fetched page reported `has_more`.
    pub has_more: bool,
}

impl RevokedKeyPoller {
    /// Build a poller over a transport, origin, and auth. It owns a fresh
    /// [`DenyList`]; share it via [`deny_list`](Self::deny_list).
    pub fn new(
        transport: Arc<dyn HttpTransport>,
        base_url: impl Into<String>,
        auth: TokenAuth,
    ) -> Self {
        RevokedKeyPoller {
            transport,
            base_url: base_url.into(),
            auth,
            deny_list: DenyList::new(),
            cursor: Mutex::new(None),
            page_limit: 100,
        }
    }

    /// Set the per-page limit (the server caps it at 100).
    pub fn with_page_limit(mut self, limit: u32) -> Self {
        self.page_limit = limit.clamp(1, 100);
        self
    }

    /// Seed the cursor (e.g. a persisted one, or a first-poll time floor as epoch
    /// millis or an ISO-8601 instant) so the first poll does not re-scan history.
    pub fn with_since(self, since: impl Into<String>) -> Self {
        *self.cursor.lock().unwrap() = Some(since.into());
        self
    }

    /// The shared deny-list this poller maintains. Clone it into a verifier.
    pub fn deny_list(&self) -> DenyList {
        self.deny_list.clone()
    }

    /// The cursor to persist so a later process resumes without a re-scan.
    pub fn cursor(&self) -> Option<String> {
        self.cursor.lock().unwrap().clone()
    }

    /// Fetch and apply EVERY page available from the current cursor, updating the
    /// deny-list and advancing the cursor until the feed is caught up. Returns all
    /// ids newly added across the drained pages.
    pub async fn poll(&self) -> Result<PollResult, ApiKeyTokenError> {
        let mut newly = Vec::new();
        let mut has_more;
        loop {
            let page = self.fetch_page().await?;
            for item in &page.data {
                if !item.id.is_empty() && self.deny_list.insert(item.id.clone()) {
                    newly.push(item.id.clone());
                }
            }
            if let Some(cursor) = page.next_cursor.clone() {
                *self.cursor.lock().unwrap() = Some(cursor);
            }
            has_more = page.has_more;
            if !page.has_more {
                break;
            }
        }
        Ok(PollResult {
            newly_revoked: newly,
            has_more,
        })
    }

    async fn fetch_page(&self) -> Result<RevokedEnvelope, ApiKeyTokenError> {
        let base = self.base_url.trim_end_matches('/');
        let mut url = format!("{base}/v1/api_keys/revoked?limit={}", self.page_limit);
        if let Some(cursor) = self.cursor.lock().unwrap().clone() {
            url.push_str("&since=");
            url.push_str(&crate::http::encode_segment(&cursor));
        }
        let req = self
            .auth
            .apply(HttpRequest::new(HttpMethod::Get, url))
            .header("accept", "application/json");
        let resp = self.transport.send(req).await?;
        if !(200..300).contains(&resp.status) {
            return Err(ApiKeyTokenError::Api {
                status: resp.status,
                body: resp.body,
            });
        }
        serde_json::from_str(&resp.body).map_err(|e| ApiKeyTokenError::Malformed(e.to_string()))
    }
}

/// Extract the key id an api-key token carries — its JWT `sub` — WITHOUT verifying
/// the signature, so a caller can look it up in a [`DenyList`]. This decodes the
/// middle segment only; it is NOT a verification. A resource server must still
/// verify the token (RS256 against the JWKS, e.g. via [`crate::AtlasBackend`]);
/// the deny-list check is complementary.
pub fn token_key_id(token: &str) -> Option<String> {
    use base64::Engine;
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("sub")?.as_str().map(|s| s.to_string())
}
