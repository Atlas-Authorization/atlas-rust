//! The shared request core every resource namespace calls.
//!
//! One place decides how a BAPI request is authenticated (`Authorization:
//! Bearer sk_…`), serialized (JSON), made idempotent, and retried — so a
//! resource method stays a one-liner naming a verb, a path, and its shapes. It
//! is built on the object-safe [`HttpTransport`] so it runs anywhere a `fetch`
//! would (the reqwest default, or an injected mock in tests), mirroring
//! `@atlasauth/backend`'s `createRequest`.

use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{ConfigError, TransportError};
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

use super::error::{AtlasApiError, AtlasErrorItem, BackendError};

/// The default BAPI origin. Override per self-hosted instance via the builder.
pub const DEFAULT_API_URL: &str = "https://api.atlasauth.net";

/// Default write-retry budget: two retries (three attempts total).
pub const DEFAULT_MAX_RETRIES: u32 = 2;

/// Default backoff base: 250 ms, doubled per attempt.
pub const DEFAULT_BASE_DELAY_MS: u64 = 250;

/// The request header that turns on strict request bodies for one call.
pub const ATLAS_STRICT_HEADER: &str = "Atlas-Strict";

/// The response header listing body fields the server ignored.
pub const ATLAS_UNKNOWN_FIELDS_HEADER: &str = "Atlas-Unknown-Fields";

/// What the server reported it ignored on one write: the request's method and
/// path, plus every unknown body field it named in `Atlas-Unknown-Fields`
/// (nested fields as `parent.child`). Delivered to the hook installed with
/// [`BackendClientBuilder::on_unknown_fields`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFields {
    pub method: HttpMethod,
    pub path: String,
    pub fields: Vec<String>,
}

/// A callback that receives every [`UnknownFields`] report.
pub type UnknownFieldsHook = Arc<dyn Fn(&UnknownFields) + Send + Sync>;

/// The typed management client for the Atlas Backend API — the secret-key
/// surface, the Rust peer of `@atlasauth/backend`'s `createAtlasClient`.
///
/// Construct it with [`BackendClient::new`] (reqwest) or
/// [`BackendClient::builder`] (custom transport / base URL / retry policy), then
/// reach a resource namespace: `client.users().get(id).await`.
///
/// The same client also drives the Platform API (`/v1/platform/*`): build it
/// with a platform key (`psk_…`) instead of a secret key and use
/// [`BackendClient::platform`].
///
/// Cloning is cheap (the transport and hooks are shared), which is how
/// [`BackendClient::with_strict`] gives a per-call strict-mode override.
#[derive(Clone)]
pub struct BackendClient {
    secret_key: String,
    base_url: String,
    transport: Arc<dyn HttpTransport>,
    max_retries: u32,
    base_delay_ms: u64,
    strict: Option<bool>,
    on_unknown_fields: Option<UnknownFieldsHook>,
    traceparent: Option<String>,
    dry_run: bool,
    secret_recipient: Option<String>,
}

/// Builder for a [`BackendClient`].
pub struct BackendClientBuilder {
    secret_key: String,
    base_url: String,
    transport: Option<Arc<dyn HttpTransport>>,
    max_retries: u32,
    base_delay_ms: u64,
    strict: Option<bool>,
    on_unknown_fields: Option<UnknownFieldsHook>,
    traceparent: Option<String>,
    secret_recipient: Option<String>,
}

impl BackendClientBuilder {
    fn new(secret_key: impl Into<String>) -> Self {
        BackendClientBuilder {
            secret_key: secret_key.into(),
            base_url: DEFAULT_API_URL.to_string(),
            transport: None,
            max_retries: DEFAULT_MAX_RETRIES,
            base_delay_ms: DEFAULT_BASE_DELAY_MS,
            strict: None,
            on_unknown_fields: None,
            traceparent: None,
            secret_recipient: None,
        }
    }

    /// Send a W3C `traceparent` header on every request, so Atlas stores the
    /// trace id on the webhook deliveries, back-channel deliveries, referral
    /// calls and executor requests the call triggers. Mint one with
    /// [`new_traceparent`](super::new_traceparent). Override per call with
    /// [`BackendClient::with_traceparent`].
    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.traceparent = Some(traceparent.into());
        self
    }

    /// Seal every shown-once secret in a response to this recipient
    /// (`x25519:<base64 public key>`, see `generate_seal_key_pair`): responses
    /// then carry `sealed_secret` fields instead of plaintext. Sent as
    /// `X-Secret-Recipient`.
    pub fn secret_recipient(mut self, recipient: impl Into<String>) -> Self {
        self.secret_recipient = Some(recipient.into());
        self
    }

    /// Strict request bodies. `true` sends `Atlas-Strict: true` on every write
    /// (POST/PUT/PATCH/DELETE), so a body field the endpoint does not accept is
    /// refused with `422 UNKNOWN_FIELD` before anything changes, instead of
    /// being ignored. `false` sends `Atlas-Strict: false`, opting out when your
    /// instance makes strict the default. Not calling this sends no header (the
    /// instance default applies). Override for one call with
    /// [`BackendClient::with_strict`].
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = Some(strict);
        self
    }

    /// Called after any successful response that carries an
    /// `Atlas-Unknown-Fields` header — i.e. the server accepted the write but
    /// ignored the named body fields (usually a typo or a field from a newer
    /// API version). Use it to log a warning.
    pub fn on_unknown_fields(mut self, hook: impl Fn(&UnknownFields) + Send + Sync + 'static) -> Self {
        self.on_unknown_fields = Some(Arc::new(hook));
        self
    }

    /// Override the BAPI origin (default `https://api.atlasauth.net`). A
    /// trailing slash is tolerated.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Inject a custom HTTP transport (a mock in tests, or a non-reqwest
    /// client). Required when the crate is built without `reqwest-transport`.
    pub fn transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// The write-retry budget on 5xx/429 (default 2). Zero disables retries.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// The backoff base in milliseconds, doubled each attempt (default 250).
    pub fn base_delay_ms(mut self, ms: u64) -> Self {
        self.base_delay_ms = ms;
        self
    }

    /// Finish building. Fails only when no transport is available (compile
    /// without `reqwest-transport` and you must supply [`Self::transport`]).
    pub fn build(self) -> Result<BackendClient, ConfigError> {
        if self.secret_key.is_empty() {
            return Err(ConfigError::new(
                "BackendClient requires a non-empty secret key (sk_…).",
            ));
        }
        let transport = match self.transport {
            Some(t) => t,
            None => default_transport()?,
        };
        Ok(BackendClient {
            secret_key: self.secret_key,
            base_url: self.base_url,
            transport,
            max_retries: self.max_retries,
            base_delay_ms: self.base_delay_ms,
            strict: self.strict,
            on_unknown_fields: self.on_unknown_fields,
            traceparent: self.traceparent,
            dry_run: false,
            secret_recipient: self.secret_recipient,
        })
    }
}

#[cfg(feature = "reqwest-transport")]
fn default_transport() -> Result<Arc<dyn HttpTransport>, ConfigError> {
    Ok(Arc::new(crate::transport::ReqwestTransport::new()))
}

#[cfg(not(feature = "reqwest-transport"))]
fn default_transport() -> Result<Arc<dyn HttpTransport>, ConfigError> {
    Err(ConfigError::new(
        "no HTTP transport: build with the `reqwest-transport` feature, or supply `.transport(...)`.",
    ))
}

impl BackendClient {
    /// The common case: talk to `https://api.atlasauth.net` with your instance
    /// secret key (`sk_live_…`). Available with the `reqwest-transport` feature
    /// (on by default).
    #[cfg(feature = "reqwest-transport")]
    pub fn new(secret_key: impl Into<String>) -> Result<Self, ConfigError> {
        Self::builder(secret_key).build()
    }

    /// Start a builder (custom base URL, transport, retry policy).
    pub fn builder(secret_key: impl Into<String>) -> BackendClientBuilder {
        BackendClientBuilder::new(secret_key)
    }

    /// The configured BAPI origin, trailing slash trimmed.
    pub(crate) fn base(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// A copy of this client with strict request bodies set for the calls made
    /// through it: `Some(true)` sends `Atlas-Strict: true`, `Some(false)` sends
    /// `Atlas-Strict: false`, `None` sends no header. The per-call override of
    /// [`BackendClientBuilder::strict`]:
    ///
    /// ```no_run
    /// # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
    /// use atlasauth::backend::UpdateUserBody;
    /// let body = UpdateUserBody { first_name: Some("Ada".into()), ..Default::default() };
    /// atlas.with_strict(Some(true)).users().update("user_123", &body).await?;
    /// # Ok(()) }
    /// ```
    pub fn with_strict(&self, strict: Option<bool>) -> BackendClient {
        let mut c = self.clone();
        c.strict = strict;
        c
    }

    /// A copy of this client that sends a W3C `traceparent` header on every
    /// call made through it (`None` sends none). The per-call override of
    /// [`BackendClientBuilder::traceparent`].
    pub fn with_traceparent(&self, traceparent: Option<String>) -> BackendClient {
        let mut c = self.clone();
        c.traceparent = traceparent;
        c
    }

    /// A copy of this client that sends every write (POST, PUT, PATCH,
    /// DELETE) as a dry run: `?dry_run=true` is added, Atlas validates the
    /// request and answers with the changes it would make, and nothing
    /// changes. The `Idempotency-Key` is not sent on a dry run. The typed
    /// result of a method called through this client is mostly empty; use
    /// [`BackendClient::dry_run`] to get a [`DryRunResult`](super::DryRunResult).
    pub fn with_dry_run(&self, dry_run: bool) -> BackendClient {
        let mut c = self.clone();
        c.dry_run = dry_run;
        c
    }

    /// A copy of this client that seals shown-once secrets to `recipient`
    /// (see [`BackendClientBuilder::secret_recipient`]); `None` turns it off.
    pub fn with_secret_recipient(&self, recipient: Option<String>) -> BackendClient {
        let mut c = self.clone();
        c.secret_recipient = recipient;
        c
    }

    /// The strict-body setting this client sends (see [`Self::with_strict`]).
    pub fn strict_mode(&self) -> Option<bool> {
        self.strict
    }

    /// Perform a request and deserialize the 2xx body into `T`.
    ///
    /// A non-2xx becomes a [`BackendError::Api`] carrying the §9.1 envelope; a
    /// 5xx or 429 is retried up to the configured budget with doubling backoff,
    /// because those are transient and the write either did not land or is made
    /// safe to repeat by the idempotency key. A 4xx is never retried — it will
    /// fail identically. An empty 2xx body (204) deserializes from JSON `null`,
    /// so a method whose `T` is `()` or an `Option` just works.
    pub(crate) async fn request<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        idempotency_key: Option<&str>,
    ) -> Result<T, BackendError> {
        let text = self.send_text(method, path, query, body, idempotency_key).await?;
        parse_body(&text)
    }

    /// Send raw bytes (an image upload) with the given `content-type`, and
    /// deserialize the 2xx body into `T`. Same auth, retry, strict header, and
    /// error mapping as [`Self::request`].
    pub(crate) async fn request_upload<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<T, BackendError> {
        let text = self
            .send_inner(method, path, query, Payload::Raw(bytes, content_type.to_string()), None, &[], true)
            .await?;
        parse_body(&text)
    }

    /// The same authenticated, retried request as [`Self::request`], returning
    /// the raw 2xx body text instead of deserializing it.
    pub(crate) async fn send_text(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        idempotency_key: Option<&str>,
    ) -> Result<String, BackendError> {
        let payload = match &body {
            Some(v) => Payload::Json(serde_json::to_string(v).map_err(|e| BackendError::Malformed(e.to_string()))?),
            None => Payload::None,
        };
        self.send_inner(method, path, query, payload, idempotency_key, &[], true).await
    }

    /// One JSON request with extra per-call headers and NO retry, for a
    /// single-use call (the Better Auth session exchange) where a retry after a
    /// lost response would spend the token twice. The extra headers can never
    /// replace the `Authorization` bearer.
    pub(crate) async fn request_once_with_headers<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, String)],
    ) -> Result<T, BackendError> {
        let payload = match &body {
            Some(v) => Payload::Json(serde_json::to_string(v).map_err(|e| BackendError::Malformed(e.to_string()))?),
            None => Payload::None,
        };
        let text = self.send_inner(method, path, &[], payload, None, headers, false).await?;
        parse_body(&text)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_inner(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        payload: Payload,
        idempotency_key: Option<&str>,
        extra_headers: &[(&str, String)],
        retry: bool,
    ) -> Result<String, BackendError> {
        let max_retries = if retry { self.max_retries } else { 0 };
        let dry = self.dry_run && method != HttpMethod::Get;
        let mut query_all: Vec<(&str, String)> = query.to_vec();
        if dry {
            query_all.push(("dry_run", "true".to_string()));
        }
        let idempotency_key = if dry { None } else { idempotency_key };
        let url = format!("{}{}{}", self.base(), path, serialize_query(&query_all));

        let mut attempt: u32 = 0;
        loop {
            let mut req = HttpRequest::new(method, url.clone())
                .header("authorization", format!("Bearer {}", self.secret_key))
                .header("accept", "application/json");
            let mut raw: Option<Vec<u8>> = None;
            match &payload {
                Payload::None => {}
                Payload::Json(s) => {
                    req = req.header("content-type", "application/json").body(s.clone());
                }
                Payload::Raw(bytes, content_type) => {
                    req = req.header("content-type", content_type.clone());
                    raw = Some(bytes.clone());
                }
            }
            if let Some(key) = idempotency_key {
                req = req.header("idempotency-key", key);
            }
            if let Some(tp) = &self.traceparent {
                req = req.header("traceparent", tp.clone());
            }
            if let Some(recipient) = &self.secret_recipient {
                req = req.header("x-secret-recipient", recipient.clone());
            }
            for (name, value) in extra_headers {
                if !name.eq_ignore_ascii_case("authorization") {
                    req = req.header(*name, value.clone());
                }
            }
            if method != HttpMethod::Get {
                if let Some(strict) = self.strict {
                    req = req.header(ATLAS_STRICT_HEADER, if strict { "true" } else { "false" });
                }
            }

            let result = self.transport.send_full(req, raw).await;
            match result {
                Err(transport_err) => {
                    if attempt < max_retries {
                        self.backoff(attempt).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(BackendError::Transport(transport_err));
                }
                Ok(resp) => {
                    if (200..300).contains(&resp.status) {
                        if let (Some(hook), Some(list)) =
                            (&self.on_unknown_fields, resp.header(ATLAS_UNKNOWN_FIELDS_HEADER))
                        {
                            let fields: Vec<String> = list
                                .split(',')
                                .map(|f| f.trim().to_string())
                                .filter(|f| !f.is_empty())
                                .collect();
                            if !fields.is_empty() {
                                hook(&UnknownFields { method, path: path.to_string(), fields });
                            }
                        }
                        return Ok(resp.body);
                    }
                    // 5xx and 429 are transient: retry while budget remains.
                    if (resp.status >= 500 || resp.status == 429) && attempt < max_retries {
                        self.backoff(attempt).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(BackendError::Api(to_api_error(resp.status, &resp.body)));
                }
            }
        }
    }

    /// Public escape hatch: call ANY BAPI endpoint the crate does not type yet.
    ///
    /// Applies the same auth (`Authorization: Bearer sk_…`), JSON encoding,
    /// 5xx/429 retry policy, and typed [`BackendError`] as every resource method,
    /// then deserializes the 2xx body into a caller-chosen `T`. `path` is the
    /// absolute API path (e.g. `/v1/some_new_thing`); `query` pairs are
    /// percent-encoded for you.
    ///
    /// ```no_run
    /// # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
    /// use atlasauth::HttpMethod;
    /// let v: serde_json::Value = atlas
    ///     .request_raw(HttpMethod::Get, "/v1/some_new_thing", &[("limit", "5".into())], None)
    ///     .await?;
    /// # let _ = v; Ok(()) }
    /// ```
    pub async fn request_raw<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<T, BackendError> {
        self.request(method, path, query, body, None).await
    }

    /// [`Self::request_raw`] returning the body as a dynamic [`Value`]
    /// (`null` for an empty body).
    pub async fn request_value(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, BackendError> {
        self.request(method, path, query, body, None).await
    }

    /// [`Self::request_raw`] returning the undecoded response body bytes — for
    /// non-JSON responses such as the JSONL/CSV audit export.
    pub async fn request_bytes(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Vec<u8>, BackendError> {
        Ok(self.send_text(method, path, query, body, None).await?.into_bytes())
    }

    /// [`Self::request_raw`] carrying an idempotency key, so a retried write
    /// (the §9.1 5xx/429 retry, or a caller's own re-issue) lands exactly once.
    /// Additive peer of [`Self::request_raw`]: pass `Some(key)` to send an
    /// `Idempotency-Key` header, or `None` for the plain behaviour.
    ///
    /// ```no_run
    /// # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
    /// use atlasauth::HttpMethod;
    /// let v: serde_json::Value = atlas
    ///     .request_raw_idem(HttpMethod::Post, "/v1/some_new_thing", &[], None, Some("idem_01H…"))
    ///     .await?;
    /// # let _ = v; Ok(()) }
    /// ```
    pub async fn request_raw_idem<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        idempotency_key: Option<&str>,
    ) -> Result<T, BackendError> {
        self.request(method, path, query, body, idempotency_key).await
    }

    /// [`Self::request_value`] carrying an idempotency key. Additive peer of
    /// [`Self::request_value`]; see [`Self::request_raw_idem`].
    pub async fn request_value_idem(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        self.request(method, path, query, body, idempotency_key).await
    }

    /// Public escape hatch for a raw-bytes upload to any endpoint: sends
    /// `bytes` verbatim with `content_type`, then deserializes the 2xx body.
    pub async fn request_upload_raw<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        query: &[(&str, String)],
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<T, BackendError> {
        self.request_upload(method, path, query, bytes, content_type).await
    }

    async fn backoff(&self, attempt: u32) {
        if self.base_delay_ms == 0 {
            return;
        }
        let delay = self.base_delay_ms.saturating_mul(1u64 << attempt.min(16));
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

/// A request body: none, serialized JSON, or raw bytes with their content-type.
enum Payload {
    None,
    Json(String),
    Raw(Vec<u8>, String),
}

/// Deserialize a 2xx body; an empty body is JSON `null` so `()`/`Option<_>`
/// methods (a 204) resolve cleanly.
fn parse_body<T: DeserializeOwned>(body: &str) -> Result<T, BackendError> {
    let text = if body.trim().is_empty() { "null" } else { body };
    serde_json::from_str::<T>(text).map_err(|e| BackendError::Malformed(e.to_string()))
}

/// Parse a non-2xx body into the §9.1 envelope, falling back to a synthetic
/// `UNKNOWN` item when the body is empty or not the expected shape.
fn to_api_error(status: u16, body: &str) -> AtlasApiError {
    #[derive(serde::Deserialize)]
    struct Envelope {
        errors: Vec<AtlasErrorItem>,
    }
    if let Ok(env) = serde_json::from_str::<Envelope>(body) {
        if !env.errors.is_empty() {
            return AtlasApiError {
                status,
                errors: env.errors,
            };
        }
    }
    let message = if body.trim().is_empty() {
        format!("Atlas API request failed with status {status}")
    } else {
        body.chars().take(500).collect()
    };
    AtlasApiError {
        status,
        errors: vec![AtlasErrorItem {
            code: "UNKNOWN".to_string(),
            message,
            param: None,
            meta: None,
            docs_url: None,
            did_you_mean: Vec::new(),
            allowed_methods: Vec::new(),
        }],
    }
}

/// Serialize a query list to `?a=1&b=2`, percent-encoding both sides and
/// dropping nothing (callers omit empties before calling).
pub(crate) fn serialize_query(query: &[(&str, String)]) -> String {
    if query.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = query
        .iter()
        .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
        .collect();
    format!("?{}", parts.join("&"))
}

/// Percent-encode one query/path component. A tiny hand-rolled encoder keeps the
/// backend feature from pulling `url` (which only the client feature needs).
pub(crate) fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Expose the transport-error constructor to sibling modules without widening
/// the public API.
#[allow(dead_code)]
pub(crate) fn transport_error(msg: impl Into<String>) -> TransportError {
    TransportError::new(msg)
}
