//! Moving from Better Auth to Atlas: the bundle-import helpers, the
//! secret-key session exchange, and a framework-neutral session bridge.
//!
//! **Import.** The Better Auth exporter (`npx atlas-better-auth-export`) seals
//! your Better Auth data to the instance's import key.
//! [`BetterAuthImports::upload`] creates an import, uploads the bundle in
//! line-aligned parts of at most 8 MiB and finalizes it (Atlas opens it and runs
//! the dry run); [`BetterAuthImports::wait_for`] polls until Atlas is done.
//!
//! **Sessions.** During the migration window a returning user still carries
//! their Better Auth session cookie (`better-auth.session_token`,
//! `__Secure-` prefixed over https). It is HttpOnly, so only your server reads
//! it. [`BetterAuthBridge`] exchanges it ONCE with Atlas through the Backend
//! API (`POST /v1/migrations/better_auth/exchange`, secret key, forwarding the
//! end user's IP and user agent), and tells you which Atlas cookies to set and
//! which Better Auth cookies to clear. A user who still owes a second factor is
//! sent to finish it. `atlasauth::axum::BetterAuthBridgeLayer` (features
//! `axum` + `backend`) renders the decision for an Axum app.
//!
//! ```no_run
//! # async fn demo(bundle: String) -> Result<(), atlasauth::backend::BackendError> {
//! use atlasauth::backend::{BackendClient, UploadOptions, WaitOptions};
//!
//! let atlas = BackendClient::new("sk_live_…").expect("client");
//! let imp = atlas.better_auth_imports().upload(&bundle, UploadOptions::default()).await?;
//! let imp = atlas.better_auth_imports().wait_for(&imp.id, WaitOptions::default()).await?;
//! if imp.status == "ready" {
//!     atlas.better_auth_imports().apply(&imp.id, &Default::default()).await?;
//! }
//! # Ok(()) }
//! ```

use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::error::TransportError;
use crate::http::HttpMethod;

use super::client::{encode_component, BackendClient};
use super::error::BackendError;
use super::types;
use super::{BetterAuthBridgeApi, BetterAuthImports};

/// Better Auth's default cookie prefix (`advanced.cookiePrefix`).
pub const BETTER_AUTH_COOKIE_PREFIX: &str = "better-auth";

/// The Backend API path of the secret-key session exchange.
pub const BETTER_AUTH_EXCHANGE_PATH: &str = "/v1/migrations/better_auth/exchange";

/// The header carrying the END USER's IP on the exchange.
pub const CLIENT_IP_HEADER: &str = "x-atlas-client-ip";

/// The header carrying the END USER's user agent on the exchange.
pub const CLIENT_USER_AGENT_HEADER: &str = "x-atlas-client-user-agent";

/// Bytes per uploaded bundle part (the API takes at most 10 MiB per part).
pub const BETTER_AUTH_IMPORT_PART_BYTES: usize = 8 * 1024 * 1024;

/// Statuses an import stays in while Atlas is working on it
/// ([`BetterAuthImports::wait_for`] polls through them).
pub const BETTER_AUTH_IMPORT_IN_FLIGHT: [&str; 3] = ["analyzing", "queued", "applying"];

// ── bundle upload ────────────────────────────────────────────────────────────

/// Split a sealed bundle into upload parts of at most `max_bytes` (UTF-8),
/// each ending on a line boundary and a newline. Empty lines are dropped; a
/// single line longer than `max_bytes` becomes a part of its own (the API
/// refuses parts over 10 MiB, so keep `max_bytes` at or under
/// [`BETTER_AUTH_IMPORT_PART_BYTES`]). A `max_bytes` of 0 is treated as 1.
pub fn split_bundle_parts(bundle: &str, max_bytes: usize) -> Vec<String> {
    let max_bytes = max_bytes.max(1);
    let mut parts = Vec::new();
    let mut current = String::new();
    for line in bundle.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let n = line.len() + 1;
        if !current.is_empty() && current.len() + n > max_bytes {
            parts.push(std::mem::take(&mut current));
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Options for [`BetterAuthImports::upload`].
#[derive(Default)]
pub struct UploadOptions {
    /// Import options stored on the import (the dry run and apply use them).
    pub options: Option<types::BetterAuthImportOptionsInput>,
    /// Bytes per part (default [`BETTER_AUTH_IMPORT_PART_BYTES`]).
    pub part_bytes: Option<usize>,
    /// Called after each part with `(part, of)`.
    pub on_part: Option<Box<dyn FnMut(usize, usize) + Send>>,
}

/// Options for [`BetterAuthImports::wait_for`].
pub struct WaitOptions {
    /// Time between polls (default 2 s).
    pub interval: Duration,
    /// Give up after this long (default 6 h).
    pub timeout: Duration,
    /// Called with every polled state.
    pub on_progress: Option<Box<dyn FnMut(&types::BetterAuthImport) + Send>>,
}

impl Default for WaitOptions {
    fn default() -> Self {
        WaitOptions { interval: Duration::from_secs(2), timeout: Duration::from_secs(6 * 3600), on_progress: None }
    }
}

impl BetterAuthImports<'_> {
    /// Create an import, upload the sealed bundle in line-aligned parts and
    /// finalize it. Returns the finalized import: `ready` or `invalid`, or
    /// `analyzing` for a large bundle — then [`Self::wait_for`] it. An empty
    /// bundle is refused before any call ([`BackendError::Malformed`]).
    pub async fn upload(&self, bundle: &str, mut opts: UploadOptions) -> Result<types::BetterAuthImport, BackendError> {
        let parts = split_bundle_parts(bundle, opts.part_bytes.unwrap_or(BETTER_AUTH_IMPORT_PART_BYTES));
        if parts.is_empty() {
            return Err(BackendError::Malformed("the Better Auth bundle is empty".to_string()));
        }
        let mut body = types::BetterAuthImportsCreateBody::new();
        if let Some(options) = opts.options.take() {
            body = body.with_options(options);
        }
        let created = self.create(&body, None).await?;
        if created.id.is_empty() {
            return Err(BackendError::Malformed("Atlas did not return an import id".to_string()));
        }
        let of = parts.len();
        for (i, part) in parts.into_iter().enumerate() {
            let n = i + 1;
            self.upload_part(&created.id, &n.to_string(), &types::BetterAuthImportsUploadPartBody::new(part))
                .await?;
            if let Some(cb) = opts.on_part.as_mut() {
                cb(n, of);
            }
        }
        self.finalize(&created.id).await
    }

    /// Poll until the import leaves `analyzing` / `queued` / `applying` and
    /// return it (`ready`, `invalid`, `completed`, `failed` — or `uploading`
    /// when it was never finalized). Past `timeout` this fails with a
    /// [`BackendError::Transport`] naming the last status.
    pub async fn wait_for(&self, id: &str, mut opts: WaitOptions) -> Result<types::BetterAuthImport, BackendError> {
        let deadline = Instant::now() + opts.timeout;
        loop {
            let imp = self.get(id).await?;
            if let Some(cb) = opts.on_progress.as_mut() {
                cb(&imp);
            }
            if !BETTER_AUTH_IMPORT_IN_FLIGHT.contains(&imp.status.as_str()) {
                return Ok(imp);
            }
            if Instant::now() >= deadline {
                return Err(BackendError::Transport(TransportError::new(format!(
                    "timed out waiting for Better Auth import {id} (status {})",
                    imp.status
                ))));
            }
            tokio::time::sleep(opts.interval).await;
        }
    }
}

// ── the session exchange ─────────────────────────────────────────────────────

/// The end user an exchange is made for, and how the session is recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeParams {
    /// The END USER's IP (sent as `X-Atlas-Client-IP`), so Atlas's guards,
    /// risk and geo checks see the user rather than your server.
    pub client_ip: Option<String>,
    /// The END USER's user agent (sent as `X-Atlas-Client-User-Agent`), for the
    /// device record.
    pub user_agent: Option<String>,
    /// `Some(false)` records a browser-session (non-persistent) session.
    pub remember: Option<bool>,
}

impl BetterAuthBridgeApi<'_> {
    /// Exchange a Better Auth session (the raw cookie value or the bare token)
    /// for an Atlas session, once. Returns the JSON body: `session_tokens`
    /// (`jwt`, `refresh_token`, `session_id`, `user_id`, `expires_in`) or, when
    /// a second factor is owed, a `sign_in_attempt` (`id`, `status`). A refusal
    /// is a [`BackendError::Api`] whose `meta.bridge_outcome` says why — use
    /// [`exchange_better_auth_session`] for a classified result. The call is
    /// never retried: the token is single use.
    pub async fn exchange(&self, token: &str, params: &ExchangeParams) -> Result<Value, BackendError> {
        let mut headers: Vec<(&str, String)> = Vec::new();
        if let Some(ip) = params.client_ip.as_deref().filter(|s| !s.is_empty()) {
            headers.push((CLIENT_IP_HEADER, ip.to_string()));
        }
        if let Some(ua) = params.user_agent.as_deref().filter(|s| !s.is_empty()) {
            headers.push((CLIENT_USER_AGENT_HEADER, ua.to_string()));
        }
        let mut body = Map::new();
        body.insert("token".into(), Value::String(token.to_string()));
        if params.remember == Some(false) {
            body.insert("remember".into(), Value::Bool(false));
        }
        self.client
            .request_once_with_headers(HttpMethod::Post, "/v1/migrations/better_auth/exchange", Some(Value::Object(body)), &headers)
            .await
    }
}

/// Why an exchange did not produce a session. Atlas reports the first six in
/// `meta.bridge_outcome`; `Unavailable` is a transport failure, a 5xx or any
/// other answer that is not a verdict on the Better Auth session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BridgeRefusal {
    /// The bridge is off or its window has ended.
    Closed,
    /// Not a known Better Auth session.
    Invalid,
    /// The cookie's signature does not match the old app's secret.
    SignatureInvalid,
    /// The Better Auth session has expired.
    Expired,
    /// The session was already exchanged.
    Reused,
    /// The user cannot sign in (banned, locked, deleted).
    UserUnavailable,
    /// Throttled (429); try again later.
    RateLimited,
    /// No verdict (transport failure, 5xx, unexpected answer); try again later.
    Unavailable,
}

impl BridgeRefusal {
    /// The wire name (`closed`, `signature_invalid`, …; `unavailable` for the
    /// SDK-side catch-all).
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeRefusal::Closed => "closed",
            BridgeRefusal::Invalid => "invalid",
            BridgeRefusal::SignatureInvalid => "signature_invalid",
            BridgeRefusal::Expired => "expired",
            BridgeRefusal::Reused => "reused",
            BridgeRefusal::UserUnavailable => "user_unavailable",
            BridgeRefusal::RateLimited => "rate_limited",
            BridgeRefusal::Unavailable => "unavailable",
        }
    }

    /// Parse a `meta.bridge_outcome` value.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "closed" => BridgeRefusal::Closed,
            "invalid" => BridgeRefusal::Invalid,
            "signature_invalid" => BridgeRefusal::SignatureInvalid,
            "expired" => BridgeRefusal::Expired,
            "reused" => BridgeRefusal::Reused,
            "user_unavailable" => BridgeRefusal::UserUnavailable,
            "rate_limited" => BridgeRefusal::RateLimited,
            _ => return None,
        })
    }

    /// True when the Better Auth session will never exchange (invalid,
    /// signature_invalid, expired, reused, user_unavailable): its cookies are
    /// cleared. Closed, rate-limited and unavailable keep them, so the
    /// exchange is retried on a later request.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            BridgeRefusal::Invalid
                | BridgeRefusal::SignatureInvalid
                | BridgeRefusal::Expired
                | BridgeRefusal::Reused
                | BridgeRefusal::UserUnavailable
        )
    }
}

/// An Atlas session from an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgedSession {
    pub jwt: String,
    pub refresh_token: String,
    pub session_id: String,
    pub user_id: String,
    pub expires_in: i64,
}

/// The classified outcome of an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BetterAuthExchangeResult {
    /// Signed in.
    Session(BridgedSession),
    /// The Better Auth session is spent and the user finishes a second factor
    /// on the sign-in attempt `attempt_id` (`status` is `needs_second_factor`
    /// or `needs_mfa_enrollment`).
    NeedsMfa { attempt_id: String, status: String },
    /// No session; `http_status` is 0 for a transport failure.
    Refused { outcome: BridgeRefusal, http_status: u16 },
}

fn classify_success(data: &Value) -> BetterAuthExchangeResult {
    let s = |k: &str| data.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    match data.get("object").and_then(Value::as_str) {
        Some("session_tokens") if !s("jwt").is_empty() && !s("refresh_token").is_empty() => {
            BetterAuthExchangeResult::Session(BridgedSession {
                jwt: s("jwt"),
                refresh_token: s("refresh_token"),
                session_id: s("session_id"),
                user_id: s("user_id"),
                expires_in: data.get("expires_in").and_then(Value::as_i64).unwrap_or(0),
            })
        }
        Some("sign_in_attempt")
            if !s("id").is_empty() && matches!(s("status").as_str(), "needs_second_factor" | "needs_mfa_enrollment") =>
        {
            BetterAuthExchangeResult::NeedsMfa { attempt_id: s("id"), status: s("status") }
        }
        _ => BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::Unavailable, http_status: 200 },
    }
}

fn classify_error(err: &BackendError) -> BetterAuthExchangeResult {
    match err {
        BackendError::Api(api) => {
            if api.status == 429 {
                return BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::RateLimited, http_status: 429 };
            }
            let outcome = api
                .errors
                .first()
                .and_then(|e| e.meta.as_ref())
                .and_then(|m| m.get("bridge_outcome"))
                .and_then(Value::as_str)
                .and_then(BridgeRefusal::parse)
                // Anything else (a 5xx, a guard refusal, an unparsable body) is
                // not a verdict on the Better Auth session: keep it, retry later.
                .unwrap_or(BridgeRefusal::Unavailable);
            BetterAuthExchangeResult::Refused { outcome, http_status: api.status }
        }
        _ => BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::Unavailable, http_status: 0 },
    }
}

/// Exchange a Better Auth session (the raw cookie value or the bare token) for
/// an Atlas session over the Backend API, classified. Never fails: a transport
/// failure is `Refused { Unavailable, 0 }`, so the caller keeps the Better Auth
/// cookie and tries again on a later request. Pass the END USER's IP and user
/// agent in `params`.
pub async fn exchange_better_auth_session(
    client: &BackendClient,
    token: &str,
    params: &ExchangeParams,
) -> BetterAuthExchangeResult {
    match client.better_auth_bridge().exchange(token, params).await {
        Ok(data) => classify_success(&data),
        Err(err) => classify_error(&err),
    }
}

// ── cookies ──────────────────────────────────────────────────────────────────

/// The Better Auth cookie names for `prefix`: the session cookie (the
/// `__Secure-` name first) and every cookie the bridge clears.
pub fn better_auth_cookie_names(prefix: &str) -> (Vec<String>, Vec<String>) {
    let base: Vec<String> = ["session_token", "session_data", "account_data", "dont_remember"]
        .iter()
        .map(|n| format!("{prefix}.{n}"))
        .collect();
    let session = vec![format!("__Secure-{prefix}.session_token"), format!("{prefix}.session_token")];
    let mut all: Vec<String> = base.iter().map(|n| format!("__Secure-{n}")).collect();
    all.extend(base);
    (session, all)
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// The raw Better Auth session cookie value from a `Cookie` header, the
/// `__Secure-` name first; `None` when absent. `cookie_name` overrides the
/// name when the old app set `advanced.cookies.session_token.name`.
pub fn read_better_auth_session_cookie(
    cookie_header: Option<&str>,
    cookie_prefix: &str,
    cookie_name: Option<&str>,
) -> Option<String> {
    let header = cookie_header?;
    let names = match cookie_name {
        Some(n) => vec![format!("__Secure-{n}"), n.to_string()],
        None => better_auth_cookie_names(cookie_prefix).0,
    };
    names
        .iter()
        .find_map(|n| cookie_value(header, n).filter(|v| !v.is_empty()))
        .map(str::to_owned)
}

/// A cookie to set (or, with `max_age == Some(0)`, clear) on the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeCookie {
    pub name: String,
    pub value: String,
    pub path: String,
    pub domain: Option<String>,
    pub http_only: bool,
    /// `Lax`, `Strict` or `None`.
    pub same_site: Option<&'static str>,
    pub secure: bool,
    pub max_age: Option<i64>,
}

impl BridgeCookie {
    /// The cookie as a `Set-Cookie` header value.
    pub fn to_set_cookie(&self) -> String {
        let mut out = format!("{}={}; Path={}", self.name, self.value, if self.path.is_empty() { "/" } else { &self.path });
        if let Some(d) = &self.domain {
            out.push_str(&format!("; Domain={d}"));
        }
        if let Some(age) = self.max_age {
            out.push_str(&format!("; Max-Age={age}"));
            if age == 0 {
                out.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
            }
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if self.secure {
            out.push_str("; Secure");
        }
        if let Some(ss) = self.same_site {
            out.push_str(&format!("; SameSite={ss}"));
        }
        out
    }
}

// ── the bridge ───────────────────────────────────────────────────────────────

/// What the bridge decided for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeAction {
    /// No Better Auth cookie, or an Atlas session is already present: carry on.
    None,
    /// Set the cookies and re-enter (redirect to the same URL).
    SignedIn,
    /// Send the browser to your sign-in page carrying the attempt
    /// ([`BridgeDecision::continuation_url`]); the cookies clear the spent
    /// Better Auth cookies.
    NeedsMfa,
    /// Carry on unauthenticated; the cookies clear the Better Auth cookies
    /// only when the refusal is final.
    Refused,
}

/// The bridge's decision: an action plus the cookies to set or clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeDecision {
    pub action: BridgeAction,
    pub cookies: Vec<BridgeCookie>,
    pub session: Option<BridgedSession>,
    pub attempt_id: String,
    pub status: String,
    pub outcome: Option<BridgeRefusal>,
}

impl BridgeDecision {
    fn none() -> Self {
        BridgeDecision {
            action: BridgeAction::None,
            cookies: Vec::new(),
            session: None,
            attempt_id: String::new(),
            status: String::new(),
            outcome: None,
        }
    }

    /// `url` with `__atlas_attempt` / `__atlas_status` set (for `NeedsMfa`);
    /// any earlier values of those two are replaced, the rest is kept as is.
    pub fn continuation_url(&self, url: &str) -> String {
        let (before_hash, hash) = match url.split_once('#') {
            Some((a, h)) => (a, Some(h)),
            None => (url, None),
        };
        let (base, query) = match before_hash.split_once('?') {
            Some((b, q)) => (b, q),
            None => (before_hash, ""),
        };
        let mut pairs: Vec<String> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .filter(|p| {
                let key = p.split('=').next().unwrap_or("");
                key != "__atlas_attempt" && key != "__atlas_status"
            })
            .map(str::to_owned)
            .collect();
        pairs.push(format!("__atlas_attempt={}", encode_component(&self.attempt_id)));
        pairs.push(format!("__atlas_status={}", encode_component(&self.status)));
        let mut out = format!("{base}?{}", pairs.join("&"));
        if let Some(h) = hash {
            out.push('#');
            out.push_str(h);
        }
        out
    }

    /// True when the request should be answered with a redirect carrying
    /// [`Self::cookies`] (everything except `None` and a non-final refusal).
    pub fn should_redirect(&self) -> bool {
        !(self.action == BridgeAction::None || (self.action == BridgeAction::Refused && self.cookies.is_empty()))
    }
}

/// The Better Auth session bridge as a function of a request. It does nothing
/// (no network) for a request without a Better Auth cookie or with an Atlas
/// session (`__session` / `__atlas_rt`) present.
///
/// ```no_run
/// # async fn demo(cookie_header: Option<&str>, ip: Option<&str>) {
/// use atlasauth::backend::{BackendClient, BetterAuthBridge, BridgeAction};
///
/// let bridge = BetterAuthBridge::new(BackendClient::new("sk_live_…").unwrap())
///     .sign_in_url("/sign-in");
/// let decision = bridge.decide(cookie_header, ip, None).await;
/// if decision.should_redirect() {
///     // Append every decision.cookies[i].to_set_cookie() and redirect (307)
///     // to the same URL — or, for BridgeAction::NeedsMfa, to
///     // decision.continuation_url(bridge.sign_in_target().unwrap_or("/")).
/// }
/// # }
/// ```
#[derive(Clone)]
pub struct BetterAuthBridge {
    client: BackendClient,
    cookie_prefix: String,
    cookie_name: Option<String>,
    better_auth_cookie_domain: Option<String>,
    secure: bool,
    sign_in_url: Option<String>,
}

impl BetterAuthBridge {
    /// A bridge exchanging through `client` (built with the instance secret
    /// key).
    pub fn new(client: BackendClient) -> Self {
        BetterAuthBridge {
            client,
            cookie_prefix: BETTER_AUTH_COOKIE_PREFIX.to_string(),
            cookie_name: None,
            better_auth_cookie_domain: None,
            secure: true,
            sign_in_url: None,
        }
    }

    /// Better Auth's `advanced.cookiePrefix` (default `better-auth`).
    pub fn cookie_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.cookie_prefix = prefix.into();
        self
    }

    /// The session cookie's full name, when the old app overrode it.
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = Some(name.into());
        self
    }

    /// The `domain` the Better Auth cookies were set on (its
    /// `crossSubDomainCookies.domain`), so they clear.
    pub fn better_auth_cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.better_auth_cookie_domain = Some(domain.into());
        self
    }

    /// Mark the Atlas cookies `Secure` (default true). Turn off only for
    /// plain-http local development.
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Where a user who still owes a second factor finishes signing in.
    /// Default: the requested URL.
    pub fn sign_in_url(mut self, url: impl Into<String>) -> Self {
        self.sign_in_url = Some(url.into());
        self
    }

    /// The configured sign-in URL, if any.
    pub fn sign_in_target(&self) -> Option<&str> {
        self.sign_in_url.as_deref()
    }

    /// The Better Auth session token to exchange, or `None` (no cookie, or an
    /// Atlas session is already present — the old cookie is then left for the
    /// old app's own expiry).
    pub fn token_from(&self, cookie_header: Option<&str>) -> Option<String> {
        let header = cookie_header?;
        if cookie_value(header, "__session").map(|v| !v.is_empty()).unwrap_or(false)
            || cookie_value(header, "__atlas_rt").map(|v| !v.is_empty()).unwrap_or(false)
        {
            return None;
        }
        read_better_auth_session_cookie(Some(header), &self.cookie_prefix, self.cookie_name.as_deref())
    }

    /// Decide for one request: `cookie_header` is the request's `Cookie`
    /// header, `client_ip` / `user_agent` the END USER's.
    pub async fn decide(&self, cookie_header: Option<&str>, client_ip: Option<&str>, user_agent: Option<&str>) -> BridgeDecision {
        let token = match self.token_from(cookie_header) {
            Some(t) => t,
            None => return BridgeDecision::none(),
        };
        let params = ExchangeParams {
            client_ip: client_ip.map(str::to_owned),
            user_agent: user_agent.map(str::to_owned),
            remember: None,
        };
        let result = exchange_better_auth_session(&self.client, &token, &params).await;
        self.decision_for(result)
    }

    /// The decision for an exchange result (what [`Self::decide`] returns).
    pub fn decision_for(&self, result: BetterAuthExchangeResult) -> BridgeDecision {
        match result {
            BetterAuthExchangeResult::Session(session) => {
                let mut cookies = vec![
                    BridgeCookie {
                        name: "__session".into(),
                        value: session.jwt.clone(),
                        path: "/".into(),
                        domain: None,
                        http_only: false,
                        same_site: Some("Lax"),
                        secure: self.secure,
                        max_age: None,
                    },
                    BridgeCookie {
                        name: "__atlas_rt".into(),
                        value: session.refresh_token.clone(),
                        path: "/".into(),
                        domain: None,
                        http_only: true,
                        same_site: Some("Lax"),
                        secure: self.secure,
                        max_age: None,
                    },
                ];
                cookies.extend(self.clear_cookies());
                BridgeDecision { action: BridgeAction::SignedIn, cookies, session: Some(session), ..BridgeDecision::none() }
            }
            BetterAuthExchangeResult::NeedsMfa { attempt_id, status } => BridgeDecision {
                action: BridgeAction::NeedsMfa,
                cookies: self.clear_cookies(),
                attempt_id,
                status,
                ..BridgeDecision::none()
            },
            BetterAuthExchangeResult::Refused { outcome, .. } => BridgeDecision {
                action: BridgeAction::Refused,
                cookies: if outcome.is_final() { self.clear_cookies() } else { Vec::new() },
                outcome: Some(outcome),
                ..BridgeDecision::none()
            },
        }
    }

    fn clear_cookies(&self) -> Vec<BridgeCookie> {
        let mut names = better_auth_cookie_names(&self.cookie_prefix).1;
        if let Some(n) = &self.cookie_name {
            names.push(n.clone());
            names.push(format!("__Secure-{n}"));
        }
        names
            .into_iter()
            .map(|name| BridgeCookie {
                // A `__Secure-` cookie can only be overwritten by a Secure Set-Cookie.
                secure: name.starts_with("__Secure-"),
                name,
                value: String::new(),
                path: "/".into(),
                domain: self.better_auth_cookie_domain.clone(),
                http_only: false,
                same_site: None,
                max_age: Some(0),
            })
            .collect()
    }
}

/// The end user's IP from proxy headers: the first `X-Forwarded-For` hop, else
/// `X-Real-IP`. Only as trustworthy as the proxy in front of your app.
pub fn client_ip_from_headers(x_forwarded_for: Option<&str>, x_real_ip: Option<&str>) -> Option<String> {
    let first = x_forwarded_for.and_then(|v| v.split(',').next()).map(str::trim).filter(|s| !s.is_empty());
    first
        .or_else(|| x_real_ip.map(str::trim).filter(|s| !s.is_empty()))
        .map(str::to_owned)
}
