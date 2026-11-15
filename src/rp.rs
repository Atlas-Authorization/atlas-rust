//! The hosted-redirect OIDC relying party (feature `rp`).
//!
//! Your server sends the user to Atlas's hosted sign-in page, verifies who came
//! back, and keeps its own session. The Rust peer of `@atlasauth/rp`:
//!
//! * [`RelyingParty::start`] builds the `/oauth2/authorize` redirect: state, nonce
//!   and PKCE (S256) ride in ONE sealed, short-lived, httpOnly flow cookie
//!   (XChaCha20-Poly1305 under a key derived from your `secret`).
//! * [`RelyingParty::callback`] checks `state`, exchanges the code (PKCE + client
//!   authentication), and verifies the ID token against the issuer's JWKS: the
//!   algorithm is pinned to RS256, ES256, ES384, PS256 and EdDSA and `iss`, `aud`/`azp`, `exp`/`iat`,
//!   `nonce` and `at_hash` are checked.
//! * [`RelyingParty::require_recent_auth`] is the step-up redirect,
//!   [`RelyingParty::touch_if_due`] keeps the Atlas session alive, and
//!   [`RelyingParty::sign_out`] ends it.
//!
//! The core is transport- and framework-agnostic: it takes the raw query string
//! and `Cookie` header and returns a [`Redirect`] (a location and the
//! `Set-Cookie` values). The `rp-axum` and `rp-actix` features add ready-made
//! handlers.
//!
//! ```no_run
//! # async fn demo(query: &str, cookie: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
//! use atlasauth::rp::{RelyingParty, RelyingPartyConfig, StartOverrides};
//!
//! let rp = RelyingParty::new(RelyingPartyConfig::new(
//!     "https://auth.example.com",
//!     "client_123",
//!     "https://app.example.com/auth/callback",
//!     "a-session-secret-of-at-least-32-characters",
//! ).client_secret("shh"))?;
//!
//! let started = rp.start("return_to=/billing", StartOverrides::default()).await?;
//! // 302 to started.location with started.set_cookies ...
//! let done = rp.callback(query, cookie).await?;
//! // create your session for done.user.sub, keep done.user.sid on it, then redirect to done.redirect
//! # let _ = (started, done); Ok(()) }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use jsonwebtoken::{decode_header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::clock::{system_clock, Clock};
use crate::error::{ConfigError, TransportError};
use crate::http::{encode_segment, HttpMethod, HttpRequest, HttpResponse, HttpTransport};
pub use crate::jwks::BoxFuture;
use crate::jwks::{decode_with_set, Jwks, JwksCache, JwksSource, SIGNING_ALGS};
use crate::oidc_claims::{
    oidc_organization_of, oidc_organizations_of, oidc_sso_of, OidcOrganization, OidcOrganizationMembership, OidcSsoContext,
};

/// The default flow cookie name.
pub const OIDC_FLOW_COOKIE: &str = "atlas_oidc";
/// How long a started sign-in stays valid, in seconds.
pub const OIDC_FLOW_MAX_AGE_SECONDS: i64 = 600;
/// How long a `require_recent_auth(.., 0, ..)` confirmation counts, in seconds.
pub const CONFIRM_NOW_WINDOW_SECONDS: i64 = 60;
/// The default Backend API origin.
pub const DEFAULT_API_URL: &str = "https://api.atlasauth.net";

const DEFAULT_TOUCH_INTERVAL_MS: u64 = 5 * 60_000;
const DISCOVERY_TTL_MS: u64 = 3_600_000;
const MAX_FORWARDED_VALUE: usize = 512;
const SEALED_PREFIX: &str = "s1.";

/// Parameters `forward_params` may not name: the helper sets them, or they mean something else here.
const NOT_FORWARDABLE: [&str; 12] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "scope",
    "return_to",
    "id_token_hint",
    "request",
    "request_uri",
];

// ── errors ──────────────────────────────────────────────────────────────────

/// Stable failure codes of the sign-in flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcErrorCode {
    StateMismatch,
    IssuerMismatch,
    InvalidRequest,
    InvalidToken,
    TokenExchangeFailed,
    /// Also stands for the OAuth `error` the authorization server redirected back with; see [`OidcError::oauth_error`].
    AccessDenied,
    DiscoveryFailed,
    ReauthenticationRequired,
    SubjectMismatch,
}

impl OidcErrorCode {
    /// The code as the other Atlas SDKs spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            OidcErrorCode::StateMismatch => "state_mismatch",
            OidcErrorCode::IssuerMismatch => "issuer_mismatch",
            OidcErrorCode::InvalidRequest => "invalid_request",
            OidcErrorCode::InvalidToken => "invalid_token",
            OidcErrorCode::TokenExchangeFailed => "token_exchange_failed",
            OidcErrorCode::AccessDenied => "access_denied",
            OidcErrorCode::DiscoveryFailed => "discovery_failed",
            OidcErrorCode::ReauthenticationRequired => "reauthentication_required",
            OidcErrorCode::SubjectMismatch => "subject_mismatch",
        }
    }
}

/// A sign-in failure. A failed [`RelyingParty::callback`] always carries
/// `clear_cookie`: send it as `Set-Cookie` on your error response.
#[derive(Debug, Clone)]
pub struct OidcError {
    pub code: OidcErrorCode,
    pub message: String,
    /// The OAuth `error` value from the authorization or token endpoint, when there was one.
    pub oauth_error: Option<String>,
    /// The OAuth `error_description`, when there was one.
    pub description: Option<String>,
    /// The token endpoint's HTTP status, when it answered.
    pub status: Option<u16>,
    /// A `Set-Cookie` value that removes the flow cookie.
    pub clear_cookie: Option<String>,
}

impl OidcError {
    fn new(code: OidcErrorCode, message: impl Into<String>) -> Self {
        OidcError { code, message: message.into(), oauth_error: None, description: None, status: None, clear_cookie: None }
    }
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "atlas oidc {}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for OidcError {}

/// A failure of a session call (keep-alive, revoke, sign-out).
#[derive(Debug, thiserror::Error)]
pub enum RpError {
    /// The relying party is not configured for this call (no secret key, public client, ...).
    #[error("atlas rp: {0}")]
    Config(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Atlas answered with a failure that is not a plain "signed out".
    #[error("atlas rp: HTTP {status} {code}: {message}")]
    Api { status: u16, code: String, message: String },
    #[error(transparent)]
    Oidc(#[from] OidcError),
}

// ── config ──────────────────────────────────────────────────────────────────

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// `Authorization: Basic` (the default with a client secret).
    Basic,
    /// `client_id` and `client_secret` in the form body.
    Post,
    /// A public client.
    None,
}

/// Settings of a [`RelyingParty`]. Build with [`RelyingPartyConfig::new`] and the chainable setters.
#[derive(Clone)]
pub struct RelyingPartyConfig {
    /// Your instance's issuer: `https://` + its frontend API host.
    pub issuer: String,
    pub client_id: String,
    /// The client secret (a confidential client). Without a `secret_key` it also authenticates
    /// [`RelyingParty::touch_if_due`] and [`RelyingParty::end_app_session`].
    pub client_secret: Option<String>,
    /// Token-endpoint authentication. Default: `Basic` with a secret, else `None`.
    pub client_auth: Option<ClientAuth>,
    /// The callback URL, registered on the client exactly.
    pub redirect_uri: String,
    /// At least 32 characters: seals the sign-in cookie.
    pub secret: String,
    /// Scopes. Default `openid profile email`.
    pub scope: String,
    /// Where the callback redirect goes when the sign-in carried no return path. Default `/`.
    pub after_sign_in_path: String,
    /// Where Atlas sends the browser after sign-out; registered on the client exactly.
    pub post_logout_redirect_uri: Option<String>,
    /// The instance secret key (`sk_...`, scope `sessions:write`): server-side revoke and keep-alive.
    pub secret_key: Option<String>,
    /// The Backend API origin.
    pub api_url: String,
    /// Flow cookie name. Default `atlas_oidc`.
    pub cookie_name: String,
    /// Sign out with ONE call, `POST /v1/oauth_clients/{id}/logout` (key scopes `oauth_clients:write` and `sessions:write`).
    pub server_sign_out: bool,
    /// Minimum time between two keep-alive calls for one session. Default 5 minutes.
    pub touch_interval_ms: u64,
    /// Query parameters of your sign-in URL passed on to `/oauth2/authorize` (for example `ref`, `utm_source`).
    pub forward_params: Vec<String>,
    /// Clock tolerance for token times, in seconds. Default 60.
    pub clock_tolerance_sec: i64,
}

impl RelyingPartyConfig {
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        RelyingPartyConfig {
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: None,
            client_auth: None,
            redirect_uri: redirect_uri.into(),
            secret: secret.into(),
            scope: "openid profile email".into(),
            after_sign_in_path: "/".into(),
            post_logout_redirect_uri: None,
            secret_key: None,
            api_url: DEFAULT_API_URL.into(),
            cookie_name: OIDC_FLOW_COOKIE.into(),
            server_sign_out: false,
            touch_interval_ms: DEFAULT_TOUCH_INTERVAL_MS,
            forward_params: Vec::new(),
            clock_tolerance_sec: 60,
        }
    }
    pub fn client_secret(mut self, v: impl Into<String>) -> Self {
        self.client_secret = Some(v.into());
        self
    }
    pub fn client_auth(mut self, v: ClientAuth) -> Self {
        self.client_auth = Some(v);
        self
    }
    pub fn scope(mut self, v: impl Into<String>) -> Self {
        self.scope = v.into();
        self
    }
    pub fn after_sign_in_path(mut self, v: impl Into<String>) -> Self {
        self.after_sign_in_path = v.into();
        self
    }
    pub fn post_logout_redirect_uri(mut self, v: impl Into<String>) -> Self {
        self.post_logout_redirect_uri = Some(v.into());
        self
    }
    pub fn secret_key(mut self, v: impl Into<String>) -> Self {
        self.secret_key = Some(v.into());
        self
    }
    pub fn api_url(mut self, v: impl Into<String>) -> Self {
        self.api_url = v.into();
        self
    }
    pub fn cookie_name(mut self, v: impl Into<String>) -> Self {
        self.cookie_name = v.into();
        self
    }
    pub fn server_sign_out(mut self, v: bool) -> Self {
        self.server_sign_out = v;
        self
    }
    pub fn touch_interval_ms(mut self, v: u64) -> Self {
        self.touch_interval_ms = v;
        self
    }
    pub fn forward_params<I: IntoIterator<Item = S>, S: Into<String>>(mut self, v: I) -> Self {
        self.forward_params = v.into_iter().map(Into::into).collect();
        self
    }
    pub fn clock_tolerance_sec(mut self, v: i64) -> Self {
        self.clock_tolerance_sec = v;
        self
    }
}

// ── results ─────────────────────────────────────────────────────────────────

/// A 302: where to send the browser and the `Set-Cookie` values to send with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub location: String,
    pub set_cookies: Vec<String>,
}

/// Who signed in: the ID-token claims an app needs.
#[derive(Debug, Clone, PartialEq)]
pub struct RelyingPartyUser {
    pub sub: String,
    /// The Atlas session id. Keep it on your session: touch, revoke and back-channel logout all name it.
    pub sid: Option<String>,
    pub email: Option<String>,
    /// True only when the ID token says so. Never match accounts on an unverified email.
    pub email_verified: bool,
    pub name: Option<String>,
    /// Your own id for the user, when the token carries one.
    pub external_id: Option<String>,
    /// The organization the sign-in was made in, when there was one.
    pub org_id: Option<String>,
    pub org_role: Option<String>,
    /// When the user last authenticated, epoch seconds. Store it for [`RelyingParty::require_recent_auth`].
    pub auth_time: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingPartyTokens {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// When the access token expires, epoch milliseconds.
    pub expires_at: u64,
}

/// Everything the verified ID token says, plus the organization / SSO context.
#[derive(Debug, Clone, PartialEq)]
pub struct OidcIdentity {
    pub sub: String,
    /// `{issuer}#{sub}`: unique across issuers.
    pub namespaced_sub: String,
    pub return_to: Option<String>,
    pub organization: Option<OidcOrganization>,
    pub organizations: Option<Vec<OidcOrganizationMembership>>,
    pub sso: Option<OidcSsoContext>,
    /// Every verified ID-token claim.
    pub claims: Map<String, Value>,
    /// A `Set-Cookie` value that removes the flow cookie.
    pub clear_cookie: String,
}

/// A finished sign-in.
#[derive(Debug, Clone, PartialEq)]
pub struct CallbackResult {
    pub user: RelyingPartyUser,
    pub tokens: RelyingPartyTokens,
    pub identity: OidcIdentity,
    /// A 302 to the return path (or `after_sign_in_path`) that already clears the flow cookie.
    /// Add your own session cookie to `set_cookies`.
    pub redirect: Redirect,
}

/// Per-call overrides for [`RelyingParty::start`]; they win over the sign-in URL's query.
#[derive(Debug, Clone, Default)]
pub struct StartOverrides {
    pub prompt: Option<String>,
    pub login_hint: Option<String>,
    pub ui_locales: Option<String>,
    pub max_age: Option<u64>,
    pub organization: Option<String>,
    pub return_to: Option<String>,
    pub expected_sub: Option<String>,
    pub scope: Option<String>,
    pub extra_params: Vec<(String, String)>,
}

/// Why a session is no longer live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndedReason {
    Revoked,
    IdleExpired,
    Expired,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchResult {
    /// Touched less than `touch_interval_ms` ago: nothing sent. Keep your `last_touched_at`.
    Skipped { last_touched_at: u64 },
    /// Atlas slid the idle window. Store `last_touched_at`.
    Touched { last_touched_at: u64, idle_expires_at: Option<String> },
    /// The Atlas session has ended. End your own session too.
    Ended { reason: EndedReason },
}

#[derive(Debug, Clone, Default)]
pub struct SignOutOptions {
    /// The ID token from sign-in: lets Atlas end the session without asking.
    pub id_token: Option<String>,
    /// The Atlas session id. With a `secret_key` it is revoked server-side before the redirect.
    pub sid: Option<String>,
    /// Overrides the configured `post_logout_redirect_uri`.
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    /// `Set-Cookie` values to send on the redirect, for example the one that clears your session cookie.
    pub set_cookies: Vec<String>,
}

// ── the relying party ───────────────────────────────────────────────────────

#[derive(Clone)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
}

struct TransportJwks(Arc<dyn HttpTransport>);

impl JwksSource for TransportJwks {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
        Box::pin(async move {
            let resp = self.0.send(HttpRequest::new(HttpMethod::Get, url).header("accept", "application/json")).await?;
            if !(200..300).contains(&resp.status) {
                return Err(TransportError::new(format!("JWKS fetch failed ({})", resp.status)));
            }
            serde_json::from_str::<Jwks>(&resp.body).map_err(|e| TransportError::new(format!("JWKS is malformed: {e}")))
        })
    }
}

/// The relying party. Create it once at startup and share it (it is `Send + Sync`).
pub struct RelyingParty {
    cfg: RelyingPartyConfig,
    transport: Arc<dyn HttpTransport>,
    clock: Clock,
    flow_key: [u8; 32],
    discovery: Mutex<Option<(Discovery, u64)>>,
    jwks: Mutex<HashMap<String, Arc<JwksCache>>>,
}

#[derive(Serialize, Deserialize)]
struct FlowPayload {
    s: String,
    n: String,
    v: String,
    r: String,
    i: String,
    c: String,
    t: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    m: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    u: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x: Option<String>,
}

fn strip_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// A plain same-site path: one leading `/`, no scheme or authority, no backslash or control characters.
pub fn is_safe_return_to(value: &str) -> bool {
    let mut chars = value.chars();
    if chars.next() != Some('/') {
        return false;
    }
    match chars.clone().next() {
        Some('/') | Some('\\') => return false,
        _ => {}
    }
    !value.chars().any(|c| c == '\\' || (c as u32) < 0x20 || c as u32 == 0x7f)
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (*a.get(i).unwrap_or(&0) ^ *b.get(i).unwrap_or(&0)) as usize;
    }
    diff == 0
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
}

fn is_secure_url(v: &str) -> bool {
    Url::parse(v).map(|u| u.scheme() == "https" || (u.scheme() == "http" && u.host_str().is_some_and(is_loopback))).unwrap_or(false)
}

fn parse_redirect_uri(v: &str) -> Result<Url, ConfigError> {
    let u = Url::parse(v).map_err(|_| ConfigError::new("rp: `redirect_uri` must be an absolute URL."))?;
    if u.scheme() != "https" && !(u.scheme() == "http" && u.host_str().is_some_and(is_loopback)) {
        return Err(ConfigError::new("rp: `redirect_uri` must be https (http is accepted only for localhost)."));
    }
    Ok(u)
}

fn form_encode(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    let q = q.split('#').next().unwrap_or("");
    let q = q.split_once('?').map(|(_, r)| r).unwrap_or(q);
    url::form_urlencoded::parse(q.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
}

fn first<'a>(q: &'a [(String, String)], key: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn serialize_cookie(name: &str, value: &str, path: &str, max_age: i64, secure: bool) -> String {
    let mut parts = vec![format!("{name}={value}"), format!("Path={path}"), format!("Max-Age={max_age}"), "HttpOnly".into(), "SameSite=Lax".into()];
    if max_age == 0 {
        parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT".into());
    }
    // Secure except on a plain-http local callback, where the browser would drop it.
    if secure {
        parts.push("Secure".into());
    }
    parts.join("; ")
}

fn read_cookie<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    let header = header?.trim();
    if header.starts_with(SEALED_PREFIX) {
        return Some(header);
    }
    header.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim() == name && !v.trim().is_empty()).then(|| v.trim())
    })
}

fn redirect(location: String, cookies: Vec<String>) -> Redirect {
    Redirect { location, set_cookies: cookies }
}

fn errors_of(body: &str) -> (String, String) {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let first = v.get("errors").and_then(|e| e.get(0));
    let code = first.and_then(|e| e.get("code")).and_then(Value::as_str).or_else(|| v.get("error").and_then(Value::as_str)).unwrap_or("request_failed");
    let message = first
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .or_else(|| v.get("error_description").and_then(Value::as_str))
        .unwrap_or("The request failed.");
    (code.to_string(), message.to_string())
}

impl RelyingParty {
    /// Build over the default reqwest transport.
    #[cfg(feature = "reqwest-transport")]
    pub fn new(cfg: RelyingPartyConfig) -> Result<Self, ConfigError> {
        Self::with_transport(cfg, Arc::new(crate::transport::ReqwestTransport::new()))
    }

    /// Build over a caller-supplied transport (a mock in tests, or another HTTP client).
    pub fn with_transport(cfg: RelyingPartyConfig, transport: Arc<dyn HttpTransport>) -> Result<Self, ConfigError> {
        if cfg.secret.chars().count() < 32 {
            return Err(ConfigError::new("rp: `secret` (at least 32 characters) is required to seal the sign-in cookie."));
        }
        if cfg.issuer.trim().is_empty() || cfg.client_id.trim().is_empty() {
            return Err(ConfigError::new("rp: `issuer` and `client_id` are required."));
        }
        parse_redirect_uri(&cfg.redirect_uri)?;
        if !is_safe_return_to(&cfg.after_sign_in_path) {
            return Err(ConfigError::new("rp: `after_sign_in_path` must be a path starting with a single `/`."));
        }
        for name in &cfg.forward_params {
            let plain = !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
            if !plain || NOT_FORWARDABLE.contains(&name.as_str()) {
                return Err(ConfigError::new(format!("rp: `forward_params` cannot forward {name:?}: use a plain parameter name the helper does not set itself.")));
            }
        }
        let mut flow_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"atlas-oidc-flow-cookie"), cfg.secret.as_bytes())
            .expand(b"v1", &mut flow_key)
            .map_err(|_| ConfigError::new("rp: could not derive the flow-cookie key."))?;
        Ok(RelyingParty { cfg, transport, clock: system_clock(), flow_key, discovery: Mutex::new(None), jwks: Mutex::new(HashMap::new()) })
    }

    /// Inject a clock (epoch milliseconds), for tests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The configuration this relying party was built with.
    pub fn config(&self) -> &RelyingPartyConfig {
        &self.cfg
    }

    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    fn issuer(&self) -> &str {
        strip_slash(&self.cfg.issuer)
    }

    fn cookie_path_secure(&self) -> (String, bool) {
        // Validated in the constructor.
        let u = Url::parse(&self.cfg.redirect_uri).expect("redirect_uri validated");
        (u.path().to_string(), u.scheme() == "https")
    }

    /// A `Set-Cookie` value that removes the flow cookie for this callback path.
    pub fn clear_cookie(&self) -> String {
        let (path, secure) = self.cookie_path_secure();
        serialize_cookie(&self.cfg.cookie_name, "", &path, 0, secure)
    }

    // ── discovery and keys ─────────────────────────────────────────────────

    async fn discover(&self) -> Result<Discovery, OidcError> {
        let now = self.now_ms();
        if let Some((d, at)) = self.discovery.lock().unwrap().as_ref() {
            if now.saturating_sub(*at) < DISCOVERY_TTL_MS {
                return Ok(d.clone());
            }
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer());
        let fail = |why: String| OidcError::new(OidcErrorCode::DiscoveryFailed, format!("OIDC discovery at {url} failed: {why}."));
        let resp = self
            .transport
            .send(HttpRequest::new(HttpMethod::Get, url.clone()).header("accept", "application/json"))
            .await
            .map_err(|e| fail(e.0))?;
        if !(200..300).contains(&resp.status) {
            return Err(fail(format!("HTTP {}", resp.status)));
        }
        let doc: Value = serde_json::from_str(&resp.body).map_err(|_| fail("the response is not JSON".into()))?;
        // OIDC Discovery §4.3: the document must be for the issuer we asked about.
        let doc_issuer = doc.get("issuer").and_then(Value::as_str).unwrap_or("");
        if strip_slash(doc_issuer) != self.issuer() {
            return Err(fail(format!("its issuer ({doc_issuer}) is not {}", self.issuer())));
        }
        let field = |name: &str| -> Result<String, OidcError> {
            let v = doc.get(name).and_then(Value::as_str).ok_or_else(|| fail(format!("it has no {name}")))?;
            if !is_secure_url(v) {
                return Err(fail(format!("its {name} is not an https URL")));
            }
            Ok(v.to_string())
        };
        let d = Discovery {
            issuer: doc_issuer.to_string(),
            authorization_endpoint: field("authorization_endpoint")?,
            token_endpoint: field("token_endpoint")?,
            jwks_uri: field("jwks_uri")?,
            end_session_endpoint: doc.get("end_session_endpoint").and_then(Value::as_str).map(str::to_string),
        };
        *self.discovery.lock().unwrap() = Some((d.clone(), now));
        Ok(d)
    }

    fn jwks_cache(&self, uri: &str) -> Arc<JwksCache> {
        let mut map = self.jwks.lock().unwrap();
        map.entry(uri.to_string())
            .or_insert_with(|| {
                Arc::new(JwksCache::new(
                    Some(uri.to_string()),
                    None,
                    Some(Arc::new(TransportJwks(self.transport.clone()))),
                    Some(self.clock.clone()),
                    None,
                    None,
                ))
            })
            .clone()
    }

    // ── the flow cookie ────────────────────────────────────────────────────

    fn seal(&self, payload: &FlowPayload) -> String {
        let json = serde_json::to_vec(payload).expect("flow payload serializes");
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&self.flow_key).into());
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), json.as_ref()).expect("encryption does not fail");
        format!("{SEALED_PREFIX}{}.{}", URL_SAFE_NO_PAD.encode(nonce), URL_SAFE_NO_PAD.encode(ct))
    }

    fn open(&self, value: &str) -> Option<FlowPayload> {
        let rest = value.strip_prefix(SEALED_PREFIX)?;
        let (n, c) = rest.split_once('.')?;
        let nonce = URL_SAFE_NO_PAD.decode(n).ok().filter(|b| b.len() == 24)?;
        let ct = URL_SAFE_NO_PAD.decode(c).ok()?;
        let cipher = XChaCha20Poly1305::new((&self.flow_key).into());
        let pt = cipher.decrypt(XNonce::from_slice(&nonce), ct.as_ref()).ok()?;
        serde_json::from_slice(&pt).ok()
    }

    // ── start ──────────────────────────────────────────────────────────────

    /// Begin sign-in: a 302 to `/oauth2/authorize` with the flow cookie set. `query` is the raw query
    /// string of your sign-in URL: `prompt`, `login_hint`, `ui_locales`, `max_age`, `organization` and
    /// `return_to` on it are passed through (a bad `return_to` is dropped), as are the configured
    /// `forward_params`; `overrides` win.
    pub async fn start(&self, query: &str, overrides: StartOverrides) -> Result<Redirect, OidcError> {
        let q = parse_query(query);
        let pick = |name: &str| first(&q, name).filter(|v| !v.is_empty()).map(str::to_string);
        let mut o = overrides;
        o.prompt = o.prompt.or_else(|| pick("prompt"));
        o.login_hint = o.login_hint.or_else(|| pick("login_hint"));
        o.ui_locales = o.ui_locales.or_else(|| pick("ui_locales"));
        o.organization = o.organization.or_else(|| pick("organization"));
        o.return_to = o.return_to.or_else(|| pick("return_to").filter(|v| is_safe_return_to(v)));
        if o.max_age.is_none() {
            o.max_age = first(&q, "max_age").filter(|v| !v.is_empty() && v.len() <= 9 && v.bytes().all(|b| b.is_ascii_digit())).and_then(|v| v.parse().ok());
        }
        let mut forwarded: Vec<(String, String)> = Vec::new();
        for name in &self.cfg.forward_params {
            if let Some(v) = first(&q, name) {
                if !v.is_empty() && v.len() <= MAX_FORWARDED_VALUE {
                    forwarded.push((name.clone(), v.to_string()));
                }
            }
        }
        forwarded.extend(std::mem::take(&mut o.extra_params));
        o.extra_params = forwarded;
        self.start_flow(o).await
    }

    async fn start_flow(&self, o: StartOverrides) -> Result<Redirect, OidcError> {
        let d = self.discover().await?;
        if let Some(rt) = &o.return_to {
            if !is_safe_return_to(rt) {
                return Err(OidcError::new(OidcErrorCode::InvalidRequest, "`return_to` must be a path on this site, starting with a single `/`."));
            }
        }
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let scope = normalise_scope(o.scope.as_deref().unwrap_or(&self.cfg.scope));

        let mut url = Url::parse(&d.authorization_endpoint).map_err(|_| OidcError::new(OidcErrorCode::DiscoveryFailed, "The authorization endpoint is not a URL."))?;
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in &o.extra_params {
                if !matches!(k.as_str(), "response_type" | "client_id" | "redirect_uri" | "state" | "nonce" | "code_challenge" | "code_challenge_method") {
                    qp.append_pair(k, v);
                }
            }
            qp.append_pair("response_type", "code");
            qp.append_pair("client_id", &self.cfg.client_id);
            qp.append_pair("redirect_uri", &self.cfg.redirect_uri);
            qp.append_pair("scope", &scope);
            qp.append_pair("state", &state);
            qp.append_pair("nonce", &nonce);
            qp.append_pair("code_challenge", &challenge);
            qp.append_pair("code_challenge_method", "S256");
            if let Some(v) = &o.prompt {
                qp.append_pair("prompt", v);
            }
            if let Some(v) = &o.login_hint {
                qp.append_pair("login_hint", v);
            }
            if let Some(v) = &o.organization {
                qp.append_pair("organization", v);
            }
            if let Some(v) = &o.ui_locales {
                qp.append_pair("ui_locales", v);
            }
            if let Some(v) = o.max_age {
                qp.append_pair("max_age", &v.to_string());
            }
        }
        let payload = FlowPayload {
            s: state,
            n: nonce,
            v: verifier,
            r: self.cfg.redirect_uri.clone(),
            i: self.issuer().to_string(),
            c: self.cfg.client_id.clone(),
            t: (self.now_ms() / 1000) as i64,
            m: o.max_age,
            u: o.return_to,
            x: o.expected_sub.filter(|s| !s.is_empty()),
        };
        let (path, secure) = self.cookie_path_secure();
        let cookie = serialize_cookie(&self.cfg.cookie_name, &self.seal(&payload), &path, OIDC_FLOW_MAX_AGE_SECONDS, secure);
        Ok(redirect(url.to_string(), vec![cookie]))
    }

    /// Step-up: `None` when `auth_time` (epoch seconds) is within `max_age_seconds`; otherwise a redirect
    /// that asks the SAME user (`sub`) to authenticate again (`max_age`, plus `prompt=login` for 0). The
    /// callback then refuses another user or an old `auth_time`; store the new `user.auth_time`. `0` asks
    /// unless the user authenticated in the last [`CONFIRM_NOW_WINDOW_SECONDS`], so the request that comes
    /// back from the confirmation goes through. `path_and_query` is where to return to.
    pub async fn require_recent_auth(
        &self,
        path_and_query: &str,
        max_age_seconds: u64,
        sub: &str,
        auth_time: Option<i64>,
    ) -> Result<Option<Redirect>, OidcError> {
        if sub.is_empty() {
            return Err(OidcError::new(OidcErrorCode::InvalidRequest, "`sub` is required."));
        }
        let allowed = if max_age_seconds == 0 { CONFIRM_NOW_WINDOW_SECONDS } else { max_age_seconds as i64 };
        if let Some(at) = auth_time {
            if (self.now_ms() / 1000) as i64 - at <= allowed {
                return Ok(None);
            }
        }
        let o = StartOverrides {
            max_age: Some(max_age_seconds),
            expected_sub: Some(sub.to_string()),
            prompt: (max_age_seconds == 0).then(|| "login".to_string()),
            return_to: is_safe_return_to(path_and_query).then(|| path_and_query.to_string()),
            ..Default::default()
        };
        self.start_flow(o).await.map(Some)
    }

    // ── callback ───────────────────────────────────────────────────────────

    /// Finish sign-in. `query` is the callback URL's raw query string and `cookie` its `Cookie` header.
    /// Every failure is an [`OidcError`] whose `clear_cookie` you should send.
    pub async fn callback(&self, query: &str, cookie: Option<&str>) -> Result<CallbackResult, OidcError> {
        let clear = self.clear_cookie();
        match self.run_callback(query, cookie, &clear).await {
            Ok(r) => Ok(r),
            Err(mut e) => {
                e.clear_cookie = Some(clear);
                Err(e)
            }
        }
    }

    async fn run_callback(&self, query: &str, cookie: Option<&str>, clear: &str) -> Result<CallbackResult, OidcError> {
        let q = parse_query(query);
        let issuer = self.issuer().to_string();
        // The flow cookie first: without it nothing in the query can be trusted.
        let raw = read_cookie(cookie, &self.cfg.cookie_name).ok_or_else(|| OidcError::new(OidcErrorCode::StateMismatch, "The sign-in flow cookie is missing or expired. Start sign-in again."))?;
        let flow = self.open(raw).ok_or_else(|| OidcError::new(OidcErrorCode::StateMismatch, "The sign-in flow cookie could not be read. Start sign-in again."))?;

        match first(&q, "state") {
            Some(s) if ct_eq(s, &flow.s) => {}
            _ => return Err(OidcError::new(OidcErrorCode::StateMismatch, "The `state` returned to the callback does not match this browser's sign-in.")),
        }
        let now_sec = (self.now_ms() / 1000) as i64;
        if now_sec - flow.t > OIDC_FLOW_MAX_AGE_SECONDS {
            return Err(OidcError::new(OidcErrorCode::StateMismatch, "This sign-in took longer than 10 minutes. Start sign-in again."));
        }
        if flow.i != issuer || flow.c != self.cfg.client_id || flow.r != self.cfg.redirect_uri {
            return Err(OidcError::new(OidcErrorCode::StateMismatch, "This sign-in was started for a different issuer, client or redirect URI."));
        }
        // RFC 9207: an authorization server that names itself must be the one we sent the user to.
        if let Some(iss) = first(&q, "iss") {
            if strip_slash(iss) != issuer {
                return Err(OidcError::new(OidcErrorCode::IssuerMismatch, format!("The callback came from {iss}, not {issuer}.")));
            }
        }
        if let Some(oauth_error) = first(&q, "error").filter(|v| !v.is_empty()) {
            let description = first(&q, "error_description").map(str::to_string);
            let mut e = OidcError::new(
                OidcErrorCode::AccessDenied,
                format!("Sign-in did not complete: {oauth_error}{}.", description.as_ref().map(|d| format!(" ({d})")).unwrap_or_default()),
            );
            e.oauth_error = Some(oauth_error.to_string());
            e.description = description;
            return Err(e);
        }
        let code = first(&q, "code").filter(|c| !c.is_empty()).ok_or_else(|| OidcError::new(OidcErrorCode::InvalidRequest, "The callback has no `code` parameter."))?;

        let d = self.discover().await?;
        let tokens = self.exchange_code(&d, code, &flow.v).await?;
        let claims = self.verify_id_token(&tokens.id_token, &d, &flow.n, Some(&tokens.access_token)).await?;

        let sub = claims.get("sub").and_then(Value::as_str).unwrap_or_default().to_string();
        let auth_time = claims.get("auth_time").and_then(Value::as_f64).filter(|f| f.is_finite()).map(|f| f as i64);
        if let Some(max_age) = flow.m {
            // OIDC Core §3.1.2.1: with max_age the client must check auth_time itself.
            let tol = self.cfg.clock_tolerance_sec;
            match auth_time {
                Some(at) if now_sec - at <= max_age as i64 + tol => {}
                _ => {
                    return Err(OidcError::new(
                        OidcErrorCode::ReauthenticationRequired,
                        format!("The sign-in is older than the {max_age} seconds this request allowed (max_age). Ask the user to sign in again."),
                    ))
                }
            }
        }
        if let Some(x) = &flow.x {
            if !ct_eq(&sub, x) {
                return Err(OidcError::new(OidcErrorCode::SubjectMismatch, "A different user signed in than the one asked to confirm it is them."));
            }
        }
        let expires_in = tokens.expires_in.filter(|n| *n > 0.0);
        let expires_at = match expires_in {
            Some(n) => self.now_ms() + (n * 1000.0) as u64,
            None => claims.get("exp").and_then(Value::as_i64).unwrap_or(0).max(0) as u64 * 1000,
        };
        let s = |k: &str| claims.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
        let organization = oidc_organization_of(&claims);
        let user = RelyingPartyUser {
            sub: sub.clone(),
            sid: s("sid"),
            email: claims.get("email").and_then(Value::as_str).map(str::to_string),
            email_verified: claims.get("email_verified").and_then(Value::as_bool) == Some(true),
            name: claims.get("name").and_then(Value::as_str).map(str::to_string),
            external_id: s("external_id"),
            org_id: organization.as_ref().map(|o| o.id.clone()),
            org_role: organization.as_ref().map(|o| o.role.clone()),
            auth_time,
        };
        let return_to = flow.u.filter(|u| is_safe_return_to(u));
        let identity = OidcIdentity {
            sub: sub.clone(),
            namespaced_sub: format!("{issuer}#{sub}"),
            return_to: return_to.clone(),
            organization,
            organizations: oidc_organizations_of(&claims),
            sso: oidc_sso_of(&claims),
            claims,
            clear_cookie: clear.to_string(),
        };
        let toks = RelyingPartyTokens {
            id_token: tokens.id_token,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at,
        };
        let location = return_to.unwrap_or_else(|| self.cfg.after_sign_in_path.clone());
        Ok(CallbackResult { user, tokens: toks, identity, redirect: redirect(location, vec![clear.to_string()]) })
    }

    fn client_auth(&self) -> ClientAuth {
        self.cfg.client_auth.unwrap_or(if self.cfg.client_secret.is_some() { ClientAuth::Basic } else { ClientAuth::None })
    }

    async fn exchange_code(&self, d: &Discovery, code: &str, verifier: &str) -> Result<TokenResponse, OidcError> {
        let method = self.client_auth();
        if method != ClientAuth::None && self.cfg.client_secret.is_none() {
            return Err(OidcError::new(OidcErrorCode::TokenExchangeFailed, format!("client auth {method:?} needs `client_secret`.")));
        }
        let mut pairs = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", self.cfg.redirect_uri.as_str()), ("code_verifier", verifier)];
        let mut req = HttpRequest::new(HttpMethod::Post, d.token_endpoint.clone()).header("content-type", "application/x-www-form-urlencoded").header("accept", "application/json");
        if method == ClientAuth::Basic {
            // RFC 6749 §2.3.1: both halves are form-encoded before Basic encoding.
            let cred = format!("{}:{}", form_encode(&self.cfg.client_id), form_encode(self.cfg.client_secret.as_deref().unwrap_or("")));
            req = req.header("authorization", format!("Basic {}", STANDARD.encode(cred)));
        } else {
            pairs.push(("client_id", self.cfg.client_id.as_str()));
            if method == ClientAuth::Post {
                pairs.push(("client_secret", self.cfg.client_secret.as_deref().unwrap_or("")));
            }
        }
        let resp = self
            .transport
            .send(req.body(form_body(&pairs)))
            .await
            .map_err(|e| OidcError::new(OidcErrorCode::TokenExchangeFailed, format!("The token endpoint could not be reached: {}.", e.0)))?;
        let json: Option<Value> = serde_json::from_str(&resp.body).ok();
        if !(200..300).contains(&resp.status) {
            let oauth_error = json.as_ref().and_then(|j| j.get("error")).and_then(Value::as_str).map(str::to_string);
            let description = json.as_ref().and_then(|j| j.get("error_description")).and_then(Value::as_str).map(str::to_string);
            let mut e = OidcError::new(
                OidcErrorCode::TokenExchangeFailed,
                format!(
                    "The token endpoint answered {}{}{}.",
                    resp.status,
                    oauth_error.as_ref().map(|o| format!(" {o}")).unwrap_or_default(),
                    description.as_ref().map(|d| format!(": {d}")).unwrap_or_default()
                ),
            );
            e.oauth_error = oauth_error;
            e.description = description;
            e.status = Some(resp.status);
            return Err(e);
        }
        let j = json.unwrap_or(Value::Null);
        let (Some(id_token), Some(access_token)) = (j.get("id_token").and_then(Value::as_str), j.get("access_token").and_then(Value::as_str)) else {
            let mut e = OidcError::new(OidcErrorCode::TokenExchangeFailed, "The token response has no `id_token`. Request the `openid` scope.");
            e.status = Some(resp.status);
            return Err(e);
        };
        Ok(TokenResponse {
            id_token: id_token.to_string(),
            access_token: access_token.to_string(),
            refresh_token: j.get("refresh_token").and_then(Value::as_str).map(str::to_string),
            expires_in: j.get("expires_in").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))),
        })
    }

    /// Verify an ID token on its own (for an app that does its own code exchange). The same checks as
    /// [`RelyingParty::callback`]: algorithm pinned to RS256, ES256, ES384, PS256 and EdDSA, `iss`, `aud`/`azp`, `exp`/`iat`,
    /// `nonce` (required) and, when `access_token` is given and the token has `at_hash`, `at_hash`.
    pub async fn verify_id_token_for(&self, id_token: &str, nonce: &str, access_token: Option<&str>) -> Result<Map<String, Value>, OidcError> {
        let d = self.discover().await?;
        self.verify_id_token(id_token, &d, nonce, access_token).await
    }

    async fn verify_id_token(&self, id_token: &str, d: &Discovery, nonce: &str, access_token: Option<&str>) -> Result<Map<String, Value>, OidcError> {
        let invalid = |why: String| OidcError::new(OidcErrorCode::InvalidToken, format!("The ID token was refused: {why}."));
        let header = decode_header(id_token).map_err(|_| invalid("it is not a JWT".into()))?;
        // Pinned before any key lookup, so `none` and HS* never get near a key.
        if !SIGNING_ALGS.contains(&header.alg) {
            return Err(invalid(format!("its algorithm is {:?}, not one of RS256, ES256, ES384, PS256 or EdDSA", header.alg)));
        }
        let keys = self.jwks_cache(&d.jwks_uri).get(header.kid.as_deref()).await;
        let keys = match keys {
            Some(k) if !k.keys.is_empty() => k,
            _ => return Err(OidcError::new(OidcErrorCode::DiscoveryFailed, format!("The issuer's signing keys could not be fetched from {}.", d.jwks_uri))),
        };
        let tol = self.cfg.clock_tolerance_sec.max(0);
        let mut v = Validation::new(header.alg);
        v.set_audience(&[self.cfg.client_id.as_str()]);
        v.set_issuer(&[d.issuer.as_str()]);
        v.set_required_spec_claims(&["sub", "iat", "exp", "iss", "aud"]);
        // Times are checked below against the injected clock.
        v.validate_exp = false;
        v.validate_nbf = false;
        let claims: Map<String, Value> = decode_with_set(id_token, &keys, header.kid.as_deref(), header.alg, &v)
            .ok_or_else(|| invalid("its signature, issuer or audience does not verify".into()))?;

        let now_sec = (self.now_ms() / 1000) as i64;
        let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
        if exp + tol <= now_sec {
            return Err(invalid("it has expired".into()));
        }
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
            if nbf > now_sec + tol {
                return Err(invalid("it is not valid yet".into()));
            }
        }
        // OIDC Core §3.1.3.7 (4)-(5): several audiences need an azp, and any azp must be us.
        let azp = claims.get("azp");
        if claims.get("aud").and_then(Value::as_array).is_some_and(|a| a.len() > 1) && azp.is_none() {
            return Err(invalid("it has several audiences and no azp".into()));
        }
        if let Some(azp) = azp {
            if azp.as_str() != Some(self.cfg.client_id.as_str()) {
                return Err(invalid(format!("its azp is {azp}, not this client")));
            }
        }
        match claims.get("nonce").and_then(Value::as_str) {
            Some(n) if ct_eq(n, nonce) => {}
            _ => return Err(invalid("its nonce does not match this sign-in".into())),
        }
        if claims.get("iat").and_then(Value::as_i64).is_some_and(|iat| iat > now_sec + tol) {
            return Err(invalid("it was issued in the future".into()));
        }
        if let (Some(at), Some(hash)) = (access_token, claims.get("at_hash").and_then(Value::as_str)) {
            let digest = Sha256::digest(at.as_bytes());
            if !ct_eq(&URL_SAFE_NO_PAD.encode(&digest[..16]), hash) {
                return Err(invalid("its at_hash does not match the access token".into()));
            }
        }
        Ok(claims)
    }

    // ── session calls ──────────────────────────────────────────────────────

    async fn backend_post(&self, path: &str, key: &str, body: Option<String>) -> Result<HttpResponse, RpError> {
        let mut req = HttpRequest::new(HttpMethod::Post, format!("{}{path}", strip_slash(&self.cfg.api_url)))
            .header("authorization", format!("Bearer {key}"))
            .header("accept", "application/json");
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b);
        }
        Ok(self.transport.send(req).await?)
    }

    fn session_key(&self, caller: &str, sid: &str) -> Result<&str, RpError> {
        if sid.is_empty() {
            return Err(RpError::Config("A session id (`sid`) is required.".into()));
        }
        self.cfg.secret_key.as_deref().ok_or_else(|| RpError::Config(format!("{caller}: `secret_key` is not configured.")))
    }

    /// The app's own sign-in, authenticated like the token endpoint (`/oauth2/session/touch` or `/end`).
    async fn app_session_call(&self, sid: &str, action: &str, caller: &str) -> Result<HttpResponse, RpError> {
        let method = self.client_auth();
        let Some(secret) = self.cfg.client_secret.as_deref().filter(|_| method != ClientAuth::None) else {
            return Err(RpError::Config(format!("{caller}: configure `client_secret` (the app's client credentials){}; a public client cannot call it.", if action == "touch" { " or `secret_key`" } else { "" })));
        };
        if sid.is_empty() {
            return Err(RpError::Config("A session id (`sid`) is required.".into()));
        }
        let mut req = HttpRequest::new(HttpMethod::Post, format!("{}/oauth2/session/{action}", self.issuer())).header("accept", "application/json");
        let mut pairs = vec![("sid", sid)];
        if method == ClientAuth::Basic {
            let cred = format!("{}:{}", form_encode(&self.cfg.client_id), form_encode(secret));
            req = req.header("authorization", format!("Basic {}", STANDARD.encode(cred)));
        } else {
            pairs.push(("client_id", self.cfg.client_id.as_str()));
            pairs.push(("client_secret", secret));
        }
        req = req.header("content-type", "application/x-www-form-urlencoded").body(form_body(&pairs));
        Ok(self.transport.send(req).await?)
    }

    fn api_failure(resp: &HttpResponse) -> RpError {
        let (code, message) = errors_of(&resp.body);
        RpError::Api { status: resp.status, code, message }
    }

    /// Keep the Atlas session alive while the user is active in your app, at most once per
    /// `touch_interval_ms` per session. Call it on each authenticated request with the `sid` and the
    /// time you last touched (`None` at first). With a `secret_key` it touches the Atlas session
    /// (`/v1/sessions/{id}/touch`); without one but with a `client_secret` it touches this app's own
    /// sign-in, where a sid with no live sign-in of this app is `Ended { NotFound }`.
    pub async fn touch_if_due(&self, sid: &str, last_touched_at: Option<u64>) -> Result<TouchResult, RpError> {
        let now = self.now_ms();
        if let Some(last) = last_touched_at {
            if now >= last && now - last < self.cfg.touch_interval_ms {
                return Ok(TouchResult::Skipped { last_touched_at: last });
            }
        }
        if self.cfg.secret_key.is_none() {
            let resp = self.app_session_call(sid, "touch", "touch_if_due").await?;
            let body: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
            if (200..300).contains(&resp.status) {
                let idle = match body.get("idle_expires_at") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Number(n)) => n.as_i64().map(|ms| {
                        // RFC 3339 without a date crate: seconds precision is enough for a window.
                        epoch_ms_to_rfc3339(ms)
                    }),
                    _ => None,
                };
                return Ok(TouchResult::Touched { last_touched_at: now, idle_expires_at: idle });
            }
            if resp.status == 404 && body.get("error").and_then(Value::as_str) == Some("session_not_found") {
                return Ok(TouchResult::Ended { reason: EndedReason::NotFound });
            }
            return Err(Self::api_failure(&resp));
        }
        let key = self.session_key("touch_if_due", sid)?;
        let resp = self.backend_post(&format!("/v1/sessions/{}/touch", encode_segment(sid)), key, None).await?;
        if (200..300).contains(&resp.status) {
            let body: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
            return Ok(TouchResult::Touched { last_touched_at: now, idle_expires_at: body.get("idle_expires_at").and_then(Value::as_str).map(str::to_string) });
        }
        if resp.status == 404 {
            return Ok(TouchResult::Ended { reason: EndedReason::NotFound });
        }
        if resp.status == 409 {
            let (code, _) = errors_of(&resp.body);
            let reason = match code.as_str() {
                "SESSION_REVOKED" => EndedReason::Revoked,
                "SESSION_IDLE_EXPIRED" => EndedReason::IdleExpired,
                _ => EndedReason::Expired,
            };
            return Ok(TouchResult::Ended { reason });
        }
        // A key, scope or availability problem is not "signed out": say so loudly.
        Err(Self::api_failure(&resp))
    }

    /// End the Atlas session server-side (`POST /v1/sessions/{id}/revoke`); every app signed in through
    /// it gets a back-channel logout. `Ok(true)` when revoked (an already-ended session is too),
    /// `Ok(false)` when this instance has no such session.
    pub async fn revoke_session(&self, sid: &str) -> Result<bool, RpError> {
        let key = self.session_key("revoke_session", sid)?;
        let resp = self.backend_post(&format!("/v1/sessions/{}/revoke", encode_segment(sid)), key, None).await?;
        if (200..300).contains(&resp.status) {
            return Ok(true);
        }
        if resp.status == 404 {
            return Ok(false);
        }
        Err(Self::api_failure(&resp))
    }

    /// End THIS app's sign-in under `sid` with the app's client credentials (`POST {issuer}/oauth2/session/end`):
    /// its refresh grants are revoked and Atlas sends the app a back-channel logout. The Atlas session and
    /// other apps are untouched. `Ok(false)`: no live sign-in of this app has that sid.
    pub async fn end_app_session(&self, sid: &str) -> Result<bool, RpError> {
        let resp = self.app_session_call(sid, "end", "end_app_session").await?;
        if (200..300).contains(&resp.status) {
            return Ok(true);
        }
        let body: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
        if resp.status == 404 && body.get("error").and_then(Value::as_str) == Some("session_not_found") {
            return Ok(false);
        }
        Err(Self::api_failure(&resp))
    }

    /// Sign out. With a `sid` and a `secret_key`, revokes the Atlas session server-side first, then
    /// redirects the browser to `/oauth2/logout`. With `server_sign_out`, one call ends this app's grants
    /// and the Atlas session and the redirect goes straight to the post-logout URI. End your own session
    /// (clear your cookie on this response) as well: put that cookie in `set_cookies`.
    pub async fn sign_out(&self, o: SignOutOptions) -> Result<Redirect, RpError> {
        let target = o.post_logout_redirect_uri.clone().or_else(|| self.cfg.post_logout_redirect_uri.clone());
        if let (true, Some(sid), Some(key)) = (self.cfg.server_sign_out, o.sid.as_deref().filter(|s| !s.is_empty()), self.cfg.secret_key.as_deref()) {
            let path = format!("/v1/oauth_clients/{}/logout", encode_segment(&self.cfg.client_id));
            let resp = self.backend_post(&path, key, Some(serde_json::json!({ "sid": sid }).to_string())).await?;
            // 404: this instance has no such session any more, so there is nothing left to end.
            if !(200..300).contains(&resp.status) && resp.status != 404 {
                return Err(Self::api_failure(&resp));
            }
            let base = Url::parse("http://relative.invalid").expect("static url");
            let mut url = base.join(target.as_deref().unwrap_or("/")).map_err(|_| RpError::Config("`post_logout_redirect_uri` is not a URL.".into()))?;
            if let Some(state) = &o.state {
                url.query_pairs_mut().append_pair("state", state);
            }
            let location = if url.host_str() == Some("relative.invalid") {
                format!("{}{}", url.path(), url.query().map(|q| format!("?{q}")).unwrap_or_default())
            } else {
                url.to_string()
            };
            return Ok(redirect(location, o.set_cookies));
        }
        if let (Some(sid), Some(_)) = (o.sid.as_deref().filter(|s| !s.is_empty()), self.cfg.secret_key.as_deref()) {
            self.revoke_session(sid).await?;
        }
        let d = self.discover().await?;
        let end = d.end_session_endpoint.ok_or_else(|| OidcError::new(OidcErrorCode::DiscoveryFailed, "The issuer does not advertise an end_session_endpoint."))?;
        let mut url = Url::parse(&end).map_err(|_| OidcError::new(OidcErrorCode::DiscoveryFailed, "The end_session_endpoint is not a URL."))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("client_id", &self.cfg.client_id);
            if let Some(h) = &o.id_token {
                qp.append_pair("id_token_hint", h);
            }
            if let Some(t) = &target {
                qp.append_pair("post_logout_redirect_uri", t);
            }
            if let Some(s) = &o.state {
                qp.append_pair("state", s);
            }
        }
        Ok(redirect(url.to_string(), o.set_cookies))
    }
}

struct TokenResponse {
    id_token: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<f64>,
}

fn normalise_scope(scope: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in scope.split_whitespace() {
        if !parts.contains(&p) {
            parts.push(p);
        }
    }
    if !parts.contains(&"openid") {
        parts.insert(0, "openid");
    }
    parts.join(" ")
}

/// `1970-01-01T00:00:00.000Z` for epoch milliseconds (days-from-civil, no date crate).
fn epoch_ms_to_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

// ── routes and hooks: what the framework adapters share ─────────────────────

/// Which of the three relying-party routes a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpRoute {
    SignIn,
    Callback,
    SignOut,
}

/// The paths the relying party answers. Defaults: `/auth/sign-in`, the path of
/// `redirect_uri`, and `/auth/sign-out`.
#[derive(Debug, Clone)]
pub struct RpRoutes {
    pub sign_in: String,
    pub callback: String,
    pub sign_out: String,
}

impl RpRoutes {
    /// The default routes for a configuration.
    pub fn for_config(cfg: &RelyingPartyConfig) -> Self {
        RpRoutes {
            sign_in: "/auth/sign-in".into(),
            callback: Url::parse(&cfg.redirect_uri).map(|u| u.path().to_string()).unwrap_or_else(|_| "/auth/callback".into()),
            sign_out: "/auth/sign-out".into(),
        }
    }

    /// Which route a request is for: `GET` on the sign-in and callback paths, `GET` or `POST` on the
    /// sign-out path; anything else is `None`, so your app answers it.
    pub fn route_for(&self, method: &str, path: &str) -> Option<RpRoute> {
        let m = method.to_ascii_uppercase();
        if m == "GET" && path == self.sign_in {
            Some(RpRoute::SignIn)
        } else if m == "GET" && path == self.callback {
            Some(RpRoute::Callback)
        } else if (m == "GET" || m == "POST") && path == self.sign_out {
            Some(RpRoute::SignOut)
        } else {
            None
        }
    }
}

/// Where your app plugs into the relying-party routes.
pub trait RpHooks: Send + Sync + 'static {
    /// A sign-in verified: create your own session and return the `Set-Cookie` values for it. They are
    /// added to the redirect to the return path (the flow cookie is cleared either way). `Err` answers 500.
    fn on_signed_in<'a>(&'a self, result: &'a CallbackResult) -> BoxFuture<'a, Result<Vec<String>, String>>;

    /// The sign-out route: end your own session and return the Atlas `sid` and `id_token` you kept, plus
    /// the `set_cookies` that clear your session cookie. `cookie_header` is the request's `Cookie` header.
    fn on_sign_out<'a>(&'a self, cookie_header: Option<&'a str>) -> BoxFuture<'a, SignOutOptions> {
        let _ = cookie_header;
        Box::pin(async { SignOutOptions::default() })
    }
}

/// A route's answer, framework-neutral: build your framework's response from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpResponse {
    pub status: u16,
    /// Set on a redirect (302).
    pub location: Option<String>,
    pub set_cookies: Vec<String>,
    /// A plain-text body for an error answer.
    pub body: Option<String>,
}

impl RpResponse {
    fn found(r: Redirect) -> Self {
        RpResponse { status: 302, location: Some(r.location), set_cookies: r.set_cookies, body: None }
    }
    fn text(status: u16, body: &str, set_cookies: Vec<String>) -> Self {
        RpResponse { status, location: None, set_cookies, body: Some(body.to_string()) }
    }
}

impl RelyingParty {
    /// Answer one request on one of the three routes, calling your [`RpHooks`]. `query` is the raw query
    /// string, `cookie` the `Cookie` header. A failed callback answers 400 and always clears the flow cookie;
    /// a failure to start answers 502; a hook error answers 500.
    pub async fn handle_route(&self, route: RpRoute, hooks: &dyn RpHooks, query: &str, cookie: Option<&str>) -> RpResponse {
        match route {
            RpRoute::SignIn => match self.start(query, StartOverrides::default()).await {
                Ok(r) => RpResponse::found(r),
                Err(_) => RpResponse::text(502, "Sign-in is temporarily unavailable. Please try again.", Vec::new()),
            },
            RpRoute::Callback => match self.callback(query, cookie).await {
                Ok(done) => match hooks.on_signed_in(&done).await {
                    Ok(mut cookies) => {
                        let mut r = done.redirect;
                        r.set_cookies.append(&mut cookies);
                        RpResponse::found(r)
                    }
                    Err(_) => RpResponse::text(500, "Sign-in failed. Please try again.", vec![done.identity.clear_cookie]),
                },
                Err(e) => RpResponse::text(400, "Sign-in failed. Please try again.", e.clear_cookie.into_iter().collect()),
            },
            RpRoute::SignOut => {
                let opts = hooks.on_sign_out(cookie).await;
                let cookies = opts.set_cookies.clone();
                match self.sign_out(opts).await {
                    Ok(r) => RpResponse::found(r),
                    Err(_) => RpResponse::text(502, "Sign-out is temporarily unavailable. Please try again.", cookies),
                }
            }
        }
    }
}
