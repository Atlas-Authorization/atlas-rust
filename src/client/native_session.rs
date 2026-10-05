//! The native (first-party) OAuth→session exchange, cookie-free.
//!
//! A FIRST-PARTY app (it IS the tenant's own property) already holds an Atlas
//! OAuth access token. On the web that token rides in a cookie and the browser
//! carries the session for free; a native app — a desktop binary, a CLI, a
//! mobile runtime — has no cookie jar against the FAPI origin, so it trades the
//! OAuth access token for a real Atlas SESSION and carries it by hand as a
//! bearer. This module is the framework-agnostic half of that, mirroring
//! `native-session.ts`:
//!
//!   1. [`exchange_for_session`] — the RFC 8693 token-exchange, trading an OAuth
//!      access token for a [`NativeSession`].
//!   2. [`refresh_native_session`] — cookie-free rotation, surfacing the four
//!      typed refusal codes.
//!   3. [`NativeSessionManager`] — holds the session, hands out a live JWT
//!      (lazy single-flight refresh near expiry), and fires `on_change` so a
//!      secure store can persist each rotated refresh token.

use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::clock::{system_clock, Clock};
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

use super::error::{RefreshRefusal, SessionError};
use super::oauth::form_encode;

/// How close to expiry (ms) the manager refreshes the token. Matches the JS
/// SDK's `REFRESH_LEAD_MS`.
pub const REFRESH_LEAD_MS: u64 = 10_000;

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const SESSION_TOKEN_TYPE: &str = "urn:atlas:token-type:session";

/// A live Atlas session held outside a cookie.
///
/// `session_token` is the short-lived (~60s) session JWT sent as
/// `Authorization: Bearer …` on `/v1/client/me/*`. `refresh_token` mints the
/// next one and ROTATES on every refresh — persist the new value, discard the
/// old. `expires_in_seconds` is the lifetime the server reported, a scheduling
/// hint only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSession {
    pub session_token: String,
    pub refresh_token: String,
    pub session_id: String,
    pub expires_in_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct TokenExchangeResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SessionTokensResponse {
    #[serde(default)]
    jwt: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    errors: Vec<ErrorItem>,
}

#[derive(Debug, Deserialize)]
struct ErrorItem {
    #[serde(default)]
    code: String,
}

/// Exchange a first-party OAuth access token for an Atlas session (RFC 8693).
///
/// POSTs the token-exchange form to `{base_url}/oauth2/token`. `device_name`,
/// when given, is recorded with the minted session so a user can tell their
/// devices apart. First-party clients only.
pub async fn exchange_for_session(
    transport: &Arc<dyn HttpTransport>,
    base_url: &str,
    client_id: &str,
    access_token: &str,
    device_name: Option<&str>,
) -> Result<NativeSession, SessionError> {
    let base = base_url.trim_end_matches('/');
    let mut pairs = vec![
        ("grant_type", TOKEN_EXCHANGE_GRANT),
        ("client_id", client_id),
        ("subject_token", access_token),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", SESSION_TOKEN_TYPE),
    ];
    if let Some(name) = device_name {
        pairs.push(("device_name", name));
    }
    let form = form_encode(&pairs);

    let req = HttpRequest::new(HttpMethod::Post, format!("{base}/oauth2/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(form);
    let resp = transport.send(req).await?;

    if !(200..300).contains(&resp.status) {
        return Err(map_refusal(resp.status, &resp.body));
    }
    let body: TokenExchangeResponse =
        serde_json::from_str(&resp.body).map_err(|e| SessionError::Malformed(e.to_string()))?;
    // A session is only a session if it carries both the JWT and the id the
    // refresh path needs; anything short of that is unusable.
    match (body.access_token, body.session_id) {
        (Some(token), Some(sid)) => Ok(NativeSession {
            session_token: token,
            refresh_token: body.refresh_token.unwrap_or_default(),
            session_id: sid,
            expires_in_seconds: body.expires_in.unwrap_or(0),
        }),
        _ => Err(SessionError::Malformed(
            "token exchange returned no session token or id".to_string(),
        )),
    }
}

/// Rotate a native session WITHOUT a cookie.
///
/// POSTs the stored refresh token to `/v1/client/sessions/{session_id}/tokens`
/// with the publishable-key header. Each refresh ROTATES the refresh token —
/// the returned session carries the new one, and the old one is dead the moment
/// this resolves — so the caller MUST persist what comes back. A non-2xx
/// carrying one of the four typed codes is a [`SessionError::Refused`]; the
/// caller's cue to re-run OAuth.
pub async fn refresh_native_session(
    transport: &Arc<dyn HttpTransport>,
    base_url: &str,
    publishable_key: &str,
    session_id: &str,
    refresh_token: &str,
) -> Result<NativeSession, SessionError> {
    let base = base_url.trim_end_matches('/');
    let url = format!(
        "{base}/v1/client/sessions/{}/tokens",
        crate::http::encode_segment(session_id)
    );
    let body = serde_json::json!({ "refresh_token": refresh_token }).to_string();
    let req = HttpRequest::new(HttpMethod::Post, url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("x-publishable-key", publishable_key)
        .body(body);
    let resp = transport.send(req).await?;

    if !(200..300).contains(&resp.status) {
        return Err(map_refusal(resp.status, &resp.body));
    }
    let parsed: SessionTokensResponse =
        serde_json::from_str(&resp.body).map_err(|e| SessionError::Malformed(e.to_string()))?;
    let jwt = parsed
        .jwt
        .ok_or_else(|| SessionError::Malformed("refresh returned no jwt".to_string()))?;
    Ok(NativeSession {
        session_token: jwt,
        // Carry the rotated token; fall back to the presented one if the server
        // reused it rather than issuing a new value.
        refresh_token: parsed.refresh_token.unwrap_or_else(|| refresh_token.to_string()),
        session_id: parsed.session_id.unwrap_or_else(|| session_id.to_string()),
        expires_in_seconds: parsed.expires_in.unwrap_or(0),
    })
}

/// Map a non-2xx body to a typed refusal when it carries one of the four codes,
/// else a generic `Unexpected`.
fn map_refusal(status: u16, body: &str) -> SessionError {
    if let Ok(env) = serde_json::from_str::<ErrorEnvelope>(body) {
        for item in &env.errors {
            if let Some(refusal) = RefreshRefusal::from_code(&item.code) {
                return SessionError::Refused(refusal);
            }
        }
    }
    SessionError::Unexpected { status }
}

/// A callback handed the session after every change, so a store can persist it.
pub type NativeSessionListener = Arc<dyn Fn(&NativeSession) + Send + Sync>;

struct ManagerState {
    session: Option<NativeSession>,
    /// Absolute expiry of the current session token, epoch ms.
    expires_at: u64,
}

/// Holds the current [`NativeSession`] and keeps its JWT live.
///
/// It refreshes LAZILY — on [`get_token`](Self::get_token) /
/// [`auth_headers`](Self::auth_headers), when the token is within
/// [`REFRESH_LEAD_MS`] of expiry — rather than on a timer, because the native
/// hosts this backs cannot keep a long-lived timer alive anyway. A single async
/// lock guards the refresh, so twenty concurrent callers make ONE network call
/// (single-flight): the losers wait, then observe the already-rotated token.
/// Each rotation fires every `on_change` listener so a secure store captures the
/// new refresh token; the previous one is dead.
pub struct NativeSessionManager {
    transport: Arc<dyn HttpTransport>,
    base_url: String,
    publishable_key: String,
    now: Clock,
    state: AsyncMutex<ManagerState>,
    listeners: Mutex<Vec<NativeSessionListener>>,
}

impl NativeSessionManager {
    /// Build a manager for an instance FAPI origin + publishable key.
    pub fn new(
        transport: Arc<dyn HttpTransport>,
        base_url: impl Into<String>,
        publishable_key: impl Into<String>,
    ) -> Self {
        NativeSessionManager {
            transport,
            base_url: base_url.into(),
            publishable_key: publishable_key.into(),
            now: system_clock(),
            state: AsyncMutex::new(ManagerState {
                session: None,
                expires_at: 0,
            }),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Inject a clock (epoch ms) for deterministic refresh-timing tests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.now = clock;
        self
    }

    /// Seed the manager with a session the app already holds (e.g. loaded from a
    /// secure store). Does NOT notify listeners — the caller already has it.
    pub async fn seed(&self, session: NativeSession) {
        let mut st = self.state.lock().await;
        st.expires_at = (self.now)() + (session.expires_in_seconds.max(0) as u64) * 1000;
        st.session = Some(session);
    }

    /// Register a listener fired with the session after every change (set or
    /// rotate). A secure-store wrapper uses this to persist each rotated token.
    pub fn on_change(&self, listener: NativeSessionListener) {
        self.listeners.lock().unwrap().push(listener);
    }

    /// The current session, or `None` when signed out. Does NOT refresh.
    pub async fn current(&self) -> Option<NativeSession> {
        self.state.lock().await.session.clone()
    }

    /// Replace the current session and notify listeners so it is persisted.
    pub async fn set_session(&self, session: NativeSession) {
        {
            let mut st = self.state.lock().await;
            st.expires_at = (self.now)() + (session.expires_in_seconds.max(0) as u64) * 1000;
            st.session = Some(session);
        }
        self.notify().await;
    }

    /// Forget the session (sign-out). Does not notify — nothing to persist.
    pub async fn clear(&self) {
        let mut st = self.state.lock().await;
        st.session = None;
        st.expires_at = 0;
    }

    /// The current session JWT, refreshed first if it is within
    /// [`REFRESH_LEAD_MS`] of expiry.
    ///
    /// Returns `None` when signed out. If a refresh is owed it is attempted
    /// under the single-flight lock; on a refused/failed refresh the EXISTING
    /// token is returned (the server will reject a truly-dead token on use,
    /// which beats pre-emptive sign-out on a flaky link). A terminal refusal
    /// bubbles up through [`refresh`](Self::refresh) if the caller uses it
    /// directly.
    pub async fn get_token(&self) -> Option<String> {
        // Fast path + refresh decision, all under the one async lock so the
        // network refresh is single-flight.
        let mut st = self.state.lock().await;
        let session = st.session.clone()?;
        let needs = st.expires_at.saturating_sub(REFRESH_LEAD_MS) <= (self.now)();
        if !needs {
            return Some(session.session_token);
        }
        match refresh_native_session(
            &self.transport,
            &self.base_url,
            &self.publishable_key,
            &session.session_id,
            &session.refresh_token,
        )
        .await
        {
            Ok(rotated) => {
                st.expires_at = (self.now)() + (rotated.expires_in_seconds.max(0) as u64) * 1000;
                st.session = Some(rotated.clone());
                drop(st);
                self.notify().await;
                Some(rotated.session_token)
            }
            // A failed/refused refresh hands back the stale token: let the next
            // real request get the authoritative 401.
            Err(_) => Some(session.session_token),
        }
    }

    /// The headers an authenticated `/v1/client/me/*` call needs: a fresh bearer
    /// (auto-refreshed like [`get_token`](Self::get_token)) plus the publishable
    /// key. When signed out, only the publishable key is returned.
    pub async fn auth_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![("x-publishable-key".to_string(), self.publishable_key.clone())];
        if let Some(token) = self.get_token().await {
            headers.push(("authorization".to_string(), format!("Bearer {token}")));
        }
        headers
    }

    /// Rotate the session now, surfacing a terminal refusal as a
    /// [`SessionError::Refused`]. On success the new session is stored and
    /// listeners fire.
    pub async fn refresh(&self) -> Result<NativeSession, SessionError> {
        let mut st = self.state.lock().await;
        let session = st
            .session
            .clone()
            .ok_or(SessionError::Unexpected { status: 0 })?;
        let rotated = refresh_native_session(
            &self.transport,
            &self.base_url,
            &self.publishable_key,
            &session.session_id,
            &session.refresh_token,
        )
        .await?;
        st.expires_at = (self.now)() + (rotated.expires_in_seconds.max(0) as u64) * 1000;
        st.session = Some(rotated.clone());
        drop(st);
        self.notify().await;
        Ok(rotated)
    }

    async fn notify(&self) {
        let session = match self.state.lock().await.session.clone() {
            Some(s) => s,
            None => return,
        };
        let listeners = self.listeners.lock().unwrap().clone();
        for cb in listeners {
            // A listener that panics must not poison the manager; callbacks are
            // expected to be cheap persistence writes.
            cb(&session);
        }
    }

    /// The FAPI origin, for a self-service client built over this manager.
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The transport, for a self-service client built over this manager.
    pub(crate) fn transport(&self) -> &Arc<dyn HttpTransport> {
        &self.transport
    }
}
