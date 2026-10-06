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

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use crate::clock::{system_clock, Clock};
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

use super::error::{OAuthError, RefreshRefusal, SessionError};
use super::oauth::{form_encode, revoke_token};
use super::store::{SecureStore, SecureStoreError};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A callback fired when a refresh is REFUSED (one of the four typed codes), so a
/// host can react — surface a "signed out" UI on a terminal refusal, or log a
/// reuse-detected race. Receives the [`RefreshRefusal`]; use
/// [`RefreshRefusal::is_terminal`] to decide whether to re-run OAuth.
pub type RefusalListener = Arc<dyn Fn(RefreshRefusal) + Send + Sync>;

struct ManagerState {
    session: Option<NativeSession>,
    /// Absolute expiry of the current session token, epoch ms.
    expires_at: u64,
    /// The most recent refusal observed on a refresh, if any. Cleared on a
    /// successful refresh.
    last_refusal: Option<RefreshRefusal>,
}

/// The internal result of a single locked refresh attempt — what to hand the
/// caller and whether to notify / fire listeners once the lock is released.
enum RefreshOutcome {
    /// The session rotated; the state now holds the new session.
    Rotated(NativeSession),
    /// A typed refusal. On a terminal one the state's session was cleared.
    Refused(RefreshRefusal),
    /// A transient transport/unexpected failure; the state was left untouched.
    Transport(SessionError),
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
    refusal_listeners: Mutex<Vec<RefusalListener>>,
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
                last_refusal: None,
            }),
            listeners: Mutex::new(Vec::new()),
            refusal_listeners: Mutex::new(Vec::new()),
        }
    }

    /// Inject a clock (epoch ms) for deterministic refresh-timing tests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.now = clock;
        self
    }

    /// Seed the manager with a FRESHLY-ISSUED session (e.g. straight off
    /// [`exchange_for_session`]). `expires_in_seconds` is read as a lifetime
    /// relative to NOW, so the absolute expiry becomes `now + expires_in`. Does
    /// NOT notify listeners — the caller already has it.
    ///
    /// Do NOT use this for a session read back from a store on restart: its
    /// `expires_in_seconds` was relative to the ORIGINAL issue time, so treating
    /// it as relative to now would hand a stale (or dead) token a whole fresh
    /// lifetime. Use [`seed_with_expiry`](Self::seed_with_expiry) with the
    /// persisted absolute expiry for that.
    pub async fn seed(&self, session: NativeSession) {
        let expires_at = (self.now)() + (session.expires_in_seconds.max(0) as u64) * 1000;
        self.seed_with_expiry(session, Some(expires_at)).await;
    }

    /// Seed the manager with a session AND its already-known absolute expiry
    /// (epoch ms) — the shape a reload from a [`SecureStore`] takes, where the
    /// expiry must come from the stored value, not be re-derived from now.
    ///
    /// * `Some(at)` seeds that exact expiry; a past/near value makes the next
    ///   [`get_token`](Self::get_token) refresh before handing anything back.
    /// * `None` means the expiry is UNKNOWN (e.g. an older persisted blob carried
    ///   no absolute expiry). It is seeded as owed-a-refresh (expiry 0), never as
    ///   fresh — the next call refreshes (or, if the session is dead, forgets it)
    ///   rather than trusting an on-disk token for a full lifetime.
    ///
    /// Does NOT notify listeners — the caller already holds the session.
    pub async fn seed_with_expiry(&self, session: NativeSession, expires_at: Option<u64>) {
        let mut st = self.state.lock().await;
        st.expires_at = expires_at.unwrap_or(0);
        st.session = Some(session);
        st.last_refusal = None;
    }

    /// Register a listener fired with the session after every change (set or
    /// rotate). A secure-store wrapper uses this to persist each rotated token.
    pub fn on_change(&self, listener: NativeSessionListener) {
        self.listeners.lock().unwrap().push(listener);
    }

    /// Register a listener fired whenever a refresh is REFUSED. A terminal
    /// refusal (see [`RefreshRefusal::is_terminal`]) means the session has also
    /// been cleared and the host should route the user back through OAuth.
    pub fn on_refused(&self, listener: RefusalListener) {
        self.refusal_listeners.lock().unwrap().push(listener);
    }

    /// The absolute expiry of the current session token in epoch ms, or `None`
    /// when signed out. A host can schedule a pre-emptive refresh off this, or
    /// decide a token is close enough to expiry to refresh before a call.
    pub async fn expires_at_ms(&self) -> Option<u64> {
        let st = self.state.lock().await;
        st.session.as_ref().map(|_| st.expires_at)
    }

    /// Alias of [`expires_at_ms`](Self::expires_at_ms): the current token's
    /// absolute expiry, epoch ms.
    pub async fn token_expiry_ms(&self) -> Option<u64> {
        self.expires_at_ms().await
    }

    /// The most recent refusal observed on a refresh, or `None` if the last
    /// refresh succeeded (or none has run). Set on every refused refresh —
    /// including a non-terminal reuse-detected one, which does NOT clear the
    /// session — so a host can inspect it without wiring an [`on_refused`](Self::on_refused)
    /// listener.
    pub async fn last_refusal(&self) -> Option<RefreshRefusal> {
        self.state.lock().await.last_refusal
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
            st.last_refusal = None;
        }
        self.notify().await;
    }

    /// Forget the session (sign-out). Does not notify — nothing to persist.
    pub async fn clear(&self) {
        let mut st = self.state.lock().await;
        st.session = None;
        st.expires_at = 0;
        st.last_refusal = None;
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
        if !self.refresh_owed(&st) {
            return Some(session.session_token);
        }
        match self.refresh_locked(&mut st, &session).await {
            RefreshOutcome::Rotated(rotated) => {
                drop(st);
                self.notify().await;
                Some(rotated.session_token)
            }
            // A failed/refused refresh hands back the stale token: let the next
            // real request get the authoritative 401. On a terminal refusal the
            // session has already been cleared (so the NEXT get_token returns
            // None), but this call still returns the stale token once.
            RefreshOutcome::Refused(r) => {
                drop(st);
                self.fire_refused(r);
                Some(session.session_token)
            }
            RefreshOutcome::Transport(_) => {
                drop(st);
                Some(session.session_token)
            }
        }
    }

    /// Like [`get_token`](Self::get_token) but SURFACES a refusal instead of
    /// silently handing back a stale token.
    ///
    /// * signed out → `Err(`[`SessionError::NoSession`]`)`.
    /// * a refused refresh → `Err(`[`SessionError::Refused`]`)` (the refusal is
    ///   recorded and [`on_refused`](Self::on_refused) listeners fire; on a
    ///   terminal refusal the session is cleared first).
    /// * a transient transport failure on an owed refresh → `Ok(stale token)`,
    ///   so a flaky link does not force a sign-out; the next real request gets
    ///   the authoritative answer. Only a typed REFUSAL is treated as fatal.
    /// * otherwise → `Ok(fresh token)`.
    pub async fn get_token_checked(&self) -> Result<String, SessionError> {
        let mut st = self.state.lock().await;
        let session = st.session.clone().ok_or(SessionError::NoSession)?;
        if !self.refresh_owed(&st) {
            return Ok(session.session_token);
        }
        match self.refresh_locked(&mut st, &session).await {
            RefreshOutcome::Rotated(rotated) => {
                drop(st);
                self.notify().await;
                Ok(rotated.session_token)
            }
            RefreshOutcome::Refused(r) => {
                drop(st);
                self.fire_refused(r);
                Err(SessionError::Refused(r))
            }
            RefreshOutcome::Transport(_) => {
                drop(st);
                Ok(session.session_token)
            }
        }
    }

    /// Whether the current token is within [`REFRESH_LEAD_MS`] of expiry.
    fn refresh_owed(&self, st: &ManagerState) -> bool {
        st.expires_at.saturating_sub(REFRESH_LEAD_MS) <= (self.now)()
    }

    /// Run the network refresh while holding the state lock (the single-flight
    /// point) and fold the result back into `st`: on success store the rotated
    /// session and clear `last_refusal`; on a typed refusal record it and, when
    /// it is TERMINAL, clear the session. Returns the outcome so the caller can
    /// decide what to hand back and whether to notify/fire listeners (which must
    /// happen after the lock is released).
    async fn refresh_locked(&self, st: &mut ManagerState, session: &NativeSession) -> RefreshOutcome {
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
                st.last_refusal = None;
                RefreshOutcome::Rotated(rotated)
            }
            Err(SessionError::Refused(r)) => {
                st.last_refusal = Some(r);
                if r.is_terminal() {
                    // Genuinely unrecoverable — drop the dead session so no stale
                    // token lingers past this call. A non-terminal reuse-detected
                    // refusal KEEPS the session for a retry with the current token.
                    st.session = None;
                    st.expires_at = 0;
                }
                RefreshOutcome::Refused(r)
            }
            // Transport/unexpected: not a verdict on the session — leave it be,
            // but carry the error so a direct `refresh()` caller can see it.
            Err(e) => RefreshOutcome::Transport(e),
        }
    }

    /// Fire the refused-refresh listeners (outside the state lock).
    fn fire_refused(&self, refusal: RefreshRefusal) {
        let listeners = self.refusal_listeners.lock().unwrap().clone();
        for cb in listeners {
            cb(refusal);
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

    /// Rotate the session now, surfacing a refusal as a [`SessionError::Refused`].
    /// On success the new session is stored and [`on_change`](Self::on_change)
    /// listeners fire; on a refusal it is recorded, [`on_refused`](Self::on_refused)
    /// listeners fire, and a TERMINAL refusal also clears the session.
    pub async fn refresh(&self) -> Result<NativeSession, SessionError> {
        let mut st = self.state.lock().await;
        let session = st.session.clone().ok_or(SessionError::NoSession)?;
        match self.refresh_locked(&mut st, &session).await {
            RefreshOutcome::Rotated(rotated) => {
                drop(st);
                self.notify().await;
                Ok(rotated)
            }
            RefreshOutcome::Refused(r) => {
                drop(st);
                self.fire_refused(r);
                Err(SessionError::Refused(r))
            }
            // A transient transport/unexpected failure: the session is untouched,
            // and the concrete error goes straight back to the caller.
            RefreshOutcome::Transport(e) => {
                drop(st);
                Err(e)
            }
        }
    }

    /// Sign out, ALSO revoking the session's refresh token at the OAuth
    /// revocation endpoint (RFC 7009) so the server kills the grant immediately
    /// rather than waiting for it to expire. The local session is cleared FIRST
    /// and unconditionally — the app is signed out even if the network revoke
    /// fails — and a revoke error is returned so a caller can log/retry it. When
    /// signed out already, this is a no-op `Ok(())`. `revoke_endpoint` is the
    /// instance `.../oauth2/revoke`; `client_id` the native app's OAuth client.
    pub async fn sign_out_revoking_grant(
        &self,
        revoke_endpoint: &str,
        client_id: &str,
    ) -> Result<(), OAuthError> {
        let refresh = {
            let mut st = self.state.lock().await;
            let rt = st.session.as_ref().map(|s| s.refresh_token.clone());
            st.session = None;
            st.expires_at = 0;
            st.last_refusal = None;
            rt
        };
        match refresh {
            Some(rt) if !rt.is_empty() => {
                revoke_token(&self.transport, revoke_endpoint, client_id, &rt, Some("refresh_token"))
                    .await
            }
            _ => Ok(()),
        }
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

    /// A clone of the manager's clock, so a wrapper (the [`StoredSessionManager`])
    /// can stamp the SAME absolute expiry the manager computes when it persists a
    /// rotated session.
    pub(crate) fn clock(&self) -> Clock {
        self.now.clone()
    }
}

/// A [`NativeSessionManager`] that PERSISTS the session through a [`SecureStore`].
///
/// The bare manager holds the session in memory and fires listeners on every
/// change; this wires those listeners to a store so the rotating refresh token
/// survives a restart, and adds the one piece the in-memory manager cannot do on
/// its own — recover from a cross-process refresh race.
///
/// # How it persists
///
/// * The [`NativeSession`] is serialized to JSON under one store `key`, wrapped
///   with its ABSOLUTE expiry (epoch ms) so a reload on restart knows the token's
///   real remaining life rather than granting it a full fresh lifetime. An older
///   bare-`NativeSession` blob still loads — its expiry is treated as unknown, so
///   it is refreshed (or forgotten) on next use, never trusted as fresh.
/// * An [`on_change`](NativeSessionManager::on_change) listener re-writes that
///   JSON after every rotation, so the store always holds the LIVE refresh
///   token; the superseded one is already dead.
/// * An [`on_refused`](NativeSessionManager::on_refused) listener DELETES the
///   stored session on a TERMINAL refusal (revoked / expired / idle-expired):
///   the session is gone, so no stale credential is left on disk.
///
/// # The one async lock
///
/// Every token-producing call takes a single async `gate` before touching the
/// inner manager, so within THIS process the load → refresh → write-back
/// sequence is serialized and single-flight (the inner manager's own lock still
/// collapses concurrent refreshes too).
///
/// # Cross-process limitation (and the reuse-detected recovery)
///
/// The refresh token rotates on every use, so two PROCESSES sharing one store
/// (two CLI invocations, an app plus a helper) can race: process A refreshes and
/// persists a new token; process B, still holding the old one in memory, then
/// refreshes and trips the server's reuse detection — even though the session is
/// perfectly alive and a valid rotated token already sits in the store. Because
/// [`RefreshRefusal::RefreshReuseDetected`] is non-terminal, this manager treats
/// it as the recoverable race it usually is: on that refusal it RE-READS the
/// store ONCE (picking up the token the other process just wrote) and retries a
/// single refresh. If it was genuine theft the whole chain is dead and the retry
/// surfaces a terminal refusal instead, so the recovery never masks a compromise
/// — it only costs one extra read.
///
/// This is best-effort, not a mutex across processes: two processes can still
/// interleave between the re-read and the retry. A store that needs a hard
/// guarantee should serialize access out of band (e.g. an OS advisory file lock
/// around the process's session use); this manager deliberately pulls in no such
/// dependency.
pub struct StoredSessionManager {
    store: Arc<dyn SecureStore>,
    key: String,
    inner: Arc<NativeSessionManager>,
    gate: AsyncMutex<()>,
    /// Whether the session JWT is written to the store. When false the persisted
    /// blob blanks the short-lived bearer and records no expiry, so a reload
    /// refreshes before first use. The rotating refresh token is still persisted.
    persist_jwt: bool,
    /// An opaque app-held value persisted and cleared alongside the session. Held
    /// in an `Arc` so the `on_change` writer can see the live value.
    app_value: Arc<Mutex<Option<String>>>,
}

/// The current persisted-blob schema version. `v1` was a bare [`NativeSession`]
/// JSON with no absolute expiry; `v2` added the absolute expiry; `v3` adds an
/// optional app-held value and the JWT-less persistence mode. Older blobs still
/// load (the new field defaults to `None`).
const PERSIST_V: u32 = 3;

/// The on-disk shape of a stored session.
///
/// A bare [`NativeSession`] only carries `expires_in_seconds`, a lifetime
/// RELATIVE to issue time — useless for deciding expiry after a restart, because
/// the issue moment is gone. So the persisted blob also carries the ABSOLUTE
/// expiry (`expires_at`, epoch ms) stamped when the session was minted/rotated;
/// a reload reads that directly instead of re-deriving a full fresh lifetime from
/// "now".
///
/// Back-compat: a v1 blob is a bare `NativeSession` (none of `v` / `session` /
/// `expires_at`), so it will NOT deserialize here (no `session` field) and
/// [`parse_persisted`] falls back to the bare shape with `expires_at: None` —
/// "unknown → refresh on next use", never "fresh".
#[derive(Debug, Serialize, Deserialize)]
struct PersistedSession {
    #[serde(default)]
    v: u32,
    session: NativeSession,
    /// Absolute expiry, epoch ms. `None` only on a hand-written/forward-compat
    /// blob that omitted it → treated as unknown. Also `None` in the JWT-less
    /// mode, so a reload refreshes before first use.
    #[serde(default)]
    expires_at: Option<u64>,
    /// An opaque app-held value persisted and cleared alongside the session. A
    /// v1/v2 blob (or any that omitted it) loads as `None`.
    #[serde(default)]
    app_value: Option<String>,
}

/// Parse a stored blob into its session and absolute expiry. Tries the current
/// [`PersistedSession`] shape first; falls back to a bare [`NativeSession`] (a v1
/// blob) with an UNKNOWN expiry so it is refreshed, not trusted, on next use.
fn parse_persisted(json: &str) -> Result<(NativeSession, Option<u64>, Option<String>), SessionError> {
    if let Ok(p) = serde_json::from_str::<PersistedSession>(json) {
        return Ok((p.session, p.expires_at, p.app_value));
    }
    // v1 fallback: a bare NativeSession with no absolute expiry recorded.
    let session: NativeSession =
        serde_json::from_str(json).map_err(|e| SessionError::Malformed(e.to_string()))?;
    Ok((session, None, None))
}

/// Serialize a session + its absolute expiry + the app-held value into the
/// current persisted shape. When `persist_jwt` is false the session JWT is
/// blanked and the expiry recorded as `None`, so a reload refreshes before first
/// use and the store never holds the short-lived bearer.
fn to_persisted(
    session: &NativeSession,
    expires_at: u64,
    persist_jwt: bool,
    app_value: Option<String>,
) -> Result<String, serde_json::Error> {
    let (session, expires_at) = if persist_jwt {
        (session.clone(), Some(expires_at))
    } else {
        let mut stripped = session.clone();
        stripped.session_token = String::new();
        (stripped, None)
    };
    serde_json::to_string(&PersistedSession {
        v: PERSIST_V,
        session,
        expires_at,
        app_value,
    })
}

impl StoredSessionManager {
    /// Wrap an existing [`NativeSessionManager`] so it persists through `store`
    /// under `key`. Registers the change/refusal listeners that keep the store in
    /// sync; build the inner manager (optionally [`with_clock`](NativeSessionManager::with_clock))
    /// first, then hand it here. Call [`load`](Self::load) once at startup to
    /// seed any persisted session.
    pub fn new(
        store: Arc<dyn SecureStore>,
        key: impl Into<String>,
        inner: NativeSessionManager,
    ) -> Self {
        Self::with_options(store, key, inner, true)
    }

    /// Like [`new`](Self::new) but keeps the session JWT OUT of the store: each
    /// persisted blob blanks the short-lived bearer and records no expiry, so a
    /// reload always refreshes before first use. The rotating refresh token is
    /// still persisted (it is the credential that survives a restart). Choose this
    /// when the store should never hold even a transient copy of the session JWT.
    pub fn new_without_jwt(
        store: Arc<dyn SecureStore>,
        key: impl Into<String>,
        inner: NativeSessionManager,
    ) -> Self {
        Self::with_options(store, key, inner, false)
    }

    fn with_options(
        store: Arc<dyn SecureStore>,
        key: impl Into<String>,
        inner: NativeSessionManager,
        persist_jwt: bool,
    ) -> Self {
        let key = key.into();
        // Hold the inner manager in an `Arc` so it can ALSO back a
        // `SelfServiceClient` (whose bearer source is an `Arc<NativeSessionManager>`)
        // without a hand-built `StaticBearer`. The listeners below are registered
        // before it is shared out, so the wiring is identical to the bare case.
        let inner = Arc::new(inner);
        let app_value: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        // Persist every rotation. A store write failure here is swallowed — the
        // in-memory session is still good; the next call's write (or a load on
        // restart) reconciles. A caller that must observe write failures can wrap
        // the store.
        {
            let store = store.clone();
            let k = key.clone();
            // Stamp the absolute expiry with the manager's own clock — the same
            // value it computed under the lock when it set this session — so the
            // persisted blob survives a restart with a real expiry instead of a
            // lifetime relative to a now that is gone.
            let clock = inner.clock();
            let app_value = app_value.clone();
            inner.on_change(Arc::new(move |s: &NativeSession| {
                let expires_at = clock() + (s.expires_in_seconds.max(0) as u64) * 1000;
                let av = app_value.lock().unwrap().clone();
                if let Ok(json) = to_persisted(s, expires_at, persist_jwt, av) {
                    let _ = store.set(&k, &json);
                }
            }));
        }
        // On a TERMINAL refusal the inner manager has cleared the session; drop
        // it from the store too so no dead credential lingers.
        {
            let store = store.clone();
            let k = key.clone();
            inner.on_refused(Arc::new(move |r: RefreshRefusal| {
                if r.is_terminal() {
                    let _ = store.delete(&k);
                }
            }));
        }
        StoredSessionManager {
            store,
            key,
            inner,
            gate: AsyncMutex::new(()),
            persist_jwt,
            app_value,
        }
    }

    /// The wrapped manager, for the read-only accessors
    /// ([`current`](NativeSessionManager::current),
    /// [`expires_at_ms`](NativeSessionManager::expires_at_ms), …).
    pub fn inner(&self) -> &NativeSessionManager {
        self.inner.as_ref()
    }

    /// A shared handle to the wrapped manager, for building a
    /// [`SelfServiceClient`](super::self_service::SelfServiceClient) whose bearer
    /// is driven by THIS stored manager — the same session, auto-refreshing and
    /// revoked on sign-out, with no hand-built `StaticBearer`. Prefer
    /// [`SelfServiceClient::from_stored`](super::self_service::SelfServiceClient::from_stored),
    /// which calls this for you.
    pub fn manager_arc(&self) -> Arc<NativeSessionManager> {
        self.inner.clone()
    }

    /// Load a persisted session from the store into the inner manager. Returns
    /// `Ok(true)` when a session was found and seeded, `Ok(false)` when the store
    /// was empty (signed out), `Err(Store)` when the read failed, and
    /// `Err(Malformed)` when the stored JSON did not parse. Seeding does NOT
    /// re-persist (nothing changed), so calling this at startup is cheap.
    pub async fn load(&self) -> Result<bool, SessionError> {
        let _gate = self.gate.lock().await;
        self.reseed_from_store().await
    }

    /// Read the store and seed the inner manager with whatever it holds. The
    /// caller holds `gate`.
    async fn reseed_from_store(&self) -> Result<bool, SessionError> {
        match self.store.get(&self.key).map_err(store_err)? {
            Some(json) => {
                // Derive the REAL expiry from the stored blob (absolute epoch ms),
                // not from `now + expires_in` — a session read off disk was issued
                // in the past, so its remaining life is whatever the stored
                // absolute expiry says, and a missing one means "unknown → refresh
                // on next use". Seeding with that is what makes a stale/expired
                // on-disk token get refreshed or forgotten instead of trusted.
                let (session, expires_at, app_value) = parse_persisted(&json)?;
                *self.app_value.lock().unwrap() = app_value;
                self.inner.seed_with_expiry(session, expires_at).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// A fresh session JWT, refreshing (and persisting the rotation) if owed.
    ///
    /// Surfaces a refusal rather than a silent stale token (like
    /// [`get_token_checked`](NativeSessionManager::get_token_checked)). On a
    /// non-terminal [`RefreshReuseDetected`](RefreshRefusal::RefreshReuseDetected)
    /// it RE-READS the store once and retries a single refresh — the cross-process
    /// recovery described on the type. A terminal refusal has already cleared and
    /// deleted the session.
    pub async fn get_token(&self) -> Result<String, SessionError> {
        let _gate = self.gate.lock().await;
        match self.inner.get_token_checked().await {
            Err(SessionError::Refused(RefreshRefusal::RefreshReuseDetected)) => {
                // Maybe another process rotated+persisted a newer token: re-read
                // the store once, re-seed, and retry a single refresh.
                if self.reseed_from_store().await? {
                    self.inner.get_token_checked().await
                } else {
                    Err(SessionError::Refused(RefreshRefusal::RefreshReuseDetected))
                }
            }
            other => other,
        }
    }

    /// Rotate the session now and persist the result. Mirrors
    /// [`NativeSessionManager::refresh`] with the same reuse-detected re-read
    /// recovery as [`get_token`](Self::get_token).
    pub async fn refresh(&self) -> Result<NativeSession, SessionError> {
        let _gate = self.gate.lock().await;
        match self.inner.refresh().await {
            Err(SessionError::Refused(RefreshRefusal::RefreshReuseDetected)) => {
                if self.reseed_from_store().await? {
                    self.inner.refresh().await
                } else {
                    Err(SessionError::Refused(RefreshRefusal::RefreshReuseDetected))
                }
            }
            other => other,
        }
    }

    /// The current session (no refresh), or `None` when signed out.
    pub async fn current(&self) -> Option<NativeSession> {
        self.inner.current().await
    }

    /// Replace the session and persist it (fires the change listener).
    pub async fn set_session(&self, session: NativeSession) {
        let _gate = self.gate.lock().await;
        self.inner.set_session(session).await;
    }

    /// Sign out: clear the in-memory session (and the app-held value) AND delete
    /// the blob from the store. The app value goes away with the blob.
    pub async fn sign_out(&self) -> Result<(), SessionError> {
        let _gate = self.gate.lock().await;
        self.inner.clear().await;
        *self.app_value.lock().unwrap() = None;
        self.store.delete(&self.key).map_err(store_err)
    }

    /// The opaque app-held value currently stored alongside the session, or
    /// `None` if none was set (or it was cleared on sign-out).
    pub fn app_value(&self) -> Option<String> {
        self.app_value.lock().unwrap().clone()
    }

    /// Set (or clear, with `None`) an opaque app-held value persisted ALONGSIDE
    /// the session in the same store blob, and cleared when the session is signed
    /// out. Use it for a small piece of app state that must live and die with the
    /// session — a selected org id, a device nickname, a feature flag. When a
    /// session is present the blob is re-written immediately so the store reflects
    /// the new value; it is also re-persisted on the next session rotation.
    pub async fn set_app_value(&self, v: Option<String>) {
        let _gate = self.gate.lock().await;
        *self.app_value.lock().unwrap() = v;
        if let Some(session) = self.inner.current().await {
            let expires_at = self.inner.expires_at_ms().await.unwrap_or(0);
            let av = self.app_value.lock().unwrap().clone();
            if let Ok(json) = to_persisted(&session, expires_at, self.persist_jwt, av) {
                let _ = self.store.set(&self.key, &json);
            }
        }
    }
}

/// Map a [`SecureStoreError`] to [`SessionError::Store`].
fn store_err(e: SecureStoreError) -> SessionError {
    SessionError::Store(e.0)
}
