//! Errors for the native client flows.

use thiserror::Error;

use crate::error::TransportError;

/// The four typed refusal codes a cookie-free session refresh can return.
///
/// The FAPI refresh endpoint answers a dead session with HTTP 401 and the §9.1
/// envelope carrying one of these stable codes (see the server
/// `session.refresh` contract). They are mapped 1:1 here so a native app can
/// tell "retry later" from "the session is gone, re-run OAuth" from "someone
/// replayed an old refresh token" — a distinction a bare `null` (as the JS SDK
/// returns) throws away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRefusal {
    /// The session was explicitly revoked (sign-out, admin action).
    SessionRevoked,
    /// The session exceeded its idle timeout without activity.
    SessionIdleExpired,
    /// The session passed its absolute lifetime.
    SessionExpired,
    /// A previously-rotated refresh token was presented again outside the grace
    /// window — the server assumes theft and kills the whole session chain.
    RefreshReuseDetected,
}

impl RefreshRefusal {
    /// Map a §9.1 error `code` to a refusal, or `None` for an unrelated code.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "SESSION_REVOKED" => Some(RefreshRefusal::SessionRevoked),
            "SESSION_IDLE_EXPIRED" => Some(RefreshRefusal::SessionIdleExpired),
            "SESSION_EXPIRED" => Some(RefreshRefusal::SessionExpired),
            "REFRESH_REUSE_DETECTED" => Some(RefreshRefusal::RefreshReuseDetected),
            _ => None,
        }
    }

    /// The stable wire code.
    pub fn code(&self) -> &'static str {
        match self {
            RefreshRefusal::SessionRevoked => "SESSION_REVOKED",
            RefreshRefusal::SessionIdleExpired => "SESSION_IDLE_EXPIRED",
            RefreshRefusal::SessionExpired => "SESSION_EXPIRED",
            RefreshRefusal::RefreshReuseDetected => "REFRESH_REUSE_DETECTED",
        }
    }

    /// Whether this refusal can NEVER be recovered by another refresh (the
    /// session is gone — re-run OAuth), versus one that *might* clear on a retry
    /// with the current stored token.
    ///
    /// The mapping:
    ///
    /// | refusal                  | terminal | why |
    /// |--------------------------|----------|-----|
    /// | [`SessionRevoked`]       | **yes**  | explicitly killed (sign-out / admin); no token revives it |
    /// | [`SessionExpired`]       | **yes**  | the absolute session lifetime elapsed; refresh cannot extend it |
    /// | [`SessionIdleExpired`]   | **yes**  | the idle window lapsed and the session was closed; re-auth required |
    /// | [`RefreshReuseDetected`] | **no**   | may be a benign single-flight RACE, not theft (see below) |
    ///
    /// The one non-terminal case is [`RefreshReuseDetected`]. The refresh token
    /// ROTATES on every use, so two near-simultaneous refreshes of the same
    /// session race: the winner rotates the token, and the loser then presents
    /// the now-superseded value and trips reuse detection — even though the
    /// session is perfectly alive and a VALID rotated token already exists. A
    /// caller that re-reads the latest persisted refresh token and refreshes once
    /// more therefore MIGHT succeed. (If it was genuine token theft the whole
    /// chain is dead and the retry fails too — surfacing a terminal
    /// [`SessionRevoked`]/[`SessionExpired`] next — so treating it as recoverable
    /// costs one extra attempt and never masks a real compromise.) The session
    /// manager uses exactly this: it clears the stored session on a terminal
    /// refusal but KEEPS it on a reuse-detected one.
    ///
    /// [`SessionRevoked`]: RefreshRefusal::SessionRevoked
    /// [`SessionExpired`]: RefreshRefusal::SessionExpired
    /// [`SessionIdleExpired`]: RefreshRefusal::SessionIdleExpired
    /// [`RefreshReuseDetected`]: RefreshRefusal::RefreshReuseDetected
    pub fn is_terminal(&self) -> bool {
        match self {
            RefreshRefusal::SessionRevoked
            | RefreshRefusal::SessionExpired
            | RefreshRefusal::SessionIdleExpired => true,
            // A reuse signal can be a single-flight race, not theft — recoverable
            // by refreshing again with the current stored token.
            RefreshRefusal::RefreshReuseDetected => false,
        }
    }
}

/// A failure of the OAuth→session exchange or a session refresh.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The refresh was refused with one of the four typed codes.
    #[error("atlas session refused: {}", .0.code())]
    Refused(RefreshRefusal),
    /// The manager holds no session (signed out) — raised by
    /// [`NativeSessionManager::get_token_checked`](crate::client::NativeSessionManager::get_token_checked).
    #[error("atlas session: not signed in")]
    NoSession,
    /// A non-2xx that was not one of the typed refusal codes.
    #[error("atlas session: unexpected HTTP {status}")]
    Unexpected { status: u16 },
    /// The request did not complete.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A 2xx with a body that did not carry a usable session.
    #[error("atlas session: malformed response: {0}")]
    Malformed(String),
}

/// A failure of an OAuth authorization/token/device call.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// The authorization server returned an OAuth `error` (invalid_grant,
    /// access_denied, …).
    #[error("atlas oauth error: {error}{}", .description.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    Server {
        error: String,
        description: Option<String>,
    },
    /// The request did not complete.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A response body that did not parse.
    #[error("atlas oauth: malformed response: {0}")]
    Malformed(String),
    /// A callback URL that could not be parsed, or carried no `code`.
    #[error("atlas oauth: invalid callback: {0}")]
    InvalidCallback(String),
}

/// The device-flow poll outcome that is not yet a token. RFC 8628 §3.5.
#[derive(Debug, Error)]
pub enum DevicePollError {
    /// The user has not yet approved — keep polling at the interval.
    #[error("authorization_pending")]
    AuthorizationPending,
    /// The server asked the client to slow its polling.
    #[error("slow_down")]
    SlowDown,
    /// The device code expired before approval.
    #[error("expired_token")]
    ExpiredToken,
    /// The user denied the request.
    #[error("access_denied")]
    AccessDenied,
    /// Any other OAuth/transport failure.
    #[error(transparent)]
    Other(#[from] OAuthError),
}
