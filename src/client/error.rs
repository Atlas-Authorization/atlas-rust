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

    /// Whether the session is permanently gone (re-run OAuth) rather than this
    /// being a transient condition.
    pub fn is_terminal(&self) -> bool {
        // All four mean the current session cannot be refreshed; a native app
        // treats every one as "sign in again". Exposed as a method so callers
        // can branch without matching every variant.
        true
    }
}

/// A failure of the OAuth→session exchange or a session refresh.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The refresh was refused with one of the four typed codes.
    #[error("atlas session refused: {}", .0.code())]
    Refused(RefreshRefusal),
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
