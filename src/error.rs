//! Error types for the crate.
//!
//! Verification failures are deliberately coarse — telling a caller whether the
//! signature, the issuer or the expiry was wrong helps someone refining a forged
//! token far more than it helps a developer debug a real one. This mirrors the
//! TypeScript `@atlasauth/backend`, `atlas-go`, and Ruby verifiers, whose reasons
//! are exactly `malformed` / `invalid` / `no_keys` / `unauthorized_party`.

use thiserror::Error;

/// Why a session-token verification failed. Coarse by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The token is not a well-formed JWT (not three `.`-separated segments).
    #[error("atlas: token verification failed: malformed")]
    Malformed,
    /// The token failed a cryptographic or claim check (signature, issuer,
    /// expiry, `nbf`, algorithm, token-use, audience, …). One reason for every
    /// such failure, on purpose.
    #[error("atlas: token verification failed: invalid")]
    Invalid,
    /// No usable verification key was available (empty or unreachable JWKS).
    #[error("atlas: token verification failed: no_keys")]
    NoKeys,
    /// The token's `azp` was not on the configured authorized-parties allowlist.
    #[error("atlas: token verification failed: unauthorized_party")]
    UnauthorizedParty,
}

/// A configuration error raised when building an [`crate::AtlasBackend`] or
/// [`crate::ApiKeyVerifier`] with an impossible combination of options.
#[derive(Debug, Clone, Error)]
#[error("atlas: {0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        ConfigError(msg.into())
    }
}

/// A transport-level failure while talking to a remote endpoint (JWKS fetch or
/// the API-key verify endpoint). Carries a human-readable message only; it is
/// never surfaced to an end user.
#[derive(Debug, Clone, Error)]
#[error("atlas: transport error: {0}")]
pub struct TransportError(pub String);

impl TransportError {
    pub fn new(msg: impl Into<String>) -> Self {
        TransportError(msg.into())
    }
}

/// The result of an API-key verification call.
#[derive(Debug, Error)]
pub enum ApiKeyError {
    /// The verify endpoint could not be reached, or returned a non-2xx status
    /// (e.g. a bad `sk_` secret key → 401). Distinct from a *valid* "this key is
    /// not good" verdict, which is an [`crate::ApiKeyVerification`] with
    /// `valid == false`, not an error.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The endpoint replied 2xx but with a body that did not parse.
    #[error("atlas: malformed api-key verify response: {0}")]
    Malformed(String),
}
