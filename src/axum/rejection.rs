//! The `401` rejection the extractor and middleware return.

use ::axum::http::StatusCode;
use ::axum::response::{IntoResponse, Response};
use thiserror::Error;

use crate::error::VerifyError;

/// Why an Axum request was rejected before its handler ran. It is an
/// [`IntoResponse`] that always renders a `401 Unauthorized` — the one verdict a
/// caller of a protected route needs, and no more. The underlying
/// [`VerifyError`] is preserved (and kept deliberately coarse, mirroring the
/// verifier) so a server can log the reason, but the body sent to the client is
/// just the coarse message: telling an attacker whether the signature, the
/// issuer or the expiry was the problem helps them refine a forgery far more
/// than it helps a real developer.
#[derive(Debug, Clone, Error)]
pub enum AtlasRejection {
    /// The request carried no credential at all — neither an
    /// `Authorization: Bearer …` header nor a `__session` cookie.
    #[error("atlas: no session credential on the request")]
    Missing,
    /// A credential was present but failed verification (signature, issuer,
    /// expiry, algorithm, token-use, audience, unknown key, …).
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

impl AtlasRejection {
    /// Classify a verifier result, promoting the "no token present" case
    /// (`authenticate_request` reports it as [`VerifyError::Malformed`]) to the
    /// clearer [`AtlasRejection::Missing`]. Both still answer the client with
    /// the same `401`; the distinction exists only so a server log can tell
    /// "no token" apart from "a token that did not verify". The `#[from]` on the
    /// `Verify` variant keeps `?` ergonomic where the distinction is not needed.
    pub(crate) fn from_verify_error(err: VerifyError, had_credential: bool) -> Self {
        if had_credential {
            AtlasRejection::Verify(err)
        } else {
            AtlasRejection::Missing
        }
    }
}

impl IntoResponse for AtlasRejection {
    fn into_response(self) -> Response {
        // One status for every variant — a protected route either got a good
        // session or it did not. The message is the coarse reason only.
        (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
    }
}
