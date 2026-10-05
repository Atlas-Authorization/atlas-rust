//! # atlasauth
//!
//! The official **Rust backend verification crate** for [Atlas](https://atlasauth.net).
//! The Rust peer of `@atlasauth/backend`, `atlas-go`, and the Ruby SDK — same
//! verification semantics, same claim names, same `@no-email.invalid` handling.
//!
//! It does two things a Rust server needs:
//!
//! 1. **Verify a session token locally** against the instance JWKS — RS256 only,
//!    with an explicit issuer, `exp`/`nbf`/`iat` checks, and an in-process JWKS
//!    cache keyed by URL that refetches on an unknown `kid` at most once a
//!    minute. No outbound call on the hot path.
//! 2. **Verify an end-user API key** (`ak_…`) against Atlas, with separate
//!    positive and negative caches so a busy API — or a caller hammering a bad
//!    key — does not hammer Atlas.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use atlasauth::AtlasBackend;
//!
//! let backend = AtlasBackend::new(
//!     "https://your-instance-fapi.atlasauth.net",                         // issuer
//!     "https://your-instance-fapi.atlasauth.net/.well-known/jwks.json",   // jwks_url
//! )?;
//!
//! let claims = backend.verify(session_jwt()).await?;
//! if claims.has_permission("billing:read") {
//!     // authorized
//! }
//! # Ok(()) }
//! # fn session_jwt() -> &'static str { "" }
//! ```
//!
//! This is a **server-side** crate: it uses your instance secret key (`sk_…`)
//! for API-key verification and must never ship to a browser or mobile app.

#![forbid(unsafe_code)]

mod apikey;
mod claims;
mod clock;
mod error;
mod jwks;
mod user;
mod verify;

#[cfg(feature = "reqwest-transport")]
mod transport;

pub use apikey::{
    ApiKeyVerification, ApiKeyVerifier, ApiKeyVerifierBuilder, HttpPost, HttpResponse,
    DEFAULT_BASE_URL, DEFAULT_NEGATIVE_TTL_MS, DEFAULT_POSITIVE_TTL_MS,
};
pub use claims::Claims;
pub use clock::{system_clock, Clock};
pub use error::{ApiKeyError, ConfigError, TransportError, VerifyError};
pub use jwks::{
    BoxFuture, FetchOutcome, Jwk, Jwks, JwksCache, JwksSource, DEFAULT_TTL_MS, REFETCH_INTERVAL_MS,
};
pub use user::{real_email, EmailAddress, User, NO_EMAIL_SENTINEL_DOMAIN};
pub use verify::{AtlasBackend, AtlasBackendBuilder, AtlasBackendOptions, CLOCK_SKEW_SECONDS};

#[cfg(feature = "reqwest-transport")]
pub use transport::ReqwestTransport;
