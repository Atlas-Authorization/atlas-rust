//! # `axum` — framework-native session verification for [Axum](https://docs.rs/axum)
//!
//! The Rust peer of Auth0's `go-jwt-middleware`: a thin, framework-native layer
//! over the crate's EXISTING verifier ([`crate::AtlasBackend`]) so an Axum app
//! protects a route the idiomatic way — an extractor on a handler, or a
//! [`tower::Layer`] on a whole `Router` — without ever re-implementing crypto.
//! Every token still travels through [`AtlasBackend::verify`] /
//! [`AtlasBackend::authenticate_request`]: local RS256, cached JWKS, no network
//! on the hot path. This module only moves the token out of the request and the
//! verdict back in.
//!
//! Two integration styles, both shown below:
//!
//! 1. The [`AtlasClaims`] extractor — put it in a handler signature and the
//!    handler only runs with verified [`Claims`] in hand; an absent or invalid
//!    credential is turned into `401` before the handler is called. Use
//!    `Option<AtlasClaims>` for a route that serves both anonymous and
//!    authenticated callers (it never rejects).
//! 2. The [`AtlasLayer`] tower middleware (or the [`require_auth`]
//!    `from_fn`-style helper) — `.layer(...)` it onto a `Router` and every route
//!    underneath is gated, with the verified [`Claims`] inserted into request
//!    extensions for downstream extractors.
//!
//! ## Wiring the verifier through state
//!
//! The verifier is supplied through Axum state as an `Arc<AtlasBackend>`. It is
//! an `Arc` and not a bare `AtlasBackend` on purpose: [`AtlasBackend`] owns a
//! live JWKS cache (an interior `Mutex`) and so is deliberately **not** `Clone` —
//! every clone must share the one cache, never copy it, or the kid-miss refetch
//! throttle would be defeated. `Arc<AtlasBackend>: FromRef<S>` is the single
//! bound the extractor needs, so it composes with any app state that can hand
//! back the shared verifier.
//!
//! ```no_run
//! # #[cfg(feature = "reqwest-transport")]
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use axum::{routing::get, Router};
//! use atlasauth::{AtlasBackend, axum::AtlasClaims};
//!
//! let backend = Arc::new(AtlasBackend::new(
//!     "https://your-instance-fapi.atlasauth.net",
//!     "https://your-instance-fapi.atlasauth.net/.well-known/jwks.json",
//! )?);
//!
//! async fn me(claims: AtlasClaims) -> String {
//!     // `claims` is verified; `AtlasClaims` derefs to `Claims`.
//!     format!("hello {}", claims.sub)
//! }
//!
//! // `Arc<AtlasBackend>` as the router state gives `FromRef` for free.
//! let app: Router = Router::new().route("/me", get(me)).with_state(backend);
//! # let _ = app; Ok(()) }
//! ```

use ::axum::http::header::{AUTHORIZATION, COOKIE};
use ::axum::http::HeaderMap;

mod claims;
mod middleware;
mod rejection;

pub use claims::AtlasClaims;
pub use middleware::{require_auth, AtlasAuth, AtlasLayer};
pub use rejection::AtlasRejection;

/// Pull the two credential-bearing headers out of a request as plain `&str`,
/// ready for [`crate::AtlasBackend::authenticate_request`] (which applies the
/// `Bearer `-wins-over-`__session`-cookie precedence itself).
///
/// A header with non-ASCII bytes simply reads as absent rather than erroring —
/// a malformed header is "no credential", which is already handled as a `401`,
/// and the verifier should never be the thing that panics on garbage input.
pub(crate) fn credentials_from_headers(headers: &HeaderMap) -> (Option<&str>, Option<&str>) {
    let authorization = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    let cookie = headers.get(COOKIE).and_then(|v| v.to_str().ok());
    (authorization, cookie)
}
