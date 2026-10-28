//! # `rocket` — framework-native session verification for [Rocket](https://docs.rs/rocket)
//!
//! An [`AtlasClaims`] request guard over the crate's existing verifier
//! ([`AtlasBackend`]): a route that takes it only runs with verified [`Claims`], and a
//! missing or invalid credential is answered `401`. Verification is local (RS256 against
//! the cached JWKS, issuer, expiry, `azp` allowlist). Use `Option<AtlasClaims>` for a
//! route that serves anonymous and signed-in callers.
//!
//! Manage the verifier once, as an `Arc<AtlasBackend>`:
//!
//! ```no_run
//! # #[cfg(feature = "reqwest-transport")]
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use atlasauth::{rocket::AtlasClaims, AtlasBackend};
//!
//! #[::rocket::get("/me")]
//! fn me(claims: AtlasClaims) -> String {
//!     format!("hello {}", claims.sub)
//! }
//!
//! let backend = Arc::new(AtlasBackend::builder("https://auth.example.com")
//!     .jwks_url("https://auth.example.com/.well-known/jwks.json")
//!     .authorized_parties(["https://app.example.com"])
//!     .build()?);
//! let _rocket = ::rocket::build().manage(backend).mount("/", ::rocket::routes![me]);
//! # Ok(()) }
//! ```
//!
//! Fail closed: if the verifier was not managed, the guard fails with `500`.

use std::ops::Deref;
use std::sync::Arc;

use ::rocket::http::Status;
use ::rocket::request::{FromRequest, Outcome, Request};
use thiserror::Error;

use crate::claims::Claims;
use crate::error::VerifyError;
use crate::verify::AtlasBackend;

/// Why the guard refused a request.
#[derive(Debug, Clone, Error)]
pub enum AtlasRejection {
    /// No `Authorization: Bearer` header and no `__session` cookie.
    #[error("atlas: no session credential on the request")]
    Missing,
    /// A credential was present but did not verify.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// `Arc<AtlasBackend>` was never managed with `Rocket::manage`.
    #[error("atlas: authentication is not configured")]
    NotConfigured,
}

/// The verified claims of the request's Atlas session. Derefs to [`Claims`].
#[derive(Debug, Clone)]
pub struct AtlasClaims(pub Claims);

impl AtlasClaims {
    pub fn claims(&self) -> &Claims {
        &self.0
    }

    pub fn into_inner(self) -> Claims {
        self.0
    }

    /// True when the session's organization permissions include `permission`.
    pub fn has(&self, permission: &str) -> bool {
        self.0.has_permission(permission)
    }

    /// `Ok(())` when the session holds `permission`, else `Status::Forbidden`: `claims.require("billing:read")?`.
    pub fn require(&self, permission: &str) -> Result<(), Status> {
        if self.has(permission) {
            Ok(())
        } else {
            Err(Status::Forbidden)
        }
    }
}

impl Deref for AtlasClaims {
    type Target = Claims;

    fn deref(&self) -> &Claims {
        &self.0
    }
}

#[::rocket::async_trait]
impl<'r> FromRequest<'r> for AtlasClaims {
    type Error = AtlasRejection;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(backend) = req.rocket().state::<Arc<AtlasBackend>>() else {
            return Outcome::Error((Status::InternalServerError, AtlasRejection::NotConfigured));
        };
        let authorization = req.headers().get_one("Authorization");
        let cookie = req.headers().get_one("Cookie");
        let had_credential = authorization.is_some() || cookie.is_some();
        match backend.authenticate_request(authorization, cookie).await {
            Ok(claims) => Outcome::Success(AtlasClaims(claims)),
            Err(err) if had_credential => Outcome::Error((Status::Unauthorized, AtlasRejection::Verify(err))),
            Err(_) => Outcome::Error((Status::Unauthorized, AtlasRejection::Missing)),
        }
    }
}
