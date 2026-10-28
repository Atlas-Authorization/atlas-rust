//! # `actix` — framework-native session verification for [actix-web](https://docs.rs/actix-web)
//!
//! An [`AtlasClaims`] extractor over the crate's existing verifier
//! ([`AtlasBackend`]): a handler that takes it only runs with verified
//! [`Claims`], and a missing or invalid credential is answered `401` before the
//! handler is called. Verification is local (RS256 against the cached JWKS, issuer,
//! expiry, `azp` allowlist) — no network call on the hot path. Use
//! `Option<AtlasClaims>` for a route that serves anonymous and signed-in callers.
//!
//! Register the verifier once as app data:
//!
//! ```no_run
//! # #[cfg(feature = "reqwest-transport")]
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use actix_web::{web, App, HttpServer};
//! use atlasauth::{actix::AtlasClaims, AtlasBackend};
//!
//! async fn me(claims: AtlasClaims) -> String {
//!     format!("hello {}", claims.sub)
//! }
//!
//! let backend = web::Data::new(AtlasBackend::builder("https://auth.example.com")
//!     .jwks_url("https://auth.example.com/.well-known/jwks.json")
//!     .authorized_parties(["https://app.example.com"])
//!     .build()?);
//! let _server = HttpServer::new(move || App::new().app_data(backend.clone()).route("/me", web::get().to(me)));
//! # Ok(()) }
//! ```
//!
//! Fail closed: if the verifier was not registered, the extractor answers `500`, never lets the request through.

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;

use ::actix_web::dev::Payload;
use ::actix_web::http::header::{AUTHORIZATION, COOKIE};
use ::actix_web::http::StatusCode;
use ::actix_web::{web, FromRequest, HttpRequest, HttpResponse, ResponseError};
use thiserror::Error;

use crate::claims::Claims;
use crate::error::VerifyError;
use crate::verify::AtlasBackend;

/// Why a request was refused before its handler ran.
#[derive(Debug, Clone, Error)]
pub enum AtlasRejection {
    /// No `Authorization: Bearer` header and no `__session` cookie.
    #[error("atlas: no session credential on the request")]
    Missing,
    /// A credential was present but did not verify. The client only sees the coarse reason.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// The signed-in session lacks a required permission.
    #[error("atlas: the session lacks the required permission")]
    Forbidden,
    /// `web::Data<AtlasBackend>` was never registered with `App::app_data`.
    #[error("atlas: authentication is not configured")]
    NotConfigured,
}

impl ResponseError for AtlasRejection {
    fn status_code(&self) -> StatusCode {
        match self {
            AtlasRejection::Missing | AtlasRejection::Verify(_) => StatusCode::UNAUTHORIZED,
            AtlasRejection::Forbidden => StatusCode::FORBIDDEN,
            AtlasRejection::NotConfigured => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status_code());
        if self.status_code() == StatusCode::UNAUTHORIZED {
            response.insert_header(("WWW-Authenticate", "Bearer"));
        }
        response.body(self.to_string())
    }
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

    /// `Ok(())` when the session holds `permission`, else a 403 [`AtlasRejection::Forbidden`]: `claims.require("billing:read")?`.
    pub fn require(&self, permission: &str) -> Result<(), AtlasRejection> {
        if self.has(permission) {
            Ok(())
        } else {
            Err(AtlasRejection::Forbidden)
        }
    }
}

impl Deref for AtlasClaims {
    type Target = Claims;

    fn deref(&self) -> &Claims {
        &self.0
    }
}

impl FromRequest for AtlasClaims {
    type Error = AtlasRejection;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let backend = req.app_data::<web::Data<AtlasBackend>>().cloned();
        // A header with non-ASCII bytes reads as absent: a malformed header is "no credential".
        let authorization = req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let cookie = req.headers().get(COOKIE).and_then(|v| v.to_str().ok()).map(str::to_owned);
        Box::pin(async move {
            let backend = backend.ok_or(AtlasRejection::NotConfigured)?;
            let had_credential = authorization.is_some() || cookie.is_some();
            match backend.authenticate_request(authorization.as_deref(), cookie.as_deref()).await {
                Ok(claims) => Ok(AtlasClaims(claims)),
                Err(err) if had_credential => Err(AtlasRejection::Verify(err)),
                Err(_) => Err(AtlasRejection::Missing),
            }
        })
    }
}
