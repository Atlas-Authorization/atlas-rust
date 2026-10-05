//! The [`AtlasClaims`] extractor: verified session claims in a handler argument.

use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;

use ::axum::extract::{FromRef, FromRequestParts, OptionalFromRequestParts};
use ::axum::http::request::Parts;

use super::credentials_from_headers;
use super::rejection::AtlasRejection;
use crate::claims::Claims;
use crate::verify::AtlasBackend;

/// A verified Atlas session, ready to use in a handler.
///
/// Name it in a handler signature and the handler runs only once the request's
/// credential has been verified; otherwise the request is answered with a `401`
/// ([`AtlasRejection`]) and the handler is never entered. It is the thinnest
/// possible wrapper over [`Claims`] — it [`Deref`]s to it — so every claim
/// helper (`has_permission`, `has_role`, `real_email`, …) is available directly:
///
/// ```no_run
/// use atlasauth::axum::AtlasClaims;
///
/// async fn billing(claims: AtlasClaims) -> &'static str {
///     if claims.has_permission("billing:read") { "ok" } else { "forbidden" }
/// }
/// ```
///
/// The verifier is read from router state as `Arc<AtlasBackend>` (see the module
/// docs for why it is shared, not cloned). For a route that must serve both
/// anonymous and signed-in callers, extract `Option<AtlasClaims>` instead: it
/// attaches the claims when a valid session is present and yields `None`
/// otherwise, and never rejects.
#[derive(Debug, Clone)]
pub struct AtlasClaims(pub Claims);

impl AtlasClaims {
    /// The verified claims, by shared reference. (`AtlasClaims` also [`Deref`]s
    /// to [`Claims`], so this is rarely needed.)
    pub fn claims(&self) -> &Claims {
        &self.0
    }

    /// Consume the wrapper and take the owned [`Claims`].
    pub fn into_inner(self) -> Claims {
        self.0
    }

    /// Permission guard over the crate's existing [`Claims::has_permission`] —
    /// true when the active organization's `org_permissions` contains
    /// `permission`. A `.has(...)` spelling so a route guard reads as a guard.
    pub fn has(&self, permission: &str) -> bool {
        self.0.has_permission(permission)
    }
}

impl Deref for AtlasClaims {
    type Target = Claims;

    fn deref(&self) -> &Claims {
        &self.0
    }
}

// The verifier must be reachable from the app's state as the shared
// `Arc<AtlasBackend>`. That single `FromRef` bound is all the extractor asks of
// `S`, so it drops into an app with its own richer state as readily as one whose
// state is the verifier itself.
impl<S> FromRequestParts<S> for AtlasClaims
where
    S: Send + Sync,
    Arc<AtlasBackend>: FromRef<S>,
{
    type Rejection = AtlasRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let backend = Arc::<AtlasBackend>::from_ref(state);
        let (authorization, cookie) = credentials_from_headers(&parts.headers);
        let had_credential = authorization.is_some() || cookie.is_some();
        match backend.authenticate_request(authorization, cookie).await {
            Ok(claims) => Ok(AtlasClaims(claims)),
            Err(err) => Err(AtlasRejection::from_verify_error(err, had_credential)),
        }
    }
}

// The optional variant backing `Option<AtlasClaims>`. It attaches a verified
// session when one is present and valid, and is otherwise `None` — a missing OR
// invalid credential both read as "not signed in", never a rejection. A route
// that is public but does something extra for a known user extracts this.
impl<S> OptionalFromRequestParts<S> for AtlasClaims
where
    S: Send + Sync,
    Arc<AtlasBackend>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let backend = Arc::<AtlasBackend>::from_ref(state);
        let (authorization, cookie) = credentials_from_headers(&parts.headers);
        Ok(backend
            .authenticate_request(authorization, cookie)
            .await
            .ok()
            .map(AtlasClaims))
    }
}
