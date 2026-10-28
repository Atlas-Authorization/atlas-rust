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

mod access_token;
mod apikey;
mod claims;
mod clock;
mod dpop;
#[cfg(any(feature = "backend", feature = "client"))]
mod introspection;
#[cfg(feature = "backend")]
mod botid;
#[cfg(feature = "sealed-box")]
mod sealed_box;
mod error;
mod jwks;
mod key_format;
mod legacy_issuers;
#[cfg(feature = "backend")]
mod policy_source;
mod logout;
mod oidc_claims;
mod user;
mod verify;

#[cfg(feature = "reqwest-transport")]
mod transport;

// The richer transport trait the management client and native-client flows
// share. Compiled only when one of those features is on.
#[cfg(any(feature = "backend", feature = "client"))]
pub mod http;

/// P0-2 — the typed Backend-API management client, the typed webhook verifier,
/// and the cursor-pagination helper. See the `backend` feature.
#[cfg(feature = "backend")]
pub mod backend;

/// P0-1 — the native (first-party) client SDK: PKCE + device OAuth flows, the
/// OAuth→session exchange, the session manager, `SecureStore`, and the
/// `/v1/client/me/**` self-service surface. See the `client` feature.
#[cfg(feature = "client")]
pub mod client;

/// Framework-native [Axum](https://docs.rs/axum) integration — the [`AtlasClaims`]
/// extractor, the [`AtlasLayer`] tower middleware, and the [`require_auth`]
/// helper — built on the crate's existing [`AtlasBackend`] verifier. See the
/// `axum` feature.
///
/// [`AtlasClaims`]: axum::AtlasClaims
/// [`AtlasLayer`]: axum::AtlasLayer
/// [`require_auth`]: axum::require_auth
#[cfg(feature = "axum")]
pub mod axum;

/// Framework-native [actix-web](https://docs.rs/actix-web) integration — the
/// [`AtlasClaims`](actix::AtlasClaims) extractor over the existing [`AtlasBackend`]
/// verifier. See the `actix` feature.
#[cfg(feature = "actix")]
pub mod actix;

/// Framework-native [Rocket](https://docs.rs/rocket) integration — the
/// [`AtlasClaims`](rocket::AtlasClaims) request guard over the existing
/// [`AtlasBackend`] verifier. See the `rocket` feature.
#[cfg(feature = "rocket")]
pub mod rocket;

pub use apikey::{
    ApiKeyCap, ApiKeyCapUsage, ApiKeyVerification, ApiKeyVerifier, ApiKeyVerifierBuilder, HttpPost,
    HttpResponse,
    DEFAULT_BASE_URL, DEFAULT_MAX_ENTRIES, DEFAULT_NEGATIVE_TTL_MS, DEFAULT_POSITIVE_TTL_MS,
};
pub use access_token::{
    build_challenge, build_www_authenticate, protected_resource_metadata, protected_resource_metadata_path,
    protected_resource_metadata_requiring_dpop, AccessTokenOptions, AccessTokenResult, ResourceRequest,
};
#[cfg(any(feature = "backend", feature = "client"))]
pub use introspection::{IntrospectionError, IntrospectionOptions, Introspector};
#[cfg(feature = "backend")]
pub use policy_source::{
    sign_policy_source_body, sign_policy_source_event, sign_policy_source_event_at, verify_policy_feed_request,
    PolicyFeedFailure, PolicyFeedRequest, PolicySourceEvent, SignedPolicyEvent, VerifiedPolicyFeedRequest,
    POLICY_SOURCE_PROTOCOL_VERSION, POLICY_SOURCE_TOLERANCE_MS, POLICY_SOURCE_VERSION_HEADER,
};
#[cfg(feature = "backend")]
pub use botid::{
    create_botid_attestation, BOTID_ATTESTATION_MAX_TTL_SECONDS, BOTID_ATTESTATION_PREFIX, BOTID_SECRET_MIN_LENGTH,
};
pub use dpop::{
    dpop_access_token_hash, jwk_thumbprint, normalize_htu, DpopNonceSource, DpopReplayStore, HmacDpopNonceSource,
    MemoryDpopReplayStore, DPOP_ALGS, DPOP_CLOCK_SKEW_SECONDS, DPOP_PROOF_MAX_AGE_SECONDS,
};
#[cfg(feature = "sealed-box")]
pub use sealed_box::{
    generate_seal_key_pair, open_sealed_box, open_sealed_secret, seal_box, SealKeyPair, SealedBoxError,
};
pub use claims::Claims;
pub use oidc_claims::{
    oidc_authorize_url_with_organization, oidc_organization_of, oidc_organizations_of, oidc_sso_of, OidcOrganization,
    OidcOrganizationMembership, OidcSsoContext, OIDC_ORGANIZATION_PARAM, OIDC_SCOPE_ORGANIZATIONS,
};
pub use key_format::{
    is_access_token, is_partner_link_secret, is_platform_key, is_publishable_key, is_secret_key, is_webhook_secret,
    parse_key_prefix, KeyKind, ParsedKey,
};
pub use clock::{system_clock, Clock};
pub use error::{ApiKeyError, ConfigError, TransportError, VerifyError};
pub use jwks::{
    SIGNING_ALGS,
    BoxFuture, FetchOutcome, Jwk, Jwks, JwksCache, JwksSource, DEFAULT_TTL_MS, REFETCH_INTERVAL_MS,
};
pub use user::{real_email, EmailAddress, User, NO_EMAIL_SENTINEL_DOMAIN};
pub use logout::{
    BackchannelLogoutResponse, LogoutTokenClaims, LogoutTokenReplayCache, BACKCHANNEL_LOGOUT_EVENT,
    BACKCHANNEL_RETRY_AFTER_SECONDS, LOGOUT_TOKEN_TYPE,
};
pub use legacy_issuers::{
    LegacyIssuer, SubjectResolver, LEGACY_ISSUER_ALGS, LEGACY_SUBJECT_CACHE_MAX, LEGACY_SUBJECT_TTL_MS,
};
#[cfg(feature = "backend")]
pub use legacy_issuers::BackendSubjectResolver;
pub use verify::{AtlasBackend, AtlasBackendBuilder, AtlasBackendOptions, CLOCK_SKEW_SECONDS};

#[cfg(feature = "reqwest-transport")]
pub use transport::ReqwestTransport;

#[cfg(any(feature = "backend", feature = "client"))]
pub use http::{HttpBytesResponse, HttpFullResponse, HttpMethod, HttpRequest, HttpTransport};
