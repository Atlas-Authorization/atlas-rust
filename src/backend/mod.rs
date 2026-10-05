//! # P0-2 — the Atlas Backend API management client
//!
//! The Rust peer of `@atlasauth/backend`'s `createAtlasClient`: the secret-key
//! (`sk_…`) management surface, a typed webhook verifier, and a cursor
//! paginator. It is built on the object-safe [`crate::HttpTransport`] so it runs
//! anywhere a `fetch` would and takes an injected mock in tests
//! ([`FakeTransport`]).
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use atlasauth::backend::{BackendClient, CursorParams};
//!
//! let atlas = BackendClient::new("sk_live_…")?;
//! let user = atlas.users().get("user_123").await?;
//! let first_page = atlas.users().list(CursorParams::default()).await?;
//! # let _ = (user, first_page); Ok(()) }
//! ```

mod client;
mod error;
mod pagination;
mod resources;
mod testing;
mod webhook;

pub use client::{
    BackendClient, BackendClientBuilder, DEFAULT_API_URL, DEFAULT_BASE_DELAY_MS, DEFAULT_MAX_RETRIES,
};
pub use error::{AtlasApiError, AtlasErrorItem, BackendError};
pub use pagination::{collect, CursorPage, CursorParams};
pub use resources::{
    AllGrantsRevocation, ApiKey, ApiKeyWithSecret, ApiKeys, Billing, BillingPlan,
    BillingSubscription, CreateApiKeyBody, CreateBillingPlanBody, CreateOrganizationBody,
    CreateUserBody, CustomDomain, DeletedObject, Domains, Grant, GrantRevocation, Grants,
    Invitation, Invitations, ListPage, Metadata, MintedSession, OrgDomain, OrgDomains,
    OrgInvitations, OrgMemberships, Organization, OrganizationInvitation, OrganizationMembership,
    OrganizationPolicy, Organizations, Session, Sessions, UpdateOrganizationBody, UpdateUserBody,
    User, Users,
};
pub use testing::FakeTransport;
pub use webhook::{
    Event, EventType, Webhook, WebhookError, WebhookHeaders, HEADER_ID, HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
};
