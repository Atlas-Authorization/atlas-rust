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

mod better_auth;
mod catalog;
mod client;
mod design;
mod error;
mod instance;
mod machines;
mod pagination;
mod platform;
mod platform_api;
mod policies;
mod resources;
mod settings_helpers;
mod testing;
pub mod types;
mod webhook;

pub use better_auth::{
    better_auth_cookie_names, client_ip_from_headers, exchange_better_auth_session, read_better_auth_session_cookie,
    split_bundle_parts, BetterAuthBridge, BetterAuthExchangeResult, BridgeAction, BridgeCookie, BridgeDecision,
    BridgeRefusal, BridgedSession, ExchangeParams, UploadOptions, WaitOptions, BETTER_AUTH_COOKIE_PREFIX,
    BETTER_AUTH_EXCHANGE_PATH, BETTER_AUTH_IMPORT_IN_FLIGHT, BETTER_AUTH_IMPORT_PART_BYTES, CLIENT_IP_HEADER,
    CLIENT_USER_AGENT_HEADER,
};
pub use catalog::*;
pub use settings_helpers::{
    BILLING_PROVIDERS, CAPTCHA_PROVIDERS, EMAIL_TEMPLATE_ACCOUNT_REACTIVATED, LINKING_TRUST_LEVELS, SIGNING_KEY_PROVIDERS,
};
pub use client::{
    BackendClient, BackendClientBuilder, UnknownFields, UnknownFieldsHook, ATLAS_STRICT_HEADER,
    ATLAS_UNKNOWN_FIELDS_HEADER, DEFAULT_API_URL, DEFAULT_BASE_DELAY_MS, DEFAULT_MAX_RETRIES,
};
pub use design::{
    sniff_image_content_type, AtlasDesign, DesignApi, DesignAsset, DesignAssetKind, DesignBackground,
    DesignBackgroundImage, DesignButtons, DesignCard, DesignElevation, DesignGradient,
    DesignGradientStop, DesignInputs, DesignLayout, DesignLogo, DesignOverlay, DesignPalette,
    DesignPreview, DesignSettings, DesignShape, DesignSpacing, DesignTypography, DesignWarning,
};
pub use error::{codes, AtlasApiError, AtlasErrorItem, BackendError};
pub use instance::{
    cookie_settings_link_presets, AllowedOriginEntry, AwsSnsConfig, BandwidthConfig, BrevoConfig, ClicksendConfig,
    CookieConsent, CookieSettingsLink, DeclaredCookie, SdkAdvisory, SdkVersionSeen, CookieSettingsLinkInput, DeleteMessagingProviderParams,
    EmailProviderConfig, InfobipConfig, Instance, MailgunConfig, MessagebirdConfig, MessagingChannel, MessagingProvider,
    MessagingProviders, MessagingProvidersApi, OAuthProvider, OAuthProviderFilter, OAuthProviderUpdate,
    OAuthProviders, PlivoConfig, Preflight, PreflightFinding, ResendConfig, SesConfig,
    SetCookieConsentBody, SinchConfig, SmsProviderConfig, SmtpConfig, TelnyxConfig, TwilioConfig,
    UpdateWebhookEndpointBody, UpsertOAuthProviderBody, VonageConfig, WalletSettings, WebhookDelivery,
    RotateWebhookSecretBody, WebhookDeliveryReceipt, WebhookEndpoint, WebhookEndpointList, WebhookEndpoints,
    WebhookSecret,
};
pub use pagination::{collect, CursorPage, CursorParams, Query};
pub use platform_api::{
    AtlasIdApp, AtlasIdAppBranding, AtlasIdAppBrandingInput, AtlasIdAppCopy, AtlasIdAppList,
    AtlasIdApps, AtlasIdPublisherApi, CreateAtlasIdAppBody, CreatePlatformAppBody, PlatformApi, PlatformApp, PlatformApps,
    RotateAtlasIdAppSecretBody, RotatePlatformSecretBody, UpdateAtlasIdAppBody, UpdatePlatformAppBody,
};
pub use machines::{
    CreateEnrolmentTokenBody, CreateMachineBody, EnrolMachineBody, EnrolledMachine, EnrolmentToken,
    ListEnrolmentTokensParams, M2mVerification, Machine, MachineChallenge, MachineFilter,
    MachineOrgMembership, MachineToken, MachineWithSecret, Machines, OrgFilter, RedeemedEnrolment,
};
pub use resources::{
    AllGrantsRevocation, ApiKey, ApiKeyToken, ApiKeyWithSecret, ApiKeys, Billing, BillingPlan,
    BillingSubscription, CreateApiKeyBody, CreateBillingPlanBody, CreateOrganizationBody,
    CreateUserBody, CustomDomain, DeletedObject, Domains, Grant, GrantRevocation, Grants,
    EndUserPoolPolicy, ImportApiKey, Invitation, Invitations, ListPage, Metadata, MintApiKeyTokenBody,
    MintedSession, OrgDomain, OrgPolicy, OrgPolicyPatch,
    OrgDomains, OrgInvitations, OrgMemberships, Organization, OrganizationInvitation,
    OrganizationMembership, OrganizationPolicy, Organizations, RevokedApiKey, Session, Sessions,
    UpdateApiKeyBody, UpdateOrganizationBody, UpdateUserBody, User, Users,
    CreateUserReferral, UserReferralAttributedEvent, UserReferralFlag,
};
pub use platform::{
    AuditActor, AuditEvent, AuditEventFilter, AuditEvents, AuditTarget, CreateEntitlementOverrideBody,
    CreateTicketBody, EffectiveEntitlements, EntitlementOverride, EntitlementOverrides, ErasureAck,
    ErasureStatus, NotificationCategories, NotificationCategory, NotificationCategoryBody,
    NotificationTemplate, NotificationTemplateBody, NotificationTemplates, Notifications, OrgBranding,
    OrgPlatform, OrgSettings, OrgSettingsSchema, OrgSettingsSchemaApi, RedeemedTicket,
    ScheduleDeletionBody, SendNotificationBody, SetOrgBrandingBody, Ticket, Tickets, UserErasure,
    WriteAuditEventBody,
};
pub use testing::FakeTransport;
pub use webhook::{
    Event, EventType, VerifiedDelivery, Webhook, WebhookError, WebhookHeaders, HEADER_ID,
    HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
