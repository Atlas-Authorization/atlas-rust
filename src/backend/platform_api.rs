//! The Platform API (`/v1/platform/*`), authenticated with a platform key
//! (`psk_…`): provision and manage the apps your platform owns, register
//! Sign in with Atlas apps, and manage their design images.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use atlasauth::backend::{BackendClient, CreateAtlasIdAppBody};
//! let platform = BackendClient::new("psk_live_…")?;
//! let app = platform
//!     .platform()
//!     .atlas_id_apps()
//!     .create(
//!         &CreateAtlasIdAppBody {
//!             name: "Acme".into(),
//!             redirect_uris: vec!["https://acme.example/callback".into()],
//!             ..Default::default()
//!         },
//!         None,
//!     )
//!     .await?;
//! println!("client_id={} secret={:?}", app.client_id, app.client_secret);
//! # Ok(()) }
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::design::{content_type_for, AtlasDesign, DesignAsset, DesignAssetKind, DesignPreview};
use super::error::BackendError;
use super::pagination::Query;
use super::instance::AllowedOriginEntry;
use super::resources::{body_of, seg, ListPage};

// ── Sign in with Atlas apps ───────────────────────────────────────────────

/// Sign-in page copy for a Sign in with Atlas app. Plain text, one line; `{app}`
/// is replaced with the app name. In an update, `Some(None)` clears a field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AtlasIdAppCopy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_title: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_subtitle: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_up_title: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_up_subtitle: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_message: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_label: Option<Option<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Branding for a Sign in with Atlas app's sign-in page. In a request, every
/// field is optional and merged per field; `Some(None)` sends `null` to clear
/// it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AtlasIdAppBrandingInput {
    /// `auto`, `light`, or `dark`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<Option<String>>,
    /// `#RRGGBB`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copy: Option<Option<AtlasIdAppCopy>>,
    /// A structured design (images must be uploaded with
    /// [`PlatformApi::upload_design_asset`]). `Some(None)` removes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub design: Option<Option<AtlasDesign>>,
}

/// A Sign in with Atlas app's branding, as returned.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AtlasIdAppBranding {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub accent_color: Option<String>,
    #[serde(default)]
    pub background_color: Option<String>,
    #[serde(default)]
    pub privacy_policy_url: Option<String>,
    #[serde(default)]
    pub terms_of_service_url: Option<String>,
    #[serde(default)]
    pub copy: Map<String, Value>,
    #[serde(default)]
    pub design: Option<AtlasDesign>,
    #[serde(default)]
    pub resolved_design: Option<AtlasDesign>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A Sign in with Atlas app (an OpenID Connect client on atlasauth.net).
#[derive(Debug, Clone, Deserialize)]
pub struct AtlasIdApp {
    pub id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub homepage_url: Option<String>,
    #[serde(default)]
    pub branding: Option<AtlasIdAppBranding>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// `confidential` or `public`.
    #[serde(default, rename = "type")]
    pub app_type: String,
    #[serde(default)]
    pub secret_prefix: Option<String>,
    #[serde(default)]
    pub managed_by_instance_id: Option<String>,
    /// `instance_toggle` (an instance's Sign in with Atlas toggle app) or
    /// `adopted` (handed to an instance with `set_managed_by`); `None` otherwise.
    #[serde(default)]
    pub managed_via: Option<String>,
    /// The page origins the Sign in with Atlas button script ran on in the last 7 days (on get).
    #[serde(default)]
    pub button_rendered_origins: Vec<super::types::AtlasIdAppPreflightButtonRenderedOriginsItem>,
    /// With a secret recipient: `client_secret` sealed to it.
    #[serde(default)]
    pub sealed_client_secret: Option<String>,
    /// With a secret recipient: `webhook_secret` sealed to it.
    #[serde(default)]
    pub sealed_webhook_secret: Option<String>,
    /// With a secret recipient: the fields that arrived sealed.
    #[serde(default)]
    pub secrets_sealed: Option<super::types::SecretsSealed>,
    /// People who have signed in to the app (on get).
    #[serde(default)]
    pub user_count: Option<u64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<i64>,
    /// Present only on create and rotate_secret, exactly once.
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// The per-app webhook URL, or `None`.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// The events the per-app webhook gets.
    #[serde(default)]
    pub webhook_events: Vec<String>,
    /// `Some(false)` once auto-disabled after repeated failures; `None` without a webhook.
    #[serde(default)]
    pub webhook_active: Option<bool>,
    /// The per-app webhook signing secret, returned exactly once (first set, or rotated).
    #[serde(default)]
    pub webhook_secret: Option<String>,
    /// While a webhook secret rotation overlap is open: when the previous
    /// secret stops signing deliveries (epoch ms).
    #[serde(default)]
    pub webhook_previous_secret_expires_at: Option<i64>,
    /// After a client secret rotation with an overlap: when the previous
    /// secret stops working (epoch ms).
    #[serde(default)]
    pub previous_secret_expires_at: Option<i64>,
    /// When the current client secret was issued (epoch ms); `None` for a
    /// public app.
    #[serde(default)]
    pub secret_issued_at: Option<i64>,
    /// On a rotation: the overlap applied, in seconds.
    #[serde(default)]
    pub overlap_seconds: Option<u64>,
    /// Test sign-in mode: `+atlas_test` addresses on a verified domain sign in
    /// to this app with the fixed code 424242. Off by default.
    #[serde(default)]
    pub test_mode: Option<bool>,
    /// Test and review accounts must use an address on a domain you verified.
    #[serde(default)]
    pub provisioned_verified_domains_only: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The body of `POST /v1/platform/atlas_id_apps/:id/rotate_secret`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RotateAtlasIdAppSecretBody {
    /// How long the previous client secret keeps working, in seconds. `None`
    /// uses the default, 86400 (24 hours); `0` revokes it now; at most 604800.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_seconds: Option<u64>,
}

impl RotateAtlasIdAppSecretBody {
    /// A body with no overlap set (the server default applies).
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `overlap_seconds` (`0` stops the previous secret now).
    pub fn with_overlap_seconds(mut self, seconds: u64) -> Self {
        self.overlap_seconds = Some(seconds);
        self
    }
}

/// The body of `POST /v1/platform/apps/:id/instances/:instance_id/rotate_secret`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RotatePlatformSecretBody {
    /// How long the prior keys keep working, in seconds. `None` uses the
    /// default, 259200 (72 hours); `0` revokes them now; at most 604800.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_seconds: Option<u64>,
}

impl RotatePlatformSecretBody {
    /// A body with no overlap set (the server default applies).
    pub fn new() -> Self {
        Self::default()
    }
    /// Set `overlap_seconds` (`0` stops the previous secret now).
    pub fn with_overlap_seconds(mut self, seconds: u64) -> Self {
        self.overlap_seconds = Some(seconds);
        self
    }
}

/// The app list, with the issuer and discovery URL your OIDC client uses.
#[derive(Debug, Clone, Deserialize)]
pub struct AtlasIdAppList {
    #[serde(default)]
    pub data: Vec<AtlasIdApp>,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub discovery_url: String,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `POST /v1/platform/atlas_id_apps`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateAtlasIdAppBody {
    pub name: String,
    /// Exact-match https URLs (`http://localhost` allowed).
    pub redirect_uris: Vec<String>,
    /// `confidential` (default; gets a client secret) or `public` (PKCE).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub app_type: Option<String>,
    /// `openid` (always), `profile`, `email`, `offline_access`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    /// Exact-match sign-out return URLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Where Atlas POSTs an OIDC back-channel `logout_token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    /// A page Atlas loads in an iframe on sign-out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branding: Option<AtlasIdAppBrandingInput>,
}

/// Body for `PATCH /v1/platform/atlas_id_apps/:id`. Double `Option`s send
/// `null` (clear) with `Some(None)`; an empty `Vec` clears a URI list.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateAtlasIdAppBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branding: Option<Option<AtlasIdAppBrandingInput>>,
    /// Per-app webhook (public https): user.updated, user.deleted and
    /// grant.revoked for this app's users. The first set returns
    /// `webhook_secret` once; `Some(None)` removes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<Option<String>>,
    /// Turn test sign-in mode on or off. Turning it on needs a verified domain
    /// on the account (422 `DOMAIN_NOT_VERIFIED` otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_mode: Option<bool>,
    /// Require test and review accounts to use an address on a domain you verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioned_verified_domains_only: Option<bool>,
}

// ── Test and review accounts ──────────────────────────────────────────────

/// An app a provisioned account is confined to.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct AtlasIdProvisionedAccountApp {
    pub id: String,
    pub client_id: String,
    pub name: String,
}

/// A Sign in with Atlas test or review account: a real Atlas account confined
/// to the app(s) it was made for. The password is present only on create and
/// password rotation (exactly once); with a secret recipient it arrives as
/// `sealed_password` instead. `Debug` never prints either.
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
pub struct AtlasIdProvisionedAccount {
    pub object: String,
    pub id: String,
    /// The Atlas ID subject the app sees.
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub label: String,
    /// `provisioned`, `test_mode` or `developer`.
    pub kind: String,
    /// `app` or `staff`.
    pub provisioned_by: String,
    pub app_ids: Vec<String>,
    pub apps: Vec<AtlasIdProvisionedAccountApp>,
    pub any_app: bool,
    pub two_factor_exempt: bool,
    /// Epoch ms; `None` = never expires.
    pub expires_at: Option<i64>,
    pub expired: bool,
    pub developer_account_id: Option<String>,
    pub created_by: Value,
    pub last_sign_in_at: Option<i64>,
    pub password_rotated_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Only on create and password rotation: the password, returned once.
    pub password: Option<String>,
    /// With a secret recipient: the password sealed to it (open it with
    /// [`open_sealed_secret`](crate::open_sealed_secret)).
    pub sealed_password: Option<String>,
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl std::fmt::Debug for AtlasIdProvisionedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtlasIdProvisionedAccount")
            .field("id", &self.id)
            .field("sub", &self.sub)
            .field("email", &self.email)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("app_ids", &self.app_ids)
            .field("any_app", &self.any_app)
            .field("expires_at", &self.expires_at)
            .field("expired", &self.expired)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("sealed_password", &self.sealed_password.as_ref().map(|_| "***"))
            .finish_non_exhaustive()
    }
}

/// The accounts of one app, with the account-wide cap.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AtlasIdProvisionedAccountList {
    pub object: String,
    pub data: Vec<AtlasIdProvisionedAccount>,
    /// The account-wide cap (default 25).
    pub limit: u32,
    /// Test accounts the account holds across all its apps.
    pub total: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The result of removing a provisioned account.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AtlasIdProvisionedAccountRemoved {
    pub object: String,
    pub id: String,
    pub deleted: bool,
    pub sessions_ended: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `POST /v1/platform/atlas_id_apps/:id/provisioned_accounts`.
/// `Debug` masks the password.
#[derive(Clone, Default, Serialize)]
pub struct CreateAtlasIdProvisionedAccountBody {
    pub email: String,
    /// What the account is for, e.g. "app-store reviewer".
    pub label: String,
    /// At least 12 characters; leave `None` and Atlas generates one. Returned once either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Default true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Never asked for a second factor when signing in to this app. A risk you opt into.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_exempt: Option<bool>,
    /// Epoch ms or ISO 8601 string; `Some(Value::Null)` or `None` for a
    /// non-expiring account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Value>,
}

impl std::fmt::Debug for CreateAtlasIdProvisionedAccountBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateAtlasIdProvisionedAccountBody")
            .field("email", &self.email)
            .field("label", &self.label)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("email_verified", &self.email_verified)
            .field("two_factor_exempt", &self.two_factor_exempt)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Body for `POST .../provisioned_accounts/:id/password`. `Debug` masks the password.
#[derive(Clone, Default, Serialize)]
pub struct RotateAtlasIdProvisionedPasswordBody {
    /// At least 12 characters; leave `None` and Atlas generates one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl std::fmt::Debug for RotateAtlasIdProvisionedPasswordBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateAtlasIdProvisionedPasswordBody")
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

/// `/v1/platform/atlas_id_apps/:id/provisioned_accounts` — test and review
/// accounts confined to one app (reviewer logins, CI, demos). Needs the scope
/// `platform:atlas_id_apps:provision` or the per-app
/// `atlas_id_apps:<app id>:provision`. Passwords come back exactly once, on
/// create and on rotation; build the client with a secret recipient to receive
/// them sealed (`sealed_password`). Reached via [`AtlasIdApps::provisioned_accounts`].
pub struct AtlasIdProvisionedAccounts<'a> {
    client: &'a BackendClient,
}

impl AtlasIdProvisionedAccounts<'_> {
    /// `GET /v1/platform/atlas_id_apps/:id/provisioned_accounts`.
    pub async fn list(&self, app_id: &str) -> Result<AtlasIdProvisionedAccountList, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}/provisioned_accounts", seg(app_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/platform/atlas_id_apps/:id/provisioned_accounts` — the
    /// password is returned once (`password`, or `sealed_password`).
    pub async fn create(
        &self,
        app_id: &str,
        body: &CreateAtlasIdProvisionedAccountBody,
        idempotency_key: Option<&str>,
    ) -> Result<AtlasIdProvisionedAccount, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}/provisioned_accounts", seg(app_id));
        self.client
            .request(HttpMethod::Post, &path, &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `GET /v1/platform/atlas_id_apps/:id/provisioned_accounts/:account`.
    pub async fn get(&self, app_id: &str, account_id: &str) -> Result<AtlasIdProvisionedAccount, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}/provisioned_accounts/{}", seg(app_id), seg(account_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `DELETE /v1/platform/atlas_id_apps/:id/provisioned_accounts/:account` —
    /// deletes the account and ends every session and grant it holds.
    pub async fn remove(&self, app_id: &str, account_id: &str) -> Result<AtlasIdProvisionedAccountRemoved, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}/provisioned_accounts/{}", seg(app_id), seg(account_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/platform/atlas_id_apps/:id/provisioned_accounts/:account/password`
    /// — a new password (yours, or one Atlas generates), returned once. Pass
    /// `None` to have Atlas generate it.
    pub async fn rotate_password(
        &self,
        app_id: &str,
        account_id: &str,
        body: Option<&RotateAtlasIdProvisionedPasswordBody>,
    ) -> Result<AtlasIdProvisionedAccount, BackendError> {
        let path = format!(
            "/v1/platform/atlas_id_apps/{}/provisioned_accounts/{}/password",
            seg(app_id),
            seg(account_id)
        );
        let b = match body {
            Some(b) => body_of(b)?,
            None => None,
        };
        self.client.request(HttpMethod::Post, &path, &[], b, None).await
    }
}

// ── Verified domains ──────────────────────────────────────────────────────

/// A domain the account claimed; verified ones gate test sign-in mode.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AccountDomain {
    pub object: String,
    pub id: String,
    pub domain: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The account's domains and the verified ones.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AccountDomainList {
    pub object: String,
    pub data: Vec<AccountDomain>,
    pub verified_domains: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/platform/domains` — domains the account verified by DNS; they gate
/// test sign-in mode and the test-account domain restriction. Reached via
/// [`PlatformApi::domains`].
pub struct AccountDomains<'a> {
    client: &'a BackendClient,
}

impl AccountDomains<'_> {
    /// `GET /v1/platform/domains`.
    pub async fn list(&self) -> Result<AccountDomainList, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/domains", &[], None, None).await
    }
    /// `POST /v1/platform/domains` — claim a domain; the result carries the
    /// TXT record to publish.
    pub async fn claim(&self, domain: &str) -> Result<AccountDomain, BackendError> {
        let body = serde_json::json!({ "domain": domain });
        self.client.request(HttpMethod::Post, "/v1/platform/domains", &[], Some(body), None).await
    }
    /// `POST /v1/platform/domains/:id/verify` — check the DNS record.
    pub async fn check(&self, domain_id: &str) -> Result<AccountDomain, BackendError> {
        let path = format!("/v1/platform/domains/{}/verify", seg(domain_id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// Alias of [`check`](Self::check), the name the other SDKs use.
    pub async fn verify(&self, domain_id: &str) -> Result<AccountDomain, BackendError> {
        self.check(domain_id).await
    }
    /// `DELETE /v1/platform/domains/:id`.
    pub async fn remove(&self, domain_id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/domains/{}", seg(domain_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

/// `/v1/platform/atlas_id_apps`.
pub struct AtlasIdApps<'a> {
    pub(super) client: &'a BackendClient,
}

impl<'a> AtlasIdApps<'a> {
    /// Test and review accounts confined to one app (scope
    /// `platform:atlas_id_apps:provision` or `atlas_id_apps:<id>:provision`).
    pub fn provisioned_accounts(&self) -> AtlasIdProvisionedAccounts<'a> {
        AtlasIdProvisionedAccounts { client: self.client }
    }
}

impl AtlasIdApps<'_> {
    /// `GET /v1/platform/atlas_id_apps`.
    pub async fn list(&self) -> Result<AtlasIdAppList, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/atlas_id_apps", &[], None, None).await
    }
    /// `POST /v1/platform/atlas_id_apps` — the client secret (confidential apps)
    /// is in the response, exactly once.
    pub async fn create(
        &self,
        body: &CreateAtlasIdAppBody,
        idempotency_key: Option<&str>,
    ) -> Result<AtlasIdApp, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/platform/atlas_id_apps", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `GET /v1/platform/atlas_id_apps/:id`.
    pub async fn get(&self, id: &str) -> Result<AtlasIdApp, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/platform/atlas_id_apps/:id`.
    pub async fn update(&self, id: &str, body: &UpdateAtlasIdAppBody) -> Result<AtlasIdApp, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    /// `DELETE /v1/platform/atlas_id_apps/:id` — its client id stops working.
    pub async fn delete(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/platform/atlas_id_apps/:id/rotate_secret` — the new secret is
    /// returned once; the previous one works for 24 hours more.
    pub async fn rotate_secret(&self, id: &str) -> Result<AtlasIdApp, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/platform/atlas_id_apps/:id/rotate_secret` with a chosen
    /// overlap (`0` revokes the previous secret now);
    /// `previous_secret_expires_at` says when it stops.
    pub async fn rotate_secret_with(&self, id: &str, body: &RotateAtlasIdAppSecretBody) -> Result<AtlasIdApp, BackendError> {
        let path = format!("/v1/platform/atlas_id_apps/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], body_of(body)?, None).await
    }
    /// `POST /v1/platform/atlas_id_apps/design/preview` — preview an app design
    /// without saving it (includes the rendered page HTML).
    pub async fn preview_design(&self, design: &AtlasDesign) -> Result<DesignPreview, BackendError> {
        let body = serde_json::json!({ "design": design });
        self.client
            .request(HttpMethod::Post, "/v1/platform/atlas_id_apps/design/preview", &[], Some(body), None)
            .await
    }
}

// ── platform apps (instances) ─────────────────────────────────────────────

/// An app (instance) your platform owns. Never carries a secret.
#[derive(Debug, Clone, Deserialize)]
pub struct PlatformApp {
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// `production` or `development`.
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub publishable_key: String,
    /// The Frontend API host: the default per-app host, or the custom domain
    /// once it is active.
    #[serde(default)]
    pub frontend_api_host: Option<String>,
    /// The `iss` the app's session tokens carry. It changes when a custom
    /// domain goes active, so read it rather than hard-coding it.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The OpenID discovery document whose `issuer` equals [`Self::issuer`].
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// The JWKS holding the app's signing keys.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// The declared integration per allowed origin (`redirect` or `embedded`).
    #[serde(default)]
    pub allowed_origin_integrations: HashMap<String, String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub archived_at: Option<i64>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `POST /v1/platform/apps`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreatePlatformAppBody {
    pub name: String,
    /// `production` or `development`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    /// Also provision a development instance beside it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_development_sibling: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Sent as `allowed_origins` instead of `allowed_origins` when set: entries
    /// that may also declare how each origin signs in.
    #[serde(skip)]
    pub allowed_origin_entries: Option<Vec<AllowedOriginEntry>>,
}

/// Body for `PATCH /v1/platform/apps/:id`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdatePlatformAppBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Sent as `allowed_origins` instead of `allowed_origins` when set: entries
    /// that may also declare how each origin signs in.
    #[serde(skip)]
    pub allowed_origin_entries: Option<Vec<AllowedOriginEntry>>,
}

/// The body with `allowed_origin_entries` (when set) written as `allowed_origins`.
fn with_origin_entries<T: Serialize>(
    body: &T,
    entries: &Option<Vec<AllowedOriginEntry>>,
) -> Result<Option<Value>, BackendError> {
    let mut v = body_of(body)?;
    if let (Some(e), Some(Value::Object(obj))) = (entries, v.as_mut()) {
        obj.insert(
            "allowed_origins".into(),
            serde_json::to_value(e).map_err(|err| BackendError::Malformed(err.to_string()))?,
        );
    }
    Ok(v)
}

/// `/v1/platform/apps` and `/v1/platform/accountless_apps`.
pub struct PlatformApps<'a> {
    pub(super) client: &'a BackendClient,
}

impl PlatformApps<'_> {
    /// `POST /v1/platform/apps` — provision an app; its first secret key is in
    /// the response, exactly once.
    pub async fn create(&self, body: &CreatePlatformAppBody, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/platform/apps",
                &[],
                with_origin_entries(body, &body.allowed_origin_entries)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/platform/apps` — e.g. `Query::new().set("include_archived", true)`.
    pub async fn list(&self, query: &Query) -> Result<ListPage<PlatformApp>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/apps", &query.as_pairs(), None, None).await
    }
    /// `GET /v1/platform/apps/:id`.
    pub async fn get(&self, id: &str) -> Result<PlatformApp, BackendError> {
        let path = format!("/v1/platform/apps/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/platform/apps/:id`.
    pub async fn update(&self, id: &str, body: &UpdatePlatformAppBody) -> Result<PlatformApp, BackendError> {
        let path = format!("/v1/platform/apps/{}", seg(id));
        let body = with_origin_entries(body, &body.allowed_origin_entries)?;
        self.client.request(HttpMethod::Patch, &path, &[], body, None).await
    }
    /// `DELETE /v1/platform/apps/:id` — soft-disable (reversible).
    pub async fn delete(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/platform/apps/:id/archive`.
    pub async fn archive(&self, id: &str) -> Result<PlatformApp, BackendError> {
        let path = format!("/v1/platform/apps/{}/archive", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/platform/apps/:id/unarchive`.
    pub async fn unarchive(&self, id: &str) -> Result<PlatformApp, BackendError> {
        let path = format!("/v1/platform/apps/{}/unarchive", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/platform/apps/bulk_delete` — up to 100 ids.
    pub async fn bulk_delete(&self, ids: &[&str]) -> Result<Value, BackendError> {
        let body = serde_json::json!({ "ids": ids });
        self.client.request(HttpMethod::Post, "/v1/platform/apps/bulk_delete", &[], Some(body), None).await
    }
    /// `POST /v1/platform/apps/:id/instances` — add an instance (e.g.
    /// `development`) under an owned app. `body`: `{ environment,
    /// allowed_origins? }`; an `allowed_origins` entry is an origin string or
    /// `{ origin, integration }` (see [`AllowedOriginEntry`]).
    pub async fn create_instance(&self, id: &str, body: Value, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/instances", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], Some(body), idempotency_key).await
    }
    /// `GET /v1/platform/apps/:id/instances`.
    pub async fn list_instances(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/instances", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/platform/apps/:id/instances/:instance_id/rotate_secret` — the prior
    /// keys stay valid for the default overlap (72 hours); see
    /// [`rotate_instance_secret_with`](Self::rotate_instance_secret_with).
    pub async fn rotate_instance_secret(
        &self,
        id: &str,
        instance_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!(
            "/v1/platform/apps/{}/instances/{}/rotate_secret",
            seg(id),
            seg(instance_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], None, idempotency_key).await
    }
    /// `POST /v1/platform/apps/:id/instances/:instance_id/rotate_secret` — the prior
    /// keys stay valid for the default overlap (72 hours); see
    /// [`rotate_instance_secret_with`](Self::rotate_instance_secret_with).with a
    /// chosen overlap: the prior keys stay valid for `overlap_seconds` (`0`
    /// revokes them now). The response carries `app_id`, `instance_id`,
    /// `overlap_seconds` and `previous_keys_expire_at`.
    pub async fn rotate_instance_secret_with(
        &self,
        id: &str,
        instance_id: &str,
        body: &RotatePlatformSecretBody,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!(
            "/v1/platform/apps/{}/instances/{}/rotate_secret",
            seg(id),
            seg(instance_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], body_of(body)?, idempotency_key).await
    }
    /// `POST /v1/platform/apps/:id/rotate_secret` — mint a new secret key while
    /// prior keys keep working for `overlap_seconds`.
    pub async fn rotate_secret(
        &self,
        id: &str,
        overlap_seconds: Option<u64>,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/rotate_secret", seg(id));
        let body = overlap_seconds.map(|s| serde_json::json!({ "overlap_seconds": s }));
        self.client.request(HttpMethod::Post, &path, &[], body, idempotency_key).await
    }
    /// `GET /v1/platform/apps/:id/secret_keys` — currently valid keys (metadata
    /// only).
    pub async fn secret_keys(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/secret_keys", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/platform/apps/:id/transfer` — start a transfer; returns a
    /// one-time `transfer_token`.
    pub async fn transfer(&self, id: &str, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/transfer", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, idempotency_key).await
    }
    /// `POST /v1/platform/apps/accept_transfer`.
    pub async fn accept_transfer(&self, transfer_token: &str, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        let body = serde_json::json!({ "transfer_token": transfer_token });
        self.client
            .request(HttpMethod::Post, "/v1/platform/apps/accept_transfer", &[], Some(body), idempotency_key)
            .await
    }
    /// `POST /v1/platform/accountless_apps` — mint an app owned by no platform,
    /// with a one-time `claim_token`. `body`: `{ name, environment?,
    /// allowed_origins? }`; an `allowed_origins` entry is an origin string or
    /// `{ origin, integration }` (see [`AllowedOriginEntry`]).
    pub async fn create_accountless(&self, body: Value, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/platform/accountless_apps", &[], Some(body), idempotency_key)
            .await
    }
    /// `POST /v1/platform/apps/claim` — claim an accountless app.
    pub async fn claim(&self, claim_token: &str, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        let body = serde_json::json!({ "claim_token": claim_token });
        self.client
            .request(HttpMethod::Post, "/v1/platform/apps/claim", &[], Some(body), idempotency_key)
            .await
    }
}

// ── namespace ─────────────────────────────────────────────────────────────

/// The Platform API. Reached via [`BackendClient::platform`]; the client must
/// be built with a platform key (`psk_…`).
pub struct PlatformApi<'a> {
    pub(super) client: &'a BackendClient,
}

/// `/v1/platform/atlas_id_publisher` — the account's Sign in with Atlas
/// publisher. Reached via [`PlatformApi::atlas_id_publisher`].
pub struct AtlasIdPublisherApi<'a> {
    pub(super) client: &'a BackendClient,
}

impl<'a> PlatformApi<'a> {
    /// Sign in with Atlas apps.
    pub fn atlas_id_apps(&self) -> AtlasIdApps<'a> {
        AtlasIdApps { client: self.client }
    }
    /// The account's Sign in with Atlas publisher name and DNS-verified domain.
    pub fn atlas_id_publisher(&self) -> AtlasIdPublisherApi<'a> {
        AtlasIdPublisherApi { client: self.client }
    }
    /// Domains the account verified by DNS (gate test sign-in mode).
    pub fn domains(&self) -> AccountDomains<'a> {
        AccountDomains { client: self.client }
    }
    /// The apps (instances) the platform owns.
    pub fn apps(&self) -> PlatformApps<'a> {
        PlatformApps { client: self.client }
    }
    /// `POST /v1/platform/design/assets?kind=` — upload a design image for Sign
    /// in with Atlas app designs: raw image bytes (PNG, JPEG, GIF or WebP, up to
    /// 8 MB). `content_type` is detected from the bytes when `None`.
    pub async fn upload_design_asset(
        &self,
        kind: DesignAssetKind,
        bytes: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<DesignAsset, BackendError> {
        let ct = content_type_for(&bytes, content_type)?;
        let q = vec![("kind", kind.as_str().to_string())];
        self.client
            .request_upload(HttpMethod::Post, "/v1/platform/design/assets", &q, bytes, &ct)
            .await
    }
    /// `GET /v1/platform/design/assets` — newest first.
    pub async fn list_design_assets(&self) -> Result<ListPage<DesignAsset>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/design/assets", &[], None, None).await
    }
    /// `DELETE /v1/platform/design/assets/:id`.
    pub async fn delete_design_asset(&self, asset_id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/design/assets/{}", seg(asset_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

impl BackendClient {
    /// The Platform API (`/v1/platform/*`). Build this client with a platform
    /// key (`psk_…`); a secret key gets `WRONG_KEY_SURFACE`.
    pub fn platform(&self) -> PlatformApi<'_> {
        PlatformApi { client: self }
    }
}
