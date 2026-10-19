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

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::design::{content_type_for, AtlasDesign, DesignAsset, DesignAssetKind, DesignPreview};
use super::error::BackendError;
use super::pagination::Query;
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
    #[serde(flatten)]
    pub extra: Map<String, Value>,
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
}

/// `/v1/platform/atlas_id_apps`.
pub struct AtlasIdApps<'a> {
    pub(super) client: &'a BackendClient,
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
    #[serde(default)]
    pub allowed_origins: Vec<String>,
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
            .request(HttpMethod::Post, "/v1/platform/apps", &[], body_of(body)?, idempotency_key)
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
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
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
    /// allowed_origins? }`.
    pub async fn create_instance(&self, id: &str, body: Value, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/instances", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], Some(body), idempotency_key).await
    }
    /// `GET /v1/platform/apps/:id/instances`.
    pub async fn list_instances(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/instances", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/platform/apps/:id/instances/:instance_id/rotate_secret`.
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
    /// allowed_origins? }`.
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
