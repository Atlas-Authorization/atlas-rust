//! Sign-in page design: the structured `AtlasDesign` document, the instance and
//! per-organization design settings, design previews, and design image assets.
//!
//! The design is typed in full — every section and field the API accepts. All
//! fields are optional (an unset field comes from the chosen preset, then the
//! defaults) and are omitted from the request when `None`. Enumerated values
//! (presets, fonts, styles) are plain strings so a value added on the server
//! never breaks deserialization; the doc on each field lists the accepted
//! values. Every struct also keeps an `extra` map, so a section field added
//! later still round-trips.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::resources::{seg, ListPage};

// ── the design document ─────────────────────────────────────────────────────

/// A structured sign-in page design: overrides on top of a preset. Colours are
/// `#RRGGBB`; images are uploaded design asset ids (`dasset_…`), never URLs;
/// fonts are ids from [`DesignApi::catalog`]. There is no field for raw CSS or
/// HTML.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AtlasDesign {
    /// Schema version; `1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `minimal`, `atlas`, `glass`, `midnight`, `editorial`, `terminal`,
    /// `sunrise`, `forest`, `grape`, `slate`, `split-photo`, or `bold`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// `auto`, `light`, or `dark`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_scheme: Option<String>,
    /// Light-mode colours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub palette: Option<DesignPalette>,
    /// Dark-mode colours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub palette_dark: Option<DesignPalette>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typography: Option<DesignTypography>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<DesignShape>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevation: Option<DesignElevation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spacing: Option<DesignSpacing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<DesignCard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<DesignLayout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buttons: Option<DesignButtons>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<DesignInputs>,
    /// Light-mode page background.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<DesignBackground>,
    /// Dark-mode page background.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_dark: Option<DesignBackground>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<DesignLogo>,
    /// Sections not modelled above.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Palette colours, each `#RRGGBB`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignPalette {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Text drawn on top of `primary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_ink: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub border: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub danger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_background: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_text: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Fonts and type scale.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignTypography {
    /// A font id from the design catalog (e.g. `system`, `inter`, `roboto`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font: Option<String>,
    /// A font id for headings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading_font: Option<String>,
    /// Base font size in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heading_weight: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_weight: Option<u32>,
    /// `none` or `uppercase`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub letter_case: Option<String>,
    /// A modular scale name, e.g. `major-third`, `perfect-fourth`, `golden`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Corner radii and border width, in pixels.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignShape {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radius: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_radius: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub border_width: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Shadow depth.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignElevation {
    /// `none`, `sm`, `md`, `lg`, or `xl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_shadow: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Spacing density.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignSpacing {
    /// `compact`, `comfortable`, or `spacious`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub density: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The sign-in card.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignCard {
    /// `solid`, `glass`, `outline`, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    /// Backdrop blur for the `glass` style, in pixels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blur: Option<u32>,
    /// `narrow`, `normal`, or `wide`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Page layout.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignLayout {
    /// `center`, `left`, `right`, or `split`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    /// For `split`: `left` or `right`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_image_side: Option<String>,
    /// `card`, `page`, or `hidden`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_placement: Option<String>,
    /// `sm`, `md`, or `lg`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_size: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Buttons.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignButtons {
    /// `solid`, `outline`, `soft`, or `gradient`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    /// Social sign-in buttons: `list`, `grid`, or `icons`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub social_layout: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Form inputs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignInputs {
    /// `outline`, `filled`, or `underline`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A page background: a colour, a gradient, an image, and/or a pattern.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignBackground {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gradient: Option<DesignGradient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<DesignBackgroundImage>,
    /// `none`, `dots`, `grid`, or `noise`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A background gradient.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignGradient {
    /// `linear` or `radial`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Angle in degrees (linear).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub angle: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stops: Option<Vec<DesignGradientStop>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One gradient stop.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignGradientStop {
    pub color: String,
    /// Position, 0–100.
    pub at: f64,
}

/// A background image from an uploaded design asset.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignBackgroundImage {
    /// The design asset id (`dasset_…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    /// `cover` or `contain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fit: Option<String>,
    /// `top-left`, `top`, `top-right`, `left`, `center`, `right`,
    /// `bottom-left`, `bottom`, or `bottom-right`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<DesignOverlay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blur: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A colour overlay over a background image.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignOverlay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// 0–1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opacity: Option<f64>,
}

/// Logos from uploaded design assets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesignLogo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    /// The logo used in dark mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dark_asset_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ── responses ───────────────────────────────────────────────────────────────

/// A contrast warning for a design (e.g. text too close to its background).
#[derive(Debug, Clone, Deserialize)]
pub struct DesignWarning {
    #[serde(default)]
    pub code: String,
    /// `light` or `dark`.
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub pair: Vec<String>,
    #[serde(default)]
    pub ratio: f64,
    #[serde(default)]
    pub required: f64,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub message: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The stored design of the instance or of one organization.
#[derive(Debug, Clone, Deserialize)]
pub struct DesignSettings {
    /// `design` or `organization_design`.
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    /// The saved overrides.
    #[serde(default)]
    pub design: AtlasDesign,
    /// The fully resolved design (preset + overrides + defaults).
    #[serde(default)]
    pub resolved: AtlasDesign,
    #[serde(default)]
    pub warnings: Vec<DesignWarning>,
    /// Whether the page still uses the older branding settings.
    #[serde(default)]
    pub legacy: bool,
    #[serde(default)]
    pub legacy_design: Option<AtlasDesign>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A compiled, unsaved design: CSS, data attributes, fonts, warnings, the
/// resolved design, and the rendered page HTML.
#[derive(Debug, Clone, Deserialize)]
pub struct DesignPreview {
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub css: String,
    #[serde(default)]
    pub data_attributes: Map<String, Value>,
    #[serde(default)]
    pub font_stylesheets: Vec<String>,
    #[serde(default)]
    pub resolved: AtlasDesign,
    #[serde(default)]
    pub warnings: Vec<DesignWarning>,
    #[serde(default)]
    pub html: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An uploaded design image (re-encoded as WebP and served by Atlas).
#[derive(Debug, Clone, Deserialize)]
pub struct DesignAsset {
    /// The id to reference from a design (`dasset_…`).
    #[serde(default)]
    pub asset_id: String,
    /// `background` or `logo`.
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default)]
    pub dominant_color: Option<String>,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The kind of design image being uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesignAssetKind {
    Background,
    Logo,
}

impl DesignAssetKind {
    /// The `?kind=` value.
    pub fn as_str(&self) -> &'static str {
        match self {
            DesignAssetKind::Background => "background",
            DesignAssetKind::Logo => "logo",
        }
    }
}

/// Guess an image content-type from its first bytes (PNG, JPEG, GIF, WebP).
pub fn sniff_image_content_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF8") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub(super) fn content_type_for(bytes: &[u8], content_type: Option<&str>) -> Result<String, BackendError> {
    match content_type {
        Some(ct) => Ok(ct.to_string()),
        None => sniff_image_content_type(bytes).map(str::to_string).ok_or_else(|| {
            BackendError::Malformed(
                "could not detect the image type; pass a content type (image/png, image/jpeg, image/gif or image/webp)"
                    .into(),
            )
        }),
    }
}

// ── namespace ───────────────────────────────────────────────────────────────

/// The instance design, per-organization designs, previews, design assets, and
/// the design catalog. Reached via [`BackendClient::design`].
pub struct DesignApi<'a> {
    pub(super) client: &'a BackendClient,
}

impl DesignApi<'_> {
    /// `GET /v1/instance/design` — the instance's design.
    pub async fn get(&self) -> Result<DesignSettings, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/design", &[], None, None).await
    }
    /// `PUT /v1/instance/design` — replace the instance design.
    pub async fn put(&self, design: &AtlasDesign) -> Result<DesignSettings, BackendError> {
        let body = serde_json::json!({ "design": design });
        self.client.request(HttpMethod::Put, "/v1/instance/design", &[], Some(body), None).await
    }
    /// `PATCH /v1/instance/design` — change part of the instance design. `patch`
    /// is the `design` merge patch: set a key to change it, `null` to remove it
    /// (e.g. `json!({"palette": {"primary": "#0F766E"}, "logo": null})`).
    pub async fn patch(&self, patch: Value) -> Result<DesignSettings, BackendError> {
        let body = serde_json::json!({ "design": patch });
        self.client.request(HttpMethod::Patch, "/v1/instance/design", &[], Some(body), None).await
    }
    /// `POST /v1/instance/design/preview` — compile an unsaved design. Nothing
    /// is saved.
    pub async fn preview(&self, design: &AtlasDesign) -> Result<DesignPreview, BackendError> {
        let body = serde_json::json!({ "design": design });
        self.client
            .request(HttpMethod::Post, "/v1/instance/design/preview", &[], Some(body), None)
            .await
    }
    /// `GET /v1/organizations/:id/design` — an organization's design override.
    pub async fn get_organization(&self, org_id: &str) -> Result<DesignSettings, BackendError> {
        let path = format!("/v1/organizations/{}/design", seg(org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PUT /v1/organizations/:id/design` — replace an organization's override.
    pub async fn put_organization(&self, org_id: &str, design: &AtlasDesign) -> Result<DesignSettings, BackendError> {
        let path = format!("/v1/organizations/{}/design", seg(org_id));
        let body = serde_json::json!({ "design": design });
        self.client.request(HttpMethod::Put, &path, &[], Some(body), None).await
    }
    /// `PATCH /v1/organizations/:id/design` — merge-patch an organization's
    /// override; `null` removes a setting.
    pub async fn patch_organization(&self, org_id: &str, patch: Value) -> Result<DesignSettings, BackendError> {
        let path = format!("/v1/organizations/{}/design", seg(org_id));
        let body = serde_json::json!({ "design": patch });
        self.client.request(HttpMethod::Patch, &path, &[], Some(body), None).await
    }
    /// `POST /v1/design/assets?kind=` — upload a design image: the raw image
    /// bytes (PNG, JPEG, GIF or WebP). `content_type` is detected from the bytes
    /// when `None`.
    pub async fn upload_asset(
        &self,
        kind: DesignAssetKind,
        bytes: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<DesignAsset, BackendError> {
        let ct = content_type_for(&bytes, content_type)?;
        let q = vec![("kind", kind.as_str().to_string())];
        self.client.request_upload(HttpMethod::Post, "/v1/design/assets", &q, bytes, &ct).await
    }
    /// `GET /v1/design/assets` — the instance's design images, newest first.
    pub async fn list_assets(&self) -> Result<ListPage<DesignAsset>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/design/assets", &[], None, None).await
    }
    /// `DELETE /v1/design/assets/:id`.
    pub async fn delete_asset(&self, asset_id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/design/assets/{}", seg(asset_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `GET /v1/design/catalog` — the presets (resolved), the curated fonts,
    /// and the CSS variable list. Public; returned as JSON.
    pub async fn catalog(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/design/catalog", &[], None, None).await
    }
}

impl BackendClient {
    /// Sign-in page design: instance and organization designs, previews,
    /// design images, and the catalog.
    pub fn design(&self) -> DesignApi<'_> {
        DesignApi { client: self }
    }
}
