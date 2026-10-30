//! Application webhooks: send YOUR app's own events (`call.completed`,
//! `invoice.paid`) to endpoints your customers' organizations register. Atlas
//! signs them with Standard Webhooks headers (verify with
//! [`Webhook::verify_standard`](super::Webhook::verify_standard)), retries,
//! tracks health, auto-disables a dead endpoint and keeps the delivery log with
//! redeliver and replay.
//!
//! ```no_run
//! # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
//! use atlasauth::backend::{AppEventTypeBody, PublishAppEventBody};
//! use serde_json::json;
//!
//! atlas
//!     .app_events()
//!     .types()
//!     .create(&AppEventTypeBody::new("call.completed").with_description("A call finished."), None)
//!     .await?;
//! let published = atlas
//!     .app_events()
//!     .publish(
//!         &PublishAppEventBody::new("org_123", "call.completed", json!({ "call_id": "c1" })),
//!         Some("c1"),
//!     )
//!     .await?;
//! # let _ = published; Ok(()) }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::pagination::Query;
use super::resources::{body_of, seg, DeletedObject, ListPage};
use super::suite::WebhookTestResult;
use super::types_ext;

/// The organization permission that lets a member manage the organization's
/// app webhook endpoints from the Frontend API.
pub const PERMISSION_ORG_WEBHOOKS_MANAGE: &str = "org:webhooks:manage";

/// A published app event. On a publish response `idempotent_replay`,
/// `deliveries_queued` and `endpoint_ids` are set too.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AppEvent {
    /// `app_event`.
    pub object: String,
    /// `evt_` id; the `webhook-id` header of every delivery of this event.
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub organization_id: String,
    pub data: Value,
    pub idempotency_key: Option<String>,
    /// Epoch ms.
    pub created_at: i64,
    /// `true` when this response returns an earlier publish with the same
    /// idempotency key (nothing new was queued).
    pub idempotent_replay: bool,
    /// How many endpoints the event was queued for (first publish only).
    pub deliveries_queued: Option<i64>,
    pub endpoint_ids: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The body of `POST /v1/app_events`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PublishAppEventBody {
    /// The organization whose subscribed endpoints receive the event.
    pub organization_id: String,
    /// A type from your event catalog.
    #[serde(rename = "type")]
    pub event_type: String,
    /// What your customers receive under `data` (at most 256 KB).
    pub data: Value,
    /// Up to 255 characters, unique per organization: a repeat returns the
    /// first event and queues nothing (kept 90 days).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PublishAppEventBody {
    pub fn new(organization_id: impl Into<String>, event_type: impl Into<String>, data: Value) -> Self {
        Self {
            organization_id: organization_id.into(),
            event_type: event_type.into(),
            data,
            ..Self::default()
        }
    }
    /// Set the body's `idempotency_key` (the deduplication key kept with the event).
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }
}

/// An entry of your event catalog.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AppEventType {
    /// `app_event_type`.
    pub object: String,
    /// `aet_` id.
    pub id: String,
    /// Lowercase dotted name, e.g. `call.completed`.
    #[serde(rename = "type")]
    pub event_type: String,
    pub description: Option<String>,
    /// JSON Schema every published `data` must match; `None` = any object.
    pub schema: Option<Value>,
    /// Still publishable and delivered; hidden from the endpoint picker.
    pub deprecated: bool,
    /// Epoch ms.
    pub created_at: i64,
    /// Epoch ms.
    pub updated_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The body of `POST /v1/app_event_types` (`event_type` required) and
/// `PATCH /v1/app_event_types/{id}` (leave `event_type` empty: it is not sent).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AppEventTypeBody {
    /// Lowercase dotted words, at least two parts, at most 100 characters.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub event_type: String,
    /// `Some(None)` sends null and clears it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Option<String>>,
    /// `Some(None)` sends null: any object is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<Option<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AppEventTypeBody {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self { event_type: event_type.into(), ..Self::default() }
    }
    pub fn with_description(mut self, v: impl Into<String>) -> Self {
        self.description = Some(Some(v.into()));
        self
    }
    pub fn with_schema(mut self, v: Value) -> Self {
        self.schema = Some(Some(v));
        self
    }
    pub fn with_deprecated(mut self, v: bool) -> Self {
        self.deprecated = Some(v);
        self
    }
}

/// `/v1/app_events`. Reached via [`BackendClient::app_events`].
pub struct AppEvents<'a> {
    pub(super) client: &'a BackendClient,
}

impl<'a> AppEvents<'a> {
    /// `POST /v1/app_events` — publish one event to one organization's
    /// subscribed endpoints (201 new, 200 replay of the same idempotency key).
    pub async fn publish(
        &self,
        body: &PublishAppEventBody,
        idempotency_key: Option<&str>,
    ) -> Result<AppEvent, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/app_events", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `GET /v1/app_events?organization_id=` — one organization's published
    /// events, newest first. `query` adds `type`, `limit`, `starting_after`.
    pub async fn list(&self, organization_id: &str, query: &Query) -> Result<ListPage<AppEvent>, BackendError> {
        let mut q = vec![("organization_id", organization_id.to_string())];
        q.extend(query.as_pairs());
        self.client.request(HttpMethod::Get, "/v1/app_events", &q, None, None).await
    }
    /// `GET /v1/app_events/{id}`.
    pub async fn get(&self, id: &str) -> Result<AppEvent, BackendError> {
        let path = format!("/v1/app_events/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// Your event catalog (`/v1/app_event_types`).
    pub fn types(&self) -> AppEventTypes<'a> {
        AppEventTypes { client: self.client }
    }
    /// One organization's endpoints for your events
    /// (`/v1/organizations/{id}/app_webhook_endpoints`).
    pub fn endpoints(&self) -> AppWebhookEndpoints<'a> {
        AppWebhookEndpoints { client: self.client }
    }
}

/// `/v1/app_event_types`. `id_or_type` is the `aet_` id or the type name.
pub struct AppEventTypes<'a> {
    client: &'a BackendClient,
}

impl AppEventTypes<'_> {
    /// `GET /v1/app_event_types`.
    pub async fn list(&self, query: &Query) -> Result<ListPage<AppEventType>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/app_event_types", &query.as_pairs(), None, None).await
    }
    /// `POST /v1/app_event_types`.
    pub async fn create(
        &self,
        body: &AppEventTypeBody,
        idempotency_key: Option<&str>,
    ) -> Result<AppEventType, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/app_event_types", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `GET /v1/app_event_types/{id_or_type}`.
    pub async fn get(&self, id_or_type: &str) -> Result<AppEventType, BackendError> {
        let path = format!("/v1/app_event_types/{}", seg(id_or_type));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/app_event_types/{id_or_type}` — `description`, `schema`,
    /// `deprecated`.
    pub async fn update(&self, id_or_type: &str, body: &AppEventTypeBody) -> Result<AppEventType, BackendError> {
        let path = format!("/v1/app_event_types/{}", seg(id_or_type));
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    /// `DELETE /v1/app_event_types/{id_or_type}`.
    pub async fn delete(&self, id_or_type: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/app_event_types/{}", seg(id_or_type));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

/// `/v1/organizations/{id}/app_webhook_endpoints`: webhook endpoint objects as
/// for the organization's Atlas webhooks, subscribed to your app event types.
pub struct AppWebhookEndpoints<'a> {
    client: &'a BackendClient,
}

impl AppWebhookEndpoints<'_> {
    /// `GET /v1/organizations/{id}/app_webhook_endpoints`. Never returns a secret.
    pub async fn list(
        &self,
        org_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsListResponse, BackendError> {
        let path = format!("/v1/organizations/{}/app_webhook_endpoints", seg(org_id));
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
    /// `POST /v1/organizations/{id}/app_webhook_endpoints` — `url`,
    /// `enabled_events` (types from your catalog, or `["*"]`, the default),
    /// `description`, `active`. The signing secret is in this response only.
    pub async fn create(
        &self,
        org_id: &str,
        body: &types_ext::OrganizationsWebhookEndpointsCreateBody,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::WebhookEndpointCreate, BackendError> {
        let path = format!("/v1/organizations/{}/app_webhook_endpoints", seg(org_id));
        self.client.request(HttpMethod::Post, &path, &[], body_of(body)?, idempotency_key).await
    }
    /// `GET /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}`.
    pub async fn get(&self, org_id: &str, endpoint_id: &str) -> Result<types_ext::WebhookEndpoint, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}`.
    pub async fn update(
        &self,
        org_id: &str,
        endpoint_id: &str,
        body: &types_ext::OrganizationsWebhookEndpointsUpdateBody,
    ) -> Result<types_ext::WebhookEndpoint, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    /// `DELETE /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}`.
    pub async fn delete(&self, org_id: &str, endpoint_id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}/rotate_secret` — the new secret is returned once; the previous
    /// one keeps signing alongside it for the overlap.
    pub async fn rotate_secret(
        &self,
        org_id: &str,
        endpoint_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsRotateSecretResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}/rotate_secret",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], None, idempotency_key).await
    }
    /// `POST /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}/reveal_secret` — `{ object: "webhook_secret", secret }`.
    pub async fn reveal_secret(&self, org_id: &str, endpoint_id: &str) -> Result<Value, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}/reveal_secret",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}/test` — send a `webhook.test` event. `wait` (at most `10s`,
    /// e.g. `"5s"`) waits for the attempt and returns its result inline.
    pub async fn test(
        &self,
        org_id: &str,
        endpoint_id: &str,
        wait: Option<&str>,
    ) -> Result<WebhookTestResult, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}/test",
            seg(org_id),
            seg(endpoint_id)
        );
        let q = Query::new().set_opt("wait", wait);
        self.client.request(HttpMethod::Post, &path, &q.as_pairs(), None, None).await
    }
    /// `GET /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}/deliveries` — filter with `status`, `event_type`, `since`,
    /// `until`, `trace`, `limit`, `starting_after`.
    pub async fn deliveries(
        &self,
        org_id: &str,
        endpoint_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsDeliveriesResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}/deliveries",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
    /// `POST /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}/deliveries/{delivery_id}/redeliver` — a new delivery of the
    /// same event (the same `webhook-id`).
    pub async fn redeliver(
        &self,
        org_id: &str,
        endpoint_id: &str,
        delivery_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}/deliveries/{}/redeliver",
            seg(org_id),
            seg(endpoint_id),
            seg(delivery_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], None, idempotency_key).await
    }
    /// `POST /v1/organizations/{id}/app_webhook_endpoints/{endpoint_id}/replay` — re-send what the endpoint missed: `{ since, until?,
    /// event_type? }` (epoch ms or ISO 8601). Answers 202.
    pub async fn replay(
        &self,
        org_id: &str,
        endpoint_id: &str,
        body: &Value,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!(
            "/v1/organizations/{}/app_webhook_endpoints/{}/replay",
            seg(org_id),
            seg(endpoint_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], Some(body.clone()), idempotency_key).await
    }
    /// `GET /v1/organizations/{id}/app_event_types` — the event types this
    /// organization's endpoints can subscribe to (the non-deprecated catalog).
    pub async fn app_event_types(&self, org_id: &str, query: &Query) -> Result<ListPage<AppEventType>, BackendError> {
        let path = format!("/v1/organizations/{}/app_event_types", seg(org_id));
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
}

impl BackendClient {
    /// Application webhooks: publish your own events, manage the event
    /// catalog and organizations' endpoints.
    pub fn app_events(&self) -> AppEvents<'_> {
        AppEvents { client: self }
    }
}
