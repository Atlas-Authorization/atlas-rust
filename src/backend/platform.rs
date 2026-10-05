//! Platform-feature resources: custom audit events, tickets, notifications
//! (+ templates and categories), per-org branding, org settings, entitlement
//! overrides and effective entitlements, and user deletion / erasure acks.
//!
//! Same conventions as [`super::resources`]: snake_case wire shapes, `Option`
//! for nullables, and an `extra` bag that absorbs unknown server fields so a new
//! field never breaks deserialization. For anything not typed here, fall back to
//! [`BackendClient::request_raw`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::pagination::CursorPage;
use super::resources::{body_of, seg, ListPage, Metadata};

// ── audit events ──────────────────────────────────────────────────────────

/// `{ type, id }` actor of a custom audit event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditActor {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// `{ type, id, name }` target of a custom audit event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditTarget {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Body for `POST /v1/audit_events` (and each element of a batch).
#[derive(Debug, Clone, Default, Serialize)]
pub struct WriteAuditEventBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<AuditActor>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<AuditTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

/// A stored custom audit event.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub actor: Option<AuditActor>,
    #[serde(default)]
    pub target: Option<AuditTarget>,
    #[serde(default)]
    pub occurred_at: Option<i64>,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Filters for `GET /v1/audit_events`, `/export`, and `DELETE /v1/audit_events`.
#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    pub organization_id: Option<String>,
    pub actor_id: Option<String>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    /// Inclusive lower bound (ms epoch or ISO-8601, as the server accepts).
    pub from: Option<String>,
    pub to: Option<String>,
    /// OR-group of filters, sent as the `any_of` query param (pass the
    /// already-encoded value the server documents).
    pub any_of: Option<String>,
    pub metadata_key: Option<String>,
    pub metadata_value: Option<String>,
    pub limit: Option<u32>,
    pub starting_after: Option<String>,
}

impl AuditEventFilter {
    fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        let mut push = |k: &'static str, v: &Option<String>| {
            if let Some(v) = v {
                q.push((k, v.clone()));
            }
        };
        push("organization_id", &self.organization_id);
        push("actor_id", &self.actor_id);
        push("action", &self.action);
        push("target_type", &self.target_type);
        push("target_id", &self.target_id);
        push("from", &self.from);
        push("to", &self.to);
        push("any_of", &self.any_of);
        push("metadata_key", &self.metadata_key);
        push("metadata_value", &self.metadata_value);
        push("starting_after", &self.starting_after);
        if let Some(l) = self.limit {
            q.push(("limit", l.to_string()));
        }
        q
    }
}

/// The `/v1/audit_events` namespace.
pub struct AuditEvents<'a> {
    client: &'a BackendClient,
}

impl AuditEvents<'_> {
    /// `POST /v1/audit_events`.
    pub async fn write(
        &self,
        body: &WriteAuditEventBody,
        idempotency_key: Option<&str>,
    ) -> Result<AuditEvent, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/audit_events", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `POST /v1/audit_events/batch` — a non-empty batch of events.
    pub async fn write_batch(
        &self,
        events: &[WriteAuditEventBody],
        idempotency_key: Option<&str>,
    ) -> Result<ListPage<AuditEvent>, BackendError> {
        let body = serde_json::json!({ "events": events });
        self.client
            .request(HttpMethod::Post, "/v1/audit_events/batch", &[], Some(body), idempotency_key)
            .await
    }
    /// `GET /v1/audit_events` — filtered, cursor-paginated.
    pub async fn list(&self, filter: &AuditEventFilter) -> Result<CursorPage<AuditEvent>, BackendError> {
        let q = filter.to_query();
        self.client.request(HttpMethod::Get, "/v1/audit_events", &q, None, None).await
    }
    /// `GET /v1/audit_events/export` — the streamed export body (`format` is
    /// `"jsonl"` or `"csv"`; default jsonl), returned as raw text.
    pub async fn export(
        &self,
        filter: &AuditEventFilter,
        format: Option<&str>,
    ) -> Result<String, BackendError> {
        let mut q = filter.to_query();
        if let Some(f) = format {
            q.push(("format", f.to_string()));
        }
        self.client
            .send_text(HttpMethod::Get, "/v1/audit_events/export", &q, None, None)
            .await
    }
    /// `DELETE /v1/audit_events` — delete matching events (the server requires
    /// `organization_id` and/or `action`).
    pub async fn delete(&self, filter: &AuditEventFilter) -> Result<Value, BackendError> {
        let q = filter.to_query();
        self.client.request(HttpMethod::Delete, "/v1/audit_events", &q, None, None).await
    }
}

// ── tickets ───────────────────────────────────────────────────────────────

/// Body for `POST /v1/tickets`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateTicketBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    pub ttl_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_use: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_org: Option<String>,
}

/// A minted capability ticket. `ticket` is the secret, shown once.
#[derive(Debug, Clone, Deserialize)]
pub struct Ticket {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub ticket: Option<String>,
    #[serde(default)]
    pub bound_user: Option<String>,
    #[serde(default)]
    pub bound_org: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The result of redeeming a ticket.
#[derive(Debug, Clone, Deserialize)]
pub struct RedeemedTicket {
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/v1/tickets` namespace.
pub struct Tickets<'a> {
    client: &'a BackendClient,
}

impl Tickets<'_> {
    /// `POST /v1/tickets`.
    pub async fn create(
        &self,
        body: &CreateTicketBody,
        idempotency_key: Option<&str>,
    ) -> Result<Ticket, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/tickets", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `POST /v1/tickets/redeem`, optionally asserting the expected user/org.
    pub async fn redeem(
        &self,
        ticket: &str,
        for_user: Option<&str>,
        for_org: Option<&str>,
    ) -> Result<RedeemedTicket, BackendError> {
        let mut body = Map::new();
        body.insert("ticket".into(), Value::String(ticket.to_string()));
        if let Some(u) = for_user {
            body.insert("for_user".into(), Value::String(u.to_string()));
        }
        if let Some(o) = for_org {
            body.insert("for_org".into(), Value::String(o.to_string()));
        }
        self.client
            .request(HttpMethod::Post, "/v1/tickets/redeem", &[], Some(Value::Object(body)), None)
            .await
    }
}

// ── notifications, templates, categories ──────────────────────────────────

/// Body for `POST /v1/notifications`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendNotificationBody {
    pub user_id: String,
    pub template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<std::collections::BTreeMap<String, String>>,
}

/// The `/v1/notifications` namespace.
pub struct Notifications<'a> {
    client: &'a BackendClient,
}

impl Notifications<'_> {
    /// `POST /v1/notifications` — send a templated notification to a user. The
    /// response shape is server-defined, so it is returned as a [`Value`].
    pub async fn send(
        &self,
        body: &SendNotificationBody,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/notifications", &[], body_of(body)?, idempotency_key)
            .await
    }
}

/// A tenant-authored notification template.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationTemplate {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `POST`/`PUT /v1/notification_templates`. `name` is used on create
/// only (on update it is the path key and is not sent).
#[derive(Debug, Clone, Default, Serialize)]
pub struct NotificationTemplateBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// The `/v1/notification_templates` namespace.
pub struct NotificationTemplates<'a> {
    client: &'a BackendClient,
}

impl NotificationTemplates<'_> {
    pub async fn list(&self) -> Result<ListPage<NotificationTemplate>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/notification_templates", &[], None, None).await
    }
    pub async fn get(&self, name: &str) -> Result<NotificationTemplate, BackendError> {
        let path = format!("/v1/notification_templates/{}", seg(name));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST` — `body.name` is required.
    pub async fn create(&self, body: &NotificationTemplateBody) -> Result<NotificationTemplate, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/notification_templates", &[], body_of(body)?, None)
            .await
    }
    /// `PUT /v1/notification_templates/:name`.
    pub async fn update(
        &self,
        name: &str,
        body: &NotificationTemplateBody,
    ) -> Result<NotificationTemplate, BackendError> {
        let path = format!("/v1/notification_templates/{}", seg(name));
        let mut b = body.clone();
        b.name = None;
        self.client.request(HttpMethod::Put, &path, &[], body_of(&b)?, None).await
    }
    pub async fn delete(&self, name: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/notification_templates/{}", seg(name));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

/// A notification category (the unit end-users opt in/out of).
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationCategory {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `POST`/`PUT /v1/notification_categories`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NotificationCategoryBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Extra server-defined fields (e.g. default opt-in) merged into the body.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/v1/notification_categories` namespace, keyed by category name.
pub struct NotificationCategories<'a> {
    client: &'a BackendClient,
}

impl NotificationCategories<'_> {
    pub async fn list(&self) -> Result<ListPage<NotificationCategory>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/notification_categories", &[], None, None).await
    }
    pub async fn get(&self, name: &str) -> Result<NotificationCategory, BackendError> {
        let path = format!("/v1/notification_categories/{}", seg(name));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn create(&self, body: &NotificationCategoryBody) -> Result<NotificationCategory, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/notification_categories", &[], body_of(body)?, None)
            .await
    }
    pub async fn update(
        &self,
        name: &str,
        body: &NotificationCategoryBody,
    ) -> Result<NotificationCategory, BackendError> {
        let path = format!("/v1/notification_categories/{}", seg(name));
        let mut b = body.clone();
        b.name = None;
        self.client.request(HttpMethod::Put, &path, &[], body_of(&b)?, None).await
    }
    pub async fn delete(&self, name: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/notification_categories/{}", seg(name));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── org branding / settings / entitlements ────────────────────────────────

/// Per-organization branding.
#[derive(Debug, Clone, Deserialize)]
pub struct OrgBranding {
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub primary_color: Option<String>,
    #[serde(default)]
    pub support_url: Option<String>,
    #[serde(default)]
    pub custom_domain: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `PUT /v1/organizations/:id/branding`. Each field is a double
/// `Option`: outer `None` omits the key, `Some(None)` sends JSON `null` to
/// clear it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SetOrgBrandingBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_url: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domain: Option<Option<String>>,
}

/// Org settings values (`{ organization_id, values }`).
#[derive(Debug, Clone, Deserialize)]
pub struct OrgSettings {
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub values: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The registered org-settings schema (`{ schema }`, server-shaped JSON Schema).
#[derive(Debug, Clone, Deserialize)]
pub struct OrgSettingsSchema {
    #[serde(default)]
    pub schema: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The effective entitlements of an org: `{ plan, features, limits }`.
#[derive(Debug, Clone, Deserialize)]
pub struct EffectiveEntitlements {
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub limits: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An entitlement override on a subject.
#[derive(Debug, Clone, Deserialize)]
pub struct EntitlementOverride {
    pub id: String,
    #[serde(default)]
    pub subject_type: String,
    #[serde(default)]
    pub subject_id: String,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub features: Option<Vec<String>>,
    #[serde(default)]
    pub limits: Option<Map<String, Value>>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body for `POST /v1/entitlement_overrides`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateEntitlementOverrideBody {
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// The `/v1/entitlement_overrides` namespace.
pub struct EntitlementOverrides<'a> {
    client: &'a BackendClient,
}

impl EntitlementOverrides<'_> {
    pub async fn create(
        &self,
        body: &CreateEntitlementOverrideBody,
        idempotency_key: Option<&str>,
    ) -> Result<EntitlementOverride, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/entitlement_overrides", &[], body_of(body)?, idempotency_key)
            .await
    }
    pub async fn list(
        &self,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<ListPage<EntitlementOverride>, BackendError> {
        let mut q: Vec<(&str, String)> = Vec::new();
        if let Some(t) = subject_type {
            q.push(("subject_type", t.to_string()));
        }
        if let Some(i) = subject_id {
            q.push(("subject_id", i.to_string()));
        }
        self.client.request(HttpMethod::Get, "/v1/entitlement_overrides", &q, None, None).await
    }
    pub async fn get(&self, id: &str) -> Result<EntitlementOverride, BackendError> {
        let path = format!("/v1/entitlement_overrides/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn delete(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/entitlement_overrides/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

/// Per-organization platform surfaces, reached via
/// [`BackendClient::org_platform`]: branding, settings, effective entitlements.
pub struct OrgPlatform<'a> {
    client: &'a BackendClient,
    org_id: String,
}

impl OrgPlatform<'_> {
    /// `GET /v1/organizations/:id/branding`.
    pub async fn get_branding(&self) -> Result<OrgBranding, BackendError> {
        let path = format!("/v1/organizations/{}/branding", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PUT /v1/organizations/:id/branding`.
    pub async fn set_branding(&self, body: &SetOrgBrandingBody) -> Result<OrgBranding, BackendError> {
        let path = format!("/v1/organizations/{}/branding", seg(&self.org_id));
        self.client.request(HttpMethod::Put, &path, &[], body_of(body)?, None).await
    }
    /// `GET /v1/organizations/:id/settings`.
    pub async fn get_settings(&self) -> Result<OrgSettings, BackendError> {
        let path = format!("/v1/organizations/{}/settings", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PUT /v1/organizations/:id/settings` with `{ values }`.
    pub async fn put_settings(&self, values: Map<String, Value>) -> Result<OrgSettings, BackendError> {
        let path = format!("/v1/organizations/{}/settings", seg(&self.org_id));
        let body = serde_json::json!({ "values": values });
        self.client.request(HttpMethod::Put, &path, &[], Some(body), None).await
    }
    /// `GET /v1/organizations/:id/entitlements` — effective `{plan,features,limits}`.
    pub async fn entitlements(&self) -> Result<EffectiveEntitlements, BackendError> {
        let path = format!("/v1/organizations/{}/entitlements", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
}

/// The instance-wide org-settings schema (`/v1/organization_settings_schema`).
pub struct OrgSettingsSchemaApi<'a> {
    client: &'a BackendClient,
}

impl OrgSettingsSchemaApi<'_> {
    pub async fn get(&self) -> Result<OrgSettingsSchema, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/organization_settings_schema", &[], None, None)
            .await
    }
    /// `PUT` — register/replace the schema.
    pub async fn put(&self, schema: Value) -> Result<OrgSettingsSchema, BackendError> {
        let body = serde_json::json!({ "schema": schema });
        self.client
            .request(HttpMethod::Put, "/v1/organization_settings_schema", &[], Some(body), None)
            .await
    }
}

// ── user deletion / erasure ───────────────────────────────────────────────

/// Body for `POST /v1/users/:id/deletion`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScheduleDeletionBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_seconds: Option<u64>,
    /// User ids whose audit entries are retained/attributed through erasure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_actor_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_actor_emails: Option<Vec<String>>,
}

/// A user's erasure state, as returned by schedule/cancel/finalize.
#[derive(Debug, Clone, Deserialize)]
pub struct ErasureStatus {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub scheduled_for: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An app's erasure acknowledgement.
#[derive(Debug, Clone, Deserialize)]
pub struct ErasureAck {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// User deletion + erasure orchestration, reached via
/// [`BackendClient::user_erasure`].
pub struct UserErasure<'a> {
    client: &'a BackendClient,
    user_id: String,
}

impl UserErasure<'_> {
    /// `POST /v1/users/:id/deletion` — schedule deletion after a grace window.
    pub async fn schedule_deletion(
        &self,
        body: &ScheduleDeletionBody,
        idempotency_key: Option<&str>,
    ) -> Result<ErasureStatus, BackendError> {
        let path = format!("/v1/users/{}/deletion", seg(&self.user_id));
        self.client.request(HttpMethod::Post, &path, &[], body_of(body)?, idempotency_key).await
    }
    /// `POST /v1/users/:id/deletion/cancel`.
    pub async fn cancel_deletion(&self) -> Result<ErasureStatus, BackendError> {
        let path = format!("/v1/users/{}/deletion/cancel", seg(&self.user_id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/users/:id/deletion/finalize` — purge now.
    pub async fn finalize_deletion(&self) -> Result<ErasureStatus, BackendError> {
        let path = format!("/v1/users/{}/deletion/finalize", seg(&self.user_id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/users/:id/erasure_acks` — an app acknowledges (optionally
    /// returning an export blob) under its `source` name.
    pub async fn erasure_ack(
        &self,
        source: &str,
        payload: Option<Value>,
        idempotency_key: Option<&str>,
    ) -> Result<ErasureAck, BackendError> {
        let path = format!("/v1/users/{}/erasure_acks", seg(&self.user_id));
        let mut body = Map::new();
        body.insert("source".into(), Value::String(source.to_string()));
        if let Some(p) = payload {
            body.insert("payload".into(), p);
        }
        self.client
            .request(HttpMethod::Post, &path, &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    /// `GET /v1/users/:id/erasure_export` — the collected export. Shape is
    /// server-defined, so it is returned as a [`Value`].
    pub async fn erasure_export(&self) -> Result<Value, BackendError> {
        let path = format!("/v1/users/{}/erasure_export", seg(&self.user_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
}

// ── accessors ─────────────────────────────────────────────────────────────

impl BackendClient {
    /// The `/v1/audit_events` namespace.
    pub fn audit_events(&self) -> AuditEvents<'_> {
        AuditEvents { client: self }
    }
    /// The `/v1/tickets` namespace.
    pub fn tickets(&self) -> Tickets<'_> {
        Tickets { client: self }
    }
    /// The `/v1/notifications` namespace.
    pub fn notifications(&self) -> Notifications<'_> {
        Notifications { client: self }
    }
    /// The `/v1/notification_templates` namespace.
    pub fn notification_templates(&self) -> NotificationTemplates<'_> {
        NotificationTemplates { client: self }
    }
    /// The `/v1/notification_categories` namespace.
    pub fn notification_categories(&self) -> NotificationCategories<'_> {
        NotificationCategories { client: self }
    }
    /// The `/v1/entitlement_overrides` namespace.
    pub fn entitlement_overrides(&self) -> EntitlementOverrides<'_> {
        EntitlementOverrides { client: self }
    }
    /// The instance org-settings schema.
    pub fn org_settings_schema(&self) -> OrgSettingsSchemaApi<'_> {
        OrgSettingsSchemaApi { client: self }
    }
    /// Per-org branding, settings, and effective entitlements.
    pub fn org_platform(&self, org_id: &str) -> OrgPlatform<'_> {
        OrgPlatform { client: self, org_id: org_id.to_string() }
    }
    /// Per-user deletion scheduling and erasure acks/export.
    pub fn user_erasure(&self, user_id: &str) -> UserErasure<'_> {
        UserErasure { client: self, user_id: user_id.to_string() }
    }
}
