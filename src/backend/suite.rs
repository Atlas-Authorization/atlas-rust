//! The integrator platform surface: secret keys, `whoami`, partner links,
//! Sign in with Atlas grants, the privacy executor client, identity
//! integrations, webhook health / replay / signature v2, status, notices,
//! security advisories, sub-processors, audit exports, delivery health, the
//! instance diagnostics (`unknown_fields_report`, `openapi/diff`,
//! `integration-health`, `embed`), account audit logs and streams, provisioning
//! (`external_ref`, `metadata`, dry runs) and W3C `traceparent` helpers.
//!
//! Request bodies are generic over [`Serialize`], so pass a typed struct or a
//! `serde_json::json!` value. Responses whose shape is large and still growing
//! come back as [`Value`]; the ones worth branching on are typed
//! ([`SecretKey`], [`Whoami`], [`PartnerLink`], [`DryRunResult`],
//! [`WebhookTestResult`], [`WebhookBulkResult`], [`PrivacyRequest`], …), each
//! keeping unknown fields in `extra`.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::design::DesignApi;
use super::error::BackendError;
use super::instance::{Instance, MessagingProvidersApi, Preflight, WebhookEndpoint, WebhookEndpoints};
use super::pagination::Query;
use super::platform_api::{PlatformApi, PlatformApps};
use super::resources::{seg, ApiKeys, ListPage, OrgMemberships, Sessions, Users};
use super::webhook::{Event, VerifiedDelivery, Webhook, WebhookError, WebhookHeaders};

fn jb<B: Serialize + ?Sized>(body: &B) -> Result<Option<Value>, BackendError> {
    serde_json::to_value(body).map(Some).map_err(|e| BackendError::Malformed(e.to_string()))
}

// ── scopes and constants ────────────────────────────────────────────────────

/// Scope of the privacy executor surface (`/v1/privacy/*`).
pub const SCOPE_PRIVACY_EXECUTE: &str = "privacy:execute";
/// Scope that lets a partner link revoke a user's Sign in with Atlas grants.
pub const SCOPE_PRIVACY_GRANTS_REVOKE: &str = "privacy:grants:revoke";
/// Scope that lets a key reveal webhook signing secrets.
pub const SCOPE_WEBHOOKS_REVEAL: &str = "webhooks:reveal";

/// Privacy request types.
pub const PRIVACY_TYPES: &[&str] = &["access", "deletion", "closure", "restriction", "rectification"];
/// Privacy request statuses.
pub const PRIVACY_STATUSES: &[&str] = &[
    "pending",
    "scheduled",
    "processing",
    "completed",
    "completed_with_retention",
    "rejected",
    "no_match",
    "cancelled",
];
/// Webhook destination types an endpoint can deliver to.
pub const WEBHOOK_DESTINATION_TYPES: &[&str] = &["https", "aws_eventbridge", "gcp_pubsub", "cloudflare_queue"];
/// Outbound delivery target kinds `delivery().health` can filter on.
pub const DELIVERY_TARGET_KINDS: &[&str] =
    &["webhook_endpoint", "referral_connection", "backchannel_receiver", "integration"];

// ── traceparent ─────────────────────────────────────────────────────────────

/// Mint a fresh sampled W3C `traceparent` (`00-<32 hex>-<16 hex>-01`). Send it
/// with [`BackendClient::with_traceparent`] and Atlas stores the trace id on
/// the webhook deliveries, referral calls and executor requests the call
/// triggers.
pub fn new_traceparent() -> String {
    let mut rng = rand::thread_rng();
    let mut trace = [0u8; 16];
    let mut span = [0u8; 8];
    rng.fill_bytes(&mut trace);
    rng.fill_bytes(&mut span);
    // All-zero ids are invalid.
    if trace.iter().all(|b| *b == 0) {
        trace[15] = 1;
    }
    if span.iter().all(|b| *b == 0) {
        span[7] = 1;
    }
    format!("00-{}-{}-01", hex_of(&trace), hex_of(&span))
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Split a W3C `traceparent` into `(trace_id, span_id, flags)`; `None` when it
/// is malformed or its ids are all zero.
pub fn parse_traceparent(traceparent: &str) -> Option<(String, String, String)> {
    let lower = traceparent.trim().to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('-').collect();
    if parts.len() != 4 || !is_lower_hex(parts[0], 2) {
        return None;
    }
    let (trace, span, flags) = (parts[1], parts[2], parts[3]);
    if !is_lower_hex(trace, 32) || !is_lower_hex(span, 16) || !is_lower_hex(flags, 2) {
        return None;
    }
    if trace.bytes().all(|b| b == b'0') || span.bytes().all(|b| b == b'0') {
        return None;
    }
    Some((trace.to_string(), span.to_string(), flags.to_string()))
}

/// Read the `traceparent` Atlas sent on an executor / orchestrator request,
/// `None` when absent or malformed.
pub fn traceparent_from_headers<H: WebhookHeaders + ?Sized>(headers: &H) -> Option<String> {
    let v = headers.get_header("traceparent")?.trim().to_string();
    parse_traceparent(&v).map(|_| v)
}

// ── provisioning ────────────────────────────────────────────────────────────

/// The create-body fields every provisioning create (platform apps, instances,
/// Sign in with Atlas apps, OAuth clients, webhook endpoints, secret keys,
/// integrations) accepts. Flatten it into a body with
/// [`ProvisioningInput::apply`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProvisioningInput {
    /// Tags for the resource (strings, numbers, booleans). On a PATCH it
    /// replaces the tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
    /// A stable key of your own: a repeat create with it returns the existing
    /// object (200, no secret) instead of creating another one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
}

impl ProvisioningInput {
    /// Merge these fields into a JSON object body and return it.
    pub fn apply(&self, body: Value) -> Value {
        let mut obj = match body {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        if let Some(m) = &self.metadata {
            obj.insert("metadata".into(), Value::Object(m.clone()));
        }
        if let Some(r) = &self.external_ref {
            obj.insert("external_ref".into(), Value::String(r.clone()));
        }
        Value::Object(obj)
    }
}

/// The provisioning fields every tagged resource carries in a response.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProvisioningFields {
    pub metadata: Option<Value>,
    pub external_ref: Option<String>,
    /// `true` on a create that sent an `external_ref` and got the existing
    /// object back.
    pub idempotent_replay: bool,
}

/// Turn a metadata filter into the `metadata[key]=value` query parameters the
/// provisioning lists accept (keys sorted, so URLs are stable).
pub fn metadata_query(filter: &Map<String, Value>) -> Query {
    let mut keys: Vec<&String> = filter.keys().collect();
    keys.sort();
    let mut q = Query::new();
    for k in keys {
        let v = match &filter[k.as_str()] {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        q.push(format!("metadata[{k}]"), v);
    }
    q
}

/// One change a write would make (config-changelog shape).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DryRunChange {
    pub section: String,
    pub before: Value,
    pub after: Value,
}

/// What a write answers with `?dry_run=true`: the changes it would make;
/// nothing changed.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DryRunResult {
    pub object: String,
    pub dry_run: bool,
    /// `native` (the endpoint validated in full) or `plan` (the body diffed
    /// over the current object, unvalidated).
    pub mode: String,
    pub validated: bool,
    pub method: String,
    pub path: String,
    pub changes: Vec<DryRunChange>,
    pub would_return: Option<Value>,
    pub note: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl BackendClient {
    /// Send one write as a dry run and return the plan. `method` is POST, PUT,
    /// PATCH or DELETE; nothing changes.
    ///
    /// ```no_run
    /// # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
    /// use atlasauth::HttpMethod;
    /// let plan = atlas
    ///     .dry_run(HttpMethod::Patch, "/v1/platform/apps/ins_1", Some(serde_json::json!({"name": "New"})))
    ///     .await?;
    /// assert!(plan.dry_run);
    /// # Ok(()) }
    /// ```
    pub async fn dry_run(&self, method: HttpMethod, path: &str, body: Option<Value>) -> Result<DryRunResult, BackendError> {
        self.with_dry_run(true).request(method, path, &[], body, None).await
    }

    /// `GET /v1/whoami` — what the key you are calling with is: type, scopes,
    /// owner, expiry, and the instance (or partner link, or operator) behind it.
    pub async fn whoami(&self) -> Result<Whoami, BackendError> {
        self.request(HttpMethod::Get, "/v1/whoami", &[], None, None).await
    }

    /// Secret keys of the instance: create, rotate, revoke.
    pub fn secret_keys(&self) -> SecretKeys<'_> {
        SecretKeys { client: self }
    }
    /// Every credential of the instance in one list (`GET /v1/keys`).
    pub fn keys(&self) -> Keys<'_> {
        Keys { client: self }
    }
    /// Partner links (inbound) and outbound partner credentials.
    pub fn partner_links(&self) -> PartnerLinks<'_> {
        PartnerLinks { client: self }
    }
    /// Sign in with Atlas apps managed by this instance and their grants.
    pub fn atlas_id_grants(&self) -> AtlasIdGrants<'_> {
        AtlasIdGrants { client: self }
    }
    /// The privacy executor client (`/v1/privacy/*`) and the orchestrator
    /// settings.
    pub fn privacy(&self) -> Privacy<'_> {
        Privacy { client: self }
    }
    /// Identity-integration helpers (`/v1/integrations/*`, public instance
    /// metadata).
    pub fn integrations(&self) -> Integrations<'_> {
        Integrations { client: self }
    }
    /// Effective entitlements (`GET /v1/entitlements`).
    pub fn entitlements(&self) -> Entitlements<'_> {
        Entitlements { client: self }
    }
    /// Instance notices (`/v1/instance/notices`).
    pub fn notices(&self) -> Notices<'_> {
        Notices { client: self }
    }
    /// Security advisories (`/v1/security_advisories`).
    pub fn security_advisories(&self) -> SecurityAdvisories<'_> {
        SecurityAdvisories { client: self }
    }
    /// The sub-processor list (`/v1/instance/sub_processors`).
    pub fn sub_processors(&self) -> SubProcessors<'_> {
        SubProcessors { client: self }
    }
    /// Audit exports (CloudEvents streams to your SIEM).
    pub fn audit_exports(&self) -> AuditExports<'_> {
        AuditExports { client: self }
    }
    /// Atlas service status: incidents, subscriptions, dependencies.
    pub fn status(&self) -> Status<'_> {
        Status { client: self }
    }
    /// Delivery health of every outbound target and the egress IPs.
    pub fn delivery(&self) -> Delivery<'_> {
        Delivery { client: self }
    }
}

// ── whoami / secret keys / keys ─────────────────────────────────────────────

/// `GET /v1/whoami` and `GET /v1/platform/whoami`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Whoami {
    pub object: String,
    /// `{ id, type, prefix, environment, scopes, effective_scopes, owner,
    /// created_at, expires_at, last_used_at, … }`.
    pub key: Value,
    pub instance: Option<Value>,
    pub account: Option<Value>,
    pub platform: Option<Value>,
    /// Set when called with a partner link: `{ link_id, id, name }`.
    pub partner: Option<Value>,
    /// Set when called with an operator access token: `{ sub, auth_time, acr, amr }`.
    pub operator: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A secret key (metadata). The secret itself is in `secret` (or
/// `sealed_secret` when a secret recipient is set) exactly once, on create and
/// rotate.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SecretKey {
    pub object: String,
    pub id: String,
    pub kind: String,
    /// `atlas` (the `atlas_<env>_sk_…` format) or `legacy` (`sk_<env>_…`).
    pub format: String,
    pub prefix: String,
    pub name: Option<String>,
    pub owner: Option<String>,
    pub scopes: Vec<String>,
    pub environment: Option<String>,
    /// `{ type, id }` of what the key acts on.
    pub resource: Value,
    pub expires_at: Option<i64>,
    pub expires_in_days: Option<i64>,
    pub status: String,
    pub ip_allowlist: Vec<String>,
    pub origin_allowlist: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub last_used_at: Option<i64>,
    pub last_used_ip: Option<String>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub rotated_from: Option<String>,
    /// The new secret, shown once (create / rotate).
    pub secret: Option<String>,
    /// The new secret sealed to your recipient key (see
    /// [`BackendClientBuilder::secret_recipient`](super::BackendClientBuilder::secret_recipient)).
    pub sealed_secret: Option<String>,
    pub note: Option<String>,
    /// On a rotate: the key this one replaces.
    pub replaces: Option<String>,
    /// On a rotate: when the previous key stops working (epoch ms).
    pub previous_key_expires_at: Option<i64>,
    pub revoked: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Body of `POST /v1/secret_keys`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateSecretKeyBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Scope names (`read_only`, `apps:read`, …). Required.
    pub scopes: Vec<String>,
    /// Expiry as epoch ms (a number) or an ISO 8601 string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,
    /// The person or system that owns the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// `atlas` (default) or `legacy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// `/v1/secret_keys`. Reached via [`BackendClient::secret_keys`].
pub struct SecretKeys<'a> {
    client: &'a BackendClient,
}

impl SecretKeys<'_> {
    /// `POST /v1/secret_keys` — mint a key. The secret is in the response once.
    pub async fn create(&self, body: &CreateSecretKeyBody, idempotency_key: Option<&str>) -> Result<SecretKey, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/secret_keys", &[], jb(body)?, idempotency_key).await
    }
    /// `GET /v1/secret_keys`.
    pub async fn list(&self) -> Result<ListPage<SecretKey>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/secret_keys", &[], None, None).await
    }
    /// `GET /v1/secret_keys/:id`.
    pub async fn get(&self, id: &str) -> Result<SecretKey, BackendError> {
        let path = format!("/v1/secret_keys/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/secret_keys/:id` — rename, change owner / expiry / allowed
    /// IPs. Send `null` (e.g. `json!({"owner": null})`) to clear a field.
    pub async fn update<B: Serialize + ?Sized>(&self, id: &str, body: &B) -> Result<SecretKey, BackendError> {
        let path = format!("/v1/secret_keys/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], jb(body)?, None).await
    }
    /// `POST /v1/secret_keys/:id/rotate` — mint a replacement; the old key
    /// keeps working for `overlap_seconds` (default per instance; `0` = cut
    /// over now).
    pub async fn rotate(
        &self,
        id: &str,
        overlap_seconds: Option<u64>,
        key_format: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<SecretKey, BackendError> {
        let path = format!("/v1/secret_keys/{}/rotate", seg(id));
        let mut body = Map::new();
        if let Some(s) = overlap_seconds {
            body.insert("overlap_seconds".into(), json!(s));
        }
        if let Some(f) = key_format {
            body.insert("key_format".into(), json!(f));
        }
        self.client
            .request(HttpMethod::Post, &path, &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    /// `POST /v1/secret_keys/:id/revoke`.
    pub async fn revoke(&self, id: &str) -> Result<SecretKey, BackendError> {
        let path = format!("/v1/secret_keys/{}/revoke", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

/// `/v1/keys`. Reached via [`BackendClient::keys`].
pub struct Keys<'a> {
    client: &'a BackendClient,
}

impl Keys<'_> {
    /// `GET /v1/keys` — every credential of the instance (secret keys,
    /// publishable keys, webhook secrets), one standard shape.
    pub async fn list(&self) -> Result<ListPage<SecretKey>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/keys", &[], None, None).await
    }
}

// ── partner links ───────────────────────────────────────────────────────────

/// A partner link: a credential that lets a partner service (a CMP, a privacy
/// orchestrator) call your instance with limited scopes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PartnerLink {
    pub object: String,
    pub id: String,
    pub client_id: String,
    pub partner: String,
    pub name: String,
    pub preset: bool,
    pub resource: String,
    pub scopes: Vec<String>,
    pub client_secret_prefix: String,
    pub token_endpoint: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub last_used_ip: Option<String>,
    pub calls_30d: i64,
    pub created_at: i64,
    /// Shown once on create / rotate.
    pub client_secret: Option<String>,
    pub sealed_client_secret: Option<String>,
    pub revoked: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/partner_links`. Reached via [`BackendClient::partner_links`].
pub struct PartnerLinks<'a> {
    client: &'a BackendClient,
}

impl PartnerLinks<'_> {
    /// `POST /v1/partner_links` — body `{ partner, name?, scopes, expires_at? }`.
    pub async fn create<B: Serialize + ?Sized>(&self, body: &B, idempotency_key: Option<&str>) -> Result<PartnerLink, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/partner_links", &[], jb(body)?, idempotency_key).await
    }
    /// `GET /v1/partner_links`.
    pub async fn list(&self) -> Result<ListPage<PartnerLink>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/partner_links", &[], None, None).await
    }
    /// `GET /v1/partner_links/:id`.
    pub async fn get(&self, id: &str) -> Result<PartnerLink, BackendError> {
        let path = format!("/v1/partner_links/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/partner_links/:id/rotate_secret` — the new secret is shown once.
    pub async fn rotate_secret(&self, id: &str) -> Result<PartnerLink, BackendError> {
        let path = format!("/v1/partner_links/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `DELETE /v1/partner_links/:id` — revoke the link.
    pub async fn revoke(&self, id: &str) -> Result<PartnerLink, BackendError> {
        let path = format!("/v1/partner_links/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// Outbound partner credentials (Atlas calling the partner).
    pub fn outbound(&self) -> OutboundPartnerLinks<'_> {
        OutboundPartnerLinks { client: self.client }
    }
}

/// `/v1/partner_links/outbound`. Reached via [`PartnerLinks::outbound`].
pub struct OutboundPartnerLinks<'a> {
    client: &'a BackendClient,
}

impl OutboundPartnerLinks<'_> {
    /// `GET /v1/partner_links/outbound`.
    pub async fn list(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/partner_links/outbound", &[], None, None).await
    }
    /// `PUT /v1/partner_links/outbound/:partner` — body `{ client_id,
    /// client_secret, scopes?, resource?, base_url?, token_url?, auth_method?,
    /// name?, expires_at? }`.
    pub async fn save<B: Serialize + ?Sized>(&self, partner: &str, body: &B) -> Result<Value, BackendError> {
        let path = format!("/v1/partner_links/outbound/{}", seg(partner));
        self.client.request(HttpMethod::Put, &path, &[], jb(body)?, None).await
    }
    /// `POST /v1/partner_links/outbound/:partner/test` — `{ ok, error? }`.
    pub async fn test(&self, partner: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/partner_links/outbound/{}/test", seg(partner));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `DELETE /v1/partner_links/outbound/:partner`.
    pub async fn remove(&self, partner: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/partner_links/outbound/{}", seg(partner));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

/// `/v1/atlas_id_apps`. Reached via [`BackendClient::atlas_id_grants`].
pub struct AtlasIdGrants<'a> {
    client: &'a BackendClient,
}

impl AtlasIdGrants<'_> {
    /// `GET /v1/atlas_id_apps` — the Sign in with Atlas apps this instance manages.
    pub async fn list_apps(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/atlas_id_apps", &[], None, None).await
    }
    /// `GET /v1/atlas_id_apps/:app/users?email=` — the grants of the user with
    /// that email.
    pub async fn lookup(&self, app_id: &str, email: &str) -> Result<ListPage<Value>, BackendError> {
        let path = format!("/v1/atlas_id_apps/{}/users", seg(app_id));
        let q = vec![("email", email.to_string())];
        self.client.request(HttpMethod::Get, &path, &q, None, None).await
    }
    /// `DELETE /v1/atlas_id_apps/:app/grants/:grant` — revoke one grant (its
    /// tokens and back-channel sessions).
    pub async fn revoke(&self, app_id: &str, grant_id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/atlas_id_apps/{}/grants/{}", seg(app_id), seg(grant_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── privacy executor ────────────────────────────────────────────────────────

/// A privacy (data subject) request as the executor API serves it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PrivacyRequest {
    pub object: String,
    pub id: String,
    #[serde(rename = "type")]
    pub request_type: String,
    #[serde(rename = "canonicalType")]
    pub canonical_type: String,
    #[serde(rename = "requestedType")]
    pub requested_type: String,
    /// One of [`PRIVACY_STATUSES`].
    pub status: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "caseId")]
    pub case_id: Option<String>,
    #[serde(rename = "executeAfter")]
    pub execute_after: Option<String>,
    pub eta: Option<String>,
    pub detail: Option<String>,
    pub retention: Vec<Value>,
    pub steps: Vec<Value>,
    pub trace: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<String>,
    pub result: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The answer of `POST /v1/privacy/lookup`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PrivacyLookupResult {
    pub object: String,
    /// `matched`, `no_match` or `ambiguous`.
    pub status: String,
    #[serde(rename = "subjectId")]
    pub subject_id: Option<String>,
    #[serde(rename = "matchedBy")]
    pub matched_by: Option<String>,
    pub detail: Option<String>,
    pub principal: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/privacy/*`. Reached via [`BackendClient::privacy`].
pub struct Privacy<'a> {
    client: &'a BackendClient,
}

impl Privacy<'_> {
    /// `GET /v1/privacy` — discovery: what the executor supports.
    pub async fn discover(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/privacy", &[], None, None).await
    }
    /// `GET /v1/privacy/presets/:id` — a partner preset (e.g. `cookiemunch`).
    pub async fn preset(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/privacy/presets/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/privacy/lookup` — find the subject: `{ "emails": [..] }` and /
    /// or `{ "atlas": { "iss", "sub" } }`.
    pub async fn lookup<B: Serialize + ?Sized>(&self, body: &B) -> Result<PrivacyLookupResult, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/privacy/lookup", &[], jb(body)?, None).await
    }
    /// `POST /v1/privacy/requests` — body `{ subjectId, type, caseId,
    /// executeAfter?, reason? }`. Pass an idempotency key.
    pub async fn create_request<B: Serialize + ?Sized>(
        &self,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<PrivacyRequest, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/privacy/requests", &[], jb(body)?, idempotency_key).await
    }
    /// `GET /v1/privacy/requests/:id`.
    pub async fn get_request(&self, id: &str) -> Result<PrivacyRequest, BackendError> {
        let path = format!("/v1/privacy/requests/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/privacy/requests/:id/cancel`.
    pub async fn cancel_request(&self, id: &str) -> Result<PrivacyRequest, BackendError> {
        let path = format!("/v1/privacy/requests/{}/cancel", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `GET /v1/instance/privacy_orchestrator`.
    pub async fn get_orchestrator(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/privacy_orchestrator", &[], None, None).await
    }
    /// `PUT /v1/instance/privacy_orchestrator` — configure where Atlas opens
    /// cases (`provider`, `case_url`, `sign_requests`, …). Send `null` to clear
    /// a field.
    pub async fn set_orchestrator<B: Serialize + ?Sized>(&self, body: &B) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Put, "/v1/instance/privacy_orchestrator", &[], jb(body)?, None).await
    }
    /// `DELETE /v1/instance/privacy_orchestrator`.
    pub async fn delete_orchestrator(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Delete, "/v1/instance/privacy_orchestrator", &[], None, None).await
    }
}

/// A verified request from Atlas to your privacy executor / orchestrator
/// receiver.
#[derive(Debug, Clone)]
pub struct PrivacyCall {
    /// The signed `atlas-id` header (stable across retries: deduplicate on it).
    pub delivery_id: String,
    /// The signed `atlas-timestamp` header (epoch ms).
    pub timestamp: i64,
    /// The W3C `traceparent` Atlas sent, if any.
    pub traceparent: Option<String>,
    /// The envelope, when the body is one (`privacy_request.*` events); `None`
    /// for a signed case call, whose body is the case itself.
    pub event: Option<Event>,
    /// The raw verified body.
    pub body: Vec<u8>,
}

/// Verify a signed call from Atlas — a case call to your orchestrator, or a
/// `privacy_request.*` event — with the signing secret you configured
/// (`signing_secret` of the privacy orchestrator, or your endpoint's secret).
/// Same `atlas-id` / `atlas-timestamp` / `atlas-signature` scheme and five
/// minute window as webhooks; verify over the RAW body.
pub fn verify_privacy_call<H: WebhookHeaders + ?Sized>(
    secret: &str,
    raw: &[u8],
    headers: &H,
) -> Result<PrivacyCall, WebhookError> {
    let VerifiedDelivery { event, delivery_id, timestamp } = Webhook::new(secret).verify_delivery(raw, headers)?;
    // An event envelope has a dotted type (`privacy_request.completed`); a case
    // call's own `type` (`deletion`) is not one.
    let has_type = event.event_type.as_str().contains('.');
    Ok(PrivacyCall {
        delivery_id,
        timestamp,
        traceparent: traceparent_from_headers(headers),
        event: if has_type { Some(event) } else { None },
        body: raw.to_vec(),
    })
}

/// Decode the `data` of a `privacy_request.*` event into a [`PrivacyRequest`].
pub fn privacy_request_from_event(event: &Event) -> Result<PrivacyRequest, BackendError> {
    serde_json::from_value(event.data.clone()).map_err(|e| BackendError::Malformed(e.to_string()))
}

// ── identity integrations ───────────────────────────────────────────────────

/// A token minted for an integration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IntegrationToken {
    pub object: String,
    pub integration: String,
    pub product: String,
    pub jwt: String,
    pub expires_in: i64,
    pub audience: String,
    pub org_id: Option<String>,
    pub space_id: Option<String>,
    pub redeem_url: Option<String>,
    pub issuer: Option<String>,
    pub jwks_uri: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Instance<'_> {
    /// `GET /v1/instance/integrations`.
    pub async fn list_integrations(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/integrations", &[], None, None).await
    }
    /// `GET /v1/instance/integrations/:id`.
    pub async fn get_integration(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/integrations/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PUT /v1/instance/integrations/:id` — enable or configure an
    /// integration (`enabled`, `audience`, `ttl_seconds`, `events_url`, `cmp`,
    /// `atlas_id_users`, `external_ref`, …). Send `null` to clear a field.
    pub async fn set_integration<B: Serialize + ?Sized>(
        &self,
        id: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/integrations/{}", seg(id));
        self.client.request(HttpMethod::Put, &path, &[], jb(body)?, idempotency_key).await
    }
    /// `DELETE /v1/instance/integrations/:id`.
    pub async fn delete_integration(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/integrations/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `GET /v1/instance/integrations/:id/deliveries` — filter with `kind`
    /// (`event` / `backchannel_logout`), `trace`, `limit`, `starting_after`.
    pub async fn integration_deliveries(&self, id: &str, query: &Query) -> Result<ListPage<Value>, BackendError> {
        let path = format!("/v1/instance/integrations/{}/deliveries", seg(id));
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
    /// `POST /v1/instance/integrations/:id/events_secret` — reveal the events
    /// signing secret.
    pub async fn reveal_integration_events_secret(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/integrations/{}/events_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/instance/integrations/:id/atlas_id_tokens` — exchange a Sign
    /// in with Atlas access token for an integration token.
    pub async fn integration_atlas_id_token(&self, id: &str, access_token: &str) -> Result<IntegrationToken, BackendError> {
        let path = format!("/v1/instance/integrations/{}/atlas_id_tokens", seg(id));
        self.client
            .request(HttpMethod::Post, &path, &[], Some(json!({ "access_token": access_token })), None)
            .await
    }
    /// `GET /v1/instance/preflight` with the `min_severity` / `include_suppressed`
    /// filters (and the new finding fields).
    pub async fn preflight_with(&self, query: &Query) -> Result<Preflight, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/preflight", &query.as_pairs(), None, None).await
    }
    /// `GET /v1/instance/unknown_fields_report?days=` — body fields your
    /// integration sends that Atlas ignored (usually typos).
    pub async fn unknown_fields_report(&self, days: Option<u32>) -> Result<Value, BackendError> {
        let q = Query::new().set_opt("days", days);
        self.client.request(HttpMethod::Get, "/v1/instance/unknown_fields_report", &q.as_pairs(), None, None).await
    }
    /// `GET /v1/openapi/diff?since=&surface=` — what changed in the API since
    /// a date; `surface` is `bapi`, `fapi`, `platform`, ….
    pub async fn openapi_diff(&self, since: &str, surface: Option<&str>) -> Result<Value, BackendError> {
        let q = Query::new().set("since", since).set_opt("surface", surface);
        self.client.request(HttpMethod::Get, "/v1/openapi/diff", &q.as_pairs(), None, None).await
    }
    /// `GET /v1/integration-health` — one call that probes every integration
    /// (`only=webhooks,email`, `probe=false`).
    pub async fn integration_health(&self, query: &Query) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/integration-health", &query.as_pairs(), None, None).await
    }
    /// `GET /v1/integration-health/providers`.
    pub async fn integration_health_providers(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/integration-health/providers", &[], None, None).await
    }
    /// `GET /v1/embed?instance=&origin=&shape=` — the embed snippet and the
    /// CSP directives for an origin.
    pub async fn embed(&self, query: &Query) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/embed", &query.as_pairs(), None, None).await
    }
    /// `POST /v1/instance/referrals/:provider/install` — one-click install of a
    /// referral provider (`{ "return_to": … }`). `referalli` is the provider
    /// id; the former `referally` is accepted too.
    pub async fn install_referral<B: Serialize + ?Sized>(&self, provider: &str, body: &B) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/referrals/{}/install", seg(provider));
        self.client.request(HttpMethod::Post, &path, &[], jb(body)?, None).await
    }
}

impl Sessions<'_> {
    /// `POST /v1/sessions/:id/integration_tokens/:integration` — mint a token
    /// for an integration server-side (the `getToken({for})` form).
    pub async fn get_integration_token(&self, session_id: &str, integration: &str) -> Result<IntegrationToken, BackendError> {
        let path = format!("/v1/sessions/{}/integration_tokens/{}", seg(session_id), seg(integration));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

impl MessagingProvidersApi<'_> {
    /// `GET /v1/messaging_providers/:channel` (`email` or `sms`) — the
    /// provider configured for one channel (with `configured`).
    pub async fn channel(&self, channel: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/messaging_providers/{}", seg(channel));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
}

impl DesignApi<'_> {
    /// `PUT /v1/instance/design` with `{ "brand_url": … }` — import brand
    /// tokens from a URL.
    pub async fn import_brand_url(&self, brand_url: &str) -> Result<Value, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/instance/design", &[], Some(json!({ "brand_url": brand_url })), None)
            .await
    }
    /// `PUT /v1/instance/design` with `{ "brand": null }` — remove the imported brand.
    pub async fn remove_brand(&self) -> Result<Value, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/instance/design", &[], Some(json!({ "brand": null })), None)
            .await
    }
}

/// `/v1/integrations/*`. Reached via [`BackendClient::integrations`].
pub struct Integrations<'a> {
    client: &'a BackendClient,
}

impl Integrations<'_> {
    /// `POST /v1/integrations/verify_errors` — report a token an integration
    /// refused: `{ integration, error, audience?, at?, kid?, sid?, detail? }`.
    pub async fn report_verify_error<B: Serialize + ?Sized>(&self, body: &B) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/integrations/verify_errors", &[], jb(body)?, None).await
    }
    /// `GET /v1/integrations/:integration/card?sub=&iss=` — the support card
    /// of a user.
    pub async fn card(&self, integration: &str, sub: &str, iss: Option<&str>) -> Result<Value, BackendError> {
        let path = format!("/v1/integrations/{}/card", seg(integration));
        let q = Query::new().set_opt("iss", iss).set("sub", sub);
        self.client.request(HttpMethod::Get, &path, &q.as_pairs(), None, None).await
    }
    /// `POST /v1/integrations/:integration/card/actions/revoke_sessions`.
    /// `agent` is the support agent doing it (`{ id?, name?, email? }`).
    pub async fn revoke_sessions(
        &self,
        integration: &str,
        sub: &str,
        iss: Option<&str>,
        agent: Option<&Value>,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/integrations/{}/card/actions/revoke_sessions", seg(integration));
        let mut body = Map::new();
        body.insert("sub".into(), json!(sub));
        if let Some(i) = iss {
            body.insert("iss".into(), json!(i));
        }
        if let Some(a) = agent {
            body.insert("agent".into(), a.clone());
        }
        self.client.request(HttpMethod::Post, &path, &[], Some(Value::Object(body)), None).await
    }
    /// `GET /v1/public/instances/:id` — public instance metadata (issuer, JWKS,
    /// token schema, integrations, trusted issuers). No key needed on the wire.
    pub async fn instance_metadata(&self, instance_id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/public/instances/{}", seg(instance_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
}

// ── entitlements, notices, advisories, sub-processors, audit exports ───────

/// `/v1/entitlements`. Reached via [`BackendClient::entitlements`].
pub struct Entitlements<'a> {
    client: &'a BackendClient,
}

impl Entitlements<'_> {
    /// `GET /v1/entitlements?subject_type=&subject_id=` — the effective
    /// entitlements of a user or organization (`subject_type` is `user` or
    /// `org`), overrides included.
    pub async fn get(&self, subject_type: &str, subject_id: &str) -> Result<Value, BackendError> {
        let q = Query::new().set("subject_id", subject_id).set("subject_type", subject_type);
        self.client.request(HttpMethod::Get, "/v1/entitlements", &q.as_pairs(), None, None).await
    }
}

/// `/v1/instance/notices`. Reached via [`BackendClient::notices`].
pub struct Notices<'a> {
    client: &'a BackendClient,
}

impl Notices<'_> {
    /// `GET /v1/instance/notices` — pass `all = true` to include acknowledged ones.
    pub async fn list(&self, all: bool) -> Result<ListPage<Value>, BackendError> {
        let q = if all { Query::new().set("all", "true") } else { Query::new() };
        self.client.request(HttpMethod::Get, "/v1/instance/notices", &q.as_pairs(), None, None).await
    }
    /// `POST /v1/instance/notices/:id/acknowledge`.
    pub async fn acknowledge(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/notices/{}/acknowledge", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

/// `/v1/security_advisories`. Reached via [`BackendClient::security_advisories`].
pub struct SecurityAdvisories<'a> {
    client: &'a BackendClient,
}

impl SecurityAdvisories<'_> {
    /// `GET /v1/security_advisories` — the advisories that apply to you.
    pub async fn list(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/security_advisories", &[], None, None).await
    }
    /// `POST /v1/security_advisories/:id/acknowledge`.
    pub async fn acknowledge(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/security_advisories/{}/acknowledge", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `GET /v1/public/security_advisories` — the public catalog.
    pub async fn catalog(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/public/security_advisories", &[], None, None).await
    }
}

/// `/v1/instance/sub_processors`. Reached via [`BackendClient::sub_processors`].
pub struct SubProcessors<'a> {
    client: &'a BackendClient,
}

impl SubProcessors<'_> {
    /// `GET /v1/instance/sub_processors`.
    pub async fn get(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/sub_processors", &[], None, None).await
    }
}

/// `/v1/audit_exports`. Reached via [`BackendClient::audit_exports`].
pub struct AuditExports<'a> {
    client: &'a BackendClient,
}

impl AuditExports<'_> {
    /// `GET /v1/audit_exports`.
    pub async fn list(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/audit_exports", &[], None, None).await
    }
    /// `GET /v1/audit_exports/:id`.
    pub async fn get(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/audit_exports/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/audit_exports` — `{ name, type, destination, backfill_hours?,
    /// action_filter? }`.
    pub async fn create<B: Serialize + ?Sized>(&self, body: &B, idempotency_key: Option<&str>) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/audit_exports", &[], jb(body)?, idempotency_key).await
    }
    /// `PATCH /v1/audit_exports/:id` — send `null` to clear `action_filter`.
    pub async fn update<B: Serialize + ?Sized>(&self, id: &str, body: &B) -> Result<Value, BackendError> {
        let path = format!("/v1/audit_exports/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], jb(body)?, None).await
    }
    /// `DELETE /v1/audit_exports/:id`.
    pub async fn delete(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/audit_exports/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/audit_exports/:id/test`.
    pub async fn test(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/audit_exports/{}/test", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/audit_exports/:id/rotate_secret`.
    pub async fn rotate_secret(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/audit_exports/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

// ── status ──────────────────────────────────────────────────────────────────

/// `/v1/status` and `/v1/instance/status_*`. Reached via [`BackendClient::status`].
pub struct Status<'a> {
    client: &'a BackendClient,
}

impl Status<'_> {
    /// `GET /v1/status` — Atlas service status.
    pub async fn service(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/status", &[], None, None).await
    }
    /// `GET /v1/instance/status_subscription`.
    pub async fn get_subscription(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/status_subscription", &[], None, None).await
    }
    /// `PUT /v1/instance/status_subscription` — `{ component_ids?, min_impact?,
    /// regions? }`.
    pub async fn update_subscription<B: Serialize + ?Sized>(&self, body: &B) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Put, "/v1/instance/status_subscription", &[], jb(body)?, None).await
    }
    /// `DELETE /v1/instance/status_subscription`.
    pub async fn disable_subscription(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Delete, "/v1/instance/status_subscription", &[], None, None).await
    }
    /// `POST /v1/instance/status_subscription/rotate_feed` — new private feed URL.
    pub async fn rotate_feed(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/instance/status_subscription/rotate_feed", &[], None, None).await
    }
    /// `GET /v1/instance/status_incidents` — `open=true`, `limit`.
    pub async fn list_incidents(&self, query: &Query) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/status_incidents", &query.as_pairs(), None, None).await
    }
    /// `GET /v1/instance/status_dependencies`.
    pub async fn list_dependencies(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/instance/status_dependencies", &[], None, None).await
    }
    /// `POST /v1/instance/status_dependencies` — `{ name, url }`.
    pub async fn create_dependency<B: Serialize + ?Sized>(&self, body: &B) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/instance/status_dependencies", &[], jb(body)?, None).await
    }
    /// `GET /v1/instance/status_dependencies/:id`.
    pub async fn get_dependency(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/status_dependencies/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/instance/status_dependencies/:id`.
    pub async fn update_dependency<B: Serialize + ?Sized>(&self, id: &str, body: &B) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/status_dependencies/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], jb(body)?, None).await
    }
    /// `DELETE /v1/instance/status_dependencies/:id`.
    pub async fn delete_dependency(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/status_dependencies/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/instance/status_dependencies/:id/refresh` — check it now.
    pub async fn refresh_dependency(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/instance/status_dependencies/{}/refresh", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

// ── delivery health and webhook endpoints ──────────────────────────────────

/// `/v1/delivery_health` and `/v1/meta/egress_ips`. Reached via
/// [`BackendClient::delivery`].
pub struct Delivery<'a> {
    client: &'a BackendClient,
}

impl Delivery<'_> {
    /// `GET /v1/meta/egress_ips` — the addresses deliveries leave from (allow
    /// them at your firewall).
    pub async fn egress_ips(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/meta/egress_ips", &[], None, None).await
    }
    /// `GET /v1/delivery_health` — health of every outbound target; filter with
    /// `kind` ([`DELIVERY_TARGET_KINDS`]) and `state` (`healthy`, `failing`,
    /// `disabled`, `unhealthy`).
    pub async fn health(&self, query: &Query) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/delivery_health", &query.as_pairs(), None, None).await
    }
    /// `PUT /v1/delivery_health/:kind/:id/alert_contacts` — who gets the
    /// failure emails for a target (empty = the account's owners).
    pub async fn set_alert_contacts(&self, kind: &str, target_id: &str, contacts: &[String]) -> Result<Value, BackendError> {
        let path = format!("/v1/delivery_health/{}/{}/alert_contacts", seg(kind), seg(target_id));
        self.client
            .request(HttpMethod::Put, &path, &[], Some(json!({ "alert_contacts": contacts })), None)
            .await
    }
}

/// The inline result of [`WebhookEndpoints::test_now`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WebhookTestResult {
    pub object: String,
    pub delivery_id: String,
    pub event_id: String,
    pub status: String,
    pub http_status: Option<i64>,
    pub latency_ms: Option<i64>,
    pub response_snippet: Option<String>,
    pub error: Option<String>,
    pub signature_header_sent: Option<String>,
    pub will_retry: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The answer to a bulk redelivery or replay.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WebhookBulkResult {
    /// `webhook_redelivery` or `webhook_replay`.
    pub object: String,
    pub endpoint_id: String,
    pub queued: i64,
    pub events_considered: Option<i64>,
    pub has_more: bool,
    /// When `has_more`: the `since` that continues the call.
    pub next_since: Option<i64>,
    /// `{ events_days, delivery_log_days, replay_window_days }`.
    pub retention: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl WebhookEndpoints<'_> {
    /// `GET /v1/webhook_endpoints/:id` — one endpoint with its health.
    pub async fn get(&self, id: &str) -> Result<WebhookEndpoint, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `GET /v1/webhook_endpoints` with `include_deprecated=true` and /
    /// or `metadata[key]=value` filters (build with [`metadata_query`]).
    pub async fn list_with(&self, query: &Query) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/webhook_endpoints", &query.as_pairs(), None, None).await
    }
    /// `PUT /v1/webhook_endpoints/by_url` — find the endpoint with this `url`
    /// and update it, or create it (then `secret` is set, once). Safe to run on
    /// every deploy.
    pub async fn upsert_by_url<B: Serialize + ?Sized>(
        &self,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<WebhookEndpoint, BackendError> {
        self.client
            .request(HttpMethod::Put, "/v1/webhook_endpoints/by_url", &[], jb(body)?, idempotency_key)
            .await
    }
    /// `POST /v1/webhook_endpoints/:id/test?wait=` — send `webhook.test` and
    /// wait for the result. `wait` is at most `10s` (`"5s"`, `"5000ms"`).
    pub async fn test_now(&self, id: &str, wait: &str) -> Result<WebhookTestResult, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/test", seg(id));
        let q = vec![("wait", wait.to_string())];
        self.client.request(HttpMethod::Post, &path, &q, None, None).await
    }
    /// `POST /v1/webhook_endpoints/:id/redeliver` — redeliver every event whose
    /// latest attempt in the window has `status` (`failed` default, or
    /// `success`): `{ since?, until?, status? }`, epoch ms, at most 90 days back.
    pub async fn redeliver_window<B: Serialize + ?Sized>(
        &self,
        id: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<WebhookBulkResult, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/redeliver", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], jb(body)?, idempotency_key).await
    }
    /// `POST /v1/webhook_endpoints/:id/replay` — re-send everything since
    /// `since` that the endpoint subscribes to and has not received:
    /// `{ since, until?, event_type? }`.
    pub async fn replay<B: Serialize + ?Sized>(
        &self,
        id: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<WebhookBulkResult, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/replay", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], jb(body)?, idempotency_key).await
    }
    /// `GET /v1/webhook_endpoints/:id/deliveries` with the `status`,
    /// `event_type`, `since`, `until`, `starting_after` filters and `limit` up
    /// to 1000.
    pub async fn deliveries_with(&self, id: &str, query: &Query) -> Result<ListPage<super::instance::WebhookDelivery>, BackendError> {
        let path = format!("/v1/webhook_endpoints/{}/deliveries", seg(id));
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
}

// ── cursor / filter list variants ───────────────────────────────────────────

impl Users<'_> {
    /// `GET /v1/users` with any query: `updated_after`, `updated_before`
    /// (epoch ms), `order_by=-updated_at`, `limit`, `starting_after`, ….
    pub async fn list_query(&self, query: &Query) -> Result<super::pagination::CursorPage<super::resources::User>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/users", &query.as_pairs(), None, None).await
    }
}

impl OrgMemberships<'_> {
    /// `GET /v1/organizations/:id/memberships` with `limit` / `starting_after`.
    pub async fn list_query(
        &self,
        query: &Query,
    ) -> Result<super::pagination::CursorPage<super::resources::OrganizationMembership>, BackendError> {
        let path = format!("/v1/organizations/{}/memberships", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
}

impl ApiKeys<'_> {
    /// `GET /v1/api_keys/revoked` with `starting_after` / `limit` / `since`.
    pub async fn list_revoked_query(&self, query: &Query) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/api_keys/revoked", &query.as_pairs(), None, None).await
    }
}

// ── platform: whoami, keys, account audit, provisioning ────────────────────

impl PlatformApi<'_> {
    /// `GET /v1/platform/whoami`.
    pub async fn whoami(&self) -> Result<Whoami, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/whoami", &[], None, None).await
    }
    /// `GET /v1/platform/keys` — `kind=secret_key`, `status=active`, ….
    pub async fn list_keys(&self, query: &Query) -> Result<ListPage<SecretKey>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/keys", &query.as_pairs(), None, None).await
    }
    /// `POST /v1/platform/keys` — `{ scopes, name?, expires_at?, key_format?, … }`.
    pub async fn create_key<B: Serialize + ?Sized>(&self, body: &B, idempotency_key: Option<&str>) -> Result<SecretKey, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/platform/keys", &[], jb(body)?, idempotency_key).await
    }
    /// `PATCH /v1/platform/keys/:id`.
    pub async fn update_key<B: Serialize + ?Sized>(&self, id: &str, body: &B) -> Result<SecretKey, BackendError> {
        let path = format!("/v1/platform/keys/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], jb(body)?, None).await
    }
    /// `POST /v1/platform/keys/:id/revoke`.
    pub async fn revoke_key(&self, id: &str) -> Result<SecretKey, BackendError> {
        let path = format!("/v1/platform/keys/{}/revoke", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `GET /v1/platform/audit_logs` — the account audit log (`action`,
    /// `limit`, `starting_after`, …).
    pub async fn audit_logs(&self, query: &Query) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/audit_logs", &query.as_pairs(), None, None).await
    }
    /// `GET /v1/platform/audit_streams`.
    pub async fn list_audit_streams(&self) -> Result<ListPage<Value>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/platform/audit_streams", &[], None, None).await
    }
    /// `POST /v1/platform/audit_streams` — `{ url, format }` (`cloudevents`).
    pub async fn create_audit_stream<B: Serialize + ?Sized>(&self, body: &B) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Post, "/v1/platform/audit_streams", &[], jb(body)?, None).await
    }
    /// `PATCH /v1/platform/audit_streams/:id`.
    pub async fn update_audit_stream<B: Serialize + ?Sized>(&self, id: &str, body: &B) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/audit_streams/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], jb(body)?, None).await
    }
    /// `DELETE /v1/platform/audit_streams/:id`.
    pub async fn delete_audit_stream(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/audit_streams/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `POST /v1/platform/audit_streams/:id/test`.
    pub async fn test_audit_stream(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/audit_streams/{}/test", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

impl PlatformApps<'_> {
    /// `POST /v1/platform/apps/:id/secret_keys` — mint a key for an app
    /// (`{ name?, external_ref?, metadata? }`); the secret is shown once.
    pub async fn create_secret_key<B: Serialize + ?Sized>(
        &self,
        id: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/secret_keys", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], jb(body)?, idempotency_key).await
    }
    /// `GET /v1/platform/apps/:id/secret_keys` filtered by
    /// `metadata[key]=value` (build with [`metadata_query`]).
    pub async fn secret_keys_with(&self, id: &str, query: &Query) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/secret_keys", seg(id));
        self.client.request(HttpMethod::Get, &path, &query.as_pairs(), None, None).await
    }
    /// `POST /v1/platform/apps/:id/clone_config` — copy configuration to another
    /// environment: `{ to_environment, dry_run? }`.
    pub async fn clone_config<B: Serialize + ?Sized>(
        &self,
        id: &str,
        body: &B,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/platform/apps/{}/clone_config", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], jb(body)?, idempotency_key).await
    }
    /// `POST /v1/platform/apps/bulk_delete` — tear down sandboxes by tag:
    /// `{ metadata: { sandbox: true }, dry_run? }`. Run it with `dry_run: true`
    /// first.
    pub async fn sandbox_teardown(&self, metadata: Option<&Map<String, Value>>, dry_run: bool) -> Result<Value, BackendError> {
        let mut body = Map::new();
        body.insert("dry_run".into(), json!(dry_run));
        if let Some(m) = metadata {
            body.insert("metadata".into(), Value::Object(m.clone()));
        }
        self.client
            .request(HttpMethod::Post, "/v1/platform/apps/bulk_delete", &[], Some(Value::Object(body)), None)
            .await
    }
}
