//! Typed resource namespaces over the shared request core.
//!
//! The wire is snake_case JSON; these types mirror it exactly (no camelCase
//! translation), because the SDK's job is to type the BAPI, not to invent a
//! second dialect a reader must reconcile against the docs. Method names,
//! endpoint paths, and body shapes match `@atlasauth/backend` (cross-checked
//! against `atlas-go`): `list`/`get`/`create`/`update`/`delete` plus the
//! resource-specific verbs.
//!
//! This covers the core management surface — users, organizations (+
//! memberships, invitations, domains, policy), instance invitations, API keys,
//! billing, sessions, OAuth access grants, and custom domains. Response structs
//! keep the fields a caller reads and flatten the rest into `extra`, so a new
//! server-side field never breaks deserialization.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::{encode_component, BackendClient};
use super::error::BackendError;
use super::pagination::{CursorPage, CursorParams};

/// A free-form metadata bag. The BAPI stores arbitrary JSON objects here.
pub type Metadata = Map<String, Value>;

/// The `{ object: "list", data, has_more? }` envelope some list routes use.
#[derive(Debug, Clone, Deserialize)]
pub struct ListPage<T> {
    #[serde(default = "Vec::new")]
    pub data: Vec<T>,
    #[serde(default)]
    pub has_more: bool,
}

/// The minimal `{ object, id, deleted }` acknowledgement several DELETE routes
/// return.
#[derive(Debug, Clone, Deserialize)]
pub struct DeletedObject {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub deleted: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Turn a typed, `skip_serializing_if`-annotated request body into an optional
/// JSON value — `None` for a body-less call, so the request core omits it.
fn body_of<T: Serialize>(body: &T) -> Result<Option<Value>, BackendError> {
    serde_json::to_value(body)
        .map(Some)
        .map_err(|e| BackendError::Malformed(e.to_string()))
}

/// A path segment encoder shared by every resource (an id, a slug, a provider).
fn seg(s: &str) -> String {
    encode_component(s)
}

// ── users ───────────────────────────────────────────────────────────────────

/// A user as the BAPI serves it. `private_metadata` is never returned.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub image_url: Option<String>,
    #[serde(default)]
    pub public_metadata: Metadata,
    #[serde(default)]
    pub mfa_enabled: bool,
    #[serde(default)]
    pub banned: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub last_sign_in_at: Option<i64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `POST /v1/users` body.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateUserBody {
    pub email_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_metadata: Option<Metadata>,
}

/// `PATCH /v1/users/:id` body.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateUserBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_metadata: Option<Metadata>,
}

/// An OAuth consent grant — the scopes a user authorized a client for. Never a
/// token.
#[derive(Debug, Clone, Deserialize)]
pub struct Grant {
    pub id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The cascade a grant revocation reports: the grant plus the live access/
/// refresh tokens that were revoked with it.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantRevocation {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub tokens_revoked: u64,
}

/// `DELETE /v1/users/:id/grants` cascade summary.
#[derive(Debug, Clone, Deserialize)]
pub struct AllGrantsRevocation {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub grants_revoked: u64,
    #[serde(default)]
    pub tokens_revoked: u64,
}

/// The `/v1/users` namespace.
pub struct Users<'a> {
    client: &'a BackendClient,
}

impl<'a> Users<'a> {
    /// `GET /v1/users` — cursor-paginated.
    pub async fn list(&self, params: CursorParams) -> Result<CursorPage<User>, BackendError> {
        let q = params.to_query();
        self.client.request(HttpMethod::Get, "/v1/users", &q, None, None).await
    }
    /// `GET /v1/users/:id`.
    pub async fn get(&self, id: &str) -> Result<User, BackendError> {
        let path = format!("/v1/users/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/users`.
    pub async fn create(
        &self,
        body: &CreateUserBody,
        idempotency_key: Option<&str>,
    ) -> Result<User, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/users", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `PATCH /v1/users/:id`.
    pub async fn update(&self, id: &str, body: &UpdateUserBody) -> Result<User, BackendError> {
        let path = format!("/v1/users/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    /// `POST /v1/users/:id/ban`.
    pub async fn ban(&self, id: &str) -> Result<User, BackendError> {
        let path = format!("/v1/users/{}/ban", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/users/:id/unban`.
    pub async fn unban(&self, id: &str) -> Result<User, BackendError> {
        let path = format!("/v1/users/{}/unban", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/users/:id/lock`, optionally for a bounded duration.
    pub async fn lock(&self, id: &str, duration_in_seconds: Option<u64>) -> Result<User, BackendError> {
        let path = format!("/v1/users/{}/lock", seg(id));
        let body = duration_in_seconds
            .map(|d| serde_json::json!({ "duration_in_seconds": d }));
        self.client.request(HttpMethod::Post, &path, &[], body, None).await
    }
    /// `POST /v1/users/:id/unlock`.
    pub async fn unlock(&self, id: &str) -> Result<User, BackendError> {
        let path = format!("/v1/users/{}/unlock", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `DELETE /v1/users/:id`.
    pub async fn delete(&self, id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/users/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `GET /v1/users/:id/grants` — the OAuth clients this user authorized.
    pub async fn list_grants(&self, id: &str) -> Result<ListPage<Grant>, BackendError> {
        let path = format!("/v1/users/{}/grants", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `DELETE /v1/users/:id/grants` — revoke every consent grant, cascading to
    /// the associated access/refresh tokens.
    pub async fn revoke_all_grants(&self, id: &str) -> Result<AllGrantsRevocation, BackendError> {
        let path = format!("/v1/users/{}/grants", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── oauth access grants ───────────────────────────────────────────────────

/// The `/v1/grants` namespace — instance-scoped OAuth consent grants.
pub struct Grants<'a> {
    client: &'a BackendClient,
}

impl<'a> Grants<'a> {
    /// `DELETE /v1/grants/:id` — revoke ONE consent grant and its live tokens.
    /// The response reports the cascaded token count.
    pub async fn revoke(&self, grant_id: &str) -> Result<GrantRevocation, BackendError> {
        let path = format!("/v1/grants/{}", seg(grant_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── organizations ────────────────────────────────────────────────────────

/// An organization as the BAPI serves it.
#[derive(Debug, Clone, Deserialize)]
pub struct Organization {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub image_url: Option<String>,
    #[serde(default)]
    pub public_metadata: Metadata,
    #[serde(default)]
    pub max_allowed_memberships: Option<u64>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationMembership {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub role: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationInvitation {
    pub id: String,
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub status: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OrgDomain {
    pub id: String,
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub auto_join: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The org security policy (§4.4). The returned `policy` bag is server-shaped.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationPolicy {
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub policy: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateOrganizationBody {
    pub name: String,
    pub slug: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_allowed_memberships: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateOrganizationBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_allowed_memberships: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_metadata: Option<Metadata>,
}

/// The `/v1/organizations` namespace.
pub struct Organizations<'a> {
    client: &'a BackendClient,
}

impl<'a> Organizations<'a> {
    pub async fn list(&self, params: CursorParams) -> Result<CursorPage<Organization>, BackendError> {
        let q = params.to_query();
        self.client.request(HttpMethod::Get, "/v1/organizations", &q, None, None).await
    }
    pub async fn get(&self, id: &str) -> Result<Organization, BackendError> {
        let path = format!("/v1/organizations/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn create(
        &self,
        body: &CreateOrganizationBody,
        idempotency_key: Option<&str>,
    ) -> Result<Organization, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/organizations", &[], body_of(body)?, idempotency_key)
            .await
    }
    pub async fn update(&self, id: &str, body: &UpdateOrganizationBody) -> Result<Organization, BackendError> {
        let path = format!("/v1/organizations/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    pub async fn delete(&self, id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/organizations/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `PATCH /v1/organizations/:id/policy` — the body's keys are camelCase on
    /// this route (`requireMfa`, `ssoRequired`, …).
    pub async fn update_policy(&self, id: &str, policy: Value) -> Result<OrganizationPolicy, BackendError> {
        let path = format!("/v1/organizations/{}/policy", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], Some(policy), None).await
    }

    /// Nested `/v1/organizations/:id/memberships`.
    pub fn memberships(&self, org_id: &str) -> OrgMemberships<'a> {
        OrgMemberships { client: self.client, org_id: org_id.to_string() }
    }
    /// Nested `/v1/organizations/:id/invitations`.
    pub fn invitations(&self, org_id: &str) -> OrgInvitations<'a> {
        OrgInvitations { client: self.client, org_id: org_id.to_string() }
    }
    /// Nested `/v1/organizations/:id/domains`.
    pub fn domains(&self, org_id: &str) -> OrgDomains<'a> {
        OrgDomains { client: self.client, org_id: org_id.to_string() }
    }
}

/// `/v1/organizations/:id/memberships`.
pub struct OrgMemberships<'a> {
    client: &'a BackendClient,
    org_id: String,
}

impl OrgMemberships<'_> {
    pub async fn list(&self) -> Result<ListPage<OrganizationMembership>, BackendError> {
        let path = format!("/v1/organizations/{}/memberships", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn add(
        &self,
        user_id: &str,
        role: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<OrganizationMembership, BackendError> {
        let path = format!("/v1/organizations/{}/memberships", seg(&self.org_id));
        let mut body = serde_json::Map::new();
        body.insert("user_id".into(), Value::String(user_id.to_string()));
        if let Some(r) = role {
            body.insert("role".into(), Value::String(r.to_string()));
        }
        self.client
            .request(HttpMethod::Post, &path, &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    pub async fn update(&self, user_id: &str, role: &str) -> Result<OrganizationMembership, BackendError> {
        let path = format!("/v1/organizations/{}/memberships/{}", seg(&self.org_id), seg(user_id));
        let body = serde_json::json!({ "role": role });
        self.client.request(HttpMethod::Patch, &path, &[], Some(body), None).await
    }
    pub async fn remove(&self, user_id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/organizations/{}/memberships/{}", seg(&self.org_id), seg(user_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

/// `/v1/organizations/:id/invitations`.
pub struct OrgInvitations<'a> {
    client: &'a BackendClient,
    org_id: String,
}

impl OrgInvitations<'_> {
    pub async fn list(&self) -> Result<ListPage<OrganizationInvitation>, BackendError> {
        let path = format!("/v1/organizations/{}/invitations", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn create(
        &self,
        email: &str,
        role: &str,
        inviter_user_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<OrganizationInvitation, BackendError> {
        let path = format!("/v1/organizations/{}/invitations", seg(&self.org_id));
        let body = serde_json::json!({ "email": email, "role": role, "inviter_user_id": inviter_user_id });
        self.client.request(HttpMethod::Post, &path, &[], Some(body), idempotency_key).await
    }
    pub async fn revoke(&self, invitation_id: &str) -> Result<OrganizationInvitation, BackendError> {
        let path = format!(
            "/v1/organizations/{}/invitations/{}/revoke",
            seg(&self.org_id),
            seg(invitation_id)
        );
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

/// `/v1/organizations/:id/domains`.
pub struct OrgDomains<'a> {
    client: &'a BackendClient,
    org_id: String,
}

impl OrgDomains<'_> {
    pub async fn list(&self) -> Result<ListPage<OrgDomain>, BackendError> {
        let path = format!("/v1/organizations/{}/domains", seg(&self.org_id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn create(
        &self,
        domain: &str,
        auto_join: Option<bool>,
        idempotency_key: Option<&str>,
    ) -> Result<OrgDomain, BackendError> {
        let path = format!("/v1/organizations/{}/domains", seg(&self.org_id));
        let mut body = serde_json::Map::new();
        body.insert("domain".into(), Value::String(domain.to_string()));
        if let Some(a) = auto_join {
            body.insert("auto_join".into(), Value::Bool(a));
        }
        self.client
            .request(HttpMethod::Post, &path, &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    pub async fn verify(&self, domain_id: &str) -> Result<OrgDomain, BackendError> {
        let path = format!("/v1/organizations/{}/domains/{}/verify", seg(&self.org_id), seg(domain_id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    pub async fn delete(&self, domain_id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/organizations/{}/domains/{}", seg(&self.org_id), seg(domain_id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── instance invitations ─────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Invitation {
    pub id: String,
    #[serde(default)]
    pub email_address: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub public_metadata: Metadata,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/v1/invitations` namespace.
pub struct Invitations<'a> {
    client: &'a BackendClient,
}

impl Invitations<'_> {
    pub async fn list(&self, params: CursorParams) -> Result<CursorPage<Invitation>, BackendError> {
        let q = params.to_query();
        self.client.request(HttpMethod::Get, "/v1/invitations", &q, None, None).await
    }
    pub async fn create(
        &self,
        email_address: &str,
        public_metadata: Option<Metadata>,
        idempotency_key: Option<&str>,
    ) -> Result<Invitation, BackendError> {
        let mut body = serde_json::Map::new();
        body.insert("email_address".into(), Value::String(email_address.to_string()));
        if let Some(m) = public_metadata {
            body.insert("public_metadata".into(), Value::Object(m));
        }
        self.client
            .request(HttpMethod::Post, "/v1/invitations", &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    pub async fn revoke(&self, id: &str) -> Result<Invitation, BackendError> {
        let path = format!("/v1/invitations/{}/revoke", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

// ── api keys ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ApiKey {
    pub id: String,
    #[serde(default)]
    pub subject_type: String,
    #[serde(default)]
    pub subject_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub claims: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The mint response: the key plus its `secret`, revealed exactly once.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyWithSecret {
    pub id: String,
    #[serde(default)]
    pub secret: String,
    #[serde(flatten)]
    pub key: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateApiKeyBody {
    pub subject_type: String,
    pub subject_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// The `/v1/api_keys` namespace. (The online *verify* with positive/negative
/// caching lives in [`crate::ApiKeyVerifier`]; this is the management surface.)
pub struct ApiKeys<'a> {
    client: &'a BackendClient,
}

impl ApiKeys<'_> {
    pub async fn list(
        &self,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<ListPage<ApiKey>, BackendError> {
        let mut q: Vec<(&str, String)> = Vec::new();
        if let Some(t) = subject_type {
            q.push(("subject_type", t.to_string()));
        }
        if let Some(i) = subject_id {
            q.push(("subject_id", i.to_string()));
        }
        self.client.request(HttpMethod::Get, "/v1/api_keys", &q, None, None).await
    }
    pub async fn create(
        &self,
        body: &CreateApiKeyBody,
        idempotency_key: Option<&str>,
    ) -> Result<ApiKeyWithSecret, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/api_keys", &[], body_of(body)?, idempotency_key)
            .await
    }
    pub async fn get(&self, id: &str) -> Result<ApiKey, BackendError> {
        let path = format!("/v1/api_keys/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn delete(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/api_keys/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── billing ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct BillingPlan {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BillingSubscription {
    pub id: String,
    #[serde(default)]
    pub subject_type: String,
    #[serde(default)]
    pub subject_id: String,
    #[serde(default)]
    pub plan_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateBillingPlanBody {
    pub name: String,
    pub slug: String,
    pub stripe_price_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

/// The `/v1/billing` namespace.
pub struct Billing<'a> {
    client: &'a BackendClient,
}

impl Billing<'_> {
    pub async fn list_plans(&self) -> Result<ListPage<BillingPlan>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/billing/plans", &[], None, None).await
    }
    pub async fn create_plan(
        &self,
        body: &CreateBillingPlanBody,
        idempotency_key: Option<&str>,
    ) -> Result<BillingPlan, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/billing/plans", &[], body_of(body)?, idempotency_key)
            .await
    }
    pub async fn get_plan(&self, id: &str) -> Result<BillingPlan, BackendError> {
        let path = format!("/v1/billing/plans/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn delete_plan(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/billing/plans/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    pub async fn list_subscriptions(
        &self,
        subject_type: Option<&str>,
        subject_id: Option<&str>,
    ) -> Result<ListPage<BillingSubscription>, BackendError> {
        let mut q: Vec<(&str, String)> = Vec::new();
        if let Some(t) = subject_type {
            q.push(("subject_type", t.to_string()));
        }
        if let Some(i) = subject_id {
            q.push(("subject_id", i.to_string()));
        }
        self.client.request(HttpMethod::Get, "/v1/billing/subscriptions", &q, None, None).await
    }
}

// ── sessions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A freshly-minted session — carries the bearer `jwt` + `refresh_token`
/// in-body for headless use.
#[derive(Debug, Clone, Deserialize)]
pub struct MintedSession {
    pub id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub jwt: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/v1/sessions` namespace.
pub struct Sessions<'a> {
    client: &'a BackendClient,
}

impl Sessions<'_> {
    /// `POST /v1/sessions` — mint a session for a user without the sign-in flow.
    pub async fn create(&self, user_id: &str, actor_sub: Option<&str>) -> Result<MintedSession, BackendError> {
        let mut body = serde_json::Map::new();
        body.insert("user_id".into(), Value::String(user_id.to_string()));
        if let Some(sub) = actor_sub {
            body.insert("actor".into(), serde_json::json!({ "sub": sub }));
        }
        self.client.request(HttpMethod::Post, "/v1/sessions", &[], Some(Value::Object(body)), None).await
    }
    /// `GET /v1/sessions?user_id=` — sessions are always scoped to one user.
    pub async fn list(&self, user_id: &str) -> Result<ListPage<Session>, BackendError> {
        let q = vec![("user_id", user_id.to_string())];
        self.client.request(HttpMethod::Get, "/v1/sessions", &q, None, None).await
    }
    pub async fn get(&self, id: &str) -> Result<Session, BackendError> {
        let path = format!("/v1/sessions/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    pub async fn revoke(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/sessions/{}/revoke", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
}

// ── custom domains ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CustomDomain {
    pub id: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub live: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `/v1/domains` namespace (the instance's own FAPI/accounts domains).
pub struct Domains<'a> {
    client: &'a BackendClient,
}

impl Domains<'_> {
    pub async fn list(&self) -> Result<Value, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/domains", &[], None, None).await
    }
    pub async fn create(
        &self,
        host: &str,
        role: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<CustomDomain, BackendError> {
        let mut body = serde_json::Map::new();
        body.insert("host".into(), Value::String(host.to_string()));
        if let Some(r) = role {
            body.insert("role".into(), Value::String(r.to_string()));
        }
        self.client
            .request(HttpMethod::Post, "/v1/domains", &[], Some(Value::Object(body)), idempotency_key)
            .await
    }
    pub async fn verify(&self, id: &str) -> Result<CustomDomain, BackendError> {
        let path = format!("/v1/domains/{}/verify", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    pub async fn delete(&self, id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/domains/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

// ── namespace accessors ──────────────────────────────────────────────────

impl BackendClient {
    /// The `/v1/users` namespace.
    pub fn users(&self) -> Users<'_> {
        Users { client: self }
    }
    /// The instance-scoped `/v1/grants` (OAuth access grants) namespace.
    pub fn grants(&self) -> Grants<'_> {
        Grants { client: self }
    }
    /// The `/v1/organizations` namespace (with nested memberships/invitations/
    /// domains/policy).
    pub fn organizations(&self) -> Organizations<'_> {
        Organizations { client: self }
    }
    /// The instance `/v1/invitations` namespace.
    pub fn invitations(&self) -> Invitations<'_> {
        Invitations { client: self }
    }
    /// The `/v1/api_keys` management namespace.
    pub fn api_keys(&self) -> ApiKeys<'_> {
        ApiKeys { client: self }
    }
    /// The `/v1/billing` namespace.
    pub fn billing(&self) -> Billing<'_> {
        Billing { client: self }
    }
    /// The `/v1/sessions` namespace.
    pub fn sessions(&self) -> Sessions<'_> {
        Sessions { client: self }
    }
    /// The `/v1/domains` namespace.
    pub fn domains(&self) -> Domains<'_> {
        Domains { client: self }
    }

    /// Convenience: deserialize a raw JSON value into a resource type, for a
    /// caller walking the `extra` bag or a webhook payload.
    pub fn parse_resource<T: DeserializeOwned>(value: Value) -> Result<T, BackendError> {
        serde_json::from_value(value).map_err(|e| BackendError::Malformed(e.to_string()))
    }
}
