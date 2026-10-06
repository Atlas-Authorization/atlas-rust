//! Machine (M2M) identities, the device registry, and enrolment.
//!
//! The §9.3/§P1-7 machine surface: a machine is a first-class non-human
//! principal with its own secret (`mk_…`) and, as a device, a registered public
//! key, a lifecycle `status`, device `metadata`, and optional org ownership.
//!
//! This module is the secret-key MANAGEMENT surface (list/filter, rename,
//! metadata, approve/revoke, key/secret rotation, delete, org memberships) plus
//! enrolment-token management and `verify_m2m_token`. The three PUBLIC device
//! self-serve calls (`enroll`/`challenge`/`token`) are included for completeness
//! — a bootstrapping device holds no `sk_`, so those authenticate on the
//! presented credential, but exposing them here keeps one typed namespace.
//!
//! Same conventions as [`super::resources`]: snake_case wire shapes, `Option`
//! for nullables, and an `extra` bag that absorbs unknown server fields so a new
//! field never breaks deserialization.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::pagination::{CursorPage, CursorParams};
use super::resources::{body_of, seg, DeletedObject, ListPage, Metadata};

// ── machine (device) ──────────────────────────────────────────────────────

/// A machine identity / device as the BAPI serves it. `secret_hash` is never
/// present — only its hash is stored, so it cannot leak on any machine surface.
#[derive(Debug, Clone, Deserialize)]
pub struct Machine {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub status: String,
    /// JWK thumbprint of the device's registered public key (device half).
    #[serde(default)]
    pub public_key_jkt: Option<String>,
    /// The opaque per-device key supplied at enrolment, echoed back here.
    #[serde(default)]
    pub device_key: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(default)]
    pub enrolled_at: Option<i64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A create/rotate_secret response: the machine plus its `secret` (`mk_…`),
/// revealed exactly once. The rest of the machine flattens into `machine`.
#[derive(Debug, Clone, Deserialize)]
pub struct MachineWithSecret {
    pub id: String,
    #[serde(default)]
    pub secret: String,
    #[serde(flatten)]
    pub machine: Map<String, Value>,
}

/// One row of the by-machine organization-membership list. A machine holds no
/// org role, so `role` is always null; `joined_at` is the enrolment time.
#[derive(Debug, Clone, Deserialize)]
pub struct MachineOrgMembership {
    #[serde(default)]
    pub organization_id: String,
    #[serde(default)]
    pub organization_slug: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub joined_at: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `{ valid, machine_id?, name? }` from `POST /v1/m2m_tokens/verify`. `valid`
/// is false for an unknown, rotated, or revoked secret, never a leak of which
/// machines exist.
#[derive(Debug, Clone, Deserialize)]
pub struct M2mVerification {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub machine_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An enrolment token (never the secret, except once on create via `token`).
#[derive(Debug, Clone, Deserialize)]
pub struct EnrolmentToken {
    pub id: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub max_uses: Option<u64>,
    #[serde(default)]
    pub uses: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default)]
    pub created_at: Option<i64>,
    /// The `met_…` secret, present only on the create response.
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The result of redeeming an enrolment token (`POST /v1/machines/redeem`): the
/// token's payload plus the owner/organization it binds to and the token's own
/// `id`.
#[derive(Debug, Clone, Deserialize)]
pub struct RedeemedEnrolment {
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub owner_user_id: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A device's enrolment result (`POST /v1/machines/enroll`).
#[derive(Debug, Clone, Deserialize)]
pub struct EnrolledMachine {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub public_key_jkt: Option<String>,
    /// The opaque per-device key supplied at enrolment, echoed back here.
    #[serde(default)]
    pub device_key: Option<String>,
    #[serde(default)]
    pub enrolled_at: Option<i64>,
    /// Whether the device must wait for approval before `/token` will work.
    #[serde(default)]
    pub approval_required: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The server challenge a device signs (`POST /v1/machines/challenge`).
#[derive(Debug, Clone, Deserialize)]
pub struct MachineChallenge {
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A minted machine JWT (`POST /v1/machines/token`).
#[derive(Debug, Clone, Deserialize)]
pub struct MachineToken {
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub machine_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ── request bodies / filters ───────────────────────────────────────────────

/// Filter for `GET /v1/machines`. `status`/`hostname` are the device-registry
/// query the server reads today; `owner_user_id`/`organization_id`/`metadata`
/// are round-7 filters and `limit`/`starting_after` the cursor — all sent as
/// query params, dropped when unset.
#[derive(Debug, Clone, Default)]
pub struct MachineFilter {
    pub status: Option<String>,
    pub hostname: Option<String>,
    pub owner_user_id: Option<String>,
    pub organization_id: Option<String>,
    pub metadata: Option<String>,
    pub limit: Option<u32>,
    pub starting_after: Option<String>,
}

impl MachineFilter {
    fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        let mut push = |k: &'static str, v: &Option<String>| {
            if let Some(v) = v {
                q.push((k, v.clone()));
            }
        };
        push("status", &self.status);
        push("hostname", &self.hostname);
        push("owner_user_id", &self.owner_user_id);
        push("organization_id", &self.organization_id);
        push("metadata", &self.metadata);
        push("starting_after", &self.starting_after);
        if let Some(l) = self.limit {
            q.push(("limit", l.to_string()));
        }
        q
    }
}

/// `POST /v1/machines` body. `name` is required; `owner_user_id`/`data` are
/// forward-compat fields the server ignores if it does not yet read them.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateMachineBody {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Metadata>,
}

/// `POST /v1/machine_enrolment_tokens` body. All optional: `max_uses` (default
/// 1), `expires_in_seconds` (default 3600, capped at a year), `organization_id`,
/// `requires_approval`. `data`/`owner_user_id`/`single_session`/`max_machines`
/// are forward-compat fields, dropped when unset.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateEnrolmentTokenBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_session: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_machines: Option<u64>,
}

/// How an enrolment-token list is scoped by organization.
///
/// The server distinguishes "tokens for this org" from "tokens in the org-less
/// (platform) pool", and the latter is expressed on the wire as the literal
/// `organization_id=null`. This enum keeps that distinct from leaving the filter
/// UNSET (which returns tokens across every scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgFilter {
    /// Tokens owned by one organization — sent as `organization_id=<id>`.
    Org(String),
    /// The org-less (platform) pool — sent as the literal `organization_id=null`.
    OrgLess,
}

/// Filter + paging for [`Machines::list_enrolment_tokens_with`]
/// (`GET /v1/machine_enrolment_tokens`). All fields are optional, sent as query
/// params, and dropped when unset.
#[derive(Debug, Clone, Default)]
pub struct ListEnrolmentTokensParams {
    /// Scope by organization — a concrete org, or the org-less pool
    /// ([`OrgFilter::OrgLess`], sent as `organization_id=null`). Left `None`, the
    /// list spans every scope.
    pub organization_id: Option<OrgFilter>,
    /// Page size, 1–100 (the server clamps out-of-range values).
    pub limit: Option<u32>,
    /// An opaque cursor from a prior page's `next_cursor`.
    pub starting_after: Option<String>,
}

impl ListEnrolmentTokensParams {
    fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        match &self.organization_id {
            Some(OrgFilter::Org(id)) => q.push(("organization_id", id.clone())),
            Some(OrgFilter::OrgLess) => q.push(("organization_id", "null".to_string())),
            None => {}
        }
        if let Some(l) = self.limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(after) = &self.starting_after {
            q.push(("starting_after", after.clone()));
        }
        q
    }
}

/// `POST /v1/machines/enroll` body (public device self-serve).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EnrolMachineBody {
    pub enrolment_token: String,
    pub name: String,
    pub public_key_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// An opaque per-device key the server records on the machine and echoes
    /// back on the machine record — lets a device be re-enrolled or located by a
    /// stable client-chosen handle. Dropped from the body when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key: Option<String>,
}

// ── namespace ───────────────────────────────────────────────────────────────

/// The `/v1/machines` (+ `/v1/machine_enrolment_tokens`, `/v1/m2m_tokens`)
/// namespace.
pub struct Machines<'a> {
    client: &'a BackendClient,
}

impl Machines<'_> {
    /// `GET /v1/machines` — the device registry, filtered.
    pub async fn list(&self, filter: &MachineFilter) -> Result<CursorPage<Machine>, BackendError> {
        let q = filter.to_query();
        self.client.request(HttpMethod::Get, "/v1/machines", &q, None, None).await
    }
    /// `POST /v1/machines` — returns the machine `secret` (`mk_…`) ONCE.
    pub async fn create(
        &self,
        body: &CreateMachineBody,
        idempotency_key: Option<&str>,
    ) -> Result<MachineWithSecret, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/machines", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `GET /v1/machines/:id`.
    pub async fn get(&self, id: &str) -> Result<Machine, BackendError> {
        let path = format!("/v1/machines/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `PATCH /v1/machines/:id` — rename a machine.
    pub async fn rename(&self, id: &str, name: &str) -> Result<Machine, BackendError> {
        let path = format!("/v1/machines/{}", seg(id));
        let body = serde_json::json!({ "name": name });
        self.client.request(HttpMethod::Patch, &path, &[], Some(body), None).await
    }
    /// `PATCH /v1/machines/:id/metadata` — merge device metadata
    /// (hostname/os/app_version/last_seen_at/…).
    pub async fn patch_metadata(&self, id: &str, metadata: Metadata) -> Result<Machine, BackendError> {
        let path = format!("/v1/machines/{}/metadata", seg(id));
        let body = serde_json::json!({ "metadata": metadata });
        self.client.request(HttpMethod::Patch, &path, &[], Some(body), None).await
    }
    /// `POST /v1/machines/:id/approve` — pending → active.
    pub async fn approve(&self, id: &str) -> Result<Machine, BackendError> {
        let path = format!("/v1/machines/{}/approve", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/machines/:id/revoke` — the record is kept (status → revoked).
    pub async fn revoke(&self, id: &str) -> Result<Machine, BackendError> {
        let path = format!("/v1/machines/{}/revoke", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/machines/:id/rotate_secret` — returns a new `secret` ONCE.
    pub async fn rotate_secret(&self, id: &str) -> Result<MachineWithSecret, BackendError> {
        let path = format!("/v1/machines/{}/rotate_secret", seg(id));
        self.client.request(HttpMethod::Post, &path, &[], None, None).await
    }
    /// `POST /v1/machines/:id/rotate_key` — register a new device public key
    /// (SPKI PEM); the old private key stops verifying at once.
    pub async fn rotate_key(&self, id: &str, public_key_pem: &str) -> Result<Machine, BackendError> {
        let path = format!("/v1/machines/{}/rotate_key", seg(id));
        let body = serde_json::json!({ "public_key_pem": public_key_pem });
        self.client.request(HttpMethod::Post, &path, &[], Some(body), None).await
    }
    /// `DELETE /v1/machines/:id`.
    pub async fn delete(&self, id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/machines/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
    /// `GET /v1/machines/:id/organization_memberships` — zero or one entry.
    pub async fn organization_memberships(
        &self,
        id: &str,
        params: CursorParams,
    ) -> Result<CursorPage<MachineOrgMembership>, BackendError> {
        let path = format!("/v1/machines/{}/organization_memberships", seg(id));
        let q = params.to_query();
        self.client.request(HttpMethod::Get, &path, &q, None, None).await
    }

    // ── enrolment tokens (sk_) ──────────────────────────────────────────────

    /// `POST /v1/machine_enrolment_tokens` — returns the `token` secret ONCE.
    pub async fn create_enrolment_token(
        &self,
        body: &CreateEnrolmentTokenBody,
        idempotency_key: Option<&str>,
    ) -> Result<EnrolmentToken, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/machine_enrolment_tokens",
                &[],
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/machine_enrolment_tokens` — never the secret. Returns the first
    /// page across every scope with the server's default paging; use
    /// [`list_enrolment_tokens_with`](Self::list_enrolment_tokens_with) to filter
    /// by organization or walk the pages via `next_cursor`.
    pub async fn list_enrolment_tokens(&self) -> Result<ListPage<EnrolmentToken>, BackendError> {
        self.list_enrolment_tokens_with(&ListEnrolmentTokensParams::default()).await
    }
    /// `GET /v1/machine_enrolment_tokens`, filtered + paged.
    ///
    /// Scope by organization (a concrete org, or the org-less pool via
    /// [`OrgFilter::OrgLess`]) and page with `limit` / `starting_after`. The
    /// returned [`ListPage`] carries `has_more` and the opaque `next_cursor` to
    /// pass back as the next page's `starting_after`.
    pub async fn list_enrolment_tokens_with(
        &self,
        params: &ListEnrolmentTokensParams,
    ) -> Result<ListPage<EnrolmentToken>, BackendError> {
        let q = params.to_query();
        self.client
            .request(HttpMethod::Get, "/v1/machine_enrolment_tokens", &q, None, None)
            .await
    }
    /// `DELETE /v1/machine_enrolment_tokens/:id`.
    pub async fn delete_enrolment_token(&self, id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/machine_enrolment_tokens/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }

    // ── M2M-token verification (sk_) ────────────────────────────────────────

    /// `POST /v1/m2m_tokens/verify` — resolve a presented machine secret to its
    /// machine (Clerk `verifyM2MToken`).
    pub async fn verify_m2m_token(&self, token: &str) -> Result<M2mVerification, BackendError> {
        let body = serde_json::json!({ "token": token });
        self.client
            .request(HttpMethod::Post, "/v1/m2m_tokens/verify", &[], Some(body), None)
            .await
    }

    // ── device self-serve (public) ──────────────────────────────────────────

    /// `POST /v1/machines/enroll` — present an enrolment token + public key.
    /// Public: authenticated by the enrolment token, not the `sk_` key.
    pub async fn enroll(&self, body: &EnrolMachineBody) -> Result<EnrolledMachine, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/machines/enroll", &[], body_of(body)?, None)
            .await
    }
    /// `POST /v1/machines/redeem` — redeem an enrolment token, resolving it to its
    /// payload, the owner/organization it binds to, and the token's `id`.
    pub async fn redeem(&self, enrolment_token: &str) -> Result<RedeemedEnrolment, BackendError> {
        let body = serde_json::json!({ "enrolment_token": enrolment_token });
        self.client
            .request(HttpMethod::Post, "/v1/machines/redeem", &[], Some(body), None)
            .await
    }
    /// `POST /v1/machines/challenge` — get a nonce for a machine to sign. Public.
    pub async fn challenge(&self, machine_id: &str) -> Result<MachineChallenge, BackendError> {
        let body = serde_json::json!({ "machine_id": machine_id });
        self.client
            .request(HttpMethod::Post, "/v1/machines/challenge", &[], Some(body), None)
            .await
    }
    /// `POST /v1/machines/token` — exchange a signed challenge for a short
    /// machine JWT. Public: authenticated by the device's private key.
    pub async fn token(
        &self,
        machine_id: &str,
        nonce: &str,
        signature: &str,
    ) -> Result<MachineToken, BackendError> {
        let body = serde_json::json!({
            "machine_id": machine_id,
            "nonce": nonce,
            "signature": signature,
        });
        self.client
            .request(HttpMethod::Post, "/v1/machines/token", &[], Some(body), None)
            .await
    }
}

// ── accessor ────────────────────────────────────────────────────────────────

impl BackendClient {
    /// The `/v1/machines` namespace — machine identities, the device registry,
    /// enrolment tokens, and M2M-token verification.
    pub fn machines(&self) -> Machines<'_> {
        Machines { client: self }
    }
}
