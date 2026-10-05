//! The typed `/v1/client/me/**` self-service surface (§9.2), over a session
//! bearer.
//!
//! These are the account-management calls a signed-in user makes for THEMSELVES
//! — read the profile, list activity and devices, manage MFA factors and
//! passkeys, satisfy a step-up challenge, disconnect an OAuth grant. Every call
//! carries the session bearer and the publishable key, supplied by a
//! [`BearerSource`] — a [`NativeSessionManager`] (auto-refreshing) or a static
//! token — so the self-service client never owns session state itself.

use std::sync::Arc;

use serde_json::Value;

use crate::http::{HttpMethod, HttpRequest, HttpTransport};
use crate::jwks::BoxFuture;

use super::native_session::NativeSessionManager;

/// A source of the auth headers a FAPI client call needs (a fresh bearer plus
/// the publishable key). Implemented by [`NativeSessionManager`] (auto-refresh)
/// and by [`StaticBearer`].
pub trait BearerSource: Send + Sync {
    fn auth_headers<'a>(&'a self) -> BoxFuture<'a, Vec<(String, String)>>;
}

impl BearerSource for NativeSessionManager {
    fn auth_headers<'a>(&'a self) -> BoxFuture<'a, Vec<(String, String)>> {
        Box::pin(async move { NativeSessionManager::auth_headers(self).await })
    }
}

/// A fixed bearer + publishable key — for a caller that manages the token
/// themselves, or a test.
pub struct StaticBearer {
    pub bearer: String,
    pub publishable_key: String,
}

impl BearerSource for StaticBearer {
    fn auth_headers<'a>(&'a self) -> BoxFuture<'a, Vec<(String, String)>> {
        let headers = vec![
            ("authorization".to_string(), format!("Bearer {}", self.bearer)),
            ("x-publishable-key".to_string(), self.publishable_key.clone()),
        ];
        Box::pin(async move { headers })
    }
}

/// A self-service FAPI call failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientApiError {
    /// A non-2xx response. `body` is the raw §9.1 envelope for the caller to
    /// inspect (it may carry a step-up `code`, a validation `param`, …).
    #[error("atlas client api: HTTP {status}")]
    Api { status: u16, body: String },
    /// The request did not complete.
    #[error(transparent)]
    Transport(#[from] crate::error::TransportError),
    /// A 2xx body that did not parse.
    #[error("atlas client api: malformed response: {0}")]
    Malformed(String),
}

/// The typed self-service client. Build it over a [`NativeSessionManager`] (the
/// common case) or any [`BearerSource`].
pub struct SelfServiceClient {
    transport: Arc<dyn HttpTransport>,
    base_url: String,
    bearer: Arc<dyn BearerSource>,
}

impl SelfServiceClient {
    /// Build over an explicit transport, FAPI origin, and bearer source.
    pub fn new(
        transport: Arc<dyn HttpTransport>,
        base_url: impl Into<String>,
        bearer: Arc<dyn BearerSource>,
    ) -> Self {
        SelfServiceClient {
            transport,
            base_url: base_url.into(),
            bearer,
        }
    }

    /// Build over a session manager — the manager supplies the transport, FAPI
    /// origin, and an auto-refreshing bearer.
    pub fn from_manager(manager: Arc<NativeSessionManager>) -> Self {
        SelfServiceClient {
            transport: manager.transport().clone(),
            base_url: manager.base_url().to_string(),
            bearer: manager,
        }
    }

    async fn call(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ClientApiError> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let mut req = HttpRequest::new(method, url).header("accept", "application/json");
        for (name, value) in self.bearer.auth_headers().await {
            req = req.header(name, value);
        }
        if let Some(b) = &body {
            let serialized = serde_json::to_string(b).map_err(|e| ClientApiError::Malformed(e.to_string()))?;
            req = req.header("content-type", "application/json").body(serialized);
        }
        let resp = self.transport.send(req).await?;
        if !(200..300).contains(&resp.status) {
            return Err(ClientApiError::Api {
                status: resp.status,
                body: resp.body,
            });
        }
        let text = if resp.body.trim().is_empty() { "null" } else { &resp.body };
        serde_json::from_str(text).map_err(|e| ClientApiError::Malformed(e.to_string()))
    }

    /// Deserialize a call into a typed struct. Used by the `*_typed` reads; the
    /// untyped [`request_raw`](Self::request_raw) remains the escape hatch.
    async fn call_typed<T: serde::de::DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, ClientApiError> {
        let value = self.call(method, path, body).await?;
        serde_json::from_value(value).map_err(|e| ClientApiError::Malformed(e.to_string()))
    }

    /// The RAW escape hatch: issue any `/v1/client/**` call and get the parsed
    /// JSON back untyped, for an endpoint without a typed wrapper (or when a
    /// caller wants a field a struct omits). The session bearer + publishable key
    /// are attached automatically.
    pub async fn request_raw(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ClientApiError> {
        self.call(method, path, body).await
    }

    /// A raw `GET` convenience over [`request_raw`](Self::request_raw).
    pub async fn get_raw(&self, path: &str) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, path, None).await
    }

    /// `GET /v1/client/me` — the signed-in user's profile (raw).
    pub async fn me(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me", None).await
    }

    /// `GET /v1/client/me` as a typed [`UserProfile`].
    pub async fn me_typed(&self) -> Result<UserProfile, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me", None).await
    }

    /// `PATCH /v1/client/me` — update mutable profile fields (first/last name,
    /// username, `unsafe_metadata`, …). Pass only the fields to change.
    pub async fn update_profile(&self, patch: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Patch, "/v1/client/me", Some(patch)).await
    }
    /// `GET /v1/client/me/activity` — the unified activity log.
    pub async fn activity(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/activity", None).await
    }
    /// `GET /v1/client/sessions` — the user's active sessions.
    pub async fn list_sessions(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/sessions", None).await
    }
    /// `POST /v1/client/sessions/:id/revoke` — revoke one session.
    pub async fn revoke_session(&self, session_id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/sessions/{}/revoke", crate::http::encode_segment(session_id));
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `POST /v1/client/sessions/revoke_all` — revoke every other session.
    pub async fn revoke_all_sessions(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/sessions/revoke_all", None).await
    }
    /// `POST /v1/client/sessions/:id/set_active` — switch the active org.
    pub async fn set_active_session(
        &self,
        session_id: &str,
        organization_id: Option<&str>,
    ) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/sessions/{}/set_active", crate::http::encode_segment(session_id));
        let body = serde_json::json!({ "organization_id": organization_id });
        self.call(HttpMethod::Post, &path, Some(body)).await
    }
    /// `GET /v1/client/me/mfa` — the user's MFA factors.
    pub async fn list_mfa(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/mfa", None).await
    }
    /// `GET /v1/client/me/passkeys` — the user's registered passkeys.
    pub async fn list_passkeys(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/passkeys", None).await
    }
    /// `POST /v1/client/me/step_up/email_code` — send a step-up email code.
    pub async fn send_step_up_email_code(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/step_up/email_code", Some(serde_json::json!({}))).await
    }
    /// `POST /v1/client/me/step_up` — satisfy a step-up challenge. Pass the
    /// `strategy` (`"email_code"`, `"password"`, `"id_token"`) and its fields
    /// (e.g. `{ "code": "123456" }` for an email code).
    pub async fn complete_step_up(&self, strategy: &str, fields: Value) -> Result<Value, ClientApiError> {
        let mut body = match fields {
            Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        body.insert("strategy".to_string(), Value::String(strategy.to_string()));
        self.call(HttpMethod::Post, "/v1/client/me/step_up", Some(Value::Object(body))).await
    }
    /// `GET /v1/client/me/oauth_grants` — the OAuth apps this user authorized.
    pub async fn list_oauth_grants(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/oauth_grants", None).await
    }
    /// `DELETE /v1/client/me/oauth_grants/:id` — disconnect one OAuth grant.
    pub async fn disconnect_oauth_grant(&self, grant_id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/oauth_grants/{}", crate::http::encode_segment(grant_id));
        self.call(HttpMethod::Delete, &path, None).await
    }
    /// `GET /v1/client/me/organizations` — the user's org memberships.
    pub async fn list_organizations(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/organizations", None).await
    }

    // ── typed read variants ─────────────────────────────────────────────────

    /// `GET /v1/client/sessions` as typed [`ClientSession`]s.
    pub async fn sessions_typed(&self) -> Result<List<ClientSession>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/sessions", None).await
    }
    /// `GET /v1/client/me/mfa` as typed [`MfaFactor`]s.
    pub async fn mfa_typed(&self) -> Result<List<MfaFactor>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me/mfa", None).await
    }
    /// `GET /v1/client/me/passkeys` as typed [`Passkey`]s.
    pub async fn passkeys_typed(&self) -> Result<List<Passkey>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me/passkeys", None).await
    }
    /// `GET /v1/client/me/oauth_grants` as typed [`OAuthGrant`]s.
    pub async fn oauth_grants_typed(&self) -> Result<List<OAuthGrant>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me/oauth_grants", None).await
    }
    /// `GET /v1/client/me/organizations` as typed [`OrganizationMembership`]s.
    pub async fn organizations_typed(&self) -> Result<List<OrganizationMembership>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me/organizations", None).await
    }
    /// `GET /v1/client/me/trusted_devices` as typed [`TrustedDevice`]s.
    pub async fn trusted_devices_typed(&self) -> Result<List<TrustedDevice>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me/trusted_devices", None).await
    }
    /// `GET /v1/client/me/api_tokens` as typed [`ApiTokenRecord`]s.
    pub async fn api_tokens_typed(&self) -> Result<List<ApiTokenRecord>, ClientApiError> {
        self.call_typed(HttpMethod::Get, "/v1/client/me/api_tokens", None).await
    }

    // ── passwords & reauthentication ────────────────────────────────────────

    /// `POST /v1/client/me/change_password` — change a known password.
    pub async fn change_password(&self, current: &str, new_password: &str) -> Result<Value, ClientApiError> {
        let body = serde_json::json!({ "current_password": current, "new_password": new_password });
        self.call(HttpMethod::Post, "/v1/client/me/change_password", Some(body)).await
    }
    /// `POST /v1/client/me/set_password` — set a password where none exists.
    pub async fn set_password(&self, new_password: &str) -> Result<Value, ClientApiError> {
        let body = serde_json::json!({ "new_password": new_password });
        self.call(HttpMethod::Post, "/v1/client/me/set_password", Some(body)).await
    }
    /// `POST /v1/client/me/reauthenticate` — satisfy a fresh-auth challenge. Pass
    /// the strategy + its fields (e.g. `{ "password": "…" }`).
    pub async fn reauthenticate(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/reauthenticate", Some(body)).await
    }

    // ── email addresses ─────────────────────────────────────────────────────

    /// `POST /v1/client/me/email_addresses` — add an email (unverified).
    pub async fn add_email_address(&self, email: &str) -> Result<Value, ClientApiError> {
        let body = serde_json::json!({ "email_address": email });
        self.call(HttpMethod::Post, "/v1/client/me/email_addresses", Some(body)).await
    }
    /// `DELETE /v1/client/me/email_addresses/:id`.
    pub async fn delete_email_address(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/email_addresses/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }
    /// `POST /v1/client/me/email_addresses/:id/attempt_verification` — submit the
    /// verification code sent to the address.
    pub async fn verify_email_address(&self, id: &str, code: &str) -> Result<Value, ClientApiError> {
        let path = format!(
            "/v1/client/me/email_addresses/{}/attempt_verification",
            crate::http::encode_segment(id)
        );
        self.call(HttpMethod::Post, &path, Some(serde_json::json!({ "code": code }))).await
    }
    /// `POST /v1/client/me/email_addresses/:id/primary` — make this the primary.
    pub async fn set_primary_email(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/email_addresses/{}/primary", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, None).await
    }

    // ── data export & account deletion ──────────────────────────────────────

    /// `GET /v1/client/me/data_export` — list the user's data-export jobs.
    pub async fn list_data_exports(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/data_export", None).await
    }
    /// `GET /v1/client/me/data_export/:id` — one export job.
    pub async fn get_data_export(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/data_export/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Get, &path, None).await
    }
    /// `POST /v1/client/me/data_export` — request a data export (DSAR).
    pub async fn create_data_export(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/data_export", Some(serde_json::json!({}))).await
    }
    /// `GET /v1/client/me/deletion_request` — the pending account-deletion request.
    pub async fn get_deletion_request(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/deletion_request", None).await
    }
    /// `POST /v1/client/me/deletion_request` — request account deletion (erasure).
    pub async fn request_deletion(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/deletion_request", Some(serde_json::json!({}))).await
    }
    /// `POST /v1/client/me/deletion_request/:id/cancel` — cancel a pending deletion.
    pub async fn cancel_deletion(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/deletion_request/{}/cancel", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `DELETE /v1/client/me/deletion_request/:id` — withdraw a deletion request.
    pub async fn delete_deletion_request(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/deletion_request/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }

    // ── personal API (access) tokens ────────────────────────────────────────

    /// `GET /v1/client/me/api_tokens` — the user's personal access tokens (raw).
    pub async fn list_api_tokens(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/api_tokens", None).await
    }
    /// `POST /v1/client/me/api_tokens` — mint a personal access token. The secret
    /// is returned once.
    pub async fn create_api_token(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/api_tokens", Some(body)).await
    }
    /// `DELETE /v1/client/me/api_tokens/:id` — revoke a personal access token.
    pub async fn revoke_api_token(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/api_tokens/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }

    // ── external (connected) accounts ───────────────────────────────────────

    /// `POST /v1/client/me/external_accounts/connect` — begin connecting a provider.
    pub async fn connect_external_account(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/external_accounts/connect", Some(body)).await
    }
    /// `GET /v1/client/me/external_accounts/:provider/token` — the connected
    /// provider's current access token (e.g. `github`, `google`).
    pub async fn external_account_token(&self, provider: &str) -> Result<Value, ClientApiError> {
        let path = format!(
            "/v1/client/me/external_accounts/{}/token",
            crate::http::encode_segment(provider)
        );
        self.call(HttpMethod::Get, &path, None).await
    }
    /// `POST /v1/client/me/external_accounts/:id/reauthorize` — re-run the OAuth
    /// grant (e.g. to widen scopes).
    pub async fn reauthorize_external_account(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!(
            "/v1/client/me/external_accounts/{}/reauthorize",
            crate::http::encode_segment(id)
        );
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `POST /v1/client/me/external_accounts/:id/revoke` — revoke a connection's tokens.
    pub async fn revoke_external_account(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/external_accounts/{}/revoke", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `DELETE /v1/client/me/external_accounts/:id` — remove a connected account.
    pub async fn delete_external_account(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/external_accounts/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }

    // ── organization invitations / suggestions / requests ───────────────────

    /// `GET /v1/client/me/organization_invitations` — pending org invitations.
    pub async fn list_organization_invitations(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/organization_invitations", None).await
    }
    /// `POST /v1/client/me/organization_invitations/:id/accept`.
    pub async fn accept_organization_invitation(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!(
            "/v1/client/me/organization_invitations/{}/accept",
            crate::http::encode_segment(id)
        );
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `POST /v1/client/me/organization_invitations/:id/decline`.
    pub async fn decline_organization_invitation(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!(
            "/v1/client/me/organization_invitations/{}/decline",
            crate::http::encode_segment(id)
        );
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `GET /v1/client/me/organization_suggestions` — orgs the user may request to join.
    pub async fn list_organization_suggestions(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/organization_suggestions", None).await
    }
    /// `POST /v1/client/me/organization_suggestions/:organization_id/accept`.
    pub async fn accept_organization_suggestion(&self, organization_id: &str) -> Result<Value, ClientApiError> {
        let path = format!(
            "/v1/client/me/organization_suggestions/{}/accept",
            crate::http::encode_segment(organization_id)
        );
        self.call(HttpMethod::Post, &path, None).await
    }
    /// `POST /v1/client/me/organization_membership_requests` — request to join an org.
    pub async fn request_organization_membership(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/organization_membership_requests", Some(body)).await
    }

    // ── trusted devices, notifications, consents, misc ──────────────────────

    /// `GET /v1/client/me/trusted_devices` — the user's trusted devices (raw).
    pub async fn list_trusted_devices(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/trusted_devices", None).await
    }
    /// `DELETE /v1/client/me/trusted_devices/:id` — forget one trusted device.
    pub async fn delete_trusted_device(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/trusted_devices/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }
    /// `DELETE /v1/client/me/trusted_devices` — forget ALL trusted devices.
    pub async fn delete_all_trusted_devices(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Delete, "/v1/client/me/trusted_devices", None).await
    }
    /// `GET /v1/client/me/notification_preferences`.
    pub async fn notification_preferences(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/notification_preferences", None).await
    }
    /// `GET /v1/client/me/consents` — the user's recorded consents.
    pub async fn list_consents(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/consents", None).await
    }
    /// `POST /v1/client/me/consents` — record a consent decision.
    pub async fn grant_consent(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/consents", Some(body)).await
    }
    /// `POST /v1/client/me/approvals/:id/respond` — respond to a pending approval
    /// (e.g. a CIBA back-channel request).
    pub async fn respond_approval(&self, id: &str, body: Value) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/approvals/{}/respond", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, Some(body)).await
    }
    /// `GET /v1/client/me/backchannel_requests` — pending back-channel (CIBA) auth requests.
    pub async fn list_backchannel_requests(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/backchannel_requests", None).await
    }
    /// `POST /v1/client/me/backchannel_requests/:id` — approve/deny a back-channel request.
    pub async fn respond_backchannel_request(&self, id: &str, body: Value) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/backchannel_requests/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, Some(body)).await
    }

    // ── MFA enrolment (TOTP / SMS / backup codes) ───────────────────────────

    /// `POST /v1/client/me/mfa/totp` — begin TOTP enrolment (returns the secret/URI).
    pub async fn start_totp_enrollment(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/mfa/totp", Some(serde_json::json!({}))).await
    }
    /// `POST /v1/client/me/mfa/totp/:id/verify` — confirm TOTP enrolment with a code.
    pub async fn verify_totp(&self, id: &str, code: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/mfa/totp/{}/verify", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, Some(serde_json::json!({ "code": code }))).await
    }
    /// `POST /v1/client/me/mfa/sms` — begin SMS-OTP enrolment for a number.
    pub async fn start_sms_enrollment(&self, phone_number: &str) -> Result<Value, ClientApiError> {
        let body = serde_json::json!({ "phone_number": phone_number });
        self.call(HttpMethod::Post, "/v1/client/me/mfa/sms", Some(body)).await
    }
    /// `POST /v1/client/me/mfa/sms/:id/verify` — confirm SMS enrolment with a code.
    pub async fn verify_sms(&self, id: &str, code: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/mfa/sms/{}/verify", crate::http::encode_segment(id));
        self.call(HttpMethod::Post, &path, Some(serde_json::json!({ "code": code }))).await
    }
    /// `POST /v1/client/me/mfa/backup_codes` — (re)generate backup codes.
    pub async fn generate_backup_codes(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/mfa/backup_codes", Some(serde_json::json!({}))).await
    }
    /// `DELETE /v1/client/me/mfa/:id` — remove an MFA factor.
    pub async fn delete_mfa_factor(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/mfa/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }
    /// `GET /v1/client/me/mfa/push` — registered push-MFA devices.
    pub async fn list_push_devices(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me/mfa/push", None).await
    }
    /// `POST /v1/client/me/mfa/push` — register a push-MFA device.
    pub async fn register_push_device(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/mfa/push", Some(body)).await
    }

    // ── passkeys (WebAuthn ceremonies) ──────────────────────────────────────

    /// `POST /v1/client/me/passkeys/begin` — start passkey registration (returns
    /// the WebAuthn creation options).
    pub async fn begin_passkey_registration(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/passkeys/begin", Some(serde_json::json!({}))).await
    }
    /// `POST /v1/client/me/passkeys/finish` — finish passkey registration with the
    /// authenticator's attestation response.
    pub async fn finish_passkey_registration(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/passkeys/finish", Some(body)).await
    }
    /// `PATCH /v1/client/me/passkeys/:id` — rename a passkey.
    pub async fn rename_passkey(&self, id: &str, name: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/passkeys/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Patch, &path, Some(serde_json::json!({ "name": name }))).await
    }
    /// `DELETE /v1/client/me/passkeys/:id`.
    pub async fn delete_passkey(&self, id: &str) -> Result<Value, ClientApiError> {
        let path = format!("/v1/client/me/passkeys/{}", crate::http::encode_segment(id));
        self.call(HttpMethod::Delete, &path, None).await
    }
    /// `POST /v1/client/me/step_up/passkey` — satisfy a step-up with a passkey assertion.
    pub async fn complete_step_up_passkey(&self, body: Value) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Post, "/v1/client/me/step_up/passkey", Some(body)).await
    }
}

// ── typed response structs (lenient: unknown fields are preserved in `extra`) ─

use std::collections::HashMap;

/// A list envelope `{ object, data, has_more?, next_cursor? }`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(bound(deserialize = "T: serde::de::Deserialize<'de>"))]
pub struct List<T> {
    #[serde(default)]
    pub data: Vec<T>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// The signed-in user (`GET /v1/client/me`). Lenient — fields Atlas adds later
/// land in `extra` rather than failing the parse.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UserProfile {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub primary_email_address: Option<String>,
    #[serde(default)]
    pub image_url: Option<String>,
    #[serde(default)]
    pub public_metadata: Option<Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One active session (`GET /v1/client/sessions`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ClientSession {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<i64>,
    #[serde(default)]
    pub expire_at: Option<i64>,
    #[serde(default)]
    pub active_organization_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One MFA factor (`GET /v1/client/me/mfa`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MfaFactor {
    #[serde(default)]
    pub id: String,
    /// `totp` / `sms` / `backup_code` / `push` / …
    #[serde(default, alias = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One registered passkey (`GET /v1/client/me/passkeys`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Passkey {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One OAuth grant the user authorized (`GET /v1/client/me/oauth_grants`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OAuthGrant {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One org membership (`GET /v1/client/me/organizations`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OrganizationMembership {
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub organization_slug: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub joined_at: Option<i64>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One trusted device (`GET /v1/client/me/trusted_devices`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TrustedDevice {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub last_active_at: Option<i64>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// One personal access token record (`GET /v1/client/me/api_tokens`). Never
/// carries the secret (shown once on create).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ApiTokenRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
