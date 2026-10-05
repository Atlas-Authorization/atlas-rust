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

    /// `GET /v1/client/me` — the signed-in user's profile.
    pub async fn me(&self) -> Result<Value, ClientApiError> {
        self.call(HttpMethod::Get, "/v1/client/me", None).await
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
}
