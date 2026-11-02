//! Trusted-JWT connections (`/v1/jwt_connections`): your system signs a
//! short-lived JWT for a person and sends them to the connection's
//! `login_url?token=…&redirect_url=…`. Atlas checks the signature against
//! `jwks_uri`, `iss`, `aud`, `exp`, the max age and that the `jti` is unused,
//! then signs them in (and seats them in the connection's organization).
//!
//! ```no_run
//! # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
//! use atlasauth::backend::JwtConnectionBody;
//!
//! let conn = atlas
//!     .jwt_connections()
//!     .create(
//!         &JwtConnectionBody {
//!             status: Some("active".into()),
//!             jwks_uri: Some("https://acme.example.com/.well-known/jwks.json".into()),
//!             issuer: Some("https://acme.example.com".into()),
//!             audience: Some("atlas".into()),
//!             ..Default::default()
//!         },
//!         None,
//!     )
//!     .await?;
//! println!("{}", conn.login_url);
//! # Ok(()) }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::resources::{body_of, seg, DeletedObject, ListPage};

/// A trusted-JWT connection.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct JwtConnection {
    /// `jwt_connection`.
    pub object: String,
    pub id: String,
    pub organization_id: Option<String>,
    /// `draft`, `active` or `disabled`.
    pub status: String,
    pub jwks_uri: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    /// The claim holding the email (default `email`).
    pub email_claim: String,
    /// `exp - iat` may be at most this many seconds.
    pub max_age_seconds: i64,
    pub default_role_id: Option<String>,
    /// Send the person here with `?token=<jwt>&redirect_url=<your app URL>`.
    pub login_url: String,
    /// Epoch ms.
    pub created_at: i64,
    /// Epoch ms.
    pub updated_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The body of `POST /v1/jwt_connections` and `PATCH /v1/jwt_connections/:id`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct JwtConnectionBody {
    /// `Some(None)` sends null: not tied to an organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<Option<String>>,
    /// `draft`, `active` or `disabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// An https URL serving your public signing keys (RS / PS / ES / EdDSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Default `email`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_claim: Option<String>,
    /// 30-3600, default 300.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<i64>,
    /// `Some(None)` sends null and clears it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role_id: Option<Option<String>>,
    /// Extra keys, sent as-is.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `/v1/jwt_connections`. Reached via [`BackendClient::jwt_connections`].
pub struct JwtConnections<'a> {
    pub(super) client: &'a BackendClient,
}

impl JwtConnections<'_> {
    /// `GET /v1/jwt_connections`.
    pub async fn list(&self) -> Result<ListPage<JwtConnection>, BackendError> {
        self.client.request(HttpMethod::Get, "/v1/jwt_connections", &[], None, None).await
    }
    /// `GET /v1/jwt_connections/:id`.
    pub async fn get(&self, id: &str) -> Result<JwtConnection, BackendError> {
        let path = format!("/v1/jwt_connections/{}", seg(id));
        self.client.request(HttpMethod::Get, &path, &[], None, None).await
    }
    /// `POST /v1/jwt_connections`.
    pub async fn create(
        &self,
        body: &JwtConnectionBody,
        idempotency_key: Option<&str>,
    ) -> Result<JwtConnection, BackendError> {
        self.client
            .request(HttpMethod::Post, "/v1/jwt_connections", &[], body_of(body)?, idempotency_key)
            .await
    }
    /// `PATCH /v1/jwt_connections/:id`.
    pub async fn update(&self, id: &str, body: &JwtConnectionBody) -> Result<JwtConnection, BackendError> {
        let path = format!("/v1/jwt_connections/{}", seg(id));
        self.client.request(HttpMethod::Patch, &path, &[], body_of(body)?, None).await
    }
    /// `DELETE /v1/jwt_connections/:id`.
    pub async fn delete(&self, id: &str) -> Result<DeletedObject, BackendError> {
        let path = format!("/v1/jwt_connections/{}", seg(id));
        self.client.request(HttpMethod::Delete, &path, &[], None, None).await
    }
}

impl BackendClient {
    /// Trusted-JWT connections: sign people in with a JWT your system signs.
    pub fn jwt_connections(&self) -> JwtConnections<'_> {
        JwtConnections { client: self }
    }
}
