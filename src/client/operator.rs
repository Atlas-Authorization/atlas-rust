//! Operator sign-in (`atlas login`) and token exchange for CLIs, without a
//! long-lived key.
//!
//! 1. [`start_operator_login`] runs the RFC 8628 device flow against Atlas's
//!    own sign-in with the public `atlas-cli` client: show the person
//!    `verification_uri_complete` / `user_code`, then
//! 2. [`poll_operator_login`] until it returns the operator access token, then
//! 3. [`exchange_operator_token`] swaps it (RFC 8693) for a ONE-HOUR Atlas
//!    token bound to one instance (`ins_…`, Backend API) or app / account
//!    (`app_…` / `acct_…`, Platform API), with only the scopes you ask for.
//!
//! Root actions (create an app or instance, mint a key) need a multi-factor
//! sign-in within five minutes; otherwise the API answers `403 STEP_UP_REQUIRED`.
//!
//! [`partner_link_token`] runs `client_credentials` for a partner service
//! calling an instance, and [`revoke_leaked_keys`] reports leaked credentials
//! (no key needed). All of them are built on the object-safe
//! [`crate::HttpTransport`], like the rest of the client flows.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

use crate::error::TransportError;
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

use super::oauth::form_encode;

/// The default Atlas API origin.
pub const OPERATOR_DEFAULT_API_URL: &str = "https://api.atlasauth.net";

/// Tunes the operator helpers.
#[derive(Debug, Clone, Default)]
pub struct OperatorOptions {
    /// The Atlas API origin (default [`OPERATOR_DEFAULT_API_URL`]).
    pub api_url: Option<String>,
    /// Replace the wait between polls (tests, or a UI that wants a faster
    /// cadence). When set, the server's `slow_down` does not add to it.
    pub poll_interval: Option<Duration>,
}

impl OperatorOptions {
    fn api(&self) -> String {
        self.api_url
            .as_deref()
            .unwrap_or(OPERATOR_DEFAULT_API_URL)
            .trim_end_matches('/')
            .to_string()
    }
}

/// A failed device-flow, token-exchange or token request.
#[derive(Debug, Error)]
pub enum OperatorError {
    /// The server refused with an OAuth error (`access_denied`,
    /// `expired_token`, `invalid_grant`, `STEP_UP_REQUIRED`, …).
    #[error("atlas operator: {error}{} (HTTP {status})", .description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Flow {
        error: String,
        description: Option<String>,
        status: u16,
    },
    /// The request did not complete.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A response body that did not parse.
    #[error("atlas operator: malformed response: {0}")]
    Malformed(String),
}

impl OperatorError {
    /// The OAuth error code, when the server refused.
    pub fn code(&self) -> Option<&str> {
        match self {
            OperatorError::Flow { error, .. } => Some(error.as_str()),
            _ => None,
        }
    }
    /// Whether a multi-factor sign-in within the last five minutes is needed.
    pub fn is_step_up_required(&self) -> bool {
        self.code() == Some("STEP_UP_REQUIRED")
    }
}

/// `GET /v1/operator`: where the device flow and token exchange live.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OperatorConfiguration {
    pub issuer: String,
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub scope: String,
    pub token_exchange_endpoint: String,
    pub token_exchange_audience: String,
    pub root_action_max_mfa_age_seconds: i64,
}

/// The RFC 8628 device authorization response.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OperatorDeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: i64,
    /// The configuration the flow runs against.
    #[serde(skip)]
    pub config: OperatorConfiguration,
}

/// A token endpoint answer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OperatorTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub issued_token_type: Option<String>,
    /// The resource a token exchange bound the token to.
    pub resource: Option<String>,
}

/// One outcome of [`revoke_leaked_keys`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LeakedKeyResult {
    pub index: i64,
    pub kind: String,
    /// `revoked`, `already_revoked` or `not_found`.
    pub outcome: String,
}

async fn post_form(
    transport: &Arc<dyn HttpTransport>,
    endpoint: &str,
    pairs: &[(&str, &str)],
) -> Result<(u16, Value), OperatorError> {
    let req = HttpRequest::new(HttpMethod::Post, endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(form_encode(pairs));
    let resp = transport.send(req).await?;
    let value = serde_json::from_str::<Value>(&resp.body).unwrap_or(Value::Null);
    Ok((resp.status, value))
}

/// Build the error for a refused request, accepting both the OAuth shape and
/// the Atlas error envelope.
fn flow_error(body: &Value, status: u16, fallback: &str) -> OperatorError {
    let mut code = body.get("error").and_then(Value::as_str).map(|s| s.to_string());
    let mut desc = body.get("error_description").and_then(Value::as_str).map(|s| s.to_string());
    if code.is_none() {
        if let Some(first) = body.get("errors").and_then(Value::as_array).and_then(|a| a.first()) {
            code = first.get("code").and_then(Value::as_str).map(|s| s.to_string());
            if desc.is_none() {
                desc = first.get("message").and_then(Value::as_str).map(|s| s.to_string());
            }
        }
    }
    OperatorError::Flow {
        error: code.unwrap_or_else(|| "error".to_string()),
        description: desc.or_else(|| Some(fallback.to_string())),
        status,
    }
}

fn decode<T: for<'de> Deserialize<'de>>(body: Value) -> Result<T, OperatorError> {
    serde_json::from_value(body).map_err(|e| OperatorError::Malformed(e.to_string()))
}

/// `GET /v1/operator` (no key needed).
pub async fn get_operator_configuration(
    transport: &Arc<dyn HttpTransport>,
    opts: &OperatorOptions,
) -> Result<OperatorConfiguration, OperatorError> {
    let req = HttpRequest::new(HttpMethod::Get, format!("{}/v1/operator", opts.api())).header("accept", "application/json");
    let resp = transport.send(req).await?;
    if !(200..300).contains(&resp.status) {
        return Err(OperatorError::Flow {
            error: "not_configured".into(),
            description: Some("The operator issuer is not configured on this deployment.".into()),
            status: resp.status,
        });
    }
    serde_json::from_str(&resp.body).map_err(|e| OperatorError::Malformed(e.to_string()))
}

/// Begin the device flow. Pass `config` to skip reading `GET /v1/operator`.
pub async fn start_operator_login(
    transport: &Arc<dyn HttpTransport>,
    config: Option<&OperatorConfiguration>,
    opts: &OperatorOptions,
) -> Result<OperatorDeviceAuthorization, OperatorError> {
    let config = match config {
        Some(c) => c.clone(),
        None => get_operator_configuration(transport, opts).await?,
    };
    let (status, body) = post_form(
        transport,
        &config.device_authorization_endpoint,
        &[("client_id", config.client_id.as_str()), ("scope", config.scope.as_str())],
    )
    .await?;
    if status != 200 {
        return Err(flow_error(&body, status, "Device authorization failed."));
    }
    let mut out: OperatorDeviceAuthorization = decode(body)?;
    out.config = config;
    Ok(out)
}

/// Poll until the person approves (returning the operator token), denies or
/// the code expires (an [`OperatorError::Flow`]). Honours the interval and
/// `slow_down`.
pub async fn poll_operator_login(
    transport: &Arc<dyn HttpTransport>,
    start: &OperatorDeviceAuthorization,
    opts: &OperatorOptions,
) -> Result<OperatorTokenResponse, OperatorError> {
    let interval = if start.interval < 1 { 1 } else { start.interval };
    let mut wait = opts.poll_interval.unwrap_or_else(|| Duration::from_secs(interval as u64));
    let lifetime = Duration::from_secs(start.expires_in.max(1) as u64);
    let deadline = Instant::now() + lifetime;
    while Instant::now() < deadline {
        tokio::time::sleep(wait).await;
        let (status, body) = post_form(
            transport,
            &start.config.token_endpoint,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", start.device_code.as_str()),
                ("client_id", start.config.client_id.as_str()),
            ],
        )
        .await?;
        if status == 200 {
            return decode(body);
        }
        match body.get("error").and_then(Value::as_str) {
            Some("authorization_pending") => continue,
            Some("slow_down") => {
                if opts.poll_interval.is_none() {
                    wait += Duration::from_secs(5);
                }
                continue;
            }
            _ => return Err(flow_error(&body, status, "Sign-in failed.")),
        }
    }
    Err(OperatorError::Flow {
        error: "expired_token".into(),
        description: Some("The sign-in code expired. Run the login again.".into()),
        status: 400,
    })
}

/// Swap an operator token (RFC 8693) for a one-hour, resource-bound Atlas
/// token. `resource` is an `ins_…` / `app_…` / `acct_…` id; `scopes` are the
/// scopes to keep.
pub async fn exchange_operator_token(
    transport: &Arc<dyn HttpTransport>,
    subject_token: &str,
    resource: &str,
    scopes: &[&str],
    opts: &OperatorOptions,
) -> Result<OperatorTokenResponse, OperatorError> {
    let scope = scopes.join(" ");
    let (status, body) = post_form(
        transport,
        &format!("{}/v1/oauth/token", opts.api()),
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", subject_token),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            ("audience", "atlas"),
            ("resource", resource),
            ("scope", scope.as_str()),
        ],
    )
    .await?;
    if status != 200 {
        return Err(flow_error(&body, status, "Token exchange failed."));
    }
    decode(body)
}

/// `client_credentials` with a partner link's credentials (a partner service
/// calling an instance). `scope` may be empty.
pub async fn partner_link_token(
    transport: &Arc<dyn HttpTransport>,
    client_id: &str,
    client_secret: &str,
    scope: &str,
    opts: &OperatorOptions,
) -> Result<OperatorTokenResponse, OperatorError> {
    let mut pairs = vec![
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if !scope.is_empty() {
        pairs.push(("scope", scope));
    }
    let (status, body) = post_form(transport, &format!("{}/v1/oauth/token", opts.api()), &pairs).await?;
    if status != 200 {
        return Err(flow_error(&body, status, "Token request failed."));
    }
    decode(body)
}

/// Revoke leaked Atlas credentials (`POST /v1/keys/revoke_leaked`, no key
/// needed). `source_url` optionally says where the secret was found.
pub async fn revoke_leaked_keys(
    transport: &Arc<dyn HttpTransport>,
    secrets: &[&str],
    source_url: Option<&str>,
    opts: &OperatorOptions,
) -> Result<Vec<LeakedKeyResult>, OperatorError> {
    let mut payload = json!({ "secrets": secrets });
    if let Some(u) = source_url {
        payload["url"] = json!(u);
    }
    let req = HttpRequest::new(HttpMethod::Post, format!("{}/v1/keys/revoke_leaked", opts.api()))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(payload.to_string());
    let resp = transport.send(req).await?;
    if !(200..300).contains(&resp.status) {
        return Err(OperatorError::Flow {
            error: "request_failed".into(),
            description: Some(format!("revoke_leaked failed ({}).", resp.status)),
            status: resp.status,
        });
    }
    #[derive(Deserialize)]
    struct Results {
        #[serde(default)]
        results: Vec<LeakedKeyResult>,
    }
    let parsed: Results = serde_json::from_str(&resp.body).map_err(|e| OperatorError::Malformed(e.to_string()))?;
    Ok(parsed.results)
}

/// Build a [`crate::backend::BackendClient`] signed with a one-hour Atlas
/// access token from [`exchange_operator_token`]. An `ins_…` token drives the
/// Backend API (`users()`, …); an `app_…` / `acct_…` token drives
/// [`platform()`](crate::backend::BackendClient::platform). Needs the
/// `backend` feature.
#[cfg(feature = "backend")]
pub fn backend_client_from_access_token(
    token: &str,
    base_url: Option<&str>,
    transport: Option<Arc<dyn HttpTransport>>,
) -> Result<crate::backend::BackendClient, crate::error::ConfigError> {
    let mut b = crate::backend::BackendClient::builder(token);
    if let Some(u) = base_url {
        b = b.base_url(u);
    }
    if let Some(t) = transport {
        b = b.transport(t);
    }
    b.build()
}
