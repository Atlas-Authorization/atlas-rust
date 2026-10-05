//! OAuth flows for a native client: the PKCE authorization-code flow (loopback
//! redirect or custom-scheme callback) and the device-authorization grant
//! (RFC 8628).
//!
//! Both are the public-client, no-secret flows a native app must use. The
//! authorization-code helpers decompose the flow into the three steps a caller
//! owns the glue between — build the authorize URL, open a browser / wait for
//! the redirect, exchange the returned code — rather than binding a TCP socket
//! here, so the same code serves a loopback redirect (`http://127.0.0.1:<port>`)
//! and a custom scheme (`myapp://callback`), and stays testable with no network.

use std::sync::Arc;

use serde::Deserialize;
use url::Url;

use crate::error::TransportError;
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

use super::error::{DevicePollError, OAuthError};
use super::pkce::Pkce;

/// The token-endpoint success response (RFC 6749 §5.1), shared by the
/// authorization-code, device, and token-exchange grants.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    /// Present on a session-exchange response (the `sess_…` id).
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// A built PKCE authorization request. Holds the `authorization_url` to open,
/// plus the `pkce` verifier and `state` the callback must be checked against.
pub struct AuthorizationRequest {
    pub authorization_url: String,
    pub pkce: Pkce,
    pub state: String,
    pub redirect_uri: String,
}

impl AuthorizationRequest {
    /// Build an authorize URL with PKCE S256. `scopes` are space-joined; `state`
    /// is echoed back on the callback and MUST be compared (CSRF defence).
    pub fn new(
        authorize_endpoint: &str,
        client_id: &str,
        redirect_uri: &str,
        scopes: &[&str],
        state: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        let pkce = Pkce::generate();
        let state = state.into();
        let mut url = Url::parse(authorize_endpoint)
            .map_err(|e| OAuthError::InvalidCallback(format!("bad authorize endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", pkce.challenge())
            .append_pair("code_challenge_method", pkce.method());
        Ok(AuthorizationRequest {
            authorization_url: url.into(),
            pkce,
            state,
            redirect_uri: redirect_uri.to_string(),
        })
    }

    /// Exchange the code this request's callback returned for tokens. Verifies
    /// `state` against [`CallbackParams::state`] is the caller's job (call
    /// [`Self::parse_callback`] first and compare).
    pub async fn exchange_code(
        &self,
        transport: &Arc<dyn HttpTransport>,
        token_endpoint: &str,
        client_id: &str,
        code: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let form = form_encode(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", client_id),
            ("code_verifier", self.pkce.verifier()),
        ]);
        post_token(transport, token_endpoint, form).await
    }
}

/// The `code`/`state` a successful callback carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackParams {
    pub code: String,
    pub state: Option<String>,
}

/// Parse an authorization-redirect URL — a loopback `http://127.0.0.1:…/cb?…`
/// or a custom-scheme `myapp://callback?…` — into its `code`/`state`. An
/// `error=` callback becomes an [`OAuthError::Server`]; a callback with no
/// `code` is an [`OAuthError::InvalidCallback`].
pub fn parse_callback(redirect_url: &str) -> Result<CallbackParams, OAuthError> {
    let url = Url::parse(redirect_url)
        .map_err(|e| OAuthError::InvalidCallback(format!("unparseable redirect: {e}")))?;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    if let Some(error) = error {
        return Err(OAuthError::Server {
            error,
            description: error_description,
        });
    }
    match code {
        Some(code) => Ok(CallbackParams { code, state }),
        None => Err(OAuthError::InvalidCallback("no `code` in callback".to_string())),
    }
}

/// A device-authorization response (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// The minimum seconds between polls (defaults to 5 per the RFC).
    #[serde(default)]
    pub interval: Option<i64>,
}

impl DeviceAuthorization {
    /// The poll interval the server asked for, or the RFC default of 5 seconds.
    pub fn poll_interval_secs(&self) -> i64 {
        self.interval.unwrap_or(5)
    }
}

/// Start a device-authorization flow (RFC 8628 §3.1): display the `user_code`
/// and `verification_uri`, then poll [`poll_device_token`].
pub async fn request_device_code(
    transport: &Arc<dyn HttpTransport>,
    device_authorization_endpoint: &str,
    client_id: &str,
    scopes: &[&str],
) -> Result<DeviceAuthorization, OAuthError> {
    let scope = scopes.join(" ");
    let form = form_encode(&[("client_id", client_id), ("scope", &scope)]);
    let resp = send_form(transport, device_authorization_endpoint, form).await?;
    if (200..300).contains(&resp.status) {
        serde_json::from_str(&resp.body).map_err(|e| OAuthError::Malformed(e.to_string()))
    } else {
        Err(oauth_error_from(resp.status, &resp.body))
    }
}

/// Poll the token endpoint once for a device-flow result (RFC 8628 §3.4). The
/// `authorization_pending` / `slow_down` / `expired_token` / `access_denied`
/// OAuth errors become typed [`DevicePollError`]s so a caller's poll loop reads
/// cleanly; a token is returned on approval.
pub async fn poll_device_token(
    transport: &Arc<dyn HttpTransport>,
    token_endpoint: &str,
    client_id: &str,
    device_code: &str,
) -> Result<TokenResponse, DevicePollError> {
    let form = form_encode(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", client_id),
    ]);
    let resp = send_form(transport, token_endpoint, form)
        .await
        .map_err(OAuthError::from)?;
    if (200..300).contains(&resp.status) {
        return serde_json::from_str(&resp.body)
            .map_err(|e| DevicePollError::Other(OAuthError::Malformed(e.to_string())));
    }
    // Map the RFC 8628 pending/slow_down/… error codes.
    match serde_json::from_str::<OAuthErrorBody>(&resp.body) {
        Ok(body) => Err(match body.error.as_str() {
            "authorization_pending" => DevicePollError::AuthorizationPending,
            "slow_down" => DevicePollError::SlowDown,
            "expired_token" => DevicePollError::ExpiredToken,
            "access_denied" => DevicePollError::AccessDenied,
            _ => DevicePollError::Other(OAuthError::Server {
                error: body.error,
                description: body.error_description,
            }),
        }),
        Err(e) => Err(DevicePollError::Other(OAuthError::Malformed(e.to_string()))),
    }
}

/// Exchange a refresh token for a fresh token set (RFC 6749 §6,
/// `grant_type=refresh_token`). A public-client form POST — no secret, the
/// `client_id` identifies the caller. The response is a [`TokenResponse`]; a
/// rotating server returns a NEW `refresh_token` on it, so persist what comes
/// back and discard the presented one. A dead/rotated token is an
/// [`OAuthError::Server`] (`invalid_grant`).
pub async fn refresh_token_grant(
    transport: &Arc<dyn HttpTransport>,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse, OAuthError> {
    let form = form_encode(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ]);
    post_token(transport, token_endpoint, form).await
}

/// Revoke an access or refresh token (RFC 7009). POSTs the form to the
/// revocation endpoint (`POST /oauth2/revoke`). Per §2.2 the server answers 200
/// with an empty body whether or not the token existed — never leaking token
/// validity — so ANY 2xx is success; only a non-2xx becomes an
/// [`OAuthError`]. `token_type_hint` (`"access_token"` / `"refresh_token"`) only
/// orders the server's lookup and may be `None`.
pub async fn revoke_token(
    transport: &Arc<dyn HttpTransport>,
    revoke_endpoint: &str,
    client_id: &str,
    token: &str,
    token_type_hint: Option<&str>,
) -> Result<(), OAuthError> {
    let mut pairs = vec![("token", token), ("client_id", client_id)];
    if let Some(hint) = token_type_hint {
        pairs.push(("token_type_hint", hint));
    }
    let resp = send_form(transport, revoke_endpoint, form_encode(&pairs)).await?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(oauth_error_from(resp.status, &resp.body))
    }
}

// ── shared helpers ──────────────────────────────────────────────────────────

/// POST a form body to a token endpoint and parse a [`TokenResponse`], mapping a
/// non-2xx to an [`OAuthError`].
async fn post_token(
    transport: &Arc<dyn HttpTransport>,
    token_endpoint: &str,
    form: String,
) -> Result<TokenResponse, OAuthError> {
    let resp = send_form(transport, token_endpoint, form).await?;
    if (200..300).contains(&resp.status) {
        serde_json::from_str(&resp.body).map_err(|e| OAuthError::Malformed(e.to_string()))
    } else {
        Err(oauth_error_from(resp.status, &resp.body))
    }
}

async fn send_form(
    transport: &Arc<dyn HttpTransport>,
    endpoint: &str,
    form: String,
) -> Result<crate::http::HttpResponse, TransportError> {
    let req = HttpRequest::new(HttpMethod::Post, endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(form);
    transport.send(req).await
}

fn oauth_error_from(status: u16, body: &str) -> OAuthError {
    match serde_json::from_str::<OAuthErrorBody>(body) {
        Ok(b) => OAuthError::Server {
            error: b.error,
            description: b.error_description,
        },
        Err(_) => OAuthError::Server {
            error: format!("http_{status}"),
            description: if body.is_empty() { None } else { Some(body.chars().take(300).collect()) },
        },
    }
}

/// `application/x-www-form-urlencoded` body from key/value pairs.
pub(crate) fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}
