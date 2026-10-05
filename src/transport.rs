//! The built-in reqwest-backed HTTP transport, used by the convenience
//! constructors. Compiled only with the `reqwest-transport` feature (on by
//! default). It implements both [`JwksSource`] (GET + parse a JWKS) and
//! [`HttpPost`] (the API-key verify call), so one client backs the whole crate.

use crate::apikey::{HttpPost, HttpResponse};
use crate::error::TransportError;
use crate::jwks::{BoxFuture, Jwks, JwksSource};

/// A reqwest-backed transport. Cheap to clone (the inner `reqwest::Client` is an
/// `Arc`).
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build with a default client.
    pub fn new() -> Self {
        ReqwestTransport {
            client: reqwest::Client::new(),
        }
    }

    /// Build around a caller-provided client (timeouts, proxies, a custom TLS
    /// config).
    pub fn with_client(client: reqwest::Client) -> Self {
        ReqwestTransport { client }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksSource for ReqwestTransport {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
        Box::pin(async move {
            let resp = self
                .client
                .get(url)
                .header("accept", "application/json")
                .send()
                .await
                .map_err(|e| TransportError::new(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(TransportError::new(format!(
                    "JWKS fetch failed ({})",
                    resp.status().as_u16()
                )));
            }
            let text = resp
                .text()
                .await
                .map_err(|e| TransportError::new(e.to_string()))?;
            serde_json::from_str::<Jwks>(&text)
                .map_err(|e| TransportError::new(format!("JWKS is malformed: {e}")))
        })
    }
}

impl HttpPost for ReqwestTransport {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        bearer: &'a str,
        body: String,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let resp = self
                .client
                .post(url)
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| TransportError::new(e.to_string()))?;
            let status = resp.status().as_u16();
            let text = resp
                .text()
                .await
                .map_err(|e| TransportError::new(e.to_string()))?;
            Ok(HttpResponse { status, body: text })
        })
    }
}
