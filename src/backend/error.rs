//! Errors for the management client.
//!
//! A failed BAPI call answers with the §9.1 envelope `{ errors: [{ code,
//! message, param?, meta? }] }`. `code` is the stable, machine-readable part of
//! that contract — integrators branch on it (`LAST_ADMIN`, `NOT_FOUND`,
//! `SCOPE_MISSING`, …) — so it is surfaced first-class here rather than buried
//! in a parsed body, mirroring `@atlasauth/backend`'s `AtlasApiError`.

use serde::Deserialize;
use thiserror::Error;

use crate::error::TransportError;

/// One entry in the §9.1 error envelope. `param`/`meta` carry the detail a
/// caller sometimes needs (a rate limit's `retry_after`, the offending field).
#[derive(Debug, Clone, Deserialize)]
pub struct AtlasErrorItem {
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

/// A non-2xx BAPI response, carrying the HTTP status and the full error
/// envelope in order.
#[derive(Debug, Clone, Error)]
#[error("atlas api error (HTTP {status}): {}", first_message(.errors))]
pub struct AtlasApiError {
    pub status: u16,
    pub errors: Vec<AtlasErrorItem>,
}

fn first_message(errors: &[AtlasErrorItem]) -> String {
    errors
        .first()
        .map(|e| {
            if e.message.is_empty() {
                e.code.clone()
            } else {
                e.message.clone()
            }
        })
        .unwrap_or_else(|| "request failed".to_string())
}

impl AtlasApiError {
    /// The first error's stable code — the field callers branch on most.
    pub fn code(&self) -> Option<&str> {
        self.errors.first().map(|e| e.code.as_str())
    }

    /// Whether ANY error in the envelope carries the given stable code.
    pub fn has_code(&self, code: &str) -> bool {
        self.errors.iter().any(|e| e.code == code)
    }
}

/// Every failure a management-client call can return.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The server answered with a non-2xx and the §9.1 error envelope.
    #[error(transparent)]
    Api(#[from] AtlasApiError),
    /// The request did not complete (DNS, TLS, connection), or a retry budget
    /// was exhausted on 5xx/429.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A 2xx with a body that did not parse into the expected type.
    #[error("atlas: malformed backend response: {0}")]
    Malformed(String),
}
