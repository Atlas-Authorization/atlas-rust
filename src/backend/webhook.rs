//! §12.2 — verify an inbound Atlas webhook, for the CUSTOMER consuming events.
//!
//! Atlas signs every delivery: `atlas-signature: v1,<base64>` is HMAC-SHA256
//! over `<id>.<timestamp>.<rawBody>` keyed with the endpoint secret, with
//! `atlas-id` and `atlas-timestamp` (epoch ms) headers. The timestamp is INSIDE
//! the signed material — a header-only timestamp would let an attacker replay a
//! captured body under a fresh timestamp — and a delivery more than five minutes
//! from now (in EITHER direction) is rejected so a captured request cannot be
//! replayed later, nor a far-future one minted to live long.
//!
//! The signing string, the header names, the `v1,` prefix, the base64 of the
//! raw MAC, and the five-minute window are matched byte-for-byte to the server
//! and to `@atlasauth/backend`'s `verifyWebhook`. Verify over the RAW request
//! body, BEFORE any JSON parse — re-serializing reorders keys and breaks the MAC.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const SIGNATURE_VERSION: &str = "v1";
const REPLAY_TOLERANCE_MS: i64 = 5 * 60_000;

/// Header names Atlas sends on every delivery (lower-case; matched
/// case-insensitively by [`WebhookHeaders`]).
pub const HEADER_ID: &str = "atlas-id";
pub const HEADER_TIMESTAMP: &str = "atlas-timestamp";
pub const HEADER_SIGNATURE: &str = "atlas-signature";

/// Why a webhook failed to verify. Coarse on purpose where it concerns the
/// signature — a precise reason helps a forger more than a developer — but the
/// header/timestamp shape problems are named so an integrator can debug their
/// own plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WebhookError {
    /// One of `atlas-id` / `atlas-timestamp` / `atlas-signature` was absent.
    #[error("atlas webhook: missing one of the atlas-id/atlas-timestamp/atlas-signature headers")]
    MissingHeaders,
    /// The signature header was not `v1,<base64>`, or the base64 did not decode.
    #[error("atlas webhook: malformed signature header")]
    MalformedSignature,
    /// The timestamp was non-numeric or outside the ±5-minute replay window.
    #[error("atlas webhook: stale or invalid timestamp (outside the replay window)")]
    StaleTimestamp,
    /// The computed HMAC did not match the delivered signature.
    #[error("atlas webhook: signature mismatch")]
    SignatureMismatch,
    /// The signature checked out but the body was not valid JSON for an [`Event`].
    #[error("atlas webhook: body is not a valid event envelope")]
    MalformedBody,
}

/// A case-insensitive header lookup, so a caller can pass whatever their web
/// framework hands them — a `HashMap`, a slice of pairs — without translating.
pub trait WebhookHeaders {
    fn get_header(&self, name: &str) -> Option<&str>;
}

impl WebhookHeaders for HashMap<String, String> {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl WebhookHeaders for [(String, String)] {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl WebhookHeaders for Vec<(String, String)> {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.as_slice().get_header(name)
    }
}

impl WebhookHeaders for [(&str, &str)] {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

/// The verifier, constructed once from an endpoint's signing secret
/// (`whsec_…`). Cheap to clone and reuse across deliveries.
#[derive(Clone)]
pub struct Webhook {
    secret: String,
    tolerance_ms: i64,
    now_ms: Option<i64>,
}

impl Webhook {
    /// Build a verifier for an endpoint's signing secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Webhook {
            secret: secret.into(),
            tolerance_ms: REPLAY_TOLERANCE_MS,
            now_ms: None,
        }
    }

    /// Override the ±replay tolerance (default five minutes). Rarely needed.
    pub fn tolerance_ms(mut self, ms: i64) -> Self {
        self.tolerance_ms = ms;
        self
    }

    /// Pin "now" (epoch ms) for deterministic tests.
    pub fn now_ms(mut self, now_ms: i64) -> Self {
        self.now_ms = Some(now_ms);
        self
    }

    /// Verify a delivery and parse the envelope.
    ///
    /// `raw` MUST be the exact bytes received; re-serialized JSON breaks the
    /// MAC. On success the parsed [`Event`] is returned; every failure is a
    /// typed [`WebhookError`], never a panic.
    pub fn verify<H: WebhookHeaders + ?Sized>(
        &self,
        raw: &[u8],
        headers: &H,
    ) -> Result<Event, WebhookError> {
        let id = headers.get_header(HEADER_ID).ok_or(WebhookError::MissingHeaders)?;
        let ts_raw = headers
            .get_header(HEADER_TIMESTAMP)
            .ok_or(WebhookError::MissingHeaders)?;
        let sig = headers
            .get_header(HEADER_SIGNATURE)
            .ok_or(WebhookError::MissingHeaders)?;

        let (version, provided) = sig.split_once(',').ok_or(WebhookError::MalformedSignature)?;
        if version != SIGNATURE_VERSION || provided.is_empty() {
            return Err(WebhookError::MalformedSignature);
        }
        let provided_mac = STANDARD
            .decode(provided)
            .map_err(|_| WebhookError::MalformedSignature)?;

        let timestamp: i64 = ts_raw.parse().map_err(|_| WebhookError::StaleTimestamp)?;
        let now = self.now_ms.unwrap_or_else(now_epoch_ms);
        if (now - timestamp).abs() > self.tolerance_ms {
            return Err(WebhookError::StaleTimestamp);
        }

        // `<id>.<timestamp>.<raw>`, with the timestamp rendered exactly as the
        // server did (the integer it signed, not the header string, so a header
        // like " 123" cannot smuggle different bytes into the MAC).
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(raw);
        // Constant-time comparison against the decoded MAC bytes.
        mac.verify_slice(&provided_mac)
            .map_err(|_| WebhookError::SignatureMismatch)?;

        parse_event(raw).ok_or(WebhookError::MalformedBody)
    }
}

/// A verified event envelope: `{ id, type, timestamp, instance_id, data }`.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub id: String,
    /// The typed event type, with an [`EventType::Other`] fallback for a type
    /// this SDK version does not yet model.
    pub event_type: EventType,
    pub timestamp: Option<i64>,
    pub instance_id: Option<String>,
    /// The event payload — the object the event is about. Left as raw JSON so a
    /// caller deserializes it into whichever resource type the event concerns.
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEvent {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    r#type: String,
    #[serde(default)]
    timestamp: Option<i64>,
    #[serde(default)]
    instance_id: Option<String>,
    #[serde(default)]
    data: serde_json::Value,
}

fn parse_event(raw: &[u8]) -> Option<Event> {
    let ev: RawEvent = serde_json::from_slice(raw).ok()?;
    Some(Event {
        id: ev.id,
        event_type: EventType::from(ev.r#type.as_str()),
        timestamp: ev.timestamp,
        instance_id: ev.instance_id,
        data: ev.data,
    })
}

/// The event types Atlas emits. `Other` carries any type string this SDK
/// version does not model, so a new server-side event never fails to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserBanned,
    UserUnbanned,
    UserLocked,
    UserDeactivated,
    SessionCreated,
    SessionEnded,
    SessionRevoked,
    SessionRemoved,
    SessionPending,
    OrganizationCreated,
    OrganizationUpdated,
    OrganizationMembershipDeleted,
    RoleCreated,
    RoleUpdated,
    RoleDeleted,
    PermissionCreated,
    PermissionDeleted,
    EmailCreated,
    SmsCreated,
    SubscriptionCreated,
    /// Any event type not modelled above — carries the raw dotted string.
    Other(String),
}

impl From<&str> for EventType {
    fn from(s: &str) -> Self {
        match s {
            "user.created" => EventType::UserCreated,
            "user.updated" => EventType::UserUpdated,
            "user.deleted" => EventType::UserDeleted,
            "user.banned" => EventType::UserBanned,
            "user.unbanned" => EventType::UserUnbanned,
            "user.locked" => EventType::UserLocked,
            "user.deactivated" => EventType::UserDeactivated,
            "session.created" => EventType::SessionCreated,
            "session.ended" => EventType::SessionEnded,
            "session.revoked" => EventType::SessionRevoked,
            "session.removed" => EventType::SessionRemoved,
            "session.pending" => EventType::SessionPending,
            "organization.created" => EventType::OrganizationCreated,
            "organization.updated" => EventType::OrganizationUpdated,
            "organization.membership.deleted" => EventType::OrganizationMembershipDeleted,
            "role.created" => EventType::RoleCreated,
            "role.updated" => EventType::RoleUpdated,
            "role.deleted" => EventType::RoleDeleted,
            "permission.created" => EventType::PermissionCreated,
            "permission.deleted" => EventType::PermissionDeleted,
            "email.created" => EventType::EmailCreated,
            "sms.created" => EventType::SmsCreated,
            "subscription.created" => EventType::SubscriptionCreated,
            other => EventType::Other(other.to_string()),
        }
    }
}

impl EventType {
    /// The dotted wire string for this event type.
    pub fn as_str(&self) -> &str {
        match self {
            EventType::UserCreated => "user.created",
            EventType::UserUpdated => "user.updated",
            EventType::UserDeleted => "user.deleted",
            EventType::UserBanned => "user.banned",
            EventType::UserUnbanned => "user.unbanned",
            EventType::UserLocked => "user.locked",
            EventType::UserDeactivated => "user.deactivated",
            EventType::SessionCreated => "session.created",
            EventType::SessionEnded => "session.ended",
            EventType::SessionRevoked => "session.revoked",
            EventType::SessionRemoved => "session.removed",
            EventType::SessionPending => "session.pending",
            EventType::OrganizationCreated => "organization.created",
            EventType::OrganizationUpdated => "organization.updated",
            EventType::OrganizationMembershipDeleted => "organization.membership.deleted",
            EventType::RoleCreated => "role.created",
            EventType::RoleUpdated => "role.updated",
            EventType::RoleDeleted => "role.deleted",
            EventType::PermissionCreated => "permission.created",
            EventType::PermissionDeleted => "permission.deleted",
            EventType::EmailCreated => "email.created",
            EventType::SmsCreated => "sms.created",
            EventType::SubscriptionCreated => "subscription.created",
            EventType::Other(s) => s,
        }
    }
}

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
