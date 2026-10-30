//! §12.2 — verify an inbound Atlas webhook, for the CUSTOMER consuming events.
//!
//! Atlas signs every delivery: `atlas-signature: v1,<base64>` is HMAC-SHA256
//! over `<id>.<timestamp>.<rawBody>` keyed with the endpoint secret, with
//! `atlas-id` and `atlas-timestamp` (epoch ms) headers. The timestamp is INSIDE
//! the signed material — a header-only timestamp would let an attacker replay a
//! captured body under a fresh timestamp — and a delivery more than five minutes
//! from now (in EITHER direction) is rejected so a captured request cannot be
//! replayed later, nor a far-future one minted to live long. The header may
//! carry several space-separated `v1,<base64>` entries (one per secret while a
//! secret rotates with an overlap); the delivery verifies when any one matches.
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
        self.verify_delivery(raw, headers).map(|d| d.event)
    }

    /// Verify a delivery and return the envelope together with the signed
    /// `atlas-id` (`delivery_id`, the same on every retry of one event: the
    /// key to deduplicate on) and `atlas-timestamp` (epoch ms of this attempt).
    pub fn verify_delivery<H: WebhookHeaders + ?Sized>(
        &self,
        raw: &[u8],
        headers: &H,
    ) -> Result<VerifiedDelivery, WebhookError> {
        let id = headers.get_header(HEADER_ID).ok_or(WebhookError::MissingHeaders)?;
        let ts_raw = headers
            .get_header(HEADER_TIMESTAMP)
            .ok_or(WebhookError::MissingHeaders)?;
        let sig = headers
            .get_header(HEADER_SIGNATURE)
            .ok_or(WebhookError::MissingHeaders)?;

        // One `v1,<base64>` entry, or several separated by spaces (while an
        // endpoint secret rotates, Atlas signs with the old and the new
        // secret). Entries of another version are skipped.
        let provided_macs: Vec<Vec<u8>> = sig
            .split_whitespace()
            .filter_map(|entry| entry.split_once(','))
            .filter(|(version, value)| *version == SIGNATURE_VERSION && !value.is_empty())
            .filter_map(|(_, value)| STANDARD.decode(value).ok())
            .collect();
        if provided_macs.is_empty() {
            return Err(WebhookError::MalformedSignature);
        }

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
        // Constant-time comparison against each decoded MAC (no early exit).
        let mut matched = false;
        for provided in &provided_macs {
            if mac.clone().verify_slice(provided).is_ok() {
                matched = true;
            }
        }
        if !matched {
            return Err(WebhookError::SignatureMismatch);
        }

        let event = parse_event(raw).ok_or(WebhookError::MalformedBody)?;
        Ok(VerifiedDelivery {
            event,
            delivery_id: id.to_string(),
            timestamp,
        })
    }
}

impl Webhook {
    /// Verify a delivery whose endpoint was created with
    /// `signature_versions: ["v1","v2"]` (or `["v2"]`). The `v2` signature is
    /// HMAC-SHA256 over `<id>.<timestamp>.<endpoint url>.<raw body>`, so a
    /// captured delivery cannot be replayed against another URL of yours.
    ///
    /// `endpoint_url` is the exact URL you registered for the endpoint.
    /// `v1` entries are accepted too (unless `require_v2`), and entries of an
    /// unknown version are ignored, so a future version never breaks you.
    /// `require_v2 = true` refuses a delivery that carries only `v1`.
    pub fn verify_url<H: WebhookHeaders + ?Sized>(
        &self,
        raw: &[u8],
        headers: &H,
        endpoint_url: &str,
        require_v2: bool,
    ) -> Result<VerifiedDelivery, WebhookError> {
        let id = headers.get_header(HEADER_ID).ok_or(WebhookError::MissingHeaders)?;
        let ts_raw = headers.get_header(HEADER_TIMESTAMP).ok_or(WebhookError::MissingHeaders)?;
        let sig = headers.get_header(HEADER_SIGNATURE).ok_or(WebhookError::MissingHeaders)?;

        let decode_all = |version: &str| -> Vec<Vec<u8>> {
            sig.split_whitespace()
                .filter_map(|entry| entry.split_once(','))
                .filter(|(v, value)| *v == version && !value.is_empty())
                .filter_map(|(_, value)| STANDARD.decode(value).ok())
                .collect()
        };
        let v1 = if require_v2 { Vec::new() } else { decode_all("v1") };
        let v2 = decode_all("v2");
        if v1.is_empty() && v2.is_empty() {
            return Err(WebhookError::MalformedSignature);
        }

        let timestamp: i64 = ts_raw.parse().map_err(|_| WebhookError::StaleTimestamp)?;
        let now = self.now_ms.unwrap_or_else(now_epoch_ms);
        if (now - timestamp).abs() > self.tolerance_ms {
            return Err(WebhookError::StaleTimestamp);
        }

        let ts = timestamp.to_string();
        let mut mac1 = HmacSha256::new_from_slice(self.secret.as_bytes()).expect("HMAC accepts a key of any length");
        mac1.update(id.as_bytes());
        mac1.update(b".");
        mac1.update(ts.as_bytes());
        mac1.update(b".");
        mac1.update(raw);
        let mut mac2 = HmacSha256::new_from_slice(self.secret.as_bytes()).expect("HMAC accepts a key of any length");
        mac2.update(id.as_bytes());
        mac2.update(b".");
        mac2.update(ts.as_bytes());
        mac2.update(b".");
        mac2.update(endpoint_url.as_bytes());
        mac2.update(b".");
        mac2.update(raw);

        let mut matched = false;
        for provided in &v1 {
            if mac1.clone().verify_slice(provided).is_ok() {
                matched = true;
            }
        }
        for provided in &v2 {
            if mac2.clone().verify_slice(provided).is_ok() {
                matched = true;
            }
        }
        if !matched {
            return Err(WebhookError::SignatureMismatch);
        }
        let event = parse_event(raw).ok_or(WebhookError::MalformedBody)?;
        Ok(VerifiedDelivery { event, delivery_id: id.to_string(), timestamp })
    }
}

/// Standard Webhooks header names (application webhooks, see
/// [`Webhook::verify_standard`]).
pub const STANDARD_HEADER_ID: &str = "webhook-id";
pub const STANDARD_HEADER_TIMESTAMP: &str = "webhook-timestamp";
pub const STANDARD_HEADER_SIGNATURE: &str = "webhook-signature";

impl Webhook {
    /// Verify an application-webhook delivery (Standard Webhooks): the
    /// `webhook-id`, `webhook-timestamp` (epoch SECONDS) and
    /// `webhook-signature` headers, where the signature is one or more
    /// space-separated `v1,<base64>` entries of HMAC-SHA256 over
    /// `<id>.<timestamp>.<raw body>`, keyed with the base64-decoded secret
    /// after its `whsec_` prefix. Any one matching entry verifies (a rotated
    /// secret signs with both). The window is [`Webhook::tolerance_ms`]
    /// (default five minutes) and "now" is [`Webhook::now_ms`] when pinned.
    ///
    /// `raw` MUST be the exact bytes received.
    pub fn verify_standard<H: WebhookHeaders + ?Sized>(
        &self,
        raw: &[u8],
        headers: &H,
    ) -> Result<StandardDelivery, WebhookError> {
        let id = headers.get_header(STANDARD_HEADER_ID).ok_or(WebhookError::MissingHeaders)?;
        let ts_raw = headers
            .get_header(STANDARD_HEADER_TIMESTAMP)
            .ok_or(WebhookError::MissingHeaders)?;
        let sig = headers
            .get_header(STANDARD_HEADER_SIGNATURE)
            .ok_or(WebhookError::MissingHeaders)?;

        let provided: Vec<Vec<u8>> = sig
            .split_whitespace()
            .filter_map(|entry| entry.split_once(','))
            .filter(|(version, value)| *version == SIGNATURE_VERSION && !value.is_empty())
            .filter_map(|(_, value)| STANDARD.decode(value).ok())
            .collect();
        if provided.is_empty() {
            return Err(WebhookError::MalformedSignature);
        }

        // Digits only, as the server writes it (no sign, no spaces).
        if ts_raw.is_empty() || !ts_raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WebhookError::StaleTimestamp);
        }
        let timestamp: i64 = ts_raw.parse().map_err(|_| WebhookError::StaleTimestamp)?;
        let now_sec = self.now_ms.unwrap_or_else(now_epoch_ms) / 1000;
        if (now_sec - timestamp).abs() > self.tolerance_ms / 1000 {
            return Err(WebhookError::StaleTimestamp);
        }

        let encoded = self.secret.strip_prefix("whsec_").unwrap_or(&self.secret);
        // A secret that is not base64 can never have produced a signature.
        let key = STANDARD.decode(encoded).map_err(|_| WebhookError::SignatureMismatch)?;
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts a key of any length");
        mac.update(id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(raw);
        let mut matched = false;
        for candidate in &provided {
            if mac.clone().verify_slice(candidate).is_ok() {
                matched = true;
            }
        }
        if !matched {
            return Err(WebhookError::SignatureMismatch);
        }
        Ok(StandardDelivery {
            id: id.to_string(),
            timestamp,
            payload: serde_json::from_slice(raw).unwrap_or(serde_json::Value::Null),
        })
    }
}

/// A verified application-webhook delivery ([`Webhook::verify_standard`]).
#[derive(Debug, Clone, PartialEq)]
pub struct StandardDelivery {
    /// The signed `webhook-id`: the event's `evt_` id, the same on every
    /// retry and redelivery, so deduplicate on it.
    pub id: String,
    /// The signed `webhook-timestamp` (epoch seconds) of this attempt.
    pub timestamp: i64,
    /// The parsed JSON body (`Null` when the body is not JSON).
    pub payload: serde_json::Value,
}

/// A verified delivery: the envelope plus the signed headers that identify it.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedDelivery {
    pub event: Event,
    /// The signed `atlas-id` header. Stable across retries of one event, so
    /// store it to drop a delivery you have already handled.
    pub delivery_id: String,
    /// The signed `atlas-timestamp` header (epoch milliseconds) of this attempt.
    pub timestamp: i64,
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
    /// The referral platform answered after `user.created` was sent. The data
    /// is a [`UserReferralAttributedEvent`](super::UserReferralAttributedEvent).
    UserReferralAttributed,
    /// Attribution finished after `user.created` was sent (attributed, none
    /// or failed). The data is the full user, with `referral` filled in.
    UserReferralResolved,
    UserDeleted,
    UserBanned,
    UserUnbanned,
    UserLocked,
    UserDeactivated,
    /// A dormant account signed in again (after the dormant-account threshold).
    UserReactivated,
    SessionCreated,
    SessionEnded,
    SessionRevoked,
    SessionRemoved,
    SessionPending,
    /// A session's custom data changed.
    SessionUpdated,
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
    ApiKeyCreated,
    ApiKeyUpdated,
    ApiKeyRevoked,
    /// One of a key's spend caps filled up, or refused a debit, for the first
    /// time in its current window. The payload is the key plus `limit`.
    ApiKeyLimitReached,
    EntitlementOverrideCreated,
    EntitlementOverrideDeleted,
    EntitlementOverrideExpired,
    /// A webhook endpoint started failing (`webhook_endpoint.failing`).
    WebhookEndpointFailing,
    /// Atlas disabled a webhook endpoint after repeated failures.
    WebhookEndpointDisabled,
    /// A failing or disabled webhook endpoint recovered.
    WebhookEndpointRecovered,
    /// An outbound delivery target (referral connection, back-channel
    /// receiver, integration) started failing.
    DeliveryTargetFailing,
    /// An outbound delivery target was disabled after repeated failures.
    DeliveryTargetDisabled,
    /// An outbound delivery target recovered.
    DeliveryTargetRecovered,
    /// The event `test` sends (`webhook.test`).
    WebhookTest,
    /// A secret key is about to expire.
    SecretKeyExpiring,
    /// A secret key was revoked.
    SecretKeyRevoked,
    /// A privacy request changed state (`privacy_request.updated`).
    PrivacyRequestUpdated,
    /// A privacy request finished (`privacy_request.completed`).
    PrivacyRequestCompleted,
    /// A user's deletion was scheduled (`user.deletion_scheduled`).
    UserDeletionScheduled,
    /// A user's scheduled deletion was canceled (`user.deletion_canceled`).
    UserDeletionCanceled,
    /// A user accepted a policy version. The data is the policy acceptance with its evidence.
    UserPolicyAccepted,
    /// A policy version was published.
    PolicyVersionPublished,
    /// Any event type not modelled above — carries the raw dotted string.
    Other(String),
}

impl From<&str> for EventType {
    fn from(s: &str) -> Self {
        match s {
            "user.created" => EventType::UserCreated,
            "user.updated" => EventType::UserUpdated,
            "user.referral_attributed" => EventType::UserReferralAttributed,
            "user.referral_resolved" => EventType::UserReferralResolved,
            "user.deleted" => EventType::UserDeleted,
            "user.banned" => EventType::UserBanned,
            "user.unbanned" => EventType::UserUnbanned,
            "user.locked" => EventType::UserLocked,
            "user.deactivated" => EventType::UserDeactivated,
            "user.reactivated" => EventType::UserReactivated,
            "session.created" => EventType::SessionCreated,
            "session.ended" => EventType::SessionEnded,
            "session.revoked" => EventType::SessionRevoked,
            "session.removed" => EventType::SessionRemoved,
            "session.pending" => EventType::SessionPending,
            "session.updated" => EventType::SessionUpdated,
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
            "api_key.created" => EventType::ApiKeyCreated,
            "api_key.updated" => EventType::ApiKeyUpdated,
            "api_key.revoked" => EventType::ApiKeyRevoked,
            "api_key.limit_reached" => EventType::ApiKeyLimitReached,
            "entitlement.override.created" => EventType::EntitlementOverrideCreated,
            "entitlement.override.deleted" => EventType::EntitlementOverrideDeleted,
            "entitlement.override.expired" => EventType::EntitlementOverrideExpired,
            "user.policy_accepted" => EventType::UserPolicyAccepted,
            "policy.version_published" => EventType::PolicyVersionPublished,
            "webhook_endpoint.failing" => EventType::WebhookEndpointFailing,
            "webhook_endpoint.disabled" => EventType::WebhookEndpointDisabled,
            "webhook_endpoint.recovered" => EventType::WebhookEndpointRecovered,
            "delivery_target.failing" => EventType::DeliveryTargetFailing,
            "delivery_target.disabled" => EventType::DeliveryTargetDisabled,
            "delivery_target.recovered" => EventType::DeliveryTargetRecovered,
            "webhook.test" => EventType::WebhookTest,
            "secret_key.expiring" => EventType::SecretKeyExpiring,
            "secret_key.revoked" => EventType::SecretKeyRevoked,
            "privacy_request.updated" => EventType::PrivacyRequestUpdated,
            "privacy_request.completed" => EventType::PrivacyRequestCompleted,
            "user.deletion_scheduled" => EventType::UserDeletionScheduled,
            "user.deletion_canceled" => EventType::UserDeletionCanceled,
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
            EventType::UserReferralAttributed => "user.referral_attributed",
            EventType::UserReferralResolved => "user.referral_resolved",
            EventType::UserDeleted => "user.deleted",
            EventType::UserBanned => "user.banned",
            EventType::UserUnbanned => "user.unbanned",
            EventType::UserLocked => "user.locked",
            EventType::UserDeactivated => "user.deactivated",
            EventType::UserReactivated => "user.reactivated",
            EventType::SessionCreated => "session.created",
            EventType::SessionEnded => "session.ended",
            EventType::SessionRevoked => "session.revoked",
            EventType::SessionRemoved => "session.removed",
            EventType::SessionPending => "session.pending",
            EventType::SessionUpdated => "session.updated",
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
            EventType::ApiKeyCreated => "api_key.created",
            EventType::ApiKeyUpdated => "api_key.updated",
            EventType::ApiKeyRevoked => "api_key.revoked",
            EventType::ApiKeyLimitReached => "api_key.limit_reached",
            EventType::EntitlementOverrideCreated => "entitlement.override.created",
            EventType::EntitlementOverrideDeleted => "entitlement.override.deleted",
            EventType::EntitlementOverrideExpired => "entitlement.override.expired",
            EventType::UserPolicyAccepted => "user.policy_accepted",
            EventType::PolicyVersionPublished => "policy.version_published",
            EventType::WebhookEndpointFailing => "webhook_endpoint.failing",
            EventType::WebhookEndpointDisabled => "webhook_endpoint.disabled",
            EventType::WebhookEndpointRecovered => "webhook_endpoint.recovered",
            EventType::DeliveryTargetFailing => "delivery_target.failing",
            EventType::DeliveryTargetDisabled => "delivery_target.disabled",
            EventType::DeliveryTargetRecovered => "delivery_target.recovered",
            EventType::WebhookTest => "webhook.test",
            EventType::SecretKeyExpiring => "secret_key.expiring",
            EventType::SecretKeyRevoked => "secret_key.revoked",
            EventType::PrivacyRequestUpdated => "privacy_request.updated",
            EventType::PrivacyRequestCompleted => "privacy_request.completed",
            EventType::UserDeletionScheduled => "user.deletion_scheduled",
            EventType::UserDeletionCanceled => "user.deletion_canceled",
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

// ── event-name aliases ──────────────────────────────────────────────────────

/// The deprecated event spellings and what they became: `(alias, canonical,
/// kind)`, where `kind` is `"rename"` (the old name is a spelling of the same
/// event) or `"companion"` (Atlas sends both names for one occurrence).
///
/// An endpoint created with `event_naming: "canonical"` receives only the
/// canonical names; `"legacy"` keeps the old spellings.
pub const WEBHOOK_EVENT_ALIASES: &[(&str, &str, &str)] = &[
    ("session.ended", "session.revoked", "companion"),
    ("session.removed", "session.revoked", "companion"),
    ("organizationMembership.created", "organization_membership.created", "rename"),
    ("organizationMembership.updated", "organization_membership.updated", "rename"),
    ("organizationMembership.deleted", "organization_membership.deleted", "rename"),
    ("organization.membership.deleted", "organization_membership.deleted", "rename"),
    ("organizationInvitation.created", "organization_invitation.created", "rename"),
    ("organizationInvitation.accepted", "organization_invitation.accepted", "rename"),
    ("organizationInvitation.revoked", "organization_invitation.revoked", "rename"),
    ("organizationInvitation.declined", "organization_invitation.declined", "rename"),
    ("organizationInvitation.resent", "organization_invitation.resent", "rename"),
    ("teamMembership.created", "team_membership.created", "rename"),
    ("teamMembership.deleted", "team_membership.deleted", "rename"),
    ("appRole.created", "app_role.created", "rename"),
    ("appRole.updated", "app_role.updated", "rename"),
    ("appRole.deleted", "app_role.deleted", "rename"),
    ("organizationDomain.created", "organization_domain.created", "rename"),
    ("organizationDomain.updated", "organization_domain.updated", "rename"),
    ("organizationDomain.deleted", "organization_domain.deleted", "rename"),
    ("organization.settings.updated", "organization_settings.updated", "rename"),
    ("waitlistEntry.created", "waitlist_entry.created", "rename"),
    ("waitlistEntry.updated", "waitlist_entry.updated", "rename"),
    ("billing.subscription.created", "billing_subscription.created", "rename"),
    ("billing.subscription.updated", "billing_subscription.updated", "rename"),
    ("billing.subscription.canceled", "billing_subscription.canceled", "rename"),
    ("billing.invoice.payment_failed", "billing_invoice.payment_failed", "rename"),
    ("billing.trial.started", "billing_trial.started", "rename"),
    ("billing.trial.will_end", "billing_trial.will_end", "rename"),
    ("billing.trial.ended", "billing_trial.ended", "rename"),
    ("entitlement.override.created", "entitlement_override.created", "rename"),
    ("entitlement.override.deleted", "entitlement_override.deleted", "rename"),
    ("entitlement.override.expired", "entitlement_override.expired", "rename"),
    ("scimToken.created", "scim_token.created", "rename"),
    ("scimToken.revoked", "scim_token.revoked", "rename"),
    ("ssoConnection.created", "sso_connection.created", "rename"),
    ("ssoConnection.updated", "sso_connection.updated", "rename"),
    ("ssoConnection.deleted", "sso_connection.deleted", "rename"),
    ("user.data_export.requested", "user.data_export_requested", "rename"),
    ("user.deletion_cancelled", "user.deletion_canceled", "companion"),
];

/// Whether `name` is a deprecated event spelling.
pub fn is_deprecated_webhook_event(name: &str) -> bool {
    WEBHOOK_EVENT_ALIASES.iter().any(|(alias, _, _)| *alias == name)
}

/// The canonical spelling of an event name (the name itself when it is already
/// canonical or unknown).
pub fn canonical_webhook_event(name: &str) -> &str {
    for (alias, canonical, _) in WEBHOOK_EVENT_ALIASES {
        if *alias == name {
            return canonical;
        }
    }
    name
}

/// Every spelling of an event: the canonical name first, then its deprecated
/// aliases in alphabetical order. Subscribe to all of them to receive the
/// event on both a `canonical` and a `legacy` endpoint.
pub fn webhook_event_spellings(name: &str) -> Vec<String> {
    let canonical = canonical_webhook_event(name).to_string();
    let mut aliases: Vec<String> = WEBHOOK_EVENT_ALIASES
        .iter()
        .filter(|(_, c, _)| *c == canonical)
        .map(|(a, _, _)| a.to_string())
        .collect();
    aliases.sort();
    let mut out = vec![canonical];
    out.extend(aliases);
    out
}

impl Event {
    /// This event's type in the canonical spelling.
    pub fn canonical_type(&self) -> String {
        canonical_webhook_event(self.event_type.as_str()).to_string()
    }
}
