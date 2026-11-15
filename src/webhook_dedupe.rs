//! Verify an Atlas webhook and drop a delivery whose `atlas-id` was already seen (feature `backend`).
//!
//! Atlas retries a delivery until your endpoint answers 2xx, and the signed `atlas-id` is identical on every
//! retry of one event, so it is the key to deduplicate on. [`WebhookDeduper::verify_and_dedupe`] checks the
//! signature and timestamp exactly as [`Webhook::verify_delivery`], then claims the id in a
//! [`WebhookDedupeStore`]: an unverified delivery never touches the store.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use atlasauth::backend::Webhook;
//! # use atlasauth::webhook_dedupe::{MemoryWebhookStore, WebhookDeduper};
//! # fn handle(raw: &[u8], headers: &[(String, String)]) -> Result<(), Box<dyn std::error::Error>> {
//! let dedupe = WebhookDeduper::new(Webhook::new("whsec_..."), Arc::new(MemoryWebhookStore::new()));
//! let got = dedupe.verify_and_dedupe(raw, headers)?;
//! if !got.duplicate {
//!     // handle got.event; if the handler fails, call dedupe.release(&got) so Atlas's retry is processed
//! }
//! # Ok(()) }
//! ```

#[cfg(feature = "webhook-dedupe-sqlx")]
#[path = "webhook_dedupe_sqlx.rs"]
pub mod sqlx_store;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::backend::{Event, Webhook, WebhookError, WebhookHeaders};
use crate::clock::{system_clock, Clock};
use crate::mirror::StoreError;

/// Where seen delivery ids live. `set_if_absent` must be atomic: it stores `key` for `ttl_seconds` and
/// returns `true` when the key was NOT there, `false` when it already was (Redis: `SET key 1 EX ttl NX`; SQL:
/// an insert with a unique key that treats an expired row as absent). `delete` is optional; with it, a failed
/// handler can release the id so Atlas's retry is processed.
pub trait WebhookDedupeStore: Send + Sync {
    fn set_if_absent(&self, key: &str, ttl_seconds: u64) -> Result<bool, StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError> {
        let _ = key;
        Ok(())
    }
}

/// A single-process store. Use a shared one (Redis, a database) when you run more than one instance.
pub struct MemoryWebhookStore {
    seen: Mutex<HashMap<String, u64>>,
    now: Clock,
}

impl MemoryWebhookStore {
    pub fn new() -> Self {
        Self::with_clock(system_clock())
    }

    /// With an injected clock (epoch ms), for tests.
    pub fn with_clock(now: Clock) -> Self {
        MemoryWebhookStore { seen: Mutex::new(HashMap::new()), now }
    }
}

impl Default for MemoryWebhookStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookDedupeStore for MemoryWebhookStore {
    fn set_if_absent(&self, key: &str, ttl_seconds: u64) -> Result<bool, StoreError> {
        let now = (self.now)();
        let mut seen = self.seen.lock().map_err(|_| StoreError("lock poisoned".into()))?;
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(key) {
            return Ok(false);
        }
        seen.insert(key.to_string(), now + ttl_seconds * 1000);
        Ok(true)
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.seen.lock().map_err(|_| StoreError("lock poisoned".into()))?.remove(key);
        Ok(())
    }
}

/// Why a delivery was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum DedupeError {
    /// The delivery does not verify (answer 400 / 401).
    #[error(transparent)]
    Verification(#[from] WebhookError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A verified delivery and whether it was already seen.
#[derive(Debug, Clone, PartialEq)]
pub struct DedupedDelivery {
    pub event: Event,
    /// True when this `atlas-id` was already seen: acknowledge with 2xx and do nothing.
    pub duplicate: bool,
    /// The signed `atlas-id`, identical on every retry of one event.
    pub delivery_id: String,
    key: String,
}

/// A verifier plus the store that remembers delivery ids.
pub struct WebhookDeduper {
    webhook: Webhook,
    store: Arc<dyn WebhookDedupeStore>,
    ttl_seconds: u64,
    key_prefix: String,
}

impl WebhookDeduper {
    /// Remember ids for 24 hours (keep it longer than your endpoint's retry window) under `atlas-webhook:`.
    pub fn new(webhook: Webhook, store: Arc<dyn WebhookDedupeStore>) -> Self {
        WebhookDeduper { webhook, store, ttl_seconds: 86_400, key_prefix: "atlas-webhook:".into() }
    }

    pub fn ttl_seconds(mut self, ttl: u64) -> Self {
        self.ttl_seconds = ttl;
        self
    }

    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Verify the RAW body and headers, then claim the delivery id.
    pub fn verify_and_dedupe<H: WebhookHeaders + ?Sized>(&self, raw: &[u8], headers: &H) -> Result<DedupedDelivery, DedupeError> {
        let d = self.webhook.verify_delivery(raw, headers)?;
        let key = format!("{}{}", self.key_prefix, d.delivery_id);
        let fresh = self.store.set_if_absent(&key, self.ttl_seconds)?;
        Ok(DedupedDelivery { event: d.event, duplicate: !fresh, delivery_id: d.delivery_id, key })
    }

    /// Forget this delivery (when the store supports `delete`) so Atlas's retry is processed, for example after
    /// your handler failed.
    pub fn release(&self, delivery: &DedupedDelivery) -> Result<(), StoreError> {
        self.store.delete(&delivery.key)
    }
}
