//! A revoked-session list: one poller over `GET /v1/sessions/revoked` (a secret key with `sessions:read`)
//! that keeps an in-memory set of revoked session ids, each remembered until its token cannot be live any
//! more. Reject a session token whose `sid` is listed: the worst-case window is the poll interval plus the
//! token lifetime.
//!
//! Two sources: the paged `feed` (default), or the signed status list (`status_list`, one small signed
//! answer verified against the instance JWKS) that falls back to the feed when it is unavailable, was
//! cut short, or does not verify.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::backend::{BackendClient, BackendError};
use crate::clock::{system_clock, Clock};
use crate::http::HttpMethod;

use super::status_list::{verify_status_list_token, StatusListSource, VerifiedStatusList};

/// What to do when the list cannot be refreshed for longer than `stale_after_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SidStaleAction {
    /// Keep trusting the last list: sign-ins that verify locally keep working through an incident, but a
    /// session revoked during it is not seen until a poll succeeds again.
    #[default]
    Allow,
    /// Fail closed: every token is refused (see [`SidRevocationList::unavailable`]) until a poll succeeds.
    Reject,
}

/// Settings of a [`SidRevocationList`].
#[derive(Clone)]
pub struct SidListRevocation {
    /// How often to poll, in ms. Default 15000.
    pub interval_ms: u64,
    /// Your longest-lived session token, in seconds (Atlas's default is 60). A listed sid is remembered this
    /// long. Default 3600.
    pub max_token_lifetime_seconds: u64,
    pub on_stale: SidStaleAction,
    /// How long without a successful poll counts as stale. Default 120000.
    pub stale_after_ms: u64,
    /// With `Reject`: keep answering from the last list for this many extra ms before failing closed. Default 0.
    pub serve_stale_for_ms: u64,
    /// Called when a check is answered from a stale list still inside `serve_stale_for_ms`, with `(last_success_at, stale_for_ms)`.
    pub on_serve_stale: Option<Arc<dyn Fn(Option<i64>, i64) + Send + Sync>>,
    /// Called when a poll fails. The last list stays in force.
    pub on_error: Option<Arc<dyn Fn(&BackendError) + Send + Sync>>,
    /// Use the signed status list instead of the paged feed (the feed stays the fallback).
    pub status_list: Option<Arc<StatusListSource>>,
}

impl Default for SidListRevocation {
    fn default() -> Self {
        SidListRevocation {
            interval_ms: 15_000,
            max_token_lifetime_seconds: 3600,
            on_stale: SidStaleAction::Allow,
            stale_after_ms: 120_000,
            serve_stale_for_ms: 0,
            on_serve_stale: None,
            on_error: None,
            status_list: None,
        }
    }
}

struct State {
    /// sid -> epoch ms after which the entry can be dropped.
    revoked: HashMap<String, i64>,
    since: Option<i64>,
    next_poll_at: i64,
    last_success_at: Option<i64>,
    list: Option<VerifiedStatusList>,
    list_next_at: i64,
}

/// The poller and the set. Share it behind an `Arc`.
pub struct SidRevocationList {
    opts: SidListRevocation,
    client: BackendClient,
    now: Clock,
    created_at: i64,
    state: Mutex<State>,
    // Serialises polls so concurrent checks share one.
    poll_lock: tokio::sync::Mutex<()>,
}

impl SidRevocationList {
    /// `client` is the management client with a secret key that has `sessions:read`.
    pub fn new(client: BackendClient, opts: SidListRevocation) -> Self {
        Self::with_clock(client, opts, system_clock())
    }

    /// As [`SidRevocationList::new`] with an injected clock (epoch ms), for tests.
    pub fn with_clock(client: BackendClient, opts: SidListRevocation, now: Clock) -> Self {
        let created_at = now() as i64;
        SidRevocationList {
            opts,
            client,
            now,
            created_at,
            state: Mutex::new(State { revoked: HashMap::new(), since: None, next_poll_at: 0, last_success_at: None, list: None, list_next_at: 0 }),
            poll_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn now_ms(&self) -> i64 {
        (self.now)() as i64
    }

    fn lifetime_ms(&self) -> i64 {
        self.opts.max_token_lifetime_seconds as i64 * 1000
    }

    /// True when the list could not be refreshed for `stale_after_ms` and the caller asked to fail closed
    /// (`Reject`). Call it after [`is_revoked`](Self::is_revoked).
    pub fn unavailable(&self) -> bool {
        if self.opts.on_stale != SidStaleAction::Reject {
            return false;
        }
        let last = self.state.lock().unwrap().last_success_at;
        let stale = self.now_ms() - last.unwrap_or(self.created_at) - self.opts.stale_after_ms as i64;
        if stale <= 0 {
            return false;
        }
        // A list that was fetched at least once may be served a little longer; one never fetched may not.
        if last.is_some() && stale <= self.opts.serve_stale_for_ms as i64 {
            if let Some(h) = &self.opts.on_serve_stale {
                h(last, stale);
            }
            return false;
        }
        true
    }

    /// Whether `sid` is in the revoked set, polling first when the interval has passed.
    pub async fn is_revoked(&self, sid: &str) -> bool {
        if let Some(src) = self.opts.status_list.clone() {
            match self.status_verdict(&src, sid).await {
                Some(revoked) => return revoked,
                None => {} // fall back to the feed
            }
        }
        let now = self.now_ms();
        if now >= self.state.lock().unwrap().next_poll_at {
            let _guard = self.poll_lock.lock().await;
            // Another check may have polled while this one waited.
            if self.now_ms() >= self.state.lock().unwrap().next_poll_at {
                self.poll().await;
            }
        }
        self.state.lock().unwrap().revoked.get(sid).is_some_and(|expiry| *expiry > now)
    }

    /// `Some(revoked)` from the signed list, or `None` when the feed must answer (no verified list yet, or the
    /// list was cut short and does not name the session).
    async fn status_verdict(&self, src: &StatusListSource, sid: &str) -> Option<bool> {
        if self.now_ms() >= self.state.lock().unwrap().list_next_at {
            let _guard = self.poll_lock.lock().await;
            if self.now_ms() >= self.state.lock().unwrap().list_next_at {
                self.refresh_list(src).await;
            }
        }
        let st = self.state.lock().unwrap();
        let list = st.list.as_ref()?;
        if list.has(sid) {
            Some(true)
        } else if list.truncated {
            None
        } else {
            Some(false)
        }
    }

    async fn refresh_list(&self, src: &StatusListSource) {
        let started = self.now_ms();
        self.state.lock().unwrap().list_next_at = started + self.opts.interval_ms as i64;
        let window = src.window_seconds.unwrap_or(self.opts.max_token_lifetime_seconds).clamp(60, 86_400);
        let q = vec![("window_seconds", window.to_string())];
        let result: Result<VerifiedStatusList, Option<BackendError>> = async {
            let body = self.client.request_value(HttpMethod::Get, "/v1/sessions/revocations/status-list", &q, None).await.map_err(Some)?;
            let token = body.get("token").and_then(Value::as_str).ok_or(None)?.to_string();
            let kid = jsonwebtoken::decode_header(&token).ok().and_then(|h| h.kid);
            let jwks = src.jwks.get(kid.as_deref()).await.ok_or(None)?;
            verify_status_list_token(&token, &jwks, src.issuer.as_deref(), started, 30).map_err(|_| None)
        }
        .await;
        match result {
            Ok(list) => {
                let mut st = self.state.lock().unwrap();
                st.list = Some(list);
                st.last_success_at = Some(started);
            }
            // A list that does not verify is never used; the last good one (if any) stays, the feed covers the rest.
            Err(e) => {
                if let (Some(e), Some(h)) = (e, &self.opts.on_error) {
                    h(&e);
                }
                let mut st = self.state.lock().unwrap();
                if st.list.as_ref().is_some_and(|l| l.expires_at_ms + 30_000 < started) {
                    st.list = None;
                }
            }
        }
    }

    /// Poll once now, regardless of the interval.
    pub async fn refresh(&self) {
        let _guard = self.poll_lock.lock().await;
        self.poll().await;
    }

    async fn poll(&self) {
        let started = self.now_ms();
        let lifetime = self.lifetime_ms();
        let since = {
            let mut st = self.state.lock().unwrap();
            st.next_poll_at = started + self.opts.interval_ms as i64;
            st.since.unwrap_or(started - lifetime)
        };
        let mut cursor: Option<String> = None;
        let mut server_time = started;
        let mut found: Vec<(String, i64)> = Vec::new();
        loop {
            let mut q: Vec<(&str, String)> = vec![("since", since.to_string()), ("limit", "5000".into())];
            if let Some(c) = &cursor {
                q.push(("cursor", c.clone()));
            }
            let page: Value = match self.client.request_value(HttpMethod::Get, "/v1/sessions/revoked", &q, None).await {
                Ok(p) => p,
                Err(e) => {
                    if let Some(h) = &self.opts.on_error {
                        h(&e);
                    }
                    return;
                }
            };
            for r in page.get("data").and_then(Value::as_array).into_iter().flatten() {
                if let (Some(sid), Some(at)) = (r.get("sid").and_then(Value::as_str), r.get("revoked_at").and_then(Value::as_i64)) {
                    found.push((sid.to_string(), at + lifetime));
                }
            }
            if let Some(t) = page.get("server_time").and_then(Value::as_i64) {
                server_time = t;
            }
            cursor = match (page.get("has_more").and_then(Value::as_bool), page.get("next_cursor").and_then(Value::as_str)) {
                (Some(true), Some(c)) => Some(c.to_string()),
                _ => None,
            };
            if cursor.is_none() {
                break;
            }
        }
        let mut st = self.state.lock().unwrap();
        st.revoked.extend(found);
        // Re-ask from a little before the answer's own clock, so a row committed late is not missed.
        st.since = Some(server_time - 10_000);
        st.last_success_at = Some(started);
        st.revoked.retain(|_, expiry| *expiry > started);
    }
}
