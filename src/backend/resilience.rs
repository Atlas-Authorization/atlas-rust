//! Status-aware retry policy for the management client.
//!
//! A 5xx or 429 is transient and retried within the client's retry budget (see
//! [`BackendClientBuilder::max_retries`](super::BackendClientBuilder::max_retries)). [`ResilienceConfig`]
//! decides HOW LONG to wait and whether to try at all:
//!
//! * `Retry-After` on a 429 or 503 is honoured (delta-seconds or an HTTP date), up to
//!   [`max_retry_after_ms`](ResilienceConfig::max_retry_after_ms); a longer wait is not retried inline, the
//!   error is returned so the caller can schedule it.
//! * Without that header the backoff is exponential with equal jitter (half to full delay), so a fleet of
//!   clients does not retry in lock step.
//! * With [`status_aware`](ResilienceConfig::status_aware), a 5xx first reads the public status endpoint
//!   (`GET /v1/status`, cached for [`status_cache_ms`](ResilienceConfig::status_cache_ms)): during a declared
//!   `major_outage` the call fails fast instead of burning its retries, and during `degraded` the backoff
//!   doubles. The status read is best-effort: if it fails, the normal backoff applies.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;

/// What the status endpoint advises for a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusAdvice {
    Normal,
    Degraded,
    FailFast,
}

/// The retry policy of a [`BackendClient`](super::BackendClient).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResilienceConfig {
    /// Honour `Retry-After` on 429 and 503. Default `true`.
    pub honour_retry_after: bool,
    /// The longest `Retry-After` (ms) waited for inline. Default 60000.
    pub max_retry_after_ms: u64,
    /// Equal jitter on the exponential backoff. Default `true`.
    pub jitter: bool,
    /// Read the status endpoint before retrying a 5xx. Default `false`.
    pub status_aware: bool,
    /// How long a status read is reused. Default 30000.
    pub status_cache_ms: u64,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        ResilienceConfig { honour_retry_after: true, max_retry_after_ms: 60_000, jitter: true, status_aware: false, status_cache_ms: 30_000 }
    }
}

/// One cached status read, shared by every clone of a client.
#[derive(Default)]
pub(crate) struct StatusCache(pub(crate) Mutex<Option<(StatusAdvice, u64)>>);

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl StatusCache {
    pub(crate) fn get(&self, ttl_ms: u64) -> Option<StatusAdvice> {
        let g = self.0.lock().unwrap();
        g.filter(|(_, at)| now_ms().saturating_sub(*at) < ttl_ms).map(|(a, _)| a)
    }
    pub(crate) fn set(&self, advice: StatusAdvice) {
        *self.0.lock().unwrap() = Some((advice, now_ms()));
    }
}

/// The advice for a `GET /v1/status` body.
pub(crate) fn advice_from_status(body: &str) -> StatusAdvice {
    match serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get("status").and_then(|s| s.as_str().map(str::to_string))).as_deref() {
        Some("major_outage") => StatusAdvice::FailFast,
        Some("degraded") => StatusAdvice::Degraded,
        _ => StatusAdvice::Normal,
    }
}

/// Exponential backoff for `attempt` (0-based), with equal jitter when asked.
pub(crate) fn backoff_ms(base_ms: u64, attempt: u32, jitter: bool) -> u64 {
    let d = base_ms.saturating_mul(1u64 << attempt.min(16));
    if jitter && d > 1 {
        rand::thread_rng().gen_range(d / 2..=d)
    } else {
        d
    }
}

/// `Retry-After` as milliseconds: delta-seconds (fractions allowed) or an HTTP date, relative to `now_ms`.
pub(crate) fn parse_retry_after(value: &str, now_ms: u64) -> Option<u64> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<f64>() {
        return (secs.is_finite() && secs >= 0.0).then(|| (secs * 1000.0) as u64);
    }
    let at = parse_http_date(v)?;
    Some((at.saturating_mul(1000) as u64).saturating_sub(now_ms))
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) as epoch seconds.
pub(crate) fn parse_http_date(value: &str) -> Option<i64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [_, day, mon, year, time, tz] = parts.as_slice() else { return None };
    if !tz.eq_ignore_ascii_case("GMT") {
        return None;
    }
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|m| m.eq_ignore_ascii_case(mon))? as i64 + 1;
    let (d, y): (i64, i64) = (day.parse().ok()?, year.parse().ok()?);
    let mut t = time.split(':');
    let (h, mi, s): (i64, i64, i64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    if !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// Shared state a client needs for the policy.
#[derive(Clone, Default)]
pub(crate) struct ResilienceState {
    pub(crate) config: ResilienceConfig,
    pub(crate) status: Arc<StatusCache>,
}

/// An HTTP date header as epoch seconds (for the doctor's clock check).
pub(crate) fn http_date_to_epoch(value: &str) -> Option<i64> {
    parse_http_date(value)
}

pub(crate) fn local_now_seconds() -> i64 {
    (now_ms() / 1000) as i64
}
