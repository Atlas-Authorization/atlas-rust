//! A tiny injectable clock, used for JWKS-cache TTL/throttle timing and the
//! API-key cache TTLs. Both caches reason in epoch milliseconds. The default
//! reads the system clock; tests inject a controllable one so the rate-limit and
//! TTL behaviour can be asserted deterministically without sleeping.
//!
//! Note this clock governs *caching* only. Session-JWT `exp`/`nbf` validation is
//! done by `jsonwebtoken` against the real system clock and is unaffected by it.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of "now", in epoch milliseconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The default clock: the real system time, in epoch milliseconds.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}
