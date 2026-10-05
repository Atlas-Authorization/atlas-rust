//! JWKS fetch + in-process cache.
//!
//! §7.3: "JWKS cached in-process with kid-miss refetch (max 1/min) so key
//! rotation needs no deploys."
//!
//! The rate limit on the refetch is the security property, not a politeness.
//! Without it, an attacker sends tokens carrying random `kid` values and every
//! one forces an outbound request to the customer's JWKS endpoint — turning any
//! unauthenticated caller into a traffic amplifier aimed at Atlas, from inside
//! the customer's own infrastructure. The cache's job is as much to refuse to
//! fetch as it is to fetch.
//!
//! A stale JWKS still verifies every token signed by a key it contains, so the
//! cache degrades to "new keys do not work yet", never "nobody can authenticate".
//! This mirrors `jwks-cache.ts`, `atlas-go`'s `JWKSCache`, and the Ruby
//! `Atlas::JwksCache` exactly.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::clock::{system_clock, Clock};
use crate::error::TransportError;

/// §7.3: at most one refetch per minute, however many kid-misses arrive.
pub const REFETCH_INTERVAL_MS: u64 = 60_000;

/// §7.3 serves `Cache-Control: max-age=3600`; honoured rather than ignored.
pub const DEFAULT_TTL_MS: u64 = 3_600_000;

/// A boxed future, so the [`JwksSource`] trait stays object-safe without pulling
/// in `async-trait` (keeps the dependency set minimal).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One key in a JWKS document. Unknown members are ignored. `n`/`e` are the
/// base64url-encoded RSA modulus and exponent, passed verbatim to
/// `jsonwebtoken`'s `DecodingKey::from_rsa_components`.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub kty: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    fn has_kid(&self, kid: Option<&str>) -> bool {
        match kid {
            None => !self.keys.is_empty(),
            Some(kid) => self.keys.iter().any(|k| k.kid.as_deref() == Some(kid)),
        }
    }
}

/// The last JWKS-cache action, exposed so a caller (or a test) can assert the
/// rate limit actually bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    Fresh,
    Cached,
    Refetched,
    Throttled,
    Failed,
}

/// Something that can fetch (and parse) a JWKS from a URL. Implemented by the
/// built-in reqwest transport (behind the `reqwest-transport` feature) and by
/// any custom/mock transport a caller supplies.
pub trait JwksSource: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>>;
}

struct CacheState {
    cached: Option<Jwks>,
    fetched_at: u64,
    last_attempt_at: u64,
    last_outcome: FetchOutcome,
}

enum Decision {
    Cached,
    Throttled,
    Fetch { kid_miss: bool },
}

/// The in-process JWKS cache. Either serves a fixed `static_jwks` (fully offline
/// — the hermetic path a customer's CI uses) or fetches from `url` through a
/// [`JwksSource`], caching with a TTL and a throttled kid-miss refetch.
pub struct JwksCache {
    url: Option<String>,
    static_jwks: Option<Jwks>,
    source: Option<Arc<dyn JwksSource>>,
    now: Clock,
    ttl_ms: u64,
    refetch_interval_ms: u64,
    state: Mutex<CacheState>,
}

impl JwksCache {
    pub(crate) fn new(
        url: Option<String>,
        static_jwks: Option<Jwks>,
        source: Option<Arc<dyn JwksSource>>,
        now: Option<Clock>,
        ttl_ms: Option<u64>,
        refetch_interval_ms: Option<u64>,
    ) -> Self {
        JwksCache {
            url,
            static_jwks,
            source,
            now: now.unwrap_or_else(system_clock),
            ttl_ms: ttl_ms.unwrap_or(DEFAULT_TTL_MS),
            refetch_interval_ms: refetch_interval_ms.unwrap_or(REFETCH_INTERVAL_MS),
            state: Mutex::new(CacheState {
                cached: None,
                fetched_at: 0,
                last_attempt_at: 0,
                last_outcome: FetchOutcome::Fresh,
            }),
        }
    }

    /// The last cache action. Diagnostic surface — never used for a security
    /// decision.
    pub fn last_outcome(&self) -> FetchOutcome {
        self.state.lock().unwrap().last_outcome
    }

    /// `(number_of_cached_keys, fetched_at_ms)`. Test/diagnostic only.
    pub fn snapshot(&self) -> (usize, u64) {
        let st = self.state.lock().unwrap();
        (
            st.cached.as_ref().map(|j| j.keys.len()).unwrap_or(0),
            st.fetched_at,
        )
    }

    fn set_outcome(&self, outcome: FetchOutcome) {
        self.state.lock().unwrap().last_outcome = outcome;
    }

    /// The JWKS to verify against, refetching if this `kid` is unknown.
    ///
    /// Returns whatever is cached when a refetch is throttled or fails. That is
    /// deliberate: a stale JWKS still verifies every token signed by a key it
    /// contains, so degrading to "the keys I already had" keeps the overwhelming
    /// majority of requests working through a JWKS outage. Only tokens signed by
    /// a brand-new key fail, and those are a minute old at most.
    pub async fn get(&self, kid: Option<&str>) -> Option<Jwks> {
        // The static path makes verification hermetic: nothing to fetch,
        // refetch or throttle, so every `get` — hit or kid-miss — is answered
        // from the set with no outbound request.
        if let Some(s) = &self.static_jwks {
            self.set_outcome(FetchOutcome::Cached);
            return Some(s.clone());
        }

        let url = match &self.url {
            Some(u) => u.clone(),
            None => {
                // Neither a URL nor a static set: nothing to verify against.
                self.set_outcome(FetchOutcome::Failed);
                return None;
            }
        };

        let now = (self.now)();

        // Decide under the lock, then release it before any await — a std Mutex
        // guard must not be held across an await point.
        let (decision, cached_before) = {
            let mut st = self.state.lock().unwrap();
            let expired = st.cached.is_none() || now.saturating_sub(st.fetched_at) >= self.ttl_ms;
            let kid_miss = st.cached.as_ref().map(|c| !c.has_kid(kid)).unwrap_or(false);

            let decision = if !expired && !kid_miss {
                Decision::Cached
            } else if kid_miss
                && !expired
                && now.saturating_sub(st.last_attempt_at) < self.refetch_interval_ms
            {
                // The throttle: a kid-miss inside the window is answered from
                // cache, and the token simply fails to verify.
                Decision::Throttled
            } else {
                st.last_attempt_at = now;
                Decision::Fetch { kid_miss }
            };
            (decision, st.cached.clone())
        };

        match decision {
            Decision::Cached => {
                self.set_outcome(FetchOutcome::Cached);
                cached_before
            }
            Decision::Throttled => {
                self.set_outcome(FetchOutcome::Throttled);
                cached_before
            }
            Decision::Fetch { kid_miss } => {
                let source = match &self.source {
                    Some(s) => s.clone(),
                    None => {
                        self.set_outcome(FetchOutcome::Failed);
                        return cached_before;
                    }
                };
                match source.fetch(&url).await {
                    Ok(fetched) => {
                        let mut st = self.state.lock().unwrap();
                        st.cached = Some(fetched.clone());
                        st.fetched_at = now;
                        st.last_outcome = if kid_miss {
                            FetchOutcome::Refetched
                        } else {
                            FetchOutcome::Fresh
                        };
                        Some(fetched)
                    }
                    Err(_) => {
                        // Keep serving what we have. A JWKS outage should degrade
                        // to "new keys do not work yet", not "nobody can auth".
                        self.set_outcome(FetchOutcome::Failed);
                        cached_before
                    }
                }
            }
        }
    }
}
