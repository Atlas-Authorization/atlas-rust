//! DPoP proof verification (RFC 9449) for
//! [`AtlasBackend::verify_access_token_request`](crate::AtlasBackend::verify_access_token_request).
//!
//! A DPoP-bound access token carries `cnf.jkt`, the RFC 7638 thumbprint of the
//! client's key. Each request must then arrive with the `DPoP` scheme and a
//! `DPoP` header: a short-lived JWT (`typ` `dpop+jwt`) signed by that key,
//! carrying the public key itself, the request method (`htm`) and URL (`htu`),
//! the hash of the access token (`ath`), a unique `jti`, and the server's nonce
//! when the API asks for one.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::clock::Clock;

/// How old a DPoP proof may be.
pub const DPOP_PROOF_MAX_AGE_SECONDS: u64 = 300;
/// Clock skew tolerated on a proof's `iat`.
pub const DPOP_CLOCK_SKEW_SECONDS: u64 = 5;
/// The JWS algorithms accepted on a DPoP proof (and advertised in challenges and
/// metadata). ES512 is not offered: the signature backend has no P-521.
pub const DPOP_ALGS: [&str; 9] = ["ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"];

const PRIVATE_MEMBERS: [&str; 7] = ["d", "k", "p", "q", "dp", "dq", "qi"];

/// Guards against a DPoP proof being used twice. Back it with something every
/// instance of your API shares (Redis `SET key 1 NX PX ttl`, a unique database
/// key) when it runs on more than one; [`MemoryDpopReplayStore`] protects a
/// single process.
pub trait DpopReplayStore: Send + Sync {
    /// Record `key` until `expires_at_ms` (epoch milliseconds). `true` the first
    /// time it is seen, `false` when it was already recorded and has not expired.
    fn claim(&self, key: &str, expires_at_ms: u64) -> bool;
}

/// The in-process [`DpopReplayStore`]: entries live until they expire, at most
/// `max_entries` of them.
pub struct MemoryDpopReplayStore {
    max: usize,
    clock: Clock,
    seen: Mutex<HashMap<String, u64>>,
}

impl MemoryDpopReplayStore {
    /// A store holding at most `max_entries` live entries (10 000 when 0).
    pub fn new(max_entries: usize) -> Self {
        Self::with_clock(max_entries, crate::clock::system_clock())
    }

    /// As [`MemoryDpopReplayStore::new`] with a clock returning epoch ms (tests).
    pub fn with_clock(max_entries: usize, clock: Clock) -> Self {
        MemoryDpopReplayStore {
            max: if max_entries == 0 { 10_000 } else { max_entries },
            clock,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// How many entries are held.
    pub fn len(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DpopReplayStore for MemoryDpopReplayStore {
    fn claim(&self, key: &str, expires_at_ms: u64) -> bool {
        let now = (self.clock)();
        let mut seen = match self.seen.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        if seen.get(key).map(|&exp| exp > now).unwrap_or(false) {
            return false;
        }
        seen.insert(key.to_owned(), expires_at_ms);
        if seen.len() > self.max {
            seen.retain(|_, exp| *exp > now);
            while seen.len() > self.max {
                let oldest = seen.iter().filter(|(k, _)| k.as_str() != key).min_by_key(|(_, exp)| **exp).map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => {
                        seen.remove(&k);
                    }
                    None => break,
                }
            }
        }
        true
    }
}

/// The process-wide default replay store, used when the options name none.
pub(crate) fn default_replay_store() -> Arc<dyn DpopReplayStore> {
    static STORE: OnceLock<Arc<MemoryDpopReplayStore>> = OnceLock::new();
    STORE.get_or_init(|| Arc::new(MemoryDpopReplayStore::new(10_000))).clone()
}

/// Hands out the server nonce a DPoP proof must carry (RFC 9449 §8) and checks
/// one. [`current`](DpopNonceSource::current) goes to the client in the
/// `DPoP-Nonce` header; [`valid`](DpopNonceSource::valid) accepts the nonces
/// still in force.
pub trait DpopNonceSource: Send + Sync {
    fn current(&self) -> String;
    fn valid(&self, nonce: &str) -> bool;
}

/// DPoP nonces derived from a secret and the clock: a nonce is good for the
/// window it was issued in and the next one, so every instance sharing the
/// secret agrees without shared state.
pub struct HmacDpopNonceSource {
    secret: Vec<u8>,
    window_ms: u64,
    clock: Clock,
}

impl HmacDpopNonceSource {
    /// `secret` must be at least 32 bytes; `window_seconds` 0 means 300.
    pub fn new(secret: &[u8], window_seconds: u64) -> Result<Self, &'static str> {
        Self::with_clock(secret, window_seconds, crate::clock::system_clock())
    }

    /// As [`HmacDpopNonceSource::new`] with a clock returning epoch ms (tests).
    pub fn with_clock(secret: &[u8], window_seconds: u64, clock: Clock) -> Result<Self, &'static str> {
        if secret.len() < 32 {
            return Err("The DPoP nonce secret must be at least 32 bytes.");
        }
        let window = if window_seconds == 0 { 300 } else { window_seconds };
        Ok(HmacDpopNonceSource { secret: secret.to_vec(), window_ms: window * 1000, clock })
    }

    fn at(&self, epoch: u64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC takes any key length");
        mac.update(b"atlas-dpop-nonce:");
        mac.update(&epoch.to_be_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn epoch(&self) -> u64 {
        (self.clock)() / self.window_ms
    }
}

impl DpopNonceSource for HmacDpopNonceSource {
    fn current(&self) -> String {
        self.at(self.epoch())
    }

    fn valid(&self, nonce: &str) -> bool {
        let e = self.epoch();
        let candidates = [Some(self.at(e)), e.checked_sub(1).map(|p| self.at(p))];
        candidates.iter().flatten().any(|c| constant_eq(c.as_bytes(), nonce.as_bytes()))
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The `ath` a DPoP proof carries for `token`: base64url(SHA-256(token)).
pub fn dpop_access_token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// The RFC 7638 SHA-256 thumbprint (base64url) of a public EC, RSA or OKP JWK:
/// the `cnf.jkt` a DPoP-bound token carries. `None` for an unsupported or
/// incomplete key.
pub fn jwk_thumbprint(jwk: &Map<String, Value>) -> Option<String> {
    let members: &[&str] = match jwk.get("kty").and_then(Value::as_str)? {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        _ => return None,
    };
    let mut parts = Vec::with_capacity(members.len());
    for m in members {
        let v = jwk.get(*m).and_then(Value::as_str).filter(|v| !v.is_empty())?;
        parts.push(format!("{}:{}", Value::from(*m), Value::from(v)));
    }
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{{{}}}", parts.join(",")).as_bytes())))
}

/// Reduce a URL to the form RFC 9449 §4.3 compares `htu` in: scheme and host
/// lower-cased, the default port dropped, an empty path as `/`, no query or
/// fragment. `None` for anything but an absolute http(s) URL.
pub fn normalize_htu(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let after = &rest[end..];
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = format!("[{}]", &stripped[..close]);
        let tail = &stripped[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p),
            None if tail.is_empty() => None,
            None => return None,
        };
        (host, port)
    } else {
        match hostport.split_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (hostport.to_owned(), None),
        }
    };
    if host.is_empty() || host.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    let port = match port {
        Some("") | None => None,
        Some(p) => {
            let n: u16 = p.parse().ok()?;
            if (scheme == "https" && n == 443) || (scheme == "http" && n == 80) {
                None
            } else {
                Some(n)
            }
        }
    };
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    let path = if path_end == 0 { "/" } else { &after[..path_end] };
    let host = host.to_ascii_lowercase();
    Some(match port {
        Some(p) => format!("{scheme}://{host}:{p}{path}"),
        None => format!("{scheme}://{host}{path}"),
    })
}

/// A refusal: `error` is `invalid_dpop_proof` or `use_dpop_nonce`.
pub(crate) struct Refusal {
    pub error: &'static str,
    pub description: &'static str,
}

fn bad(description: &'static str) -> Refusal {
    Refusal { error: "invalid_dpop_proof", description }
}

fn json_segment(segment: &str) -> Option<Map<String, Value>> {
    let raw = URL_SAFE_NO_PAD.decode(segment).ok()?;
    serde_json::from_slice::<Map<String, Value>>(&raw).ok()
}

pub(crate) struct ProofContext<'a> {
    pub token: &'a str,
    pub jkt: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub public_origin: Option<&'a str>,
    pub now_ms: u64,
    pub replay: &'a dyn DpopReplayStore,
    pub nonces: Option<&'a dyn DpopNonceSource>,
}

pub(crate) fn check_proof(proof: &str, ctx: &ProofContext<'_>) -> Option<Refusal> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Some(bad("The DPoP proof is malformed."));
    }
    let header = match json_segment(parts[0]) {
        Some(h) => h,
        None => return Some(bad("The DPoP proof is malformed.")),
    };
    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Some(bad("The DPoP proof must have typ dpop+jwt."));
    }
    let alg = match header.get("alg").and_then(Value::as_str) {
        Some(a) if DPOP_ALGS.contains(&a) => a,
        _ => return Some(bad("The DPoP proof uses an unsupported algorithm.")),
    };
    let jwk = match header.get("jwk").and_then(Value::as_object) {
        Some(j) => j,
        None => return Some(bad("The DPoP proof must carry its public key.")),
    };
    if PRIVATE_MEMBERS.iter().any(|m| jwk.contains_key(*m)) {
        return Some(bad("The DPoP proof key must be a public key."));
    }
    if !verify_signature(jwk, alg, &format!("{}.{}", parts[0], parts[1]), parts[2]) {
        return Some(bad("The DPoP proof signature is invalid."));
    }
    let payload = match json_segment(parts[1]) {
        Some(p) => p,
        None => return Some(bad("The DPoP proof is malformed.")),
    };
    match jwk_thumbprint(jwk) {
        Some(t) if constant_eq(t.as_bytes(), ctx.jkt.as_bytes()) => {}
        _ => return Some(bad("The DPoP proof key does not match the token binding.")),
    }
    if payload.get("htm").and_then(Value::as_str) != Some(ctx.method) {
        return Some(bad("The DPoP proof htm does not match the request method."));
    }
    let lower = ctx.url.to_ascii_lowercase();
    let target = if lower.starts_with("http://") || lower.starts_with("https://") {
        Some(ctx.url.to_owned())
    } else {
        match ctx.public_origin {
            Some(origin) if ctx.url.starts_with('/') => Some(format!("{}{}", origin.trim_end_matches('/'), ctx.url)),
            _ => None,
        }
    };
    let expected = target.as_deref().and_then(normalize_htu);
    let got = payload.get("htu").and_then(Value::as_str).and_then(normalize_htu);
    if expected.is_none() || expected != got {
        return Some(bad("The DPoP proof htu does not match the request URL."));
    }
    let now = ctx.now_ms as f64 / 1000.0;
    let iat = match payload.get("iat").and_then(Value::as_f64) {
        Some(i) if i <= now + DPOP_CLOCK_SKEW_SECONDS as f64 && now - i <= DPOP_PROOF_MAX_AGE_SECONDS as f64 => i,
        _ => return Some(bad("The DPoP proof is too old or from the future.")),
    };
    if let Some(exp) = payload.get("exp").and_then(Value::as_f64) {
        if now >= exp + DPOP_CLOCK_SKEW_SECONDS as f64 {
            return Some(bad("The DPoP proof is too old or from the future."));
        }
    }
    if payload.get("ath").and_then(Value::as_str) != Some(dpop_access_token_hash(ctx.token).as_str()) {
        return Some(bad("The DPoP proof ath does not match the access token."));
    }
    let jti = match payload.get("jti").and_then(Value::as_str) {
        Some(j) if !j.is_empty() => j,
        _ => return Some(bad("The DPoP proof needs a jti.")),
    };
    if let Some(nonces) = ctx.nonces {
        let ok = payload.get("nonce").and_then(Value::as_str).map(|n| !n.is_empty() && nonces.valid(n)).unwrap_or(false);
        if !ok {
            return Some(Refusal {
                error: "use_dpop_nonce",
                description: "The DPoP proof must carry the nonce from the DPoP-Nonce header.",
            });
        }
    }
    let expires = (iat.max(0.0) * 1000.0) as u64 + DPOP_PROOF_MAX_AGE_SECONDS * 1000;
    if !ctx.replay.claim(&format!("{}:{}", ctx.jkt, jti), expires) {
        return Some(bad("The DPoP proof has already been used."));
    }
    None
}

fn verify_signature(jwk: &Map<String, Value>, alg: &str, signing_input: &str, signature: &str) -> bool {
    let s = |k: &str| jwk.get(k).and_then(Value::as_str);
    if let Some(ka) = s("alg") {
        if !ka.is_empty() && ka != alg {
            return false;
        }
    }
    let decoded_len = |k: &str| s(k).and_then(|v| URL_SAFE_NO_PAD.decode(v).ok()).map(|b| b.len());
    let key = match alg {
        "ES256" | "ES384" => {
            let (crv, size) = if alg == "ES256" { ("P-256", 32) } else { ("P-384", 48) };
            if s("kty") != Some("EC") || s("crv") != Some(crv) || decoded_len("x") != Some(size) || decoded_len("y") != Some(size) {
                return false;
            }
            DecodingKey::from_ec_components(s("x").unwrap_or(""), s("y").unwrap_or(""))
        }
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            let n_len = s("n").and_then(|v| URL_SAFE_NO_PAD.decode(v).ok()).map(|b| b.iter().skip_while(|&&x| x == 0).count());
            if s("kty") != Some("RSA") || n_len.unwrap_or(0) < 256 || decoded_len("e").map(|l| l == 0 || l > 4).unwrap_or(true) {
                return false;
            }
            DecodingKey::from_rsa_components(s("n").unwrap_or(""), s("e").unwrap_or(""))
        }
        "EdDSA" => {
            if s("kty") != Some("OKP") || s("crv") != Some("Ed25519") || decoded_len("x") != Some(32) {
                return false;
            }
            DecodingKey::from_ed_components(s("x").unwrap_or(""))
        }
        _ => return false,
    };
    let key = match key {
        Ok(k) => k,
        Err(_) => return false,
    };
    let algorithm = match Algorithm::from_str(alg) {
        Ok(a) => a,
        Err(_) => return false,
    };
    if URL_SAFE_NO_PAD.decode(signature).is_err() {
        return false;
    }
    jsonwebtoken::crypto::verify(signature, signing_input.as_bytes(), &key, algorithm).unwrap_or(false)
}
