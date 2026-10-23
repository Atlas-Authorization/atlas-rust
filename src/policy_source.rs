//! Atlas policy source protocol v1: the helpers for the system that SERVES an
//! instance's policy documents (a CMS, a docs platform, your own service).
//!
//! * Atlas to you: `GET {endpoint_url}/policies` (the full feed) or
//!   `GET {endpoint_url}/policies?key=<key>` (one policy, after your event),
//!   signed with the source's signing secret: `atlas-id`, `atlas-timestamp`
//!   (epoch milliseconds) and `atlas-signature: v1,<base64 HMAC-SHA256>` over
//!   `{atlas-id}.{atlas-timestamp}.GET\n{path+query}`. Verify it with
//!   [`verify_policy_feed_request`], then answer
//!   `{"object":"policy_list","policies":[...]}` (at most 512 KB per version).
//! * You to Atlas: `POST {webhook_url}` (from `policy_source`), an event signed
//!   with the same secret: [`sign_policy_source_event`] (Atlas-style headers) or
//!   any Standard Webhooks library. Atlas then re-fetches that policy; it never
//!   stores content from the event.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

/// The protocol version sent in the `atlas-policies-version` header.
pub const POLICY_SOURCE_PROTOCOL_VERSION: &str = "2026-10-24";
/// The header carrying the protocol version.
pub const POLICY_SOURCE_VERSION_HEADER: &str = "atlas-policies-version";
/// The accepted clock difference, in milliseconds (5 minutes).
pub const POLICY_SOURCE_TOLERANCE_MS: i64 = 5 * 60_000;

/// Why a policy feed request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFeedFailure {
    MissingHeaders,
    MalformedSignature,
    StaleTimestamp,
    SignatureMismatch,
    WrongMethod,
}

/// A verified feed request: `key` is the `key` query parameter (`None` for the
/// full feed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPolicyFeedRequest {
    pub delivery_id: String,
    pub timestamp: i64,
    pub key: Option<String>,
    pub protocol_version: Option<String>,
}

/// What to verify: the request as received.
pub struct PolicyFeedRequest<'a> {
    /// The HTTP method (compared case-insensitively to `GET`); `None` skips the check.
    pub method: Option<&'a str>,
    /// The path AND query exactly as received (for example `/atlas/policies?key=tos`).
    pub path_and_query: &'a str,
    /// Looks a header up by lower-case name.
    pub header: &'a dyn Fn(&str) -> Option<String>,
    /// The source's signing secret.
    pub secret: &'a str,
    /// The current time in epoch milliseconds; `None` uses the system clock.
    pub now_ms: Option<i64>,
    /// The accepted clock difference; `None` is 5 minutes.
    pub tolerance_ms: Option<i64>,
}

/// An event for `POST {webhook_url}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySourceEvent {
    /// A version was published; Atlas re-fetches `GET {endpoint}/policies?key=<key>`.
    Published { key: String, version: String },
    /// A policy was retired (its history is kept).
    Retired { key: String },
}

/// A signed event: POST `body` byte-for-byte with `headers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPolicyEvent {
    pub body: String,
    /// `atlas-id`, `atlas-timestamp`, `atlas-signature`.
    pub headers: Vec<(String, String)>,
}

fn mac_for(secret: &str, id: &str, timestamp: &str, payload: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    mac
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Verify Atlas's signed GET of your feed.
///
/// Several `v1,` values are accepted (any one matching passes); other versions
/// are ignored. Every candidate is compared in constant time.
pub fn verify_policy_feed_request(req: &PolicyFeedRequest<'_>) -> Result<VerifiedPolicyFeedRequest, PolicyFeedFailure> {
    if let Some(m) = req.method {
        if !m.eq_ignore_ascii_case("GET") {
            return Err(PolicyFeedFailure::WrongMethod);
        }
    }
    let id = (req.header)("atlas-id").filter(|s| !s.is_empty());
    let ts = (req.header)("atlas-timestamp").filter(|s| !s.is_empty());
    let sig = (req.header)("atlas-signature").filter(|s| !s.is_empty());
    let (Some(id), Some(ts), Some(sig)) = (id, ts, sig) else {
        return Err(PolicyFeedFailure::MissingHeaders);
    };
    let provided: Vec<Vec<u8>> = sig
        .split_whitespace()
        .filter_map(|e| e.strip_prefix("v1,"))
        .map(|b| STANDARD.decode(b).unwrap_or_default())
        .collect();
    if provided.is_empty() {
        return Err(PolicyFeedFailure::MalformedSignature);
    }
    let timestamp: i64 = ts.trim().parse().map_err(|_| PolicyFeedFailure::StaleTimestamp)?;
    let now = req.now_ms.unwrap_or_else(now_ms);
    if (now - timestamp).abs() > req.tolerance_ms.unwrap_or(POLICY_SOURCE_TOLERANCE_MS) {
        return Err(PolicyFeedFailure::StaleTimestamp);
    }
    let mac = mac_for(req.secret, &id, &ts, &format!("GET\n{}", req.path_and_query));
    let mut ok = false;
    for p in &provided {
        // verify_slice is constant time; evaluate every candidate.
        ok |= mac.clone().verify_slice(p).is_ok();
    }
    if !ok {
        return Err(PolicyFeedFailure::SignatureMismatch);
    }
    Ok(VerifiedPolicyFeedRequest {
        delivery_id: id,
        timestamp,
        key: query_param(req.path_and_query, "key"),
        protocol_version: (req.header)(POLICY_SOURCE_VERSION_HEADER),
    })
}

/// Sign an event for `POST {webhook_url}` (Atlas-style headers) with a fresh
/// `evt_<random>` id and the current time.
pub fn sign_policy_source_event(event: &PolicySourceEvent, secret: &str) -> SignedPolicyEvent {
    sign_policy_source_event_at(event, secret, None, None)
}

/// [`sign_policy_source_event`] with an explicit `atlas-id` and/or timestamp (epoch ms).
pub fn sign_policy_source_event_at(
    event: &PolicySourceEvent,
    secret: &str,
    id: Option<&str>,
    timestamp_ms: Option<i64>,
) -> SignedPolicyEvent {
    let ts = timestamp_ms.unwrap_or_else(now_ms);
    let occurred_at = iso8601_ms(now_ms());
    let json = |s: &str| serde_json::to_string(s).expect("a string always serializes");
    let body = match event {
        PolicySourceEvent::Published { key, version } => format!(
            "{{\"occurred_at\":{},\"type\":\"policy.published\",\"key\":{},\"version\":{}}}",
            json(&occurred_at),
            json(key),
            json(version)
        ),
        PolicySourceEvent::Retired { key } => format!(
            "{{\"occurred_at\":{},\"type\":\"policy.retired\",\"key\":{}}}",
            json(&occurred_at),
            json(key)
        ),
    };
    sign_policy_source_body(&body, secret, id, Some(ts))
}

/// Sign an already serialised JSON body.
pub fn sign_policy_source_body(body: &str, secret: &str, id: Option<&str>, timestamp_ms: Option<i64>) -> SignedPolicyEvent {
    let id = match id {
        Some(i) => i.to_string(),
        None => {
            let mut raw = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut raw);
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            format!("evt_{hex}")
        }
    };
    let ts = timestamp_ms.unwrap_or_else(now_ms).to_string();
    let sig = STANDARD.encode(mac_for(secret, &id, &ts, body).finalize().into_bytes());
    SignedPolicyEvent {
        body: body.to_string(),
        headers: vec![
            ("atlas-id".to_string(), id),
            ("atlas-timestamp".to_string(), ts),
            ("atlas-signature".to_string(), format!("v1,{sig}")),
        ],
    }
}

fn query_param(path_and_query: &str, name: &str) -> Option<String> {
    let (_, query) = path_and_query.split_once('?')?;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k) == name {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `2026-10-24T00:00:00.000Z` from epoch milliseconds (proleptic Gregorian, UTC).
fn iso8601_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Vectors shared with the TypeScript reference (packages/backend policy-source).
    const SECRET: &str = "whsec_test_secret_0123456789";
    const TS: i64 = 1_760_000_000_000;
    const SIG_KEY: &str = "YfnQOCSMi2qm50WuVdA/aIV4avYpC6Hms9wdKrZcgHI=";
    const SIG_FULL: &str = "KT51ui3s0XNh9yr/2FedfQgVWCpYAMLQRKOvohc9VTM=";
    const SIG_EVENT: &str = "1q9qbfr02vQN6Xwsj0NjzR65jJiWo39qg8+JutS9ebs=";

    fn verify(method: &str, path: &str, id: Option<&str>, sig: Option<&str>, secret: &str, now: i64) -> Result<VerifiedPolicyFeedRequest, PolicyFeedFailure> {
        let mut h: HashMap<String, String> = HashMap::new();
        if let Some(i) = id {
            h.insert("atlas-id".into(), i.into());
        }
        h.insert("atlas-timestamp".into(), TS.to_string());
        if let Some(s) = sig {
            h.insert("atlas-signature".into(), s.into());
        }
        h.insert("atlas-policies-version".into(), "2026-10-24".into());
        let lookup = move |n: &str| h.get(n).cloned();
        verify_policy_feed_request(&PolicyFeedRequest {
            method: Some(method),
            path_and_query: path,
            header: &lookup,
            secret,
            now_ms: Some(now),
            tolerance_ms: None,
        })
    }

    #[test]
    fn verifies_against_the_reference_vectors() {
        let r = verify("GET", "/atlas/policies?key=tos", Some("msg_01"), Some(&format!("v1,{SIG_KEY}")), SECRET, TS + 1000).unwrap();
        assert_eq!(r.key.as_deref(), Some("tos"));
        assert_eq!(r.delivery_id, "msg_01");
        assert_eq!(r.protocol_version.as_deref(), Some("2026-10-24"));
        let full = verify("get", "/atlas/policies", Some("msg_01"), Some(&format!("v1,{SIG_FULL}")), SECRET, TS).unwrap();
        assert_eq!(full.key, None);
    }

    #[test]
    fn accepts_any_of_several_v1_values() {
        let sig = format!("v1,AAAA v2,zzzz v1,{SIG_KEY}");
        assert!(verify("GET", "/atlas/policies?key=tos", Some("msg_01"), Some(&sig), SECRET, TS).is_ok());
    }

    #[test]
    fn refuses_bad_requests() {
        let good = format!("v1,{SIG_KEY}");
        assert_eq!(verify("GET", "/atlas/policies?key=other", Some("msg_01"), Some(&good), SECRET, TS).unwrap_err(), PolicyFeedFailure::SignatureMismatch);
        assert_eq!(verify("GET", "/atlas/policies?key=tos", Some("msg_01"), Some(&good), "wrong", TS).unwrap_err(), PolicyFeedFailure::SignatureMismatch);
        assert_eq!(verify("GET", "/atlas/policies?key=tos", Some("msg_01"), Some(&good), SECRET, TS + 300_001).unwrap_err(), PolicyFeedFailure::StaleTimestamp);
        assert!(verify("GET", "/atlas/policies?key=tos", Some("msg_01"), Some(&good), SECRET, TS + 300_000).is_ok());
        assert_eq!(verify("GET", "/x", None, Some("v1,AA"), SECRET, TS).unwrap_err(), PolicyFeedFailure::MissingHeaders);
        assert_eq!(verify("GET", "/x", Some("a"), Some("v2,AA"), SECRET, TS).unwrap_err(), PolicyFeedFailure::MalformedSignature);
        assert_eq!(verify("POST", "/x", Some("a"), Some("v1,AA"), SECRET, TS).unwrap_err(), PolicyFeedFailure::WrongMethod);
    }

    #[test]
    fn signs_like_the_reference() {
        let body = "{\"occurred_at\":\"2026-10-24T00:00:00.000Z\",\"type\":\"policy.published\",\"key\":\"tos\",\"version\":\"2026-10-24\"}";
        let signed = sign_policy_source_body(body, SECRET, Some("evt_1"), Some(TS));
        assert_eq!(signed.body, body);
        let header = |n: &str| signed.headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(header("atlas-signature"), format!("v1,{SIG_EVENT}"));
        assert_eq!(header("atlas-id"), "evt_1");
        assert_eq!(header("atlas-timestamp"), TS.to_string());
    }

    #[test]
    fn built_events_carry_their_fields() {
        let p = sign_policy_source_event(&PolicySourceEvent::Published { key: "tos".into(), version: "2026-10-24".into() }, SECRET);
        let v: serde_json::Value = serde_json::from_str(&p.body).unwrap();
        assert_eq!(v["type"], "policy.published");
        assert_eq!(v["version"], "2026-10-24");
        assert!(v["occurred_at"].as_str().unwrap().ends_with('Z'));
        assert!(p.headers.iter().any(|(k, v)| k == "atlas-id" && v.starts_with("evt_")));
        let r = sign_policy_source_event(&PolicySourceEvent::Retired { key: "tos".into() }, SECRET);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["type"], "policy.retired");
        assert!(v.get("version").is_none());
    }

    #[test]
    fn formats_iso_timestamps() {
        assert_eq!(iso8601_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_ms(1_760_000_000_123), "2025-10-09T08:53:20.123Z");
        assert_eq!(iso8601_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn decodes_the_key_parameter() {
        assert_eq!(query_param("/p?key=a%20b&x=1", "key").as_deref(), Some("a b"));
        assert_eq!(query_param("/p?x=1", "key"), None);
        assert_eq!(query_param("/p", "key"), None);
    }
}
