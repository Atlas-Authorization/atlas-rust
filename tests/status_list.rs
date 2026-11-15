//! The signed session status list: verification and the sid-revocation source that uses it, falling back to
//! the paged feed. The Atlas side is a `FakeTransport`; the signing key is generated at runtime.
#![cfg(feature = "backend")]

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::Jwks;
use atlasauth::mirror::{verify_status_list_token, SidListRevocation, SidRevocationList, StatusListError, StatusListSource};
use atlasauth::{Clock, HttpResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ISS: &str = "https://inst.example";

fn jwks() -> Jwks {
    serde_json::from_value(support::keys().jwks.clone()).unwrap()
}

fn list_claims(sids: &[&str], truncated: bool) -> Value {
    let mut hashes: Vec<Vec<u8>> = sids.iter().map(|s| Sha256::digest(s.as_bytes())[..8].to_vec()).collect();
    hashes.sort();
    let now = support::now_secs();
    json!({ "iss": ISS, "aud": "atlas:session-status-list", "token_use": "session_status_list", "iat": now, "exp": now + 120,
        "since": now - 3600, "hash_bytes": 8, "count": sids.len(), "truncated": truncated, "h": URL_SAFE_NO_PAD.encode(hashes.concat()) })
}

fn token(sids: &[&str], truncated: bool) -> String {
    support::es256(&list_claims(sids, truncated), Some("statuslist+jwt"))
}

fn now_ms() -> i64 {
    support::now_secs() * 1000
}

#[test]
fn a_signed_list_answers_membership() {
    let l = verify_status_list_token(&token(&["sess_a", "sess_b", "sess_c"], false), &jwks(), Some(ISS), now_ms(), 30).unwrap();
    assert_eq!(l.count, 3);
    assert!(l.has("sess_a") && l.has("sess_c"));
    assert!(!l.has("sess_z"));
    assert!(!l.truncated);
}

#[test]
fn a_list_that_does_not_verify_is_refused() {
    let good = token(&["sess_a"], false);
    // Wrong issuer, wrong typ, tampered payload, expired, wrong audience.
    assert_eq!(verify_status_list_token(&good, &jwks(), Some("https://other.example"), now_ms(), 30).unwrap_err(), StatusListError::BadClaims);
    let no_typ = support::es256(&list_claims(&["sess_a"], false), None);
    assert_eq!(verify_status_list_token(&no_typ, &jwks(), Some(ISS), now_ms(), 30).unwrap_err(), StatusListError::Unsupported);
    let mut parts: Vec<&str> = good.split('.').collect();
    let forged = URL_SAFE_NO_PAD.encode(list_claims(&["sess_a", "sess_evil"], false).to_string());
    parts[1] = &forged;
    assert_eq!(verify_status_list_token(&parts.join("."), &jwks(), Some(ISS), now_ms(), 30).unwrap_err(), StatusListError::BadSignature);
    assert_eq!(verify_status_list_token(&good, &jwks(), Some(ISS), now_ms() + 600_000, 30).unwrap_err(), StatusListError::Expired);
    let mut c = list_claims(&["sess_a"], false);
    c["aud"] = json!("someone-else");
    let bad_aud = support::es256(&c, Some("statuslist+jwt"));
    assert_eq!(verify_status_list_token(&bad_aud, &jwks(), Some(ISS), now_ms(), 30).unwrap_err(), StatusListError::BadSignature);
}

fn clock(cell: &Arc<AtomicU64>) -> Clock {
    let c = cell.clone();
    Arc::new(move || c.load(Ordering::SeqCst))
}

fn client(t: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x").transport(Arc::new(t.clone())).max_retries(0).build().unwrap()
}

fn ok(v: Value) -> HttpResponse {
    HttpResponse { status: 200, body: v.to_string() }
}

fn source() -> Arc<StatusListSource> {
    Arc::new(StatusListSource::from_static(jwks(), Some(ISS.into())))
}

#[tokio::test]
async fn the_sid_list_uses_the_signed_list_and_never_touches_the_feed_when_it_is_complete() {
    let t = FakeTransport::new(|req| {
        if req.url.contains("/v1/sessions/revocations/status-list") {
            ok(json!({ "token": token(&["sess_dead"], false) }))
        } else {
            HttpResponse { status: 500, body: "{}".into() }
        }
    });
    let now = Arc::new(AtomicU64::new(now_ms() as u64));
    let opts = SidListRevocation { status_list: Some(source()), ..Default::default() };
    let list = SidRevocationList::with_clock(client(&t), opts, clock(&now));
    assert!(list.is_revoked("sess_dead").await);
    assert!(!list.is_revoked("sess_live").await);
    assert_eq!(t.request_count(), 1);
    assert!(t.requests().iter().all(|r| r.url.contains("status-list")));
}

#[tokio::test]
async fn a_truncated_list_falls_back_to_the_feed_for_a_miss() {
    let t = FakeTransport::new(|req| {
        if req.url.contains("/v1/sessions/revocations/status-list") {
            ok(json!({ "token": token(&["sess_a"], true) }))
        } else if req.url.contains("/v1/sessions/revoked") {
            ok(json!({ "data": [{ "sid": "sess_b", "revoked_at": now_ms() }], "has_more": false, "next_cursor": null, "server_time": now_ms() }))
        } else {
            HttpResponse { status: 404, body: "{}".into() }
        }
    });
    let now = Arc::new(AtomicU64::new(now_ms() as u64));
    let opts = SidListRevocation { status_list: Some(source()), ..Default::default() };
    let list = SidRevocationList::with_clock(client(&t), opts, clock(&now));
    assert!(list.is_revoked("sess_a").await, "named by the list");
    assert!(list.is_revoked("sess_b").await, "not in the truncated list: the feed names it");
    assert!(!list.is_revoked("sess_c").await);
}

#[tokio::test]
async fn an_unverifiable_list_is_ignored_and_the_feed_answers() {
    let t = FakeTransport::new(|req| {
        if req.url.contains("/v1/sessions/revocations/status-list") {
            ok(json!({ "token": "a.b.c" }))
        } else {
            ok(json!({ "data": [{ "sid": "sess_dead", "revoked_at": now_ms() }], "has_more": false, "next_cursor": null, "server_time": now_ms() }))
        }
    });
    let now = Arc::new(AtomicU64::new(now_ms() as u64));
    let opts = SidListRevocation { status_list: Some(source()), ..Default::default() };
    let list = SidRevocationList::with_clock(client(&t), opts, clock(&now));
    assert!(list.is_revoked("sess_dead").await);
    assert!(!list.is_revoked("sess_live").await);
}
