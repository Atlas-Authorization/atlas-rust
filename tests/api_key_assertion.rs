//! Key-pair API key assertions: header, claims, and a signature that verifies with the public key.
#![cfg(feature = "backend")]

use atlasauth::{sign_api_key_assertion, ApiKeyAssertionOptions};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

// Throwaway test vectors generated for these tests only; they protect nothing.
const EC_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghniYXev3KDLEBa2r\n+3iEdilAGxVI8M1GeJHdxkAv3jqhRANCAATkbbEsHEIO2Xwdp0kkxp/ADrEf+uEn\nXXgVQvtgjEmx8b/HrWuPS9y+ZoiAEvjtpQemEtX7sqeh8oNwr/rpo/vQ\n-----END PRIVATE KEY-----\n";
const EC_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5G2xLBxCDtl8HadJJMafwA6xH/rh\nJ114FUL7YIxJsfG/x61rj0vcvmaIgBL47aUHphLV+7KnofKDcK/66aP70A==\n-----END PUBLIC KEY-----\n";
const ED_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA5lQoMJ6NV176fElUJy5cwXZobH8DyEIvldYO96xmsO\n-----END PRIVATE KEY-----\n";
const ED_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAzSonXyAOoCeqBYNturPBX7YYL2Gc/DGkR9UQObI5LWk=\n-----END PUBLIC KEY-----\n";

fn check(jwt: &str, alg: Algorithm, key: DecodingKey) -> Value {
    let header = decode_header(jwt).unwrap();
    assert_eq!(header.alg, alg);
    assert_eq!(header.kid.as_deref(), Some("key_1"));
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    let mut v = Validation::new(alg);
    v.set_audience(&["ins_1"]);
    v.set_required_spec_claims(&["iss", "aud", "exp"]);
    decode::<Value>(jwt, &key, &v).unwrap().claims
}

#[test]
fn es256_is_raw_rs_and_verifies() {
    let opts = ApiKeyAssertionOptions { scope: Some("read".into()), jti: Some("j1".into()), ..Default::default() };
    let jwt = sign_api_key_assertion(EC_PRIVATE, "key_1", "ins_1", &opts).unwrap();
    let claims = check(&jwt, Algorithm::ES256, DecodingKey::from_ec_pem(EC_PUBLIC.as_bytes()).unwrap());
    assert_eq!(claims["iss"], "key_1");
    assert_eq!(claims["scope"], "read");
    assert_eq!(claims["jti"], "j1");
    assert_eq!(claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(), 300);
    let sig = jwt.rsplit('.').next().unwrap();
    assert_eq!(sig.len(), 86); // 64 bytes in unpadded base64url
}

#[test]
fn eddsa_verifies() {
    let opts = ApiKeyAssertionOptions { ttl_seconds: 60, ..Default::default() };
    let jwt = sign_api_key_assertion(ED_PRIVATE, "key_1", "ins_1", &opts).unwrap();
    let claims = check(&jwt, Algorithm::EdDSA, DecodingKey::from_ed_pem(ED_PUBLIC.as_bytes()).unwrap());
    assert_eq!(claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(), 60);
    assert!(!claims["jti"].as_str().unwrap().is_empty());
}

// ── ApiKeyVerifier::verify_assertion ──────────────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use atlasauth::{ApiKeyVerifier, BoxFuture, Clock, HttpPost, HttpResponse, TransportError};
use serde_json::json;

struct Canned {
    calls: AtomicUsize,
    bodies: Mutex<Vec<String>>,
    reply: Value,
}

impl HttpPost for Canned {
    fn post_json<'a>(&'a self, _url: &'a str, _bearer: &'a str, body: String) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bodies.lock().unwrap().push(body);
        let reply = self.reply.to_string();
        Box::pin(async move { Ok(HttpResponse { status: 200, body: reply }) })
    }
}

fn canned(reply: Value) -> Arc<Canned> {
    Arc::new(Canned { calls: AtomicUsize::new(0), bodies: Mutex::new(vec![]), reply })
}

fn fixed_clock(ms: u64) -> Clock {
    Arc::new(move || ms)
}

#[tokio::test]
async fn verify_assertion_sends_token_and_caches_per_assertion_until_exp() {
    let mock = canned(json!({ "valid": true, "id": "key_1", "credential": "key_pair", "exp": 1_000 }));
    let v = ApiKeyVerifier::builder("sk_test").transport(mock.clone()).clock(fixed_clock(500_000)).build().unwrap();
    assert!(v.verify_assertion("t1").await.unwrap().valid);
    assert_eq!(serde_json::from_str::<Value>(&mock.bodies.lock().unwrap()[0]).unwrap(), json!({ "token": "t1" }));
    // the same assertion is served from the cache; another is not
    v.verify_assertion("t1").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    v.verify_assertion("t2").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    // a secret with the same text is a different entry, and is sent as a secret
    v.verify("t1").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
    assert_eq!(serde_json::from_str::<Value>(&mock.bodies.lock().unwrap()[2]).unwrap(), json!({ "secret": "t1" }));
}

#[tokio::test]
async fn verify_assertion_never_caches_past_exp_or_a_single_use_jti() {
    let now = Arc::new(AtomicUsize::new(100_000));
    let c = now.clone();
    let clock: Clock = Arc::new(move || c.load(Ordering::SeqCst) as u64);
    // exp is 100 s out (epoch s 200): the entry must not outlive it even though the positive TTL is 5 minutes
    let mock = canned(json!({ "valid": true, "id": "key_1", "exp": 200 }));
    let v = ApiKeyVerifier::builder("sk_test").transport(mock.clone()).clock(clock).build().unwrap();
    v.verify_assertion("t").await.unwrap();
    v.verify_assertion("t").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    now.store(200_001, Ordering::SeqCst);
    v.verify_assertion("t").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);

    // a verdict with a jti is single-use at Atlas: not cached, so a replay reaches Atlas
    let single = canned(json!({ "valid": true, "id": "key_1", "jti": "j", "exp": 9_999_999 }));
    let v = ApiKeyVerifier::builder("sk_test").transport(single.clone()).build().unwrap();
    v.verify_assertion("t").await.unwrap();
    v.verify_assertion("t").await.unwrap();
    assert_eq!(single.calls.load(Ordering::SeqCst), 2);
}
