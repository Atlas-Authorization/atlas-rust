//! Hermetic integration tests. No network: RSA keypairs are generated in-test,
//! the JWKS is served either statically or through a counting mock, and the
//! API-key endpoint is a mock `HttpPost`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::{
    ApiKeyVerifier, AtlasBackend, BoxFuture, Clock, FetchOutcome, HttpPost, HttpResponse, Jwks,
    JwksSource, TransportError, User, VerifyError,
};

// ── key material ──────────────────────────────────────────────────────────

struct KeyMaterial {
    pem: Vec<u8>,
    n: String,
    e: String,
}

fn gen_key() -> KeyMaterial {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate key");
    let pem = priv_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("encode pem")
        .as_bytes()
        .to_vec();
    let pub_key = RsaPublicKey::from(&priv_key);
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    KeyMaterial { pem, n, e }
}

/// A single 2048-bit key, generated once for the whole test binary (RSA keygen
/// is slow in debug — do it exactly once).
fn primary() -> &'static KeyMaterial {
    static K: OnceLock<KeyMaterial> = OnceLock::new();
    K.get_or_init(gen_key)
}

fn jwks_for(km: &KeyMaterial, kid: &str) -> Jwks {
    serde_json::from_value(json!({
        "keys": [{
            "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
            "n": km.n, "e": km.e,
        }]
    }))
    .unwrap()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign_rs256(km: &KeyMaterial, kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(&km.pem).expect("encoding key");
    encode(&header, claims, &key).expect("sign")
}

const ISSUER: &str = "https://inst.fapi.atlasauth.net";

fn valid_claims() -> Value {
    let now = now_secs();
    json!({
        "iss": ISSUER,
        "sub": "user_1",
        "sid": "sess_1",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 3600,
        // A real first-party Atlas session token is positively marked (S4) and
        // carries its instance id as `aud` by default — both present together.
        "token_use": "session",
        "aud": ISSUER,
        "org_role": "admin",
        "org_permissions": ["billing:read"],
    })
}

fn static_backend(km: &KeyMaterial, kid: &str) -> AtlasBackend {
    AtlasBackend::builder(ISSUER)
        .static_jwks(jwks_for(km, kid))
        .build()
        .unwrap()
}

// ── session-token verification ──────────────────────────────────────────────

#[tokio::test]
async fn rs256_happy_path() {
    let km = primary();
    let backend = static_backend(km, "kid-1");
    let token = sign_rs256(km, "kid-1", &valid_claims());

    let claims = backend.verify(&token).await.expect("should verify");
    assert_eq!(claims.sub, "user_1");
    assert_eq!(claims.sid.as_deref(), Some("sess_1"));
    assert!(claims.has_role("admin"));
    assert!(claims.has_permission("billing:read"));
    assert!(!claims.has_permission("billing:write"));
}

#[tokio::test]
async fn rejects_alg_none() {
    let km = primary();
    let backend = static_backend(km, "kid-1");

    // Hand-craft an unsigned token: header alg "none", empty signature.
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"none","typ":"JWT","kid":"kid-1"}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(valid_claims().to_string());
    let token = format!("{header}.{payload}.");

    assert_eq!(backend.verify(&token).await, Err(VerifyError::Invalid));
}

#[tokio::test]
async fn rejects_hs256() {
    let km = primary();
    let backend = static_backend(km, "kid-1");

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("kid-1".to_string());
    let token = encode(
        &header,
        &valid_claims(),
        &EncodingKey::from_secret(b"attacker-chosen-secret"),
    )
    .unwrap();

    assert_eq!(backend.verify(&token).await, Err(VerifyError::Invalid));
}

#[tokio::test]
async fn rejects_wrong_issuer() {
    let km = primary();
    let backend = static_backend(km, "kid-1");
    let mut claims = valid_claims();
    claims["iss"] = json!("https://evil.example.com");
    let token = sign_rs256(km, "kid-1", &claims);

    assert_eq!(backend.verify(&token).await, Err(VerifyError::Invalid));
}

#[tokio::test]
async fn rejects_expired() {
    let km = primary();
    let backend = static_backend(km, "kid-1");
    let now = now_secs();
    let mut claims = valid_claims();
    claims["exp"] = json!(now - 3600);
    let token = sign_rs256(km, "kid-1", &claims);

    assert_eq!(backend.verify(&token).await, Err(VerifyError::Invalid));
}

#[tokio::test]
async fn rejects_malformed() {
    let backend = static_backend(primary(), "kid-1");
    assert_eq!(
        backend.verify("not-a-jwt").await,
        Err(VerifyError::Malformed)
    );
}

#[tokio::test]
async fn rejects_tampered_signature() {
    let km = primary();
    let other = gen_key();
    // JWKS serves `km`, but the token is signed with `other`.
    let backend = static_backend(km, "kid-1");
    let token = sign_rs256(&other, "kid-1", &valid_claims());

    assert_eq!(backend.verify(&token).await, Err(VerifyError::Invalid));
}

#[tokio::test]
async fn rejects_token_use_and_aud() {
    let km = primary();
    let backend = static_backend(km, "kid-1");

    let mut c1 = valid_claims();
    c1["token_use"] = json!("access_token");
    assert_eq!(
        backend.verify(&sign_rs256(km, "kid-1", &c1)).await,
        Err(VerifyError::Invalid)
    );

    // An id_token carries `aud` but is NOT session-marked — the token-confusion
    // guard rejects it even with no audience configured.
    let mut c2 = valid_claims();
    c2.as_object_mut().unwrap().remove("token_use");
    c2["aud"] = json!("some-rp-client");
    assert_eq!(
        backend.verify(&sign_rs256(km, "kid-1", &c2)).await,
        Err(VerifyError::Invalid)
    );
}

#[tokio::test]
async fn session_with_aud_verifies_when_no_audience_configured() {
    // The real-world default: an S4 session token carries `token_use:"session"`
    // AND its instance id as `aud`. A verifier with NO configured audience must
    // still accept it (regression: the old reject-any-aud logic broke this).
    let km = primary();
    let backend = static_backend(km, "kid-1");
    let claims = valid_claims(); // session-marked + aud = ISSUER
    assert!(backend.verify(&sign_rs256(km, "kid-1", &claims)).await.is_ok());
}

#[tokio::test]
async fn multiple_audiences_or() {
    // A verifier serving several instances accepts a token whose `aud` matches
    // ANY configured audience, and rejects one that matches none.
    let km = primary();
    let backend = AtlasBackend::builder(ISSUER)
        .static_jwks(jwks_for(km, "kid-1"))
        .audiences(["ins_a", "ins_b"])
        .build()
        .unwrap();

    let mut a = valid_claims();
    a["aud"] = json!("ins_b");
    assert!(backend.verify(&sign_rs256(km, "kid-1", &a)).await.is_ok());

    let mut none = valid_claims();
    none["aud"] = json!("ins_c");
    assert_eq!(
        backend.verify(&sign_rs256(km, "kid-1", &none)).await,
        Err(VerifyError::Invalid)
    );
}

#[tokio::test]
async fn authorized_parties_allowlist() {
    let km = primary();
    let backend = AtlasBackend::builder(ISSUER)
        .static_jwks(jwks_for(km, "kid-1"))
        .authorized_parties(["https://app.example.com"])
        .build()
        .unwrap();

    let mut bad = valid_claims();
    bad["azp"] = json!("https://evil.example.com");
    assert_eq!(
        backend.verify(&sign_rs256(km, "kid-1", &bad)).await,
        Err(VerifyError::UnauthorizedParty)
    );

    let mut good = valid_claims();
    good["azp"] = json!("https://app.example.com");
    assert!(backend
        .verify(&sign_rs256(km, "kid-1", &good))
        .await
        .is_ok());
}

#[tokio::test]
async fn optional_audience_backwards_compatible() {
    let km = primary();
    // With an expected audience (S4), a matching aud verifies and a session
    // without aud is rejected.
    let backend = AtlasBackend::builder(ISSUER)
        .static_jwks(jwks_for(km, "kid-1"))
        .audience("https://api.gaiadesk.com")
        .build()
        .unwrap();

    let mut with_aud = valid_claims();
    with_aud["aud"] = json!("https://api.gaiadesk.com");
    assert!(backend
        .verify(&sign_rs256(km, "kid-1", &with_aud))
        .await
        .is_ok());

    // aud as an array containing the expected value also matches.
    let mut arr = valid_claims();
    arr["aud"] = json!(["https://other", "https://api.gaiadesk.com"]);
    assert!(backend.verify(&sign_rs256(km, "kid-1", &arr)).await.is_ok());

    // Wrong aud is rejected.
    let mut wrong = valid_claims();
    wrong["aud"] = json!("https://api.other.com");
    assert_eq!(
        backend.verify(&sign_rs256(km, "kid-1", &wrong)).await,
        Err(VerifyError::Invalid)
    );
}

// ── JWKS cache refetch / throttle ───────────────────────────────────────────

struct MockJwksSource {
    jwks: Jwks,
    fetches: AtomicUsize,
}

impl JwksSource for MockJwksSource {
    fn fetch<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let j = self.jwks.clone();
        Box::pin(async move { Ok(j) })
    }
}

#[tokio::test]
async fn jwks_cache_refetches_on_unknown_kid_then_throttles() {
    let km = primary();
    let src = Arc::new(MockJwksSource {
        jwks: jwks_for(km, "kid-1"),
        fetches: AtomicUsize::new(0),
    });

    let clock_ms = Arc::new(Mutex::new(1_700_000_000_000u64));
    let clk: Clock = {
        let c = clock_ms.clone();
        Arc::new(move || *c.lock().unwrap())
    };

    let backend = AtlasBackend::builder(ISSUER)
        .jwks_url("mock://jwks")
        .jwks_source(src.clone())
        .clock(clk)
        .build()
        .unwrap();

    // First verify populates the cache: one fetch.
    let valid = sign_rs256(km, "kid-1", &valid_claims());
    backend.verify(&valid).await.expect("verify");
    assert_eq!(src.fetches.load(Ordering::SeqCst), 1);
    assert_eq!(backend.jwks_cache().last_outcome(), FetchOutcome::Fresh);

    // Past the refetch interval, an unknown kid triggers exactly one refetch.
    *clock_ms.lock().unwrap() += 120_000;
    let unknown = sign_rs256(km, "kid-unknown", &valid_claims());
    let _ = backend.verify(&unknown).await; // Invalid (kid absent), but it refetched.
    assert_eq!(src.fetches.load(Ordering::SeqCst), 2);
    assert_eq!(backend.jwks_cache().last_outcome(), FetchOutcome::Refetched);

    // A second kid-miss at the same instant is throttled: no new fetch.
    let _ = backend.verify(&unknown).await;
    assert_eq!(src.fetches.load(Ordering::SeqCst), 2);
    assert_eq!(backend.jwks_cache().last_outcome(), FetchOutcome::Throttled);
}

// ── email helpers / @no-email.invalid sentinel ──────────────────────────────

#[tokio::test]
async fn no_email_invalid_sentinel_is_none() {
    // A user whose only address is the placeholder has no real primary email.
    let placeholder: User = serde_json::from_value(json!({
        "id": "user_1",
        "email_addresses": [{
            "id": "idn_1",
            "email_address": "github-12345@no-email.invalid",
            "verified": true,
            "primary": true,
        }],
        "primary_email_address_id": "idn_1",
        "primary_email": null,
    }))
    .unwrap();
    assert_eq!(placeholder.primary_email(), None);
    assert!(!placeholder.has_real_email());
    assert_eq!(placeholder.real_emails().count(), 0);

    // A real address resolves.
    let real: User = serde_json::from_value(json!({
        "id": "user_2",
        "email_addresses": [{
            "id": "idn_2",
            "email_address": "ada@example.com",
            "verified": true,
            "primary": true,
        }],
        "primary_email_address_id": "idn_2",
        "primary_email": "ada@example.com",
    }))
    .unwrap();
    assert_eq!(real.primary_email(), Some("ada@example.com"));
    assert!(real.has_real_email());

    // The free function and the claim helper agree.
    assert_eq!(atlasauth::real_email("x@no-email.invalid"), None);
    assert_eq!(atlasauth::real_email("x@real.com"), Some("x@real.com"));
}

// ── API-key positive / negative caches ──────────────────────────────────────

struct MockApiKeyEndpoint {
    calls: AtomicUsize,
    valid_secret: String,
}

impl HttpPost for MockApiKeyEndpoint {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _bearer: &'a str,
        body: String,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let v: Value = serde_json::from_str(&body).unwrap();
        let secret = v["secret"].as_str().unwrap_or("").to_string();
        let valid = secret == self.valid_secret;
        let body = if valid {
            json!({"object":"api_key_verification","valid":true,"id":"ak_1","subject_type":"user","subject_id":"user_1"}).to_string()
        } else {
            json!({"object":"api_key_verification","valid":false}).to_string()
        };
        Box::pin(async move { Ok(HttpResponse { status: 200, body }) })
    }
}

#[tokio::test]
async fn api_key_positive_and_negative_caches() {
    let endpoint = Arc::new(MockApiKeyEndpoint {
        calls: AtomicUsize::new(0),
        valid_secret: "ak_good".to_string(),
    });

    let clock_ms = Arc::new(Mutex::new(1_000_000u64));
    let clk: Clock = {
        let c = clock_ms.clone();
        Arc::new(move || *c.lock().unwrap())
    };

    let verifier = ApiKeyVerifier::builder("sk_test_123")
        .transport(endpoint.clone())
        .clock(clk)
        .positive_ttl_ms(300_000)
        .negative_ttl_ms(30_000)
        .build()
        .unwrap();

    // A valid key: verified once, then served from the positive cache.
    assert!(verifier.verify("ak_good").await.unwrap().valid);
    assert!(verifier.verify("ak_good").await.unwrap().valid);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);

    // A bad key: one call, then the negative cache answers without hammering.
    assert!(!verifier.verify("ak_bad").await.unwrap().valid);
    assert!(!verifier.verify("ak_bad").await.unwrap().valid);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 2);

    // Past the SHORT negative TTL, the bad key is re-checked.
    *clock_ms.lock().unwrap() += 31_000;
    assert!(!verifier.verify("ak_bad").await.unwrap().valid);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 3);

    // The good key is still inside the LONGER positive TTL: still no new call.
    assert!(verifier.verify("ak_good").await.unwrap().valid);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 3);

    // Past the positive TTL, the good key is re-checked too.
    *clock_ms.lock().unwrap() += 300_001;
    assert!(verifier.verify("ak_good").await.unwrap().valid);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 4);
}
