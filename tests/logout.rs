//! Back-channel logout token verification (OIDC Back-Channel Logout 1.0 §2.6),
//! against a test RSA key generated here and served as a static JWKS.

use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::{
    AtlasBackend, BoxFuture, Jwks, JwksSource, LogoutTokenReplayCache, TransportError, VerifyError,
    BACKCHANNEL_LOGOUT_EVENT, LOGOUT_TOKEN_TYPE,
};

const ISSUER: &str = "https://atlasauth.net";
const CLIENT_ID: &str = "aid_client_1";
const NOW: i64 = 1_800_000_000;

struct Key {
    pem: Vec<u8>,
    n: String,
    e: String,
}

fn gen_key() -> Key {
    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = sk.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec();
    let pk = RsaPublicKey::from(&sk);
    Key {
        pem,
        n: URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be()),
    }
}

fn key() -> &'static Key {
    static K: OnceLock<Key> = OnceLock::new();
    K.get_or_init(gen_key)
}

fn other_key() -> &'static Key {
    static K: OnceLock<Key> = OnceLock::new();
    K.get_or_init(gen_key)
}

fn verifier() -> AtlasBackend {
    let k = key();
    let jwks: Jwks = serde_json::from_value(json!({ "keys": [{
        "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": k.n, "e": k.e,
    }]}))
    .unwrap();
    AtlasBackend::builder(ISSUER)
        .static_jwks(jwks)
        .clock(Arc::new(|| (NOW as u64) * 1000))
        .build()
        .unwrap()
}

fn sign_with(k: &Key, typ: Option<&str>, claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k1".into());
    header.typ = typ.map(str::to_string);
    let enc = jsonwebtoken::EncodingKey::from_rsa_pem(&k.pem).unwrap();
    jsonwebtoken::encode(&header, claims, &enc).unwrap()
}

fn sign(claims: &Value) -> String {
    sign_with(key(), Some(LOGOUT_TOKEN_TYPE), claims)
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": NOW - 5,
        "exp": NOW + 115,
        "jti": "jti_1",
        "sub": "user_1",
        "sid": "sess_1",
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
    })
}

fn without(mut v: Value, key: &str) -> Value {
    v.as_object_mut().unwrap().remove(key);
    v
}

#[tokio::test]
async fn valid_logout_token_returns_its_claims() {
    let got = verifier().verify_logout_token(&sign(&claims()), CLIENT_ID).await.unwrap();
    assert_eq!(got.sub.as_deref(), Some("user_1"));
    assert_eq!(got.sid.as_deref(), Some("sess_1"));
    assert_eq!(got.jti, "jti_1");
    assert_eq!(got.iat, NOW - 5);
}

#[tokio::test]
async fn audience_may_be_an_array_and_typ_may_be_absent() {
    let mut c = claims();
    c["aud"] = json!(["other", CLIENT_ID]);
    let token = sign_with(key(), None, &c);
    assert!(verifier().verify_logout_token(&token, CLIENT_ID).await.is_ok());
}

#[tokio::test]
async fn sid_only_and_sub_only_are_both_accepted() {
    let v = verifier();
    let sid_only = v.verify_logout_token(&sign(&without(claims(), "sub")), CLIENT_ID).await.unwrap();
    assert_eq!((sid_only.sub, sid_only.sid.as_deref()), (None, Some("sess_1")));
    let sub_only = v.verify_logout_token(&sign(&without(claims(), "sid")), CLIENT_ID).await.unwrap();
    assert_eq!((sub_only.sub.as_deref(), sub_only.sid), (Some("user_1"), None));
}

#[tokio::test]
async fn exp_is_optional() {
    let token = sign(&without(claims(), "exp"));
    assert!(verifier().verify_logout_token(&token, CLIENT_ID).await.is_ok());
}

async fn rejects(token: String) {
    let err = verifier().verify_logout_token(&token, CLIENT_ID).await.unwrap_err();
    assert!(matches!(err, VerifyError::Invalid | VerifyError::Malformed), "{err:?}");
}

#[tokio::test]
async fn wrong_typ_is_rejected() {
    rejects(sign_with(key(), Some("JWT"), &claims())).await;
}

#[tokio::test]
async fn a_nonce_is_rejected() {
    let mut c = claims();
    c["nonce"] = json!("n-1");
    rejects(sign(&c)).await;
}

#[tokio::test]
async fn missing_or_malformed_events_are_rejected() {
    rejects(sign(&without(claims(), "events"))).await;
    let mut c = claims();
    c["events"] = json!({ "http://example.com/other": {} });
    rejects(sign(&c)).await;
    let mut c = claims();
    c["events"][BACKCHANNEL_LOGOUT_EVENT] = json!(true);
    rejects(sign(&c)).await;
}

#[tokio::test]
async fn wrong_audience_is_rejected() {
    let mut c = claims();
    c["aud"] = json!("someone_else");
    rejects(sign(&c)).await;
    rejects(sign(&without(claims(), "aud"))).await;
}

#[tokio::test]
async fn wrong_issuer_is_rejected() {
    let mut c = claims();
    c["iss"] = json!("https://evil.example");
    rejects(sign(&c)).await;
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let mut c = claims();
    c["iat"] = json!(NOW - 600);
    c["exp"] = json!(NOW - 300);
    rejects(sign(&c)).await;
}

#[tokio::test]
async fn iat_missing_or_in_the_future_is_rejected() {
    rejects(sign(&without(claims(), "iat"))).await;
    let mut c = claims();
    c["iat"] = json!(NOW + 3600);
    rejects(sign(&c)).await;
}

#[tokio::test]
async fn missing_jti_is_rejected() {
    rejects(sign(&without(claims(), "jti"))).await;
}

#[tokio::test]
async fn missing_both_sid_and_sub_is_rejected() {
    rejects(sign(&without(without(claims(), "sid"), "sub"))).await;
}

#[tokio::test]
async fn bad_signature_is_rejected() {
    rejects(sign_with(other_key(), Some(LOGOUT_TOKEN_TYPE), &claims())).await;
    rejects("not-a-jwt".to_string()).await;
}

#[tokio::test]
async fn a_non_rs256_token_is_rejected() {
    let header = jsonwebtoken::Header {
        typ: Some(LOGOUT_TOKEN_TYPE.into()),
        ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256)
    };
    let token =
        jsonwebtoken::encode(&header, &claims(), &jsonwebtoken::EncodingKey::from_secret(b"s")).unwrap();
    rejects(token).await;
}

#[test]
fn replay_cache_refuses_a_repeat_until_it_expires() {
    let cache = LogoutTokenReplayCache::new(2, 120);
    assert!(cache.check_and_remember("a", NOW));
    assert!(!cache.check_and_remember("a", NOW + 1));
    assert!(cache.check_and_remember("b", NOW + 2));
    // Capacity 2: a third id evicts the oldest instead of failing.
    assert!(cache.check_and_remember("c", NOW + 3));
    // After the TTL the id is forgotten.
    assert!(cache.check_and_remember("b", NOW + 500));
}

/// A JWKS endpoint that is down.
struct Unreachable;

impl JwksSource for Unreachable {
    fn fetch<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
        Box::pin(async { Err(TransportError::new("connection refused")) })
    }
}

#[tokio::test]
async fn an_unreachable_jwks_is_no_keys_and_retryable() {
    let atlas = AtlasBackend::builder(ISSUER)
        .jwks_url("https://keys.example.com/jwks")
        .jwks_source(Arc::new(Unreachable))
        .clock(Arc::new(|| (NOW as u64) * 1000))
        .build()
        .unwrap();
    let err = atlas.verify_logout_token(&sign(&claims()), CLIENT_ID).await.unwrap_err();
    assert_eq!(err, VerifyError::NoKeys);
    assert!(err.is_retryable());
}

#[tokio::test]
async fn a_bad_token_is_not_retryable() {
    let mut c = claims();
    c["aud"] = json!("someone-else");
    let err = verifier().verify_logout_token(&sign(&c), CLIENT_ID).await.unwrap_err();
    assert!(!err.is_retryable());
    assert!(!VerifyError::Malformed.is_retryable());
}
