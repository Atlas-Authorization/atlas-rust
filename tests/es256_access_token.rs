//! ES256 acceptance (pinned to RS256 + ES256), the app-claim helpers and the
//! access-token verifier with its WWW-Authenticate challenge. Hermetic: keys
//! are generated in-test and the JWKS is static.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::{
    build_www_authenticate, protected_resource_metadata, protected_resource_metadata_path, AccessTokenOptions,
    AccessTokenResult, AtlasBackend, Jwks, SIGNING_ALGS,
};

const ISSUER: &str = "https://issuer.test";
const AUD: &str = "https://api.test";

struct Keys {
    ec_pem: String,
    rsa_pem: Vec<u8>,
    jwks: Value,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let ec = p256::SecretKey::random(&mut rand::thread_rng());
        let point = ec.public_key().to_encoded_point(false);
        let ec_pem = ec.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let rsa = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let rsa_pem = rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec();
        let pubk = RsaPublicKey::from(&rsa);
        let jwks = json!({ "keys": [
            { "kty": "EC", "crv": "P-256", "kid": "ec-1", "alg": "ES256",
              "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()) },
            { "kty": "RSA", "kid": "rs-1", "alg": "RS256",
              "n": URL_SAFE_NO_PAD.encode(pubk.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(pubk.e().to_bytes_be()) },
        ]});
        Keys { ec_pem, rsa_pem, jwks }
    })
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn es256(claims: &Value, kid: &str) -> String {
    let mut h = Header::new(Algorithm::ES256);
    h.kid = Some(kid.into());
    encode(&h, claims, &EncodingKey::from_ec_pem(keys().ec_pem.as_bytes()).unwrap()).unwrap()
}

fn rs256(claims: &Value, kid: &str) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(kid.into());
    encode(&h, claims, &EncodingKey::from_rsa_pem(&keys().rsa_pem).unwrap()).unwrap()
}

fn backend() -> AtlasBackend {
    let jwks: Jwks = serde_json::from_value(keys().jwks.clone()).unwrap();
    AtlasBackend::builder(ISSUER).static_jwks(jwks).build().unwrap()
}

#[tokio::test]
async fn session_verifier_accepts_es256_and_pins_algorithms() {
    let b = backend();
    let claims = json!({ "iss": ISSUER, "sub": "u_1", "exp": now() + 300,
        "app_roles": ["support"], "app_permissions": ["tickets:read"] });
    let c = b.verify(&es256(&claims, "ec-1")).await.expect("ES256 verifies");
    assert!(c.has_app_role("support") && !c.has_app_role("admin"));
    assert!(c.has_app_permission("tickets:read") && !c.has_app_permission("tickets:write"));
    assert!(b.verify(&rs256(&claims, "rs-1")).await.is_ok(), "RS256 still verifies");
    assert!(b.verify(&es256(&claims, "rs-1")).await.is_err(), "ES256 under the RSA kid");
    let hs = encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(b"secret")).unwrap();
    assert!(b.verify(&hs).await.is_err(), "HS256");
    assert_eq!(SIGNING_ALGS, [Algorithm::RS256, Algorithm::ES256]);
}

fn access(extra: Value) -> Value {
    let mut c = json!({ "iss": ISSUER, "sub": "u_1", "aud": AUD, "exp": now() + 300,
        "token_use": "access_token", "scope": "read write", "client_id": "oc_1" });
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    c
}

fn opts() -> AccessTokenOptions {
    AccessTokenOptions {
        audiences: vec![AUD.into()],
        required_scopes: vec!["read".into()],
        resource_metadata_url: Some(format!("{AUD}/.well-known/oauth-protected-resource")),
        ..Default::default()
    }
}

fn refused(r: &AccessTokenResult) -> (u16, Option<&'static str>, String) {
    match r {
        AccessTokenResult::Refused { status, error, www_authenticate, .. } => (*status, *error, www_authenticate.clone()),
        AccessTokenResult::Ok { .. } => panic!("expected a refusal"),
    }
}

#[tokio::test]
async fn access_token_verifier() {
    let b = backend();
    let o = opts();
    match b.verify_access_token(Some(&format!("Bearer {}", es256(&access(json!({})), "ec-1"))), &o).await {
        AccessTokenResult::Ok { subject, client_id, scopes, .. } => {
            assert_eq!(subject, "u_1");
            assert_eq!(client_id.as_deref(), Some("oc_1"));
            assert_eq!(scopes, vec!["read", "write"]);
        }
        other => panic!("refused: {other:?}"),
    }
    let (status, error, www) = refused(&b.verify_access_token(None, &o).await);
    assert_eq!((status, error), (401, None));
    assert_eq!(www, format!("Bearer scope=\"read\", resource_metadata=\"{AUD}/.well-known/oauth-protected-resource\""));
    assert_eq!(refused(&b.verify_access_token(Some("Basic abc"), &o).await).0, 400);
    let wrong = b.verify_access_token(Some(&format!("Bearer {}", es256(&access(json!({"aud": "https://other.test"})), "ec-1"))), &o).await;
    let (s, _, w) = refused(&wrong);
    assert_eq!(s, 401);
    assert!(w.contains("error=\"invalid_token\""));
    for extra in [json!({"token_use": "session"}), json!({"cnf": {"jkt": "x"}}), json!({"exp": now() - 600})] {
        let r = b.verify_access_token(Some(&format!("Bearer {}", es256(&access(extra.clone()), "ec-1"))), &o).await;
        assert!(!r.is_ok(), "accepted {extra}");
    }
    let mut o2 = o.clone();
    o2.required_scopes.push("admin".into());
    let short = b.verify_access_token(Some(&format!("Bearer {}", rs256(&access(json!({"scope": "write"})), "rs-1"))), &o2).await;
    let (s, e, w) = refused(&short);
    assert_eq!((s, e), (403, Some("insufficient_scope")));
    assert!(w.contains("scope=\"read admin\""));
}

#[test]
fn challenge_and_metadata_helpers() {
    assert_eq!(build_www_authenticate(None, None, None, None, None), "Bearer");
    assert_eq!(protected_resource_metadata_path("https://api.test/v1/"), "/.well-known/oauth-protected-resource/v1");
    assert_eq!(protected_resource_metadata_path("https://api.test"), "/.well-known/oauth-protected-resource");
    let doc = protected_resource_metadata(AUD, "https://issuer.test/", &["read"]);
    assert_eq!(doc["authorization_servers"][0], "https://issuer.test");
    assert_eq!(doc["scopes_supported"][0], "read");
}
