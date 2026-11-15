//! Session-token verification accepts RS256, ES256, ES384, PS256 and EdDSA, each against a key generated at
//! runtime, with the JWK type checked against the header algorithm: no algorithm confusion, no `none`, no HS*.

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs8::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};

use atlasauth::{verify_transaction_token, AtlasBackend, Jwks, TxnTokenOptions, VerifyError};

const ISSUER: &str = "https://issuer.test";

/// A signing key: its encoding key and the public JWK (without `alg`) that publishes it.
struct Key {
    enc: EncodingKey,
    jwk: Value,
}

fn rsa_key() -> Key {
    let k = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let p = rsa::RsaPublicKey::from(&k);
    Key {
        enc: EncodingKey::from_rsa_pem(k.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes()).unwrap(),
        jwk: json!({ "kty": "RSA", "n": URL_SAFE_NO_PAD.encode(p.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(p.e().to_bytes_be()) }),
    }
}

fn p256_key() -> Key {
    use p256::pkcs8::EncodePrivateKey;
    let k = p256::SecretKey::random(&mut rand::thread_rng());
    let pt = k.public_key().to_encoded_point(false);
    Key {
        enc: EncodingKey::from_ec_pem(k.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap(),
        jwk: json!({ "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(pt.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(pt.y().unwrap()) }),
    }
}

fn p384_key() -> Key {
    use p384::pkcs8::EncodePrivateKey;
    let k = p384::SecretKey::random(&mut rand::thread_rng());
    let pt = k.public_key().to_encoded_point(false);
    Key {
        enc: EncodingKey::from_ec_pem(k.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap(),
        jwk: json!({ "kty": "EC", "crv": "P-384", "x": URL_SAFE_NO_PAD.encode(pt.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(pt.y().unwrap()) }),
    }
}

fn ed_key() -> Key {
    let k = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    Key {
        enc: EncodingKey::from_ed_pem(k.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap(),
        jwk: json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes()) }),
    }
}

fn jwks_of(key: &Key, kid: &str, alg: Option<&str>) -> Jwks {
    let mut jwk = key.jwk.clone();
    jwk["kid"] = json!(kid);
    if let Some(a) = alg {
        jwk["alg"] = json!(a);
    }
    serde_json::from_value(json!({ "keys": [jwk] })).unwrap()
}

fn token(alg: Algorithm, key: &Key, kid: &str, typ: Option<&str>, extra: Value) -> String {
    let mut h = Header::new(alg);
    h.kid = Some(kid.into());
    h.typ = typ.map(str::to_string);
    let mut claims = json!({ "iss": ISSUER, "sub": "user_1", "exp": support::now_secs() + 300 });
    claims.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    encode(&h, &claims, &key.enc).unwrap()
}

fn backend(jwks: Jwks) -> AtlasBackend {
    AtlasBackend::builder(ISSUER).static_jwks(jwks).build().unwrap()
}

#[tokio::test]
async fn every_supported_algorithm_verifies_with_and_without_a_declared_key_alg() {
    let cases: Vec<(Algorithm, &str, Key)> = vec![
        (Algorithm::RS256, "RS256", rsa_key()),
        (Algorithm::PS256, "PS256", rsa_key()),
        (Algorithm::ES256, "ES256", p256_key()),
        (Algorithm::ES384, "ES384", p384_key()),
        (Algorithm::EdDSA, "EdDSA", ed_key()),
    ];
    for (alg, name, key) in &cases {
        let t = token(*alg, key, "k1", None, json!({}));
        for declared in [Some(*name), None] {
            let c = backend(jwks_of(key, "k1", declared)).verify(&t).await.unwrap_or_else(|e| panic!("{name} (declared {declared:?}): {e}"));
            assert_eq!(c.sub, "user_1");
        }
    }
}

#[tokio::test]
async fn the_key_type_must_fit_the_header_algorithm() {
    let rsa = rsa_key();
    let ec = p256_key();
    // A PS256 token against an RSA key that declares RS256 is skipped, and the reverse.
    let ps = token(Algorithm::PS256, &rsa, "k1", None, json!({}));
    assert!(backend(jwks_of(&rsa, "k1", Some("RS256"))).verify(&ps).await.is_err());
    let rs = token(Algorithm::RS256, &rsa, "k1", None, json!({}));
    assert!(backend(jwks_of(&rsa, "k1", Some("PS256"))).verify(&rs).await.is_err());
    // An ES256 token against an RSA key published under the same kid never verifies (and vice versa).
    let es = token(Algorithm::ES256, &ec, "k1", None, json!({}));
    assert!(backend(jwks_of(&rsa, "k1", None)).verify(&es).await.is_err());
    assert!(backend(jwks_of(&ec, "k1", None)).verify(&rs).await.is_err());
    // A P-256 key cannot verify ES384, nor a P-384 key ES256.
    let p384 = p384_key();
    let es384 = token(Algorithm::ES384, &p384, "k1", None, json!({}));
    assert!(backend(jwks_of(&ec, "k1", None)).verify(&es384).await.is_err());
    assert!(backend(jwks_of(&p384, "k1", None)).verify(&es).await.is_err());
    // A key whose own alg contradicts its type is skipped entirely.
    assert!(backend(jwks_of(&ec, "k1", Some("ES384"))).verify(&es).await.is_err());
    // The right pairs still verify.
    assert!(backend(jwks_of(&p384, "k1", None)).verify(&es384).await.is_ok());
}

#[tokio::test]
async fn none_and_hmac_never_verify() {
    let rsa = rsa_key();
    let jwks = jwks_of(&rsa, "k1", None);
    let b = backend(jwks);
    let hs = encode(&Header::new(Algorithm::HS256), &json!({ "iss": ISSUER, "sub": "u", "exp": support::now_secs() + 300 }), &EncodingKey::from_secret(b"secret")).unwrap();
    assert_eq!(b.verify(&hs).await.unwrap_err(), VerifyError::Invalid);
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(json!({ "iss": ISSUER, "sub": "u", "exp": support::now_secs() + 300 }).to_string())
    );
    assert!(b.verify(&none).await.is_err());
}

#[test]
fn transaction_tokens_use_the_same_algorithms() {
    let now = support::now_secs();
    let claims = json!({ "iss": "https://tts.test", "sub": "u", "aud": "td", "iat": now, "exp": now + 60, "txn": "t", "scope": "a", "req_wl": "w" });
    let opts = TxnTokenOptions { issuer: "https://tts.test".into(), trust_domain: "td".into(), now_seconds: None };
    for (alg, key) in [(Algorithm::ES384, p384_key()), (Algorithm::EdDSA, ed_key()), (Algorithm::PS256, rsa_key())] {
        let mut h = Header::new(alg);
        h.kid = Some("k1".into());
        h.typ = Some("txntoken+jwt".into());
        let t = encode(&h, &claims, &key.enc).unwrap();
        assert!(verify_transaction_token(&t, &jwks_of(&key, "k1", None), &opts).is_ok(), "{alg:?}");
    }
}
