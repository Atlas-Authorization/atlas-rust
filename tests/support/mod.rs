//! Shared fixtures: an in-test ES256 key and the JWKS that publishes it.
#![allow(dead_code)]

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use rsa::pkcs8::LineEnding;
use serde_json::{json, Value};

pub struct Keys {
    pub ec_pem: String,
    pub jwks: Value,
}

pub fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let ec = p256::SecretKey::random(&mut rand::thread_rng());
        let point = ec.public_key().to_encoded_point(false);
        let ec_pem = ec.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let jwks = json!({ "keys": [
            { "kty": "EC", "crv": "P-256", "kid": "ec-1", "alg": "ES256",
              "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()) },
        ]});
        Keys { ec_pem, jwks }
    })
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Sign `claims` as ES256 under kid `ec-1`, with an optional `typ`.
pub fn es256(claims: &Value, typ: Option<&str>) -> String {
    let mut h = Header::new(Algorithm::ES256);
    h.kid = Some("ec-1".into());
    h.typ = typ.map(str::to_string);
    encode(&h, claims, &EncodingKey::from_ec_pem(keys().ec_pem.as_bytes()).unwrap()).unwrap()
}
