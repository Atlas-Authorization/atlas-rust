//! Signs the short-lived assertion a key-pair API key presents instead of a secret: ES256 for P-256
//! keys (raw `r || s`), EdDSA for Ed25519 keys.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::RngCore;
use serde_json::{json, Map, Value};

use crate::error::ConfigError;

/// The optional claims of an assertion.
#[derive(Debug, Clone)]
pub struct ApiKeyAssertionOptions {
    /// Lifetime in seconds (default 300).
    pub ttl_seconds: u64,
    /// Space-separated scopes narrowing the key's own.
    pub scope: Option<String>,
    /// A fixed `jti`; `None` draws a random one.
    pub jti: Option<String>,
}

impl Default for ApiKeyAssertionOptions {
    fn default() -> Self {
        ApiKeyAssertionOptions { ttl_seconds: 300, scope: None, jti: None }
    }
}

// The PKCS#8 header of a bare Ed25519 seed (48 bytes in all).
const ED25519_PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

/// Sign an assertion with the PKCS#8 PEM private key Atlas returned once at create. Present it as
/// `token` to `POST /v1/api_keys/verify` or as `assertion` to `POST /v1/api_keys/token`.
pub fn sign_api_key_assertion(
    private_key_pem: &str,
    key_id: &str,
    audience: &str,
    options: &ApiKeyAssertionOptions,
) -> Result<String, ConfigError> {
    let body: String = private_key_pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(body.trim()).map_err(|_| ConfigError::new("the private key is not a PEM"))?;
    let ed = der.len() == 48 && der.starts_with(&ED25519_PKCS8_PREFIX);
    let (alg, key) = if ed {
        (Algorithm::EdDSA, EncodingKey::from_ed_pem(private_key_pem.as_bytes()))
    } else {
        (Algorithm::ES256, EncodingKey::from_ec_pem(private_key_pem.as_bytes()))
    };
    let key = key.map_err(|e| ConfigError::new(format!("the key must be a P-256 or Ed25519 PKCS#8 private key: {e}")))?;

    let jti = options.jti.clone().unwrap_or_else(|| {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        URL_SAFE_NO_PAD.encode(b)
    });
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut claims = Map::new();
    claims.insert("iss".into(), json!(key_id));
    claims.insert("aud".into(), json!(audience));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(now + options.ttl_seconds));
    claims.insert("jti".into(), json!(jti));
    if let Some(scope) = &options.scope {
        claims.insert("scope".into(), json!(scope));
    }
    let mut header = Header::new(alg);
    header.kid = Some(key_id.to_string());
    // jsonwebtoken (ring) signs ES256 as the raw 64-byte r || s a JWS carries.
    encode(&header, &Value::Object(claims), &key).map_err(|e| ConfigError::new(format!("signing failed: {e}")))
}
