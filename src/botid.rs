//! Vercel BotID for Atlas: the signing half that runs next to your BotID check.
//!
//! BotID's verdict (`checkBotId()`) only exists inside a Vercel-hosted request,
//! so that route turns it into a short signed attestation; the browser sends it
//! to Atlas as `captcha_token`, and Atlas checks the signature, freshness and
//! `is_bot == false`, and spends it (each attestation passes once). The same
//! secret is stored in Atlas for the `vercel_botid` captcha provider.
//!
//! Format (version 1): `atlas_botid.v1.<payload>.<sig>` — `payload` is base64url
//! JSON `{v: 1, is_bot, verified_bot, iat, exp, jti}`; `sig` is base64url
//! HMAC-SHA256 over `atlas_botid.v1.<payload>` keyed by the shared secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

/// The prefix every attestation carries.
pub const BOTID_ATTESTATION_PREFIX: &str = "atlas_botid.v1.";
/// The longest lifetime Atlas accepts, in seconds.
pub const BOTID_ATTESTATION_MAX_TTL_SECONDS: u64 = 300;
/// The shortest secret Atlas accepts.
pub const BOTID_SECRET_MIN_LENGTH: usize = 32;

/// Sign a BotID verdict for Atlas. `ttl_seconds` is clamped to 1–300 and
/// `now_seconds` is the issue time (UNIX seconds). Errors when the secret is
/// shorter than 32 characters (Atlas would refuse every attestation it signs).
/// A bot verdict is still signed — Atlas refuses it.
pub fn create_botid_attestation(
    secret: &str,
    is_bot: bool,
    is_verified_bot: bool,
    ttl_seconds: u64,
    now_seconds: u64,
) -> Result<String, crate::ConfigError> {
    if secret.chars().count() < BOTID_SECRET_MIN_LENGTH {
        return Err(crate::ConfigError::new(format!(
            "the BotID attestation secret must be at least {BOTID_SECRET_MIN_LENGTH} characters"
        )));
    }
    let ttl = ttl_seconds.clamp(1, BOTID_ATTESTATION_MAX_TTL_SECONDS);
    let mut jti = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut jti);
    let payload = serde_json::json!({
        "v": 1,
        "is_bot": is_bot,
        "verified_bot": is_verified_bot,
        "iat": now_seconds,
        "exp": now_seconds + ttl,
        "jti": URL_SAFE_NO_PAD.encode(jti),
    });
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(BOTID_ATTESTATION_PREFIX.as_bytes());
    mac.update(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{BOTID_ATTESTATION_PREFIX}{payload}.{sig}"))
}
