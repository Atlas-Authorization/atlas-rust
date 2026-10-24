//! Sealed secret delivery.
//!
//! Build a [`BackendClient`](crate::backend::BackendClient) with
//! `.secret_recipient(pair.recipient())` and every shown-once secret in a
//! response (`secret`, `client_secret`, a webhook `secret`, …) arrives as a
//! libsodium sealed box (`sealed_secret`, `sealed_client_secret`, …) instead of
//! plaintext, so it never crosses a log line or a proxy readable. Open one with
//! [`open_sealed_secret`].
//!
//! The cryptography is the vetted [`crypto_box`] crate's `crypto_box_seal` /
//! `crypto_box_seal_open` (X25519 + XSalsa20-Poly1305, nonce from BLAKE2b) —
//! nothing is hand-rolled here. Needs the `sealed-box` feature.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use crypto_box::{PublicKey, SecretKey};
use rand::RngCore;
use thiserror::Error;

/// Why a sealed box did not open (or could not be made).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SealedBoxError {
    /// The box is too short, was sealed to another key, or was altered.
    #[error("atlas: sealed box did not open (wrong key, altered, or truncated)")]
    Invalid,
    /// The sealed value was not valid base64.
    #[error("atlas: sealed value is not valid base64")]
    NotBase64,
    /// The opened plaintext was not UTF-8 text.
    #[error("atlas: sealed secret is not UTF-8")]
    NotUtf8,
}

/// A key pair for sealed secret delivery.
#[derive(Clone)]
pub struct SealKeyPair {
    public_key: [u8; 32],
    secret_key: [u8; 32],
}

impl std::fmt::Debug for SealKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealKeyPair").field("recipient", &self.recipient()).finish_non_exhaustive()
    }
}

impl SealKeyPair {
    /// Rebuild a pair from a stored 32-byte secret key.
    pub fn from_secret_key(secret_key: [u8; 32]) -> Self {
        let public_key = SecretKey::from(secret_key).public_key().to_bytes();
        SealKeyPair { public_key, secret_key }
    }

    /// The 32-byte X25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The 32-byte X25519 secret key. Keep it private.
    pub fn secret_key(&self) -> [u8; 32] {
        self.secret_key
    }

    /// The value for `BackendClientBuilder::secret_recipient`:
    /// `x25519:<base64 public key>`.
    pub fn recipient(&self) -> String {
        format!("x25519:{}", STANDARD.encode(self.public_key))
    }
}

/// Make a key pair for sealed secret delivery from the operating system's
/// random number generator.
pub fn generate_seal_key_pair() -> SealKeyPair {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    SealKeyPair::from_secret_key(secret)
}

/// Seal `message` to a recipient public key (`crypto_box_seal`).
pub fn seal_box(message: &[u8], recipient: &[u8; 32]) -> Result<Vec<u8>, SealedBoxError> {
    PublicKey::from(*recipient)
        .seal(&mut rand::rngs::OsRng, message)
        .map_err(|_| SealedBoxError::Invalid)
}

/// Open a sealed box addressed to `pair` (`crypto_box_seal_open`).
pub fn open_sealed_box(sealed: &[u8], pair: &SealKeyPair) -> Result<Vec<u8>, SealedBoxError> {
    SecretKey::from(pair.secret_key).unseal(sealed).map_err(|_| SealedBoxError::Invalid)
}

/// Open a `sealed_*` field (base64 sealed box) from an Atlas response with the
/// key pair whose [`recipient`](SealKeyPair::recipient) the client was built
/// with, returning the secret.
pub fn open_sealed_secret(sealed_base64: &str, pair: &SealKeyPair) -> Result<String, SealedBoxError> {
    let raw = STANDARD.decode(sealed_base64.trim()).map_err(|_| SealedBoxError::NotBase64)?;
    let plain = open_sealed_box(&raw, pair)?;
    String::from_utf8(plain).map_err(|_| SealedBoxError::NotUtf8)
}
