//! PKCE (RFC 7636) code verifier/challenge derivation.
//!
//! A native app cannot keep a client secret, so the authorization-code flow is
//! protected by PKCE instead: the client picks a high-entropy `verifier`, sends
//! only its SHA-256 `challenge` on the authorize request, and proves possession
//! of the verifier at the token endpoint. Only S256 is implemented — the `plain`
//! method offers no protection against an intercepted authorization code.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A PKCE verifier/challenge pair. The `verifier` is secret and stays on the
/// device; the `challenge` + `method` ride the authorize URL.
#[derive(Debug, Clone)]
pub struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    /// Generate a fresh pair from 32 bytes of CSPRNG entropy (a 43-char
    /// base64url verifier, the RFC-recommended length).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        Self::from_verifier(verifier)
    }

    /// Derive the challenge for a caller-supplied verifier. Exposed so a caller
    /// can persist a verifier across a redirect and rebuild the pair, and so the
    /// RFC 7636 test vector can be asserted.
    pub fn from_verifier(verifier: impl Into<String>) -> Self {
        let verifier = verifier.into();
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        Pkce { verifier, challenge }
    }

    /// The secret code verifier — presented at the token endpoint, never on the
    /// authorize request.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The S256 code challenge — sent on the authorize request.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The challenge method token. Always `"S256"`.
    pub fn method(&self) -> &'static str {
        "S256"
    }
}
