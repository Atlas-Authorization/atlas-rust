//! DPoP (RFC 9449) for a machine: a key the machine holds, and the proofs it signs with it. A token minted
//! with a proof from this key carries `cnf.jkt`, and a resource server accepts it only with a fresh proof
//! from the same key, so a stolen token is useless on its own. Ed25519 keys only (the TS client also takes
//! P-256; a P-256 DPoP key is not ported).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::client::MachineError;
use crate::dpop::{dpop_access_token_hash, normalize_htu};

/// An Ed25519 key the machine signs DPoP proofs with. Keep it as safely as the machine's own key.
pub struct DpopKey {
    signing: SigningKey,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

impl DpopKey {
    /// A new key from the OS CSPRNG.
    pub fn generate() -> Self {
        DpopKey { signing: SigningKey::generate(&mut rand::rngs::OsRng) }
    }

    /// Restore a key from a PKCS#8 PEM (as [`to_pkcs8_pem`](Self::to_pkcs8_pem) produced).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, MachineError> {
        SigningKey::from_pkcs8_pem(pem).map(|signing| DpopKey { signing }).map_err(|e| MachineError::Key(format!("a DPoP key must be an Ed25519 PKCS#8 PEM: {e}")))
    }

    /// The private key as a PKCS#8 PEM, for persisting. A secret.
    pub fn to_pkcs8_pem(&self) -> Result<String, MachineError> {
        self.signing.to_pkcs8_pem(LineEnding::LF).map(|p| p.as_str().to_string()).map_err(|e| MachineError::Key(format!("cannot encode DPoP key: {e}")))
    }

    fn x(&self) -> String {
        b64(self.signing.verifying_key().as_bytes())
    }

    /// The RFC 7638 thumbprint of the key: the `cnf.jkt` a token minted with its proofs carries.
    pub fn thumbprint(&self) -> String {
        b64(&Sha256::digest(format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x()).as_bytes()))
    }

    /// Sign one DPoP proof for one request. `url` is the full request URL (query and fragment are dropped, as
    /// the standard requires); pass `access_token` when calling a resource server so the proof names the
    /// token, and `nonce` when the server answered `use_dpop_nonce`. `now_ms` is epoch ms.
    pub fn proof(&self, method: &str, url: &str, access_token: Option<&str>, nonce: Option<&str>, now_ms: u64) -> Result<String, MachineError> {
        let htu = normalize_htu(url).ok_or_else(|| MachineError::Key(format!("a DPoP proof needs an absolute http(s) URL, got {url}")))?;
        let mut jti = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut jti);
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "EdDSA", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": self.x() } });
        let mut payload = serde_json::json!({ "jti": b64(&jti), "htm": method.to_ascii_uppercase(), "htu": htu, "iat": now_ms / 1000 });
        if let Some(t) = access_token.filter(|t| !t.is_empty()) {
            payload["ath"] = dpop_access_token_hash(t).into();
        }
        if let Some(n) = nonce.filter(|n| !n.is_empty()) {
            payload["nonce"] = n.into();
        }
        let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(payload.to_string().as_bytes()));
        let sig = self.signing.sign(input.as_bytes());
        Ok(format!("{input}.{}", b64(&sig.to_bytes())))
    }
}
