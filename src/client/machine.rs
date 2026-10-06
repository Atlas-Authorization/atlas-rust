//! §P1-7 the public MACHINE (device) flow — enrol, challenge, token — with an
//! Ed25519 keypair the device generates and keeps.
//!
//! A machine bootstrapping itself holds no `sk_`/`pk_` key: possession of a
//! PRIVATE KEY is the credential. The device:
//!
//!  1. generates an [`MachineKeypair`] (Ed25519) and enrols with its PUBLIC key +
//!     a one-time enrolment token ([`MachineClient::enroll`]),
//!  2. asks for a server CHALLENGE (nonce) ([`MachineClient::challenge`]),
//!  3. SIGNS the nonce with its private key and trades the signature for a short
//!     machine JWT ([`MachineClient::token`]).
//!
//! All three endpoints are PUBLIC — no secret key — matching the server's
//! `bapi-machine-enrolment` routes. [`MachineTokenManager`] caches the minted
//! token and re-mints it near expiry, mirroring
//! [`NativeSessionManager`](crate::client::NativeSessionManager).
//!
//! The server verifies the signature over the raw challenge bytes against the
//! registered public key (Ed25519 → pure EdDSA, no external hash), so this signs
//! `challenge.as_bytes()` and sends the 64-byte signature base64url-encoded.

use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::clock::{system_clock, Clock};
use crate::http::{HttpMethod, HttpRequest, HttpTransport};

/// An Ed25519 keypair a device enrols and signs challenges with. The private
/// half NEVER leaves the host; only [`public_key_pem`](Self::public_key_pem) is
/// sent to Atlas. Persist it across restarts with
/// [`to_pkcs8_pem`](Self::to_pkcs8_pem) into a [`SecureStore`](crate::client::SecureStore).
pub struct MachineKeypair {
    signing: SigningKey,
}

impl MachineKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        MachineKeypair {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// Restore a keypair from a PKCS#8 PEM (as [`to_pkcs8_pem`](Self::to_pkcs8_pem)
    /// produced).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, MachineError> {
        let signing = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| MachineError::Key(format!("bad PKCS#8 PEM: {e}")))?;
        Ok(MachineKeypair { signing })
    }

    /// The private key as a PKCS#8 PEM, for persisting in a secure store. Treat it
    /// as a secret — it is the whole credential.
    pub fn to_pkcs8_pem(&self) -> Result<String, MachineError> {
        self.signing
            .to_pkcs8_pem(LineEnding::LF)
            .map(|z| z.as_str().to_string())
            .map_err(|e| MachineError::Key(format!("encode PKCS#8: {e}")))
    }

    /// The public key as an SPKI PEM — what [`MachineClient::enroll`] registers.
    pub fn public_key_pem(&self) -> Result<String, MachineError> {
        self.signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| MachineError::Key(format!("encode SPKI: {e}")))
    }

    /// Sign a server challenge, returning the base64url signature to send to
    /// [`MachineClient::token`]. Signs the raw challenge bytes (Ed25519, no
    /// external hash) to match the server's verifier.
    pub fn sign_challenge(&self, challenge: &str) -> String {
        let sig = self.signing.sign(challenge.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

/// A failure of the machine flow.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    /// A keypair encode/decode failure.
    #[error("atlas machine: key error: {0}")]
    Key(String),
    /// A non-2xx response; `body` is the raw error envelope.
    #[error("atlas machine: HTTP {status}")]
    Api { status: u16, body: String },
    /// The request did not complete.
    #[error(transparent)]
    Transport(#[from] crate::error::TransportError),
    /// A 2xx body that did not parse, or a response missing a required field.
    #[error("atlas machine: malformed response: {0}")]
    Malformed(String),
}

/// The result of [`MachineClient::enroll`].
#[derive(Debug, Clone, Deserialize)]
pub struct Enrollment {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub public_key_jkt: Option<String>,
    /// The opaque per-device key supplied at enrolment, echoed back here.
    #[serde(default)]
    pub device_key: Option<String>,
    #[serde(default)]
    pub enrolled_at: Option<i64>,
    /// When true the device must wait for an admin to approve it before
    /// [`MachineClient::token`] will mint.
    #[serde(default)]
    pub approval_required: bool,
}

/// The server challenge from [`MachineClient::challenge`].
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub expires_in_seconds: i64,
}

/// A minted machine token (`POST /v1/machines/token`).
#[derive(Debug, Clone, Deserialize)]
pub struct MachineToken {
    pub token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: i64,
    #[serde(default)]
    pub machine_id: Option<String>,
}

/// The public device endpoints. No secret key — the credential is the enrolment
/// token (enroll) or the private key (challenge → token).
pub struct MachineClient {
    transport: Arc<dyn HttpTransport>,
    base_url: String,
}

impl MachineClient {
    /// Build over a transport and the API origin that serves `/v1/machines/*`.
    pub fn new(transport: Arc<dyn HttpTransport>, base_url: impl Into<String>) -> Self {
        MachineClient {
            transport,
            base_url: base_url.into(),
        }
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> Result<String, MachineError> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let req = HttpRequest::new(HttpMethod::Post, url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(body.to_string());
        let resp = self.transport.send(req).await?;
        if !(200..300).contains(&resp.status) {
            return Err(MachineError::Api {
                status: resp.status,
                body: resp.body,
            });
        }
        Ok(resp.body)
    }

    /// Enrol a device: present a one-time enrolment token and the keypair's
    /// public SPKI PEM. `metadata` is arbitrary device detail (hostname, os, …).
    pub async fn enroll(
        &self,
        enrolment_token: &str,
        name: &str,
        public_key_pem: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<Enrollment, MachineError> {
        self.enroll_with(enrolment_token, name, public_key_pem, metadata, None)
            .await
    }

    /// Enrol a device like [`enroll`](Self::enroll), additionally recording an
    /// opaque per-device `device_key` — a stable client-chosen handle the server
    /// stores on the machine and echoes back. Sent only when `Some`.
    pub async fn enroll_with(
        &self,
        enrolment_token: &str,
        name: &str,
        public_key_pem: &str,
        metadata: Option<serde_json::Value>,
        device_key: Option<&str>,
    ) -> Result<Enrollment, MachineError> {
        let mut body = serde_json::json!({
            "enrolment_token": enrolment_token,
            "name": name,
            "public_key_pem": public_key_pem,
        });
        if let Some(md) = metadata {
            body["metadata"] = md;
        }
        if let Some(dk) = device_key {
            body["device_key"] = serde_json::Value::String(dk.to_string());
        }
        let raw = self.post("/v1/machines/enroll", body).await?;
        serde_json::from_str(&raw).map_err(|e| MachineError::Malformed(e.to_string()))
    }

    /// Request a signing challenge for an enrolled, active machine.
    pub async fn challenge(&self, machine_id: &str) -> Result<Challenge, MachineError> {
        let raw = self
            .post(
                "/v1/machines/challenge",
                serde_json::json!({ "machine_id": machine_id }),
            )
            .await?;
        serde_json::from_str(&raw).map_err(|e| MachineError::Malformed(e.to_string()))
    }

    /// Trade a signed challenge for a machine token.
    pub async fn token(
        &self,
        machine_id: &str,
        nonce: &str,
        signature: &str,
    ) -> Result<MachineToken, MachineError> {
        let raw = self
            .post(
                "/v1/machines/token",
                serde_json::json!({
                    "machine_id": machine_id,
                    "nonce": nonce,
                    "signature": signature,
                }),
            )
            .await?;
        serde_json::from_str(&raw).map_err(|e| MachineError::Malformed(e.to_string()))
    }

    /// The whole mint in one call: fetch a challenge, sign it with `keypair`, and
    /// exchange the signature for a token.
    pub async fn mint_token(
        &self,
        machine_id: &str,
        keypair: &MachineKeypair,
    ) -> Result<MachineToken, MachineError> {
        let challenge = self.challenge(machine_id).await?;
        if challenge.nonce.is_empty() {
            return Err(MachineError::Malformed("challenge returned no nonce".into()));
        }
        let signature = keypair.sign_challenge(&challenge.nonce);
        self.token(machine_id, &challenge.nonce, &signature).await
    }
}

/// How close to expiry (ms) the manager re-mints a machine token.
pub const MACHINE_REFRESH_LEAD_MS: u64 = 10_000;

struct MachineManagerState {
    token: Option<String>,
    expires_at: u64,
}

/// Holds a machine token and keeps it live, mirroring
/// [`NativeSessionManager`](crate::client::NativeSessionManager): it re-mints
/// LAZILY on [`get_token`](Self::get_token) when the current token is within
/// [`MACHINE_REFRESH_LEAD_MS`] of expiry, single-flight under one async lock, by
/// running the full challenge → sign → token exchange with the held keypair.
pub struct MachineTokenManager {
    client: MachineClient,
    machine_id: String,
    keypair: MachineKeypair,
    now: Clock,
    state: AsyncMutex<MachineManagerState>,
}

impl MachineTokenManager {
    /// Build a manager for a machine id + its keypair.
    pub fn new(
        client: MachineClient,
        machine_id: impl Into<String>,
        keypair: MachineKeypair,
    ) -> Self {
        MachineTokenManager {
            client,
            machine_id: machine_id.into(),
            keypair,
            now: system_clock(),
            state: AsyncMutex::new(MachineManagerState {
                token: None,
                expires_at: 0,
            }),
        }
    }

    /// Inject a clock (epoch ms) for deterministic refresh-timing tests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.now = clock;
        self
    }

    /// The absolute expiry of the current token in epoch ms, or `None` if none is
    /// held yet.
    pub async fn expires_at_ms(&self) -> Option<u64> {
        let st = self.state.lock().await;
        st.token.as_ref().map(|_| st.expires_at)
    }

    /// A live machine token, minting or re-minting as needed. Single-flight: twenty
    /// concurrent callers make ONE exchange.
    pub async fn get_token(&self) -> Result<String, MachineError> {
        let mut st = self.state.lock().await;
        let owed = st
            .token
            .is_none()
            || st.expires_at.saturating_sub(MACHINE_REFRESH_LEAD_MS) <= (self.now)();
        if !owed {
            // Safe: owed is false only when a token is present.
            return Ok(st.token.clone().unwrap());
        }
        let minted = self.client.mint_token(&self.machine_id, &self.keypair).await?;
        st.expires_at = (self.now)() + (minted.expires_in.max(0) as u64) * 1000;
        st.token = Some(minted.token.clone());
        Ok(minted.token)
    }

    /// Force a re-mint now, replacing any cached token.
    pub async fn refresh(&self) -> Result<String, MachineError> {
        let mut st = self.state.lock().await;
        let minted = self.client.mint_token(&self.machine_id, &self.keypair).await?;
        st.expires_at = (self.now)() + (minted.expires_in.max(0) as u64) * 1000;
        st.token = Some(minted.token.clone());
        Ok(minted.token)
    }
}
