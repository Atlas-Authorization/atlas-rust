//! A machine that REMEMBERS: it enrols once, keeps its identity in a store, and trades signed challenges for
//! short-lived machine tokens (per audience, scopes and organization), cached until shortly before they expire.
//! The Rust peer of `createMachineClient` in `@atlasauth/backend/machine`, on top of [`MachineClient`] and
//! [`MachineKeypair`].
//!
//! The wire contract is the same everywhere: `POST /v1/machines/enroll` with the public key, then
//! `POST /v1/machines/challenge`, then `POST /v1/machines/token` with the pure Ed25519 signature (over the
//! nonce's UTF-8 bytes, base64url) of the nonce.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex as AsyncMutex;

use super::machine_dpop::DpopKey;
use super::machine::{MachineClient, MachineError, MachineKeypair, MachineTokenRequest};
use crate::clock::{system_clock, Clock};
use crate::http::HttpTransport;

/// What a machine keeps between runs. The private key never leaves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIdentity {
    pub issuer: String,
    pub machine_id: String,
    /// PKCS#8 PEM of the Ed25519 private key.
    pub private_key_pem: String,
    /// SPKI PEM of the matching public key (what enrolment registered).
    pub public_key_pem: String,
    pub enrolled_at: i64,
}

/// Where the identity lives; implement it to use a keychain or a secret manager.
pub trait MachineIdentityStore: Send + Sync {
    fn load(&self) -> Result<Option<MachineIdentity>, MachineError>;
    fn save(&self, identity: &MachineIdentity) -> Result<(), MachineError>;
    fn clear(&self) -> Result<(), MachineError>;
}

/// A store that forgets on exit (tests, short-lived jobs that enrol every run).
#[derive(Default)]
pub struct MemoryMachineStore(Mutex<Option<MachineIdentity>>);

impl MemoryMachineStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MachineIdentityStore for MemoryMachineStore {
    fn load(&self) -> Result<Option<MachineIdentity>, MachineError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, identity: &MachineIdentity) -> Result<(), MachineError> {
        *self.0.lock().unwrap() = Some(identity.clone());
        Ok(())
    }
    fn clear(&self) -> Result<(), MachineError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// A store backed by one JSON file, written `0600` (on Unix) through a temporary file and a rename.
pub struct FileMachineStore(PathBuf);

impl FileMachineStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileMachineStore(path.into())
    }
}

fn io_err(e: std::io::Error) -> MachineError {
    MachineError::Key(format!("identity store: {e}"))
}

impl MachineIdentityStore for FileMachineStore {
    fn load(&self) -> Result<Option<MachineIdentity>, MachineError> {
        match std::fs::read_to_string(&self.0) {
            Ok(text) => Ok(serde_json::from_str(&text).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    fn save(&self, identity: &MachineIdentity) -> Result<(), MachineError> {
        use std::io::Write;
        if let Some(dir) = self.0.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(io_err)?;
        }
        let tmp = self.0.with_extension(format!("{}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io_err)?;
        f.write_all(serde_json::to_string(identity).map_err(|e| MachineError::Key(e.to_string()))?.as_bytes()).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        std::fs::rename(&tmp, &self.0).map_err(io_err)
    }

    fn clear(&self) -> Result<(), MachineError> {
        match std::fs::remove_file(&self.0) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(e)),
        }
    }
}

/// What to enrol with.
#[derive(Debug, Clone, Default)]
pub struct MachineEnrolOptions {
    /// A `met_` enrolment token, or a short user code (`XXXX-XXXX`).
    pub credential: String,
    pub name: String,
    pub metadata: Option<Value>,
    /// A stable device identifier, so re-enrolling replaces this device's earlier machine.
    pub device_key: Option<String>,
}

/// The outcome of [`MachineSession::enroll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineEnrolResult {
    pub machine_id: String,
    pub status: String,
    /// True when an administrator must approve the machine before it can get tokens.
    pub approval_required: bool,
}

/// A machine token with what the grant says about it.
#[derive(Debug, Clone, PartialEq)]
pub struct MachineAccessToken {
    pub token: String,
    /// `Bearer`, or `DPoP` when the session has a [`DpopKey`]: send `Authorization: DPoP <token>` with
    /// [`MachineSession::dpop_proof`].
    pub token_type: String,
    /// Epoch ms when the token stops being valid.
    pub expires_at: u64,
    pub audience: Option<String>,
    pub scope: Option<String>,
    /// The grant's `constraints`, as the token carries them. Your API enforces them.
    pub constraints: Option<Value>,
    pub organization_id: Option<String>,
}

fn cache_key(r: &MachineTokenRequest) -> String {
    let mut scopes = r.scopes.clone();
    scopes.sort();
    let mut presets = r.scope_presets.clone();
    presets.sort();
    serde_json::json!([r.audience.clone().unwrap_or_default(), scopes, presets, r.organization_id.clone().unwrap_or_default()]).to_string()
}

/// The device side of machine enrolment: enrol once, then get tokens.
pub struct MachineSession {
    client: MachineClient,
    store: Arc<dyn MachineIdentityStore>,
    issuer: String,
    now: Clock,
    refresh_skew_ms: u64,
    dpop: Option<DpopKey>,
    // Held across a mint, so concurrent callers share one exchange.
    cache: AsyncMutex<HashMap<String, MachineAccessToken>>,
}

impl MachineSession {
    /// `issuer` is your instance's issuer URL (the `iss` of its tokens): it is also the API origin that serves
    /// `/v1/machines/*`.
    pub fn new(transport: Arc<dyn HttpTransport>, issuer: impl Into<String>, store: Arc<dyn MachineIdentityStore>) -> Self {
        let issuer = issuer.into().trim_end_matches('/').to_string();
        MachineSession {
            client: MachineClient::new(transport, issuer.clone()),
            store,
            issuer,
            now: system_clock(),
            refresh_skew_ms: 60_000,
            dpop: None,
            cache: AsyncMutex::new(HashMap::new()),
        }
    }

    /// Fetch a new token this long before the cached one expires (default 60 seconds).
    pub fn refresh_skew_ms(mut self, ms: u64) -> Self {
        self.refresh_skew_ms = ms;
        self
    }

    /// Bind every token to a DPoP key (RFC 9449): the token requests carry a proof, minted tokens are
    /// `DPoP`-typed and carry `cnf.jkt`. Send [`dpop_proof`](Self::dpop_proof) with each call to your API.
    pub fn dpop_key(mut self, key: DpopKey) -> Self {
        self.dpop = Some(key);
        self
    }

    /// The thumbprint (`cnf.jkt`) tokens minted by this session carry, or `None` without a DPoP key.
    pub fn dpop_thumbprint(&self) -> Option<String> {
        self.dpop.as_ref().map(DpopKey::thumbprint)
    }

    /// A DPoP proof for one call to your API with a token this session minted: `Authorization: DPoP <token>`
    /// plus `DPoP: <proof>`. Pass `nonce` when the API answered `use_dpop_nonce`. Needs [`dpop_key`](Self::dpop_key).
    pub fn dpop_proof(&self, token: &str, method: &str, url: &str, nonce: Option<&str>) -> Result<String, MachineError> {
        let key = self.dpop.as_ref().ok_or_else(|| MachineError::Key("create the session with dpop_key() to sign DPoP proofs".into()))?;
        key.proof(method, url, Some(token), nonce, (self.now)())
    }

    /// Inject a clock (epoch ms), for tests.
    pub fn with_clock(mut self, now: Clock) -> Self {
        self.now = now;
        self
    }

    /// The stored identity, or `None` before enrolment (or when it belongs to another issuer).
    fn identity(&self) -> Result<Option<MachineIdentity>, MachineError> {
        Ok(self.store.load()?.filter(|i| i.issuer == self.issuer))
    }

    /// Generate a key, enrol with a token or short code, and store the identity. The private key is created
    /// here and only its public half is sent.
    pub async fn enroll(&self, opts: MachineEnrolOptions) -> Result<MachineEnrolResult, MachineError> {
        let keypair = MachineKeypair::generate();
        let public_pem = keypair.public_key_pem()?;
        let res = self
            .client
            .enroll_with(opts.credential.trim(), &opts.name, &public_pem, opts.metadata, opts.device_key.as_deref())
            .await?;
        if res.id.is_empty() {
            return Err(MachineError::Malformed("enrolment returned no machine id".into()));
        }
        self.store.save(&MachineIdentity {
            issuer: self.issuer.clone(),
            machine_id: res.id.clone(),
            private_key_pem: keypair.to_pkcs8_pem()?,
            public_key_pem: public_pem,
            enrolled_at: res.enrolled_at.unwrap_or((self.now)() as i64),
        })?;
        self.cache.lock().await.clear();
        Ok(MachineEnrolResult { machine_id: res.id, status: res.status.unwrap_or_default(), approval_required: res.approval_required })
    }

    pub fn is_enrolled(&self) -> Result<bool, MachineError> {
        Ok(self.identity()?.is_some())
    }

    pub fn machine_id(&self) -> Result<Option<String>, MachineError> {
        Ok(self.identity()?.map(|i| i.machine_id))
    }

    /// A machine token for this request, from the cache while it has more than the refresh skew left.
    /// Concurrent callers asking for the same thing share one mint.
    pub async fn get_token(&self, request: &MachineTokenRequest) -> Result<MachineAccessToken, MachineError> {
        let key = cache_key(request);
        let mut cache = self.cache.lock().await;
        let now = (self.now)();
        if let Some(hit) = cache.get(&key) {
            if hit.expires_at.saturating_sub(self.refresh_skew_ms) > now {
                return Ok(hit.clone());
            }
        }
        let id = self.identity()?.ok_or_else(|| MachineError::Key("this machine is not enrolled: call enroll() first".into()))?;
        let keypair = MachineKeypair::from_pkcs8_pem(&id.private_key_pem)?;
        let res = self.client.mint_token_with_dpop(&id.machine_id, &keypair, request, self.dpop.as_ref().map(|k| (k, now))).await?;
        let token = res.get("token").and_then(Value::as_str).ok_or_else(|| MachineError::Malformed("the token response has no token".into()))?.to_string();
        let expires_in = res.get("expires_in").and_then(Value::as_u64).ok_or_else(|| MachineError::Malformed("the token response has no expires_in".into()))?;
        let text = |k: &str| res.get(k).and_then(Value::as_str).map(str::to_string);
        let minted = MachineAccessToken {
            token,
            token_type: if res.get("token_type").and_then(Value::as_str) == Some("DPoP") { "DPoP".into() } else { "Bearer".into() },
            expires_at: now + expires_in * 1000,
            audience: text("audience"),
            scope: text("scope"),
            constraints: res.get("constraints").filter(|c| !c.is_null()).cloned(),
            organization_id: text("organization_id"),
        };
        cache.insert(key, minted.clone());
        Ok(minted)
    }

    /// Forget cached tokens (the stored identity stays).
    pub async fn clear_tokens(&self) {
        self.cache.lock().await.clear();
    }

    /// Forget the identity too: the machine must enrol again.
    pub async fn reset(&self) -> Result<(), MachineError> {
        self.cache.lock().await.clear();
        self.store.clear()
    }
}
