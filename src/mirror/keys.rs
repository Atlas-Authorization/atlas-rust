//! A local, authoritative mirror of end-user API keys (`ak_`), with Atlas as the minting and revocation
//! backstop. Your request path verifies a presented key against the LOCAL row (sha256 hash, scopes, expiry,
//! revocation, IP allowlist) with no network call. Revoking locally happens FIRST, so a failed Atlas call
//! never leaves a key usable here.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{freshness, hex, Freshness, MirrorError, StoreError};
use crate::backend::{BackendClient, BackendError};
use crate::clock::{system_clock, Clock};
use crate::http::{encode_segment, HttpMethod};

/// What the mirror keeps per key. Never the secret: only its sha256 (hex).
#[derive(Debug, Clone, PartialEq)]
pub struct MirroredApiKey {
    /// The Atlas key id (`eak_...`).
    pub id: String,
    /// sha256 of the full secret, lowercase hex.
    pub hash: String,
    pub prefix: String,
    pub subject_type: String,
    pub subject_id: String,
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    /// CIDR allowlist; `None` or empty: any caller.
    pub allowed_ips: Option<Vec<String>>,
    /// Epoch ms; `None`: never.
    pub expires_at: Option<i64>,
    /// Epoch ms; `None`: live.
    pub revoked_at: Option<i64>,
    /// The organization a user key is bound to.
    pub organization_id: Option<String>,
    pub revoked_reason: Option<String>,
    /// `Some(false)`: refused like an unknown key; `None`: enabled.
    pub enabled: Option<bool>,
    /// `"secret"` or `"key_pair"`. A key-pair row has no secret hash (`hash` is a placeholder nothing matches).
    pub credential: String,
    /// Key pair: the SPKI PEM assertions are verified against.
    pub public_key_pem: Option<String>,
    /// Key pair: the `aud` an assertion must carry.
    pub audience: Option<String>,
    /// Key pair: the longest assertion lifetime in seconds; `None`: 3600.
    pub max_token_lifetime_seconds: Option<i64>,
}

/// The member's standing in the organization a key is bound to.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiKeyOrganization {
    pub id: String,
    pub role: String,
    pub permissions: Vec<String>,
}

/// The smallest store that works: put / get / get_by_hash / mark_revoked and a feed cursor.
pub trait KeyMirrorStore: Send + Sync {
    fn put(&self, key: MirroredApiKey) -> Result<(), StoreError>;
    fn get(&self, id: &str) -> Result<Option<MirroredApiKey>, StoreError>;
    fn get_by_hash(&self, hash: &str) -> Result<Option<MirroredApiKey>, StoreError>;
    /// Stamp a key revoked. A no-op for an id the mirror does not hold or a key already revoked.
    fn mark_revoked(&self, id: &str, revoked_at: i64, reason: Option<&str>) -> Result<(), StoreError>;
    /// Stamp every live key of `user_id` bound to `organization_id` revoked (reason `membership_ended`).
    /// Returns whether the store supports it; a store without it still drops those keys through the
    /// revocation feed and the `api_key.revoked` webhook Atlas sends for each.
    fn mark_membership_ended(&self, user_id: &str, organization_id: &str, revoked_at: i64) -> Result<bool, StoreError> {
        let _ = (user_id, organization_id, revoked_at);
        Ok(false)
    }
    /// Optional: record an assertion `jti` as used until `expires_at_ms`. `Ok(Some(false))` is a replay;
    /// `Ok(None)` (the default) means the store does not track them and the mirror keeps used ids in process memory.
    fn claim_assertion_jti(&self, key_id: &str, jti: &str, expires_at_ms: i64) -> Result<Option<bool>, StoreError> {
        let _ = (key_id, jti, expires_at_ms);
        Ok(None)
    }
    fn cursor(&self) -> Result<Option<String>, StoreError>;
    fn set_cursor(&self, cursor: &str) -> Result<(), StoreError>;
    /// Epoch ms of the last COMPLETED `sync()`. Without a persistent value the mirror keeps it in memory,
    /// so a restart reads as never synced.
    fn last_sync_at(&self) -> Result<Option<i64>, StoreError> {
        Ok(None)
    }
    fn set_last_sync_at(&self, at: i64) -> Result<(), StoreError> {
        let _ = at;
        Ok(())
    }
}

#[derive(Default)]
struct MemoryInner {
    keys: HashMap<String, MirroredApiKey>,
    cursor: Option<String>,
    last_sync_at: Option<i64>,
}

/// An in-memory store, for tests and single-process apps.
#[derive(Default)]
pub struct MemoryKeyMirrorStore(Mutex<MemoryInner>);

impl MemoryKeyMirrorStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryInner>, StoreError> {
        self.0.lock().map_err(|_| StoreError("lock poisoned".into()))
    }
}

impl KeyMirrorStore for MemoryKeyMirrorStore {
    fn put(&self, key: MirroredApiKey) -> Result<(), StoreError> {
        self.lock()?.keys.insert(key.id.clone(), key);
        Ok(())
    }
    fn get(&self, id: &str) -> Result<Option<MirroredApiKey>, StoreError> {
        Ok(self.lock()?.keys.get(id).cloned())
    }
    fn get_by_hash(&self, hash: &str) -> Result<Option<MirroredApiKey>, StoreError> {
        Ok(self.lock()?.keys.values().find(|k| k.hash == hash).cloned())
    }
    fn mark_revoked(&self, id: &str, revoked_at: i64, reason: Option<&str>) -> Result<(), StoreError> {
        if let Some(k) = self.lock()?.keys.get_mut(id) {
            if k.revoked_at.is_none() {
                k.revoked_at = Some(revoked_at);
                if let Some(r) = reason {
                    k.revoked_reason = Some(r.to_string());
                }
            }
        }
        Ok(())
    }
    fn mark_membership_ended(&self, user_id: &str, organization_id: &str, revoked_at: i64) -> Result<bool, StoreError> {
        for k in self.lock()?.keys.values_mut() {
            if k.revoked_at.is_none() && k.subject_type == "user" && k.subject_id == user_id && k.organization_id.as_deref() == Some(organization_id) {
                k.revoked_at = Some(revoked_at);
                k.revoked_reason = Some("membership_ended".into());
            }
        }
        Ok(true)
    }
    fn cursor(&self) -> Result<Option<String>, StoreError> {
        Ok(self.lock()?.cursor.clone())
    }
    fn set_cursor(&self, cursor: &str) -> Result<(), StoreError> {
        self.lock()?.cursor = Some(cursor.to_string());
        Ok(())
    }
    fn last_sync_at(&self) -> Result<Option<i64>, StoreError> {
        Ok(self.lock()?.last_sync_at)
    }
    fn set_last_sync_at(&self, at: i64) -> Result<(), StoreError> {
        self.lock()?.last_sync_at = Some(at);
        Ok(())
    }
}

type MembershipFn = Arc<dyn Fn(&str, &str) -> Option<ApiKeyOrganization> + Send + Sync>;
type StaleHook = Arc<dyn Fn(Option<i64>, i64) + Send + Sync>;

/// Settings of a [`KeyMirror`].
#[derive(Clone, Default)]
pub struct KeyMirrorOptions {
    /// The instance scope implications (`auth_config.endUserApiKeys.scopeImplications`), so a local scope
    /// check matches Atlas verify. `*` as an implied scope means every scope in `allowed_scopes` plus both
    /// sides of the map.
    pub scope_implications: HashMap<String, Vec<String>>,
    pub allowed_scopes: Vec<String>,
    /// On a local miss, ask Atlas to verify the secret. Required for keys imported with a bcrypt or Argon2id
    /// hash, which cannot be checked locally; once Atlas accepts one, the mirror stores its sha256.
    pub verify_at_atlas: bool,
    /// When set, `verify` answers `Stale` if the mirror has never completed a `sync()` or the last one
    /// finished more than this many ms ago. `None` turns the check off (webhook-only mirrors).
    pub max_staleness_ms: Option<u64>,
    /// Keep answering for this many extra ms after `max_staleness_ms`, flagging `stale` (needs `max_staleness_ms`).
    pub serve_stale_for_ms: u64,
    /// Called each time an answer is served inside the grace, with `(last_sync_at, stale_for_ms)`.
    pub on_serve_stale: Option<StaleHook>,
    /// For a key bound to an organization: the user's CURRENT membership from your own data (`None`: no
    /// longer a member). Without it a bound key is verified at Atlas; with neither it answers
    /// `MembershipUnresolved`.
    pub membership: Option<MembershipFn>,
}

/// Why a verification said no, beyond a plain unknown / revoked / expired key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCode {
    InsufficientScope,
    IpNotAllowed,
    ClientIpRequired,
    MembershipUnresolved,
    // Refusals of a key-pair assertion, named as Atlas verify names them.
    InvalidAssertion,
    AssertionExpired,
    AssertionNotYetValid,
    WrongAudience,
    AssertionLifetimeTooLong,
    AssertionReplayed,
    ScopeNotGranted,
}

/// The answer of [`KeyMirror::verify`].
#[derive(Debug, Clone, PartialEq)]
pub enum MirrorVerification {
    Valid {
        key: MirroredApiKey,
        effective_scopes: Vec<String>,
        /// True when the mirror was past `max_staleness_ms` and this came from its last synced data.
        stale: bool,
        /// A bound key: the membership the scopes were narrowed by.
        organization: Option<ApiKeyOrganization>,
        /// `Some("key_pair")` after [`KeyMirror::verify_assertion`], with the assertion's `jti` and `exp` (epoch seconds).
        credential: Option<String>,
        jti: Option<String>,
        exp: Option<i64>,
    },
    Invalid { code: Option<InvalidCode>, missing_scopes: Vec<String> },
    /// The mirror is not fresh enough to answer. Retry after `sync()`.
    Stale { last_sync_at: Option<i64> },
}

impl MirrorVerification {
    pub fn is_valid(&self) -> bool {
        matches!(self, MirrorVerification::Valid { .. })
    }
    fn no() -> Self {
        MirrorVerification::Invalid { code: None, missing_scopes: Vec::new() }
    }
    fn code(c: InvalidCode) -> Self {
        MirrorVerification::Invalid { code: Some(c), missing_scopes: Vec::new() }
    }
}

/// An existing key to import: the full `secret`, or its `secret_hash`, or a bcrypt / Argon2id hash.
#[derive(Debug, Clone, Default)]
pub struct MirrorImport {
    /// The full existing secret (hashed here, never sent).
    pub secret: Option<String>,
    /// sha256 hex of the full secret.
    pub secret_hash: Option<String>,
    /// An existing bcrypt hash of the full secret (verified at Atlas on first use).
    pub bcrypt_hash: Option<String>,
    /// An existing Argon2id hash of the full secret (same).
    pub argon2id_hash: Option<String>,
    /// The public head shown in listings, e.g. the first 16 characters.
    pub prefix: String,
    /// The rest of the create body (`subject_type`, `subject_id`, `name`, `scopes`, ...).
    pub body: Map<String, Value>,
}

/// sha256 hex, the hash the mirror stores and Atlas imports as `sha256_hex`.
pub fn hash_api_key_secret(secret: &str) -> String {
    hex(&Sha256::digest(secret.as_bytes()))
}

/// Whether a permission covers a key scope: same name, `*`, or `<prefix>:*`. Mirrors Atlas verify.
pub fn permission_covers_scope(permission: &str, scope: &str) -> bool {
    if permission == scope || permission == "*" {
        return true;
    }
    permission.strip_suffix('*').is_some_and(|p| p.ends_with(':') && scope.starts_with(p))
}

/// The key scopes a membership's permissions cover: what Atlas returns as `effective_scopes` for a key
/// bound to an organization. Sorted.
pub fn intersect_scopes_with_permissions(scopes: &[String], permissions: &[String]) -> Vec<String> {
    let set: BTreeSet<&String> = scopes.iter().filter(|s| permissions.iter().any(|p| permission_covers_scope(p, s))).collect();
    set.into_iter().cloned().collect()
}

fn expand(held: &[String], implications: &HashMap<String, Vec<String>>, allowed: &[String]) -> Vec<String> {
    let mut vocab: BTreeSet<String> = allowed.iter().cloned().collect();
    for (from, tos) in implications {
        vocab.insert(from.clone());
        vocab.extend(tos.iter().filter(|t| *t != "*").cloned());
    }
    let mut out: BTreeSet<String> = held.iter().cloned().collect();
    let mut queue: Vec<String> = held.to_vec();
    while let Some(s) = queue.pop() {
        for to in implications.get(&s).into_iter().flatten() {
            let targets: Vec<String> = if to == "*" { vocab.iter().cloned().collect() } else { vec![to.clone()] };
            for t in targets {
                if out.insert(t.clone()) {
                    queue.push(t);
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Whether `ip` is inside one of the addresses / CIDR ranges. Unparseable input is never inside.
pub fn ip_in_allowlist(ip: &str, cidrs: &[String]) -> bool {
    let Ok(addr) = ip.trim().parse::<IpAddr>() else { return false };
    cidrs.iter().any(|entry| {
        let (base, bits) = match entry.trim().split_once('/') {
            Some((b, n)) => (b, n.parse::<u32>().ok()),
            None => (entry.trim(), None),
        };
        let Ok(net) = base.parse::<IpAddr>() else { return false };
        let (a, n, width): (u128, u128, u32) = match (addr, net) {
            (IpAddr::V4(a), IpAddr::V4(n)) => (u32::from(a) as u128, u32::from(n) as u128, 32),
            (IpAddr::V6(a), IpAddr::V6(n)) => (u128::from(a), u128::from(n), 128),
            _ => return false,
        };
        let bits = bits.unwrap_or(width);
        if bits > width {
            return false;
        }
        if bits == 0 {
            return true;
        }
        let shift = width - bits;
        (a >> shift) == (n >> shift)
    })
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn str_of(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn strings_of(v: &Value, k: &str) -> Option<Vec<String>> {
    v.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
}

fn to_mirrored(key: &Value, hash: String) -> Result<MirroredApiKey, MirrorError> {
    let id = str_of(key, "id").ok_or_else(|| MirrorError::Invalid("the API key has no id".into()))?;
    Ok(MirroredApiKey {
        id,
        hash,
        prefix: str_of(key, "prefix").unwrap_or_default(),
        subject_type: str_of(key, "subject_type").unwrap_or_default(),
        subject_id: str_of(key, "subject_id").unwrap_or_default(),
        name: str_of(key, "name"),
        scopes: strings_of(key, "scopes"),
        allowed_ips: strings_of(key, "allowed_ips"),
        expires_at: key.get("expires_at").and_then(Value::as_i64),
        revoked_at: key.get("revoked_at").and_then(Value::as_i64),
        organization_id: str_of(key, "organization_id"),
        revoked_reason: str_of(key, "revoked_reason"),
        enabled: key.get("enabled").and_then(Value::as_bool),
        credential: str_of(key, "credential").unwrap_or_else(|| "secret".into()),
        public_key_pem: str_of(key, "public_key"),
        audience: str_of(key, "audience"),
        max_token_lifetime_seconds: key.get("max_token_lifetime_seconds").and_then(Value::as_i64),
    })
}

/// The secret's sha256; a key-pair key has no secret, so its row carries a placeholder nothing can match.
fn key_hash(key: &Value) -> Result<String, MirrorError> {
    match (str_of(key, "secret"), str_of(key, "id")) {
        (Some(secret), _) => Ok(hash_api_key_secret(&secret)),
        (None, Some(id)) if str_of(key, "credential").as_deref() == Some("key_pair") => Ok(format!("key_pair:{id}")),
        _ => Err(MirrorError::Invalid("Atlas returned no secret".into())),
    }
}

fn org_of(v: &Value) -> Option<ApiKeyOrganization> {
    Some(ApiKeyOrganization { id: str_of(v, "id")?, role: str_of(v, "role").unwrap_or_default(), permissions: strings_of(v, "permissions").unwrap_or_default() })
}

/// The mirror. Cheap to share behind an `Arc`.
pub struct KeyMirror {
    store: Arc<dyn KeyMirrorStore>,
    client: BackendClient,
    opts: KeyMirrorOptions,
    now: Clock,
    memory_sync_at: Mutex<Option<i64>>,
    used_jtis: Mutex<HashMap<String, i64>>,
}

impl KeyMirror {
    /// `client` is the management client (secret key with the `api_keys` scopes).
    pub fn new(store: Arc<dyn KeyMirrorStore>, client: BackendClient, opts: KeyMirrorOptions) -> Self {
        KeyMirror { store, client, opts, now: system_clock(), memory_sync_at: Mutex::new(None), used_jtis: Mutex::new(HashMap::new()) }
    }

    /// Inject a clock (epoch ms), for tests.
    pub fn with_clock(mut self, now: Clock) -> Self {
        self.now = now;
        self
    }

    fn now_ms(&self) -> i64 {
        (self.now)() as i64
    }

    /// Epoch ms of the last completed `sync()`; `None`: never synced.
    pub fn last_sync_at(&self) -> Result<Option<i64>, MirrorError> {
        Ok(self.store.last_sync_at()?.or(*self.memory_sync_at.lock().unwrap()))
    }

    /// Mint at Atlas, then mirror it. Returns the create response, which carries the one-time `secret`.
    pub async fn mint(&self, body: Value, idempotency_key: Option<&str>) -> Result<Value, MirrorError> {
        let created = self.client.request_value_idem(HttpMethod::Post, "/v1/api_keys", &[], Some(body), idempotency_key).await?;
        self.store.put(to_mirrored(&created, key_hash(&created)?)?)?;
        Ok(created)
    }

    /// Rotate at Atlas, then mirror both sides: the successor is added, and the old key now ends at the end of
    /// the overlap (or is revoked at once when the overlap is 0). Returns the successor with its one-time `secret`.
    pub async fn rotate(&self, id: &str, body: Value, idempotency_key: Option<&str>) -> Result<Value, MirrorError> {
        let path = format!("/v1/api_keys/{}/rotate", encode_segment(id));
        let rotated = self.client.request_value_idem(HttpMethod::Post, &path, &[], Some(body), idempotency_key).await?;
        self.store.put(to_mirrored(&rotated, key_hash(&rotated)?)?)?;
        if let Some(old) = self.store.get(id)? {
            let prev = rotated.get("previous_key").cloned().unwrap_or(Value::Null);
            if prev.get("revoked").and_then(Value::as_bool) == Some(true) {
                self.store.mark_revoked(id, self.now_ms(), Some("rotated"))?;
            } else {
                let expires_at = prev.get("expires_at").and_then(Value::as_i64).or(old.expires_at);
                self.store.put(MirroredApiKey { expires_at, ..old })?;
            }
        }
        Ok(rotated)
    }

    /// Import an existing key so customers keep their secret: Atlas stores the hash, the mirror stores the
    /// same hash (a bcrypt / Argon2id import has no local sha256 yet; `verify` with `verify_at_atlas` fills
    /// it in on first use). Returns Atlas's answer, which carries `outcome` (`created` / `already_present`).
    pub async fn import(&self, input: MirrorImport, idempotency_key: Option<&str>) -> Result<Value, MirrorError> {
        let MirrorImport { secret, secret_hash, bcrypt_hash, argon2id_hash, prefix, mut body } = input;
        let legacy = bcrypt_hash.as_ref().map(|h| (h.clone(), "bcrypt")).or_else(|| argon2id_hash.as_ref().map(|h| (h.clone(), "argon2id")));
        let (hash_for_atlas, algorithm, local_hash) = match legacy {
            Some((h, alg)) => (h, alg, None),
            None => {
                let hash = secret_hash.map(|h| h.to_lowercase()).or_else(|| secret.as_deref().map(hash_api_key_secret));
                match hash.filter(|h| is_hex64(h)) {
                    Some(h) => (h.clone(), "sha256_hex", Some(h)),
                    None => return Err(MirrorError::Invalid("import needs the full `secret` or its `secret_hash` (64 lowercase hex characters of sha256).".into())),
                }
            }
        };
        body.insert("import".into(), json!({ "secret_hash": hash_for_atlas, "hash_algorithm": algorithm, "prefix": prefix }));
        let mut imported = self.client.request_value_idem(HttpMethod::Post, "/v1/api_keys", &[], Some(Value::Object(body)), idempotency_key).await?;
        let outcome = str_of(&imported, "outcome").unwrap_or_else(|| "created".into());
        let id = str_of(&imported, "id").ok_or_else(|| MirrorError::Invalid("Atlas returned no id".into()))?;
        match local_hash {
            Some(h) => self.store.put(to_mirrored(&imported, h)?)?,
            // A retry that answered already_present keeps a sha256 the mirror already learned.
            None => {
                if outcome != "already_present" || self.store.get(&id)?.is_none() {
                    self.store.put(to_mirrored(&imported, format!("legacy:{id}"))?)?;
                }
            }
        }
        imported["outcome"] = Value::String(outcome);
        Ok(imported)
    }

    /// Revoke LOCALLY first (the key stops working here at once), then at Atlas. A key Atlas already revoked or
    /// no longer knows (404 / 409) counts as revoked; any other Atlas error is returned after the local revoke,
    /// so retry it.
    pub async fn revoke(&self, id: &str) -> Result<(), MirrorError> {
        self.store.mark_revoked(id, self.now_ms(), None)?;
        match self.client.request_value(HttpMethod::Delete, &format!("/v1/api_keys/{}", encode_segment(id)), &[], None).await {
            Ok(_) => Ok(()),
            Err(BackendError::Api(e)) if e.status == 404 || e.status == 409 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn atlas_verify(&self, secret: &str, client_ip: Option<&str>) -> Result<Option<Value>, MirrorError> {
        let mut body = json!({ "secret": secret });
        if let Some(ip) = client_ip {
            body["client_ip"] = Value::String(ip.to_string());
        }
        let r = self.client.request_value(HttpMethod::Post, "/v1/api_keys/verify", &[], Some(body)).await?;
        Ok((r.get("valid").and_then(Value::as_bool) == Some(true)).then_some(r))
    }

    /// Verify a presented secret against the mirror (no network call unless `verify_at_atlas` applies).
    /// Unknown, revoked and expired keys all answer `Invalid`; a mirror that is not fresh (see
    /// `max_staleness_ms`) answers `Stale` instead.
    pub async fn verify(&self, secret: &str, required_scopes: &[String], client_ip: Option<&str>) -> Result<MirrorVerification, MirrorError> {
        if secret.is_empty() {
            return Ok(MirrorVerification::no());
        }
        let (refusal, served_stale) = self.check_fresh()?;
        if let Some(r) = refusal {
            return Ok(r);
        }
        let hash = hash_api_key_secret(secret);
        let mut key = self.store.get_by_hash(&hash)?;
        if key.is_none() && self.opts.verify_at_atlas {
            if let Some(remote) = self.atlas_verify(secret, client_ip).await? {
                if let Some(id) = str_of(&remote, "id") {
                    let full = self.client.request_value(HttpMethod::Get, &format!("/v1/api_keys/{}", encode_segment(&id)), &[], None).await?;
                    let k = to_mirrored(&full, hash)?;
                    self.store.put(k.clone())?;
                    key = Some(k);
                }
            }
        }
        let Some(key) = key else { return Ok(MirrorVerification::no()) };
        if key.revoked_at.is_some() || key.enabled == Some(false) {
            return Ok(MirrorVerification::no());
        }
        if key.expires_at.is_some_and(|e| e <= self.now_ms()) {
            return Ok(MirrorVerification::no());
        }
        // A key with allowed_ips needs the end caller's address; no address fails closed.
        if let Some(ips) = key.allowed_ips.as_ref().filter(|i| !i.is_empty()) {
            match client_ip {
                None | Some("") => return Ok(MirrorVerification::code(InvalidCode::ClientIpRequired)),
                Some(ip) if !ip_in_allowlist(ip, ips) => return Ok(MirrorVerification::code(InvalidCode::IpNotAllowed)),
                _ => {}
            }
        }
        let mut effective = expand(key.scopes.as_deref().unwrap_or(&[]), &self.opts.scope_implications, &self.opts.allowed_scopes);
        let mut organization = None;
        if let (true, Some(org_id)) = (key.subject_type == "user", key.organization_id.as_deref()) {
            // A bound key stands for the user's CURRENT membership; never answer from the key's own scopes.
            if let Some(f) = &self.opts.membership {
                let Some(held) = f(&key.subject_id, org_id) else { return Ok(MirrorVerification::no()) };
                effective = intersect_scopes_with_permissions(&effective, &held.permissions);
                organization = Some(held);
            } else if self.opts.verify_at_atlas {
                let Some(remote) = self.atlas_verify(secret, client_ip).await? else { return Ok(MirrorVerification::no()) };
                let Some(org) = remote.get("organization").and_then(org_of) else { return Ok(MirrorVerification::no()) };
                effective = strings_of(&remote, "effective_scopes").unwrap_or_default();
                organization = Some(org);
            } else {
                return Ok(MirrorVerification::code(InvalidCode::MembershipUnresolved));
            }
        }
        let missing: Vec<String> = required_scopes.iter().filter(|s| !effective.contains(s)).cloned().collect();
        if !missing.is_empty() {
            return Ok(MirrorVerification::Invalid { code: Some(InvalidCode::InsufficientScope), missing_scopes: missing });
        }
        Ok(MirrorVerification::Valid { key, effective_scopes: effective, stale: served_stale, organization, credential: None, jti: None, exp: None })
    }

    /// A refusal when the mirror is too stale to answer, and whether the answer is served stale.
    fn check_fresh(&self) -> Result<(Option<MirrorVerification>, bool), MirrorError> {
        let last = self.last_sync_at()?;
        Ok(match freshness(last, self.now_ms(), self.opts.max_staleness_ms, self.opts.serve_stale_for_ms) {
            Freshness::Fresh => (None, false),
            Freshness::Refuse => (Some(MirrorVerification::Stale { last_sync_at: last }), false),
            Freshness::ServedStale { behind_ms } => {
                if let Some(h) = &self.opts.on_serve_stale {
                    h(last, behind_ms);
                }
                (None, true)
            }
        })
    }

    /// Verify a key-pair assertion ([`crate::sign_api_key_assertion`]) locally with the checks Atlas verify makes: the
    /// signature with the stored public key (`alg` must fit its type), `iss` = `kid`, `aud`, `iat`, `exp` and the
    /// lifetime cap, `nbf`, `scope` (a subset of the key's, narrows the result), revocation, expiry, the IP allowlist,
    /// then the single-use `jti`. A refusal carries the server's code; a key the mirror does not hold answers `Invalid`
    /// with none. The `jti` is claimed through the store's optional `claim_assertion_jti`, else in this process's
    /// memory, and only after every other check passed.
    pub async fn verify_assertion(&self, token: &str, required_scopes: &[String], client_ip: Option<&str>) -> Result<MirrorVerification, MirrorError> {
        let (refusal, served_stale) = self.check_fresh()?;
        if let Some(r) = refusal {
            return Ok(r);
        }
        let bad = MirrorVerification::code;
        let parts: Vec<&str> = token.split('.').collect();
        let decoded: Option<(Value, Value)> = (parts.len() == 3)
            .then(|| {
                let h = serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?;
                let c = serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(parts[1]).ok()?).ok()?;
                (h.is_object() && c.is_object()).then_some((h, c))
            })
            .flatten();
        let Some((header, claims)) = decoded else { return Ok(bad(InvalidCode::InvalidAssertion)) };
        let Some(kid) = header.get("kid").and_then(Value::as_str).filter(|k| !k.is_empty()) else { return Ok(bad(InvalidCode::InvalidAssertion)) };
        let Some(key) = self.store.get(kid)? else { return Ok(MirrorVerification::no()) };
        let Some(pem) = key.public_key_pem.as_deref().filter(|_| key.credential == "key_pair") else { return Ok(bad(InvalidCode::InvalidAssertion)) };
        let decoding = match header.get("alg").and_then(Value::as_str) {
            Some("ES256") => DecodingKey::from_ec_pem(pem.as_bytes()).map(|k| (Algorithm::ES256, k)),
            Some("EdDSA") => DecodingKey::from_ed_pem(pem.as_bytes()).map(|k| (Algorithm::EdDSA, k)),
            _ => return Ok(bad(InvalidCode::InvalidAssertion)),
        };
        let signed = format!("{}.{}", parts[0], parts[1]);
        let verified = decoding
            .ok()
            .is_some_and(|(alg, k)| jsonwebtoken::crypto::verify(parts[2], signed.as_bytes(), &k, alg).unwrap_or(false));
        if !verified || claims.get("iss").and_then(Value::as_str) != Some(kid) || key.enabled == Some(false) {
            return Ok(bad(InvalidCode::InvalidAssertion));
        }
        let now_ms = self.now_ms();
        if key.revoked_at.is_some() || key.expires_at.is_some_and(|e| e <= now_ms) {
            return Ok(MirrorVerification::no());
        }
        let now_s = now_ms / 1000;
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => Some(a.as_str()) == key.audience.as_deref(),
            Some(Value::Array(list)) => list.iter().any(|a| a.as_str().is_some() && a.as_str() == key.audience.as_deref()),
            _ => false,
        };
        if !aud_ok {
            return Ok(bad(InvalidCode::WrongAudience));
        }
        let num = |k: &str| claims.get(k).and_then(Value::as_f64).map(|f| f.floor() as i64);
        let (iat, exp) = match (num("iat"), num("exp")) {
            (Some(i), Some(e)) => (i, e),
            _ => return Ok(bad(InvalidCode::InvalidAssertion)),
        };
        let nbf = num("nbf");
        let jti = claims.get("jti");
        let scope = claims.get("scope");
        if (claims.get("nbf").is_some() && nbf.is_none())
            || jti.is_some_and(|j| j.as_str().is_none_or(str::is_empty))
            || scope.is_some_and(|s| !s.is_string())
        {
            return Ok(bad(InvalidCode::InvalidAssertion));
        }
        if iat > now_s + 60 || nbf.is_some_and(|n| n > now_s + 60) {
            return Ok(bad(InvalidCode::AssertionNotYetValid));
        }
        if exp <= now_s - 30 {
            return Ok(bad(InvalidCode::AssertionExpired));
        }
        if exp - iat > key.max_token_lifetime_seconds.unwrap_or(3600).min(86400) {
            return Ok(bad(InvalidCode::AssertionLifetimeTooLong));
        }
        if let Some(ips) = key.allowed_ips.as_ref().filter(|i| !i.is_empty()) {
            match client_ip {
                None | Some("") => return Ok(bad(InvalidCode::ClientIpRequired)),
                Some(ip) if !ip_in_allowlist(ip, ips) => return Ok(bad(InvalidCode::IpNotAllowed)),
                _ => {}
            }
        }
        let mut effective = expand(key.scopes.as_deref().unwrap_or(&[]), &self.opts.scope_implications, &self.opts.allowed_scopes);
        let mut organization = None;
        if let (true, Some(org_id)) = (key.subject_type == "user", key.organization_id.as_deref()) {
            let Some(f) = &self.opts.membership else { return Ok(bad(InvalidCode::MembershipUnresolved)) };
            let Some(held) = f(&key.subject_id, org_id) else { return Ok(MirrorVerification::no()) };
            effective = intersect_scopes_with_permissions(&effective, &held.permissions);
            organization = Some(held);
        }
        if let Some(asked) = scope.and_then(Value::as_str).map(|s| s.split_whitespace().map(str::to_string).collect::<Vec<_>>()).filter(|a| !a.is_empty()) {
            let not_granted: Vec<String> = asked.iter().filter(|x| !effective.contains(x)).cloned().collect();
            if !not_granted.is_empty() {
                return Ok(MirrorVerification::Invalid { code: Some(InvalidCode::ScopeNotGranted), missing_scopes: not_granted });
            }
            effective.retain(|x| asked.contains(x));
        }
        let missing: Vec<String> = required_scopes.iter().filter(|x| !effective.contains(x)).cloned().collect();
        if !missing.is_empty() {
            return Ok(MirrorVerification::Invalid { code: Some(InvalidCode::InsufficientScope), missing_scopes: missing });
        }
        // Last, so a refused assertion never burns its jti.
        if let Some(j) = jti.and_then(Value::as_str) {
            let until = exp * 1000;
            let first = match self.store.claim_assertion_jti(&key.id, j, until)? {
                Some(first) => first,
                None => {
                    let mut used = self.used_jtis.lock().unwrap();
                    used.retain(|_, t| *t > now_ms);
                    used.insert(format!("{}\n{j}", key.id), until).is_none()
                }
            };
            if !first {
                return Ok(bad(InvalidCode::AssertionReplayed));
            }
        }
        Ok(MirrorVerification::Valid {
            key,
            effective_scopes: effective,
            stale: served_stale,
            organization,
            credential: Some("key_pair".into()),
            jti: jti.and_then(Value::as_str).map(str::to_string),
            exp: Some(exp),
        })
    }

    /// Consume the revocation feed (`GET /v1/api_keys/revoked`) from the stored cursor, revoking each listed
    /// key locally. Call it on a timer (every few seconds to a minute): a key revoked at Atlas is rejected
    /// here within one tick. Returns how many ids it applied.
    pub async fn sync(&self) -> Result<usize, MirrorError> {
        let mut since = self.store.cursor()?;
        let mut revoked = 0usize;
        loop {
            let mut query: Vec<(&str, String)> = vec![("limit", "100".into())];
            if let Some(s) = &since {
                query.push(("since", s.clone()));
            }
            let page = self.client.request_value(HttpMethod::Get, "/v1/api_keys/revoked", &query, None).await?;
            for r in page.get("data").and_then(Value::as_array).into_iter().flatten() {
                if let Some(id) = str_of(r, "id") {
                    let at = r.get("revoked_at").and_then(Value::as_i64).unwrap_or_else(|| self.now_ms());
                    self.store.mark_revoked(&id, at, str_of(r, "revoked_reason").as_deref())?;
                    revoked += 1;
                }
            }
            let next = str_of(&page, "next_cursor");
            if let Some(n) = &next {
                self.store.set_cursor(n)?;
                since = Some(n.clone());
            }
            if page.get("has_more").and_then(Value::as_bool) != Some(true) || next.is_none() {
                let at = self.now_ms();
                *self.memory_sync_at.lock().unwrap() = Some(at);
                self.store.set_last_sync_at(at)?;
                return Ok(revoked);
            }
        }
    }

    /// Apply a VERIFIED `api_key.*` webhook (check the signature first). `api_key.revoked` revokes locally;
    /// `api_key.restored` lifts a revocation a ban caused; `api_key.updated` refreshes name, scopes and expiry
    /// of a key the mirror holds. A key the mirror does not hold is ignored (mint / import adds it). Also
    /// handles `organization_membership.deleted`. Returns whether the event changed the mirror.
    pub fn apply_webhook(&self, event_type: &str, data: &Value) -> Result<bool, MirrorError> {
        if event_type == "organization_membership.deleted" || event_type == "organizationMembership.deleted" {
            return match (str_of(data, "user_id"), str_of(data, "organization_id")) {
                (Some(u), Some(o)) => Ok(self.store.mark_membership_ended(&u, &o, self.now_ms())?),
                _ => Ok(false),
            };
        }
        if !event_type.starts_with("api_key.") {
            return Ok(false);
        }
        let Some(id) = str_of(data, "id") else { return Ok(false) };
        let Some(held) = self.store.get(&id)? else { return Ok(false) };
        let opt_i64 = |k: &str| data.get(k).map(|v| v.as_i64());
        if event_type == "api_key.restored" {
            if held.revoked_at.is_none() {
                return Ok(false);
            }
            let expires_at = opt_i64("expires_at").unwrap_or(held.expires_at);
            self.store.put(MirroredApiKey { revoked_at: None, revoked_reason: None, expires_at, ..held })?;
            return Ok(true);
        }
        let data_revoked_at = data.get("revoked_at").and_then(Value::as_i64);
        if event_type == "api_key.revoked" || (data_revoked_at.is_some() && held.revoked_at.is_none()) {
            self.store.mark_revoked(&held.id, data_revoked_at.unwrap_or_else(|| self.now_ms()), str_of(data, "revoked_reason").as_deref())?;
            return Ok(true);
        }
        if event_type == "api_key.updated" || event_type == "api_key.created" {
            let updated = MirroredApiKey {
                name: if data.get("name").is_some() { str_of(data, "name") } else { held.name.clone() },
                scopes: if data.get("scopes").is_some() { strings_of(data, "scopes") } else { held.scopes.clone() },
                allowed_ips: if data.get("allowed_ips").is_some() { strings_of(data, "allowed_ips") } else { held.allowed_ips.clone() },
                expires_at: opt_i64("expires_at").unwrap_or(held.expires_at),
                enabled: data.get("enabled").and_then(Value::as_bool).or(held.enabled),
                ..held
            };
            self.store.put(updated)?;
            return Ok(true);
        }
        Ok(false)
    }
}
