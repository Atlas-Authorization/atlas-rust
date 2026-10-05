//! A `SecureStore` for the rotating refresh token.
//!
//! A native app must persist the refresh token across restarts, but a plaintext
//! file is a credential-theft primitive. The platform secret stores exist for
//! exactly this — the macOS Keychain, the Windows Credential Manager (DPAPI),
//! and the Linux Secret Service (libsecret) — so this exposes a tiny trait and
//! gates a real backend for each behind its own feature AND its target, so the
//! crate still builds on any one platform. A default in-memory store makes tests
//! (and a deliberately-ephemeral session) need no OS integration.

/// A minimal secret key/value store. Synchronous — the platform keychains are
/// blocking, and a refresh-token read happens once at startup, not on a hot
/// path. Errors are coarse strings: a caller either has the secret or does not.
pub trait SecureStore: Send + Sync {
    /// Fetch a stored secret, or `None` when absent.
    fn get(&self, key: &str) -> Result<Option<String>, SecureStoreError>;
    /// Store (or overwrite) a secret.
    fn set(&self, key: &str, value: &str) -> Result<(), SecureStoreError>;
    /// Delete a secret. Deleting an absent key is not an error.
    fn delete(&self, key: &str) -> Result<(), SecureStoreError>;
}

/// A secure-store failure — the backend was unreachable or refused.
#[derive(Debug, Clone, thiserror::Error)]
#[error("atlas secure store: {0}")]
pub struct SecureStoreError(pub String);

/// An in-memory [`SecureStore`]. The default for tests and for a session that is
/// deliberately not persisted (it lives only as long as the process). NOT
/// durable and NOT encrypted — never the choice for a real refresh token.
#[derive(Default)]
pub struct MemorySecureStore {
    map: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl MemorySecureStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecureStore for MemorySecureStore {
    fn get(&self, key: &str) -> Result<Option<String>, SecureStoreError> {
        Ok(self.map.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &str) -> Result<(), SecureStoreError> {
        self.map.lock().unwrap().insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), SecureStoreError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
}

// ── host-callback backend (the Android / custom-platform hook) ────────────────
//
// Not every target has a Rust-native secret store. Android's credential store is
// the Android Keystore, reached through the Java/Kotlin layer over JNI; iOS apps
// built in Swift may already own a Keychain wrapper. Rather than bind to a
// specific FFI here (and give up `#![forbid(unsafe_code)]`), the SDK exposes a
// store whose three operations are CLOSURES the host supplies — the documented
// trait hook. On Android the host wires these to `EncryptedSharedPreferences` /
// the Keystore via JNI; on any platform a host can delegate to whatever secret
// store it already trusts. It is pure Rust, so it compiles (and is testable) on
// every target.

type GetFn = Arc<dyn Fn(&str) -> Result<Option<String>, SecureStoreError> + Send + Sync>;
type SetFn = Arc<dyn Fn(&str, &str) -> Result<(), SecureStoreError> + Send + Sync>;
type DeleteFn = Arc<dyn Fn(&str) -> Result<(), SecureStoreError> + Send + Sync>;

use std::sync::Arc;

/// A [`SecureStore`] that delegates to host-provided closures.
///
/// This is the designated store for **Android** (host closures call the Android
/// Keystore / `EncryptedSharedPreferences` through JNI) and for any platform
/// without a built-in backend. Build it with [`CallbackSecureStore::new`].
///
/// ```no_run
/// # use atlasauth::client::{CallbackSecureStore, SecureStore, SecureStoreError};
/// let store = CallbackSecureStore::new(
///     |key| { /* read from the host keystore */ Ok(None) },
///     |key, value| { /* write */ Ok(()) },
///     |key| { /* delete */ Ok(()) },
/// );
/// # let _: &dyn SecureStore = &store;
/// ```
#[derive(Clone)]
pub struct CallbackSecureStore {
    get: GetFn,
    set: SetFn,
    delete: DeleteFn,
}

impl CallbackSecureStore {
    /// Build a store from `get` / `set` / `delete` closures. `get` returns `None`
    /// for an absent key; `delete` of an absent key must not be an error.
    pub fn new(
        get: impl Fn(&str) -> Result<Option<String>, SecureStoreError> + Send + Sync + 'static,
        set: impl Fn(&str, &str) -> Result<(), SecureStoreError> + Send + Sync + 'static,
        delete: impl Fn(&str) -> Result<(), SecureStoreError> + Send + Sync + 'static,
    ) -> Self {
        CallbackSecureStore {
            get: Arc::new(get),
            set: Arc::new(set),
            delete: Arc::new(delete),
        }
    }
}

impl SecureStore for CallbackSecureStore {
    fn get(&self, key: &str) -> Result<Option<String>, SecureStoreError> {
        (self.get)(key)
    }
    fn set(&self, key: &str, value: &str) -> Result<(), SecureStoreError> {
        (self.set)(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), SecureStoreError> {
        (self.delete)(key)
    }
}

// ── platform keychain backend ───────────────────────────────────────────────
//
// One `keyring`-backed impl serves all three platforms — the crate's API is
// identical across them — so availability, not code, differs by target. Each
// platform feature enables the store only on its matching OS, which is also why
// `--all-features` on one host compiles just that host's backend.

#[cfg(any(
    all(feature = "keychain", any(target_os = "macos", target_os = "ios")),
    all(feature = "dpapi", target_os = "windows"),
    all(feature = "libsecret", target_os = "linux"),
    all(feature = "linux-keyutils", target_os = "linux")
))]
mod keyring_backend {
    use super::{SecureStore, SecureStoreError};

    /// A [`SecureStore`] backed by the OS secret store via the `keyring` crate:
    /// the macOS Keychain, the Windows Credential Manager (DPAPI), or the Linux
    /// Secret Service (libsecret). Secrets are namespaced under a service name so
    /// one app's tokens never collide with another's.
    pub struct KeyringSecureStore {
        service: String,
    }

    impl KeyringSecureStore {
        /// Build a store that namespaces secrets under `service` (e.g. your app
        /// id, `"com.acme.app"`).
        pub fn new(service: impl Into<String>) -> Self {
            KeyringSecureStore {
                service: service.into(),
            }
        }

        fn entry(&self, key: &str) -> Result<keyring::Entry, SecureStoreError> {
            keyring::Entry::new(&self.service, key).map_err(|e| SecureStoreError(e.to_string()))
        }
    }

    impl SecureStore for KeyringSecureStore {
        fn get(&self, key: &str) -> Result<Option<String>, SecureStoreError> {
            match self.entry(key)?.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(SecureStoreError(e.to_string())),
            }
        }
        fn set(&self, key: &str, value: &str) -> Result<(), SecureStoreError> {
            self.entry(key)?
                .set_password(value)
                .map_err(|e| SecureStoreError(e.to_string()))
        }
        fn delete(&self, key: &str) -> Result<(), SecureStoreError> {
            match self.entry(key)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(SecureStoreError(e.to_string())),
            }
        }
    }
}

#[cfg(any(
    all(feature = "keychain", any(target_os = "macos", target_os = "ios")),
    all(feature = "dpapi", target_os = "windows"),
    all(feature = "libsecret", target_os = "linux"),
    all(feature = "linux-keyutils", target_os = "linux")
))]
pub use keyring_backend::KeyringSecureStore;

// ── encrypted-file backend (portable, no OS keychain, no dbus) ────────────────

/// A cross-platform encrypted-file [`SecureStore`]. See the module-level docs on
/// [`EncryptedFileStore`]. Behind the `encrypted-file` feature.
#[cfg(feature = "encrypted-file")]
mod encrypted_file {
    use super::{SecureStore, SecureStoreError};
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use base64::Engine;
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    use hkdf::Hkdf;
    use rand::RngCore;
    use sha2::Sha256;

    const MAGIC: &str = "atlas-efs-v1";
    const SALT_LEN: usize = 16;
    const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce

    /// An encrypted key/value [`SecureStore`] persisted to a single file.
    ///
    /// Every secret lives in one JSON map, sealed with **XChaCha20-Poly1305**
    /// under a 256-bit key derived with **HKDF-SHA256** from a caller-supplied
    /// passphrase or machine key plus a random per-file salt. It needs no OS
    /// keychain and no dbus, so it is the portable fallback on a headless Linux
    /// box (where neither the Secret Service nor a desktop keyring is available)
    /// and on any platform for a deliberately self-contained credential file.
    ///
    /// The encryption is only as strong as the key material: pass a
    /// high-entropy **machine key** (e.g. derived from a TPM/enclave secret or a
    /// random value stored with OS file permissions), not a short human password
    /// — HKDF is a key-derivation function, not a password hash, and applies no
    /// work factor. Secrets are held decrypted in memory while the store is
    /// alive, and re-sealed with a fresh nonce on every write.
    pub struct EncryptedFileStore {
        path: PathBuf,
        cipher: XChaCha20Poly1305,
        salt: [u8; SALT_LEN],
        cache: Mutex<HashMap<String, String>>,
    }

    impl EncryptedFileStore {
        /// Open (or create) an encrypted store at `path`, keyed by `key_material`.
        ///
        /// If the file exists it is decrypted with a key derived from the file's
        /// own stored salt; wrong key material fails the AEAD tag and returns an
        /// error (never silent corruption). If it does not exist, a fresh random
        /// salt is generated and the file is created empty on the first write.
        pub fn open(
            path: impl AsRef<Path>,
            key_material: &[u8],
        ) -> Result<Self, SecureStoreError> {
            let path = path.as_ref().to_path_buf();
            if path.exists() {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| SecureStoreError(format!("read {}: {e}", path.display())))?;
                let (salt, nonce, ct) = parse_envelope(&raw)?;
                let cipher = derive_cipher(key_material, &salt);
                let plain = cipher
                    .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
                    .map_err(|_| {
                        SecureStoreError("decryption failed: wrong key or corrupt file".into())
                    })?;
                let cache: HashMap<String, String> = serde_json::from_slice(&plain)
                    .map_err(|e| SecureStoreError(format!("decode store: {e}")))?;
                Ok(EncryptedFileStore {
                    path,
                    cipher,
                    salt,
                    cache: Mutex::new(cache),
                })
            } else {
                let mut salt = [0u8; SALT_LEN];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let cipher = derive_cipher(key_material, &salt);
                Ok(EncryptedFileStore {
                    path,
                    cipher,
                    salt,
                    cache: Mutex::new(HashMap::new()),
                })
            }
        }

        /// Re-seal the in-memory map to disk with a fresh random nonce.
        fn flush(&self, cache: &HashMap<String, String>) -> Result<(), SecureStoreError> {
            let plain = serde_json::to_vec(cache)
                .map_err(|e| SecureStoreError(format!("encode store: {e}")))?;
            let mut nonce = [0u8; NONCE_LEN];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let ct = self
                .cipher
                .encrypt(XNonce::from_slice(&nonce), plain.as_ref())
                .map_err(|_| SecureStoreError("encryption failed".into()))?;
            let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
            let envelope = format!(
                "{MAGIC}\n{}\n{}\n{}\n",
                b64.encode(self.salt),
                b64.encode(nonce),
                b64.encode(ct)
            );
            std::fs::write(&self.path, envelope)
                .map_err(|e| SecureStoreError(format!("write {}: {e}", self.path.display())))
        }
    }

    fn derive_cipher(key_material: &[u8], salt: &[u8]) -> XChaCha20Poly1305 {
        let hk = Hkdf::<Sha256>::new(Some(salt), key_material);
        let mut key = [0u8; 32];
        // The only failure is an invalid output length; 32 is always valid.
        hk.expand(b"atlas secure store key", &mut key)
            .expect("HKDF expand of 32 bytes");
        XChaCha20Poly1305::new((&key).into())
    }

    fn parse_envelope(raw: &str) -> Result<([u8; SALT_LEN], Vec<u8>, Vec<u8>), SecureStoreError> {
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
        let mut lines = raw.lines();
        let magic = lines.next().unwrap_or_default();
        if magic != MAGIC {
            return Err(SecureStoreError("not an atlas encrypted store".into()));
        }
        let mut next = || -> Result<Vec<u8>, SecureStoreError> {
            let line = lines
                .next()
                .ok_or_else(|| SecureStoreError("truncated store file".into()))?;
            b64.decode(line.trim())
                .map_err(|e| SecureStoreError(format!("corrupt store field: {e}")))
        };
        let salt_v = next()?;
        let nonce = next()?;
        let ct = next()?;
        let salt: [u8; SALT_LEN] = salt_v
            .try_into()
            .map_err(|_| SecureStoreError("bad salt length".into()))?;
        Ok((salt, nonce, ct))
    }

    impl SecureStore for EncryptedFileStore {
        fn get(&self, key: &str) -> Result<Option<String>, SecureStoreError> {
            Ok(self.cache.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &str) -> Result<(), SecureStoreError> {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(key.to_string(), value.to_string());
            self.flush(&cache)
        }
        fn delete(&self, key: &str) -> Result<(), SecureStoreError> {
            let mut cache = self.cache.lock().unwrap();
            if cache.remove(key).is_some() {
                self.flush(&cache)?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "encrypted-file")]
pub use encrypted_file::EncryptedFileStore;
