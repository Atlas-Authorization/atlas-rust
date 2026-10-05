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

// ── platform keychain backend ───────────────────────────────────────────────
//
// One `keyring`-backed impl serves all three platforms — the crate's API is
// identical across them — so availability, not code, differs by target. Each
// platform feature enables the store only on its matching OS, which is also why
// `--all-features` on one host compiles just that host's backend.

#[cfg(any(
    all(feature = "keychain", target_os = "macos"),
    all(feature = "dpapi", target_os = "windows"),
    all(feature = "libsecret", target_os = "linux")
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
    all(feature = "keychain", target_os = "macos"),
    all(feature = "dpapi", target_os = "windows"),
    all(feature = "libsecret", target_os = "linux")
))]
pub use keyring_backend::KeyringSecureStore;
