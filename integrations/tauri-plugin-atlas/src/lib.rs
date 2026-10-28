//! # tauri-plugin-atlas
//!
//! Atlas for Tauri 2: the hosted sign-in runs in the system browser with PKCE and a loopback redirect
//! (RFC 8252), the OAuth access token is traded for an Atlas session, the rotating refresh token lives in
//! the OS keychain, and `getToken()` hands your frontend a fresh session token for calls to your API.
//! The API verifies that token with a server SDK.
//!
//! ```ignore
//! tauri::Builder::default().plugin(tauri_plugin_atlas::init())
//! ```
//!
//! ```json
//! { "plugins": { "atlas": { "issuer": "https://auth.example.com", "publishableKey": "pk_live_...", "clientId": "..." } } }
//! ```

mod core;

use std::sync::Arc;

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime, State};

pub use crate::core::{Config, Error, Status};
use crate::core::{Atlas, SystemOpener};

impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

#[tauri::command]
async fn sign_in(atlas: State<'_, Arc<Atlas>>) -> Result<Status, Error> {
    atlas.sign_in().await
}

#[tauri::command]
async fn get_token(atlas: State<'_, Arc<Atlas>>) -> Result<Option<String>, Error> {
    Ok(atlas.token().await)
}

#[tauri::command]
async fn status(atlas: State<'_, Arc<Atlas>>) -> Result<Status, Error> {
    Ok(atlas.status().await)
}

#[tauri::command]
async fn sign_out(atlas: State<'_, Arc<Atlas>>) -> Result<(), Error> {
    atlas.sign_out().await;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn secure_store(service: &str) -> Arc<dyn atlasauth::client::SecureStore> {
    Arc::new(atlasauth::client::KeyringSecureStore::new(service))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn secure_store(_service: &str) -> Arc<dyn atlasauth::client::SecureStore> {
    // No keychain on this target: the session lives for the process only.
    Arc::new(atlasauth::client::MemorySecureStore::new())
}

/// The plugin. Reads `plugins.atlas` from `tauri.conf.json`.
pub fn init<R: Runtime>() -> TauriPlugin<R, Config> {
    Builder::<R, Config>::new("atlas")
        .invoke_handler(tauri::generate_handler![sign_in, get_token, status, sign_out])
        .setup(|app, api| {
            let config = api.config().clone();
            let service = config.keychain_service.clone().unwrap_or_else(|| "atlas".into());
            let atlas = Atlas::new(
                config,
                Arc::new(atlasauth::ReqwestTransport::new()),
                secure_store(&service),
                Arc::new(SystemOpener),
            )
            .map_err(|e| e.to_string())?;
            let atlas = Arc::new(atlas);
            let loader = atlas.clone();
            tauri::async_runtime::spawn(async move { loader.load().await });
            app.manage(atlas);
            Ok(())
        })
        .build()
}
