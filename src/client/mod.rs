//! # P0-1 — the native (first-party) client SDK
//!
//! Everything a native app — a desktop binary, a CLI, a mobile runtime — needs
//! to authenticate a user with Atlas without a browser cookie jar:
//!
//! * [`Pkce`] + [`AuthorizationRequest`] — the PKCE S256 authorization-code flow
//!   (loopback redirect or custom-scheme callback), plus [`parse_callback`].
//! * [`request_device_code`] / [`poll_device_token`] — the RFC 8628 device flow.
//! * [`exchange_for_session`] — the RFC 8693 OAuth→session exchange.
//! * [`NativeSessionManager`] — a lazy, single-flight session that keeps the JWT
//!   live and surfaces the four typed [`RefreshRefusal`] codes.
//! * [`SecureStore`] — a secret store for the rotating refresh token, with a
//!   default in-memory impl and platform keychain backends behind sub-features.
//! * [`SelfServiceClient`] — the typed `/v1/client/me/**` self-service surface.
//!
//! The flows are built on the object-safe [`crate::HttpTransport`], so the same
//! code runs against the reqwest default or an injected mock in tests.

mod error;
mod native_session;
mod oauth;
mod pkce;
mod revocation;
mod self_service;
mod store;

#[cfg(feature = "machine")]
mod machine;

pub use error::{DevicePollError, OAuthError, RefreshRefusal, SessionError};
pub use native_session::{
    exchange_for_session, refresh_native_session, NativeSession, NativeSessionListener,
    NativeSessionManager, RefusalListener, REFRESH_LEAD_MS,
};
pub use oauth::{
    parse_callback, poll_device_token, request_device_code, AuthorizationRequest, CallbackParams,
    DeviceAuthorization, TokenResponse,
};
pub use pkce::Pkce;
pub use revocation::{
    token_key_id, ApiKeyToken, ApiKeyTokenClient, ApiKeyTokenError, DenyList, MintOptions,
    PollResult, RevokedKeyPoller, TokenAuth,
};
pub use self_service::{
    ApiTokenRecord, BearerSource, ClientApiError, ClientSession, List, MfaFactor, OAuthGrant,
    OrganizationMembership, Passkey, SelfServiceClient, StaticBearer, TrustedDevice, UserProfile,
};
pub use store::{CallbackSecureStore, MemorySecureStore, SecureStore, SecureStoreError};

#[cfg(feature = "encrypted-file")]
pub use store::EncryptedFileStore;

#[cfg(feature = "machine")]
pub use machine::{
    Challenge, Enrollment, MachineClient, MachineError, MachineKeypair, MachineToken,
    MachineTokenManager, MACHINE_REFRESH_LEAD_MS,
};

#[cfg(any(
    all(feature = "keychain", any(target_os = "macos", target_os = "ios")),
    all(feature = "dpapi", target_os = "windows"),
    all(feature = "libsecret", target_os = "linux"),
    all(feature = "linux-keyutils", target_os = "linux")
))]
pub use store::KeyringSecureStore;
