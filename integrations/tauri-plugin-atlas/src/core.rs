//! The plugin's logic, free of Tauri types so it can be tested without a window.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlasauth::client::{
    exchange_for_session, parse_callback, AuthorizationRequest, NativeSessionManager, SecureStore, StoredSessionManager,
};
use atlasauth::{HttpMethod, HttpRequest, HttpTransport};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const STORE_KEY: &str = "atlas.session";

/// `plugins.atlas` in `tauri.conf.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// The instance's frontend API origin (the `iss` of its tokens).
    pub issuer: String,
    /// The instance publishable key (`pk_...`).
    pub publishable_key: String,
    /// Your first-party public OAuth client.
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// Loopback port for the redirect. 0 (default) picks a free one; register
    /// `http://127.0.0.1:<port>/callback` for the client when you pin a port.
    #[serde(default)]
    pub redirect_port: u16,
    /// Seconds to wait for the person to finish in the browser. Default 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Keychain service name. Default `atlas`.
    #[serde(default)]
    pub keychain_service: Option<String>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("atlas: {0}")]
    Config(String),
    #[error("atlas: sign-in failed: {0}")]
    SignIn(String),
    #[error("atlas: session: {0}")]
    Session(String),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub signed_in: bool,
    pub session_id: Option<String>,
}

/// Opens the system browser. Replaced in tests.
pub trait Opener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), String>;
}

pub struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, url: &str) -> Result<(), String> {
        open::that(url).map_err(|e| e.to_string())
    }
}

pub struct Atlas {
    config: Config,
    transport: Arc<dyn HttpTransport>,
    opener: Arc<dyn Opener>,
    manager: StoredSessionManager,
}

impl Atlas {
    /// `store` holds the session between launches: pass the OS keychain store in the app, memory in tests.
    pub fn new(
        config: Config,
        transport: Arc<dyn HttpTransport>,
        store: Arc<dyn SecureStore>,
        opener: Arc<dyn Opener>,
    ) -> Result<Self, Error> {
        let issuer = Url::parse(&config.issuer).map_err(|e| Error::Config(format!("bad issuer: {e}")))?;
        let local = matches!(issuer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if issuer.scheme() != "https" && !(local && issuer.scheme() == "http") {
            return Err(Error::Config("issuer must be an https URL".into()));
        }
        if config.publishable_key.is_empty() || config.client_id.is_empty() {
            return Err(Error::Config("publishableKey and clientId are required".into()));
        }
        let base = config.issuer.trim_end_matches('/').to_string();
        let manager = StoredSessionManager::new(
            store,
            STORE_KEY,
            NativeSessionManager::new(transport.clone(), base, config.publishable_key.clone()),
        );
        Ok(Atlas { config, transport, opener, manager })
    }

    /// Load a session saved by a previous run.
    pub async fn load(&self) {
        let _ = self.manager.load().await;
    }

    pub async fn status(&self) -> Status {
        let session = self.manager.current().await;
        Status { signed_in: session.is_some(), session_id: session.map(|s| s.session_id) }
    }

    /// A fresh session token, or `None` when signed out (or the session was refused and cleared).
    pub async fn token(&self) -> Option<String> {
        self.manager.get_token().await.ok()
    }

    pub async fn sign_out(&self) {
        let _ = self.manager.sign_out().await;
    }

    pub async fn sign_in(&self) -> Result<Status, Error> {
        let issuer = self.config.issuer.trim_end_matches('/').to_string();
        let (authorize, token) = self.discover(&issuer).await?;

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, self.config.redirect_port)))
            .map_err(|e| Error::SignIn(format!("could not listen for the redirect: {e}")))?;
        let port = listener.local_addr().map_err(|e| Error::SignIn(e.to_string()))?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");

        let state = random_state();
        let scope = self.config.scope.clone().unwrap_or_else(|| "openid profile email".into());
        let scopes: Vec<&str> = scope.split_whitespace().collect();
        let request = AuthorizationRequest::new(&authorize, &self.config.client_id, &redirect_uri, &scopes, state.clone())
            .map_err(|e| Error::SignIn(e.to_string()))?;

        self.opener.open(&request.authorization_url).map_err(|e| Error::SignIn(format!("could not open the browser: {e}")))?;

        let timeout = Duration::from_secs(self.config.timeout_secs.unwrap_or(300));
        let target = tokio::task::spawn_blocking(move || wait_for_callback(listener, port, timeout))
            .await
            .map_err(|e| Error::SignIn(e.to_string()))??;

        let params = parse_callback(&target).map_err(|e| Error::SignIn(e.to_string()))?;
        match params.state.as_deref() {
            Some(returned) if constant_time_eq(returned.as_bytes(), state.as_bytes()) => {}
            _ => return Err(Error::SignIn("the callback did not match the request".into())),
        }

        let tokens = request
            .exchange_code(&self.transport, &token, &self.config.client_id, &params.code)
            .await
            .map_err(|e| Error::SignIn(e.to_string()))?;
        let session = exchange_for_session(&self.transport, &issuer, &self.config.client_id, &tokens.access_token, None)
            .await
            .map_err(|e| Error::SignIn(e.to_string()))?;
        self.manager.set_session(session).await;
        Ok(self.status().await)
    }

    async fn discover(&self, issuer: &str) -> Result<(String, String), Error> {
        let resp = self
            .transport
            .send(HttpRequest::new(HttpMethod::Get, format!("{issuer}/.well-known/openid-configuration")).header("accept", "application/json"))
            .await
            .map_err(|e| Error::SignIn(e.to_string()))?;
        if !(200..300).contains(&resp.status) {
            return Err(Error::SignIn("could not load the sign-in configuration".into()));
        }
        let doc: serde_json::Value = serde_json::from_str(&resp.body).map_err(|_| Error::SignIn("the sign-in configuration was not JSON".into()))?;
        if doc["issuer"].as_str().map(|s| s.trim_end_matches('/')) != Some(issuer) {
            return Err(Error::SignIn("the sign-in configuration is for a different issuer".into()));
        }
        let origin = Url::parse(issuer).map_err(|e| Error::Config(e.to_string()))?.origin();
        let endpoint = |name: &str| -> Result<String, Error> {
            let raw = doc[name].as_str().ok_or_else(|| Error::SignIn(format!("the sign-in configuration has no {name}")))?;
            let url = Url::parse(raw).map_err(|_| Error::SignIn(format!("bad {name}")))?;
            // A code or token must never be sent to another origin than the issuer.
            if url.origin() != origin {
                return Err(Error::SignIn(format!("the {name} is not on the issuer's origin")));
            }
            Ok(raw.to_string())
        };
        Ok((endpoint("authorization_endpoint")?, endpoint("token_endpoint")?))
    }
}

fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Accept connections until one requests `/callback`; answer it with a small page; return the absolute URL.
fn wait_for_callback(listener: TcpListener, port: u16, timeout: Duration) -> Result<String, Error> {
    listener.set_nonblocking(true).map_err(|e| Error::SignIn(e.to_string()))?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::SignIn("timed out waiting for the browser".into()));
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(target) = handle(stream) {
                    return Ok(format!("http://127.0.0.1:{port}{target}"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(Error::SignIn(e.to_string())),
        }
    }
}

fn handle(mut stream: TcpStream) -> Option<String> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next()?, parts.next()?);
    let on_callback = method == "GET" && (target == "/callback" || target.starts_with("/callback?"));
    let (status, body) = if on_callback {
        ("200 OK", "<!doctype html><meta charset=utf-8><title>Signed in</title><p>You can close this window and return to the app.</p>")
    } else {
        ("404 Not Found", "")
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    on_callback.then(|| target.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlasauth::client::MemorySecureStore;
    use atlasauth::{BoxFuture, HttpResponse, TransportError};
    use std::sync::Mutex;

    const ISSUER: &str = "https://auth.example.com";

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<(String, String)>>,
        wrong_issuer: bool,
        foreign_endpoint: bool,
    }

    impl HttpTransport for Fake {
        fn send<'a>(&'a self, req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                let body = req.body.clone().unwrap_or_default();
                self.calls.lock().unwrap().push((req.url.clone(), body.clone()));
                let url = Url::parse(&req.url).unwrap();
                let (status, body) = match url.path() {
                    "/.well-known/openid-configuration" => {
                        let auth = if self.foreign_endpoint { "https://evil.example.com/oauth2/authorize" } else { "https://auth.example.com/oauth2/authorize" };
                        let iss = if self.wrong_issuer { "https://other.example.com" } else { ISSUER };
                        (200, format!(r#"{{"issuer":"{iss}","authorization_endpoint":"{auth}","token_endpoint":"{ISSUER}/oauth2/token"}}"#))
                    }
                    "/oauth2/token" if body.contains("grant_type=authorization_code") => (200, r#"{"access_token":"oat_1","token_type":"Bearer"}"#.to_string()),
                    "/oauth2/token" => (200, r#"{"access_token":"jwt_1","session_id":"sess_1","refresh_token":"r1","expires_in":60}"#.to_string()),
                    _ => (404, "{}".to_string()),
                };
                Ok(HttpResponse { status, body })
            })
        }
    }

    /// Plays the browser: follows the authorize URL by calling its redirect_uri on loopback.
    struct Browser {
        state: Option<&'static str>, // None = echo the real state
        query: &'static str,         // extra/override: "error" replaces the code
        silent: bool,
    }

    impl Opener for Browser {
        fn open(&self, url: &str) -> Result<(), String> {
            if self.silent {
                return Ok(());
            }
            let u = Url::parse(url).unwrap();
            let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
            let redirect = Url::parse(&q["redirect_uri"]).unwrap();
            let state = self.state.map(str::to_string).unwrap_or_else(|| q["state"].clone());
            let path = if self.query == "error" { format!("/callback?error=access_denied&state={state}") } else { format!("/callback?code=abc&state={state}") };
            let port = redirect.port().unwrap();
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
                let _ = write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
            });
            Ok(())
        }
    }

    fn config(timeout: Option<u64>) -> Config {
        Config {
            issuer: ISSUER.into(),
            publishable_key: "pk_test_1".into(),
            client_id: "client_1".into(),
            scope: None,
            redirect_port: 0,
            timeout_secs: timeout,
            keychain_service: None,
        }
    }

    fn atlas(fake: Fake, browser: Browser, timeout: Option<u64>) -> (Atlas, Arc<MemorySecureStore>, Arc<Fake>) {
        let fake = Arc::new(fake);
        let store = Arc::new(MemorySecureStore::new());
        let a = Atlas::new(config(timeout), fake.clone(), store.clone(), Arc::new(browser)).unwrap();
        (a, store, fake)
    }

    fn browser() -> Browser {
        Browser { state: None, query: "", silent: false }
    }

    #[tokio::test]
    async fn sign_in_runs_pkce_code_then_the_session_exchange_and_persists_the_session() {
        let (a, store, fake) = atlas(Fake::default(), browser(), None);
        let status = a.sign_in().await.unwrap();
        assert_eq!(status, Status { signed_in: true, session_id: Some("sess_1".into()) });
        assert_eq!(a.token().await.as_deref(), Some("jwt_1"));
        assert!(store.get(STORE_KEY).unwrap().is_some());
        let calls = fake.calls.lock().unwrap();
        let code_call = calls.iter().find(|(_, b)| b.contains("grant_type=authorization_code")).unwrap();
        assert!(code_call.1.contains("code=abc") && code_call.1.contains("code_verifier="));
        assert!(calls.iter().any(|(_, b)| b.contains("subject_token=oat_1")));
    }

    #[tokio::test]
    async fn a_forged_state_an_error_callback_and_silence_are_all_refused() {
        let (a, store, _) = atlas(Fake::default(), Browser { state: Some("forged"), query: "", silent: false }, None);
        assert!(a.sign_in().await.is_err());
        assert!(!a.status().await.signed_in && store.get(STORE_KEY).unwrap().is_none());

        let (a, ..) = atlas(Fake::default(), Browser { state: None, query: "error", silent: false }, None);
        assert!(a.sign_in().await.is_err());

        let (a, ..) = atlas(Fake::default(), Browser { state: None, query: "", silent: true }, Some(1));
        assert!(matches!(a.sign_in().await, Err(Error::SignIn(m)) if m.contains("timed out")));
    }

    #[tokio::test]
    async fn discovery_for_another_issuer_or_on_another_origin_is_refused_before_the_browser_opens() {
        for fake in [Fake { wrong_issuer: true, ..Default::default() }, Fake { foreign_endpoint: true, ..Default::default() }] {
            let (a, ..) = atlas(fake, Browser { state: None, query: "", silent: true }, Some(1));
            let err = a.sign_in().await.unwrap_err().to_string();
            assert!(!err.contains("timed out"), "should fail at discovery: {err}");
        }
    }

    #[tokio::test]
    async fn sign_out_forgets_the_session() {
        let (a, ..) = atlas(Fake::default(), browser(), None);
        a.sign_in().await.unwrap();
        a.sign_out().await;
        assert!(!a.status().await.signed_in);
        assert_eq!(a.token().await, None);
    }

    #[test]
    fn config_must_be_https_and_complete() {
        let fake: Arc<dyn HttpTransport> = Arc::new(Fake::default());
        let store: Arc<dyn SecureStore> = Arc::new(MemorySecureStore::new());
        let open: Arc<dyn Opener> = Arc::new(SystemOpener);
        let mut c = config(None);
        c.issuer = "http://auth.example.com".into();
        assert!(Atlas::new(c, fake.clone(), store.clone(), open.clone()).is_err());
        let mut c = config(None);
        c.client_id = String::new();
        assert!(Atlas::new(c, fake, store, open).is_err());
    }
}
