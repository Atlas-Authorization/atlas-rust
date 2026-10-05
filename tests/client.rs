//! Hermetic tests for the `client` feature — PKCE derivation, the native-session
//! refusal-code mapping, the in-memory SecureStore round-trip, and the session
//! manager's lazy refresh over a fake transport. No network.
//!
//! Reuses the backend feature's `FakeTransport`, so it is gated on both.
#![cfg(all(feature = "client", feature = "backend"))]

use std::sync::Arc;

use atlasauth::client::{
    exchange_for_session, refresh_native_session, MemorySecureStore, NativeSession,
    NativeSessionManager, Pkce, RefreshRefusal, SecureStore, SessionError,
};
use atlasauth::backend::FakeTransport;
use atlasauth::{Clock, HttpRequest, HttpResponse, HttpTransport};

#[test]
fn pkce_s256_matches_the_rfc_7636_test_vector() {
    // RFC 7636 Appendix B: verifier → S256 challenge.
    let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(pkce.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assert_eq!(pkce.method(), "S256");

    // A generated pair round-trips: deriving from its own verifier reproduces
    // the challenge, and the verifier is the RFC-recommended 43 chars.
    let gen = Pkce::generate();
    assert_eq!(gen.verifier().len(), 43);
    assert_eq!(Pkce::from_verifier(gen.verifier()).challenge(), gen.challenge());
}

#[test]
fn secure_store_in_memory_round_trips() {
    let store = MemorySecureStore::new();
    assert_eq!(store.get("refresh").unwrap(), None);

    store.set("refresh", "rt_abc").unwrap();
    assert_eq!(store.get("refresh").unwrap().as_deref(), Some("rt_abc"));

    // Overwrite, then delete; delete of an absent key is not an error.
    store.set("refresh", "rt_def").unwrap();
    assert_eq!(store.get("refresh").unwrap().as_deref(), Some("rt_def"));
    store.delete("refresh").unwrap();
    assert_eq!(store.get("refresh").unwrap(), None);
    store.delete("refresh").unwrap();
}

/// A transport that always answers with one canned response.
fn canned(status: u16, body: &str) -> Arc<dyn HttpTransport> {
    let body = body.to_string();
    Arc::new(FakeTransport::new(move |_req: &HttpRequest| HttpResponse {
        status,
        body: body.clone(),
    }))
}

#[tokio::test]
async fn refresh_maps_each_refusal_code() {
    let base = "https://fapi.acme.atlasauth.net";
    let cases = [
        ("SESSION_REVOKED", RefreshRefusal::SessionRevoked),
        ("SESSION_IDLE_EXPIRED", RefreshRefusal::SessionIdleExpired),
        ("SESSION_EXPIRED", RefreshRefusal::SessionExpired),
        ("REFRESH_REUSE_DETECTED", RefreshRefusal::RefreshReuseDetected),
    ];
    for (code, expected) in cases {
        let transport = canned(401, &format!(r#"{{"errors":[{{"code":"{code}"}}]}}"#));
        let err = refresh_native_session(&transport, base, "pk_test", "sess_1", "rt_old")
            .await
            .unwrap_err();
        match err {
            SessionError::Refused(r) => assert_eq!(r, expected, "code {code}"),
            other => panic!("expected Refused({expected:?}) for {code}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn refresh_rotates_the_token_on_success() {
    let base = "https://fapi.acme.atlasauth.net";
    let transport = canned(
        200,
        r#"{"object":"session","jwt":"jwt_new","refresh_token":"rt_new","session_id":"sess_1","expires_in":60}"#,
    );
    let rotated = refresh_native_session(&transport, base, "pk_test", "sess_1", "rt_old")
        .await
        .expect("refresh");
    assert_eq!(rotated.session_token, "jwt_new");
    assert_eq!(rotated.refresh_token, "rt_new"); // rotated away from rt_old
    assert_eq!(rotated.session_id, "sess_1");
}

#[tokio::test]
async fn exchange_for_session_parses_the_token_exchange_response() {
    let base = "https://fapi.acme.atlasauth.net";
    let transport = canned(
        200,
        r#"{"access_token":"jwt_1","refresh_token":"rt_1","session_id":"sess_42","expires_in":60}"#,
    );
    let session = exchange_for_session(&transport, base, "client_abc", "oauth_at", Some("Ada's laptop"))
        .await
        .expect("exchange");
    assert_eq!(session.session_token, "jwt_1");
    assert_eq!(session.session_id, "sess_42");
    assert_eq!(session.expires_in_seconds, 60);
}

#[tokio::test]
async fn manager_refreshes_lazily_and_notifies_listeners() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    // A controllable clock so expiry is deterministic.
    let now_ms = Arc::new(AtomicU64::new(1_000_000));
    let clock: Clock = {
        let n = now_ms.clone();
        Arc::new(move || n.load(Ordering::SeqCst))
    };

    let transport = canned(
        200,
        r#"{"object":"session","jwt":"jwt_rotated","refresh_token":"rt_rotated","session_id":"sess_1","expires_in":60}"#,
    );
    let manager = NativeSessionManager::new(transport, "https://fapi.acme.atlasauth.net", "pk_test")
        .with_clock(clock);

    // Record each rotation a secure store would persist.
    let persisted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let p = persisted.clone();
        manager.on_change(Arc::new(move |s: &NativeSession| {
            p.lock().unwrap().push(s.refresh_token.clone());
        }));
    }

    // Seed a session that still has ~60s of life: get_token returns it, no refresh.
    manager
        .seed(NativeSession {
            session_token: "jwt_seed".into(),
            refresh_token: "rt_seed".into(),
            session_id: "sess_1".into(),
            expires_in_seconds: 60,
        })
        .await;
    assert_eq!(manager.get_token().await.as_deref(), Some("jwt_seed"));
    assert!(persisted.lock().unwrap().is_empty(), "no refresh yet");

    // Advance the clock to inside the refresh lead: get_token now rotates.
    now_ms.fetch_add(60_000, Ordering::SeqCst);
    assert_eq!(manager.get_token().await.as_deref(), Some("jwt_rotated"));
    assert_eq!(*persisted.lock().unwrap(), vec!["rt_rotated".to_string()]);
}

// ── gap #1: expiry + refusal surfacing from the session manager ───────────────

#[test]
fn is_terminal_maps_each_refusal() {
    // Three are unrecoverable; reuse-detected is NOT (single-flight race).
    assert!(RefreshRefusal::SessionRevoked.is_terminal());
    assert!(RefreshRefusal::SessionExpired.is_terminal());
    assert!(RefreshRefusal::SessionIdleExpired.is_terminal());
    assert!(!RefreshRefusal::RefreshReuseDetected.is_terminal());
}

/// A controllable clock + a manager seeded with an about-to-expire session.
async fn seeded_manager(transport: Arc<dyn HttpTransport>) -> (NativeSessionManager, Arc<std::sync::atomic::AtomicU64>) {
    use std::sync::atomic::AtomicU64;
    let now_ms = Arc::new(AtomicU64::new(1_000_000));
    let clock: Clock = {
        let n = now_ms.clone();
        Arc::new(move || n.load(std::sync::atomic::Ordering::SeqCst))
    };
    let manager = NativeSessionManager::new(transport, "https://fapi.acme.atlasauth.net", "pk_test")
        .with_clock(clock);
    manager
        .seed(NativeSession {
            session_token: "jwt_seed".into(),
            refresh_token: "rt_seed".into(),
            session_id: "sess_1".into(),
            expires_in_seconds: 60,
        })
        .await;
    (manager, now_ms)
}

#[tokio::test]
async fn manager_exposes_expiry_and_checked_errors_on_terminal_refusal() {
    use std::sync::atomic::Ordering;
    let transport = canned(401, r#"{"errors":[{"code":"SESSION_REVOKED"}]}"#);
    let (manager, now_ms) = seeded_manager(transport).await;

    // Expiry is exposed: seeded at now(1_000_000) + 60s.
    assert_eq!(manager.expires_at_ms().await, Some(1_060_000));
    assert_eq!(manager.token_expiry_ms().await, Some(1_060_000));
    assert_eq!(manager.last_refusal().await, None);

    // Record whether a refused-refresh callback fired.
    use std::sync::Mutex;
    let fired: Arc<Mutex<Vec<RefreshRefusal>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let f = fired.clone();
        manager.on_refused(Arc::new(move |r: RefreshRefusal| f.lock().unwrap().push(r)));
    }

    // Advance into the refresh lead and ask for a CHECKED token: the terminal
    // refusal surfaces as an error instead of a silent stale token.
    now_ms.fetch_add(60_000, Ordering::SeqCst);
    match manager.get_token_checked().await {
        Err(SessionError::Refused(RefreshRefusal::SessionRevoked)) => {}
        other => panic!("expected Refused(SessionRevoked), got {other:?}"),
    }
    // The refusal was recorded, the callback fired, and the terminal refusal
    // CLEARED the session.
    assert_eq!(manager.last_refusal().await, Some(RefreshRefusal::SessionRevoked));
    assert_eq!(*fired.lock().unwrap(), vec![RefreshRefusal::SessionRevoked]);
    assert!(manager.current().await.is_none(), "terminal refusal clears the session");
    // Signed out now → NoSession, not a stale token.
    assert!(matches!(manager.get_token_checked().await, Err(SessionError::NoSession)));
}

#[tokio::test]
async fn manager_keeps_session_on_non_terminal_reuse_refusal() {
    use std::sync::atomic::Ordering;
    let transport = canned(401, r#"{"errors":[{"code":"REFRESH_REUSE_DETECTED"}]}"#);
    let (manager, now_ms) = seeded_manager(transport).await;

    now_ms.fetch_add(60_000, Ordering::SeqCst);
    match manager.get_token_checked().await {
        Err(SessionError::Refused(RefreshRefusal::RefreshReuseDetected)) => {}
        other => panic!("expected Refused(RefreshReuseDetected), got {other:?}"),
    }
    // Non-terminal: the session is KEPT for a retry with the current token.
    assert_eq!(manager.last_refusal().await, Some(RefreshRefusal::RefreshReuseDetected));
    assert!(manager.current().await.is_some(), "non-terminal refusal keeps the session");
}

// ── gap #2: api-key token mint + revoked poller ───────────────────────────────

#[tokio::test]
async fn api_key_token_mint_and_revoked_poller() {
    use atlasauth::client::{ApiKeyTokenClient, MintOptions, RevokedKeyPoller, TokenAuth};
    use atlasauth::backend::FakeTransport;

    // A router fake: /token mints, /revoked serves two pages then empties.
    let transport: Arc<dyn HttpTransport> = Arc::new(FakeTransport::new(|req: &HttpRequest| {
        if req.url.contains("/v1/api_keys/token") {
            return HttpResponse {
                status: 200,
                body: r#"{"object":"api_key_token","token":"jwt_minted","token_type":"Bearer","jti":"akt_1","key_id":"eak_42","scopes":["read"],"expires_in":600}"#.to_string(),
            };
        }
        if req.url.contains("/v1/api_keys/revoked") {
            // Page 1 (has_more) unless we already presented the page-2 cursor.
            if req.url.contains("since=cursor2") {
                return HttpResponse { status: 200, body: r#"{"object":"list","data":[],"has_more":false,"next_cursor":"cursor2"}"#.to_string() };
            }
            if req.url.contains("since=cursor1") {
                return HttpResponse { status: 200, body: r#"{"object":"list","data":[{"object":"api_key","id":"eak_b","revoked_at":2}],"has_more":false,"next_cursor":"cursor2"}"#.to_string() };
            }
            return HttpResponse { status: 200, body: r#"{"object":"list","data":[{"object":"api_key","id":"eak_a","revoked_at":1}],"has_more":true,"next_cursor":"cursor1"}"#.to_string() };
        }
        HttpResponse { status: 404, body: "{}".to_string() }
    }));

    // Mint with a bearer (ak_ self-mint).
    let minter = ApiKeyTokenClient::new(transport.clone(), "https://api.atlasauth.net");
    let token = minter
        .mint(&TokenAuth::Bearer("ak_live_x".into()), &MintOptions::default())
        .await
        .expect("mint");
    assert_eq!(token.token, "jwt_minted");
    assert_eq!(token.key_id.as_deref(), Some("eak_42"));
    assert_eq!(token.expires_in, Some(600));

    // Poll: drains page 1 (has_more) then page 2, folding both ids into the list.
    let poller = RevokedKeyPoller::new(transport.clone(), "https://api.atlasauth.net", TokenAuth::Bearer("sk_live_x".into()));
    let deny = poller.deny_list();
    assert!(!deny.is_revoked("eak_a"));
    let result = poller.poll().await.expect("poll");
    assert_eq!(result.newly_revoked, vec!["eak_a".to_string(), "eak_b".to_string()]);
    assert!(deny.is_revoked("eak_a") && deny.is_revoked("eak_b"));
    assert_eq!(deny.len(), 2);
    assert_eq!(poller.cursor().as_deref(), Some("cursor2"));

    // A caught-up re-poll adds nothing.
    let again = poller.poll().await.expect("re-poll");
    assert!(again.newly_revoked.is_empty());
}

// ── gap #3: machine flow round-trip (challenge → sign → token) ────────────────

#[cfg(feature = "machine")]
#[tokio::test]
async fn machine_flow_round_trips_against_a_fake() {
    use atlasauth::backend::FakeTransport;
    use atlasauth::client::{MachineClient, MachineKeypair, MachineTokenManager};
    use ed25519_dalek::{Verifier, VerifyingKey};
    use ed25519_dalek::pkcs8::DecodePublicKey;

    let keypair = MachineKeypair::generate();
    let public_pem = keypair.public_key_pem().expect("public pem");

    // The fake plays the server: /challenge issues a fixed nonce; /token VERIFIES
    // the Ed25519 signature over that nonce against the enrolled public key before
    // minting — a genuine cryptographic round-trip.
    const NONCE: &str = "nonce_for_sess";
    let verifying = VerifyingKey::from_public_key_pem(&public_pem).expect("vk");
    let transport: Arc<dyn HttpTransport> = Arc::new(FakeTransport::new(move |req: &HttpRequest| {
        if req.url.ends_with("/v1/machines/enroll") {
            return HttpResponse { status: 201, body: r#"{"object":"machine","id":"mch_1","status":"active","approval_required":false}"#.to_string() };
        }
        if req.url.ends_with("/v1/machines/challenge") {
            return HttpResponse { status: 200, body: format!(r#"{{"object":"machine_challenge","nonce":"{NONCE}","expires_in_seconds":120}}"#) };
        }
        if req.url.ends_with("/v1/machines/token") {
            let body: serde_json::Value = serde_json::from_str(req.body.as_deref().unwrap_or("{}")).unwrap();
            let sig_b64 = body["signature"].as_str().unwrap_or("");
            let sig_bytes = base64::engine::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD, sig_b64,
            ).unwrap_or_default();
            let ok = <[u8; 64]>::try_from(sig_bytes.as_slice())
                .ok()
                .map(|b| ed25519_dalek::Signature::from_bytes(&b))
                .map(|s| verifying.verify(NONCE.as_bytes(), &s).is_ok())
                .unwrap_or(false);
            return if ok {
                HttpResponse { status: 200, body: r#"{"object":"machine_token","token":"m2m_jwt","token_type":"Bearer","expires_in":600,"machine_id":"mch_1"}"#.to_string() }
            } else {
                HttpResponse { status: 400, body: r#"{"errors":[{"code":"BAD_SIGNATURE"}]}"#.to_string() }
            };
        }
        HttpResponse { status: 404, body: "{}".to_string() }
    }));

    let client = MachineClient::new(transport, "https://api.atlasauth.net");

    // Enroll.
    let enrol = client.enroll("met_abc", "ci-runner-1", &public_pem, None).await.expect("enroll");
    assert_eq!(enrol.id, "mch_1");
    assert!(!enrol.approval_required);

    // Direct mint (challenge → sign → token).
    let token = client.mint_token("mch_1", &keypair).await.expect("mint");
    assert_eq!(token.token, "m2m_jwt");
    assert_eq!(token.expires_in, 600);

    // The manager caches and re-mints; first get mints, within-TTL get is cached.
    let manager = MachineTokenManager::new(
        MachineClient::new(
            // a second client over the same fake
            {
                let t: Arc<dyn HttpTransport> = Arc::new(FakeTransport::new(move |req: &HttpRequest| {
                    if req.url.ends_with("/v1/machines/challenge") {
                        return HttpResponse { status: 200, body: format!(r#"{{"nonce":"{NONCE}","expires_in_seconds":120}}"#) };
                    }
                    HttpResponse { status: 200, body: r#"{"object":"machine_token","token":"m2m_jwt2","expires_in":600,"machine_id":"mch_1"}"#.to_string() }
                }));
                t
            },
            "https://api.atlasauth.net",
        ),
        "mch_1",
        MachineKeypair::generate(),
    );
    let t1 = manager.get_token().await.expect("mgr mint");
    assert_eq!(t1, "m2m_jwt2");
    assert!(manager.expires_at_ms().await.is_some());
    let t2 = manager.get_token().await.expect("mgr cached");
    assert_eq!(t2, "m2m_jwt2"); // cached, not re-minted
}

// ── gap: Callback + encrypted-file (non-dbus Linux) stores ────────────────────

#[test]
fn callback_secure_store_round_trips() {
    use atlasauth::client::CallbackSecureStore;
    use std::sync::{Arc as StdArc, Mutex};
    let backing: StdArc<Mutex<std::collections::HashMap<String, String>>> = StdArc::new(Mutex::new(Default::default()));
    let store = {
        let g = backing.clone();
        let s = backing.clone();
        let d = backing.clone();
        CallbackSecureStore::new(
            move |k| Ok(g.lock().unwrap().get(k).cloned()),
            move |k, v| { s.lock().unwrap().insert(k.into(), v.into()); Ok(()) },
            move |k| { d.lock().unwrap().remove(k); Ok(()) },
        )
    };
    store.set("refresh", "rt_1").unwrap();
    assert_eq!(store.get("refresh").unwrap().as_deref(), Some("rt_1"));
    store.delete("refresh").unwrap();
    assert_eq!(store.get("refresh").unwrap(), None);
}

#[cfg(feature = "encrypted-file")]
#[test]
fn encrypted_file_store_round_trips_without_dbus() {
    use atlasauth::client::EncryptedFileStore;
    let dir = std::env::temp_dir();
    let path = dir.join(format!("atlas-efs-test-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key = b"a-high-entropy-machine-key-32byte";

    {
        let store = EncryptedFileStore::open(&path, key).expect("open");
        assert_eq!(store.get("refresh").unwrap(), None);
        store.set("refresh", "rt_secret").unwrap();
        assert_eq!(store.get("refresh").unwrap().as_deref(), Some("rt_secret"));
    }
    // Reopen with the SAME key: the persisted secret decrypts back.
    {
        let store = EncryptedFileStore::open(&path, key).expect("reopen");
        assert_eq!(store.get("refresh").unwrap().as_deref(), Some("rt_secret"));
        store.delete("refresh").unwrap();
        assert_eq!(store.get("refresh").unwrap(), None);
    }
    // Reopen with the WRONG key: the AEAD tag fails, not silent corruption.
    {
        // re-seed a value first
        let store = EncryptedFileStore::open(&path, key).expect("reseed");
        store.set("x", "y").unwrap();
        let wrong = EncryptedFileStore::open(&path, b"a-different-machine-key-32-bytes!");
        assert!(wrong.is_err(), "wrong key must fail the AEAD tag");
    }
    let _ = std::fs::remove_file(&path);
}

// ── round-8 #6: refresh-token grant + RFC 7009 revoke ─────────────────────────

/// A FakeTransport that records requests and answers from a handler, so a test
/// can assert the exact form body a client posted.
fn recording(handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static) -> Arc<FakeTransport> {
    Arc::new(FakeTransport::new(handler))
}

#[tokio::test]
async fn refresh_token_grant_round_trips() {
    use atlasauth::client::refresh_token_grant;

    let transport = recording(|_req| HttpResponse {
        status: 200,
        body: r#"{"access_token":"at_new","token_type":"Bearer","expires_in":3600,"refresh_token":"rt_rotated","scope":"openid profile"}"#.to_string(),
    });
    let t: Arc<dyn HttpTransport> = transport.clone();

    let tokens = refresh_token_grant(&t, "https://idp.atlasauth.net/oauth2/token", "client_abc", "rt_old")
        .await
        .expect("refresh grant");
    assert_eq!(tokens.access_token, "at_new");
    assert_eq!(tokens.refresh_token.as_deref(), Some("rt_rotated"));
    assert_eq!(tokens.expires_in, Some(3600));

    // The posted form carries the refresh_token grant + the presented token.
    let reqs = transport.requests();
    assert_eq!(reqs.len(), 1);
    let body = reqs[0].body.clone().unwrap_or_default();
    assert!(body.contains("grant_type=refresh_token"), "body: {body}");
    assert!(body.contains("refresh_token=rt_old"), "body: {body}");
    assert!(body.contains("client_id=client_abc"), "body: {body}");
    assert!(reqs[0]
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v == "application/x-www-form-urlencoded"));
}

#[tokio::test]
async fn revoke_token_posts_the_right_form() {
    use atlasauth::client::revoke_token;

    // §2.2: a 200 empty body is success.
    let transport = recording(|_req| HttpResponse { status: 200, body: String::new() });
    let t: Arc<dyn HttpTransport> = transport.clone();

    revoke_token(&t, "https://idp.atlasauth.net/oauth2/revoke", "client_abc", "rt_dead", Some("refresh_token"))
        .await
        .expect("revoke");

    let reqs = transport.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, atlasauth::HttpMethod::Post);
    let body = reqs[0].body.clone().unwrap_or_default();
    assert!(body.contains("token=rt_dead"), "body: {body}");
    assert!(body.contains("client_id=client_abc"), "body: {body}");
    assert!(body.contains("token_type_hint=refresh_token"), "body: {body}");

    // The hint is optional: omitting it still posts, with no hint field.
    let transport2 = recording(|_req| HttpResponse { status: 200, body: String::new() });
    let t2: Arc<dyn HttpTransport> = transport2.clone();
    revoke_token(&t2, "https://idp.atlasauth.net/oauth2/revoke", "client_abc", "at_x", None)
        .await
        .expect("revoke no hint");
    let body2 = transport2.requests()[0].body.clone().unwrap_or_default();
    assert!(!body2.contains("token_type_hint"), "no hint field: {body2}");

    // A non-2xx surfaces as an OAuthError::Server.
    let transport3 = recording(|_req| HttpResponse {
        status: 400,
        body: r#"{"error":"invalid_request"}"#.to_string(),
    });
    let t3: Arc<dyn HttpTransport> = transport3.clone();
    let err = revoke_token(&t3, "https://idp.atlasauth.net/oauth2/revoke", "c", "tok", None)
        .await
        .unwrap_err();
    assert!(matches!(err, atlasauth::client::OAuthError::Server { .. }));
}

// ── round-8 #7: store-backed session manager ──────────────────────────────────

/// A controllable clock shared by a test's manager.
fn test_clock(now_ms: Arc<std::sync::atomic::AtomicU64>) -> Clock {
    let n = now_ms.clone();
    Arc::new(move || n.load(std::sync::atomic::Ordering::SeqCst))
}

fn session_json(token: &str, refresh: &str, sid: &str, expires_in: i64) -> String {
    serde_json::to_string(&NativeSession {
        session_token: token.into(),
        refresh_token: refresh.into(),
        session_id: sid.into(),
        expires_in_seconds: expires_in,
    })
    .unwrap()
}

#[tokio::test]
async fn stored_manager_loads_refreshes_and_writes_back() {
    use atlasauth::client::StoredSessionManager;
    use std::sync::atomic::{AtomicU64, Ordering};

    let now_ms = Arc::new(AtomicU64::new(1_000_000));
    let store = Arc::new(MemorySecureStore::new());
    // A persisted session, near expiry once we advance the clock.
    store.set("session", &session_json("jwt_seed", "rt_seed", "sess_1", 60)).unwrap();

    let transport = canned(
        200,
        r#"{"object":"session","jwt":"jwt_rotated","refresh_token":"rt_rotated","session_id":"sess_1","expires_in":60}"#,
    );
    let inner = NativeSessionManager::new(transport, "https://fapi.acme.atlasauth.net", "pk_test")
        .with_clock(test_clock(now_ms.clone()));
    let mgr = StoredSessionManager::new(store.clone(), "session", inner);

    // Load seeds the inner manager; no rewrite (seed doesn't notify).
    assert!(mgr.load().await.expect("load"));
    assert_eq!(mgr.current().await.unwrap().session_token, "jwt_seed");

    // Still fresh → returns the seeded token, store unchanged.
    assert_eq!(mgr.get_token().await.unwrap(), "jwt_seed");
    assert!(store.get("session").unwrap().unwrap().contains("rt_seed"));

    // Advance into the refresh lead → get_token rotates AND writes back.
    now_ms.fetch_add(60_000, Ordering::SeqCst);
    assert_eq!(mgr.get_token().await.unwrap(), "jwt_rotated");
    let persisted = store.get("session").unwrap().unwrap();
    assert!(persisted.contains("rt_rotated"), "store holds rotated token: {persisted}");
    assert!(persisted.contains("jwt_rotated"));
}

#[tokio::test]
async fn stored_manager_deletes_on_terminal_refusal() {
    use atlasauth::client::StoredSessionManager;
    use std::sync::atomic::{AtomicU64, Ordering};

    let now_ms = Arc::new(AtomicU64::new(1_000_000));
    let store = Arc::new(MemorySecureStore::new());
    store.set("session", &session_json("jwt_seed", "rt_seed", "sess_1", 60)).unwrap();

    let transport = canned(401, r#"{"errors":[{"code":"SESSION_REVOKED"}]}"#);
    let inner = NativeSessionManager::new(transport, "https://fapi.acme.atlasauth.net", "pk_test")
        .with_clock(test_clock(now_ms.clone()));
    let mgr = StoredSessionManager::new(store.clone(), "session", inner);
    assert!(mgr.load().await.expect("load"));

    // Advance into the lead; the refresh is refused terminally.
    now_ms.fetch_add(60_000, Ordering::SeqCst);
    match mgr.get_token().await {
        Err(SessionError::Refused(RefreshRefusal::SessionRevoked)) => {}
        other => panic!("expected terminal refusal, got {other:?}"),
    }
    // The terminal refusal cleared the session AND deleted it from the store.
    assert!(mgr.current().await.is_none());
    assert_eq!(store.get("session").unwrap(), None, "terminal refusal deletes the stored session");
}

#[tokio::test]
async fn stored_manager_rereads_store_on_reuse_detected() {
    use atlasauth::client::StoredSessionManager;
    use std::sync::atomic::{AtomicU64, Ordering};

    let now_ms = Arc::new(AtomicU64::new(1_000_000));
    let store = Arc::new(MemorySecureStore::new());
    // Seed session A (near expiry after the clock advance).
    store.set("session", &session_json("jwt_A", "rt_A", "sess_1", 60)).unwrap();

    // The server ALWAYS trips reuse detection for the token this process holds.
    let transport = canned(401, r#"{"errors":[{"code":"REFRESH_REUSE_DETECTED"}]}"#);
    let inner = NativeSessionManager::new(transport, "https://fapi.acme.atlasauth.net", "pk_test")
        .with_clock(test_clock(now_ms.clone()));
    let mgr = StoredSessionManager::new(store.clone(), "session", inner);
    assert!(mgr.load().await.expect("load"));

    // Advance so A is owed a refresh.
    now_ms.fetch_add(60_000, Ordering::SeqCst);

    // Simulate ANOTHER process having rotated + persisted a fresh session B.
    // (expires_in 60 at now = 1_060_000 → not owed, so the retry returns it
    // without a second network refresh.)
    store.set("session", &session_json("jwt_B", "rt_B", "sess_1", 60)).unwrap();

    // get_token: refresh with rt_A trips reuse → re-read store → find B → return B.
    assert_eq!(mgr.get_token().await.unwrap(), "jwt_B");
    assert_eq!(mgr.current().await.unwrap().refresh_token, "rt_B");
}
