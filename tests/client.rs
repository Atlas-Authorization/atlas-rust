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
