//! The key mirror verifies key-pair assertions locally with the server's refusal codes; a disabled row is refused.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::mirror::{InvalidCode, KeyMirror, KeyMirrorOptions, KeyMirrorStore, MemoryKeyMirrorStore, MirrorVerification, MirroredApiKey};
use atlasauth::{sign_api_key_assertion, ApiKeyAssertionOptions, Clock};
use serde_json::{json, Value};

// Throwaway test vectors generated for these tests only; they protect nothing.
const EC_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghniYXev3KDLEBa2r\n+3iEdilAGxVI8M1GeJHdxkAv3jqhRANCAATkbbEsHEIO2Xwdp0kkxp/ADrEf+uEn\nXXgVQvtgjEmx8b/HrWuPS9y+ZoiAEvjtpQemEtX7sqeh8oNwr/rpo/vQ\n-----END PRIVATE KEY-----\n";
const EC_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5G2xLBxCDtl8HadJJMafwA6xH/rh\nJ114FUL7YIxJsfG/x61rj0vcvmaIgBL47aUHphLV+7KnofKDcK/66aP70A==\n-----END PUBLIC KEY-----\n";

fn mirror_for(row: Value, offset: Arc<AtomicI64>) -> (KeyMirror, Arc<MemoryKeyMirrorStore>) {
    let transport = FakeTransport::json_ok(&row.to_string());
    let client = BackendClient::builder("sk_test_x").transport(Arc::new(transport)).max_retries(0).build().unwrap();
    let store = Arc::new(MemoryKeyMirrorStore::new());
    let clock: Clock = Arc::new(move || {
        let real = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        (real + offset.load(Ordering::SeqCst)) as u64
    });
    (KeyMirror::new(store.clone(), client, KeyMirrorOptions::default()).with_clock(clock), store)
}

fn sign(audience: &str, ttl_seconds: u64, scope: Option<&str>, jti: Option<&str>) -> String {
    let opts = ApiKeyAssertionOptions { ttl_seconds, scope: scope.map(Into::into), jti: jti.map(Into::into) };
    sign_api_key_assertion(EC_PRIVATE, "key_1", audience, &opts).unwrap()
}

fn code(v: &MirrorVerification) -> Option<InvalidCode> {
    match v {
        MirrorVerification::Invalid { code, .. } => *code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn key_pair_mirror(offset: Arc<AtomicI64>) -> (KeyMirror, Arc<MemoryKeyMirrorStore>) {
    let row = json!({ "id": "key_1", "subject_type": "machine", "subject_id": "m1", "scopes": ["read", "write"],
        "credential": "key_pair", "audience": "ins_1", "public_key": EC_PUBLIC });
    let (m, store) = mirror_for(row.clone(), offset);
    m.mint(json!({}), None).await.unwrap();
    (m, store)
}

#[tokio::test]
async fn valid_assertion_narrows_scope() {
    let (m, _) = key_pair_mirror(Arc::new(AtomicI64::new(0))).await;
    match m.verify_assertion(&sign("ins_1", 300, Some("read"), Some("a")), &["read".to_string()], None).await.unwrap() {
        MirrorVerification::Valid { effective_scopes, credential, jti, .. } => {
            assert_eq!(effective_scopes, vec!["read".to_string()]);
            assert_eq!(credential.as_deref(), Some("key_pair"));
            assert_eq!(jti.as_deref(), Some("a"));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(code(&m.verify_assertion(&sign("ins_1", 300, Some("admin"), None), &[], None).await.unwrap()), Some(InvalidCode::ScopeNotGranted));
}

#[tokio::test]
async fn refusal_codes_and_jti_claimed_last() {
    let offset = Arc::new(AtomicI64::new(0));
    let (m, _) = key_pair_mirror(offset.clone()).await;
    assert_eq!(code(&m.verify_assertion(&sign("other", 300, None, None), &[], None).await.unwrap()), Some(InvalidCode::WrongAudience));
    assert_eq!(code(&m.verify_assertion(&sign("ins_1", 7200, None, None), &[], None).await.unwrap()), Some(InvalidCode::AssertionLifetimeTooLong));
    assert_eq!(code(&m.verify_assertion("a.b.c", &[], None).await.unwrap()), Some(InvalidCode::InvalidAssertion));
    let token = sign("ins_1", 300, None, Some("j1"));
    assert_eq!(code(&m.verify_assertion(&token, &["nope".to_string()], None).await.unwrap()), Some(InvalidCode::InsufficientScope));
    assert!(m.verify_assertion(&token, &[], None).await.unwrap().is_valid());
    assert_eq!(code(&m.verify_assertion(&token, &[], None).await.unwrap()), Some(InvalidCode::AssertionReplayed));
    // a clock 10 minutes ahead of the signer: expired; behind: not yet valid
    offset.store(600_000, Ordering::SeqCst);
    assert_eq!(code(&m.verify_assertion(&sign("ins_1", 300, None, None), &[], None).await.unwrap()), Some(InvalidCode::AssertionExpired));
    offset.store(-600_000, Ordering::SeqCst);
    assert_eq!(code(&m.verify_assertion(&sign("ins_1", 300, None, None), &[], None).await.unwrap()), Some(InvalidCode::AssertionNotYetValid));
}

#[tokio::test]
async fn disabled_rows_are_refused_and_webhook_copies_enabled() {
    let (m, store) = key_pair_mirror(Arc::new(AtomicI64::new(0))).await;
    let held = store.get("key_1").unwrap().unwrap();
    store.put(MirroredApiKey { enabled: Some(false), ..held }).unwrap();
    assert_eq!(code(&m.verify_assertion(&sign("ins_1", 300, None, None), &[], None).await.unwrap()), Some(InvalidCode::InvalidAssertion));
    assert!(m.apply_webhook("api_key.updated", &json!({ "id": "key_1", "enabled": true })).unwrap());
    assert!(m.verify_assertion(&sign("ins_1", 300, None, None), &[], None).await.unwrap().is_valid());
    store.mark_revoked("key_1", 1, None).unwrap();
    assert!(!m.verify_assertion(&sign("ins_1", 300, None, None), &[], None).await.unwrap().is_valid());

    let (sm, _) = mirror_for(json!({ "id": "k2", "secret": "ak_s", "enabled": false }), Arc::new(AtomicI64::new(0)));
    sm.mint(json!({}), None).await.unwrap();
    assert!(!sm.verify("ak_s", &[], None).await.unwrap().is_valid());
    sm.apply_webhook("api_key.updated", &json!({ "id": "k2", "enabled": true })).unwrap();
    assert!(sm.verify("ak_s", &[], None).await.unwrap().is_valid());
}
