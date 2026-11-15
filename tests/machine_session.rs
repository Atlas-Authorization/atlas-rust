//! `MachineSession`: enrol once, keep the identity, mint audience-scoped machine tokens and cache them. The
//! fake Atlas verifies every challenge signature against the key the device registered.
#![cfg(all(feature = "machine", feature = "backend"))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use atlasauth::backend::FakeTransport;
use atlasauth::client::{
    FileMachineStore, MachineEnrolOptions, MachineIdentityStore, MachineKeypair, MachineSession, MachineTokenRequest, MemoryMachineStore,
};
use atlasauth::{HttpRequest, HttpResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

const ISSUER: &str = "https://id.example.com";

#[derive(Default)]
struct Server {
    public_pem: Mutex<String>,
    mints: Mutex<u32>,
    bodies: Mutex<Vec<Value>>,
}

fn fake(server: Arc<Server>) -> FakeTransport {
    FakeTransport::new(move |req: &HttpRequest| {
        let body: Value = serde_json::from_str(req.body.as_deref().unwrap_or("{}")).unwrap();
        server.bodies.lock().unwrap().push(body.clone());
        let json = |status: u16, v: Value| HttpResponse { status, body: v.to_string() };
        if req.url == format!("{ISSUER}/v1/machines/enroll") {
            if body["enrolment_token"] == "bad" {
                return json(401, json!({ "errors": [{ "code": "enrolment_token_invalid", "message": "no" }] }));
            }
            *server.public_pem.lock().unwrap() = body["public_key_pem"].as_str().unwrap().to_string();
            return json(201, json!({ "object": "machine", "id": "mch_1", "status": "active", "approval_required": false, "enrolled_at": 1000 }));
        }
        if req.url == format!("{ISSUER}/v1/machines/challenge") {
            return json(200, json!({ "object": "machine_challenge", "nonce": "nonce-1.sig", "expires_in_seconds": 120 }));
        }
        if req.url == format!("{ISSUER}/v1/machines/token") {
            let vk = VerifyingKey::from_public_key_pem(&server.public_pem.lock().unwrap()).unwrap();
            let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(body["signature"].as_str().unwrap()).unwrap()).unwrap();
            if vk.verify(body["nonce"].as_str().unwrap().as_bytes(), &sig).is_err() {
                return json(400, json!({ "errors": [{ "code": "validation_failed", "message": "bad signature" }] }));
            }
            let mut n = server.mints.lock().unwrap();
            *n += 1;
            return json(200, json!({ "object": "machine_token", "token": format!("tok-{n}"), "token_type": "Bearer", "expires_in": 600,
                "audience": body["audience"], "scope": "orders:read", "constraints": { "max_rps": 5 } }));
        }
        json(404, json!({}))
    })
}

fn session(server: &Arc<Server>, store: Arc<dyn MachineIdentityStore>, now: &Arc<AtomicU64>) -> MachineSession {
    let n = now.clone();
    MachineSession::new(Arc::new(fake(server.clone())), format!("{ISSUER}/"), store).with_clock(Arc::new(move || n.load(Ordering::SeqCst)))
}

fn enrol_opts() -> MachineEnrolOptions {
    MachineEnrolOptions { credential: " ABCD-EFGH ".into(), name: "edge-1".into(), device_key: Some("dev-1".into()), ..Default::default() }
}

#[tokio::test]
async fn enrol_stores_an_identity_and_tokens_carry_the_grant() {
    let server = Arc::new(Server::default());
    let store = Arc::new(MemoryMachineStore::new());
    let now = Arc::new(AtomicU64::new(1_000_000));
    let s = session(&server, store.clone(), &now);

    assert!(!s.is_enrolled().unwrap());
    assert!(s.get_token(&MachineTokenRequest::default()).await.is_err(), "not enrolled yet");
    let enrolled = s.enroll(enrol_opts()).await.unwrap();
    assert_eq!((enrolled.machine_id.as_str(), enrolled.status.as_str(), enrolled.approval_required), ("mch_1", "active", false));
    let sent = server.bodies.lock().unwrap()[0].clone();
    assert_eq!(sent["enrolment_token"], "ABCD-EFGH");
    assert_eq!(sent["device_key"], "dev-1");
    assert!(sent["public_key_pem"].as_str().unwrap().contains("BEGIN PUBLIC KEY"));
    let id = store.load().unwrap().unwrap();
    assert_eq!(id.issuer, ISSUER);
    assert_eq!(MachineKeypair::from_pkcs8_pem(&id.private_key_pem).unwrap().public_key_pem().unwrap(), id.public_key_pem);

    let req = MachineTokenRequest { audience: Some("https://api.example.com".into()), scopes: vec!["orders:read".into()], ..Default::default() };
    let t = s.get_token(&req).await.unwrap();
    assert_eq!(t.token, "tok-1");
    assert_eq!(t.token_type, "Bearer");
    assert_eq!(t.audience.as_deref(), Some("https://api.example.com"));
    assert_eq!(t.expires_at, 1_000_000 + 600_000);
    assert_eq!(t.constraints, Some(json!({ "max_rps": 5 })));
    let token_body = server.bodies.lock().unwrap().last().unwrap().clone();
    assert_eq!(token_body["scopes"], json!(["orders:read"]));
    assert_eq!(token_body["machine_id"], "mch_1");
}

#[tokio::test]
async fn tokens_are_cached_per_request_shape_and_re_minted_near_expiry() {
    let server = Arc::new(Server::default());
    let now = Arc::new(AtomicU64::new(1_000_000));
    let s = session(&server, Arc::new(MemoryMachineStore::new()), &now);
    s.enroll(enrol_opts()).await.unwrap();
    let a = MachineTokenRequest { audience: Some("a".into()), scopes: vec!["x".into(), "y".into()], ..Default::default() };
    let a_reordered = MachineTokenRequest { audience: Some("a".into()), scopes: vec!["y".into(), "x".into()], ..Default::default() };
    let b = MachineTokenRequest { audience: Some("b".into()), ..Default::default() };

    assert_eq!(s.get_token(&a).await.unwrap().token, "tok-1");
    assert_eq!(s.get_token(&a_reordered).await.unwrap().token, "tok-1", "scope order does not change the cache key");
    assert_eq!(s.get_token(&b).await.unwrap().token, "tok-2");
    now.fetch_add(541_000, Ordering::SeqCst); // inside the 60 s refresh skew
    assert_eq!(s.get_token(&a).await.unwrap().token, "tok-3");
    s.clear_tokens().await;
    assert_eq!(s.get_token(&a).await.unwrap().token, "tok-4");
}

#[tokio::test]
async fn a_bad_enrolment_token_is_an_error_and_reset_forgets_the_identity() {
    let server = Arc::new(Server::default());
    let now = Arc::new(AtomicU64::new(1_000_000));
    let s = session(&server, Arc::new(MemoryMachineStore::new()), &now);
    let bad = MachineEnrolOptions { credential: "bad".into(), name: "x".into(), ..Default::default() };
    assert!(s.enroll(bad).await.is_err());
    assert!(!s.is_enrolled().unwrap());
    s.enroll(enrol_opts()).await.unwrap();
    assert_eq!(s.machine_id().unwrap().as_deref(), Some("mch_1"));
    s.reset().await.unwrap();
    assert!(!s.is_enrolled().unwrap());
}

#[tokio::test]
async fn an_identity_for_another_issuer_is_ignored_and_the_file_store_round_trips() {
    let server = Arc::new(Server::default());
    let now = Arc::new(AtomicU64::new(1_000_000));
    let dir = std::env::temp_dir().join(format!("atlas-machine-{}", std::process::id()));
    let path = dir.join("identity.json");
    let store = Arc::new(FileMachineStore::new(&path));
    let s = session(&server, store.clone(), &now);
    s.enroll(enrol_opts()).await.unwrap();
    assert!(path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // A second process sees the same identity and can mint without enrolling again.
    let again = session(&server, store.clone(), &now);
    assert!(again.is_enrolled().unwrap());
    assert!(again.get_token(&MachineTokenRequest::default()).await.is_ok());
    // The same file read by a client for a different issuer is not its identity.
    let other = MachineSession::new(Arc::new(fake(server.clone())), "https://other.example.com", store.clone());
    assert!(!other.is_enrolled().unwrap());
    s.reset().await.unwrap();
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(dir);
}
