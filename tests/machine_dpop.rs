//! DPoP for a machine: proofs verify against their own key and name the request and token (the same checks
//! the TS client's tests make), and a session with a DPoP key sends a proof on the token request.
#![cfg(all(feature = "machine", feature = "backend"))]

use std::sync::{Arc, Mutex};

use atlasauth::backend::FakeTransport;
use atlasauth::client::{DpopKey, MachineEnrolOptions, MachineSession, MachineTokenRequest, MemoryMachineStore};
use atlasauth::{dpop_access_token_hash, jwk_thumbprint, HttpRequest, HttpResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};

fn decode(part: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

#[test]
fn a_proof_verifies_against_its_own_key_names_the_request_and_matches_the_thumbprint() {
    let key = DpopKey::generate();
    let proof = key.proof("get", "https://api.example.com/orders?x=1#frag", Some("tok"), Some("n1"), 1_700_000_000_000).unwrap();
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = decode(parts[0]);
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "EdDSA");
    let x = URL_SAFE_NO_PAD.decode(header["jwk"]["x"].as_str().unwrap()).unwrap();
    let vk = VerifyingKey::from_bytes(x.as_slice().try_into().unwrap()).unwrap();
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).expect("signature verifies");

    let payload = decode(parts[1]);
    assert_eq!(payload["htm"], "GET");
    assert_eq!(payload["htu"], "https://api.example.com/orders");
    assert_eq!(payload["iat"], 1_700_000_000);
    assert_eq!(payload["nonce"], "n1");
    assert_eq!(payload["ath"], dpop_access_token_hash("tok"));
    assert!(payload["jti"].as_str().is_some_and(|j| !j.is_empty()));
    // Two proofs never share a jti.
    let again = key.proof("get", "https://api.example.com/orders", None, None, 1_700_000_000_000).unwrap();
    assert_ne!(decode(again.split('.').nth(1).unwrap())["jti"], payload["jti"]);
    assert!(decode(again.split('.').nth(1).unwrap()).get("ath").is_none());

    let jwk: Map<String, Value> = header["jwk"].as_object().unwrap().clone();
    assert_eq!(jwk_thumbprint(&jwk).unwrap(), key.thumbprint());
}

#[test]
fn a_key_round_trips_through_pem_and_a_relative_url_is_refused() {
    let key = DpopKey::generate();
    let restored = DpopKey::from_pkcs8_pem(&key.to_pkcs8_pem().unwrap()).unwrap();
    assert_eq!(key.thumbprint(), restored.thumbprint());
    assert!(DpopKey::from_pkcs8_pem("not a pem").is_err());
    assert!(key.proof("GET", "/orders", None, None, 0).is_err());
}

#[tokio::test]
async fn a_session_with_a_dpop_key_proves_possession_on_the_token_request() {
    let seen: Arc<Mutex<Vec<(String, Option<String>)>>> = Arc::default();
    let s = seen.clone();
    let fake = FakeTransport::new(move |req: &HttpRequest| {
        let dpop = req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("dpop")).map(|(_, v)| v.clone());
        s.lock().unwrap().push((req.url.clone(), dpop.clone()));
        let json = |status: u16, v: Value| HttpResponse { status, body: v.to_string() };
        if req.url.ends_with("/v1/machines/enroll") {
            json(201, json!({ "id": "mch_1", "status": "active", "approval_required": false }))
        } else if req.url.ends_with("/v1/machines/challenge") {
            json(200, json!({ "nonce": "n" }))
        } else {
            json(200, json!({ "token": "t", "token_type": if dpop.is_some() { "DPoP" } else { "Bearer" }, "expires_in": 600 }))
        }
    });
    let session = MachineSession::new(Arc::new(fake), "https://id.example.com", Arc::new(MemoryMachineStore::new())).dpop_key(DpopKey::generate());
    session
        .enroll(MachineEnrolOptions { credential: "enrol".into(), name: "box".into(), metadata: None, device_key: None })
        .await
        .unwrap();
    let t = session.get_token(&MachineTokenRequest::default()).await.unwrap();
    assert_eq!(t.token_type, "DPoP");
    let calls = seen.lock().unwrap();
    assert!(calls.iter().find(|(u, _)| u.ends_with("/challenge")).unwrap().1.is_none(), "only the token request carries a proof");
    let proof = calls.iter().find(|(u, _)| u.ends_with("/v1/machines/token")).unwrap().1.clone().unwrap();
    let payload = decode(proof.split('.').nth(1).unwrap());
    assert_eq!(payload["htu"], "https://id.example.com/v1/machines/token");
    assert_eq!(payload["htm"], "POST");
    drop(calls);

    assert!(session.dpop_thumbprint().is_some());
    let call_proof = session.dpop_proof(&t.token, "GET", "https://api.example.com/x", None).unwrap();
    assert_eq!(decode(call_proof.split('.').nth(1).unwrap())["ath"], dpop_access_token_hash("t"));
}

#[tokio::test]
async fn without_a_dpop_key_no_proof_is_sent_and_proofs_cannot_be_signed() {
    let fake = FakeTransport::new(|_| HttpResponse { status: 404, body: "{}".into() });
    let session = MachineSession::new(Arc::new(fake), "https://id.example.com", Arc::new(MemoryMachineStore::new()));
    assert!(session.dpop_thumbprint().is_none());
    assert!(session.dpop_proof("t", "GET", "https://x.example.com/", None).is_err());
}

// The wire-spec vector the TS client's tests use: RFC 8032 section 7.1, TEST 1, a published Ed25519 key and
// the signature over the empty message. The challenge signature is pure Ed25519 over the nonce bytes, base64url.
const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n";
const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const TEST1_SIG_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

#[test]
fn the_challenge_signature_matches_the_rfc_8032_vector() {
    use atlasauth::client::MachineKeypair;
    let kp = MachineKeypair::from_pkcs8_pem(PRIVATE_PEM).unwrap();
    let want: Vec<u8> = (0..TEST1_SIG_HEX.len()).step_by(2).map(|i| u8::from_str_radix(&TEST1_SIG_HEX[i..i + 2], 16).unwrap()).collect();
    assert_eq!(kp.sign_challenge(""), URL_SAFE_NO_PAD.encode(want));
    assert_eq!(kp.public_key_pem().unwrap().trim(), PUBLIC_PEM.trim());

    let nonce = "eyJtY2giOiJtY2hfMSJ9.c2lnbmF0dXJl";
    let sig = kp.sign_challenge(nonce);
    assert_eq!(sig.len(), 86);
    let vk = {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_pem(PUBLIC_PEM).unwrap()
    };
    let raw = Signature::from_slice(&URL_SAFE_NO_PAD.decode(&sig).unwrap()).unwrap();
    assert!(vk.verify(nonce.as_bytes(), &raw).is_ok());
    assert!(vk.verify(format!("{nonce}x").as_bytes(), &raw).is_err());
}
