//! Sealed secret delivery: the vetted `crypto_box` sealed box, and the
//! `secret_recipient` header on the client.
#![cfg(all(feature = "sealed-box", feature = "backend"))]

use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::{
    generate_seal_key_pair, open_sealed_box, open_sealed_secret, seal_box, SealKeyPair, SealedBoxError,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

#[test]
fn sealed_box_round_trips_and_refuses_tampering() {
    let pair = generate_seal_key_pair();
    assert!(pair.recipient().starts_with("x25519:"));
    let long = "x".repeat(1000);
    for msg in ["a", "atlas_live_sk_0123456789abcdef", long.as_str()] {
        let sealed = seal_box(msg.as_bytes(), &pair.public_key()).unwrap();
        assert_eq!(sealed.len(), 32 + 16 + msg.len());
        assert_eq!(open_sealed_box(&sealed, &pair).unwrap(), msg.as_bytes());
        let b64 = STANDARD.encode(&sealed);
        assert_eq!(open_sealed_secret(&b64, &pair).unwrap(), msg);
    }
    let other = generate_seal_key_pair();
    let sealed = seal_box(b"secret", &pair.public_key()).unwrap();
    assert_eq!(open_sealed_box(&sealed, &other).unwrap_err(), SealedBoxError::Invalid);
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(open_sealed_box(&tampered, &pair).unwrap_err(), SealedBoxError::Invalid);
    assert_eq!(open_sealed_box(&[0u8; 10], &pair).unwrap_err(), SealedBoxError::Invalid);
    assert_eq!(open_sealed_secret("***", &pair).unwrap_err(), SealedBoxError::NotBase64);
    // a pair rebuilt from its secret key opens the same boxes
    let again = SealKeyPair::from_secret_key(pair.secret_key());
    assert_eq!(again.recipient(), pair.recipient());
    assert_eq!(open_sealed_box(&sealed, &again).unwrap(), b"secret");
}

#[tokio::test]
async fn a_client_with_a_recipient_asks_for_sealed_secrets() {
    let pair = generate_seal_key_pair();
    let sealed = STANDARD.encode(seal_box(b"atlas_live_sk_shownonce", &pair.public_key()).unwrap());
    let body = format!(r#"{{"id":"key_1","sealed_secret":"{sealed}"}}"#);
    let fake = FakeTransport::json_ok(body);
    let c = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .secret_recipient(pair.recipient())
        .max_retries(0)
        .build()
        .unwrap();
    let key = c.secret_keys().get("key_1").await.unwrap();
    let req = &fake.requests()[0];
    assert!(req.headers.iter().any(|(k, v)| k == "x-secret-recipient" && *v == pair.recipient()));
    assert_eq!(key.secret, None);
    assert_eq!(open_sealed_secret(key.sealed_secret.as_deref().unwrap(), &pair).unwrap(), "atlas_live_sk_shownonce");
}
