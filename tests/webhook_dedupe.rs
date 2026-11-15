//! Webhook verification with delivery-id deduplication.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use atlasauth::backend::{Webhook, WebhookError};
use atlasauth::webhook_dedupe::{DedupeError, MemoryWebhookStore, WebhookDedupeStore, WebhookDeduper};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET: &str = "whsec_test_secret";
const NOW: i64 = 1_757_937_600_000;
const BODY: &str = r#"{"id":"evt_1","type":"user.created","instance_id":"ins_1","data":{"id":"user_1"}}"#;

fn signed(id: &str, body: &str) -> Vec<(String, String)> {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("{id}.{NOW}.{body}").as_bytes());
    vec![
        ("atlas-id".into(), id.into()),
        ("atlas-timestamp".into(), NOW.to_string()),
        ("atlas-signature".into(), format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))),
    ]
}

fn deduper() -> WebhookDeduper {
    WebhookDeduper::new(Webhook::new(SECRET).now_ms(NOW), Arc::new(MemoryWebhookStore::new()))
}

#[test]
fn a_retried_delivery_is_flagged_as_a_duplicate_and_release_lets_it_through_again() {
    let d = deduper();
    let headers = signed("dlv_1", BODY);
    let first = d.verify_and_dedupe(BODY.as_bytes(), headers.as_slice()).unwrap();
    assert!(!first.duplicate);
    assert_eq!(first.delivery_id, "dlv_1");
    assert_eq!(first.event.id, "evt_1");
    let retry = d.verify_and_dedupe(BODY.as_bytes(), headers.as_slice()).unwrap();
    assert!(retry.duplicate);
    d.release(&first).unwrap();
    assert!(!d.verify_and_dedupe(BODY.as_bytes(), headers.as_slice()).unwrap().duplicate);
    // A different delivery id is a different delivery.
    assert!(!d.verify_and_dedupe(BODY.as_bytes(), signed("dlv_2", BODY).as_slice()).unwrap().duplicate);
}

#[test]
fn an_unverified_delivery_never_touches_the_store() {
    let d = deduper();
    let mut headers = signed("dlv_1", BODY);
    headers[2].1 = "v1,AAAA".into();
    assert!(matches!(d.verify_and_dedupe(BODY.as_bytes(), headers.as_slice()), Err(DedupeError::Verification(WebhookError::SignatureMismatch))));
    // The id is still unclaimed: the genuine delivery is not a duplicate.
    assert!(!d.verify_and_dedupe(BODY.as_bytes(), signed("dlv_1", BODY).as_slice()).unwrap().duplicate);
}

#[test]
fn the_memory_store_expires_ids_after_the_ttl() {
    let now = Arc::new(AtomicU64::new(1_000));
    let n = now.clone();
    let store = MemoryWebhookStore::with_clock(Arc::new(move || n.load(Ordering::SeqCst)));
    assert!(store.set_if_absent("k", 10).unwrap());
    assert!(!store.set_if_absent("k", 10).unwrap());
    now.fetch_add(10_001, Ordering::SeqCst);
    assert!(store.set_if_absent("k", 10).unwrap(), "an expired id counts as unseen");
}
