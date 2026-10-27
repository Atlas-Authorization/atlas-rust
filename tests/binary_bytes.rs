//! A binary response body reaches the caller byte for byte, and the
//! pre-existing request helpers and catalog methods keep their behaviour.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport, Query};
use atlasauth::{HttpMethod, HttpResponse};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

#[tokio::test]
async fn policy_bundle_archive_round_trips_non_utf8_bytes() {
    let payload: Vec<u8> = vec![0x1f, 0x8b, 0xff, 0xfe, 0x00, 0x80];
    assert!(String::from_utf8(payload.clone()).is_err());
    let fake = FakeTransport::new(|_| HttpResponse { status: 200, body: String::new() }).with_bytes_body(payload.clone());
    let got = client(&fake).policy_bundles().archive("rev 1").await.unwrap();
    assert_eq!(got, payload);
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Get);
    assert_eq!(reqs[0].url, "https://api.atlasauth.net/v1/policy_bundles/rev%201/archive");
}

#[tokio::test]
async fn request_raw_bytes_maps_errors() {
    let fake = FakeTransport::new(|_| HttpResponse {
        status: 404,
        body: r#"{"errors":[{"code":"NOT_FOUND","message":"nope"}]}"#.into(),
    });
    let err = client(&fake)
        .request_raw_bytes(HttpMethod::Get, "/v1/policy_bundles/x/archive", &[], None)
        .await
        .unwrap_err();
    assert!(matches!(err, atlasauth::backend::BackendError::Api(_)));
}

#[tokio::test]
async fn existing_helpers_and_methods_are_unchanged() {
    let fake = FakeTransport::json_ok(r#"{"ok":true}"#);
    let c = client(&fake);
    // request_bytes still returns the (text) body as bytes.
    let b = c.request_bytes(HttpMethod::Get, "/v1/x", &[], None).await.unwrap();
    assert_eq!(b, br#"{"ok":true}"#.to_vec());
    c.request_value(HttpMethod::Get, "/v1/x", &[], None).await.unwrap();
    // Pre-existing catalog namespaces keep their names and signatures.
    let q = Query::new().set("limit", 2);
    c.action_gallery().list(&q).await.unwrap();
    c.action_gallery().get("slug").await.unwrap();
    c.waitlist().list(&q).await.unwrap();
    c.roles().list(&q).await.unwrap();
    assert_eq!(fake.request_count(), 6);
}
