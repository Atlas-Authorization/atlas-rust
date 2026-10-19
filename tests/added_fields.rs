//! The response fields added for this release decode on the hand-written types.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::HttpResponse;

fn client(body: &'static str) -> BackendClient {
    let fake = FakeTransport::new(move |_req| HttpResponse { status: 200, body: body.into() });
    BackendClient::builder("sk_test_x").transport(Arc::new(fake)).max_retries(0).build().unwrap()
}

#[tokio::test]
async fn cookie_consent_carries_culture_and_the_cookie_inventory() {
    let c = client(
        r#"{"object":"cookie_consent","enabled":true,"culture":"page","declared_cookies":[{"name":"__session","pattern":null,"store":"cookie","domain":".example.com","lifetime_seconds":null,"lifetime":"session","http_only":true,"category":"necessary","purpose":"p","written_when":"w","set_by":"atlas_frontend_api"}]}"#,
    );
    let cc = c.instance().get_cookie_consent().await.unwrap();
    assert_eq!(cc.culture.as_deref(), Some("page"));
    assert_eq!(cc.declared_cookies.len(), 1);
    assert_eq!(cc.declared_cookies[0].store, "cookie");
    assert!(cc.declared_cookies[0].http_only);
    assert_eq!(cc.declared_cookies[0].lifetime_seconds, None);
}

#[tokio::test]
async fn preflight_lists_the_sdk_versions_seen() {
    let c = client(
        r#"{"object":"preflight","ok":true,"checked_at":1,"findings":[],"sdk_versions_seen":[{"package":"@atlasauth/react","version":"0.8.0","last_seen_at":2,"advisories":[{"object":"sdk_advisory","package":"@atlasauth/react","affected":"<0.8.1","fixed_in":"0.8.1","reason":"email_code_sign_in","severity":"high","summary":"s","published_at":"2026-10-01"}]}]}"#,
    );
    let p = c.instance().preflight().await.unwrap();
    assert_eq!(p.sdk_versions_seen[0].version, "0.8.0");
    assert_eq!(p.sdk_versions_seen[0].advisories[0].fixed_in, "0.8.1");
}
