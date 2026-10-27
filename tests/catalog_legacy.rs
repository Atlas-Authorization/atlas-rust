//! The Chatly / Forumulate integration helpers on `instance()` outlived their
//! routes in the API description; they are hand-written (see `src/backend/legacy.rs`)
//! and keep hitting the documented method and path.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{types, BackendClient, FakeTransport};
use atlasauth::{HttpMethod, HttpResponse};

#[tokio::test]
async fn legacy_integration_helpers_hit_their_routes() {
    let fake = FakeTransport::new(|_| HttpResponse { status: 200, body: r#"{"ok":true}"#.into() });
    let c = BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap();
    c.instance().get_chatly_integration().await.unwrap();
    c.instance()
        .set_chatly_integration(&types::InstanceSetChatlyIntegrationBody::default())
        .await
        .unwrap();
    c.instance().delete_chatly_integration().await.unwrap();
    c.instance().get_forumulate_integration().await.unwrap();
    c.instance()
        .set_forumulate_integration(&types::InstanceSetForumulateIntegrationBody::default())
        .await
        .unwrap();
    c.instance().delete_forumulate_integration().await.unwrap();
    let got: Vec<(HttpMethod, String)> = fake.requests().iter().map(|r| (r.method, r.url.clone())).collect();
    let want = [
        (HttpMethod::Get, "chatly"),
        (HttpMethod::Put, "chatly"),
        (HttpMethod::Delete, "chatly"),
        (HttpMethod::Get, "forumulate"),
        (HttpMethod::Put, "forumulate"),
        (HttpMethod::Delete, "forumulate"),
    ];
    assert_eq!(got.len(), want.len());
    for ((m, u), (wm, w)) in got.iter().zip(want) {
        assert_eq!(*m, wm);
        assert!(u.ends_with(&format!("/v1/instance/integrations/{w}")), "{u}");
    }
}
