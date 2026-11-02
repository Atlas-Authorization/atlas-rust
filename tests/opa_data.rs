//! The hand-written OPA Data API method keeps `/` in the decision path as a
//! separator and encodes each part on its own.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::HttpMethod;
use serde_json::json;

#[tokio::test]
async fn opa_data_posts_to_the_decision_path() {
    let t = Arc::new(FakeTransport::json_ok(r#"{"result":true}"#));
    let c = BackendClient::builder("sk_test")
        .transport(t.clone())
        .max_retries(0)
        .build()
        .unwrap();
    let out = c
        .opa()
        .data("/atlas/fga/store 1/allow", &json!({"input": {"user": "user:1"}}), None)
        .await
        .unwrap();
    assert_eq!(out, json!({"result": true}));
    let req = t.requests().pop().unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(
        req.url,
        "https://api.atlasauth.net/v1/opa/v1/data/atlas/fga/store%201/allow"
    );
}
