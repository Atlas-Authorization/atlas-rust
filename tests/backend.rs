//! Hermetic tests for the `backend` feature — webhook verification, cursor
//! pagination over the in-memory fake transport, idempotency-key propagation,
//! and retry/backoff. No network.
#![cfg(feature = "backend")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use atlasauth::backend::{
    collect, BackendClient, CursorPage, CursorParams, Event, EventType, FakeTransport, Webhook,
    WebhookError,
};
use atlasauth::{HttpMethod, HttpRequest, HttpResponse};

const SECRET: &str = "whsec_test_secret";

fn sign(id: &str, ts: i64, body: &str, secret: &str) -> Vec<(String, String)> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{id}.{ts}.{body}").as_bytes());
    let sig = STANDARD.encode(mac.finalize().into_bytes());
    vec![
        ("atlas-id".to_string(), id.to_string()),
        ("atlas-timestamp".to_string(), ts.to_string()),
        ("atlas-signature".to_string(), format!("v1,{sig}")),
    ]
}

#[test]
fn webhook_accepts_a_correctly_signed_delivery() {
    let now = 1_757_937_600_000i64; // fixed "now" for a stable timestamp
    let body = r#"{"id":"evt_1","type":"user.created","instance_id":"ins_1","data":{"object":"user","id":"user_1"}}"#;
    let headers = sign("evt_1", now, body, SECRET);

    let event: Event = Webhook::new(SECRET)
        .now_ms(now)
        .verify(body.as_bytes(), headers.as_slice())
        .expect("should verify");

    assert_eq!(event.id, "evt_1");
    assert_eq!(event.event_type, EventType::UserCreated);
    assert_eq!(event.instance_id.as_deref(), Some("ins_1"));
    assert_eq!(event.data["id"], "user_1");
}

#[test]
fn webhook_rejects_a_tampered_body() {
    let now = 1_757_937_600_000i64;
    let body = r#"{"id":"evt_1","type":"user.created","data":{"id":"user_1"}}"#;
    let headers = sign("evt_1", now, body, SECRET);

    // Same signature, body mutated — the MAC no longer matches.
    let tampered = body.replace("user_1", "user_hacked");
    let err = Webhook::new(SECRET)
        .now_ms(now)
        .verify(tampered.as_bytes(), headers.as_slice())
        .unwrap_err();
    assert_eq!(err, WebhookError::SignatureMismatch);
}

#[test]
fn webhook_rejects_stale_and_wrong_secret() {
    let now = 1_757_937_600_000i64;
    let body = r#"{"id":"evt_1","type":"user.created","data":{}}"#;

    // 6 minutes old → outside the 5-minute replay window.
    let stale = sign("evt_1", now - 6 * 60_000, body, SECRET);
    assert_eq!(
        Webhook::new(SECRET).now_ms(now).verify(body.as_bytes(), stale.as_slice()).unwrap_err(),
        WebhookError::StaleTimestamp
    );

    // Right time, wrong secret.
    let wrong = sign("evt_1", now, body, "whsec_wrong");
    assert_eq!(
        Webhook::new(SECRET).now_ms(now).verify(body.as_bytes(), wrong.as_slice()).unwrap_err(),
        WebhookError::SignatureMismatch
    );

    // Missing headers.
    let none: Vec<(String, String)> = vec![];
    assert_eq!(
        Webhook::new(SECRET).now_ms(now).verify(body.as_bytes(), none.as_slice()).unwrap_err(),
        WebhookError::MissingHeaders
    );
}

#[tokio::test]
async fn cursor_pagination_walker_follows_has_more_and_next_cursor() {
    // Drive the public `collect` walker with canned pages: it must follow
    // next_cursor while has_more, pass the cursor back, and stop cleanly.
    let pages: Vec<CursorPage<String>> = vec![
        CursorPage {
            data: vec!["a".into(), "b".into()],
            has_more: true,
            next_cursor: Some("c2".into()),
        },
        CursorPage {
            data: vec!["c".into()],
            has_more: false,
            next_cursor: None,
        },
    ];
    let pages = std::sync::Mutex::new(std::collections::VecDeque::from(pages));
    let seen_cursors = std::sync::Mutex::new(Vec::<Option<String>>::new());

    let all = collect(|cursor| {
        seen_cursors.lock().unwrap().push(cursor.clone());
        let page = pages.lock().unwrap().pop_front().unwrap();
        async move { Ok::<_, atlasauth::backend::BackendError>(page) }
    })
    .await
    .expect("walk");

    assert_eq!(all, ["a", "b", "c"]);
    // First fetch has no cursor; the second carries the server's next_cursor.
    assert_eq!(
        *seen_cursors.lock().unwrap(),
        vec![None, Some("c2".to_string())]
    );
}

#[tokio::test]
async fn resource_list_merges_two_pages_via_public_api() {
    // The same walk, but through the typed `users().list` surface.
    let transport = Arc::new(FakeTransport::new(|req: &HttpRequest| {
        let body = if req.url.contains("starting_after=c2") {
            r#"{"data":[{"id":"user_3","object":"user"}],"has_more":false,"next_cursor":null}"#
        } else {
            r#"{"data":[{"id":"user_1","object":"user"},{"id":"user_2","object":"user"}],"has_more":true,"next_cursor":"c2"}"#
        };
        HttpResponse { status: 200, body: body.to_string() }
    }));
    let client = Arc::new(
        BackendClient::builder("sk_test")
            .transport(transport)
            .base_delay_ms(0)
            .build()
            .unwrap(),
    );

    let all = collect(|cursor| {
        let client = client.clone();
        async move {
            client
                .users()
                .list(CursorParams { starting_after: cursor, ..Default::default() })
                .await
        }
    })
    .await
    .expect("paginate");

    assert_eq!(all.len(), 3);
    assert_eq!(all[2].id, "user_3");
}

#[tokio::test]
async fn idempotency_key_is_sent_on_writes() {
    let transport = Arc::new(FakeTransport::json_ok(
        r#"{"id":"user_1","object":"user"}"#,
    ));
    let client = BackendClient::builder("sk_test")
        .transport(transport.clone())
        .build()
        .unwrap();

    let body = atlasauth::backend::CreateUserBody {
        email_address: "ada@example.com".to_string(),
        ..Default::default()
    };
    client.users().create(&body, Some("idem_123")).await.unwrap();

    let reqs = transport.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert!(reqs[0]
        .headers
        .iter()
        .any(|(k, v)| k == "idempotency-key" && v == "idem_123"));
}

#[tokio::test]
async fn retries_on_5xx_then_succeeds() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let transport = Arc::new(FakeTransport::new(move |_req| {
        let n = c.fetch_add(1, Ordering::SeqCst);
        if n < 2 {
            HttpResponse { status: 503, body: String::new() }
        } else {
            HttpResponse { status: 200, body: r#"{"id":"user_1","object":"user"}"#.to_string() }
        }
    }));
    let client = BackendClient::builder("sk_test")
        .transport(transport)
        .max_retries(2)
        .base_delay_ms(0) // no real sleep in tests
        .build()
        .unwrap();

    let user = client.users().get("user_1").await.expect("should succeed after retries");
    assert_eq!(user.id, "user_1");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn non_2xx_becomes_typed_api_error() {
    let transport = Arc::new(FakeTransport::new(|_req| HttpResponse {
        status: 404,
        body: r#"{"errors":[{"code":"NOT_FOUND","message":"no such user"}]}"#.to_string(),
    }));
    let client = BackendClient::builder("sk_test")
        .transport(transport)
        .base_delay_ms(0)
        .build()
        .unwrap();

    let err = client.users().get("user_nope").await.unwrap_err();
    match err {
        atlasauth::backend::BackendError::Api(api) => {
            assert_eq!(api.status, 404);
            assert!(api.has_code("NOT_FOUND"));
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

// ── round-8 #5: idempotency on the raw request + import on CreateApiKeyBody ────

#[tokio::test]
async fn request_raw_idem_sends_the_idempotency_key_header() {
    let transport = Arc::new(FakeTransport::json_ok(r#"{"ok":true}"#));
    let client = BackendClient::builder("sk_test")
        .transport(transport.clone())
        .build()
        .unwrap();

    // With a key → the header is present.
    let _: serde_json::Value = client
        .request_raw_idem(
            HttpMethod::Post,
            "/v1/some_new_thing",
            &[],
            Some(serde_json::json!({"a": 1})),
            Some("idem_raw_1"),
        )
        .await
        .unwrap();
    // request_value_idem is the dynamic-Value peer.
    let _ = client
        .request_value_idem(HttpMethod::Post, "/v1/some_other", &[], None, Some("idem_raw_2"))
        .await
        .unwrap();
    // And the existing (non-idem) escape hatch still sends NO key.
    let _: serde_json::Value = client
        .request_raw(HttpMethod::Post, "/v1/plain", &[], None)
        .await
        .unwrap();

    let reqs = transport.requests();
    assert_eq!(reqs.len(), 3);
    let key_of = |r: &HttpRequest| {
        r.headers
            .iter()
            .find(|(k, _)| k == "idempotency-key")
            .map(|(_, v)| v.clone())
    };
    assert_eq!(key_of(&reqs[0]).as_deref(), Some("idem_raw_1"));
    assert_eq!(key_of(&reqs[1]).as_deref(), Some("idem_raw_2"));
    assert_eq!(key_of(&reqs[2]), None, "request_raw still sends no idempotency key");
}

#[test]
fn create_api_key_body_serializes_import() {
    use atlasauth::backend::{CreateApiKeyBody, ImportApiKey};

    // No import → the field is omitted entirely.
    let plain = CreateApiKeyBody {
        subject_type: "user".into(),
        subject_id: "user_1".into(),
        ..Default::default()
    };
    let v = serde_json::to_value(&plain).unwrap();
    assert!(v.get("import").is_none(), "import omitted when None");

    // With import → every set field is serialized under `import`.
    let body = CreateApiKeyBody {
        subject_type: "user".into(),
        subject_id: "user_1".into(),
        import: Some(ImportApiKey {
            secret_hash: Some("abc123".into()),
            hash_algorithm: Some("sha256_hex".into()),
            prefix: Some("ak_live_".into()),
            created_at: Some(1_700_000_000_000),
            last_used_at: Some(1_700_000_100_000),
            revoked_at: None,
            expires_at: Some(1_800_000_000_000),
        }),
        ..Default::default()
    };
    let v = serde_json::to_value(&body).unwrap();
    let imp = v.get("import").expect("import present");
    assert_eq!(imp["secret_hash"], "abc123");
    assert_eq!(imp["hash_algorithm"], "sha256_hex");
    assert_eq!(imp["prefix"], "ak_live_");
    assert_eq!(imp["created_at"], 1_700_000_000_000i64);
    assert_eq!(imp["last_used_at"], 1_700_000_100_000i64);
    assert_eq!(imp["expires_at"], 1_800_000_000_000i64);
    // Unset inner field is omitted, not null.
    assert!(imp.get("revoked_at").is_none(), "unset import field omitted");
}
