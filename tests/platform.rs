//! Hermetic tests for the round-7 additions: the public raw request, the new
//! platform resources, the bounded/invalidatable API-key cache, the
//! FakeTransport JWKS/signing helpers, and cursor pagination on the two lists.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::backend::{
    collect, AuditEventFilter, BackendClient, CreateTicketBody, CursorParams, FakeTransport,
    ScheduleDeletionBody, SendNotificationBody, WriteAuditEventBody,
};
use atlasauth::{
    ApiKeyVerifier, AtlasBackend, BoxFuture, Clock, HttpMethod, HttpPost, HttpResponse,
    TransportError,
};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

// ── public raw request ────────────────────────────────────────────────────

#[tokio::test]
async fn raw_request_round_trips_with_auth_and_typed_errors() {
    let fake = FakeTransport::new(|req| {
        if req.url.contains("/v1/missing") {
            HttpResponse {
                status: 404,
                body: r#"{"errors":[{"code":"NOT_FOUND","message":"nope"}]}"#.into(),
            }
        } else {
            HttpResponse { status: 200, body: r#"{"hello":"world","n":3}"#.into() }
        }
    });
    let c = client(&fake);

    #[derive(serde::Deserialize)]
    struct Out {
        hello: String,
        n: u32,
    }
    let out: Out = c
        .request_raw(HttpMethod::Post, "/v1/new_thing", &[("a", "b c".into())], Some(json!({"x": 1})))
        .await
        .unwrap();
    assert_eq!((out.hello.as_str(), out.n), ("world", 3));

    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert!(reqs[0].url.ends_with("/v1/new_thing?a=b%20c"));
    assert!(reqs[0]
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == "Bearer sk_test_x"));
    assert_eq!(reqs[0].body.as_deref(), Some(r#"{"x":1}"#));

    let v = c.request_value(HttpMethod::Get, "/v1/x", &[], None).await.unwrap();
    assert_eq!(v["hello"], "world");
    let bytes = c.request_bytes(HttpMethod::Get, "/v1/x", &[], None).await.unwrap();
    assert!(String::from_utf8(bytes).unwrap().contains("world"));

    let err = c
        .request_raw::<Value>(HttpMethod::Get, "/v1/missing", &[], None)
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("NOT_FOUND"));
}

// ── new resources ─────────────────────────────────────────────────────────

#[tokio::test]
async fn audit_events_write_and_list_hit_right_method_and_path() {
    let fake = FakeTransport::new(|req| {
        let body = if req.method == HttpMethod::Post {
            r#"{"id":"ae_1","action":"invoice.paid","metadata":{"k":"v"},"future_field":1}"#
        } else {
            r#"{"data":[{"id":"ae_1","action":"invoice.paid"}],"has_more":false}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let c = client(&fake);

    let ev = c
        .audit_events()
        .write(
            &WriteAuditEventBody { action: "invoice.paid".into(), ..Default::default() },
            Some("idem-1"),
        )
        .await
        .unwrap();
    assert_eq!(ev.id, "ae_1");
    assert!(ev.extra.contains_key("future_field"));

    let page = c
        .audit_events()
        .list(&AuditEventFilter {
            organization_id: Some("org_1".into()),
            metadata_key: Some("plan".into()),
            metadata_value: Some("pro".into()),
            limit: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.data.len(), 1);

    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert!(reqs[0].url.ends_with("/v1/audit_events"));
    assert_eq!(reqs[0].body.as_deref(), Some(r#"{"action":"invoice.paid"}"#));
    assert!(reqs[0].headers.iter().any(|(k, v)| k == "idempotency-key" && v == "idem-1"));
    assert_eq!(reqs[1].method, HttpMethod::Get);
    assert!(reqs[1].url.contains("/v1/audit_events?"));
    assert!(reqs[1].url.contains("organization_id=org_1"));
    assert!(reqs[1].url.contains("metadata_key=plan"));
    assert!(reqs[1].url.contains("limit=5"));
}

#[tokio::test]
async fn tickets_notifications_entitlements_and_erasure() {
    let fake = FakeTransport::new(|req| {
        let body = if req.url.ends_with("/entitlements") {
            r#"{"plan":"pro","features":["sso"],"limits":{"seats":10}}"#
        } else {
            r#"{"id":"x","ticket":"tk_secret","status":"scheduled"}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let c = client(&fake);

    let t = c
        .tickets()
        .create(&CreateTicketBody { ttl_seconds: 60, single_use: Some(true), ..Default::default() }, None)
        .await
        .unwrap();
    assert_eq!(t.ticket.as_deref(), Some("tk_secret"));
    c.tickets().redeem("tk_secret", Some("user_1"), None).await.unwrap();
    c.notifications()
        .send(&SendNotificationBody { user_id: "u".into(), template: "welcome".into(), data: None }, None)
        .await
        .unwrap();
    let eff = c.org_platform("org_1").entitlements().await.unwrap();
    assert_eq!(eff.plan.as_deref(), Some("pro"));
    assert_eq!(eff.features, vec!["sso".to_string()]);
    assert_eq!(eff.limits["seats"], 10);
    c.user_erasure("user_1")
        .schedule_deletion(
            &ScheduleDeletionBody {
                grace_seconds: Some(60),
                audit_actor_emails: Some(vec!["a@b.co".into()]),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    c.notification_categories().delete("marketing").await.unwrap();
    c.notification_templates().get("welcome").await.unwrap();

    let got: Vec<(HttpMethod, String)> = fake
        .requests()
        .into_iter()
        .map(|r| (r.method, r.url.replace("https://api.atlasauth.net", "")))
        .collect();
    assert_eq!(got[0], (HttpMethod::Post, "/v1/tickets".into()));
    assert_eq!(got[1], (HttpMethod::Post, "/v1/tickets/redeem".into()));
    assert_eq!(got[2], (HttpMethod::Post, "/v1/notifications".into()));
    assert_eq!(got[3], (HttpMethod::Get, "/v1/organizations/org_1/entitlements".into()));
    assert_eq!(got[4], (HttpMethod::Post, "/v1/users/user_1/deletion".into()));
    assert_eq!(got[5], (HttpMethod::Delete, "/v1/notification_categories/marketing".into()));
    assert_eq!(got[6], (HttpMethod::Get, "/v1/notification_templates/welcome".into()));
    assert_eq!(
        serde_json::from_str::<Value>(fake.requests()[4].body.as_deref().unwrap()).unwrap(),
        json!({"grace_seconds":60,"audit_actor_emails":["a@b.co"]})
    );
}

// ── cursors on the two lists ──────────────────────────────────────────────

fn paged_fake() -> FakeTransport {
    FakeTransport::new(|req| {
        let body = if req.url.contains("starting_after=c1") {
            r#"{"data":[{"id":"i3"}],"has_more":false}"#
        } else {
            r#"{"data":[{"id":"i1"},{"id":"i2"}],"has_more":true,"next_cursor":"c1"}"#
        };
        HttpResponse { status: 200, body: body.into() }
    })
}

#[tokio::test]
async fn org_memberships_list_paginates_by_cursor() {
    let fake = paged_fake();
    let c = client(&fake);
    let all = collect(|cursor| {
        let c = &c;
        async move {
            c.organizations()
                .memberships("org_1")
                .list(CursorParams { starting_after: cursor, limit: Some(2) })
                .await
        }
    })
    .await
    .unwrap();
    assert_eq!(all.len(), 3);
    assert!(fake.requests()[1].url.contains("starting_after=c1"));
    assert!(fake.requests()[0].url.contains("/v1/organizations/org_1/memberships?limit=2"));
}

#[tokio::test]
async fn api_keys_list_and_user_memberships_paginate_by_cursor() {
    let fake = paged_fake();
    let c = client(&fake);
    let all = collect(|cursor| {
        let c = &c;
        async move {
            c.api_keys()
                .list(Some("user"), Some("user_1"), CursorParams { starting_after: cursor, limit: None })
                .await
        }
    })
    .await
    .unwrap();
    assert_eq!(all.len(), 3);
    let second = &fake.requests()[1].url;
    assert!(second.contains("starting_after=c1") && second.contains("subject_type=user"));

    let page = c.users().organization_memberships("user_1", CursorParams::default()).await.unwrap();
    assert!(page.has_more);
    assert!(fake.requests()[2].url.ends_with("/v1/users/user_1/organization_memberships"));
}

// ── ApiKeyVerifier cache bound + invalidate ───────────────────────────────

struct MockVerify {
    calls: AtomicUsize,
    revoked: AtomicBool,
}

impl HttpPost for MockVerify {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _bearer: &'a str,
        body: String,
    ) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let valid = !self.revoked.load(Ordering::SeqCst);
        let _ = body;
        Box::pin(async move {
            Ok(HttpResponse { status: 200, body: json!({ "valid": valid, "id": "ak_1" }).to_string() })
        })
    }
}

fn ticking_clock() -> Clock {
    let t = Arc::new(AtomicUsize::new(1000));
    Arc::new(move || t.fetch_add(1, Ordering::SeqCst) as u64)
}

#[tokio::test]
async fn api_key_cache_evicts_at_capacity() {
    let mock = Arc::new(MockVerify { calls: AtomicUsize::new(0), revoked: AtomicBool::new(false) });
    let v = ApiKeyVerifier::builder("sk_test")
        .transport(mock.clone())
        .clock(ticking_clock())
        .max_entries(2)
        .build()
        .unwrap();

    for k in ["ak_a", "ak_b", "ak_c"] {
        assert!(v.verify(k).await.unwrap().valid);
    }
    assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
    // ak_c (newest) is still cached; ak_a (oldest) was evicted and must refetch.
    v.verify("ak_c").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
    v.verify("ak_a").await.unwrap();
    assert_eq!(mock.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn api_key_invalidate_makes_a_revoked_key_stop_verifying() {
    let mock = Arc::new(MockVerify { calls: AtomicUsize::new(0), revoked: AtomicBool::new(false) });
    let v = ApiKeyVerifier::builder("sk_test").transport(mock.clone()).build().unwrap();

    assert!(v.verify("ak_x").await.unwrap().valid);
    mock.revoked.store(true, Ordering::SeqCst);
    // Still served from the positive cache until invalidated.
    assert!(v.verify("ak_x").await.unwrap().valid);
    v.invalidate("ak_x");
    assert!(!v.verify("ak_x").await.unwrap().valid);

    // clear() drops everything, negatives included.
    mock.revoked.store(false, Ordering::SeqCst);
    assert!(!v.verify("ak_x").await.unwrap().valid); // negative-cached
    v.clear();
    assert!(v.verify("ak_x").await.unwrap().valid);
}

// ── FakeTransport-served JWKS ─────────────────────────────────────────────

fn key() -> &'static (Vec<u8>, String, String) {
    static K: OnceLock<(Vec<u8>, String, String)> = OnceLock::new();
    K.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = sk.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec();
        let pk = RsaPublicKey::from(&sk);
        (
            pem,
            URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be()),
        )
    })
}

#[tokio::test]
async fn token_verifies_against_fake_transport_served_jwks() {
    let (pem, n, e) = key();
    let fake = FakeTransport::with_signing_key("kid-t", pem.clone(), n.clone(), e.clone());
    let issuer = "https://inst.fapi.atlasauth.net";
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let token = fake
        .sign_token(&json!({
            "iss": issuer, "sub": "user_9", "sid": "sess_9",
            "iat": now - 10, "nbf": now - 10, "exp": now + 600,
            "token_use": "session", "aud": issuer,
        }))
        .expect("signed");

    let backend = AtlasBackend::builder(issuer)
        .jwks_url(format!("{issuer}/.well-known/jwks.json"))
        .jwks_source(Arc::new(fake.clone()))
        .build()
        .unwrap();
    let claims = backend.verify(&token).await.expect("verifies via fake JWKS");
    assert_eq!(claims.sub, "user_9");
    assert!(fake.requests()[0].url.ends_with("/.well-known/jwks.json"));
    assert_eq!(fake.jwks().unwrap().keys[0].kid.as_deref(), Some("kid-t"));
    assert_eq!(fake.jwks_json().unwrap()["keys"][0]["alg"], "RS256");
}
