//! The Better Auth migration surface: bundle import (upload in line-aligned
//! parts, finalize, wait), bridge settings, the secret-key session exchange
//! (forwarded end-user IP / user agent, never retried, classified) and the
//! framework-neutral bridge decision.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use atlasauth::backend::{
    better_auth_cookie_names, client_ip_from_headers, exchange_better_auth_session, read_better_auth_session_cookie,
    split_bundle_parts, types, BackendClient, BackendError, BetterAuthBridge, BetterAuthExchangeResult, BridgeAction,
    BridgeRefusal, ExchangeParams, FakeTransport, UploadOptions, WaitOptions, BETTER_AUTH_EXCHANGE_PATH,
    BETTER_AUTH_IMPORT_PART_BYTES,
};
use atlasauth::{HttpMethod, HttpRequest, HttpResponse};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_secret")
        .base_url("https://api.atlas.test")
        .transport(Arc::new(fake.clone()))
        .base_delay_ms(1)
        .build()
        .unwrap()
}

fn ok(body: Value) -> HttpResponse {
    HttpResponse { status: 200, body: body.to_string() }
}

fn err(status: u16, code: &str, outcome: Option<&str>) -> HttpResponse {
    let mut item = json!({ "code": code, "message": "refused" });
    if let Some(o) = outcome {
        item["meta"] = json!({ "bridge_outcome": o });
    }
    HttpResponse { status, body: json!({ "errors": [item] }).to_string() }
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn body(req: &HttpRequest) -> Value {
    serde_json::from_str(req.body.as_deref().unwrap_or("null")).unwrap()
}

fn import(status: &str) -> Value {
    json!({ "object": "better_auth_import", "id": "bai_1", "status": status, "created_at": 1, "updated_at": 2,
            "parts": 2, "progress": { "total": 3, "processed": 1, "succeeded": 1, "failed": 0, "percent": 33 } })
}

// ── bundle import ────────────────────────────────────────────────────────────

#[test]
fn splits_bundles_on_line_boundaries() {
    let bundle = "aaaa\n\nbbbb\r\ncccc\ndddddddddddd\ne";
    let parts = split_bundle_parts(bundle, 10);
    assert_eq!(parts, vec!["aaaa\nbbbb\n", "cccc\n", "dddddddddddd\n", "e\n"]);
    assert!(parts.iter().all(|p| p.ends_with('\n')));
    assert_eq!(split_bundle_parts("\n\n", 10), Vec::<String>::new());
    assert_eq!(split_bundle_parts("x\ny", BETTER_AUTH_IMPORT_PART_BYTES), vec!["x\ny\n"]);
    // Multi-byte lines are counted in UTF-8 bytes.
    assert_eq!(split_bundle_parts("éé\néé", 5), vec!["éé\n", "éé\n"]);
    assert_eq!(BETTER_AUTH_IMPORT_PART_BYTES, 8 * 1024 * 1024);
}

#[tokio::test]
async fn upload_creates_sends_each_part_and_finalizes() {
    let fake = FakeTransport::new(|req: &HttpRequest| {
        if req.url.ends_with("/v1/better_auth_imports") && req.method == HttpMethod::Post {
            HttpResponse { status: 201, body: import("uploading").to_string() }
        } else if req.url.contains("/parts/") {
            let part = req.url.rsplit('/').next().unwrap().to_string();
            ok(json!({ "object": "better_auth_import_part", "import_id": "bai_1", "part": part.parse::<i64>().unwrap(), "bytes": 5, "sha256": "x" }))
        } else if req.url.ends_with("/finalize") {
            ok(import("ready"))
        } else {
            err(404, "NOT_FOUND", None)
        }
    });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let opts = UploadOptions {
        options: Some(types::BetterAuthImportOptionsInput::new().with_import_sessions(true).with_models(vec!["user".to_string()])),
        part_bytes: Some(10),
        on_part: Some(Box::new(move |n, of| s2.lock().unwrap().push((n, of)))),
    };
    let imp = client(&fake).better_auth_imports().upload("line-one\nline-two\nline-3", opts).await.unwrap();
    assert_eq!(imp.status, "ready");
    assert_eq!(imp.progress.as_ref().and_then(|p| p.percent), Some(33));
    assert_eq!(*seen.lock().unwrap(), vec![(1, 3), (2, 3), (3, 3)]);

    let reqs = fake.requests();
    let urls: Vec<String> = reqs.iter().map(|r| format!("{} {}", r.method.as_str(), r.url)).collect();
    assert_eq!(
        urls,
        vec![
            "POST https://api.atlas.test/v1/better_auth_imports",
            "PUT https://api.atlas.test/v1/better_auth_imports/bai_1/parts/1",
            "PUT https://api.atlas.test/v1/better_auth_imports/bai_1/parts/2",
            "PUT https://api.atlas.test/v1/better_auth_imports/bai_1/parts/3",
            "POST https://api.atlas.test/v1/better_auth_imports/bai_1/finalize",
        ]
    );
    assert_eq!(body(&reqs[0]), json!({ "options": { "import_sessions": true, "models": ["user"] } }));
    assert_eq!(body(&reqs[1]), json!({ "data": "line-one\n" }));
    assert_eq!(body(&reqs[3]), json!({ "data": "line-3\n" }));
    assert!(reqs.iter().all(|r| header(r, "authorization") == Some("Bearer sk_test_secret")));
}

#[tokio::test]
async fn upload_refuses_an_empty_bundle_before_any_call() {
    let fake = FakeTransport::json_ok("{}");
    let out = client(&fake).better_auth_imports().upload("\n \n".trim(), UploadOptions::default()).await;
    assert!(matches!(out, Err(BackendError::Malformed(_))));
    assert_eq!(fake.request_count(), 0);
}

#[tokio::test]
async fn wait_for_polls_until_the_import_settles_or_times_out() {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let fake = FakeTransport::new(move |_req: &HttpRequest| {
        let i = n2.fetch_add(1, Ordering::SeqCst);
        ok(import(["analyzing", "queued", "applying", "completed"][i.min(3)]))
    });
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let s2 = statuses.clone();
    let imp = client(&fake)
        .better_auth_imports()
        .wait_for(
            "bai_1",
            WaitOptions {
                interval: Duration::from_millis(1),
                timeout: Duration::from_secs(5),
                on_progress: Some(Box::new(move |imp: &types::BetterAuthImport| s2.lock().unwrap().push(imp.status.clone()))),
            },
        )
        .await
        .unwrap();
    assert_eq!(imp.status, "completed");
    assert_eq!(*statuses.lock().unwrap(), vec!["analyzing", "queued", "applying", "completed"]);
    assert!(fake.requests().iter().all(|r| r.method == HttpMethod::Get && r.url.ends_with("/v1/better_auth_imports/bai_1")));

    let stuck = FakeTransport::new(|_req: &HttpRequest| ok(import("applying")));
    let out = client(&stuck)
        .better_auth_imports()
        .wait_for("bai_1", WaitOptions { interval: Duration::from_millis(1), timeout: Duration::from_millis(5), on_progress: None })
        .await;
    match out {
        Err(BackendError::Transport(e)) => assert!(e.to_string().contains("applying"), "{e}"),
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn the_rest_of_the_import_surface_hits_its_routes() {
    let fake = FakeTransport::new(|req: &HttpRequest| {
        if req.url.contains("public_key") {
            ok(json!({ "object": "better_auth_import_key", "kid": "baik_1", "public_key": "pk", "alg": "X25519-HKDF-SHA256-A256GCM",
                       "status": "active", "fingerprint": "fp", "compact": "baik_1:pk", "created_at": 1 }))
        } else if req.url.contains("/jwks") && req.method == HttpMethod::Get {
            ok(json!({ "object": "list", "data": [{ "object": "imported_jwk", "kid": "k1" }], "has_more": false }))
        } else if req.method == HttpMethod::Delete {
            ok(json!({ "object": "better_auth_import", "id": "bai_1", "deleted": true }))
        } else if req.method == HttpMethod::Get && req.url.ends_with("/v1/better_auth_imports?limit=5") {
            ok(json!({ "object": "list", "data": [import("ready")], "has_more": false }))
        } else {
            ok(import("ready"))
        }
    });
    let c = client(&fake);
    let bai = c.better_auth_imports();
    assert_eq!(bai.get_public_key().await.unwrap().compact, "baik_1:pk");
    assert_eq!(bai.rotate_public_key().await.unwrap().kid, "baik_1");
    let page = bai.list(&atlasauth::backend::Query::new().set("limit", 5)).await.unwrap();
    assert_eq!(page.data[0].id, "bai_1");
    bai.dry_run("bai_1", &types::BetterAuthImportsDryRunBody::new()).await.unwrap();
    bai.apply("bai_1", &types::BetterAuthImportsApplyBody::new().with_confirm_conflicts(true)).await.unwrap();
    assert_eq!(bai.list_jwks(&atlasauth::backend::Query::new()).await.unwrap().data.len(), 1);
    bai.delete_jwk("k1").await.unwrap();
    bai.delete("bai_1").await.unwrap();
    let reqs = fake.requests();
    let apply = reqs.iter().find(|r| r.url.ends_with("/apply")).unwrap();
    assert_eq!(body(apply), json!({ "confirm_conflicts": true }));
    assert!(reqs.iter().any(|r| r.method == HttpMethod::Post && r.url.ends_with("/v1/better_auth_imports/public_key/rotate")));
    assert!(reqs.iter().any(|r| r.method == HttpMethod::Delete && r.url.ends_with("/v1/better_auth_imports/jwks/k1")));
}

// ── bridge settings ──────────────────────────────────────────────────────────

#[tokio::test]
async fn bridge_settings_get_update_delete() {
    let view = json!({ "object": "better_auth_bridge", "enabled": true, "ends_at": 1_798_675_200_000i64, "cookie_prefix": "myapp",
        "live_fallback": { "enabled": true, "base_url": "https://app.example.com/api/auth", "has_secret": true },
        "exchange_path": "/v1/client/migrations/better_auth/exchange", "stats": { "exchanged": 4, "from_import": 3, "from_live": 1 },
        "created_at": 1, "updated_at": 2 });
    let v2 = view.clone();
    let fake = FakeTransport::new(move |req: &HttpRequest| {
        if req.method == HttpMethod::Delete {
            ok(json!({ "object": "better_auth_bridge", "deleted": true }))
        } else {
            ok(v2.clone())
        }
    });
    let c = client(&fake);
    let s = c.better_auth_bridge().get().await.unwrap();
    assert_eq!(s.enabled, Some(true));
    assert_eq!(s.live_fallback.as_ref().and_then(|l| l.has_secret), Some(true));
    assert_eq!(s.stats.as_ref().and_then(|x| x.exchanged), Some(4));
    let upd = types::BetterAuthBridgeUpdateBody::new()
        .with_enabled(true)
        .with_ends_at("2026-12-31T00:00:00Z")
        .with_cookie_prefix("myapp")
        .with_live_fallback(
            types::BetterAuthBridgeUpdateBodyLiveFallback::new()
                .with_enabled(true)
                .with_base_url("https://app.example.com/api/auth")
                .with_secret("0123456789abcdef0123"),
        );
    c.better_auth_bridge().update(&upd, Some("idem-1")).await.unwrap();
    c.better_auth_bridge()
        .update(
            &types::BetterAuthBridgeUpdateBody::new()
                .with_ends_at(Value::Null)
                .with_live_fallback(types::BetterAuthBridgeUpdateBodyLiveFallback::new().clear_secret()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(c.better_auth_bridge().delete(None).await.unwrap().deleted, Some(true));
    let reqs = fake.requests();
    assert!(reqs.iter().all(|r| r.url == "https://api.atlas.test/v1/migrations/better_auth/bridge"));
    assert_eq!(
        body(&reqs[1]),
        json!({ "enabled": true, "ends_at": "2026-12-31T00:00:00Z", "cookie_prefix": "myapp",
                "live_fallback": { "enabled": true, "base_url": "https://app.example.com/api/auth", "secret": "0123456789abcdef0123" } })
    );
    assert_eq!(header(&reqs[1], "idempotency-key"), Some("idem-1"));
    assert_eq!(body(&reqs[2]), json!({ "ends_at": null, "live_fallback": { "secret": null } }));
    assert_eq!(reqs[3].method, HttpMethod::Delete);
}

// ── the exchange ─────────────────────────────────────────────────────────────

fn session_tokens() -> Value {
    json!({ "object": "session_tokens", "session_id": "sess_1", "user_id": "user_1", "jwt": "eyJ.jwt", "refresh_token": "rt_1", "expires_in": 60 })
}

#[tokio::test]
async fn exchange_forwards_the_end_user_and_never_retries() {
    let fake = FakeTransport::new(|_req: &HttpRequest| ok(session_tokens()));
    let c = client(&fake);
    let params = ExchangeParams {
        client_ip: Some("203.0.113.9".into()),
        user_agent: Some("Mozilla/5.0 test".into()),
        remember: Some(false),
    };
    let raw = c.better_auth_bridge().exchange("tok.sig", &params).await.unwrap();
    assert_eq!(raw["jwt"], "eyJ.jwt");
    let req = &fake.requests()[0];
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(req.url, format!("https://api.atlas.test{BETTER_AUTH_EXCHANGE_PATH}"));
    assert_eq!(header(req, "authorization"), Some("Bearer sk_test_secret"));
    assert_eq!(header(req, "x-atlas-client-ip"), Some("203.0.113.9"));
    assert_eq!(header(req, "x-atlas-client-user-agent"), Some("Mozilla/5.0 test"));
    assert_eq!(body(req), json!({ "token": "tok.sig", "remember": false }));

    // Without params nothing extra is sent and `remember` is left to the default.
    c.better_auth_bridge().exchange("tok", &ExchangeParams::default()).await.unwrap();
    let req = &fake.requests()[1];
    assert_eq!(header(req, "x-atlas-client-ip"), None);
    assert_eq!(body(req), json!({ "token": "tok" }));

    // A 5xx / 429 is NOT retried: the token is single use.
    for status in [503u16, 429] {
        let down = FakeTransport::new(move |_req: &HttpRequest| err(status, "UNAVAILABLE", None));
        let _ = client(&down).better_auth_bridge().exchange("tok", &ExchangeParams::default()).await;
        assert_eq!(down.request_count(), 1, "status {status}");
    }
}

#[tokio::test]
async fn exchange_results_are_classified() {
    async fn run(resp: HttpResponse) -> BetterAuthExchangeResult {
        let fake = FakeTransport::new(move |_req: &HttpRequest| HttpResponse { status: resp.status, body: resp.body.clone() });
        exchange_better_auth_session(&client(&fake), "tok", &ExchangeParams::default()).await
    }
    match run(ok(session_tokens())).await {
        BetterAuthExchangeResult::Session(s) => {
            assert_eq!((s.jwt.as_str(), s.refresh_token.as_str(), s.session_id.as_str(), s.user_id.as_str(), s.expires_in), ("eyJ.jwt", "rt_1", "sess_1", "user_1", 60))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        run(ok(json!({ "object": "sign_in_attempt", "id": "sia_1", "status": "needs_second_factor" }))).await,
        BetterAuthExchangeResult::NeedsMfa { attempt_id: "sia_1".into(), status: "needs_second_factor".into() }
    );
    for (outcome, want) in [
        ("closed", BridgeRefusal::Closed),
        ("invalid", BridgeRefusal::Invalid),
        ("signature_invalid", BridgeRefusal::SignatureInvalid),
        ("expired", BridgeRefusal::Expired),
        ("reused", BridgeRefusal::Reused),
        ("user_unavailable", BridgeRefusal::UserUnavailable),
    ] {
        assert_eq!(
            run(err(400, "BAD", Some(outcome))).await,
            BetterAuthExchangeResult::Refused { outcome: want, http_status: 400 }
        );
        assert_eq!(want.as_str(), outcome);
    }
    assert_eq!(
        run(err(429, "RATE_LIMITED", Some("rate_limited"))).await,
        BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::RateLimited, http_status: 429 }
    );
    assert_eq!(
        run(err(500, "INTERNAL", None)).await,
        BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::Unavailable, http_status: 500 }
    );
    assert_eq!(
        run(err(403, "FORBIDDEN", Some("something_new"))).await,
        BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::Unavailable, http_status: 403 }
    );
    assert_eq!(
        run(ok(json!({ "object": "weird" }))).await,
        BetterAuthExchangeResult::Refused { outcome: BridgeRefusal::Unavailable, http_status: 200 }
    );
    assert!(BridgeRefusal::Reused.is_final() && !BridgeRefusal::Closed.is_final() && !BridgeRefusal::RateLimited.is_final());
}

// ── cookies + the bridge decision ────────────────────────────────────────────

#[test]
fn cookie_names_and_reading() {
    let (session, all) = better_auth_cookie_names("better-auth");
    assert_eq!(session, vec!["__Secure-better-auth.session_token", "better-auth.session_token"]);
    assert_eq!(all.len(), 8);
    assert!(all.contains(&"__Secure-better-auth.dont_remember".to_string()));
    let header = "a=1; better-auth.session_token=plain; __Secure-better-auth.session_token=secure";
    assert_eq!(read_better_auth_session_cookie(Some(header), "better-auth", None).as_deref(), Some("secure"));
    assert_eq!(read_better_auth_session_cookie(Some("better-auth.session_token=p"), "better-auth", None).as_deref(), Some("p"));
    assert_eq!(read_better_auth_session_cookie(Some("myapp.session_token=m"), "myapp", None).as_deref(), Some("m"));
    assert_eq!(read_better_auth_session_cookie(Some("sid=x"), "better-auth", Some("sid")).as_deref(), Some("x"));
    assert_eq!(read_better_auth_session_cookie(None, "better-auth", None), None);
    assert_eq!(client_ip_from_headers(Some(" 198.51.100.1, 10.0.0.1"), Some("10.0.0.2")).as_deref(), Some("198.51.100.1"));
    assert_eq!(client_ip_from_headers(None, Some("10.0.0.2")).as_deref(), Some("10.0.0.2"));
}

fn bridge_with(resp: HttpResponse) -> (BetterAuthBridge, FakeTransport) {
    let fake = FakeTransport::new(move |_req: &HttpRequest| HttpResponse { status: resp.status, body: resp.body.clone() });
    (BetterAuthBridge::new(client(&fake)), fake)
}

#[tokio::test]
async fn the_bridge_does_nothing_without_a_better_auth_cookie_or_with_an_atlas_session() {
    let (bridge, fake) = bridge_with(ok(session_tokens()));
    assert_eq!(bridge.decide(None, None, None).await.action, BridgeAction::None);
    assert_eq!(bridge.decide(Some("other=1"), None, None).await.action, BridgeAction::None);
    let d = bridge.decide(Some("better-auth.session_token=t; __session=eyJ"), None, None).await;
    assert_eq!(d.action, BridgeAction::None);
    assert!(!d.should_redirect());
    assert_eq!(fake.request_count(), 0);
}

#[tokio::test]
async fn signed_in_sets_atlas_cookies_and_clears_better_auth() {
    let (bridge, fake) = bridge_with(ok(session_tokens()));
    let bridge = bridge.cookie_prefix("myapp").better_auth_cookie_domain(".example.com");
    let d = bridge.decide(Some("myapp.session_token=tok.sig"), Some("203.0.113.9"), Some("UA")).await;
    assert_eq!(d.action, BridgeAction::SignedIn);
    assert!(d.should_redirect());
    assert_eq!(d.session.as_ref().unwrap().user_id, "user_1");
    let set: Vec<String> = d.cookies.iter().map(|c| c.to_set_cookie()).collect();
    assert_eq!(set[0], "__session=eyJ.jwt; Path=/; Secure; SameSite=Lax");
    assert_eq!(set[1], "__atlas_rt=rt_1; Path=/; HttpOnly; Secure; SameSite=Lax");
    assert!(set.contains(&"myapp.session_token=; Path=/; Domain=.example.com; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string()));
    assert!(set.contains(
        &"__Secure-myapp.session_token=; Path=/; Domain=.example.com; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure".to_string()
    ));
    let req = &fake.requests()[0];
    assert_eq!(body(req), json!({ "token": "tok.sig" }));
    assert_eq!(header(req, "x-atlas-client-ip"), Some("203.0.113.9"));
    assert_eq!(header(req, "x-atlas-client-user-agent"), Some("UA"));

    let insecure = bridge.secure(false).decision_for(BetterAuthExchangeResult::Session(d.session.unwrap()));
    assert_eq!(insecure.cookies[0].to_set_cookie(), "__session=eyJ.jwt; Path=/; SameSite=Lax");
}

#[tokio::test]
async fn needs_mfa_clears_the_spent_cookie_and_carries_the_attempt() {
    let (bridge, _) = bridge_with(ok(json!({ "object": "sign_in_attempt", "id": "sia_1", "status": "needs_mfa_enrollment" })));
    let d = bridge.decide(Some("better-auth.session_token=t"), None, None).await;
    assert_eq!(d.action, BridgeAction::NeedsMfa);
    assert!(!d.cookies.is_empty() && d.cookies.iter().all(|c| c.max_age == Some(0)));
    assert_eq!(
        d.continuation_url("/sign-in?next=%2Fdash&__atlas_attempt=old#top"),
        "/sign-in?next=%2Fdash&__atlas_attempt=sia_1&__atlas_status=needs_mfa_enrollment#top"
    );
    assert_eq!(d.continuation_url("https://app.test/login"), "https://app.test/login?__atlas_attempt=sia_1&__atlas_status=needs_mfa_enrollment");
}

#[tokio::test]
async fn refusals_clear_only_when_final() {
    let (bridge, _) = bridge_with(err(400, "INVALID", Some("reused")));
    let d = bridge.decide(Some("better-auth.session_token=t"), None, None).await;
    assert_eq!((d.action, d.outcome), (BridgeAction::Refused, Some(BridgeRefusal::Reused)));
    assert!(d.should_redirect() && !d.cookies.is_empty());

    for resp in [err(403, "CLOSED", Some("closed")), err(429, "RATE_LIMITED", Some("rate_limited")), err(502, "BAD_GATEWAY", None)] {
        let (bridge, _) = bridge_with(resp);
        let d = bridge.decide(Some("better-auth.session_token=t"), None, None).await;
        assert_eq!(d.action, BridgeAction::Refused);
        assert!(d.cookies.is_empty() && !d.should_redirect(), "{:?}", d.outcome);
    }

    let (custom, _) = bridge_with(err(400, "INVALID", Some("expired")));
    let d = custom.cookie_name("sid").decide(Some("sid=t"), None, None).await;
    let names: Vec<&str> = d.cookies.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"sid") && names.contains(&"__Secure-sid"));
}
