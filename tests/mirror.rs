//! The local mirrors: end-user API keys, the revoked-session list and resource-role assignments. The Atlas
//! side is a `FakeTransport`; no network.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::mirror::{
    hash_api_key_secret, ip_in_allowlist, InvalidCode, KeyMirror, KeyMirrorOptions, MemoryKeyMirrorStore, MemoryResourceRoleMirrorStore,
    MirrorImport, MirrorSubject, MirrorVerification, ResourceRef, ResourceRoleCheckOptions, ResourceRoleMirror, ResourceRoleMirrorOptions,
    SidListRevocation, SidRevocationList, SidStaleAction,
};
use atlasauth::{Clock, HttpResponse};
use serde_json::{json, Value};

fn ok(v: Value) -> HttpResponse {
    HttpResponse { status: 200, body: v.to_string() }
}

fn client(t: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x").transport(Arc::new(t.clone())).max_retries(0).build().unwrap()
}

fn clock(cell: &Arc<AtomicU64>) -> Clock {
    let c = cell.clone();
    Arc::new(move || c.load(Ordering::SeqCst))
}

fn path(url: &str) -> &str {
    url.split('?').next().unwrap().trim_start_matches("https://api.atlasauth.net")
}

fn key_json(id: &str) -> Value {
    json!({ "object": "api_key", "id": id, "prefix": "ak_0123", "subject_type": "organization", "subject_id": "org_1",
        "name": "CI", "scopes": ["calls:write"], "expires_at": null, "revoked_at": null })
}

// ── key mirror ──────────────────────────────────────────────────────────────

fn key_atlas(revoked: Arc<Mutex<Vec<(String, i64)>>>) -> FakeTransport {
    FakeTransport::new(move |req| match (req.method.as_str(), path(&req.url)) {
        ("POST", "/v1/api_keys") => {
            let body: Value = serde_json::from_str(req.body.as_deref().unwrap_or("{}")).unwrap();
            if body.get("import").is_some() {
                ok(key_json("eak_imp"))
            } else {
                let mut k = key_json("eak_new");
                k["secret"] = json!("ak_0123_secret");
                ok(k)
            }
        }
        ("DELETE", _) => HttpResponse { status: 500, body: "{}".into() },
        ("GET", "/v1/api_keys/revoked") => {
            // Two rows per page; the cursor is the index of the last row served.
            let since: Option<usize> = req.url.split("since=").nth(1).and_then(|s| s.split('&').next()).and_then(|s| s.parse().ok());
            let from = since.map(|s| s + 1).unwrap_or(0);
            let all = revoked.lock().unwrap().clone();
            let page: Vec<_> = all.iter().skip(from).take(2).collect();
            ok(json!({
                "data": page.iter().map(|(id, at)| json!({ "object": "api_key", "id": id, "revoked_at": at })).collect::<Vec<_>>(),
                "has_more": from + 2 < all.len(),
                "next_cursor": if page.is_empty() { Value::Null } else { json!((from + page.len() - 1).to_string()) },
            }))
        }
        _ => HttpResponse { status: 404, body: "{}".into() },
    })
}

#[tokio::test]
async fn mint_mirrors_the_hash_and_verifies_locally_with_scope_implications() {
    let t = key_atlas(Arc::default());
    let store = Arc::new(MemoryKeyMirrorStore::new());
    let mut opts = KeyMirrorOptions::default();
    opts.scope_implications.insert("calls:write".into(), vec!["calls:read".into()]);
    let mirror = KeyMirror::new(store.clone(), client(&t), opts);

    let created = mirror.mint(json!({ "subject_type": "organization", "subject_id": "org_1" }), Some("idem-1")).await.unwrap();
    assert_eq!(created["secret"], "ak_0123_secret");
    assert_eq!(t.requests().len(), 1);
    assert!(t.requests()[0].headers.iter().any(|(k, v)| k == "idempotency-key" && v == "idem-1"));

    match mirror.verify("ak_0123_secret", &["calls:read".to_string()], None).await.unwrap() {
        MirrorVerification::Valid { key, effective_scopes, .. } => {
            assert_eq!(key.hash, hash_api_key_secret("ak_0123_secret"));
            assert_eq!(effective_scopes, vec!["calls:read".to_string(), "calls:write".to_string()]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(t.requests().len(), 1, "verify made no network call");
    assert!(!mirror.verify("wrong", &[], None).await.unwrap().is_valid());
    assert!(!mirror.verify("", &[], None).await.unwrap().is_valid());
    match mirror.verify("ak_0123_secret", &["billing:write".to_string()], None).await.unwrap() {
        MirrorVerification::Invalid { code, missing_scopes } => {
            assert_eq!(code, Some(InvalidCode::InsufficientScope));
            assert_eq!(missing_scopes, vec!["billing:write".to_string()]);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn revoke_stops_the_key_locally_even_when_atlas_fails() {
    let t = key_atlas(Arc::default());
    let mirror = KeyMirror::new(Arc::new(MemoryKeyMirrorStore::new()), client(&t), KeyMirrorOptions::default());
    mirror.mint(json!({}), None).await.unwrap();
    assert!(mirror.revoke("eak_new").await.is_err(), "the Atlas 500 is returned for a retry");
    assert!(!mirror.verify("ak_0123_secret", &[], None).await.unwrap().is_valid());
}

#[tokio::test]
async fn import_stores_the_sha256_and_refuses_a_bad_hash() {
    let t = key_atlas(Arc::default());
    let mirror = KeyMirror::new(Arc::new(MemoryKeyMirrorStore::new()), client(&t), KeyMirrorOptions::default());
    let input = MirrorImport { secret: Some("ak_0123_old_secret".into()), prefix: "ak_0123".into(), ..Default::default() };
    let imported = mirror.import(input, None).await.unwrap();
    assert_eq!(imported["outcome"], "created");
    let sent: Value = serde_json::from_str(t.requests()[0].body.as_deref().unwrap()).unwrap();
    assert_eq!(sent["import"]["hash_algorithm"], "sha256_hex");
    assert_eq!(sent["import"]["secret_hash"], hash_api_key_secret("ak_0123_old_secret"));
    assert!(mirror.verify("ak_0123_old_secret", &[], None).await.unwrap().is_valid());
    let bad = MirrorImport { secret_hash: Some("nothex".into()), prefix: "p".into(), ..Default::default() };
    assert!(mirror.import(bad, None).await.is_err());
}

#[tokio::test]
async fn sync_consumes_the_revocation_feed_across_pages_and_gates_on_staleness() {
    let revoked = Arc::new(Mutex::new(vec![("eak_new".to_string(), 5i64), ("other".to_string(), 6), ("third".to_string(), 7)]));
    let t = key_atlas(revoked.clone());
    let now = Arc::new(AtomicU64::new(1_000_000));
    let opts = KeyMirrorOptions { max_staleness_ms: Some(60_000), serve_stale_for_ms: 30_000, ..Default::default() };
    let mirror = KeyMirror::new(Arc::new(MemoryKeyMirrorStore::new()), client(&t), opts).with_clock(clock(&now));
    mirror.mint(json!({}), None).await.unwrap();

    // Never synced: refuse rather than trust a list a revocation may not have reached.
    assert!(matches!(mirror.verify("ak_0123_secret", &[], None).await.unwrap(), MirrorVerification::Stale { last_sync_at: None }));
    revoked.lock().unwrap().clear();
    assert_eq!(mirror.sync().await.unwrap(), 0);
    assert!(mirror.verify("ak_0123_secret", &[], None).await.unwrap().is_valid());

    now.fetch_add(70_000, Ordering::SeqCst); // past the bound, inside the grace
    match mirror.verify("ak_0123_secret", &[], None).await.unwrap() {
        MirrorVerification::Valid { stale, .. } => assert!(stale),
        other => panic!("{other:?}"),
    }
    now.fetch_add(60_000, Ordering::SeqCst); // past the grace
    assert!(matches!(mirror.verify("ak_0123_secret", &[], None).await.unwrap(), MirrorVerification::Stale { .. }));

    revoked.lock().unwrap().extend([("eak_new".to_string(), 5i64), ("x".to_string(), 6), ("y".to_string(), 7)]);
    assert_eq!(mirror.sync().await.unwrap(), 3, "two pages of the feed");
    assert!(!mirror.verify("ak_0123_secret", &[], None).await.unwrap().is_valid());
}

#[tokio::test]
async fn a_key_with_an_ip_allowlist_needs_a_caller_inside_it() {
    let t = key_atlas(Arc::default());
    let store = Arc::new(MemoryKeyMirrorStore::new());
    let mirror = KeyMirror::new(store.clone(), client(&t), KeyMirrorOptions::default());
    mirror.mint(json!({}), None).await.unwrap();
    use atlasauth::mirror::KeyMirrorStore;
    let mut k = store.get("eak_new").unwrap().unwrap();
    k.allowed_ips = Some(vec!["10.0.0.0/8".into()]);
    store.put(k).unwrap();
    let code = |v: MirrorVerification| match v {
        MirrorVerification::Invalid { code, .. } => code,
        MirrorVerification::Valid { .. } => None,
        other => panic!("{other:?}"),
    };
    assert_eq!(code(mirror.verify("ak_0123_secret", &[], None).await.unwrap()), Some(InvalidCode::ClientIpRequired));
    assert_eq!(code(mirror.verify("ak_0123_secret", &[], Some("192.168.1.1")).await.unwrap()), Some(InvalidCode::IpNotAllowed));
    assert!(mirror.verify("ak_0123_secret", &[], Some("10.1.2.3")).await.unwrap().is_valid());
}

#[test]
fn ip_allowlist_matches_cidr_ranges_and_never_matches_garbage() {
    let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(ip_in_allowlist("10.1.2.3", &l(&["10.0.0.0/8"])));
    assert!(!ip_in_allowlist("11.0.0.1", &l(&["10.0.0.0/8"])));
    assert!(ip_in_allowlist("203.0.113.9", &l(&["203.0.113.9"])));
    assert!(ip_in_allowlist("2001:db8::1", &l(&["2001:db8::/32"])));
    assert!(!ip_in_allowlist("2001:db9::1", &l(&["2001:db8::/32"])));
    assert!(!ip_in_allowlist("10.0.0.1", &l(&["2001:db8::/32"])));
    assert!(!ip_in_allowlist("not an ip", &l(&["0.0.0.0/0"])));
    assert!(ip_in_allowlist("1.2.3.4", &l(&["0.0.0.0/0"])));
    assert!(!ip_in_allowlist("1.2.3.4", &l(&["10.0.0.0/33"])));
}

#[tokio::test]
async fn webhooks_revoke_restore_and_update_a_held_key() {
    let t = key_atlas(Arc::default());
    let mirror = KeyMirror::new(Arc::new(MemoryKeyMirrorStore::new()), client(&t), KeyMirrorOptions::default());
    mirror.mint(json!({}), None).await.unwrap();
    assert!(!mirror.apply_webhook("api_key.revoked", &json!({ "id": "unknown" })).unwrap(), "an unheld key is ignored");
    assert!(mirror.apply_webhook("api_key.updated", &json!({ "id": "eak_new", "scopes": ["a:b"], "name": "n2" })).unwrap());
    assert!(mirror.verify("ak_0123_secret", &["a:b".to_string()], None).await.unwrap().is_valid());
    assert!(mirror.apply_webhook("api_key.revoked", &json!({ "id": "eak_new", "revoked_at": 9, "revoked_reason": "user_banned" })).unwrap());
    assert!(!mirror.verify("ak_0123_secret", &[], None).await.unwrap().is_valid());
    assert!(mirror.apply_webhook("api_key.restored", &json!({ "id": "eak_new" })).unwrap());
    assert!(mirror.verify("ak_0123_secret", &[], None).await.unwrap().is_valid());
}

// ── sid revocation ──────────────────────────────────────────────────────────

#[tokio::test]
async fn the_sid_list_polls_once_per_interval_keeps_the_last_list_on_failure_and_can_fail_closed() {
    let fail = Arc::new(Mutex::new(false));
    let f = fail.clone();
    let t = FakeTransport::new(move |req| {
        assert_eq!(path(&req.url), "/v1/sessions/revoked");
        if *f.lock().unwrap() {
            return HttpResponse { status: 503, body: "{}".into() };
        }
        ok(json!({ "data": [{ "sid": "sess_dead", "revoked_at": 1_000_000 }], "has_more": false, "next_cursor": null, "server_time": 1_000_500 }))
    });
    let now = Arc::new(AtomicU64::new(1_000_600));
    let opts = SidListRevocation { interval_ms: 10_000, on_stale: SidStaleAction::Reject, stale_after_ms: 30_000, ..Default::default() };
    let list = SidRevocationList::with_clock(client(&t), opts, clock(&now));

    assert!(list.is_revoked("sess_dead").await);
    assert!(!list.is_revoked("sess_live").await);
    assert_eq!(t.request_count(), 1, "one poll serves both checks inside the interval");
    assert!(!list.unavailable());

    *fail.lock().unwrap() = true;
    now.fetch_add(11_000, Ordering::SeqCst);
    assert!(list.is_revoked("sess_dead").await, "a failed poll never forgets the list");
    assert_eq!(t.request_count(), 2);
    assert!(!list.unavailable());
    now.fetch_add(40_000, Ordering::SeqCst);
    assert!(list.unavailable(), "past stale_after_ms with Reject: fail closed");
}

// ── resource role mirror ────────────────────────────────────────────────────

fn roles_atlas() -> FakeTransport {
    FakeTransport::new(|req| match path(&req.url) {
        "/v1/resource_types" => ok(json!({ "data": [
            { "key": "folder", "inherit": true, "roles": [
                { "key": "viewer", "permissions": ["read"], "includes": [] },
                { "key": "editor", "permissions": ["write"], "includes": ["viewer"] },
                { "key": "owner", "permissions": ["*"], "includes": [] } ] },
            { "key": "doc", "inherit": true, "roles": [
                { "key": "viewer", "permissions": ["read"], "includes": [] },
                { "key": "editor", "permissions": ["write"], "includes": ["viewer"] },
                { "key": "owner", "permissions": ["*"], "includes": [] } ] } ] })),
        "/v1/resources" => ok(json!({ "data": [
            { "id": "res_f", "type": "folder", "external_id": "f1", "parent_id": null },
            { "id": "res_d", "type": "doc", "external_id": "d1", "parent_id": "res_f" } ], "has_more": false, "next_cursor": null })),
        "/v1/resource_role_assignments/changes" => ok(json!({ "data": [
            { "change": "created", "assignment_id": "a1", "resource_id": "res_f", "subject": { "type": "user", "id": "u1" }, "role": "editor", "inherit": true },
            { "change": "created", "assignment_id": "a2", "resource_id": "res_f", "subject": { "type": "group", "id": "eng" }, "role": "viewer", "inherit": false },
            { "change": "created", "assignment_id": "a3", "resource_id": "res_d", "subject": { "type": "user", "id": "u2" }, "role": "owner", "inherit": true } ],
            "has_more": false, "next_cursor": "3" })),
        _ => HttpResponse { status: 404, body: "{}".into() },
    })
}

#[tokio::test]
async fn can_answers_locally_with_role_includes_inheritance_and_group_subjects() {
    let t = roles_atlas();
    let store = Arc::new(MemoryResourceRoleMirrorStore::new());
    let mirror = ResourceRoleMirror::new(store.clone(), client(&t), ResourceRoleMirrorOptions::default());
    assert_eq!(mirror.sync().await.unwrap(), 3);
    assert_eq!(store.assignment_count(), 3);
    let calls = t.request_count();

    let d1 = ResourceRef::External { resource_type: "doc".into(), external_id: "d1".into() };
    let none = ResourceRoleCheckOptions::default();
    // u1 is editor on the folder: inherited down to the doc, and `includes` adds viewer's read.
    assert!(mirror.can(&MirrorSubject::user("u1"), "write", &d1, &none).unwrap());
    assert!(mirror.can(&MirrorSubject::user("u1"), "read", &d1, &none).unwrap());
    assert!(!mirror.can(&MirrorSubject::user("u1"), "delete", &d1, &none).unwrap());
    // u2 owns the doc: `*` grants everything, but not on the folder above it.
    assert!(mirror.can(&MirrorSubject::user("u2"), "delete", &d1, &none).unwrap());
    assert!(!mirror.can(&MirrorSubject::user("u2"), "read", &ResourceRef::Id("res_f".into()), &none).unwrap());
    // The group assignment does not inherit: only the folder itself.
    let eng = ResourceRoleCheckOptions { groups: vec!["eng".into()], ..Default::default() };
    assert!(mirror.can(&MirrorSubject::user("u3"), "read", &ResourceRef::Id("res_f".into()), &eng).unwrap());
    assert!(!mirror.can(&MirrorSubject::user("u3"), "read", &d1, &eng).unwrap());
    let verdict = mirror.check(&MirrorSubject::user("u1"), "write", &d1, &none).unwrap();
    assert_eq!(verdict.grants.len(), 1);
    assert!(verdict.grants[0].inherited && verdict.grants[0].resource_id == "res_f");
    assert!(mirror.check(&MirrorSubject::user("u1"), "read", &ResourceRef::Id("nope".into()), &none).unwrap().unknown_resource);
    assert_eq!(t.request_count(), calls, "checks made no network call");
}

#[tokio::test]
async fn webhooks_change_assignments_and_a_stale_mirror_refuses() {
    let t = roles_atlas();
    let now = Arc::new(AtomicU64::new(1_000_000));
    let opts = ResourceRoleMirrorOptions { max_staleness_ms: Some(10_000), ..Default::default() };
    let mirror = ResourceRoleMirror::new(Arc::new(MemoryResourceRoleMirrorStore::new()), client(&t), opts).with_clock(clock(&now));
    let f1 = ResourceRef::Id("res_f".into());
    let none = ResourceRoleCheckOptions::default();
    assert!(mirror.check(&MirrorSubject::user("u1"), "write", &f1, &none).unwrap().stale_refused, "never synced");
    mirror.sync().await.unwrap();
    assert!(mirror.can(&MirrorSubject::user("u1"), "write", &f1, &none).unwrap());
    assert!(mirror.apply_webhook("resource_role_assignment.deleted", &json!({ "id": "a1", "resource_id": "res_f", "subject": { "type": "user", "id": "u1" }, "role": "editor" })).unwrap());
    assert!(!mirror.can(&MirrorSubject::user("u1"), "write", &f1, &none).unwrap());
    assert!(!mirror.apply_webhook("user.created", &json!({})).unwrap());
    now.fetch_add(20_000, Ordering::SeqCst);
    assert!(mirror.check(&MirrorSubject::user("u1"), "write", &f1, &none).unwrap().stale_refused);
}
