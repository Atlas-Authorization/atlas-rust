//! Hermetic tests for the wave-3 #7 additions: the machine / device-registry /
//! enrolment surface, plus the API-key patch / mint_token / revoked gaps. All
//! offline via FakeTransport — assert the method + path + (de)serialization.
#![cfg(feature = "backend")]

use std::sync::Arc;

use serde_json::{json, Value};

use atlasauth::backend::{
    BackendClient, CreateEnrolmentTokenBody, CreateMachineBody, CursorParams, EnrolMachineBody,
    EnrolmentToken, FakeTransport, ListEnrolmentTokensParams, ListPage, Machine, MachineFilter,
    MintApiKeyTokenBody, OrgFilter, RedeemedEnrolment, UpdateApiKeyBody,
};
use atlasauth::{HttpMethod, HttpResponse};

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

/// Route a canned body by (method, path-suffix). The order of the match arms is
/// the only thing that distinguishes `/v1/machines` from its sub-paths.
fn routed() -> FakeTransport {
    FakeTransport::new(|req| {
        let path = req.url.replace("https://api.atlasauth.net", "");
        let p = path.split('?').next().unwrap_or("");
        let body: &str = match (req.method, p) {
            (HttpMethod::Post, "/v1/machines") => {
                r#"{"object":"machine","id":"mch_1","name":"ci-runner","status":"active","metadata":{},"secret":"mk_newsecret","future_field":1}"#
            }
            (HttpMethod::Get, "/v1/machines") => {
                r#"{"object":"list","data":[{"id":"mch_1","status":"active","name":"ci-runner"}]}"#
            }
            (HttpMethod::Patch, "/v1/machines/mch_1") => {
                r#"{"object":"machine","id":"mch_1","name":"renamed","status":"active"}"#
            }
            (HttpMethod::Post, "/v1/machines/redeem") => {
                r#"{"object":"enrolment_redemption","data":{"scope":"ci"},"owner_user_id":"user_1","organization_id":"org_1","id":"met_1"}"#
            }
            (HttpMethod::Post, "/v1/machines/enroll") => {
                r#"{"object":"machine","id":"mch_1","name":"ci-runner","status":"active","device_key":"dev-xyz","approval_required":false}"#
            }
            (HttpMethod::Post, "/v1/m2m_tokens/verify") => {
                r#"{"object":"m2m_verification","valid":true,"machine_id":"mch_1","name":"ci-runner"}"#
            }
            (HttpMethod::Post, "/v1/machine_enrolment_tokens") => {
                r#"{"object":"machine_enrolment_token","id":"met_1","organization_id":"org_1","max_uses":3,"uses":0,"requires_approval":true,"expires_at":123,"token":"met_secret"}"#
            }
            (HttpMethod::Get, "/v1/machine_enrolment_tokens") => {
                r#"{"object":"list","data":[{"id":"met_1","max_uses":3,"uses":1,"requires_approval":false}]}"#
            }
            (HttpMethod::Delete, "/v1/machine_enrolment_tokens/met_1") => {
                r#"{"object":"machine_enrolment_token","id":"met_1","deleted":true}"#
            }
            (HttpMethod::Patch, "/v1/api_keys/ak_1") => {
                r#"{"object":"api_key","id":"ak_1","subject_type":"user","subject_id":"user_1","name":"renamed","scopes":["read","write"],"claims":{"plan":"pro"}}"#
            }
            (HttpMethod::Post, "/v1/api_keys/token") => {
                r#"{"object":"api_key_token","token":"eyJ.jwt","token_type":"Bearer","jti":"jti_1","key_id":"ak_1","subject_type":"user","subject_id":"user_1","scopes":["read"],"constraints":{"ip":"*"},"expires_in":300,"expires_at":999,"issuer":"https://inst.fapi.atlasauth.net"}"#
            }
            (HttpMethod::Get, "/v1/api_keys/revoked") => {
                r#"{"object":"list","data":[{"object":"api_key","id":"ak_9","revoked_at":4242}],"has_more":true,"next_cursor":"c2"}"#
            }
            _ => r#"{"object":"machine","id":"mch_1","status":"active","name":"ci-runner","metadata":{"hostname":"h1"}}"#,
        };
        HttpResponse { status: 200, body: body.into() }
    })
}

// ── machines ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn machine_create_and_rename_hit_right_method_path_and_deserialize() {
    let fake = routed();
    let c = client(&fake);

    let created = c
        .machines()
        .create(&CreateMachineBody { name: "ci-runner".into(), ..Default::default() }, Some("idem-m"))
        .await
        .unwrap();
    assert_eq!(created.id, "mch_1");
    assert_eq!(created.secret, "mk_newsecret");
    // The rest of the machine flattens into `machine` (never a typed secret_hash).
    assert_eq!(created.machine["name"], "ci-runner");
    assert!(created.machine.contains_key("future_field"));

    let renamed = c.machines().rename("mch_1", "renamed").await.unwrap();
    assert_eq!(renamed.name.as_deref(), Some("renamed"));

    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert!(reqs[0].url.ends_with("/v1/machines"));
    assert_eq!(reqs[0].body.as_deref(), Some(r#"{"name":"ci-runner"}"#));
    assert!(reqs[0].headers.iter().any(|(k, v)| k == "idempotency-key" && v == "idem-m"));
    assert_eq!(reqs[1].method, HttpMethod::Patch);
    assert!(reqs[1].url.ends_with("/v1/machines/mch_1"));
    assert_eq!(reqs[1].body.as_deref(), Some(r#"{"name":"renamed"}"#));
}

#[tokio::test]
async fn machine_list_sends_filters_and_cursor_and_verify_m2m() {
    let fake = routed();
    let c = client(&fake);

    let page = c
        .machines()
        .list(&MachineFilter {
            status: Some("active".into()),
            owner_user_id: Some("user_1".into()),
            organization_id: Some("org_1".into()),
            limit: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].id, "mch_1");
    assert!(!page.has_more); // the `{object,data}` list has no cursor fields

    let v = c.machines().verify_m2m_token("mk_presented").await.unwrap();
    assert!(v.valid);
    assert_eq!(v.machine_id.as_deref(), Some("mch_1"));

    let reqs = fake.requests();
    assert!(reqs[0].url.contains("/v1/machines?"));
    assert!(reqs[0].url.contains("status=active"));
    assert!(reqs[0].url.contains("owner_user_id=user_1"));
    assert!(reqs[0].url.contains("organization_id=org_1"));
    assert!(reqs[0].url.contains("limit=5"));
    assert_eq!(reqs[1].method, HttpMethod::Post);
    assert!(reqs[1].url.ends_with("/v1/m2m_tokens/verify"));
    assert_eq!(reqs[1].body.as_deref(), Some(r#"{"token":"mk_presented"}"#));
}

#[tokio::test]
async fn enrolment_token_create_list_delete() {
    let fake = routed();
    let c = client(&fake);

    let tok = c
        .machines()
        .create_enrolment_token(
            &CreateEnrolmentTokenBody {
                organization_id: Some("org_1".into()),
                max_uses: Some(3),
                requires_approval: Some(true),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(tok.id, "met_1");
    assert_eq!(tok.token.as_deref(), Some("met_secret"));
    assert_eq!(tok.max_uses, Some(3));
    assert!(tok.requires_approval);

    let list = c.machines().list_enrolment_tokens().await.unwrap();
    assert_eq!(list.data.len(), 1);
    assert_eq!(list.data[0].id, "met_1");

    let del = c.machines().delete_enrolment_token("met_1").await.unwrap();
    assert_eq!(del.id, "met_1");
    assert!(del.deleted);

    let got: Vec<(HttpMethod, String)> = fake
        .requests()
        .into_iter()
        .map(|r| (r.method, r.url.replace("https://api.atlasauth.net", "")))
        .collect();
    assert_eq!(got[0], (HttpMethod::Post, "/v1/machine_enrolment_tokens".into()));
    assert_eq!(got[1], (HttpMethod::Get, "/v1/machine_enrolment_tokens".into()));
    assert_eq!(got[2], (HttpMethod::Delete, "/v1/machine_enrolment_tokens/met_1".into()));
    // The forward-compat body fields are omitted when unset.
    assert_eq!(
        serde_json::from_str::<Value>(fake.requests()[0].body.as_deref().unwrap()).unwrap(),
        json!({"organization_id":"org_1","max_uses":3,"requires_approval":true})
    );
}

// ── api-key gaps ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn api_key_patch_mint_token_and_revoked() {
    let fake = routed();
    let c = client(&fake);

    let patched = c
        .api_keys()
        .patch(
            "ak_1",
            &UpdateApiKeyBody {
                name: Some(Some("renamed".into())),
                scopes: Some(vec!["read".into(), "write".into()]),
                // `Some(None)` clears the field (serializes as JSON null).
                max_token_lifetime_seconds: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(patched.id, "ak_1");
    assert_eq!(patched.name.as_deref(), Some("renamed"));

    let minted = c
        .api_keys()
        .mint_token(&MintApiKeyTokenBody {
            secret: "ak_abc_secret".into(),
            ttl_seconds: Some(300),
            audience: Some(json!("https://resource.example")),
        })
        .await
        .unwrap();
    assert_eq!(minted.token, "eyJ.jwt");
    assert_eq!(minted.key_id.as_deref(), Some("ak_1"));
    assert_eq!(minted.expires_in, Some(300));
    assert_eq!(minted.scopes, vec!["read".to_string()]);

    let revoked = c.api_keys().revoked(Some("4000"), Some(50)).await.unwrap();
    assert_eq!(revoked.data.len(), 1);
    assert_eq!(revoked.data[0].id, "ak_9");
    assert_eq!(revoked.data[0].revoked_at, Some(4242));
    assert!(revoked.has_more);
    assert_eq!(revoked.next_cursor.as_deref(), Some("c2"));

    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Patch);
    assert!(reqs[0].url.ends_with("/v1/api_keys/ak_1"));
    assert_eq!(
        serde_json::from_str::<Value>(reqs[0].body.as_deref().unwrap()).unwrap(),
        json!({"name":"renamed","scopes":["read","write"],"max_token_lifetime_seconds":null})
    );
    assert_eq!(reqs[1].method, HttpMethod::Post);
    assert!(reqs[1].url.ends_with("/v1/api_keys/token"));
    assert_eq!(
        serde_json::from_str::<Value>(reqs[1].body.as_deref().unwrap()).unwrap(),
        json!({"secret":"ak_abc_secret","ttl_seconds":300,"audience":"https://resource.example"})
    );
    assert_eq!(reqs[2].method, HttpMethod::Get);
    assert!(reqs[2].url.contains("/v1/api_keys/revoked?"));
    assert!(reqs[2].url.contains("since=4000"));
    assert!(reqs[2].url.contains("limit=50"));
}

// `update` is an alias of `patch`.
#[tokio::test]
async fn api_key_update_is_patch_alias() {
    let fake = routed();
    let c = client(&fake);
    c.api_keys()
        .update("ak_1", &UpdateApiKeyBody { name: Some(Some("x".into())), ..Default::default() })
        .await
        .unwrap();
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Patch);
    assert!(reqs[0].url.ends_with("/v1/api_keys/ak_1"));
}

// ── device_key + redeem (0.6.2) ──────────────────────────────────────────────

/// `EnrolMachineBody` serializes `device_key` only when set, and omits it (like
/// the other `skip_serializing_if` fields) when `None`.
#[test]
fn enrol_machine_body_device_key_serializes_only_when_set() {
    let with = EnrolMachineBody {
        enrolment_token: "met_abc".into(),
        name: "ci-runner".into(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\n...".into(),
        device_key: Some("dev-xyz".into()),
        ..Default::default()
    };
    let v = serde_json::to_value(&with).unwrap();
    assert_eq!(v["device_key"], json!("dev-xyz"));
    // No metadata was set, so it is absent — only the fields that are Some appear.
    assert!(v.get("metadata").is_none());

    let without = EnrolMachineBody {
        enrolment_token: "met_abc".into(),
        name: "ci-runner".into(),
        public_key_pem: "pem".into(),
        ..Default::default()
    };
    let v = serde_json::to_value(&without).unwrap();
    assert!(v.get("device_key").is_none(), "device_key omitted when None: {v}");
}

/// A `Machine` record deserializes the echoed `device_key`.
#[test]
fn machine_record_picks_up_device_key() {
    let m: Machine = serde_json::from_str(
        r#"{"id":"mch_1","status":"active","device_key":"dev-xyz","metadata":{}}"#,
    )
    .unwrap();
    assert_eq!(m.id, "mch_1");
    assert_eq!(m.device_key.as_deref(), Some("dev-xyz"));
    // Absent device_key defaults to None.
    let m2: Machine = serde_json::from_str(r#"{"id":"mch_2","status":"active"}"#).unwrap();
    assert_eq!(m2.device_key, None);
}

/// A `RedeemedEnrolment` deserializes `data`, the owner/org binding, and the
/// token `id`.
#[test]
fn redeemed_enrolment_deserializes_data_owner_and_id() {
    let r: RedeemedEnrolment = serde_json::from_str(
        r#"{"object":"enrolment_redemption","data":{"scope":"ci"},"owner_user_id":"user_1","organization_id":"org_1","id":"met_1"}"#,
    )
    .unwrap();
    assert_eq!(r.id.as_deref(), Some("met_1"));
    assert_eq!(r.owner_user_id.as_deref(), Some("user_1"));
    assert_eq!(r.organization_id.as_deref(), Some("org_1"));
    assert_eq!(r.data["scope"], json!("ci"));
}

/// `machines().redeem()` POSTs the token to `/v1/machines/redeem` and returns the
/// redemption; `machines().enroll(..device_key..)` sends the field and reads it
/// back off the machine record.
#[tokio::test]
async fn machine_redeem_and_enroll_with_device_key() {
    let fake = routed();
    let c = client(&fake);

    let redeemed = c.machines().redeem("met_secret").await.unwrap();
    assert_eq!(redeemed.id.as_deref(), Some("met_1"));
    assert_eq!(redeemed.organization_id.as_deref(), Some("org_1"));

    let enrolled = c
        .machines()
        .enroll(&EnrolMachineBody {
            enrolment_token: "met_secret".into(),
            name: "ci-runner".into(),
            public_key_pem: "pem".into(),
            device_key: Some("dev-xyz".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(enrolled.device_key.as_deref(), Some("dev-xyz"));

    let reqs = fake.requests();
    assert_eq!(reqs[0].method, HttpMethod::Post);
    assert!(reqs[0].url.ends_with("/v1/machines/redeem"));
    assert_eq!(
        serde_json::from_str::<Value>(reqs[0].body.as_deref().unwrap()).unwrap(),
        json!({"enrolment_token": "met_secret"})
    );
    assert_eq!(reqs[1].method, HttpMethod::Post);
    assert!(reqs[1].url.ends_with("/v1/machines/enroll"));
    let enroll_body: Value = serde_json::from_str(reqs[1].body.as_deref().unwrap()).unwrap();
    assert_eq!(enroll_body["device_key"], json!("dev-xyz"));
}

// ── enrolment-token listing: filter + paging + next_cursor (0.6.3) ───────────

/// `list_enrolment_tokens_with` serializes the org filter + paging into the
/// query: a concrete org as `organization_id=<id>`, the org-less pool as the
/// literal `organization_id=null`, `limit`/`starting_after` when set — and the
/// bare `list_enrolment_tokens()` sends no query string at all.
#[tokio::test]
async fn list_enrolment_tokens_with_serializes_filter_and_paging() {
    let fake = routed();
    let c = client(&fake);

    // Concrete org + paging.
    c.machines()
        .list_enrolment_tokens_with(&ListEnrolmentTokensParams {
            organization_id: Some(OrgFilter::Org("org_1".into())),
            limit: Some(50),
            starting_after: Some("cur_abc".into()),
        })
        .await
        .unwrap();
    // Org-less pool → the literal `organization_id=null`, nothing else.
    c.machines()
        .list_enrolment_tokens_with(&ListEnrolmentTokensParams {
            organization_id: Some(OrgFilter::OrgLess),
            ..Default::default()
        })
        .await
        .unwrap();
    // Bare list: every field None → no query params.
    c.machines().list_enrolment_tokens().await.unwrap();

    let urls: Vec<String> = fake
        .requests()
        .into_iter()
        .map(|r| r.url.replace("https://api.atlasauth.net", ""))
        .collect();

    assert!(urls[0].starts_with("/v1/machine_enrolment_tokens?"));
    assert!(urls[0].contains("organization_id=org_1"));
    assert!(urls[0].contains("limit=50"));
    assert!(urls[0].contains("starting_after=cur_abc"));

    assert!(
        urls[1].contains("organization_id=null"),
        "org-less pool sends the null literal: {}",
        urls[1]
    );
    assert!(!urls[1].contains("limit="));
    assert!(!urls[1].contains("starting_after="));

    // Omitted-when-None: the default (bare) list carries no query string.
    assert_eq!(urls[2], "/v1/machine_enrolment_tokens");
}

/// A paginated enrolment-token `ListPage` deserializes `has_more` + the opaque
/// `next_cursor`; a single-page response (no cursor fields) leaves them
/// `false` / `None`.
#[test]
fn enrolment_token_list_page_reads_next_cursor() {
    let page: ListPage<EnrolmentToken> = serde_json::from_str(
        r#"{"object":"list","data":[{"id":"met_1","max_uses":3,"uses":1,"requires_approval":false}],"has_more":true,"next_cursor":"cur_next"}"#,
    )
    .unwrap();
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].id, "met_1");
    assert!(page.has_more);
    assert_eq!(page.next_cursor.as_deref(), Some("cur_next"));

    // Absent next_cursor / has_more default to None / false (the single-page shape).
    let page2: ListPage<EnrolmentToken> =
        serde_json::from_str(r#"{"object":"list","data":[{"id":"met_2"}]}"#).unwrap();
    assert!(!page2.has_more);
    assert_eq!(page2.next_cursor, None);
}

/// End-to-end: `list_enrolment_tokens_with` returns the server's `next_cursor`
/// so a caller can page.
#[tokio::test]
async fn list_enrolment_tokens_with_returns_next_cursor() {
    let fake = FakeTransport::new(|_req| HttpResponse {
        status: 200,
        body: r#"{"object":"list","data":[{"id":"met_1","requires_approval":false}],"has_more":true,"next_cursor":"cur_page2"}"#
            .into(),
    });
    let c = client(&fake);
    let page = c
        .machines()
        .list_enrolment_tokens_with(&ListEnrolmentTokensParams {
            limit: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.data[0].id, "met_1");
    assert!(page.has_more);
    assert_eq!(page.next_cursor.as_deref(), Some("cur_page2"));
}

// Organization memberships for a machine deserialize with a null `role`.
#[tokio::test]
async fn machine_org_memberships_tolerate_null_role() {
    let fake = FakeTransport::new(|_req| HttpResponse {
        status: 200,
        body: r#"{"object":"list","data":[{"object":"organization_membership","organization_id":"org_1","organization_slug":"acme","role":null,"plan":"pro","joined_at":55}],"has_more":false,"next_cursor":null}"#
            .into(),
    });
    let c = client(&fake);
    let page = c
        .machines()
        .organization_memberships("mch_1", CursorParams::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 1);
    assert_eq!(page.data[0].organization_id, "org_1");
    assert_eq!(page.data[0].role, None);
    assert_eq!(page.data[0].plan.as_deref(), Some("pro"));
    assert!(fake.requests()[0].url.ends_with("/v1/machines/mch_1/organization_memberships"));
}
