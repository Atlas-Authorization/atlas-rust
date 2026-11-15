//! Step-up helpers (`authenticated_within`, `used_multi_factor`) and transaction-token verification.

mod support;

use atlasauth::{authenticated_within, used_multi_factor, verify_transaction_token, Claims, Jwks, TxnTokenOptions};
use serde_json::json;

fn claims(extra: serde_json::Value) -> Claims {
    let mut base = json!({ "iss": "https://i.test", "sub": "user_1", "exp": 9_999_999_999i64 });
    base.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    serde_json::from_value(base).unwrap()
}

#[test]
fn authenticated_within_uses_auth_time_and_never_trusts_a_missing_one() {
    let now_ms = 1_000_000_000_000i64;
    let c = claims(json!({ "auth_time": 1_000_000_000 - 120 }));
    assert!(c.authenticated_within_at(300, now_ms));
    assert!(!c.authenticated_within_at(60, now_ms));
    assert!(!claims(json!({})).authenticated_within_at(10_000, now_ms));
    assert!(authenticated_within(Some(1_000_000_000.0), 0, Some(now_ms)));
    assert!(!authenticated_within(None, 300, Some(now_ms)));
    assert!(!authenticated_within(Some(f64::NAN), 300, Some(now_ms)));
}

#[test]
fn used_multi_factor_reads_acr_or_amr() {
    assert!(claims(json!({ "acr": "urn:atlas:acr:mfa" })).used_multi_factor());
    assert!(claims(json!({ "amr": ["pwd", "mfa"] })).used_multi_factor());
    assert!(!claims(json!({ "acr": "urn:atlas:acr:basic", "amr": ["pwd"] })).used_multi_factor());
    assert!(used_multi_factor(Some("urn:atlas:acr:mfa"), None));
}

#[test]
fn org_mfa_policy_needs_the_ok_flag_and_the_right_organization() {
    let required_ok = claims(json!({ "org_id": "org_1", "org_mfa_required": true, "org_mfa_ok": true }));
    assert!(required_ok.mfa_org_satisfied(None));
    assert!(required_ok.mfa_org_satisfied(Some("org_1")));
    let required_no = claims(json!({ "org_id": "org_1", "org_mfa_required": true }));
    assert!(!required_no.mfa_org_satisfied(None));
    let other = claims(json!({ "org_id": "org_2", "org_mfa_required": true, "org_mfa_ok": true }));
    assert!(!other.mfa_org_satisfied(Some("org_1")));
    assert!(claims(json!({ "org_id": "org_1" })).mfa_org_satisfied(Some("org_1")));
}

fn opts(now: i64) -> TxnTokenOptions {
    TxnTokenOptions { issuer: "https://tts.test/".into(), trust_domain: "td.example".into(), now_seconds: Some(now) }
}

fn txn_claims(now: i64) -> serde_json::Value {
    json!({ "iss": "https://tts.test", "sub": "user_1", "aud": "td.example", "iat": now, "exp": now + 60,
        "txn": "t-1", "scope": "orders:read orders:write", "req_wl": "svc-a" })
}

#[test]
fn a_valid_transaction_token_verifies_and_splits_scopes() {
    let jwks: Jwks = serde_json::from_value(support::keys().jwks.clone()).unwrap();
    let now = support::now_secs();
    let token = support::es256(&txn_claims(now), Some("txntoken+jwt"));
    let c = verify_transaction_token(&token, &jwks, &opts(now)).expect("verifies");
    assert_eq!(c.txn, "t-1");
    assert_eq!(c.scopes(), vec!["orders:read", "orders:write"]);
}

#[test]
fn a_transaction_token_is_refused_for_the_wrong_type_audience_expiry_or_missing_claim() {
    let jwks: Jwks = serde_json::from_value(support::keys().jwks.clone()).unwrap();
    let now = support::now_secs();
    let good = txn_claims(now);
    assert!(verify_transaction_token(&support::es256(&good, Some("JWT")), &jwks, &opts(now)).is_err());
    assert!(verify_transaction_token(&support::es256(&good, None), &jwks, &opts(now)).is_err());
    let mut other = good.clone();
    other["aud"] = json!("someone-else");
    assert!(verify_transaction_token(&support::es256(&other, Some("txntoken+jwt")), &jwks, &opts(now)).is_err());
    assert!(verify_transaction_token(&support::es256(&good, Some("txntoken+jwt")), &jwks, &opts(now + 3600)).is_err());
    let mut no_scope = good.clone();
    no_scope.as_object_mut().unwrap().remove("scope");
    assert!(verify_transaction_token(&support::es256(&no_scope, Some("txntoken+jwt")), &jwks, &opts(now)).is_err());
    assert!(verify_transaction_token("not.a.jwt", &jwks, &opts(now)).is_err());
}
