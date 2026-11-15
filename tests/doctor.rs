//! `doctor`: key shape, clock skew, JWKS reachability, service status and the secret key, against a fake API.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::FakeTransport;
use atlasauth::doctor::{run, DoctorOptions, DoctorStatus};
use atlasauth::HttpResponse;
use serde_json::json;

fn api(key_status: u16, svc: &'static str) -> FakeTransport {
    FakeTransport::new(move |req| {
        if req.url.ends_with("/v1/status") {
            HttpResponse { status: 200, body: json!({ "status": svc }).to_string() }
        } else if req.url.ends_with("/jwks.json") {
            HttpResponse { status: 200, body: json!({ "keys": [{ "kty": "EC", "crv": "P-256", "kid": "k", "alg": "ES256", "x": "AA", "y": "AA" }] }).to_string() }
        } else if req.url.ends_with("/v1/instance") {
            HttpResponse { status: key_status, body: "{}".into() }
        } else {
            HttpResponse { status: 404, body: "{}".into() }
        }
    })
}

fn status_of(r: &atlasauth::doctor::DoctorReport, name: &str) -> DoctorStatus {
    r.checks.iter().find(|c| c.name == name).unwrap().status
}

#[tokio::test]
async fn a_healthy_setup_passes_and_the_report_never_prints_a_key() {
    let t = api(200, "operational");
    let o = DoctorOptions::new(Arc::new(t)).secret_key("sk_live_abcdef").issuer("https://auth.example.com").publishable_key("pk_live_abc");
    let r = run(&o).await;
    assert!(r.ok(), "{r}");
    for name in ["keys", "api", "status", "jwks", "config", "secret_key"] {
        assert_eq!(status_of(&r, name), DoctorStatus::Pass, "{name}: {r}");
    }
    assert_eq!(status_of(&r, "clock"), DoctorStatus::Skip, "the fake sends no Date header");
    assert!(!r.to_string().contains("sk_live_abcdef"));
}

#[tokio::test]
async fn problems_are_named() {
    let t = api(401, "major_outage");
    let o = DoctorOptions::new(Arc::new(t)).secret_key("not-a-key").issuer("http://auth.example.com");
    let r = run(&o).await;
    assert!(!r.ok());
    assert_eq!(status_of(&r, "keys"), DoctorStatus::Fail);
    assert_eq!(status_of(&r, "status"), DoctorStatus::Fail);
    assert_eq!(status_of(&r, "config"), DoctorStatus::Fail);

    let rejected = run(&DoctorOptions::new(Arc::new(api(401, "operational"))).secret_key("sk_live_x")).await;
    assert_eq!(status_of(&rejected, "secret_key"), DoctorStatus::Fail);
    let degraded = run(&DoctorOptions::new(Arc::new(api(200, "degraded")))).await;
    assert_eq!(status_of(&degraded, "status"), DoctorStatus::Warn);
    assert!(degraded.ok(), "a warning does not fail the report");
}

#[tokio::test]
async fn a_clock_far_from_the_api_fails_and_mixed_environments_warn() {
    let t = api(200, "operational").with_response_headers([("date", "Sun, 06 Nov 1994 08:49:37 GMT")]);
    let r = run(&DoctorOptions::new(Arc::new(t))).await;
    assert_eq!(status_of(&r, "clock"), DoctorStatus::Fail);
    let mixed = run(&DoctorOptions::new(Arc::new(api(200, "operational"))).secret_key("sk_live_a").publishable_key("pk_test_a")).await;
    assert_eq!(status_of(&mixed, "keys"), DoctorStatus::Warn);
}
