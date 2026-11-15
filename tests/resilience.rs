//! Status-aware retries: `Retry-After`, jitter bounds and the status endpoint. No network, no real sleeping.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use atlasauth::backend::{BackendClient, BackendError, FakeTransport, ResilienceConfig};
use atlasauth::{HttpMethod, HttpResponse};

fn client(t: &FakeTransport, cfg: ResilienceConfig, retries: u32) -> BackendClient {
    BackendClient::builder("sk_test_x").transport(Arc::new(t.clone())).max_retries(retries).base_delay_ms(0).resilience(cfg).build().unwrap()
}

/// Fails `fail_first` times with `status`, then answers 200. `/v1/status` answers `status_body`.
fn flaky(fail_first: usize, status: u16, status_body: &'static str) -> FakeTransport {
    let n = Arc::new(AtomicUsize::new(0));
    FakeTransport::new(move |req| {
        if req.url.ends_with("/v1/status") {
            return HttpResponse { status: 200, body: status_body.into() };
        }
        if n.fetch_add(1, Ordering::SeqCst) < fail_first {
            HttpResponse { status, body: r#"{"errors":[{"code":"UNAVAILABLE","message":"try later"}]}"#.into() }
        } else {
            HttpResponse { status: 200, body: "{}".into() }
        }
    })
}

async fn get(c: &BackendClient) -> Result<serde_json::Value, BackendError> {
    c.request_value(HttpMethod::Get, "/v1/users/user_1", &[], None).await
}

#[tokio::test]
async fn a_short_retry_after_is_honoured_and_a_long_one_is_not_waited_for() {
    let t = flaky(1, 429, "{}").with_response_headers([("retry-after", "0")]);
    assert!(get(&client(&t, ResilienceConfig::default(), 2)).await.is_ok());
    assert_eq!(t.request_count(), 2);

    // An HTTP date in the past is a zero wait.
    let t = flaky(1, 503, "{}").with_response_headers([("retry-after", "Thu, 01 Jan 1970 00:00:00 GMT")]);
    assert!(get(&client(&t, ResilienceConfig::default(), 2)).await.is_ok());
    assert_eq!(t.request_count(), 2);

    // Two minutes is past the default cap: the 429 is returned for the caller to schedule.
    let t = flaky(5, 429, "{}").with_response_headers([("retry-after", "120")]);
    match get(&client(&t, ResilienceConfig::default(), 3)).await {
        Err(BackendError::Api(e)) => assert_eq!(e.status, 429),
        other => panic!("{other:?}"),
    }
    assert_eq!(t.request_count(), 1, "no inline retry");

    // Turned off, the header is ignored and the normal backoff retries.
    let t = flaky(1, 429, "{}").with_response_headers([("retry-after", "120")]);
    let cfg = ResilienceConfig { honour_retry_after: false, ..Default::default() };
    assert!(get(&client(&t, cfg, 2)).await.is_ok());
}

#[tokio::test]
async fn a_declared_outage_fails_fast_and_a_degraded_service_still_retries() {
    let t = flaky(10, 503, r#"{"status":"major_outage"}"#);
    let cfg = ResilienceConfig { status_aware: true, ..Default::default() };
    assert!(get(&client(&t, cfg.clone(), 3)).await.is_err());
    let calls: Vec<String> = t.requests().iter().map(|r| r.url.clone()).collect();
    assert_eq!(calls.iter().filter(|u| u.ends_with("/v1/users/user_1")).count(), 1, "no retries during a major outage");
    assert_eq!(calls.iter().filter(|u| u.ends_with("/v1/status")).count(), 1);

    let t = flaky(2, 503, r#"{"status":"degraded"}"#);
    assert!(get(&client(&t, cfg.clone(), 3)).await.is_ok());
    assert_eq!(t.requests().iter().filter(|r| r.url.ends_with("/v1/status")).count(), 1, "the status read is cached across retries");

    // A status endpoint that is itself down never blocks the retry.
    let t = FakeTransport::new({
        let n = Arc::new(AtomicUsize::new(0));
        move |req| {
            if req.url.ends_with("/v1/status") {
                return HttpResponse { status: 500, body: "x".into() };
            }
            if n.fetch_add(1, Ordering::SeqCst) == 0 {
                HttpResponse { status: 503, body: "{}".into() }
            } else {
                HttpResponse { status: 200, body: "{}".into() }
            }
        }
    });
    assert!(get(&client(&t, cfg, 2)).await.is_ok());
}

#[tokio::test]
async fn a_4xx_is_never_retried() {
    let t = flaky(5, 404, "{}");
    assert!(get(&client(&t, ResilienceConfig::default(), 3)).await.is_err());
    assert_eq!(t.request_count(), 1);
}
