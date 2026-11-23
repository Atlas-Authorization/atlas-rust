//! A connection reset before any response is retried once, for safe requests only.
#![cfg(feature = "backend")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use atlasauth::backend::BackendClient;
use atlasauth::{BoxFuture, HttpMethod, HttpRequest, HttpResponse, HttpTransport, TransportError};

/// Fails the first `failures` calls with `error`, then answers 200 `{}`.
struct Flaky {
    failures: usize,
    error: &'static str,
    calls: AtomicUsize,
}

impl HttpTransport for Flaky {
    fn send<'a>(&'a self, _req: HttpRequest) -> BoxFuture<'a, Result<HttpResponse, TransportError>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if n < self.failures {
                Err(TransportError::new(self.error))
            } else {
                Ok(HttpResponse { status: 200, body: "{}".into() })
            }
        })
    }
}

fn setup(failures: usize, error: &'static str) -> (BackendClient, Arc<Flaky>) {
    let t = Arc::new(Flaky { failures, error, calls: AtomicUsize::new(0) });
    let c = BackendClient::builder("sk_test").transport(t.clone()).base_delay_ms(1).build().unwrap();
    (c, t)
}

const RESET: &str = "error sending request: connection closed before message completed";

#[tokio::test]
async fn get_and_keyed_post_are_retried_once() {
    let (c, t) = setup(1, RESET);
    c.request_value(HttpMethod::Get, "/v1/users", &[], None).await.unwrap();
    assert_eq!(t.calls.load(Ordering::SeqCst), 2);

    let (c, t) = setup(1, RESET);
    c.request_value_idem(HttpMethod::Post, "/v1/users", &[], None, Some("k1")).await.unwrap();
    assert_eq!(t.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn plain_write_timeout_and_second_reset_are_not_retried() {
    let (c, t) = setup(1, RESET);
    assert!(c.request_value(HttpMethod::Post, "/v1/users", &[], None).await.is_err());
    assert_eq!(t.calls.load(Ordering::SeqCst), 1);

    let (c, t) = setup(1, "timeout: operation timed out");
    assert!(c.request_value(HttpMethod::Get, "/v1/users", &[], None).await.is_err());
    assert_eq!(t.calls.load(Ordering::SeqCst), 1);

    let (c, t) = setup(2, RESET);
    assert!(c.request_value(HttpMethod::Get, "/v1/users", &[], None).await.is_err());
    assert_eq!(t.calls.load(Ordering::SeqCst), 2);
}
