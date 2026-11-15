//! Metrics through the `metrics` facade (feature `tracing-metrics`): a request count, a duration histogram and
//! a retry count, labelled with the route TEMPLATE, never the expanded path.
#![cfg(all(feature = "backend", feature = "tracing-metrics"))]

use std::sync::Arc;

use atlasauth::backend::{BackendClient, FakeTransport};
use atlasauth::{HttpMethod, HttpResponse};
use metrics_util::debugging::DebuggingRecorder;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn a_retried_request_counts_requests_duration_and_retries_by_route_template() {
    let n = Arc::new(AtomicUsize::new(0));
    let t = FakeTransport::new(move |_| {
        if n.fetch_add(1, Ordering::SeqCst) == 0 {
            HttpResponse { status: 503, body: "{}".into() }
        } else {
            HttpResponse { status: 200, body: "{}".into() }
        }
    });
    let client = BackendClient::builder("sk_test_x").transport(Arc::new(t)).max_retries(2).base_delay_ms(0).build().unwrap();

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async { client.request_value(HttpMethod::Get, "/v1/users/user_01H8ZZZZZZZZ", &[], None).await.unwrap() });
    });

    let seen: Vec<(String, Vec<(String, String)>)> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(k, _, _, _)| (k.key().name().to_string(), k.key().labels().map(|l| (l.key().to_string(), l.value().to_string())).collect()))
        .collect();
    let labels = |name: &str| seen.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no {name} in {seen:?}")).1.clone();

    let requests = labels("atlas_requests_total");
    assert!(requests.contains(&("method".into(), "GET".into())));
    assert!(requests.contains(&("route".into(), "/v1/users/{id}".into())), "the route is a template: {requests:?}");
    assert!(requests.contains(&("status".into(), "200".into())));
    assert!(seen.iter().any(|(n, _)| n == "atlas_request_duration_seconds"));
    assert!(seen.iter().any(|(n, _)| n == "atlas_request_retries_total"));
}
