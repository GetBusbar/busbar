// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/limits/admission.rs`.

use super::*;

#[test]
fn exhausting_permits_returns_none() {
    let gate = AdmissionGate::new(1, "test-exhaust");
    let _held = gate.try_enter().expect("first entry admits");
    assert!(
        gate.try_enter().is_none(),
        "a saturated gate must deny further entries"
    );
}

#[test]
fn dropping_a_permit_frees_a_slot() {
    let gate = AdmissionGate::new(1, "test-release");
    let held = gate.try_enter().expect("first entry admits");
    assert!(
        gate.try_enter().is_none(),
        "saturated while the only permit is held"
    );
    drop(held);
    assert!(
        gate.try_enter().is_some(),
        "dropping the held permit must free the slot"
    );
}

#[test]
fn denied_entry_increments_the_gate_counter() {
    crate::metrics::init();
    let gate = AdmissionGate::new(1, "test-denied-counter");
    let _held = gate.try_enter().expect("first entry admits");
    assert!(gate.try_enter().is_none(), "second entry must be denied");

    let out = crate::metrics::render();
    assert!(
        out.contains("busbar_admission_denied_total{gate=\"test-denied-counter\"} 1"),
        "a denied try_enter must increment the per-gate denied counter; got:\n{out}"
    );
}

/// THE SHED CONTRACT: an arrival that finds the cap full is answered IMMEDIATELY — it never parks
/// waiting for a slot. Pinned on the layer's own service (not just the gate) because the parking
/// hazard lives in the service's `call`: a version that awaited a permit here left the over-cap
/// callers hanging for as long as the admitted work took, which reads to a client as a hung
/// gateway. The shed response's exact bytes are pinned too — status, `Retry-After`, content type,
/// and body are the observable contract.
#[tokio::test]
async fn a_saturated_gate_sheds_instead_of_parking_the_caller() {
    use tower::{Service as _, ServiceExt as _};

    // An inner service that never completes: if the layer ever awaits a permit behind this, the
    // over-cap call cannot finish either, and the timeout below fires.
    #[derive(Clone)]
    struct NeverFinishes;
    impl tower::Service<axum::extract::Request> for NeverFinishes {
        type Response = axum::response::Response;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
        >;
        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn call(&mut self, _req: axum::extract::Request) -> Self::Future {
            Box::pin(std::future::pending())
        }
    }

    let mut svc = <InboundAdmissionLayer as tower::Layer<NeverFinishes>>::layer(
        &InboundAdmissionLayer::new(1),
        NeverFinishes,
    );
    let req = || axum::extract::Request::new(axum::body::Body::empty());

    // The one permit goes to a call that will never resolve.
    let mut admitted = svc.clone();
    let admitted = tokio::spawn(async move { admitted.ready().await.unwrap().call(req()).await });
    tokio::task::yield_now().await;

    // The next arrival must be answered NOW, not parked behind the in-flight one.
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        svc.ready().await.unwrap().call(req()),
    )
    .await
    .expect("an over-cap arrival must be shed immediately, never parked")
    .expect("the shed arm is infallible");

    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "a shed names a concrete backoff so a client can retry sanely"
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(crate::proxy::APPLICATION_JSON)
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("the static shed body always collects")
        .to_bytes();
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#,
    );

    admitted.abort();
}

/// CONCURRENT-CAP BOUNDARY at N > 1: a gate of N permits admits EXACTLY N in-flight holders and
/// denies the (N+1)th — the instantaneous cap is N, not N-1 (off-by-one over-throttle) nor N+1
/// (over-admit past the cap). Freeing exactly one held permit re-opens exactly one slot: the next
/// `try_enter` admits, and the one after that is denied again. This is the shape of the group
/// `{ concurrent: N }` gauge — an operator's in-flight cap must admit the full N they configured.
#[test]
fn concurrent_cap_admits_exactly_n_and_frees_one_at_a_time() {
    let gate = AdmissionGate::new(3, "test-concurrent-boundary");
    assert_eq!(gate.available_permits(), 3);
    let a = gate.try_enter().expect("1st of 3 admits");
    let b = gate.try_enter().expect("2nd of 3 admits");
    let c = gate.try_enter().expect("3rd of 3 admits");
    assert_eq!(gate.available_permits(), 0, "all 3 slots held");
    assert!(
        gate.try_enter().is_none(),
        "the 4th must be denied — the cap is exactly 3, never 4"
    );
    drop(b);
    assert_eq!(
        gate.available_permits(),
        1,
        "freeing one reopens exactly one slot"
    );
    let d = gate
        .try_enter()
        .expect("one freed slot admits exactly one more");
    assert!(
        gate.try_enter().is_none(),
        "and only one — the cap re-saturates at 3"
    );
    drop((a, c, d));
    assert_eq!(
        gate.available_permits(),
        3,
        "all holders gone, cap fully restored"
    );
}

#[test]
fn unbounded_sentinel_never_denies() {
    let gate = AdmissionGate::new(Semaphore::MAX_PERMITS, "test-unbounded");
    // Hold a generous handful of permits; an unbounded gate must keep admitting.
    let held: Vec<_> = (0..1000).map(|_| gate.try_enter().unwrap()).collect();
    assert!(gate.try_enter().is_some());
    drop(held);
}
