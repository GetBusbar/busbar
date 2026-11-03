// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let gate = AdmissionGate::new(1, "test-denied-counter");
    let _held = gate.try_enter().expect("first entry admits");
    assert!(gate.try_enter().is_none(), "second entry must be denied");

    let snapshot = crate::snapshot::snapshot().expect("the real recorder is installed");
    assert!(
        snapshot
            .iter()
            .flat_map(|family| family.samples.iter())
            .any(|sample| {
                sample.name == "busbar_admission_denied_total"
                    && sample.labels == [("gate".to_string(), "test-denied-counter".to_string())]
                    && sample.value == "1"
            }),
        "a denied try_enter must increment the per-gate denied counter; got: {snapshot:?}"
    );
}

#[tokio::test]
async fn a_saturated_gate_sheds_instead_of_parking_the_caller() {
    use tower::{Service as _, ServiceExt as _};

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

    let mut admitted = svc.clone();
    let admitted = tokio::spawn(async move { admitted.ready().await.unwrap().call(req()).await });
    tokio::task::yield_now().await;

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
        Some(busbar_contract::protocol::APPLICATION_JSON)
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

    let held: Vec<_> = (0..1000).map(|_| gate.try_enter().unwrap()).collect();
    assert!(gate.try_enter().is_some());
    drop(held);
}
