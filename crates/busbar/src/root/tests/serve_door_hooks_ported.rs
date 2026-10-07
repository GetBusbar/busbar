// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANDIDATE CATALOG SIGNALS ON THE DOOR, ported from the legacy engine crate's signal catalog
//! tests before that crate is deleted: the plane serving the `pools` map served end to end
//! (`super::hook_seat_tests::rig`), its pool ranked by an abstaining policy that records each
//! candidate's signal bag, the generation declaring exactly the signals a test names. What the bag
//! carries is read off the kernel's lane store and the egress's p95 reservoir, as production reads
//! it. Each test names the legacy test it ports (crate-relative path) and keeps the values it
//! asserted.

use busbar_contract::{Signal, SignalBag, SignalValue};

use super::hook_seat_tests::{far_end_answering, rig, DoorRig, RigOpts};
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

/// The far end's answer: an openai chat completion.
const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// A rig over `members` live far ends, the generation declaring `signals`.
async fn signal_rig(instance: &'static str, members: usize, signals: &'static [Signal]) -> DoorRig {
    let mut ports = Vec::new();
    for _ in 0..members {
        ports.push((far_end_answering(200, ANSWER).await.port, 1));
    }
    rig(
        instance,
        RigOpts {
            members: &ports,
            signals: Some(signals),
            ..RigOpts::default()
        },
    )
    .await
}

/// One chat through the door, then each candidate's bag as the ranker was shown it.
async fn bags_after_chat(rig: &DoorRig) -> Vec<SignalBag> {
    let (status, _, body) = rig.chat().await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    rig.ranker_bags()
}

/// A declared `CandidateBreakerState` reaches the candidate's bag: a fresh member's breaker starts
/// closed, so the projected value is the `"closed"` label, and only the declared signal is present.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::declared_signal_is_computed_and_projected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_breaker_state_reaches_the_bag_as_closed_for_a_fresh_member() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-breaker-closed";
    let _published = Withdrawn(instance);
    let rig = signal_rig(instance, 1, &[Signal::CandidateBreakerState]).await;
    let bags = bags_after_chat(&rig).await;
    assert_eq!(bags.len(), 1);
    match bags[0].get(Signal::CandidateBreakerState) {
        Some(SignalValue::Str(s)) => assert_eq!(s.as_ref(), "closed"),
        other => panic!("expected CandidateBreakerState = Str(\"closed\"), got {other:?}"),
    }
    // Only the declared signal is present — CandidateErrorRate was never asked for.
    assert!(bags[0].get(Signal::CandidateErrorRate).is_none());
}

/// An UNDECLARED signal is absent from the bag, even once the member's outcome window and latency
/// reservoir hold what it would be computed from.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::undeclared_signal_is_absent`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undeclared_signal_is_absent_from_the_bag() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-undeclared";
    let _published = Withdrawn(instance);
    let rig = signal_rig(instance, 1, &[Signal::CandidateBreakerState]).await;
    // A served request first: the outcome window then holds an outcome.
    bags_after_chat(&rig).await;
    let bags = bags_after_chat(&rig).await;
    assert!(
        bags[0].get(Signal::CandidateErrorRate).is_none(),
        "CandidateErrorRate was not declared by any hook; it must not appear"
    );
    assert!(bags[0].get(Signal::CandidateLatencyP95Ms).is_none());
}

/// With nothing declared the candidate's bag is empty and never spills its inline capacity onto
/// the heap: the zero-cost-when-undeclared guarantee.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::default_path_allocates_no_signals_container`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_nothing_declared_the_bag_is_empty_and_never_spills() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-no-signals";
    let _published = Withdrawn(instance);
    let rig = signal_rig(instance, 1, &[]).await;
    let bags = bags_after_chat(&rig).await;
    assert_eq!(bags.len(), 1);
    assert!(bags[0].is_empty(), "no hook declared any signal");
    assert!(
        !bags[0].spilled(),
        "an empty (or ≤4-entry) SignalBag must never spill onto the heap"
    );
}

/// `CandidateBreakerState` tracks the REAL breaker: forcing the member's cell in the routing pool
/// open (cooldown far in the future) flips the projected label to `"open"`.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::breaker_state_projects_open_after_a_trip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_breaker_state_reads_open_after_the_cell_is_forced_open() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-breaker-open";
    let _published = Withdrawn(instance);
    // A second, healthy member serves the request; the first is the one forced open.
    let rig = signal_rig(instance, 2, &[Signal::CandidateBreakerState]).await;
    rig.app
        .store
        .force_open_in("p", 0, busbar_kernel::store::now() + 3600);
    let bags = bags_after_chat(&rig).await;
    match bags[0].get(Signal::CandidateBreakerState) {
        Some(SignalValue::Str(s)) => assert_eq!(s.as_ref(), "open"),
        other => panic!("expected CandidateBreakerState = Str(\"open\"), got {other:?}"),
    }
}

/// `CandidateErrorRate` projects the breaker's own outcome-window error rate: one error and three
/// successes recorded against the member's cell in the routing pool read as exactly 0.25.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::error_rate_projects_the_outcome_window_fraction`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_error_rate_projects_the_outcome_window_fraction() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-error-rate";
    let _published = Withdrawn(instance);
    // A second, healthy member serves the request; the first carries the recorded outcomes.
    let rig = signal_rig(instance, 2, &[Signal::CandidateErrorRate]).await;
    let cfg = busbar_kernel::store::BreakerCfg::default();
    // 1 error + 3 successes = 25%, well under the default trip threshold.
    rig.app
        .store
        .record_transient_in("p", 0, "test", &cfg, None);
    rig.app.store.record_success_in("p", 0);
    rig.app.store.record_success_in("p", 0);
    rig.app.store.record_success_in("p", 0);
    let bags = bags_after_chat(&rig).await;
    match bags[0].get(Signal::CandidateErrorRate) {
        Some(SignalValue::F64(rate)) => assert!(
            (*rate - 0.25).abs() < 1e-9,
            "expected 1/4 = 0.25 error rate, got {rate}"
        ),
        other => panic!("expected CandidateErrorRate = F64(0.25), got {other:?}"),
    }
}

/// A declared `CandidateLatencyP95Ms` is computed from served requests and reaches the bag as a
/// whole-millisecond `U64`, rounded up, so a sub-millisecond loopback far end reads at least 1.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::declared_latency_p95_is_computed_from_served_requests`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_p95_is_computed_from_served_requests() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-p95";
    let _published = Withdrawn(instance);
    let rig = signal_rig(instance, 1, &[Signal::CandidateLatencyP95Ms]).await;
    for _ in 0..5 {
        bags_after_chat(&rig).await;
    }
    // The next decision sees the five served samples.
    let bags = bags_after_chat(&rig).await;
    assert_eq!(bags.len(), 1);
    match bags[0].get(Signal::CandidateLatencyP95Ms) {
        Some(SignalValue::U64(ms)) => assert!(*ms >= 1, "p95 must read at least 1 ms, got {ms}"),
        other => panic!("expected CandidateLatencyP95Ms = U64(_), got {other:?}"),
    }
}

/// With no hook declaring p95, a served request moves the member's latency average (always on)
/// and the bag never carries a p95. The reservoir's write gate is
/// `model_egress::signals_tests::an_undeclared_p95_is_never_collected_and_a_declared_one_is`.
///
/// Ports legacy `engine/tests/signal_catalog_tests.rs::undeclared_latency_p95_is_never_collected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undeclared_p95_is_never_shown_though_the_latency_average_moves() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-p95-undeclared";
    let _published = Withdrawn(instance);
    let rig = signal_rig(instance, 1, &[Signal::CandidateErrorRate]).await;
    bags_after_chat(&rig).await;
    assert!(
        rig.app.store.lane_latency_ms(0).is_some(),
        "the latency average is always-on"
    );
    let bags = bags_after_chat(&rig).await;
    assert!(bags[0].get(Signal::CandidateLatencyP95Ms).is_none());
}
