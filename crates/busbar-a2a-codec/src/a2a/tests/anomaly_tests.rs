// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The anomaly breaker, judged mostly on the ways it could suspend an innocent agent.
//!
//! This control's failure modes are asymmetric and both are bad. Failing to trip leaves a poisoned
//! agent serving traffic under busbar's provenance stamp. Tripping wrongly takes a healthy agent out
//! of service, and does it with a strict arm that has no soft form. So the tests below are mostly
//! about the second: the floor, the unconfigured threshold, the empty window, and the stability of
//! the reason string, because those are how a well-meaning default becomes an outage.

use super::*;
use busbar_substrate::trust::{Approval, Sighting, TrustState};

fn thresholds() -> Thresholds {
    Thresholds {
        min_observations: 20,
        error_rate: Some(0.5),
        terminal_failure_rate: Some(0.5),
        latency_p95_ms: Some(10_000),
        egress_budget_ratio: Some(3.0),
    }
}

fn window(observations: u32) -> Window {
    Window {
        observations,
        first_observation_ms: 1_000,
        last_observation_ms: 61_000,
        ..Window::default()
    }
}

/// THE FLOOR, and it is the most important test here. One failed dispatch is a 100 percent error
/// rate. Without a sample floor the first request of the day failing suspends the agent, which is a
/// self-inflicted outage dressed as a security control.
#[test]
fn a_ratio_over_a_tiny_sample_cannot_trip() {
    let mut w = window(1);
    w.errors = 1;
    assert_eq!(evaluate(&w, &thresholds()), None);

    // One short of the floor is still short of the floor.
    let mut w = window(19);
    w.errors = 19;
    assert_eq!(evaluate(&w, &thresholds()), None);

    // And at the floor it trips, so the floor is a floor and not an off switch.
    let mut w = window(20);
    w.errors = 20;
    assert!(evaluate(&w, &thresholds()).is_some());
}

/// AN EMPTY WINDOW cannot trip and cannot divide by zero, even when the operator set the floor to
/// zero. A configured floor of zero says "do not require a sample", not "trip on no data".
#[test]
fn an_empty_window_never_trips_even_with_no_floor() {
    let t = Thresholds {
        min_observations: 0,
        ..thresholds()
    };
    assert_eq!(evaluate(&window(0), &t), None);
    assert_eq!(evaluate(&Window::default(), &t), None);
    assert_eq!(evaluate(&Window::default(), &Thresholds::default()), None);
}

/// AN UNCONFIGURED THRESHOLD NEVER TRIPS. `None` means the operator did not configure the signal; it
/// does not mean zero. Read as zero, every agent in the deployment suspends the moment this ships,
/// which would be the largest availability event this design could cause and it would be caused by
/// a default rather than by an attack.
#[test]
fn an_unconfigured_threshold_is_not_a_threshold_of_zero() {
    let none_configured = Thresholds {
        min_observations: 1,
        ..Thresholds::default()
    };
    let mut w = window(100);
    w.errors = 100;
    w.terminal_failures = 100;
    w.latency_p95_ms = u64::MAX;
    w.egress_spend_ratio = 1_000.0;
    assert_eq!(
        evaluate(&w, &none_configured),
        None,
        "a deployment that configured nothing must suspend nothing"
    );
}

/// A HEALTHY AGENT at a healthy sample size does not trip. The negative control: a breaker that
/// trips on everything passes every test about tripping.
#[test]
fn a_healthy_window_does_not_trip() {
    let mut w = window(500);
    w.errors = 3;
    w.terminal_failures = 4;
    w.latency_p95_ms = 900;
    w.egress_spend_ratio = 1.1;
    assert_eq!(evaluate(&w, &thresholds()), None);
}

/// REACHING the threshold trips it. The operator wrote the number they consider unacceptable, so
/// treating it as the last acceptable value would make every configured threshold quietly mean
/// something other than what it says. Pinned on both sides of the boundary.
#[test]
fn reaching_the_threshold_trips_and_just_under_it_does_not() {
    let mut at = window(100);
    at.errors = 50;
    assert_eq!(
        evaluate(&at, &thresholds()).map(|t| t.signal),
        Some(AnomalySignal::ErrorRate)
    );

    let mut under = window(100);
    under.errors = 49;
    assert_eq!(evaluate(&under, &thresholds()), None);

    // The same rule for the integer signal.
    let mut at_latency = window(100);
    at_latency.latency_p95_ms = 10_000;
    assert_eq!(
        evaluate(&at_latency, &thresholds()).map(|t| t.signal),
        Some(AnomalySignal::LatencyP95Ms)
    );
    let mut under_latency = window(100);
    under_latency.latency_p95_ms = 9_999;
    assert_eq!(evaluate(&under_latency, &thresholds()), None);
}

/// EACH SIGNAL TRIPS ON ITS OWN. Terminal failure is deliberately not folded into error rate: an
/// agent that cleanly ACCEPTS work and then refuses all of it is not erroring, it is not doing the
/// job it was approved for, and an operator seeing "error_rate 0.00" alongside a suspension would
/// reasonably conclude the breaker was broken.
#[test]
fn each_signal_trips_on_its_own() {
    type Arm = (AnomalySignal, fn(&mut Window));
    let cases: [Arm; 4] = [
        (AnomalySignal::ErrorRate, |w| w.errors = 60),
        (AnomalySignal::TerminalFailureRate, |w| {
            w.terminal_failures = 60
        }),
        (AnomalySignal::LatencyP95Ms, |w| w.latency_p95_ms = 30_000),
        (AnomalySignal::EgressBudget, |w| w.egress_spend_ratio = 9.0),
    ];
    for (expected, arm) in cases {
        let mut w = window(100);
        arm(&mut w);
        assert_eq!(
            evaluate(&w, &thresholds()).map(|t| t.signal),
            Some(expected),
            "{} must trip on its own signal",
            expected.label()
        );
    }
}

/// WHEN SEVERAL TRIP AT ONCE the reported signal is FIXED, not whichever looked worst. A reason
/// string that flapped between evaluations is one an operator cannot correlate with anything, and
/// "worst" is not comparable across signals measured in different units.
#[test]
fn a_multi_signal_trip_reports_one_stable_signal() {
    let mut w = window(100);
    w.errors = 100;
    w.terminal_failures = 100;
    w.latency_p95_ms = u64::MAX;
    w.egress_spend_ratio = 1_000.0;

    let first = evaluate(&w, &thresholds()).expect("trips");
    assert_eq!(first.signal, AnomalySignal::ErrorRate);
    for _ in 0..8 {
        assert_eq!(evaluate(&w, &thresholds()), Some(first.clone()));
    }
}

/// THE REASON MUST BE ACTIONABLE. It names the signal, the observed value, the configured threshold,
/// the sample size and the window. A breaker whose trips cannot be explained gets its thresholds
/// raised until it never fires, and then it protects nothing.
#[test]
fn the_reason_names_the_signal_the_numbers_and_the_window() {
    let mut w = window(120);
    w.errors = 96;
    w.first_observation_ms = 1_700_000;
    w.last_observation_ms = 1_760_000;
    let reason = evaluate(&w, &thresholds()).expect("trips").reason();

    for needle in [
        "error_rate", // which signal
        "0.800",      // what was observed
        "0.500",      // what the operator configured
        "120",        // how big the sample was
        "1700000",    // when the window opened
        "1760000",    // when it closed
    ] {
        assert!(
            reason.contains(needle),
            "the operator-visible reason must contain {needle:?}: {reason}"
        );
    }
}

/// A trip on one signal does not misreport another signal's numbers. The observed and threshold
/// values belong to the signal that actually tripped, or the reason is worse than no reason.
#[test]
fn the_reported_numbers_belong_to_the_signal_that_tripped() {
    let mut w = window(100);
    w.errors = 0;
    w.latency_p95_ms = 45_000;
    let trip = evaluate(&w, &thresholds()).expect("trips");
    assert_eq!(trip.signal, AnomalySignal::LatencyP95Ms);
    assert_eq!(trip.observed, "45000");
    assert_eq!(trip.threshold, "10000");
    assert!(!trip.reason().contains("error_rate"));
}

/// THE LOAD-BEARING INTEGRATION. A trip SUSPENDS, and suspension outranks everything: the pin is
/// still locked, the digests still match, the agent is still exactly what the operator approved, and
/// it serves nothing. This is the whole point of `Suspended` being a first-class state rather than a
/// field beside the trust state, and it is what replaces the deleted reward loop.
#[test]
fn a_trip_suspends_an_otherwise_perfectly_healthy_registration() {
    use crate::a2a::pin::{approve_registration, CardPin};
    use busbar_substrate::trust::Observation;
    use std::collections::BTreeMap;

    let pin = CardPin::JwsIssuerKey {
        issuer_key: "OPERATOR-KEY".to_string(),
        card_fingerprint: "sha256/FP".to_string(),
    };
    let sighting = Sighting::Seen(Observation {
        pin: Some(pin),
        capabilities: BTreeMap::from([("plan".to_string(), "sha256/PLAN".to_string())]),
    });
    let mut approval = Approval::registered();
    approve_registration(&mut approval, &sighting, None).expect("approve");
    assert_eq!(approval.state(&sighting), TrustState::Approved);
    assert!(approval.serves("plan", "sha256/PLAN"));

    let mut w = window(200);
    w.terminal_failures = 180;
    let trip = evaluate(&w, &thresholds()).expect("trips");
    approval.suspend(&trip.reason());

    assert_eq!(
        approval.state(&sighting),
        TrustState::Suspended,
        "a tripped agent leaves service, it does not sort last"
    );
    assert!(
        !approval.serves("plan", "sha256/PLAN"),
        "dispatch must refuse a suspended agent even though nothing about its card changed"
    );
    let visible = approval.suspension().expect("an operator-visible reason");
    assert!(visible.contains("terminal_failure_rate"));
    assert!(visible.contains("0.900"));

    // Resuming returns it to what its approval and sighting actually say. Lifting a suspension is
    // not a re-approval, and here there is nothing else wrong, so it serves again.
    approval.resume();
    assert_eq!(approval.state(&sighting), TrustState::Approved);
    assert!(approval.serves("plan", "sha256/PLAN"));
}
