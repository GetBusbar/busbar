// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The re-verification cadence, driven the way a hostile upstream would drive it.
//!
//! Every test below is something an upstream that wants to change its card without being demoted
//! would actually try: stop the clock, refuse connections, flap, or wait out a backoff it earned
//! earlier. The happy path is the last test in the file, and it is the least interesting one.

use super::super::{Observation, TrustState};
use super::*;
use crate::trust::{Approval, Sighting};
use busbar_a2a::a2a::pin::{approve_registration, CardPin};
use std::collections::BTreeMap;

fn policy() -> Policy {
    Policy {
        ttl_ms: 6 * 60 * 60 * 1000,
        recovery_backoff_ms: 30 * 60 * 1000,
    }
}

fn pin(fingerprint: &str) -> CardPin {
    CardPin::JwsIssuerKey {
        issuer_key: "OPERATOR-KEY".to_string(),
        card_fingerprint: fingerprint.to_string(),
    }
}

fn seen(fingerprint: &str, plan_digest: &str) -> Sighting<CardPin> {
    Sighting::Seen(Observation {
        pin: Some(pin(fingerprint)),
        capabilities: BTreeMap::from([("plan".to_string(), plan_digest.to_string())]),
    })
}

/// An approved registration, plus the sighting it was approved from.
fn approved() -> (Approval<CardPin>, Sighting<CardPin>) {
    let sighting = seen("sha256/FP-1", "sha256/PLAN-1");
    let mut approval = Approval::registered();
    approve_registration(&mut approval, &sighting, None).expect("approve");
    (approval, sighting)
}

/// A registration approved from a declarative pin has legitimately never been contacted, and that is
/// due rather than fresh. Treating "no observation" as "nothing has changed" would mean an upstream
/// nobody ever looked at is the one thing nobody ever looks at.
#[test]
fn never_contacted_is_due() {
    assert_eq!(
        due(&Ledger::default(), &policy(), 0, false),
        Due::NeverChecked
    );
    assert!(due(&Ledger::default(), &policy(), 0, false).should_check());
}

/// Reaching the TTL is due, both sides of the boundary pinned. The operator wrote the longest
/// staleness they will accept, so treating it as still acceptable makes the setting mean something
/// other than what it says.
#[test]
fn reaching_the_ttl_is_due_and_one_tick_short_is_not() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000),
        ..Ledger::default()
    };
    let p = policy();
    assert_eq!(due(&ledger, &p, 1_000 + p.ttl_ms - 1, false), Due::No);
    assert_eq!(due(&ledger, &p, 1_000 + p.ttl_ms, false), Due::TtlExpired);
    assert_eq!(
        due(&ledger, &p, 1_000 + p.ttl_ms * 9, false),
        Due::TtlExpired
    );
}

/// THE CLOCK GOING BACKWARDS. An NTP correction, a restored snapshot, or a tampered host clock makes
/// the elapsed time uncomputable. The fail-closed answer is to check; the naive one saturates the
/// subtraction to zero, reports fresh, and hands the upstream permanent freshness. An upstream that
/// is never checked again can change whatever it likes.
#[test]
fn a_clock_that_went_backwards_is_due_rather_than_permanently_fresh() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000_000),
        ..Ledger::default()
    };
    assert_eq!(
        due(&ledger, &policy(), 999_999, false),
        Due::ClockWentBackwards
    );
    assert_eq!(due(&ledger, &policy(), 0, false), Due::ClockWentBackwards);
    assert!(due(&ledger, &policy(), 0, false).should_check());
}

/// An operator sync outranks the timer. Someone with out-of-band reason to suspect an upstream, or
/// handling a scheduled vendor key rotation, does not wait for it.
#[test]
fn an_operator_sync_outranks_a_fresh_window() {
    let ledger = Ledger {
        last_checked_ms: Some(1_000),
        ..Ledger::default()
    };
    assert_eq!(due(&ledger, &policy(), 1_001, false), Due::No);
    assert_eq!(due(&ledger, &policy(), 1_001, true), Due::OperatorSync);
}

/// THE FIRST DRIFT DEMOTES IMMEDIATELY. Nothing is held on the way down, so an upstream that flapped
/// recently never earns a window in which its next change goes unacted on. Choosing when to flap is
/// entirely within its gift, so any such window is one it can arrange.
#[test]
fn the_first_drift_demotes_immediately_and_nothing_buys_a_free_window() {
    let (approval, recorded) = approved();
    let mut ledger = Ledger::default();

    let drifted = seen("sha256/FP-2", "sha256/PLAN-1");
    let settled = settle(
        &approval,
        &recorded,
        drifted.clone(),
        &mut ledger,
        &policy(),
        10_000,
    );
    assert!(settled.drift_observed);
    assert!(!settled.recovery_held);
    assert_eq!(settled.sighting, drifted);
    assert_eq!(approval.state(&settled.sighting), TrustState::Quarantined);

    // And again immediately afterwards, while a backoff from the first is still running: the second
    // change is acted on too.
    let drifted_again = seen("sha256/FP-3", "sha256/PLAN-1");
    let settled = settle(
        &approval,
        &settled.sighting,
        drifted_again.clone(),
        &mut ledger,
        &policy(),
        10_001,
    );
    assert!(settled.drift_observed);
    assert_eq!(settled.sighting, drifted_again);
    assert_eq!(approval.state(&settled.sighting), TrustState::Quarantined);
}

/// THE FLAP. An upstream alternating between the approved card and a changed one, as fast as the
/// job will look. The recorded state must not alternate with it: that alternation is a demotion
/// storm, which is a denial of service against the operator rather than against the gateway, and an
/// operator buried in alerts turns them off.
#[test]
fn a_flapping_upstream_stays_quarantined_instead_of_producing_a_storm() {
    let (approval, clean) = approved();
    let drifted = seen("sha256/FP-2", "sha256/PLAN-1");
    let mut ledger = Ledger::default();
    let mut recorded = clean.clone();

    let mut quarantined_ticks = 0;
    let mut approved_ticks = 0;
    for tick in 0..20u64 {
        // One minute apart, well inside the thirty minute backoff.
        let now = tick * 60_000;
        let observed = if tick % 2 == 0 {
            drifted.clone()
        } else {
            clean.clone()
        };
        let settled = settle(&approval, &recorded, observed, &mut ledger, &policy(), now);
        recorded = settled.sighting;
        match approval.state(&recorded) {
            TrustState::Quarantined => quarantined_ticks += 1,
            TrustState::Approved => approved_ticks += 1,
            other => panic!("unexpected state {other:?}"),
        }
    }

    assert_eq!(
        approved_ticks, 0,
        "a clean answer inside the backoff must not restore service to an upstream that keeps \
         changing its card"
    );
    assert_eq!(quarantined_ticks, 20);
    // DETECTION IS NEVER SUPPRESSED. Every one of the ten drifting observations is counted, because
    // the changes queue an operator works must show what actually happened rather than what
    // survived the filter.
    assert_eq!(ledger.drift_observations, 10);
}

/// The backoff is held on RECOVERY only, and it does expire. A genuine transient must be able to
/// come back, or the control is a one-way door and operators route around it.
#[test]
fn recovery_is_disbelieved_only_until_the_backoff_elapses() {
    let (approval, clean) = approved();
    let drifted = seen("sha256/FP-2", "sha256/PLAN-1");
    let p = policy();
    let mut ledger = Ledger::default();

    let after_drift = settle(&approval, &clean, drifted, &mut ledger, &p, 1_000).sighting;
    assert_eq!(approval.state(&after_drift), TrustState::Quarantined);

    // One tick short of the backoff: still disbelieved, and said so out loud.
    let held = settle(
        &approval,
        &after_drift,
        clean.clone(),
        &mut ledger,
        &p,
        1_000 + p.recovery_backoff_ms - 1,
    );
    assert!(held.recovery_held);
    assert!(!held.drift_observed);
    assert_eq!(approval.state(&held.sighting), TrustState::Quarantined);

    // At the backoff: believed.
    let recovered = settle(
        &approval,
        &held.sighting,
        clean.clone(),
        &mut ledger,
        &p,
        1_000 + p.recovery_backoff_ms,
    );
    assert!(!recovered.recovery_held);
    assert_eq!(recovered.sighting, clean);
    assert_eq!(approval.state(&recovered.sighting), TrustState::Approved);
}

/// A FAILED CONTACT IS NOT A RECOVERY, and it does not age the quarantine out. An upstream that
/// could clear its own drift clock by refusing connections would have the cheapest possible escape:
/// change the card, then stop answering until the backoff lapses.
#[test]
fn an_upstream_cannot_refuse_connections_to_age_out_its_own_quarantine() {
    let (approval, clean) = approved();
    let drifted = seen("sha256/FP-2", "sha256/PLAN-1");
    let p = policy();
    let mut ledger = Ledger::default();

    settle(&approval, &clean, drifted, &mut ledger, &p, 1_000);
    let drift_clock = ledger.last_drift_ms;

    // Refuse everything for a long time. Each refusal is recorded, and each derives `Error`, which
    // never serves.
    let mut recorded = seen("sha256/FP-2", "sha256/PLAN-1");
    for tick in 1..=10u64 {
        let settled = settle(
            &approval,
            &recorded,
            Sighting::Failed("connection refused".to_string()),
            &mut ledger,
            &p,
            1_000 + tick * p.recovery_backoff_ms,
        );
        recorded = settled.sighting;
        assert!(!settled.drift_observed);
        assert_eq!(approval.state(&recorded), TrustState::Error);
    }
    assert_eq!(
        ledger.last_drift_ms, drift_clock,
        "a refused connection must not move the drift clock"
    );
    // The check itself is still stamped, so the upstream cannot look fresh by being unreachable.
    assert_eq!(
        ledger.last_checked_ms,
        Some(1_000 + 10 * p.recovery_backoff_ms)
    );
}

/// A zero backoff is a legitimate operator setting and means "believe a recovery immediately". It
/// must not accidentally mean "hold forever" or "hold for one tick".
#[test]
fn a_zero_backoff_believes_a_recovery_at_once() {
    let (approval, clean) = approved();
    let p = Policy {
        recovery_backoff_ms: 0,
        ..policy()
    };
    let mut ledger = Ledger::default();

    let drifted = seen("sha256/FP-2", "sha256/PLAN-1");
    let after = settle(&approval, &clean, drifted, &mut ledger, &p, 1_000).sighting;
    assert_eq!(approval.state(&after), TrustState::Quarantined);

    let recovered = settle(&approval, &after, clean.clone(), &mut ledger, &p, 1_000);
    assert!(!recovered.recovery_held);
    assert_eq!(approval.state(&recovered.sighting), TrustState::Approved);
}

/// Nothing observed folds to nothing recorded. Inventing an observation from an absence is how a
/// quarantine would silently clear itself on a pass that never reached the upstream at all.
#[test]
fn an_absent_observation_changes_nothing_but_the_clock() {
    let (approval, clean) = approved();
    let drifted = seen("sha256/FP-2", "sha256/PLAN-1");
    let mut ledger = Ledger::default();
    let quarantined = settle(&approval, &clean, drifted, &mut ledger, &policy(), 1_000).sighting;

    let settled = settle(
        &approval,
        &quarantined,
        Sighting::Never,
        &mut ledger,
        &policy(),
        999_000,
    );
    assert_eq!(settled.sighting, quarantined);
    assert!(!settled.drift_observed);
    assert_eq!(approval.state(&settled.sighting), TrustState::Quarantined);
    assert_eq!(ledger.last_checked_ms, Some(999_000));
}

/// The happy path, last and least interesting: a healthy upstream re-observed on schedule stays
/// approved, keeps serving, and accumulates no drift.
#[test]
fn a_healthy_upstream_re_observed_on_schedule_stays_approved() {
    let (approval, clean) = approved();
    let p = policy();
    let mut ledger = Ledger::default();
    let mut recorded = clean.clone();

    for tick in 1..=5u64 {
        let now = tick * p.ttl_ms;
        assert!(due(&ledger, &p, now, false).should_check());
        let settled = settle(&approval, &recorded, clean.clone(), &mut ledger, &p, now);
        recorded = settled.sighting;
        assert!(!settled.drift_observed);
        assert!(!settled.recovery_held);
        assert_eq!(approval.state(&recorded), TrustState::Approved);
        assert!(approval.serves("plan", "sha256/PLAN-1"));
        assert_eq!(due(&ledger, &p, now + 1, false), Due::No);
    }
    assert_eq!(ledger.drift_observations, 0);
    assert_eq!(ledger.last_drift_ms, None);
}
