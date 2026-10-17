// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The provenance of a number, and the three questions asked about it.
//!
//! A usage line is a quantity plus where it came from, and the crate answers three questions about
//! the source: did the kernel derive it, did somebody else report it, and is it a floor rather than
//! a count. Those three decide whether a figure wants a companion to be checked against, whether the
//! variance rule has anything to compare, and whether the posting carries the estimate mark onto the
//! disputes report — and each of them was a function nothing called with both answers in mind. A
//! predicate that says yes to everything and one that says no to everything are the same defect from
//! two directions, and neither of them changed a single existing test.
//!
//! The report's own bound is here for the same reason: `MAX_USAGE_LINES` is the size of a fixed
//! record, so the last report that FITS has to be accepted. A ceiling that refused it would drop the
//! final line of the largest unit the node runs, and the only place that shows is a bill.
//!
//! The tests in this file that have to MINT a token live in the kernel, under the same file name
//! in `busbar-kernel/src/tests/caps_tests/` (construction `token-sealed`); what stays here needs
//! no seal.

use crate::caps::*;

/// Every source, with the three answers each one owes.
///
/// The exhaustive match below is the totality check: an eighth source does not compile until it has
/// said which of the three it is, which is what "the set is closed on purpose" has to mean in code.
/// A quantity that could come from anywhere is a quantity nobody can check.
fn every_source() -> Vec<(QuantitySource, bool, bool)> {
    let all = [
        QuantitySource::Locator {
            direction: crate::ClassDirection::Response,
            ptr: LocatorPtr::new("/usage/total_tokens"),
        },
        QuantitySource::KernelBytes { divisor: 1_024 },
        QuantitySource::KernelFrames { factor: 3 },
        QuantitySource::TransportUnits,
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
        QuantitySource::PlaneCount {
            content_fact_key: "messages".into(),
        },
    ];
    all.into_iter()
        .map(|source| {
            // (kernel-derived, a floor). Named one arm at a time, so a source added later has to
            // come back here and say what it is rather than inheriting a neighbour's answer.
            let (derived, floor) = match &source {
                QuantitySource::KernelBytes { .. } => (true, true),
                QuantitySource::KernelFrames { .. } => (true, false),
                QuantitySource::KernelElapsedMono => (true, false),
                QuantitySource::Count => (true, false),
                QuantitySource::Locator { .. } => (false, false),
                QuantitySource::TransportUnits => (false, false),
                QuantitySource::PlaneCount { .. } => (false, false),
            };
            (source, derived, floor)
        })
        .collect()
}

#[test]
fn every_quantity_source_says_who_derived_it_and_whether_it_is_a_floor() {
    let table = every_source();
    assert_eq!(table.len(), 7, "a source was added or dropped");

    // Both answers appear in each column, which is what stops a predicate that has collapsed into a
    // constant from passing: a table of all-true or all-false would be satisfied by one.
    assert!(table.iter().any(|(_, derived, _)| *derived));
    assert!(table.iter().any(|(_, derived, _)| !*derived));
    assert!(table.iter().any(|(_, _, floor)| *floor));
    assert!(table.iter().any(|(_, _, floor)| !*floor));

    for (source, derived, floor) in &table {
        assert_eq!(
            source.is_kernel_derived(),
            *derived,
            "{source:?} disagrees about who derived it"
        );
        // Reported is the complement, not a second opinion: a figure is the kernel's or it is
        // somebody else's, and a unit that answered yes to both would want a companion to check
        // itself against.
        assert_eq!(source.is_reported(), !*derived, "{source:?}");
        assert_ne!(source.is_kernel_derived(), source.is_reported());
        assert_eq!(
            source.is_floor(),
            *floor,
            "{source:?} disagrees about whether it floors"
        );
    }

    // The one that floors is the byte division and only the byte division: it divides and division
    // floors, so the result is a floor and the line carrying it is an estimate. A frame count times
    // a factor is exact, because a frame is a whole thing.
    assert!(QuantitySource::KernelBytes { divisor: 2 }.is_floor());
    assert!(!QuantitySource::KernelFrames { factor: 2 }.is_floor());
    assert!(!QuantitySource::KernelElapsedMono.is_floor());
}

#[test]
fn a_locator_says_where_in_the_payload_the_number_was_found() {
    // The pointer is what the audit row records, and it is the whole of the evidence that a reported
    // figure came from where the plane declared it would. A locator that rendered as nothing would
    // put every reported quantity on the record as unlocatable.
    let ptr = LocatorPtr::new("/usage/output_tokens");
    assert_eq!(ptr.as_str(), "/usage/output_tokens");

    let elsewhere = LocatorPtr::new("/usage/input_tokens");
    assert_ne!(ptr.as_str(), elsewhere.as_str());
    assert_ne!(ptr, elsewhere);
    assert!(format!("{ptr:?}").contains("/usage/output_tokens"));

    let source = QuantitySource::Locator {
        direction: crate::ClassDirection::Response,
        ptr: LocatorPtr::new("/usage/total_tokens"),
    };
    match &source {
        QuantitySource::Locator { ptr, .. } => assert_eq!(ptr.as_str(), "/usage/total_tokens"),
        other => panic!("built a locator, got {other:?}"),
    }
}

#[test]
fn an_authenticate_step_that_asked_for_another_round_names_no_principal() {
    // Two arms, because a challenge is not a decision about the unit — it is a request for one more
    // round before one can be made. A step that answered with a principal anyway would have the loop
    // proceeding past authentication on an identity nobody established; one that answered with none
    // where an identity WAS established would send an authenticated caller back round for ever.
    let established = Authenticated::Principal(PrincipalId::new("acct-4"));
    assert_eq!(
        established.principal(),
        Some(&PrincipalId::new("acct-4")),
        "the step settled on somebody"
    );

    let another_round = Authenticated::Challenge(crate::Challenge {
        bytes: b"nonce".to_vec(),
        state: crate::ChallengeState(b"round-1".to_vec()),
        rounds_left: 2,
    });
    assert_eq!(
        another_round.principal(),
        None,
        "a challenge is not an identity"
    );
    assert_ne!(established, another_round);
}

#[test]
fn only_a_completed_outcome_says_the_unit_ran_to_the_end() {
    // `is_completed` is what decides whether a unit's end is the ordinary one. Everything else — a
    // refusal, a failure, an abort, a deadline — is a unit that stopped, and answering yes for any
    // of them would report a stopped unit as a served one.
    assert!(Outcome::Completed.is_completed());
    let stopped = [
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
        Outcome::Failed(StepName::Route, ReasonCode::PlanePanic),
        Outcome::TimedOut(StepName::Meter),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
        Outcome::Aborted(Abort::Superseded {
            by: UnitKey::new(3),
        }),
    ];
    for outcome in stopped {
        assert!(
            !outcome.is_completed(),
            "{outcome:?} did not run to the end"
        );
    }
}
