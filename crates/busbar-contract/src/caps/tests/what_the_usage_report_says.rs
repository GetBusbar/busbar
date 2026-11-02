// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The provenance of a number, and the three questions asked about it.

use crate::caps::*;

/// Every source, with the three answers each one owes.
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

        assert_eq!(source.is_reported(), !*derived, "{source:?}");
        assert_ne!(source.is_kernel_derived(), source.is_reported());
        assert_eq!(
            source.is_floor(),
            *floor,
            "{source:?} disagrees about whether it floors"
        );
    }

    assert!(QuantitySource::KernelBytes { divisor: 2 }.is_floor());
    assert!(!QuantitySource::KernelFrames { factor: 2 }.is_floor());
    assert!(!QuantitySource::KernelElapsedMono.is_floor());
}

#[test]
fn a_locator_says_where_in_the_payload_the_number_was_found() {
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
