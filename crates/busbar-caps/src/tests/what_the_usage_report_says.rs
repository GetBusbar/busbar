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

use crate::*;

fn seal() -> KernelSeal {
    KernelSeal::acquire_for_kernel()
}

fn line(source: QuantitySource) -> UsageLine {
    UsageLine {
        class: MeterClassId::new("class"),
        quantity: 1,
        source,
        estimated: false,
    }
}

/// Every source, with the three answers each one owes.
///
/// The exhaustive match below is the totality check: an eighth source does not compile until it has
/// said which of the three it is, which is what "the set is closed on purpose" has to mean in code.
/// A quantity that could come from anywhere is a quantity nobody can check.
fn every_source() -> Vec<(QuantitySource, bool, bool)> {
    let all = [
        QuantitySource::Locator {
            direction: busbar_contract::ClassDirection::Response,
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
        direction: busbar_contract::ClassDirection::Response,
        ptr: LocatorPtr::new("/usage/total_tokens"),
    };
    match &source {
        QuantitySource::Locator { ptr, .. } => assert_eq!(ptr.as_str(), "/usage/total_tokens"),
        other => panic!("built a locator, got {other:?}"),
    }
}

#[test]
fn a_report_hands_back_the_lines_it_was_given() {
    // The lines are what the posting is evidence FOR. A report that handed back an empty slice would
    // settle an amount with nothing on the record saying what it was for, and the settlement itself
    // would look untouched.
    let k = seal();
    let lines = vec![
        UsageLine {
            class: MeterClassId::new("tokens"),
            quantity: 900,
            source: QuantitySource::Locator {
                direction: busbar_contract::ClassDirection::Response,
                ptr: LocatorPtr::new("/usage/total_tokens"),
            },
            estimated: false,
        },
        UsageLine {
            class: MeterClassId::new("seconds"),
            quantity: 12,
            source: QuantitySource::KernelElapsedMono,
            estimated: false,
        },
    ];
    let usage = Usage::report(&UsageToken::mint(&k), lines.clone()).expect("two lines fit");
    assert_eq!(usage.lines(), &lines[..]);
    assert_eq!(usage.lines().len(), 2);
    assert_eq!(usage.lines()[0].quantity, 900);
    assert_eq!(usage.lines()[1].class, MeterClassId::new("seconds"));
    assert_eq!(usage.total(), 912);
    assert!(!usage.is_estimated());
}

#[test]
fn the_largest_report_the_record_can_hold_is_accepted() {
    // The boundary the bound is written at. `MAX_USAGE_LINES` is the size of the fixed record, so a
    // report of exactly that many lines is the last one that FITS — refusing it would drop the final
    // line of the biggest unit the node runs, and the place that shows is a bill.
    let k = seal();
    let full: Vec<UsageLine> = (0..MAX_USAGE_LINES)
        .map(|_| line(QuantitySource::Count))
        .collect();
    let usage = Usage::report(&UsageToken::mint(&k), full).expect("exactly the bound fits");
    assert_eq!(usage.lines().len(), MAX_USAGE_LINES);
    assert_eq!(usage.total(), MAX_USAGE_LINES as u64);

    // And one past it does not, in either constructor.
    let over: Vec<UsageLine> = (0..MAX_USAGE_LINES + 1)
        .map(|_| line(QuantitySource::Count))
        .collect();
    assert_eq!(
        Usage::report(&UsageToken::mint(&k), over.clone()),
        Err(UsageError::TooManyLines)
    );
    assert_eq!(
        Usage::estimate(&UsageToken::mint(&k), over),
        Err(UsageError::TooManyLines),
        "the estimate goes through the same bound rather than around it"
    );
}

#[test]
fn an_authenticate_step_that_asked_for_another_round_names_no_principal() {
    // Two arms, because a challenge is not a decision about the unit — it is a request for one more
    // round before one can be made. A step that answered with a principal anyway would have the loop
    // proceeding past authentication on an identity nobody established; one that answered with none
    // where an identity WAS established would send an authenticated caller back round for ever.
    let established = Authenticated::Principal {
        id: PrincipalId::new("acct-4"),
        tier: None,
    };
    assert_eq!(
        established.principal(),
        Some(&PrincipalId::new("acct-4")),
        "the step settled on somebody"
    );

    let another_round = Authenticated::Challenge(busbar_contract::Challenge {
        bytes: b"nonce".to_vec(),
        state: busbar_contract::ChallengeState(b"round-1".to_vec()),
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

#[test]
fn a_cell_counts_the_accruals_it_took_and_starts_at_none() {
    // One of the four numbers the canary balances. A count that started at one would have the
    // canary reporting a settlement missing on every clean run; one that never moved would let a
    // child's spend disappear without the arithmetic noticing.
    let k = seal();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&k);
    let cell = HoldCell::new(Hold::open(&admit, PrincipalId::new("acct-1"), 0));
    assert_eq!(cell.accruals(), 0, "a fresh cell has taken nothing");

    let arrival = cell
        .admit(
            Hold::open(&admit, PrincipalId::new("acct-1"), 1_000),
            &admit,
        )
        .expect("admitted");
    assert_eq!(cell.accruals(), 0, "passing the door is not an accrual");

    let mut children = Vec::new();
    for expected in 1..=3 {
        children.push(
            cell.accrue_child(&PrincipalId::new("acct-1"), 10, &admit)
                .expect("an admitted parent takes a child's spend"),
        );
        assert_eq!(cell.accruals(), expected);
    }

    // A refused accrual is not one the cell took.
    cell.accrue_child(&PrincipalId::new("acct-2"), 10, &admit)
        .expect_err("another principal's child is refused");
    assert_eq!(cell.accruals(), 3);

    let ledger = LedgerToken::mint(&k);
    for child in children {
        let _ = Posted::into_parent(child, &cell, &ledger).expect("the parent is still open");
    }
    let taken = cell.take(&ExitToken::mint(&k)).expect("the exit takes it");
    let _ = Posted::settle(
        arrival,
        0,
        &Usage::report(&UsageToken::mint(&k), Vec::new()).unwrap(),
        &ledger,
    );
    let _ = Posted::settle(
        taken,
        30,
        &Usage::report(&UsageToken::mint(&k), Vec::new()).unwrap(),
        &ledger,
    );
}
