// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The evidence accessors, the lane-leg declaration gates, the proxy band's own boundary and the
//! "this settlement bills nothing" predicate — each pinned by a case that fails if the accessor
//! stops answering with what it was handed.
//!
//! These are the readers the whole metering fold is driven through. A `values()` that answered an
//! empty slice, a `lane_legs()` that answered a default, or an `is_empty()` frozen at one answer
//! would each route a real unit down the wrong row of the settlement table with no other symptom,
//! so each one is stated here against a value it could not have invented.

use std::collections::{BTreeMap, BTreeSet};

use busbar_caps::step::MeterClassId;

use super::{counts, kernel_count, located, plane_count, token, usage, INPUT, OUTPUT};
use crate::{
    cross_check_lane, meter, settle, DisputeReason, Evidence, KernelCounts, LaneLegs,
    LegDeclaration, MeterPolicy, RetainedLocatorValues, SettleFlag, Settlement, UnitEndKind,
};
use busbar_contract::ClassDirection as Direction;

/// The three lane names a unit retained come back out of the retained values unchanged.
///
/// Both halves of the constructor are asserted in one case, because the accessor and the
/// constructor are only meaningful together: values that survived the build and legs that survived
/// it are what the fold reads next.
#[test]
fn retained_values_carry_the_legs_they_were_built_with() {
    let legs = LaneLegs {
        admit_locator: Some("pool-west".to_string()),
        verified: Some("lane-a".to_string()),
        response: Some("lane-a".to_string()),
    };
    let retained = RetainedLocatorValues::with_lane_legs(
        vec![located(INPUT, 7, Direction::Input)],
        legs.clone(),
    );

    assert_eq!(retained.lane_legs(), &legs);
    assert_eq!(retained.values().len(), 1);
    assert_eq!(retained.values()[0].quantity, 7);
    assert_eq!(retained.values()[0].class, MeterClassId::new(INPUT));
}

/// A unit with no lane evidence at all retains the default legs, and a unit with legs does not.
///
/// The pair is what makes the accessor's answer content-bearing: one shape reads as the default
/// and the other must not, so an accessor that always answered the default fails the second half.
#[test]
fn legs_are_default_only_when_nothing_located_a_lane() {
    let bare = RetainedLocatorValues::new(vec![located(INPUT, 1, Direction::Input)]);
    assert_eq!(bare.lane_legs(), &LaneLegs::default());

    let with_legs = RetainedLocatorValues::with_lane_legs(
        vec![located(INPUT, 1, Direction::Input)],
        LaneLegs {
            admit_locator: None,
            verified: Some("lane-a".to_string()),
            response: None,
        },
    );
    assert_ne!(with_legs.lane_legs(), &LaneLegs::default());
    assert_eq!(with_legs.lane_legs().verified.as_deref(), Some("lane-a"));
}

/// Emptiness is a question about the values, and it answers both ways.
///
/// A predicate frozen at either answer sends every unit down one row of the settlement table:
/// always-empty bills the kernel floor for work a locator did report, always-non-empty reads a
/// locator that never ran as one that did.
#[test]
fn retained_emptiness_answers_both_ways() {
    assert!(RetainedLocatorValues::new(Vec::new()).is_empty());
    assert!(!RetainedLocatorValues::new(vec![located(INPUT, 0, Direction::Input)]).is_empty());
}

/// The kernel's own lines come back out whole — they are the floor a unit settles at when no
/// locator arrived, so an accessor answering nothing would settle that unit at zero.
#[test]
fn kernel_lines_come_back_whole() {
    let kernel = counts(vec![kernel_count(INPUT, 11), kernel_count(OUTPUT, 3)]);

    assert_eq!(kernel.lines().len(), 2);
    assert_eq!(kernel.lines()[0].quantity, 11);
    assert_eq!(kernel.lines()[1].quantity, 3);
    assert_eq!(kernel.lines()[0].class, MeterClassId::new(INPUT));

    // The empty case is stated too, so "answers a fresh empty slice" cannot be read as correct.
    assert!(KernelCounts::new(Vec::new()).lines().is_empty());
}

/// The proxy band is `>`, not `>=`: a reported cardinality exactly at the floor times the ratio is
/// inside the band and raises no second dispute.
///
/// The boundary is the whole of the rule. A figure exactly at the bound is the largest figure the
/// policy allows, and flagging it would dispute a unit the operator's own configuration permits.
#[test]
fn a_cardinality_exactly_at_the_proxy_bound_is_inside_the_band() {
    let policy = MeterPolicy {
        locator_floor_ratio: 4,
        ..MeterPolicy::default()
    };
    let mut proxies = BTreeMap::new();
    // The bound is proxy * ratio == 40; the reported figure sits exactly on it.
    proxies.insert(OUTPUT.to_string(), 10u64);
    // No companion for OUTPUT in the kernel lines, so the fold takes the no-companion arm.
    let kernel = KernelCounts::with_proxies(vec![kernel_count(INPUT, 5)], proxies);
    let retained = RetainedLocatorValues::new(vec![plane_count(OUTPUT, 40, "choices")]);

    let metered = meter(
        &retained,
        &kernel,
        &policy,
        &LegDeclaration {
            admit_locator: false,
            verified: false,
            response: false,
        },
        &token(),
    )
    .expect("a one-line report stays within the bound");

    // Exactly one dispute — the missing companion — and no band dispute beside it.
    let band: Vec<_> = metered
        .disputes
        .iter()
        .filter(|d| d.reason == DisputeReason::AboveFloorBand)
        .collect();
    assert!(band.is_empty(), "at the bound is inside the band");
    assert_eq!(metered.disputes.len(), 1);
    assert_eq!(metered.disputes[0].reason, DisputeReason::NoCompanion);

    // One unit past the bound is outside it, which is what makes the boundary a boundary.
    let over = RetainedLocatorValues::new(vec![plane_count(OUTPUT, 41, "choices")]);
    let metered_over = meter(
        &over,
        &kernel,
        &policy,
        &LegDeclaration {
            admit_locator: false,
            verified: false,
            response: false,
        },
        &token(),
    )
    .expect("a one-line report stays within the bound");
    assert!(metered_over
        .disputes
        .iter()
        .any(|d| d.reason == DisputeReason::AboveFloorBand));
}

/// The request-side membership check runs only when BOTH its legs are declared.
///
/// An undeclared admission leg is not evidence, and comparing a lane against a name the plane never
/// promised to produce would dispute every unit on a plane that locates no lane at all.
#[test]
fn the_membership_check_needs_both_its_legs_declared() {
    let policy = MeterPolicy::default();
    let legs = LaneLegs {
        // A name that expands to itself, and it is not the lane that was served.
        admit_locator: Some("pool-west".to_string()),
        verified: Some("lane-a".to_string()),
        response: None,
    };
    let declared = LegDeclaration {
        admit_locator: false,
        verified: true,
        response: false,
    };

    let check = cross_check_lane(&legs, &declared, &policy);
    assert!(
        !check.disputed,
        "an undeclared admission leg is not compared against the served lane"
    );
    assert_eq!(check.lane.as_deref(), Some("lane-a"));

    // Declared on both sides, the same disagreement is a dispute.
    let both = LegDeclaration {
        admit_locator: true,
        verified: true,
        response: false,
    };
    assert!(cross_check_lane(&legs, &both, &policy).disputed);
}

/// The response-side equality runs only when BOTH its legs are declared.
#[test]
fn the_response_equality_needs_both_its_legs_declared() {
    let policy = MeterPolicy::default();
    let legs = LaneLegs {
        admit_locator: None,
        verified: Some("lane-a".to_string()),
        response: Some("lane-b".to_string()),
    };
    let declared = LegDeclaration {
        admit_locator: false,
        verified: true,
        response: false,
    };

    let check = cross_check_lane(&legs, &declared, &policy);
    assert!(
        !check.disputed,
        "an undeclared response leg is not compared against the served lane"
    );
    assert_eq!(check.lane.as_deref(), Some("lane-a"));

    let both = LegDeclaration {
        admit_locator: false,
        verified: true,
        response: true,
    };
    assert!(cross_check_lane(&legs, &both, &policy).disputed);
}

/// A pool name that DOES expand to the served lane never disputes, however the legs are declared.
///
/// The membership rule is the reason the request-side leg is a set test rather than an equality,
/// and a rule stated only in the negative would pass on a check that always disputed.
#[test]
fn a_pool_that_contains_the_served_lane_agrees_with_it() {
    let mut expansions = BTreeMap::new();
    expansions.insert(
        "pool-west".to_string(),
        BTreeSet::from(["lane-a".to_string(), "lane-b".to_string()]),
    );
    let policy = MeterPolicy {
        lane_expansions: expansions,
        ..MeterPolicy::default()
    };
    let legs = LaneLegs {
        admit_locator: Some("pool-west".to_string()),
        verified: Some("lane-b".to_string()),
        response: Some("lane-b".to_string()),
    };

    let check = cross_check_lane(&legs, &LegDeclaration::default(), &policy);
    assert!(!check.disputed);
    assert_eq!(check.lane.as_deref(), Some("lane-b"));
}

/// "Bills nothing" is a question about the quantities, and it answers both ways.
///
/// A settlement whose lines are all zero bills nothing; one with any positive quantity bills
/// something. A predicate frozen at either answer is a settlement nobody can tell apart from a
/// void, which is the difference between an invoice and no invoice.
#[test]
fn a_settlement_bills_nothing_only_when_every_line_is_zero() {
    let zeroed = Settlement {
        lines: super::plain(&[(INPUT, 0), (OUTPUT, 0)]),
        flags: Default::default(),
        internal_evidence: Vec::new(),
    };
    assert!(zeroed.is_zero());

    let billed = Settlement {
        lines: super::plain(&[(INPUT, 0), (OUTPUT, 5)]),
        flags: Default::default(),
        internal_evidence: Vec::new(),
    };
    assert!(!billed.is_zero());

    // A settlement with no lines at all bills nothing, which the fold over an empty slice already
    // says — stated so the empty case is not left to inference.
    let empty = Settlement {
        lines: Vec::new(),
        flags: Default::default(),
        internal_evidence: Vec::new(),
    };
    assert!(empty.is_zero());
}

/// The completed row bills what the locator reported, and the predicate agrees with the lines.
///
/// The two readers of one settlement — the lines an invoice is cut from and the predicate a caller
/// asks — must not be able to disagree, so they are asserted against each other on a real row of
/// the table rather than on a hand-built value.
#[test]
fn the_completed_row_bills_the_located_figure_and_says_so() {
    let located_usage = usage(&[(INPUT, 12), (OUTPUT, 4)]);
    let evidence = Evidence {
        located: Some(&located_usage),
        ..Evidence::default()
    };
    let settlement = settle(UnitEndKind::Completed, &evidence);

    assert!(!settlement.is_zero());
    assert_eq!(
        super::pairs(&settlement.lines),
        vec![(INPUT, 12), (OUTPUT, 4)]
    );
    assert!(!settlement.flags.contains(&SettleFlag::Estimated));
}
