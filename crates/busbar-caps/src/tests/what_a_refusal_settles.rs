// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTLEMENT COLUMN, WALKED.
//!
//! `RefusalReason`'s doc has always said that adding a code "is a kernel change, because every code
//! has to have a settlement row". These tests are what make that sentence true: they walk
//! `ReasonCode::ALL`, so a reason added without a money consequence fails here rather than reaching
//! a client as whatever the nearest arm decided.

use crate::decision::ReasonCode;
use crate::step::StepName;
use busbar_contract::unit::{RefusalReason, Settlement};

/// The five reasons the design calls MONEY reasons, and the binding that says money refuses at the
/// door. `crates/busbar/tests/money_never_ends_an_admitted_unit.rs` proves the tree cannot construct
/// them past the door; this proves the table agrees that none of them is ever charged.
const MONEY_REASONS: &[ReasonCode] = &[
    ReasonCode::OverBudget,
    ReasonCode::OverdraftCeiling,
    ReasonCode::StaleSlice,
    ReasonCode::GroupFrozen,
    ReasonCode::Unpriced,
];

#[test]
fn every_reason_the_kernel_can_raise_has_a_settlement() {
    // Non-vacuity: a table this walk found empty would pass every claim below.
    assert_eq!(
        ReasonCode::ALL.len(),
        42,
        "the reason vocabulary changed size"
    );
    for &code in ReasonCode::ALL {
        // `settlement()` is exhaustive with no fallback arm, so this cannot panic — the value of
        // the walk is that it also cannot be a settlement nobody meant, which the next line checks.
        let settled = RefusalReason::from(code).settlement();
        assert!(
            Settlement::ALL.contains(&settled),
            "{code} settles as something outside the closed table"
        );
    }
}

#[test]
fn a_money_reason_is_never_charged() {
    for &code in MONEY_REASONS {
        assert_eq!(
            RefusalReason::from(code).settlement(),
            Settlement::NeverCharged,
            "{code} is a money reason: money refuses at the door and is never charged there"
        );
    }
}

#[test]
fn the_door_is_the_cut_and_admit_is_on_the_uncharged_side() {
    // The claim the whole column rests on: `under_hold` is strictly PAST the door, so a refusal AT
    // the door is a refusal the door never let through.
    for step in StepName::ALL {
        let under_hold = step.under_hold();
        assert_eq!(
            under_hold,
            matches!(
                step,
                StepName::Route | StepName::Meter | StepName::Audit | StepName::Encode
            ),
            "{step:?} is on the wrong side of the door"
        );
        assert_eq!(
            Settlement::of(under_hold, true),
            if under_hold {
                Settlement::ChargedRefundable
            } else {
                Settlement::NeverCharged
            }
        );
    }
}

#[test]
fn past_the_door_and_never_charged_is_its_own_row_and_refunds_nothing() {
    // The case `StepName::under_hold`'s prose does not cover: governance off, no resolved key, or a
    // store error that failed open. A refund here is the blind decrement that erodes a stranger's
    // window, so the row exists precisely so that it can answer `false`.
    assert_eq!(
        Settlement::of(true, false),
        Settlement::AdmittedUncharged,
        "past the door with no fee landed is neither of the other two rows"
    );
    assert!(!Settlement::AdmittedUncharged.refunds());
    assert!(!Settlement::NeverCharged.refunds());
    assert!(Settlement::ChargedRefundable.refunds());
    assert_eq!(
        Settlement::ALL.iter().filter(|s| s.refunds()).count(),
        1,
        "exactly one row refunds, and it is the only one that was charged"
    );
}

#[test]
fn an_unstamped_refusal_settles_the_fail_safe_way() {
    // A refusal that never became a decision has no step, so it cannot have reached one past the
    // door. The failure mode of the other choice is the spurious refund, so this is fail-safe.
    let refusal = crate::decision::Refusal::new(ReasonCode::NoDestination);
    assert!(!refusal.under_hold());
    assert_eq!(refusal.settlement(true), Settlement::NeverCharged);
    assert_eq!(refusal.settlement(false), Settlement::NeverCharged);
}

#[test]
fn no_two_settlements_spell_the_same_word() {
    let mut seen = std::collections::BTreeSet::new();
    for s in Settlement::ALL {
        assert!(
            seen.insert(s.label()),
            "two settlements render as `{}`, which is two consequences nothing can tell apart",
            s.label()
        );
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn the_declared_bound_admits_what_the_derivation_produces() {
    // The declared column is a CHECKED claim, not a second source of truth: every reason must admit
    // the settlements a refusal for it can actually reach.
    for &code in ReasonCode::ALL {
        let reason = RefusalReason::from(code);
        assert!(
            reason.settles_within(Settlement::NeverCharged),
            "{code}: every reason can be raised before a hold opens"
        );
        if !matches!(reason.settlement(), Settlement::NeverCharged) {
            assert!(reason.settles_within(Settlement::ChargedRefundable));
            assert!(reason.settles_within(Settlement::AdmittedUncharged));
        }
    }
}
