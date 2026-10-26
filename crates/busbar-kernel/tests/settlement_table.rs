// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement WRITER, row by row, and the two quantity rules beside it (TD step 13,
//! re-baselined from the old settlement table).
//!
//! THE PLANE REPORTS; THE KERNEL WRITES (`BUSBAR-1.6.0.md` §7, #77(2)). The kernel
//! decides no figure and no fee: whatever the end, it writes what the plane reported, adds no
//! floor, and resolves no disagreement. There is no unit brought back from a journal any more: the
//! one ledger is the store's usage counts (MONEY-DESIGN §4, PR-C).

use busbar_contract::caps::OriginKind;
use busbar_contract::caps::{Outcome, PostingFlags, ReasonCode, StepName};
use busbar_kernel::teller::{requests_drawn, requests_settled, settle_written, Evidence, Written};

fn ends() -> [Outcome; 4] {
    [
        Outcome::Completed,
        Outcome::Failed(StepName::Route, ReasonCode::ClientGone),
        Outcome::Failed(StepName::Route, ReasonCode::OverBudget),
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
    ]
}

fn written(end: &Outcome, evidence: &Evidence) -> (u64, PostingFlags) {
    let Written { amount, flags, .. } = settle_written(end, evidence);
    (amount, flags)
}

#[test]
fn a_reported_figure_is_written_as_told_on_every_end() {
    // A cut bills what streamed (#62), an error end bills what the plane reported of it: no end
    // lowers, zeroes or raises the plane's figure.
    let evidence = Evidence {
        reported: Some(4_200),
        ..Evidence::default()
    };
    for end in ends() {
        assert_eq!(
            written(&end, &evidence),
            (4_200, PostingFlags::NONE),
            "{end:?}"
        );
    }
}

#[test]
fn a_completed_unit_that_reported_nothing_writes_zero_unmarked() {
    assert_eq!(
        written(&Outcome::Completed, &Evidence::default()),
        (0, PostingFlags::NONE)
    );
}

#[test]
fn an_unfinished_unit_that_reported_nothing_writes_zero_marked_estimated_and_no_floor() {
    for end in ends().into_iter().skip(1) {
        assert_eq!(
            written(&end, &Evidence::default()),
            (0, PostingFlags::ESTIMATED),
            "{end:?}: the kernel adds no floor (BUSBAR-1.6.0.md §7)"
        );
    }
}

#[test]
fn the_fee_units_are_the_planes_as_told_on_every_end() {
    // The kernel decides no fee (TD step 13: the kernel fee decider is deleted); it writes the fee
    // units the plane reported, whatever the end, and never invents one.
    for fee_units in [0u32, 1, 3] {
        let evidence = Evidence {
            fee_units,
            ..Evidence::default()
        };
        for end in ends() {
            assert_eq!(settle_written(&end, &evidence).fee, fee_units, "{end:?}");
        }
    }
}

#[test]
fn no_row_ever_resolves_upward() {
    // Whatever the evidence, the amount written is never more than what the plane reported.
    let cases = [
        Evidence {
            reported: Some(100),
            ..Evidence::default()
        },
        Evidence::default(),
    ];
    for evidence in cases {
        for end in ends() {
            let (amount, _) = written(&end, &evidence);
            let highest = evidence.reported.unwrap_or(0);
            assert!(amount <= highest, "{evidence:?} at {end:?} wrote {amount}");
        }
    }
}

// ── the request slot ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_client_unit_with_an_upstream_draws_one_slot_and_never_gets_it_back() {
    let drawn = requests_drawn(OriginKind::Client, true);
    assert_eq!(drawn, 1);
    // Whatever the end, a unit that reached the door keeps the slot: failures cannot escape a cap.
    assert_eq!(requests_settled(true, drawn), 1);
    // A unit refused before the door drew nothing.
    assert_eq!(requests_settled(false, drawn), 0);
}

#[test]
fn a_provider_push_and_a_unit_with_no_upstream_draw_no_slot() {
    assert_eq!(requests_drawn(OriginKind::Provider, true), 0);
    assert_eq!(requests_drawn(OriginKind::Client, false), 0);
    assert_eq!(requests_drawn(OriginKind::Tick, true), 0);
}
