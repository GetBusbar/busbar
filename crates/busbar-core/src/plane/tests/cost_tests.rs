// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the neutral itemized cost breakdown. The load-bearing property is "the parts add up":
//! a breakdown whose top-level components do not sum to the total cannot be constructed.

use super::*;

/// The owner-supplied worked example (Claude Haiku, first turn) constructs and reports its split.
#[test]
fn owner_haiku_example_constructs_and_the_parts_add_up() {
    // 0.0078345 USD == 7_834_500 nanodollars, split into three top-level lines.
    let b = CostBreakdown::new(
        CostAmount(7_834_500),
        vec![
            CostComponent::top("Prompt", CostAmount(12_000)),
            CostComponent::top("Cache write", CostAmount(7_802_500)),
            CostComponent::top("Output", CostAmount(20_000)),
        ],
    )
    .expect("well-formed breakdown");

    assert_eq!(b.total(), CostAmount(7_834_500));
    let top: Vec<_> = b.top_level().map(|c| c.label.as_str()).collect();
    assert_eq!(top, ["Prompt", "Cache write", "Output"]);
    // Prompt + cache write + output == total, structurally.
    let sum: u128 = b.top_level().map(|c| c.amount.0).sum();
    assert_eq!(sum, b.total().0);
}

#[test]
fn top_level_components_must_sum_to_total() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![CostComponent::top("a", CostAmount(60)), CostComponent::top("b", CostAmount(30))],
    )
    .unwrap_err();
    assert_eq!(err, CostError::TopLevelSumMismatch { total: 100, top_level_sum: 90 });
}

#[test]
fn a_zero_component_is_rejected_so_breakdowns_stay_sparse() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![CostComponent::top("a", CostAmount(100)), CostComponent::top("cache", CostAmount(0))],
    )
    .unwrap_err();
    assert_eq!(err, CostError::ZeroComponent { label: "cache".into() });
}

#[test]
fn duplicate_labels_are_rejected() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![CostComponent::top("a", CostAmount(50)), CostComponent::top("a", CostAmount(50))],
    )
    .unwrap_err();
    assert_eq!(err, CostError::DuplicateLabel { label: "a".into() });
}

/// Reasoning nests under output: it does NOT add a fourth top-level line, and the top-level lines
/// still sum to the total.
#[test]
fn a_nested_child_does_not_add_to_the_total() {
    let b = CostBreakdown::new(
        CostAmount(100),
        vec![
            CostComponent::top("Prompt", CostAmount(30)),
            CostComponent::top("Output", CostAmount(70)),
            // reasoning is inside output; 40 <= 70 and does not push the total past 100.
            CostComponent::nested("reasoning", CostAmount(40), "Output"),
        ],
    )
    .expect("nested child is contained");
    assert_eq!(b.total(), CostAmount(100));
    assert_eq!(b.top_level().count(), 2);
}

#[test]
fn a_child_naming_a_missing_parent_is_rejected() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![
            CostComponent::top("Output", CostAmount(100)),
            CostComponent::nested("reasoning", CostAmount(10), "NoSuchLine"),
        ],
    )
    .unwrap_err();
    assert_eq!(
        err,
        CostError::UnknownParent { label: "reasoning".into(), parent: "NoSuchLine".into() }
    );
}

#[test]
fn children_cannot_exceed_their_parent() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![
            CostComponent::top("Output", CostAmount(70)),
            CostComponent::top("Prompt", CostAmount(30)),
            CostComponent::nested("reasoning", CostAmount(90), "Output"),
        ],
    )
    .unwrap_err();
    assert_eq!(
        err,
        CostError::ChildrenExceedParent {
            parent: "Output".into(),
            parent_amount: 70,
            children_sum: 90,
        }
    );
}

// ── CostHold: reserve → settle → refund ─────────────────────────────────────────────────────────

/// Helper: a single-line breakdown of `n` nanodollars.
fn charge(n: u128) -> CostBreakdown {
    CostBreakdown::new(CostAmount(n), vec![CostComponent::top("charge", CostAmount(n))]).unwrap()
}

#[test]
fn reserve_folds_the_flat_fee_in_once() {
    let h = CostHold::reserve(CostAmount(1_000), CostAmount(50));
    assert_eq!(h.reserved(), CostAmount(1_050));
}

#[test]
fn finalize_ledgers_the_exact_settled_sum_and_refunds_the_unspent_reserve() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0));
    h.settle_partial(&charge(300));
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(300)); // the EXACT charge, not the reserve
    assert_eq!(s.refund, CostAmount(700)); // reserved 1000 − settled 300
}

#[test]
fn streamed_partials_accumulate_to_the_true_charge() {
    let mut h = CostHold::reserve(CostAmount(1_000), CostAmount(0));
    h.settle_partial(&charge(120));
    h.settle_partial(&charge(80));
    h.settle_partial(&charge(50));
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(250));
    assert_eq!(s.refund, CostAmount(750));
}

#[test]
fn an_over_settle_ledgers_the_true_amount_and_refunds_zero_never_negative() {
    let mut h = CostHold::reserve(CostAmount(100), CostAmount(0));
    h.settle_partial(&charge(250)); // the coarse estimate was low
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(250));
    assert_eq!(s.refund, CostAmount(0));
}

#[test]
fn a_hold_never_settled_refunds_the_whole_reserve() {
    let h = CostHold::reserve(CostAmount(500), CostAmount(25));
    let s = h.finalize();
    assert_eq!(s.ledgered_total, CostAmount(0));
    assert_eq!(s.refund, CostAmount(525));
}
