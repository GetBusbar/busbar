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
        vec![
            CostComponent::top("a", CostAmount(60)),
            CostComponent::top("b", CostAmount(30)),
        ],
    )
    .unwrap_err();
    assert_eq!(
        err,
        CostError::TopLevelSumMismatch {
            total: 100,
            top_level_sum: 90
        }
    );
}

#[test]
fn a_zero_component_is_rejected_so_breakdowns_stay_sparse() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![
            CostComponent::top("a", CostAmount(100)),
            CostComponent::top("cache", CostAmount(0)),
        ],
    )
    .unwrap_err();
    assert_eq!(
        err,
        CostError::ZeroComponent {
            label: "cache".into()
        }
    );
}

#[test]
fn duplicate_labels_are_rejected() {
    let err = CostBreakdown::new(
        CostAmount(100),
        vec![
            CostComponent::top("a", CostAmount(50)),
            CostComponent::top("a", CostAmount(50)),
        ],
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
        CostError::UnknownParent {
            label: "reasoning".into(),
            parent: "NoSuchLine".into()
        }
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

#[test]
fn cost_amount_addition_saturates_instead_of_wrapping() {
    // C1 regression: a hostile/huge breakdown or a long run of partial settles must NOT wrap the
    // u128 accumulator to ~0 (silent under-settlement in release, debug panic). Add + Sum saturate.
    let big = CostAmount(u128::MAX);
    assert_eq!(
        big + CostAmount(1),
        CostAmount(u128::MAX),
        "Add must saturate, not wrap to 0"
    );
    assert_eq!(big + big, CostAmount(u128::MAX));
    let summed: CostAmount = [big, CostAmount(1), big].into_iter().sum();
    assert_eq!(summed, CostAmount(u128::MAX), "Sum must saturate, not wrap");
}

/// Item 139: the "parts add up" invariant is checked with a CHECKED sum. Two top-level lines of
/// `u128::MAX` and `2` wrap, in a release build, to exactly `1` — so a raw `Sum` validated a
/// breakdown claiming a total of one nano-unit whose parts are astronomically larger (and panicked
/// in a debug build). An ill-formed breakdown is refused, never validated and never a panic.
#[test]
fn a_top_level_sum_that_overflows_is_refused_not_wrapped_onto_the_total() {
    let err = CostBreakdown::new(
        CostAmount(1),
        vec![
            CostComponent::top("a", CostAmount(u128::MAX)),
            CostComponent::top("b", CostAmount(2)),
        ],
    )
    .unwrap_err();
    assert_eq!(err, CostError::SumOverflow { parent: None });
}

/// The containment check sums a parent's children the same way, and refuses the same way: two
/// children that wrap to less than their parent must not pass as "contained".
#[test]
fn a_children_sum_that_overflows_is_refused_not_wrapped_under_the_parent() {
    let err = CostBreakdown::new(
        CostAmount(10),
        vec![
            CostComponent::top("p", CostAmount(10)),
            CostComponent::nested("x", CostAmount(u128::MAX), "p"),
            CostComponent::nested("y", CostAmount(3), "p"),
        ],
    )
    .unwrap_err();
    assert_eq!(
        err,
        CostError::SumOverflow {
            parent: Some("p".to_string())
        }
    );
}
