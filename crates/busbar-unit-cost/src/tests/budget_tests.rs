// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The budget comparison, and the proof that moving it here did not move it.**
//!
//! The door compared `spent >= cap || spent + fee > cap` and read `cap - spent` separately for the
//! headroom. Both are now one subtraction here. That is a rearrangement of a money comparison, which
//! is the class of change that decides who gets a 429, so it is proved rather than asserted: the
//! tag's predicate is written out verbatim below and the two are asked the same question over the
//! whole interesting domain — every boundary, both saturation edges, and ten thousand generated
//! triples.

use crate::{budget_remaining_cents, over_budget, spend_total_cents};

/// The predicate exactly as the door spelled it, transcribed from
/// `busbar-unit-admission/src/decide.rs` at the tag. Nothing here may be simplified: it is the
/// reference, and a reference that had been tidied would be proving the tidying rather than the
/// move.
fn the_tags_predicate(cap: i64, derived: i64, fee: i64) -> bool {
    derived >= cap || derived.saturating_add(fee) > cap
}

/// The headroom exactly as the door spelled it.
fn the_tags_headroom(cap: i64, derived: i64) -> i64 {
    cap.saturating_sub(derived).max(0)
}

/// A deterministic generator: no dependency, and the same ten thousand cases on every machine and
/// in every run, which is what makes a failure reproducible from the seed alone.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[test]
fn the_rearranged_comparison_answers_the_tags_question_at_every_boundary() {
    // Around a hundred-cent cap, with the fee at each of the sizes that changes the answer.
    for cap in [0i64, 1, 2, 99, 100, 101, i64::MAX - 1, i64::MAX] {
        for spent in [0i64, 1, 99, 100, 101, i64::MAX - 1, i64::MAX] {
            for fee in [0i64, 1, 2, 100, i64::MAX] {
                assert_eq!(
                    over_budget(cap, spent, fee),
                    the_tags_predicate(cap, spent, fee),
                    "cap {cap}, spent {spent}, fee {fee}"
                );
                assert_eq!(
                    budget_remaining_cents(cap, spent),
                    the_tags_headroom(cap, spent),
                    "headroom at cap {cap}, spent {spent}"
                );
            }
        }
    }
}

#[test]
fn the_two_agree_on_ten_thousand_generated_triples() {
    let mut state = 0x5EED_1234_5678_9ABC_u64;
    for _ in 0..10_000 {
        // Non-negative, because a cap, a derived spend and a fee are all clamped non-negative
        // before they reach the comparison — the pricer clamps the fee at resolve, the derivation
        // floors at zero, and a configured cap comes through `i64::try_from` on a `u64`.
        let cap = (splitmix(&mut state) >> 1) as i64;
        let spent = (splitmix(&mut state) >> 1) as i64;
        let fee = (splitmix(&mut state) >> 33) as i64;
        assert_eq!(
            over_budget(cap, spent, fee),
            the_tags_predicate(cap, spent, fee),
            "cap {cap}, spent {spent}, fee {fee}"
        );
        assert_eq!(
            budget_remaining_cents(cap, spent),
            the_tags_headroom(cap, spent)
        );
    }
}

#[test]
fn the_subtraction_form_of_the_comparison_is_not_the_tags_and_that_is_why_it_is_not_used() {
    // The measurement behind [`over_budget`]'s doc comment. The obvious rearrangement — compare the
    // fee against the headroom — is not the same predicate, and the case it differs on is a request
    // the shipped binary admits.
    let subtraction_form = |cap: i64, spent: i64, fee: i64| {
        budget_remaining_cents(cap, spent) <= 0 || fee > budget_remaining_cents(cap, spent)
    };
    assert!(
        !over_budget(i64::MAX, 1, i64::MAX),
        "the tag admits here, because its saturating add pins at the cap rather than above it"
    );
    assert!(
        subtraction_form(i64::MAX, 1, i64::MAX),
        "and the rearrangement refuses, which is a money decision moved by a rearrangement"
    );
}

#[test]
fn the_fee_lookahead_is_the_second_arm_and_it_is_not_optional() {
    // A bucket under its cap that the fee alone would put over. Drop this arm and the bucket is
    // over budget by exactly one fee for the rest of the window.
    assert!(
        !over_budget(100, 90, 10),
        "ten cents left covers a ten-cent fee"
    );
    assert!(over_budget(100, 90, 11), "eleven does not");
    assert!(
        over_budget(100, 100, 0),
        "at the cap is over, fee or no fee"
    );
    assert!(!over_budget(100, 99, 0), "and one cent under is not");
}

#[test]
fn the_spend_a_comparison_reads_saturates_rather_than_wrapping_into_free() {
    assert_eq!(spend_total_cents(0, 0), 0);
    assert_eq!(spend_total_cents(90, 10), 100, "carried plus accrued");
    assert_eq!(
        spend_total_cents(i64::MAX, i64::MAX),
        i64::MAX,
        "two maximal figures pin at the top; wrapped, they would land negative and read as FREE"
    );
    assert!(
        over_budget(i64::MAX, spend_total_cents(i64::MAX, i64::MAX), 0),
        "and a saturated spend is over every cap there is"
    );
    assert_eq!(
        spend_total_cents(-5, 2),
        0,
        "and the floor holds, so no arrangement of the inputs credits a bucket"
    );
}

#[test]
fn the_headroom_never_goes_negative_however_far_over_the_cap_the_spend_is() {
    assert_eq!(budget_remaining_cents(100, 140), 0);
    assert_eq!(budget_remaining_cents(0, i64::MAX), 0);
    assert_eq!(
        budget_remaining_cents(i64::MIN, 1),
        0,
        "and the subtraction saturates rather than overflowing"
    );
}
