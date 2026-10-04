// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause two, three and five: what a posting stores, how it projects, and the tier multiplier.

use crate::cost::{apply_tier, apply_tier_signed, checked_apply_tier, STANDARD_TIER_BP};

/// **THE NEUTRAL TIER IS THE IDENTITY, AT EVERY MAGNITUDE INCLUDING THE CEILING.**
///
/// This cell used to read `assert_eq!(apply_tier(u128::MAX, 20_000), u128::MAX / 10_000)` and
/// called that saturation. It was not saturation, it was the defect written down as an
/// expectation: `saturating_mul` pinned the PRODUCT at `u128::MAX` and the divide by ten thousand
/// then shrank it, so the function returned one ten-thousandth of the true amount and a test
/// asserted that it should.
///
/// The row below it is why that mattered rather than being a curiosity at an unreachable input.
/// `tier_bp` is `STANDARD_TIER_BP` on EVERY production path in this tree (`plane_node.rs` pins it
/// on the posting, `policy.rs` pins it on the group, and both defaults resolve to it), so ×1 is
/// the only tier the arithmetic is ever actually asked for — and ×1 at the ceiling was returning
/// `34028236692093846346337460743176821` in place of
/// `340282366920938463463374607431768211455`. A bill of `u128::MAX` was derived as ten thousand
/// times less than itself.
#[test]
fn the_neutral_tier_is_the_identity_at_every_magnitude() {
    assert_eq!(
        apply_tier(u128::MAX, STANDARD_TIER_BP),
        u128::MAX,
        "x1 at the ceiling must return the ceiling, not one ten-thousandth of it"
    );
    assert_eq!(apply_tier(12_345, STANDARD_TIER_BP), 12_345);
    assert_eq!(apply_tier(0, STANDARD_TIER_BP), 0);
    assert_eq!(apply_tier(1, STANDARD_TIER_BP), 1);
}

/// A tiered amount that genuinely does not fit pins at the ceiling; one that does is exact.
///
/// The distinction the old spelling could not make: `u128::MAX` at double price really is past the
/// type, so `u128::MAX` is the honest narrowing of it — but `u128::MAX` at ×1 is not past anything
/// and must come back whole.
#[test]
fn only_a_genuinely_unrepresentable_tiered_amount_pins_at_the_ceiling() {
    assert_eq!(apply_tier(u128::MAX, 20_000), u128::MAX);
    assert_eq!(checked_apply_tier(u128::MAX, 20_000), None);
    assert_eq!(
        checked_apply_tier(u128::MAX, STANDARD_TIER_BP),
        Some(u128::MAX)
    );
    assert_eq!(apply_tier(0, 20_000), 0);
    // Half the ceiling at double price is exactly the ceiling plus one, which is the first value
    // that does not fit — the boundary stated as arithmetic rather than as a literal.
    assert_eq!(checked_apply_tier((u128::MAX / 2) + 1, 20_000), None);
    assert_eq!(
        checked_apply_tier(u128::MAX / 2, 20_000),
        Some(u128::MAX - 1)
    );
}

/// **#44 (`BUSBAR-1.6.0.md:372`) AT THE EXACT HALF, IN BOTH SIGNS.**
///
/// *"only a 'per-N-units' division term uses banker's (half-to-even) rounding"*, restated by #81
/// (`:428`): *"a per-N-units division term still uses banker's rounding (#44), because a DIVISION
/// can genuinely be inexact where a MEASUREMENT cannot."* `× tier_bp / 10_000` is that term.
///
/// The five tier implementations this tree carried truncated toward zero (four of them) or rounded
/// up (one), and not one of them was banker's. Truncation is not rounding: it is a discount the
/// operator never configured, taken in one direction, on every posting, forever.
///
/// Both signs, because a reversal is a negative amount and a rule that is not symmetric about zero
/// would let a correction be worth more or less depending on which side of the book it is written
/// on. Half-to-even is symmetric: `2.5 -> 2` and `-2.5 -> -2`.
#[test]
fn a_tier_that_lands_on_an_exact_half_rounds_to_even_in_both_signs() {
    // 5 x 5,000bp = 2.5 exactly. 2 is even, so DOWN. (Truncation agreed here by luck.)
    assert_eq!(apply_tier(5, 5_000), 2);
    assert_eq!(apply_tier_signed(-5, 5_000), -2);
    // 15 x 5,000bp = 7.5 exactly. 7 is odd, so UP to 8. (Truncation billed 7.)
    assert_eq!(apply_tier(15, 5_000), 8);
    assert_eq!(apply_tier_signed(-15, 5_000), -8);
    // 25 x 5,000bp = 12.5 exactly. 12 is even, so DOWN.
    assert_eq!(apply_tier(25, 5_000), 12);
    assert_eq!(apply_tier_signed(-25, 5_000), -12);
    // 3 x 5,000bp = 1.5 exactly. 1 is odd, so UP to 2. (Truncation billed 1.)
    assert_eq!(apply_tier(3, 5_000), 2);
    assert_eq!(apply_tier_signed(-3, 5_000), -2);

    // AND THE TIE IS THE ONLY PLACE THE EVEN RULE APPLIES. Either side of it goes to the nearer
    // neighbour regardless of parity, which is what distinguishes banker's from "always down to
    // even".
    assert_eq!(apply_tier(14, 5_000), 7, "7.0 exactly: nothing to round");
    assert_eq!(apply_tier(16, 5_000), 8, "8.0 exactly: nothing to round");
    assert_eq!(apply_tier(1, 9_999), 1, "0.9999 rounds to the nearer 1");
    assert_eq!(apply_tier(1, 4_999), 0, "0.4999 rounds to the nearer 0");
    assert_eq!(apply_tier(1, 5_000), 0, "0.5 exactly: 0 is even");
    assert_eq!(apply_tier(3, 5_001), 2, "1.5003 rounds to the nearer 2");
}

/// **HALF-AWAY-FROM-ZERO IS THE OTHER RULE IN #44, AND IT IS NOT THIS ONE.**
///
/// #44 (`:372`) carries two rounding rules in one sentence and they apply to different terms:
/// *"only a 'per-N-units' division term uses banker's (half-to-even) rounding; card-build-time
/// quantization stays half-away-from-zero (byte-identity)"*. Card-build quantisation is
/// [`crate::cost::nano_rate`], once, at the boundary where an operator's configured decimal becomes
/// an integer rate. The tier is not that term, and at a tie the two rules give different money —
/// which is exactly why the row names them separately.
///
/// Written as a test rather than a comment so that a future reader who reaches for the wrong half
/// of the row gets a NO instead of a plausible-looking diff.
#[test]
fn the_tier_does_not_use_the_card_builds_rounding_rule() {
    // At 7.5, half-away-from-zero gives 8 and half-to-even gives 8 too: agreement, not evidence.
    assert_eq!(apply_tier(15, 5_000), 8);
    // At 2.5 they part: half-away-from-zero gives 3, half-to-even gives 2. The tier gives 2.
    assert_eq!(
        apply_tier(5, 5_000),
        2,
        "not 3 — the tier is not card-build quantisation"
    );
    assert_eq!(apply_tier(25, 5_000), 12, "not 13");
    assert_eq!(apply_tier(45, 5_000), 22, "not 23");
}

/// **BYTE-NEUTRALITY AT THE ONLY TIER THIS TREE EVER ASKS FOR.**
///
/// `tier_bp` is [`STANDARD_TIER_BP`] on every production path: the live LLM posting pins it
/// (`crates/busbar/src/root/plane_node.rs`, `Posting::from_usage(.., STANDARD_TIER_BP, ..)`), the
/// group runtime pins it (`crates/busbar/src/root/policy.rs`), a `LedgerEntry` defaults to it, and
/// the recompute archive's `tier_bp` defaults to it. No operator configuration key sets a
/// basis-point multiplier at all — `config/pools.rs`'s `tier` is a routing LABEL (`"large"`), not a
/// price.
///
/// So this is the sweep that says the rounding correction moved no byte anybody can observe: over
/// the whole ordinary range, at the tier every posting actually carries, the answer is the input,
/// which is what the previous implementation also gave. Zero differences.
///
/// The rounding rule only becomes visible at a tier that is not ×1, and a tier that is not ×1 is
/// unreachable from any configuration this tree parses.
#[test]
fn the_neutral_tier_moves_no_ordinary_amount() {
    // A deterministic spread across every magnitude a book reaches, plus the exact powers of ten
    // either side of each one, so the sweep lands on and beside every rounding step.
    let mut cases: Vec<u128> = Vec::new();
    let mut decade: u128 = 1;
    for _ in 0..34 {
        for near in [0u128, 1, 2, 4_999, 5_000, 5_001, 9_999] {
            cases.push(decade.saturating_add(near));
            cases.push(decade.saturating_sub(near));
        }
        decade = decade.saturating_mul(10);
    }
    cases.push(0);
    cases.push(u128::from(u64::MAX));
    cases.push(u128::from(u64::MAX) * 4);

    let mut checked = 0u32;
    for &pre in &cases {
        assert_eq!(
            apply_tier(pre, STANDARD_TIER_BP),
            pre,
            "x1 moved an ordinary amount: {pre}"
        );
        // And the previous implementation's answer, computed here, is the same one — for every
        // amount whose ×10,000 stayed inside the type, which is every amount below about 3.4e34.
        if pre < u128::MAX / 10_000 {
            assert_eq!(
                pre.saturating_mul(10_000) / 10_000,
                apply_tier(pre, STANDARD_TIER_BP),
                "the correction moved a byte at {pre}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 479, "the sweep must actually have run");
}
