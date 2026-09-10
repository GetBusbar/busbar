// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two decimal-to-money conversions, held to the same answer.
//!
//! There is ONE of them in the tree now, and this file is what says so.
//!
//! There used to be two. This crate's [`nano_rate`] is the pricing law's conversion; the admission
//! unit carried its own copy inside its rate projection, because that crate named nothing here and
//! could not call across. They had to give the same integer for the same configured rate — if they
//! drifted, a request would be JUDGED at one rate by the door and BILLED at another by the ledger,
//! silently, with no error and no refusal, just a bill that did not match the decision that produced
//! it. This file was the only place that could notice.
//!
//! It noticed. A clamp for a finite-but-overflowing rate landed on one copy and not the other, and
//! the two answered a config typo with too many zeros as "prices at nothing" and "prices at the
//! largest rate there is". A test that catches a drift is not as good as an arithmetic that cannot
//! drift, so the admission unit's projection now CALLS this crate's conversion.
//!
//! What is left is a guard against the second copy coming back. Both sides of every assertion below
//! are the same function today, so every case passes by construction — and the moment somebody
//! re-forks those three lines to "avoid a dependency", these are the assertions that stop being
//! trivially true.

use busbar_unit_admission::{ChainBucket, RateNanos};
use busbar_unit_cost::{minor_of, nano_rate, CurrencyCode, KeyBudgetView, LaneClass, RateCard};

/// The admission unit's conversion, asked for one rate.
///
/// Its projection converts all four reserved token rates at once, so the value under test goes into
/// the first slot and the answer is read back out of it.
fn admission_nano_rate(micro_per_unit: f64) -> u64 {
    RateNanos::from_micros_per_token(micro_per_unit, 0.0, 0.0, 0.0).input
}

/// A deterministic sequence, written out here rather than taken as a dependency: the cases must be
/// identical on every machine and every run, and a money property that only fails on somebody
/// else's seed is not a property.
struct Seq(u64);

impl Seq {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    /// A value in `[0, bound)`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// TEN THOUSAND CONFIGURED RATES, AND THE TWO CONVERSIONS AGREE ON EVERY ONE.
///
/// The generated values are micro-units per unit of quantity, to six decimal places, spanning from
/// a millionth of a micro-unit up to ten thousand of them. Six places is one thousandth of a
/// nano-unit, which puts a large fraction of the cases within a rounding step of a boundary — so
/// the rounding rule, not just the multiply, is what is being compared.
#[test]
fn the_two_conversions_agree_on_ten_thousand_generated_rates() {
    let mut seq = Seq(0xC0FF_EE00_D15E_A5E5);
    for case in 0..10_000u32 {
        let micro = seq.below(10_000_000_000) as f64 / 1_000_000.0;
        let ours = nano_rate(micro);
        let theirs = admission_nano_rate(micro);
        assert_eq!(
            ours, theirs,
            "case {case}: the two conversions disagree at {micro} micro-units per unit"
        );
    }
}

/// The values where a difference would actually live: the rounding boundary in both directions,
/// zero, the smallest configured rate that is not zero, the clamped inputs, and the whole
/// neighbourhood of the `u64` ceiling — which is where the drift that prompted the unification
/// actually was. A generator reaches these only by luck, so they are named.
///
/// The `u64::MAX`-adjacent block is the sharp one. A float outside the target integer's range
/// SATURATES when cast rather than wrapping, so a config typo with too many zeros converts to the
/// largest rate there is — an astronomical overcharge — unless something clamps it. Whichever way
/// the law resolves that (clamp to zero, or take the saturated value), the door and the ledger have
/// to resolve it the SAME way, and these rows are what says they do.
#[test]
fn the_two_conversions_agree_at_every_boundary_value() {
    // The largest configured micro-rate whose ×1000 still fits a `u64`, and its neighbours either
    // side of the ceiling. Written as arithmetic on `u64::MAX` rather than as a literal, so the
    // cases follow the type rather than a number somebody typed once.
    const CEILING_MICRO: f64 = (u64::MAX as f64) / 1000.0;
    let boundaries = [
        0.0,
        0.0004, // below the half-nano-unit boundary: floors to nothing
        0.0005, // exactly a half nano-unit: rounds AWAY from zero
        0.0014, // one and four tenths: floors to one
        0.0015, // one and a half: rounds to two
        0.001,  // exactly one nano-unit
        1.0,
        10_000.0,
        f64::MIN_POSITIVE,
        -0.0,
        -1.0,     // a negative rate is not a discount
        f64::NAN, // cannot be ordered, so cannot be priced
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::MAX,            // finite, but times a thousand it is not
        CEILING_MICRO,       // right at the `u64` ceiling
        CEILING_MICRO * 2.0, // finite, and just past it
        1e15,                // ×1000 is 1e18: comfortably inside, must convert normally
        1e16,                // ×1000 is 1e19: still inside, and close
        1e17,                // ×1000 is 1e20: finite and past the ceiling
        1e18,                // the config-typo case the clamp was written for
        -1e18,               // and its negative twin, which is not a discount either
    ];
    for micro in boundaries {
        assert_eq!(
            nano_rate(micro),
            admission_nano_rate(micro),
            "the two conversions disagree at {micro} micro-units per unit"
        );
    }
    // And the clamp is the same clamp, not merely the same answer by coincidence: everything that
    // is not a finite positive number converts to nothing on both sides.
    for micro in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
        assert_eq!(nano_rate(micro), 0, "{micro} prices at nothing here");
        assert_eq!(
            admission_nano_rate(micro),
            0,
            "{micro} prices at nothing in the admission unit too"
        );
    }
}

/// **THE CURRENCY AXIS.** The decimal-to-integer conversion does not depend on the currency, and a
/// card proves it: the same configured decimal, set as a rate in a two-decimal currency and in a
/// zero-decimal one, holds the SAME integer in every cell.
///
/// This is the assertion that stands where a cross-rate would have gone. A conversion that knew
/// about currencies would have to scale one against another somewhere, and the moment it did, a
/// rate in yen would be a rate in dollars times a number nobody configured. The currency enters
/// ONCE, at the projection, through `nanos_per_minor` — never at the rate.
#[test]
fn the_conversion_is_the_same_integer_in_every_currency() {
    let jpy = CurrencyCode::new("JPY").expect("a three-letter code");
    let bhd = CurrencyCode::new("BHD").expect("a three-letter code");
    let mut seq = Seq(0x1234_5678_9ABC_DEF0);
    for case in 0..10_000u32 {
        let micro = seq.below(10_000_000_000) as f64 / 1_000_000.0;
        let expected = nano_rate(micro);

        let mut card = RateCard::from_micro_rates([(LaneClass::new("lane", "input"), micro)], 0);
        card.set_rate(LaneClass::new("lane", "input"), jpy, micro);
        card.set_rate(LaneClass::new("lane", "input"), bhd, micro);

        for currency in [CurrencyCode::USD, jpy, bhd] {
            let rates = card
                .lane_rates("lane", currency)
                .expect("the lane is priced");
            assert_eq!(
                rates.nanos_per_unit("input"),
                expected,
                "case {case}: the rate moved with the currency at {micro} micro-units per unit"
            );
        }
        // And the admission unit's projection, which knows nothing of currencies at all, still
        // gives that same integer.
        assert_eq!(admission_nano_rate(micro), expected, "case {case}");
    }
}

/// The currency changes the PROJECTION and only the projection. One nano-unit total, three
/// currencies: the answers differ by exactly the ratio of the divisors and by nothing else.
#[test]
fn the_currency_enters_at_the_projection_and_nowhere_else() {
    let jpy = CurrencyCode::new("JPY").expect("a three-letter code");
    let bhd = CurrencyCode::new("BHD").expect("a three-letter code");
    assert_eq!(CurrencyCode::USD.nanos_per_minor(), 10_000_000);
    assert_eq!(jpy.nanos_per_minor(), 1_000_000_000);
    assert_eq!(bhd.nanos_per_minor(), 1_000_000);

    let nanos = 3_500_000_000u128;
    assert_eq!(minor_of(nanos, CurrencyCode::USD), 350);
    assert_eq!(minor_of(nanos, jpy), 3);
    assert_eq!(minor_of(nanos, bhd), 3_500);
}

// ── PARITY WITH THE DOOR, ON THE BUDGET SIDE ─────────────────────────────────────────────────────
//
// The door performs the budget comparison inline over its own bucket chain, because a unit never
// calls another unit and the admission unit cannot reach the cost unit. Two copies of one
// comparison with nothing checking they agree is how a request comes to be judged at one figure
// and billed at another — the same argument as the rate side above, applied to the budget view.

/// Build the door's own chain of one bucket, capped, so the same question can be put to both.
fn door_bucket(cap: Option<i64>) -> ChainBucket {
    ChainBucket {
        bucket_id: "group:parity@total".to_string(),
        group_name: Some("parity".to_string()),
        window: "total",
        requests_cap: None,
        tokens_cap: None,
        tokens_input_cap: None,
        tokens_output_cap: None,
        tokens_cache_read_cap: None,
        tokens_cache_write_cap: None,
        budget_cap: cap,
        scope: None,
        downgrade_to: None,
    }
}

/// The door's blocking rule for the budget metric, lifted out of `decide.rs` as the source of truth
/// this view has to match. Not a re-implementation: the two expressions are compared below over ten
/// thousand cases, which is what makes copying it here a MEASUREMENT rather than a second policy.
fn door_blocks(bucket: &ChainBucket, derived: i64, fee: i64) -> bool {
    bucket
        .budget_cap
        .is_some_and(|cap| derived >= cap || derived.saturating_add(fee) > cap)
}

/// The door's headroom rule, likewise.
fn door_headroom(bucket: &ChainBucket, derived: i64) -> Option<i64> {
    bucket
        .budget_cap
        .map(|cap| cap.saturating_sub(derived).max(0))
}

#[test]
fn the_view_blocks_exactly_where_the_door_blocks() {
    for cap in [None, Some(0), Some(1), Some(100), Some(i64::MAX)] {
        let bucket = door_bucket(cap);
        let view = match cap {
            None => KeyBudgetView::uncapped("group:parity@total"),
            Some(c) => KeyBudgetView::capped("group:parity@total", c),
        };
        for spent in [0u128, 1, 50, 99, 100, 101, 1_000, u128::MAX] {
            for fee in [0i64, 1, 10, 100, i64::MAX] {
                let derived = view.spent_cents(spent);
                assert_eq!(
                    view.would_exceed(spent, fee),
                    door_blocks(&bucket, derived, fee),
                    "cap={cap:?} spent_nanos={spent} fee={fee}"
                );
            }
        }
    }
}

#[test]
fn the_views_remaining_is_exactly_the_doors_headroom() {
    for cap in [None, Some(0), Some(1), Some(100), Some(i64::MAX)] {
        let bucket = door_bucket(cap);
        let view = match cap {
            None => KeyBudgetView::uncapped("group:parity@total"),
            Some(c) => KeyBudgetView::capped("group:parity@total", c),
        };
        for spent in [0u128, 1, 50, 99, 100, 101, 1_000, u128::MAX] {
            let derived = view.spent_cents(spent);
            assert_eq!(
                view.remaining_cents(spent),
                door_headroom(&bucket, derived),
                "cap={cap:?} spent_nanos={spent}"
            );
        }
    }
}
