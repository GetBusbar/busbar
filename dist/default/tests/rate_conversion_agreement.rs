// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two decimal-to-money conversions, held to the same answer.
//!
//! There is ONE of them in the tree now, and this file is what says so.
//!
//! There used to be two. The ledger's [`nano_rate`] is the pricing law's conversion; the admission
//! door carried its own copy inside its rate projection, because its crate named nothing there and
//! could not call across. They had to give the same integer for the same configured rate — if they
//! drifted, a request would be JUDGED at one rate by the door and BILLED at another by the ledger,
//! silently, with no error and no refusal, just a bill that did not match the decision that produced
//! it. This file was the only place that could notice.
//!
//! It noticed. A clamp for a finite-but-overflowing rate landed on one copy and not the other, and
//! the two answered a config typo with too many zeros as "prices at nothing" and "prices at the
//! largest rate there is". A test that catches a drift is not as good as an arithmetic that cannot
//! drift, so the live door reads the rate the CONFIG INTAKE converted once
//! (`RateEntryCfg::raw_tier_rates`, which calls the ledger's conversion), and `RateNanos::from_raw`
//! copies those integers — no float crosses into it at all (#81).
//!
//! What is left is a guard against the second copy coming back. Both sides of every assertion below
//! are the same function today — and the moment somebody re-forks those three lines to "avoid a
//! dependency", these are the assertions that stop being trivially true.
//!
//! **AND THAT IS WHY AGREEMENT IS NO LONGER THE ONLY THING ASSERTED HERE.** "Both sides are the
//! same function today" also means every agreement-only row passes BY CONSTRUCTION, whatever the
//! function does — including when it does the wrong thing. That is not a hypothetical: this file
//! defined `CEILING_MICRO` as `(u64::MAX as f64) / 1000.0`, fed it to both readers, and reported
//! green while the conversion returned `u64::MAX` nano-units for it. The input was the defect and
//! the row still passed, because two copies of one guard agree on a wrong answer exactly as
//! readily as on a right one. An instrument that cannot produce a NO is not a check.
//!
//! So every boundary row now names the integer it expects, derived from the conversion rule rather
//! than read off the implementation, and the agreement assertion rides alongside it as the
//! second-copy tripwire it was always meant to be.

use busbar_kernel::config::RateEntryCfg;
use busbar_kernel::cost::RateNanos;
use busbar_kernel_ledger::cost::{nano_rate, LaneClass, Money, RateCard, NANOS_PER_CENT};

/// The live door's rate, asked for one configured figure: the config intake
/// (`RateEntryCfg::raw_tier_rates`) and then the kernel's `RateNanos` projection of what it carried.
///
/// The intake converts all four reserved token rates at once, so the value under test goes into
/// the first slot and the answer is read back out of it.
fn admission_nano_rate(micro_per_unit: f64) -> u64 {
    RateNanos::from_cfg(&RateEntryCfg {
        input_utok: micro_per_unit,
        ..RateEntryCfg::default()
    })
    .input
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

/// **EVERY BOUNDARY VALUE CONVERTS TO THE INTEGER NAMED HERE** — and, separately, the two readers
/// agree on it.
///
/// THE ORDER OF THOSE TWO CLAUSES IS THE POINT, and it is a correction. This cell used to assert
/// ONLY `nano_rate(micro) == admission_nano_rate(micro)`, and its prose declined to settle the
/// value: *"Whichever way the law resolves that (clamp to zero, or take the saturated value), the
/// door and the ledger have to resolve it the SAME way."* That is not a check. Both sides are the
/// same function today — the kernel's projection CALLS `nano_rate` — so an agreement-only
/// row cannot return a NO no matter what the function does, and when the conversion did the wrong
/// thing at `CEILING_MICRO` below, this row passed. An instrument that cannot produce a NO is not an
/// instrument. So the expected integer is written down, and the agreement assertion stays where it
/// is useful: as the tripwire for a second copy of those three lines coming back.
///
/// The expected column is derived from the rule, not read off the implementation: multiply the
/// configured DECIMAL by a thousand, exactly, and take it only if it is a positive whole number of
/// nano-units that fits a `u64` (#81: no binary float on the money path). A rate with any digit past
/// the third decimal is NOT rounded — not up, not down, not to 1.5.5's figure — it is a rate the
/// card cannot hold, and it converts to nothing here and is refused at boot.
///
/// THE CEILING IS AN INTEGER ONE. The conversion used to cast a float, and `u64::MAX as f64` rounds
/// UP to `2^64`, so a guard spelled against it let a cast SATURATE to `u64::MAX` — an astronomical
/// overcharge from a config typo. The conversion is a checked integer multiply now: the last
/// configured rate whose nano-units fit converts exactly, and the next one prices at nothing.
#[test]
fn every_boundary_value_converts_to_its_named_integer_and_both_readers_agree() {
    let cases: [(f64, u64, &str); 25] = [
        (0.0, 0, "zero is not a rate"),
        (
            0.0004,
            0,
            "four tenths of a nano-unit: refused, never rounded",
        ),
        (
            0.0005,
            0,
            "half a nano-unit: refused, never rounded up to one",
        ),
        (
            0.0014,
            0,
            "one and four tenths: refused, never rounded to one",
        ),
        (0.0015, 0, "one and a half: refused, never rounded to two"),
        (0.001, 1, "exactly one nano-unit"),
        (1.0, 1_000, "one micro-unit is a thousand nano-units"),
        (
            0.5005,
            0,
            "500.5 nano-units: neither 1.5.5's float-rounded 500 nor a half-away 501 — refused",
        ),
        (0.3, 300, "a three-decimal rate is exactly its nano-units"),
        (
            10_000.0,
            10_000_000,
            "ten thousand micro-units, converted flat",
        ),
        (
            f64::MIN_POSITIVE,
            0,
            "the smallest positive f64 rounds to nothing",
        ),
        (-0.0, 0, "negative zero is still not a rate"),
        (-1.0, 0, "a negative rate is not a discount"),
        (f64::NAN, 0, "cannot be ordered, so cannot be priced"),
        (f64::INFINITY, 0, "not finite"),
        (f64::NEG_INFINITY, 0, "not finite and not positive"),
        (f64::MAX, 0, "finite, but times a thousand it is not"),
        (
            18_446_744_073_709_548.0,
            18_446_744_073_709_548_000,
            "the last rate under the ceiling converts EXACTLY (the float product was …547_520)",
        ),
        (
            18_446_744_073_709_556.0,
            0,
            "one past what a u64 of nano-units holds: nothing, never u64::MAX",
        ),
        (
            1e15,
            1_000_000_000_000_000_000,
            "x1000 is 1e18: comfortably inside",
        ),
        (
            1e16,
            10_000_000_000_000_000_000,
            "x1000 is 1e19: still inside, and close — the largest decade that converts",
        ),
        (1e17, 0, "x1000 is 1e20: finite and past the ceiling"),
        (1e18, 0, "the config-typo case the clamp was written for"),
        (
            -1e18,
            0,
            "and its negative twin, which is not a discount either",
        ),
        (
            1e12,
            1_000_000_000_000_000,
            "an ordinary large rate, unmoved",
        ),
    ];

    for (micro, expected, why) in cases {
        // THE VALUE FIRST. This is the assertion that can fail when both readers are wrong together.
        assert_eq!(
            nano_rate(micro),
            expected,
            "{micro:e} micro-units per unit must convert to {expected} nano-units — {why}"
        );
        // AND THEN AGREEMENT, which guards against a second copy of the conversion returning.
        assert_eq!(
            admission_nano_rate(micro),
            expected,
            "the kernel's projection converted {micro:e} to something other than {expected} — a second \
             copy of the conversion has come back"
        );
    }

    // And the clamp is the same clamp, not merely the same answer by coincidence: everything that
    // is not a finite positive number converts to nothing on both sides.
    for micro in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
        assert_eq!(nano_rate(micro), 0, "{micro} prices at nothing here");
        assert_eq!(
            admission_nano_rate(micro),
            0,
            "{micro} prices at nothing in the kernel's projection too"
        );
    }
}

/// **THE CARD HOLDS THE INTEGER THE CONVERSION GAVE IT, AND NOTHING RESCALES IT.** A configured
/// decimal, set through the constructor (a card is built whole; it has no rate mutator), is the SAME
/// integer in the cell as the conversion gave.
///
/// This is the assertion that stands where a cross-rate would have gone. #66 removed the axis a
/// cross-rate needed: there is no second denomination for a rate to be scaled against, so a rate
/// on a card can only ever be the integer somebody configured. The projection (`Money::of_nanos`,
/// then `minor_i64`) divides by ONE constant, `NANOS_PER_CENT`, which nothing can name and therefore
/// nothing can move.
#[test]
fn the_conversion_is_the_integer_the_card_holds() {
    let mut seq = Seq(0x1234_5678_9ABC_DEF0);
    for case in 0..10_000u32 {
        let micro = seq.below(10_000_000_000) as f64 / 1_000_000.0;
        let expected = nano_rate(micro);

        let built = RateCard::from_micro_rates([(LaneClass::new("lane", "input"), micro)], 0);

        let rates = built.lane_rates("lane").expect("the lane is priced");
        assert_eq!(
            rates.nanos_per_unit("input"),
            expected,
            "case {case}: the rate moved at {micro} micro-units per unit"
        );
        // A rate the card cannot hold is an UNPRICED cell, never a priced zero (item 22).
        assert_eq!(
            rates.class_priced("input"),
            micro == 0.0 || expected != 0,
            "case {case}: {micro} micro-units per unit"
        );
        // And the kernel's projection, which is the same one function, still gives that
        // same integer.
        assert_eq!(admission_nano_rate(micro), expected, "case {case}");
    }
}

/// **THE PROJECTION HAS ONE DIVISOR AND IT IS A CONSTANT.** One nano-unit total, one answer —
/// there is no argument, table or label that could produce a second.
#[test]
fn the_projection_divides_by_the_one_constant() {
    assert_eq!(NANOS_PER_CENT, 10_000_000);
    let nanos = 3_500_000_000u128;
    // The CHECKED projection (item 28): the one money type, which refuses rather than pins.
    let minor = Money::of_nanos(nanos).and_then(Money::minor_i64);
    assert_eq!(minor, Ok(350));
    assert_eq!(
        minor,
        Ok(i64::try_from(nanos / NANOS_PER_CENT).expect("fits")),
        "the projection is the constant and nothing else"
    );
}
