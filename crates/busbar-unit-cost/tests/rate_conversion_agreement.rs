// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two decimal-to-money conversions, held to the same answer.
//!
//! There are two of them in the tree, not one. This crate's [`nano_rate`] is the pricing law's
//! conversion; the admission unit carries its own copy inside its rate projection, because that
//! crate depends on nothing here and cannot call across. Both take micro-units per unit of quantity
//! off config, multiply by a thousand, round to nearest half away from zero, and clamp anything not
//! finite or not positive to zero.
//!
//! They have to give the same integer for the same configured rate. If they ever drift, a request
//! is JUDGED at one rate by the door and BILLED at another by the ledger, and the gap between the
//! two is silent — no error, no refusal, just a bill that does not match the decision that produced
//! it. This file is the only place that can notice, so it does: ten thousand generated rates, and
//! the specific values where a rounding rule or a clamp would be the thing that differs.
//!
//! The dependency that makes the comparison possible is a DEV dependency. Neither library gains a
//! dependency on the other; nothing in either crate's compiled arithmetic changes. What the two
//! Cargo files say about having no workspace dependencies beyond the capability types remains true
//! of both libraries, and the copies are now checked against each other instead of merely asserted
//! to match.

use busbar_unit_admission::RateNanos;
use busbar_unit_cost::nano_rate;

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
/// zero, the smallest configured rate that is not zero, and the three clamped inputs. A generator
/// reaches these only by luck, so they are named.
#[test]
fn the_two_conversions_agree_at_every_boundary_value() {
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
        f64::MAX, // finite, but times a thousand it is not
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
