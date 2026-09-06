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
