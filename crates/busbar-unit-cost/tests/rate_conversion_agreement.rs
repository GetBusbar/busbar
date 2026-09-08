// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money rules the door and the pricing law both need, held to the same answer.
//!
//! Two of them: the decimal-to-integer RATE conversion, and the nano-unit-to-cent PROJECTION. There
//! is one of each in the tree now, and this file is what says so.
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
use busbar_unit_cost::{cents_of, minor_of, nano_rate, CurrencyCode, LaneClass, RateCard};

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

/// The admission unit's CENT PROJECTION, asked for one nano-unit total.
///
/// The door has no way to be handed a nano total directly — it derives one from counts and rates —
/// so the total is factored into a count and a rate whose product is exactly it, put through the
/// door's own accumulation, and read back as cents. Nothing else in the derivation moves: the fee is
/// zero, so what comes back out is the projection and only the projection.
fn admission_cents(count: u64, nanos_per_unit: u64) -> i64 {
    let mut table = std::collections::BTreeMap::new();
    table.insert(
        "m".to_string(),
        RateNanos {
            input: nanos_per_unit,
            ..RateNanos::default()
        },
    );
    let mut units = std::collections::BTreeMap::new();
    units.insert(busbar_unit_admission::price::UNIT_INPUT.to_string(), count);
    let pricer = busbar_unit_admission::Pricer::with_card(0, table);
    pricer.derive_spend_cents(std::iter::once(("m", &units)), 0, true)
}

/// **THE CENT PROJECTION, HELD TO THE SAME ANSWER AS THE RATE CONVERSION IS.**
///
/// The door decides admission in cents and the ledger bills in cents, and until this file said so
/// there were two truncating divides in the tree deriving that figure — this crate's [`cents_of`]
/// and a second copy inside the admission unit's spend derivation, beside a second declaration of
/// the divisor. That is the same shape as the rate conversion above, one fold further down: the
/// divisor, the truncation direction and the saturation posture all have to be the same three
/// decisions, because a request JUDGED at one projection and BILLED at another is a bill that does
/// not match the decision that produced it.
///
/// The door now calls this crate's projection. Both sides of every assertion below are therefore the
/// same function today, and the file passes by construction — exactly as the rate assertions above
/// do, and for the same reason. What it is FOR is the day somebody re-forks those two lines: the
/// moment the door carries its own divide again, these are the assertions that stop being trivially
/// true.
#[test]
fn the_two_cent_projections_agree_on_ten_thousand_generated_totals() {
    let mut seq = Seq(0x5EED_0000_CE47_5000);
    for case in 0..10_000u32 {
        // A count and a rate rather than a total, because the door reaches a total only by
        // multiplying one by the other. Both are drawn to land the PRODUCT in the range where the
        // divisor is what decides the answer: up to a hundred million nano-units per unit against a
        // million units is a total of a few million cents, so almost every case sits a rounding step
        // from a whole-cent boundary. Drawing both wide instead would look more searching and test
        // less — every product would saturate at the top of the signed range and agree there
        // whatever divisor either side used. The saturation has its own named cases below.
        let count = seq.below(1_000_000);
        let rate = seq.below(100_000_000);
        let nanos = u128::from(count).saturating_mul(u128::from(rate));
        assert_eq!(
            cents_of(nanos),
            admission_cents(count, rate),
            "case {case}: the two cent projections disagree at {nanos} nano-units"
        );
    }
}

/// The totals where a difference in the cent projection would actually live: nothing, either side of
/// a whole cent, the exact boundary, and the whole neighbourhood of the signed ceiling the
/// saturation exists for. A generator reaches these only by luck, so they are named.
#[test]
fn the_two_cent_projections_agree_at_every_boundary_total() {
    let cent = busbar_unit_cost::NANOS_PER_CENT;
    assert_eq!(
        busbar_unit_admission::price::NANOS_PER_CENT,
        cent,
        "the divisor is one number, not two that happen to match"
    );
    // (count, rate) pairs, and the nano total each one is: the door multiplies, so a total is named
    // by its factors.
    let boundaries: [(u64, u64); 10] = [
        (0, 0),                 // nothing at all
        (1, 1),                 // a single nano-unit: floors to nothing
        (1, 9_999_999),         // one nano-unit short of a cent: still nothing
        (1, 10_000_000),        // exactly one cent
        (1, 10_000_001),        // a cent and a nano-unit: truncates back to one cent
        (2, 5_000_000),         // half a cent twice: the counts sum BEFORE the divide
        (1, u64::MAX),          // the widest single product a rate can carry
        (u64::MAX, 1),          // and the widest a count can
        (u64::MAX, 10_000_000), // past the signed ceiling in cents: saturates
        (u64::MAX, u64::MAX),   // the largest product there is
    ];
    for (count, rate) in boundaries {
        let nanos = u128::from(count).saturating_mul(u128::from(rate));
        assert_eq!(
            cents_of(nanos),
            admission_cents(count, rate),
            "the two cent projections disagree at {nanos} nano-units"
        );
    }
    // And the saturation is the same saturation, not merely the same answer by coincidence: a total
    // past the top of the signed range pins at the maximum on both sides rather than wrapping
    // negative, which the floor would then read as free.
    let over = u128::from(u64::MAX).saturating_mul(u128::from(u64::MAX));
    assert_eq!(cents_of(over), i64::MAX);
    assert_eq!(admission_cents(u64::MAX, u64::MAX), i64::MAX);
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
