// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity that ties the two readers together: the older release's read-time derivation, run
//! against the pinned card, equals the sum of the nano-units the new layout stores.
//!
//! This is the property the shadow comparison rests on. The two paths reach the same figure by
//! different routes — one truncates the quantities to cents and then adds the fee in cents, the
//! other sums the fee in as a line and truncates once at the end — and they agree because the fee
//! line is an exact multiple of a cent.
//!
//! The generator is a plain congruential sequence written out here rather than a dependency: the
//! cases must be identical on every machine and every run, and a money property that only fails on
//! someone else's seed is not a property.

use super::*;
use crate::{
    cents_of, derive_spend_cents, derive_spend_micros, micros_of, price, STANDARD_TIER_BP,
};
use crate::{LaneClass, RateCard, RateCardVersion, FEE_CLASS, NANOS_PER_CENT};

/// A deterministic sequence. Same numbers everywhere, forever.
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

/// The class names the generated reports draw from — a mix of the older release's four and some
/// open ones, so open classes take part in the identity too.
const CLASSES: [&str; 6] = [INPUT, OUTPUT, CACHE_READ, CACHE_WRITE, "audio", "images"];

/// The identity, over ten thousand generated postings: the older derivation at the pinned card
/// equals the projection of the stored nano-units, in cents and in micro-units alike.
///
/// The generated ranges stay well inside the saturating region on purpose. Saturation itself is
/// pinned by its own cases in the other files; mixing the two would let a case pass because both
/// sides pinned at the top rather than because they agreed.
#[test]
fn the_older_derivation_at_the_pinned_card_equals_the_stored_nano_units() {
    let mut seq = Seq(0x5EED_1234_ABCD_0001);
    for case in 0..10_000u32 {
        // A card over one lane: each class priced at up to ten thousand micro-units, to three
        // decimal places, so the rounding step at resolve is genuinely exercised.
        let entries: Vec<(LaneClass, f64)> = CLASSES
            .iter()
            .map(|c| {
                let micro = seq.below(10_000_000) as f64 / 1000.0;
                (LaneClass::new("lane", *c), micro)
            })
            .collect();
        let fee_cents = seq.below(1_000) as i64;
        let card = RateCard::from_micro_rates(RateCardVersion::new("pinned"), entries, fee_cents);

        // A report of up to six lines with quantities up to a billion.
        let count = seq.below(CLASSES.len() as u64 + 1) as usize;
        let reported: Vec<(&str, u64)> = CLASSES
            .iter()
            .take(count)
            .map(|c| (*c, seq.below(1_000_000_000)))
            .collect();
        let fee_count = seq.below(2); // one fee per client request, or none
        let report = usage(&reported);
        let plain = lines(&reported);

        let posted = price(&card.pin(), "lane", &report, fee_count, STANDARD_TIER_BP);
        let derived_cents = derive_spend_cents(
            &card,
            [("lane", plain.as_slice())].into_iter(),
            fee_count,
            true,
        );
        let derived_micros = derive_spend_micros(
            &card,
            [("lane", plain.as_slice())].into_iter(),
            fee_count,
            true,
        );

        assert_eq!(
            derived_cents,
            posted.cents(),
            "case {case}: derived cents must equal the projection of the stored nano-units"
        );
        assert_eq!(
            derived_micros,
            posted.micros(),
            "case {case}: derived micro-units must equal the projection of the stored nano-units"
        );

        // The fee and the usage also agree SEPARATELY, which is how the shadow comparison reads
        // them: the usage-only derivation against the posting's non-fee lines, and the fee against
        // its own line.
        let usage_only = derive_spend_cents(
            &card,
            [("lane", plain.as_slice())].into_iter(),
            fee_count,
            false,
        );
        let stored_usage: u128 = posted
            .lines()
            .iter()
            .filter(|l| l.class != FEE_CLASS)
            .fold(0u128, |a, l| a + l.amount_nanos);
        assert_eq!(
            usage_only,
            cents_of(stored_usage),
            "case {case}: usage alone"
        );
        let stored_fee = posted
            .lines()
            .iter()
            .find(|l| l.class == FEE_CLASS)
            .expect("every posting carries a fee line")
            .amount_nanos;
        assert_eq!(
            stored_fee,
            u128::from(fee_count)
                * u128::try_from(fee_cents).expect("clamped non-negative")
                * NANOS_PER_CENT,
            "case {case}: the fee line alone"
        );
    }
}

/// The two projections are consistent with each other by construction: a nano-unit total in
/// micro-units, divided by the ten thousand micro-units in a cent, is the same total in cents.
#[test]
fn the_two_projections_agree_at_every_generated_total() {
    let mut seq = Seq(0x0FF1_CE00_1234_5678);
    for _ in 0..10_000 {
        let nanos = u128::from(seq.next()) * u128::from(seq.below(1_000_000) + 1);
        assert_eq!(cents_of(nanos), micros_of(nanos) / crate::MICROS_PER_CENT);
    }
}

/// A tiered posting has no older-release counterpart, so the identity deliberately stops at the
/// neutral tier: the tier multiplier is asserted against hand computation instead. This case pins
/// the boundary itself — at the neutral multiplier the two agree, and away from it the posting is
/// expected to diverge from the older derivation, which is the designed difference rather than a
/// defect.
#[test]
fn the_identity_holds_at_the_neutral_tier_and_the_tier_is_the_only_divergence() {
    let c = card("m", 2.0, 5.0, 3);
    let report = usage(&[(INPUT, 3), (OUTPUT, 4)]);
    let plain = lines(&[(INPUT, 3), (OUTPUT, 4)]);
    let derived = derive_spend_cents(&c, [("m", plain.as_slice())].into_iter(), 1, true);

    let neutral = price(&c.pin(), "m", &report, 1, STANDARD_TIER_BP);
    assert_eq!(derived, neutral.cents());

    let tiered = price(&c.pin(), "m", &report, 1, 15_000);
    assert_ne!(
        derived,
        tiered.cents(),
        "a tier away from neutral is expected to differ from the older derivation"
    );
    assert_eq!(tiered.pre_tier_amount(), neutral.priced_amount());
}
