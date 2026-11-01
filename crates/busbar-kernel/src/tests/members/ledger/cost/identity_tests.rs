// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MIGRATION'S EXACTNESS**, and the identity that ties the two readers together.
//!
//! Every case in this file prices through a SINGLE-ENTRY HISTORY effective from instant zero — the
//! shape a migration seals — and compares settlement and read-time pricing against independently
//! computed integer amounts. A single-entry history is the pinned card, arithmetically, so a
//! deployment that never edits a price sees no figure move at all.
//!
//! Expected amounts sum integer rate × quantity and the fee before one final division. Both
//! production paths must agree with these amounts, including their separate usage and fee lines.
//!
//! The generator is a plain congruential sequence written out here rather than a dependency: the
//! cases must be identical on every machine and every run, and a money property that only fails on
//! someone else's seed is not a property.

use super::super::fixtures::Rng;
use super::fixtures::*;
use busbar_kernel_ledger::cost::{price_ledger, History, LedgerEntry, STANDARD_TIER_BP};
use busbar_kernel_ledger::cost::{LaneClass, RateCard, FEE_CLASS, NANOS_PER_CENT, NANOS_PER_MICRO};

/// The class names the generated reports draw from — a mix of the older release's four and some
/// open ones, so open classes take part in the identity too.
const CLASSES: [&str; 6] = [INPUT, OUTPUT, CACHE_READ, CACHE_WRITE, "audio", "images"];

/// The identity, over the existing generated postings: settlement and the read over a
/// single-entry history equal independent integer amounts, in cents and in micro-units alike.
///
/// The generated ranges stay well inside the representable range. Overflow refusal has its own
/// cases; these successful postings must agree on their exact amounts.
#[test]
fn settlement_and_single_entry_history_match_independent_integer_amounts() {
    let mut seq = Rng::seeded(0x5EED_1234_ABCD_0001);
    for case in 0..10_000u32 {
        // A card over one lane: each class priced at up to ten thousand micro-units, to three
        // decimal places, so exact rate conversion at resolve is exercised too.
        let nano_rates: Vec<(&str, u64)> = CLASSES
            .iter()
            .map(|c| (*c, seq.below(10_000_000)))
            .collect();
        let fee_cents = seq.below(1_000) as i64;
        let card = RateCard::from_micro_rates(
            nano_rates
                .iter()
                .map(|(class, nanos)| (LaneClass::new("lane", *class), *nanos as f64 / 1000.0)),
            fee_cents,
        );

        // A report of up to six lines with quantities up to a billion.
        let count = seq.below(CLASSES.len() as u64 + 1) as usize;
        let reported: Vec<(&str, u64)> = CLASSES
            .iter()
            .take(count)
            .map(|c| (*c, seq.below(1_000_000_000)))
            .collect();
        let fee_count = seq.below(2); // one fee per client request, or none
        let report = usage(&reported);
        let posted = priced(&card, "lane", &report, fee_count, STANDARD_TIER_BP);
        let entry = reported
            .iter()
            .fold(LedgerEntry::new("lane", 0), |e, (class, n)| {
                e.with_whole(*class, *n)
            });
        let history = History::opening(card, 0);
        let read = price_ledger(&[entry.clone().with_fee_count(fee_count)], &history)
            .expect("the single-entry history prices");
        let usage_nanos: u128 = reported
            .iter()
            .zip(&nano_rates)
            .map(|((_, quantity), (_, nanos))| u128::from(*quantity) * u128::from(*nanos))
            .sum();
        let fee_nanos = u128::from(fee_count)
            * u128::try_from(fee_cents).expect("non-negative fixture fee")
            * NANOS_PER_CENT;
        let total_nanos = usage_nanos + fee_nanos;
        let derived_cents = i64::try_from(total_nanos / NANOS_PER_CENT).expect("fixture fits");
        let derived_micros = i64::try_from(total_nanos / NANOS_PER_MICRO).expect("fixture fits");

        assert_eq!(
            read.minor_i64(),
            Ok(derived_cents),
            "case {case}: history cents"
        );
        assert_eq!(
            read.micros_i64(),
            Ok(derived_micros),
            "case {case}: history micros"
        );
        assert_eq!(
            posted.priced_nanos, total_nanos,
            "case {case}: settlement nanos"
        );

        assert_eq!(
            derived_cents,
            minor(&posted),
            "case {case}: derived cents must equal the projection of the stored nano-units"
        );
        assert_eq!(
            derived_micros,
            micros(&posted),
            "case {case}: derived micro-units must equal the projection of the stored nano-units"
        );

        // The fee and the usage also agree SEPARATELY, which is how the shadow comparison reads
        // them: the usage-only derivation against the posting's non-fee lines, and the fee against
        // its own line.
        let usage_only = price_ledger(&[entry], &history)
            .expect("usage alone prices")
            .minor_i64()
            .expect("fixture fits");
        let stored_usage: u128 = posted
            .lines
            .iter()
            .filter(|l| l.class != FEE_CLASS)
            .fold(0u128, |a, l| a + l.amount_nanos);
        assert_eq!(
            usage_only,
            minor_nanos(stored_usage).expect("in range"),
            "case {case}: usage alone"
        );
        assert_eq!(
            stored_usage, usage_nanos,
            "case {case}: independent usage amount"
        );
        let stored_fee = posted
            .lines
            .iter()
            .find(|l| l.class == FEE_CLASS)
            .expect("every posting carries a fee line")
            .amount_nanos;
        assert_eq!(stored_fee, fee_nanos, "case {case}: the fee line alone");
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
    let history = History::opening(c.clone(), 0);
    let entry = LedgerEntry::new("m", 0)
        .with_whole(INPUT, 3)
        .with_whole(OUTPUT, 4)
        .with_fee_count(1);
    let derived = price_ledger(&[entry], &history).expect("the history prices");
    assert_eq!(derived.micros_i64(), Ok(30_026), "3×2 + 4×5 + 3×10,000");

    let neutral = priced(&c, "m", &report, 1, STANDARD_TIER_BP);
    assert_eq!(derived.minor_i64(), Ok(minor(&neutral)));
    assert_eq!(neutral.priced_nanos, 30_026_000);

    let tiered = priced(&c, "m", &report, 1, 15_000);
    assert_ne!(
        derived.minor_i64().expect("fits"),
        minor(&tiered),
        "a tier away from neutral is expected to differ from the older derivation"
    );
    assert_eq!(tiered.pre_tier_nanos, neutral.priced_nanos);
    assert_eq!(tiered.priced_nanos, 45_039_000, "neutral amount × 1.5");
}
