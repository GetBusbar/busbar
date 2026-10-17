// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ONE TEST.** A known ledger × a known card history → a known figure.
//!
//! The owner's acceptance criterion, in his words: *"money is just a function … one test and it
//! works or doesn't."* Everything else in this file is that test's supporting cast: the same
//! function asked whether it agrees with each of the implementations it replaces, and whether it
//! gives the CORRECT answer where those implementations disagree with each other.

use busbar_kernel_ledger::cost::{
    price_exact, price_in_view, History, LaneClass, LedgerEntry, RateCard, STANDARD_TIER_BP,
};

use super::fixtures::{CACHE_READ, INPUT, OUTPUT};

/// The lane every case below serves on.
const LANE: &str = "gpt-4o";

#[test]
fn it_equals_the_posting_lookup_on_the_same_quantities() {
    let card = super::fixtures::card4(LANE, [3.0, 16.0, 0.5, 4.0], 2);
    let history = History::opening(card, 0);
    let usage = super::fixtures::usage(&[(INPUT, 1_000), (OUTPUT, 250), (CACHE_READ, 7_000)]);
    let posting =
        busbar_kernel_ledger::cost::Posting::from_usage(LANE, &usage, 3, STANDARD_TIER_BP, 0, 0);
    let lookup =
        busbar_kernel_ledger::cost::price(&history.current(), &posting).expect("the lookup prices");

    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(INPUT, 1_000)
        .with_whole(OUTPUT, 250)
        .with_whole(CACHE_READ, 7_000)
        .with_fee_count(3)];
    let one = price_in_view(&slice, &history.current()).expect("prices");

    assert_eq!(i128::from(super::fixtures::micros(&lookup)), one.micros());
}

/// **ITEM 437 — THE SAME CERTIFICATE AT THE TIERS WHERE THE TWO COULD DISAGREE.** The case above is
/// pinned to [`STANDARD_TIER_BP`] with whole counts, the one input where a nano-scale tier and an
/// exact-scale tier cannot answer differently. This one asks at half price over an ODD nano-unit
/// pre-tier sum — the exact half the tier rule has to decide:
///
/// one class, 1,999 units at 0.001 micro-units (1 nano-unit) a unit, tier 5,000 bp.
/// - A lookup that tiered at NANO scale (half-to-even over 999.5 → 1,000 nano-units) billed
///   `1` micro-unit.
/// - The one function tiers at the exact scale (999.5 nano-units, exact) and truncates once:
///   `999` nano-units, `0` micro-units.
///
/// Settlement and every read are one tier rule (item 27), so the posting lookup and the view must
/// answer the same figure at EVERY tier, in nano-units and in micro-units, and a lookup that grew
/// its own tier call back would go red here.
#[test]
fn it_equals_the_posting_lookup_at_every_tier_including_an_exact_half() {
    let card = RateCard::from_micro_rates([(LaneClass::new(LANE, INPUT), 0.001)], 0);
    let history = History::opening(card, 0);
    let view = history.current();
    for tier in [5_000u32, 3_333, 7_500, STANDARD_TIER_BP, 15_000] {
        for quantity in [1u64, 999, 1_999, 2_001, 1_000_001] {
            let usage = super::fixtures::usage(&[(INPUT, quantity)]);
            let posting =
                busbar_kernel_ledger::cost::Posting::from_usage(LANE, &usage, 0, tier, 0, 0);
            let lookup =
                busbar_kernel_ledger::cost::price(&view, &posting).expect("the lookup prices");
            let slice = vec![LedgerEntry::new(LANE, 0)
                .with_whole(INPUT, quantity)
                .with_tier(tier)];
            let exact = price_exact(&slice, &view).expect("the view prices");
            assert_eq!(
                lookup.priced_nanos,
                busbar_kernel_ledger::cost::nanos_of_exact(exact).expect("in range"),
                "tier {tier} bp, {quantity} units: the settlement lookup and the view are one \
                 tier rule and must answer one nano-unit figure"
            );
            assert_eq!(
                i128::from(super::fixtures::micros(&lookup)),
                price_in_view(&slice, &view)
                    .expect("the view prices")
                    .micros(),
                "tier {tier} bp, {quantity} units: one micro-unit figure"
            );
        }
    }
    // Stated as absolutes, so a change that moved BOTH sides identically still fails.
    let usage = super::fixtures::usage(&[(INPUT, 1_999)]);
    let posting = busbar_kernel_ledger::cost::Posting::from_usage(LANE, &usage, 0, 5_000, 0, 0);
    let lookup = busbar_kernel_ledger::cost::price(&view, &posting).expect("the lookup prices");
    assert_eq!(lookup.pre_tier_nanos, 1_999);
    assert_eq!(lookup.priced_nanos, 999, "999.5 exact, one truncation");
    assert_eq!(
        super::fixtures::micros(&lookup),
        0,
        "never the nano-scale tier's 1"
    );
}
