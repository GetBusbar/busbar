// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORRECTION VERB'S KERNEL HALF (item 404): a root admin amends a recorded unit's COUNTS, the
//! read-time money view prices the corrected counts at the card epoch, and a correction that would
//! take a count below zero — or one made below the root scope — seals nothing.
//!
//! The journal is process-wide, so every test here names an entry digest no other test uses and
//! reads only the rows that name it.

use super::{
    correct_counts, counts_now, node_corrections, Adjust, AmendBody, ClassCounts, CorrectionError,
    CorrectionRefused, CountCorrection, Scope,
};
use busbar_kernel_ledger::cost::{
    nanos_of_exact, whole, Count, LaneClass, RateCard, Tally, STANDARD_TIER_BP,
};

fn counts(pairs: &[(&str, u64)]) -> ClassCounts {
    pairs
        .iter()
        .map(|(class, n)| ((*class).to_string(), whole(*n)))
        .collect()
}

/// The corrections sealed against `amends`, oldest first.
fn corrections_of(amends: &str) -> Vec<Adjust> {
    node_corrections()
        .into_iter()
        .filter_map(|a| match a.body {
            AmendBody::Adjust(adj) if adj.amends_hash == amends => Some(adj),
            _ => None,
        })
        .collect()
}

/// What `c` costs, in nano-units, on lane `m` at the card, through the one function.
fn priced(card: &RateCard, c: &ClassCounts) -> u128 {
    let mut tally = Tally::at_card(card);
    tally
        .row(
            "m",
            0,
            STANDARD_TIER_BP,
            c.iter().map(|(class, n)| (class.as_str(), *n)),
            Count::ZERO,
        )
        .expect("every class is priced");
    nanos_of_exact(tally.exact().expect("in range")).expect("in range")
}

fn correction<'a>(amends: &'a str, now: ClassCounts) -> CountCorrection<'a> {
    CountCorrection {
        amends,
        principal: Some("pseudonym-1"),
        lane: "m",
        card_epoch_ms: 1_700_000_000_000,
        now,
        authorised_by: "root",
        reason: "duplicate charge on a retried request",
    }
}

/// A CORRECTION AMENDS THE COUNT, AND MONEY FOLLOWS THE COUNT. 1,000 input units at 2.5 micro-units
/// is 2,500,000 nano-units as recorded; corrected to 800 the view reads 2,000,000 — the new count ×
/// the same card — while the recorded counts themselves are untouched and the adjustment carries
/// both, with who and why.
#[test]
fn a_root_correction_amends_the_count_and_the_money_view_follows_it() {
    let card = RateCard::from_micro_rates([(LaneClass::new("m", "input"), 2.5)], 0);
    let recorded = counts(&[("input", 1_000)]);
    assert_eq!(priced(&card, &counts_now("p2-404-a", &recorded)), 2_500_000);

    correct_counts(
        Scope::Full,
        &recorded,
        correction("p2-404-a", counts(&[("input", 800)])),
    )
    .expect("a root correction to a non-negative count lands");

    let now = counts_now("p2-404-a", &recorded);
    assert_eq!(now, counts(&[("input", 800)]));
    assert_eq!(priced(&card, &now), 2_000_000);
    assert_eq!(
        recorded,
        counts(&[("input", 1_000)]),
        "the record is never rewritten"
    );

    let sealed = corrections_of("p2-404-a");
    assert_eq!(sealed.len(), 1, "exactly one adjustment is sealed");
    assert_eq!(sealed[0].was, counts(&[("input", 1_000)]));
    assert_eq!(sealed[0].now, counts(&[("input", 800)]));
    assert_eq!(sealed[0].card_epoch_ms, 1_700_000_000_000);
    assert_eq!(sealed[0].authorised_by, "root");
}

/// A SECOND CORRECTION STARTS FROM THE FIRST ONE'S RESULT, so the chain reads as the history of
/// the count rather than two claims about the original.
#[test]
fn a_second_correction_names_the_first_ones_result_as_what_it_was() {
    let recorded = counts(&[("input", 10)]);
    correct_counts(
        Scope::Full,
        &recorded,
        correction("p2-404-b", counts(&[("input", 8)])),
    )
    .unwrap();
    correct_counts(
        Scope::Full,
        &recorded,
        correction("p2-404-b", counts(&[("input", 5)])),
    )
    .unwrap();
    let sealed = corrections_of("p2-404-b");
    assert_eq!(sealed.len(), 2);
    assert_eq!(sealed[1].was, counts(&[("input", 8)]));
    assert_eq!(counts_now("p2-404-b", &recorded), counts(&[("input", 5)]));
}

/// A CORRECTION BELOW ZERO REFUSES, and seals nothing: the count and the money stay as recorded.
#[test]
fn a_negative_correction_refuses_and_seals_nothing() {
    let card = RateCard::from_micro_rates([(LaneClass::new("m", "input"), 2.5)], 0);
    let recorded = counts(&[("input", 1_000)]);
    let mut negative = ClassCounts::new();
    negative.insert("input".into(), Count::from_integer(-1).unwrap());
    assert_eq!(
        correct_counts(Scope::Full, &recorded, correction("p2-404-c", negative)).unwrap_err(),
        CorrectionError::Refused(CorrectionRefused::NegativeCount {
            class: "input".into()
        })
    );
    assert!(corrections_of("p2-404-c").is_empty());
    assert_eq!(priced(&card, &counts_now("p2-404-c", &recorded)), 2_500_000);
}

/// BELOW THE ROOT SCOPE NOTHING IS CORRECTED.
#[test]
fn a_correction_below_the_root_scope_refuses_and_seals_nothing() {
    let recorded = counts(&[("input", 1_000)]);
    assert_eq!(
        correct_counts(
            Scope::ReadOnly,
            &recorded,
            correction("p2-404-d", counts(&[("input", 1)]))
        )
        .unwrap_err(),
        CorrectionError::NotRoot
    );
    assert!(corrections_of("p2-404-d").is_empty());
    assert_eq!(counts_now("p2-404-d", &recorded), recorded);
}
