// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RULING 5's LAW: an enabled plane that reports a class nobody priced refuses boot, an explicit
//! zero row is free and boots, and a 1.5.5 config still boots because its card has always carried
//! every class it priced.

use crate::coverage::{refusal, unpriced_cells, PlaneClasses};
use crate::rate::TierRates;
use crate::table::{
    RateRow, RateTable, RowAuthor, CLASS_REQUESTS, CLASS_TOKENS_CACHE_READ,
    CLASS_TOKENS_CACHE_WRITE, CLASS_TOKENS_INPUT, CLASS_TOKENS_OUTPUT,
};
use crate::CurrencyCode;

const LANE: &str = "claude-sonnet";
const USD: CurrencyCode = CurrencyCode::USD;

/// The classes the llm plane declares, in the config/wire spelling its meta now uses.
const LLM_CLASSES: &[&str] = &[
    CLASS_TOKENS_INPUT,
    CLASS_TOKENS_OUTPUT,
    CLASS_TOKENS_CACHE_READ,
    CLASS_TOKENS_CACHE_WRITE,
];

fn llm() -> PlaneClasses<'static> {
    PlaneClasses {
        plane: "llm",
        classes: LLM_CLASSES,
    }
}

fn tiers() -> TierRates {
    TierRates {
        input: 3.0,
        output: 15.0,
        cache_read: 0.3,
        cache_write: 3.75,
    }
}

/// A table carrying exactly the named classes on the one lane, each at a nominal price.
fn table_with(classes: &[&str], nanos: u64) -> RateTable {
    let mut table = RateTable::new();
    for class in classes {
        table.add(RateRow {
            lane: LANE.to_string(),
            class: (*class).to_string(),
            currency: USD,
            nanos_per_unit: nanos,
            effective_from: 0,
            author: RowAuthor::Config { policy_epoch: 0 },
        });
    }
    table
}

#[test]
fn an_enabled_plane_reporting_a_class_with_no_rate_row_refuses_and_names_plane_lane_and_class() {
    // THE RED CASE THE RULING NAMES: the llm plane is enabled, the operator has started pricing, and
    // `tokens_cache_read` has no row. A cache-read token would be metered and billed at nothing.
    let table = table_with(
        &[
            CLASS_TOKENS_INPUT,
            CLASS_TOKENS_OUTPUT,
            CLASS_TOKENS_CACHE_WRITE,
            CLASS_REQUESTS,
        ],
        3_000,
    );

    let found = unpriced_cells(&table, &[llm()], &[LANE], USD);
    assert_eq!(found.len(), 1, "exactly one cell is unpriced: {found:?}");
    assert_eq!(found[0].plane, "llm");
    assert_eq!(found[0].lane, LANE);
    assert_eq!(found[0].class, CLASS_TOKENS_CACHE_READ);

    let msg = refusal(&found).expect("an unpriced cell must produce a refusal");
    // The refusal names all three, so an operator can act on it without reading the source.
    assert!(msg.contains("llm"), "the refusal names the plane: {msg}");
    assert!(msg.contains(LANE), "the refusal names the lane: {msg}");
    assert!(
        msg.contains(CLASS_TOKENS_CACHE_READ),
        "the refusal names the class: {msg}"
    );
    // And it says what the two acceptable answers are, so the operator chooses rather than guesses.
    assert!(
        msg.contains("FREE IS AN EXPLICIT ZERO ROW"),
        "the refusal states the remedy: {msg}"
    );
}

#[test]
fn an_explicit_zero_row_is_free_and_boots() {
    // The same deployment, with the operator having said out loud that cache reads are free.
    let mut table = table_with(
        &[
            CLASS_TOKENS_INPUT,
            CLASS_TOKENS_OUTPUT,
            CLASS_TOKENS_CACHE_WRITE,
            CLASS_REQUESTS,
        ],
        3_000,
    );
    table.add(RateRow {
        lane: LANE.to_string(),
        class: CLASS_TOKENS_CACHE_READ.to_string(),
        currency: USD,
        nanos_per_unit: 0,
        effective_from: 0,
        author: RowAuthor::Config { policy_epoch: 0 },
    });

    let found = unpriced_cells(&table, &[llm()], &[LANE], USD);
    assert!(
        found.is_empty(),
        "a zero row is a price, not a silence: {found:?}"
    );
    assert_eq!(refusal(&found), None);
}

#[test]
fn a_1_5_5_config_still_boots_because_its_card_carries_every_class_it_ever_priced() {
    // THE BYTE-IDENTITY GUARD. A 1.5.5 operator who wrote only two of the four tiers: the omitted
    // two arrived as 0.0 and have always priced at zero, and `from_config` derives them as explicit
    // zero rows. So the config that booted before this rule existed still boots.
    let sparse = TierRates {
        input: 3.0,
        output: 15.0,
        cache_read: 0.0,
        cache_write: 0.0,
    };
    let table = RateTable::from_config(USD, Some(vec![(LANE, sparse.into())]), 0, 0);
    let found = unpriced_cells(&table, &[llm()], &[LANE], USD);
    assert!(
        found.is_empty(),
        "a 1.5.5 config must still boot: {found:?}"
    );

    // And so does a fully-written one.
    let full = RateTable::from_config(USD, Some(vec![(LANE, tiers().into())]), 3, 0);
    assert!(unpriced_cells(&full, &[llm()], &[LANE], USD).is_empty());
}

#[test]
fn a_deployment_that_prices_nothing_is_not_a_deployment_with_unpriced_classes() {
    // No `rate_card:` at all. Every release before this one booted, and this rule does not change
    // that: the operator has not opted into pricing rather than priced half of it.
    let table = RateTable::from_config(USD, None::<Vec<(&str, crate::rate::ConfiguredLane)>>, 0, 0);
    let found = unpriced_cells(&table, &[llm()], &[LANE], USD);
    assert!(found.is_empty(), "no card is not a refusal: {found:?}");
}

#[test]
fn a_class_priced_on_one_lane_and_not_another_refuses_for_the_lane_that_lacks_it() {
    // The rule is per (lane, class): pricing a model and forgetting its sibling is exactly the case
    // where an invoice is quietly short.
    let table = RateTable::from_config(USD, Some(vec![(LANE, tiers().into())]), 0, 0);
    let found = unpriced_cells(&table, &[llm()], &[LANE, "gpt-4o"], USD);

    assert_eq!(
        found.len(),
        4,
        "every class of the unpriced lane: {found:?}"
    );
    assert!(found.iter().all(|c| c.lane == "gpt-4o"));
    let msg = refusal(&found).expect("four unpriced cells refuse");
    assert!(msg.contains("gpt-4o"));
    // Plural agreement, so the refusal reads as English on the common multi-cell case.
    assert!(msg.contains("4 (plane, lane, class) cells have"), "{msg}");
}

#[test]
fn a_future_dated_row_is_a_price_the_operator_stated_and_does_not_refuse() {
    let mut table = table_with(LLM_CLASSES, 3_000);
    // Replace nothing; add a cell that only starts later, on a second lane.
    table.add(RateRow {
        lane: "gpt-4o".to_string(),
        class: CLASS_TOKENS_INPUT.to_string(),
        currency: USD,
        nanos_per_unit: 2_500,
        effective_from: u64::MAX / 2,
        author: RowAuthor::Config { policy_epoch: 0 },
    });
    let found = unpriced_cells(
        &table,
        &[PlaneClasses {
            plane: "llm",
            classes: &[CLASS_TOKENS_INPUT],
        }],
        &["gpt-4o"],
        USD,
    );
    assert!(
        found.is_empty(),
        "planning ahead is not an unpriced class: {found:?}"
    );
}

#[test]
fn the_refusal_names_every_cell_rather_than_the_first_one() {
    // An operator who fixes one cell and reboots into the next has been made to discover their
    // config one restart at a time.
    let table = table_with(&[CLASS_TOKENS_INPUT], 3_000);
    let found = unpriced_cells(&table, &[llm()], &[LANE], USD);
    assert_eq!(found.len(), 3);
    let msg = refusal(&found).expect("three unpriced cells refuse");
    for class in [
        CLASS_TOKENS_OUTPUT,
        CLASS_TOKENS_CACHE_READ,
        CLASS_TOKENS_CACHE_WRITE,
    ] {
        assert!(msg.contains(class), "the refusal names {class}: {msg}");
    }
}

#[test]
fn the_finding_order_is_stable_so_two_boots_of_one_config_refuse_identically() {
    let table = table_with(&[CLASS_TOKENS_INPUT], 3_000);
    let a = unpriced_cells(&table, &[llm()], &[LANE, "gpt-4o"], USD);
    let b = unpriced_cells(&table, &[llm()], &[LANE, "gpt-4o"], USD);
    assert_eq!(a, b);
    // Sorted, so a diff of two boots' stderr shows a real change rather than a reordering.
    let mut sorted = a.clone();
    sorted.sort();
    assert_eq!(a, sorted);
}

#[test]
fn a_plane_that_reports_nothing_can_never_refuse() {
    // The admin plane declares no meter classes at all. It cannot be the reason a boot fails.
    let table = table_with(&[CLASS_TOKENS_INPUT], 3_000);
    let found = unpriced_cells(
        &table,
        &[PlaneClasses {
            plane: "admin",
            classes: &[],
        }],
        &[LANE],
        USD,
    );
    assert!(found.is_empty());
}

#[test]
fn a_class_priced_only_in_another_currency_is_unpriced_here() {
    // No pivot: a row in EUR does not price a USD deployment's cell.
    let eur = CurrencyCode::new("EUR").expect("EUR is a well-formed code");
    let mut table = table_with(LLM_CLASSES, 3_000);
    table.add(RateRow {
        lane: "gpt-4o".to_string(),
        class: CLASS_TOKENS_INPUT.to_string(),
        currency: eur,
        nanos_per_unit: 2_500,
        effective_from: 0,
        author: RowAuthor::Config { policy_epoch: 0 },
    });
    let found = unpriced_cells(
        &table,
        &[PlaneClasses {
            plane: "llm",
            classes: &[CLASS_TOKENS_INPUT],
        }],
        &["gpt-4o"],
        USD,
    );
    assert_eq!(found.len(), 1, "the EUR row does not price the USD cell");
}
