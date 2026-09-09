// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE TABLE'S LAW: rows are added and never edited, the lookup answers the row in force at an
//! instant, and a missing row is a different answer from a zero row.
//!
//! The last file in this module is the one that matters most to the rest of the tree: the table
//! derived from a config must price every cell at the same integer the card derived from the SAME
//! config already prices it at. That is what lets the table be introduced beside the card without a
//! single recorded money byte moving.

use crate::rate::TierRates;
use crate::table::{
    RateRow, RateTable, RowAuthor, CLASS_REQUESTS, CLASS_TOKENS_CACHE_READ,
    CLASS_TOKENS_CACHE_WRITE, CLASS_TOKENS_INPUT, CLASS_TOKENS_OUTPUT,
};
use crate::{CurrencyCode, LaneClass, RateCard};

const LANE: &str = "claude-sonnet";
const USD: CurrencyCode = CurrencyCode::USD;

/// The rates the 1.5.5 example config prices this model at, in micro-units per token.
fn tiers() -> TierRates {
    TierRates {
        input: 3.0,
        output: 15.0,
        cache_read: 0.3,
        cache_write: 3.75,
    }
}

fn row(class: &str, nanos: u64, effective_from: u64) -> RateRow {
    RateRow {
        lane: LANE.to_string(),
        class: class.to_string(),
        currency: USD,
        nanos_per_unit: nanos,
        effective_from,
        author: RowAuthor::Config { policy_epoch: 0 },
    }
}

#[test]
fn an_empty_table_prices_nothing_and_says_so_rather_than_answering_zero() {
    let table = RateTable::new();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
    // The distinction the whole boot refusal rests on: "nobody has priced this" is `None`, and it is
    // NOT `Some(0)`. A reader that collapsed the two would turn an unpriced class into a free one.
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 0), None);
    assert!(!table.prices_cell(LANE, CLASS_TOKENS_INPUT, USD));
}

#[test]
fn an_explicit_zero_row_is_free_and_is_not_the_same_answer_as_no_row() {
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_CACHE_READ, 0, 0));

    // Priced, at zero. The operator said this is free, and the table can tell you they said it.
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_CACHE_READ, USD, 0),
        Some(0)
    );
    assert!(table.prices_cell(LANE, CLASS_TOKENS_CACHE_READ, USD));

    // The sibling class nobody mentioned is still unpriced. One zero row does not price a table.
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_CACHE_WRITE, USD, 0), None);
    assert!(!table.prices_cell(LANE, CLASS_TOKENS_CACHE_WRITE, USD));
}

#[test]
fn a_row_is_added_and_the_row_it_supersedes_still_answers_for_its_own_instants() {
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_INPUT, 3_000, 0));
    table.add(row(CLASS_TOKENS_INPUT, 9_000, 1_000));

    // Both rows are in the table. Nothing was edited and nothing was removed.
    assert_eq!(table.len(), 2);

    // Before the second row's instant, the first still answers -- forever, not just until the
    // second was added. This is the whole of "originals are never edited".
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 0), Some(3_000));
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 999),
        Some(3_000)
    );
    // From its own instant onward, the later row answers.
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 1_000),
        Some(9_000)
    );
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, u64::MAX),
        Some(9_000)
    );
}

#[test]
fn a_row_may_be_back_dated_and_re_prices_what_already_happened() {
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_OUTPUT, 15_000, 5_000));
    // At instant 1_000 nothing covers the cell yet: the table refuses rather than guessing.
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_OUTPUT, USD, 1_000), None);

    // The operator amends, naming an instant in the past. Ruling 3: rows are only ever ADDED, and a
    // retroactive reprice is free because every read derives money afresh.
    table.add(RateRow {
        lane: LANE.to_string(),
        class: CLASS_TOKENS_OUTPUT.to_string(),
        currency: USD,
        nanos_per_unit: 12_000,
        effective_from: 0,
        author: RowAuthor::Amend {
            operator_fingerprint: "op-1".to_string(),
            reason_hash: [7u8; 32],
        },
    });

    // The same instant now answers, and it answers the back-dated row.
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_OUTPUT, USD, 1_000),
        Some(12_000)
    );
    // The later row is untouched by the amendment beneath it.
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_OUTPUT, USD, 5_000),
        Some(15_000)
    );
    assert_eq!(table.len(), 2);
}

#[test]
fn two_rows_at_one_instant_are_answered_by_the_one_added_later() {
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_INPUT, 3_000, 2_000));
    // A correction to a back-dated row is another row beside it, never a reach into the first.
    table.add(row(CLASS_TOKENS_INPUT, 4_000, 2_000));
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 2_000),
        Some(4_000)
    );
    assert_eq!(table.len(), 2);
}

#[test]
fn a_row_answers_only_for_the_lane_the_class_and_the_currency_it_names() {
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_INPUT, 3_000, 0));

    assert_eq!(table.rate_at("gpt-4o", CLASS_TOKENS_INPUT, USD, 0), None);
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_OUTPUT, USD, 0), None);
    let eur = CurrencyCode::new("EUR").expect("EUR is a well-formed code");
    // No pivot and no cross-rate: a currency the table does not price refuses rather than
    // converting from one it does.
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_INPUT, eur, 0), None);
}

#[test]
fn a_row_that_starts_in_the_future_is_still_a_price_the_operator_has_stated() {
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_INPUT, 3_000, 9_999));

    // Not in force yet...
    assert_eq!(table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 0), None);
    // ...but the cell IS priced, which is the question boot validation asks. Refusing a config for
    // having planned ahead would refuse the thing the model is for.
    assert!(table.prices_cell(LANE, CLASS_TOKENS_INPUT, USD));
}

#[test]
fn a_config_with_no_rate_card_derives_no_rows_at_all() {
    let table = RateTable::from_config(USD, None::<Vec<(&str, crate::rate::ConfiguredLane)>>, 0, 0);
    assert!(table.is_empty());
    assert!(table.lanes().is_empty());
}

#[test]
fn a_configured_lane_derives_every_class_it_has_always_priced_including_the_omitted_ones() {
    // An operator who wrote only the two token rates: `RateEntryCfg`'s fields are `#[serde(default)]`
    // so the other two arrived here as 0.0, and a card has always priced them at zero.
    let sparse = TierRates {
        input: 3.0,
        output: 15.0,
        cache_read: 0.0,
        cache_write: 0.0,
    };
    let table = RateTable::from_config(USD, Some(vec![(LANE, sparse.into())]), 0, 0);

    // Five rows: the four token classes and the flat fee's `requests` class.
    assert_eq!(table.len(), 5);
    for class in [
        CLASS_TOKENS_INPUT,
        CLASS_TOKENS_OUTPUT,
        CLASS_TOKENS_CACHE_READ,
        CLASS_TOKENS_CACHE_WRITE,
        CLASS_REQUESTS,
    ] {
        assert!(
            table.prices_cell(LANE, class, USD),
            "a 1.5.5 config must carry every class it has always priced: {class}"
        );
    }
    // The omitted tiers are EXPLICIT zeros, which is what ruling 5 needs them to be, and the same
    // integer the card already held for them.
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_CACHE_READ, USD, 0),
        Some(0)
    );
    assert_eq!(table.rate_at(LANE, CLASS_REQUESTS, USD, 0), Some(0));
}

#[test]
fn the_flat_fee_is_the_requests_class_row_lifted_to_nano_units() {
    // Ruling 4: "a flat fee = the `requests` class with a per-unit price". Three cents a request, in
    // USD, is three times ten million nano-units.
    let table = RateTable::from_config(USD, Some(vec![(LANE, tiers().into())]), 3, 0);
    assert_eq!(
        table.rate_at(LANE, CLASS_REQUESTS, USD, 0),
        Some(30_000_000)
    );

    // A negative fee can never credit a budget: it clamps at zero, exactly as the card's fee does.
    let clamped = RateTable::from_config(USD, Some(vec![(LANE, tiers().into())]), -500, 0);
    assert_eq!(clamped.rate_at(LANE, CLASS_REQUESTS, USD, 0), Some(0));
}

#[test]
fn every_derived_row_is_attributable_to_the_config_that_produced_it() {
    let table = RateTable::from_config(USD, Some(vec![(LANE, tiers().into())]), 0, 42);
    for r in table.rows() {
        assert_eq!(r.author, RowAuthor::Config { policy_epoch: 42 });
        // A config's card has always applied to everything the deployment ever did.
        assert_eq!(r.effective_from, 0);
    }
}

#[test]
fn the_table_and_the_card_price_every_token_cell_at_the_same_integer() {
    // THE EQUALITY THAT LETS THE TABLE EXIST BESIDE THE CARD WITHOUT MOVING A BYTE.
    //
    // The card keys its cells by the METER's older spellings and the table keys its rows by the
    // config/wire ones. Two spellings, one set of integers. When the meter's posting path adopts the
    // config/wire names the card's keys move onto the table's and this test keeps holding.
    let lanes = vec![
        (LANE, tiers().into()),
        (
            "gpt-4o",
            crate::rate::ConfiguredLane::from_tiers(TierRates {
                input: 2.5,
                output: 10.0,
                cache_read: 0.0,
                cache_write: 0.0,
            }),
        ),
    ];
    let fee = 7;
    let table = RateTable::from_config(USD, Some(lanes.clone()), fee, 0);
    let card = RateCard::from_config_in(USD, Some(lanes.clone()), fee);

    for (lane, _) in &lanes {
        let rates = card
            .lane_rates(lane, USD)
            .expect("the card names this lane");
        for (table_class, card_class) in [
            (CLASS_TOKENS_INPUT, crate::CLASS_INPUT),
            (CLASS_TOKENS_OUTPUT, crate::CLASS_OUTPUT),
            (CLASS_TOKENS_CACHE_READ, crate::CLASS_CACHE_READ),
            (CLASS_TOKENS_CACHE_WRITE, crate::CLASS_CACHE_WRITE),
        ] {
            assert_eq!(
                table.rate_at(lane, table_class, USD, 0),
                Some(rates.nanos_per_unit(card_class)),
                "{lane}: the table's {table_class} row and the card's {card_class} cell are one price"
            );
        }
        // And the fee: the table's `requests` row is the card's fee line's unit price.
        assert_eq!(
            table.rate_at(lane, CLASS_REQUESTS, USD, 0),
            Some(u64::try_from(card.fee_unit_price_nanos(USD)).expect("a configured fee fits")),
        );
    }
}

#[test]
fn the_lane_list_is_sorted_and_carries_each_lane_once() {
    let table = RateTable::from_config(
        USD,
        Some(vec![
            ("zeta", tiers().into()),
            ("alpha", tiers().into()),
            ("mid", tiers().into()),
        ]),
        1,
        0,
    );
    // Five rows per lane, one entry per lane in the list.
    assert_eq!(table.lanes(), vec!["alpha", "mid", "zeta"]);
    assert_eq!(table.len(), 15);
}

#[test]
fn a_lane_class_names_the_same_cell_the_table_files_a_row_under() {
    // The card's cell key and the table's row key are the same pair, so a reader holding one can ask
    // the other. This is a shape check, not an arithmetic one.
    let cell = LaneClass::new(LANE, CLASS_TOKENS_INPUT);
    let mut table = RateTable::new();
    table.add(row(CLASS_TOKENS_INPUT, 3_000, 0));
    assert_eq!(table.rate_at(&cell.lane, &cell.class, USD, 0), Some(3_000));
}

/// The three open classes a lane might price, at three deliberately different magnitudes so a
/// derivation that dropped one, or priced them all from one figure, is red rather than green.
fn open_classes() -> std::collections::BTreeMap<String, f64> {
    let mut classes = std::collections::BTreeMap::new();
    classes.insert("tool_calls".to_string(), 250.0);
    classes.insert("bytes".to_string(), 0.002);
    classes.insert("audio_seconds_in".to_string(), 60.0);
    classes
}

/// RULING 1: A LANE PRICES ANY DECLARED CLASS, not only the four a 1.5.5 card could spell.
///
/// The four token tiers keep their own fields, their own spelling and their own canonical order.
/// The classes a plane declares that no tier can name -- `tool_calls` off the MCP plane, `bytes`
/// off A2A, `audio_seconds_in` off voice -- arrive as rows beside them, at the price the operator
/// wrote, through the same micro-to-nano conversion.
#[test]
fn a_lane_prices_every_class_the_operator_named_beside_the_four_tiers() {
    let table = RateTable::from_config(
        USD,
        Some(vec![(
            LANE,
            crate::rate::ConfiguredLane {
                tiers: tiers(),
                classes: open_classes(),
            },
        )]),
        7,
        0,
    );

    assert_eq!(
        table.rate_at(LANE, "tool_calls", USD, 0),
        Some(crate::nano_rate(250.0)),
    );
    assert_eq!(
        table.rate_at(LANE, "bytes", USD, 0),
        Some(crate::nano_rate(0.002)),
    );
    assert_eq!(
        table.rate_at(LANE, "audio_seconds_in", USD, 0),
        Some(crate::nano_rate(60.0)),
    );

    // And the four tiers and the fee are exactly what they were: the open rows are ADDED, and they
    // disturb no row the 1.5.5 grammar derived.
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_INPUT, USD, 0),
        Some(crate::nano_rate(3.0)),
    );
    assert_eq!(
        table.rate_at(LANE, CLASS_TOKENS_OUTPUT, USD, 0),
        Some(crate::nano_rate(15.0)),
    );
    assert_eq!(
        table.rate_at(LANE, CLASS_REQUESTS, USD, 0),
        Some(70_000_000)
    );
    // Five 1.5.5 rows plus the three the operator priced.
    assert_eq!(table.len(), 8);
}

/// A LANE THAT NAMES NO OPEN CLASS DERIVES THE 1.5.5 TABLE, ROW FOR ROW.
///
/// The guarantee the whole grammar rests on: the per-class map is defaulted, so a configuration
/// written before it existed derives the same five rows, in the same sequence, at the same
/// integers.
#[test]
fn a_lane_with_no_open_classes_derives_exactly_the_rows_it_always_did() {
    let with = RateTable::from_config(USD, Some(vec![(LANE, tiers().into())]), 7, 0);
    let without = RateTable::from_config(
        USD,
        Some(vec![(
            LANE,
            crate::rate::ConfiguredLane {
                tiers: tiers(),
                classes: std::collections::BTreeMap::new(),
            },
        )]),
        7,
        0,
    );
    assert_eq!(with.len(), 5);
    let a: Vec<_> = with.rows().collect();
    let b: Vec<_> = without.rows().collect();
    assert_eq!(a, b);
}

/// The card and the table agree about an OPEN class too, not only about the four tiers -- the same
/// identity the tier-by-tier test makes, extended to the rows the new grammar adds.
#[test]
fn the_table_and_the_card_price_an_open_class_identically() {
    let lanes = vec![(
        LANE,
        crate::rate::ConfiguredLane {
            tiers: tiers(),
            classes: open_classes(),
        },
    )];
    let table = RateTable::from_config(USD, Some(lanes.clone()), 7, 0);
    let card = RateCard::from_config_in(USD, Some(lanes), 7);
    let rates = card
        .lane_rates(LANE, USD)
        .expect("the card names this lane");
    for class in ["tool_calls", "bytes", "audio_seconds_in"] {
        assert_eq!(
            table.rate_at(LANE, class, USD, 0),
            Some(rates.nanos_per_unit(class)),
            "{class}: the table's row and the card's cell are one price"
        );
    }
}
