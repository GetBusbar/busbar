// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ONE TEST.** A known ledger × a known card history → a known figure.
//!
//! The owner's acceptance criterion, in his words: *"money is just a function … one test and it
//! works or doesn't."* Everything else in this file is that test's supporting cast: the same
//! function asked whether it agrees with each of the implementations it replaces, and whether it
//! gives the CORRECT answer where those implementations disagree with each other.

use busbar_contract::count::Count;

use crate::cost::{
    derive_spend_cents, derive_spend_micros, price_exact, price_in_view, price_ledger, Author,
    CardEntryDraft, History, LaneClass, LedgerEntry, Money, MoneyError, RateCard, STANDARD_TIER_BP,
};

use super::{lines, CACHE_READ, INPUT, OUTPUT};

/// The lane every case below serves on.
const LANE: &str = "gpt-4o";

/// **CARD A**, in force from instant zero: input at 3 micro-units a token, output at 16, a flat fee
/// of 2 minor units a request.
fn card_a() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 3.0),
            (LaneClass::new(LANE, OUTPUT), 16.0),
        ],
        2,
    )
}

/// **CARD B**, appended effective from instant 1,000,000: input at 1, output at 4, a fee of 1.
fn card_b() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 1.0),
            (LaneClass::new(LANE, OUTPUT), 4.0),
        ],
        1,
    )
}

/// **THE KNOWN CARD HISTORY**: card A from zero, card B appended from instant 1,000,000.
///
/// This is the owner's worked example in miniature — a rate that was one thing and became another.
/// The first window keeps pricing at the first rate forever.
fn known_history() -> History {
    let mut history = History::opening(card_a(), 0);
    history.append(CardEntryDraft {
        effective_from: 1_000_000,
        effective_until: None,
        card: card_b(),
        appended_at: 1_000_000,
        author: Author::Config { policy_epoch: 1 },
    });
    history
}

/// **THE KNOWN LEDGER SLICE**: two rows of identical consumption, one on each side of the edit.
///
/// The output count is `27.5` and it is fractional on purpose (#81) — *"you spent 27.5 tokens not
/// 27 not 28"* — so the test would fail if any step of the path rounded a measurement or sent it
/// through a double.
fn known_ledger() -> Vec<LedgerEntry> {
    vec![
        LedgerEntry::new(LANE, 500_000)
            .with_whole(INPUT, 1_000)
            .with_count(OUTPUT, Count::parse("27.5").expect("27.5 is a decimal"))
            .with_fee_count(1),
        LedgerEntry::new(LANE, 2_000_000)
            .with_whole(INPUT, 1_000)
            .with_count(OUTPUT, Count::parse("27.5").expect("27.5 is a decimal"))
            .with_fee_count(1),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ONE TEST
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_known_ledger_times_a_known_card_history_is_a_known_figure() {
    let figure = price_ledger(&known_ledger(), &known_history())
        .expect("every line of the known slice is priced by the card in force at its own instant");

    // Derived by hand, and the arithmetic is small enough to check without a machine.
    //
    //   ROW 1, arrived 500,000 — card A is in force (card B starts at 1,000,000):
    //     input   1000    × 3 micro-units  =  3,000 micro-units
    //     output  27.5    × 16             =    440
    //     fee     1       × 2 minor units  = 20,000   (1 minor unit = 10,000 micro-units)
    //                                       ───────
    //                                        23,440
    //
    //   ROW 2, arrived 2,000,000 — card B is in force:
    //     input   1000    × 1              =  1,000
    //     output  27.5    × 4              =    110
    //     fee     1       × 1 minor unit   = 10,000
    //                                       ───────
    //                                        11,110
    //
    //   TOTAL                                34,550 micro-units  =  "0.034550"
    assert_eq!(figure.micros(), 34_550, "money = f(ledger, card history)");
    assert_eq!(figure.to_decimal_string(), "0.034550");
    // And in the whole minor units a 1.5.5 deployment's figures were read in: 3 (3.4550 truncates).
    assert_eq!(figure.minor(), 3);
}

#[test]
fn the_known_figure_is_exact_at_scale_six() {
    let exact =
        price_exact(&known_ledger(), &known_history().current()).expect("the known slice prices");
    // Nothing was dropped by the single projection: the scale-15 accumulator is a whole number of
    // scale-6 steps. A figure that cannot say this about itself is a figure with a rounding in it.
    assert_eq!(exact % 1_000_000_000, 0);
    assert_eq!(exact / 1_000_000_000, 34_550);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// #79 — PUBLISHING A CARD NEVER REPRICES THE WINDOW BEFORE ITS `effective_from`
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn publishing_a_card_leaves_every_prior_posting_byte_identical() {
    let before = History::opening(card_a(), 0);
    let row_one = &known_ledger()[..1];

    let priced_before = price_ledger(row_one, &before).expect("prices");
    let priced_after = price_ledger(row_one, &known_history()).expect("prices");

    assert_eq!(
        priced_before, priced_after,
        "#79: publishing reprices nothing"
    );
    assert_eq!(priced_before.micros(), 23_440);
}

#[test]
fn pricing_flat_at_the_newest_card_is_a_different_and_wrong_figure() {
    // THE DIVERGENCE, with numbers. `get_group_usage`, `GET /keys/{id}/usage` and the
    // `busbar_bucket_spend_cents` gauge price flat at whatever card is configured at the moment of
    // the read. Against this history that is card B for BOTH rows.
    let flat = History::opening(card_b(), 0);
    let flat_figure = price_ledger(&known_ledger(), &flat).expect("prices");

    assert_eq!(flat_figure.micros(), 22_220, "both rows at card B");
    assert_eq!(
        price_ledger(&known_ledger(), &known_history())
            .expect("prices")
            .micros(),
        34_550,
        "each row at the card in force when it arrived"
    );
    // 12,330 micro-units of the same consumption, unbilled, on every read that prices flat.
    assert_eq!(34_550 - flat_figure.micros(), 12_330);
}

#[test]
fn a_back_dated_correction_reprices_exactly_its_window_and_nothing_outside_it() {
    let mut history = known_history();
    // The sanctioned repair path (#79): an APPEND, signed, whose `effective_from` lies in the past
    // and whose window is closed. It covers row one's instant and not row two's.
    history.append(CardEntryDraft {
        effective_from: 400_000,
        effective_until: Some(600_000),
        card: RateCard::from_micro_rates(
            [
                (LaneClass::new(LANE, INPUT), 6.0),
                (LaneClass::new(LANE, OUTPUT), 32.0),
            ],
            2,
        ),
        appended_at: 9_000_000,
        author: Author::Amend {
            operator_fingerprint: "op".to_string(),
            reason_hash: [0u8; 32],
        },
    });

    let figure = price_ledger(&known_ledger(), &history).expect("prices");
    // Row one doubles on tokens (6,000 + 880 + 20,000 = 26,880); row two is untouched at 11,110.
    assert_eq!(figure.micros(), 26_880 + 11_110);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// #42 — A SILENT ZERO APPEARS ONLY WHEN NO RATE CARD IS CONFIGURED AT ALL
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_present_card_silent_about_the_lane_refuses() {
    let history = History::opening(card_a(), 0);
    let slice = vec![LedgerEntry::new("a-model-nobody-priced", 0).with_whole(OUTPUT, 1_000)];
    assert!(matches!(
        price_ledger(&slice, &history),
        Err(MoneyError::LaneUnpriced { .. })
    ));
}

#[test]
fn a_present_card_silent_about_a_hit_class_refuses() {
    // Card A prices `input` and `output`. A row reporting `cache_read` hit a class the card does
    // not name, and #42 says that REFUSES. Every reserved-four derivation in this tree instead
    // prices it at zero and says nothing.
    let history = History::opening(card_a(), 0);
    let slice = vec![LedgerEntry::new(LANE, 0).with_whole(CACHE_READ, 1_000_000)];
    assert!(matches!(
        price_ledger(&slice, &history),
        Err(MoneyError::ClassUnpriced { .. })
    ));
}

#[test]
fn an_open_meter_class_the_card_prices_is_charged_not_dropped() {
    // The classes a non-LLM plane declares — a2a `hops`, mcp `calls`, streaming `audio-seconds` —
    // are ordinary card entries here. The reserved-four derivations cannot see them at all.
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, OUTPUT), 2.0),
            (LaneClass::new(LANE, "hops"), 5.0),
        ],
        0,
    );
    let history = History::opening(card, 0);
    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(OUTPUT, 100)
        .with_whole("hops", 1_000)];
    // 100 × 2 + 1000 × 5 = 5,200 micro-units.
    assert_eq!(
        price_ledger(&slice, &history)
            .expect("both classes are priced")
            .micros(),
        5_200
    );
}

#[test]
fn no_card_at_all_is_billing_off_and_the_flat_fee_still_posts() {
    // The one circumstance in which a zero is the honest answer (#42): no rate card configured.
    // Tokens price at nothing; the configured fee still bills.
    let history = History::opening(RateCard::absent(2), 0);
    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(OUTPUT, 1_000_000)
        .with_fee_count(3)];
    assert_eq!(
        price_ledger(&slice, &history)
            .expect("an absent card prices everything at nothing")
            .micros(),
        60_000,
        "3 requests × 2 minor units = 60,000 micro-units, and no token charge"
    );
}

#[test]
fn a_hole_in_the_history_refuses_rather_than_costing_nothing() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 1_000,
        effective_until: None,
        card: card_a(),
        appended_at: 1_000,
        author: Author::Config { policy_epoch: 0 },
    });
    let slice = vec![LedgerEntry::new(LANE, 0).with_whole(OUTPUT, 1_000)];
    assert!(matches!(
        price_ledger(&slice, &history),
        Err(MoneyError::NoCardInForce { at: 0 })
    ));
}

/// **THE ONE FUNCTION TAKES NO DENOMINATION, SO NO READ CAN ASK FOR A SECOND SCALE.**
///
/// This stands where `a_currency_the_card_does_not_name_refuses_rather_than_converting` stood. That
/// case proved a cross-rate could not be invented; #66 (`BUSBAR-1.6.0.md:528`) removes the axis a
/// cross-rate needed, so the same slice against the same history is ONE figure, forever, with no
/// argument that could move it. Priced twice to say so.
#[test]
fn the_same_slice_against_the_same_history_is_one_figure_with_no_scale_to_choose() {
    let history = History::opening(card_a(), 0);
    let slice = vec![LedgerEntry::new(LANE, 0).with_whole(OUTPUT, 1_000)];
    let once = price_ledger(&slice, &history).expect("the card prices the lane");
    let twice = price_ledger(&slice, &history).expect("the card prices the lane");
    assert_eq!(once, twice);
    assert!(!once.is_zero(), "a real figure, not two zeros agreeing");
    // The minor projection has one divisor and it is the constant, not a parameter.
    assert_eq!(
        once.minor(),
        once.micros() / i128::from(crate::cost::MICROS_PER_CENT)
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// EQUIVALENCE — THE ONE FUNCTION EQUALS THE DERIVATIONS IT REPLACES, WHERE THOSE AGREE
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The conditions under which every implementation in the tree is supposed to answer the same
/// figure: one card, whole counts, the standard tier, a priced lane, every hit class priced.
#[test]
fn it_equals_the_legacy_micro_derivation_on_a_single_entry_history() {
    let card = super::card4(LANE, [3.0, 16.0, 0.5, 4.0], 2);
    let history = History::opening(card.clone(), 0);
    let usage = [(INPUT, 1_000u64), (OUTPUT, 250), (CACHE_READ, 7_000)];

    let legacy = derive_spend_micros(&card, [(LANE, &lines(&usage)[..])].into_iter(), 3, true)
        .expect("the one function prices");

    let slice = vec![usage
        .iter()
        .fold(LedgerEntry::new(LANE, 0), |e, (class, q)| {
            e.with_whole(*class, *q)
        })
        .with_fee_count(3)];
    let one = price_in_view(&slice, &history.current()).expect("prices");

    assert_eq!(
        i128::from(legacy),
        one.micros(),
        "the one function equals `derive_spend_micros` where the card is silent about nothing"
    );
}

#[test]
fn it_equals_the_legacy_cent_derivation_on_a_single_entry_history() {
    let card = super::card4(LANE, [3.0, 16.0, 0.5, 4.0], 2);
    let history = History::opening(card.clone(), 0);
    let usage = [(INPUT, 1_000_000u64), (OUTPUT, 250_000)];

    let legacy = derive_spend_cents(&card, [(LANE, &lines(&usage)[..])].into_iter(), 3, true)
        .expect("the one function prices");

    let slice = vec![usage
        .iter()
        .fold(LedgerEntry::new(LANE, 0), |e, (class, q)| {
            e.with_whole(*class, *q)
        })
        .with_fee_count(3)];
    let one = price_in_view(&slice, &history.current()).expect("prices");

    assert_eq!(i128::from(legacy), one.minor());
}

#[test]
fn it_equals_the_posting_lookup_on_the_same_quantities() {
    let card = super::card4(LANE, [3.0, 16.0, 0.5, 4.0], 2);
    let history = History::opening(card, 0);
    let usage = super::usage(&[(INPUT, 1_000), (OUTPUT, 250), (CACHE_READ, 7_000)]);
    let posting = crate::cost::Posting::from_usage(LANE, &usage, 3, STANDARD_TIER_BP, 0, 0);
    let lookup = crate::cost::price(&history.current(), &posting).expect("the lookup prices");

    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(INPUT, 1_000)
        .with_whole(OUTPUT, 250)
        .with_whole(CACHE_READ, 7_000)
        .with_fee_count(3)];
    let one = price_in_view(&slice, &history.current()).expect("prices");

    assert_eq!(i128::from(lookup.micros()), one.micros());
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE PROPERTIES THE ONE FUNCTION IS SUPPOSED TO HAVE
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_total_does_not_depend_on_the_order_the_rows_arrived_in() {
    let history = known_history();
    let mut forward = known_ledger();
    forward.push(
        LedgerEntry::new(LANE, 1_500_000)
            .with_count(OUTPUT, Count::parse("0.000001").expect("a decimal"))
            .with_fee_count(0),
    );
    let mut reversed = forward.clone();
    reversed.reverse();

    assert_eq!(
        price_exact(&forward, &history.current()),
        price_exact(&reversed, &history.current()),
    );
}

#[test]
fn a_fraction_of_a_micro_unit_is_kept_across_lines_not_floored_per_line() {
    // Two lines each worth half a micro-unit make one micro-unit. A per-line projection would floor
    // both to nothing and undercharge every row that used more than one class.
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 0.5),
            (LaneClass::new(LANE, OUTPUT), 0.5),
        ],
        0,
    );
    let history = History::opening(card, 0);
    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(INPUT, 1)
        .with_whole(OUTPUT, 1)];
    assert_eq!(price_ledger(&slice, &history).expect("prices").micros(), 1);
}

#[test]
fn a_seconds_reading_where_milliseconds_belong_resolves_to_the_wrong_card() {
    // THE HAZARD, PINNED. `effective_from` is in milliseconds. A caller handing this field a
    // seconds reading resolves against the from-zero opening entry and reports it forever — the
    // failure would pass a "reads a history" review, so it is asserted rather than commented.
    let history = known_history();
    let ms = vec![LedgerEntry::new(LANE, 2_000_000).with_whole(OUTPUT, 1_000)];
    let secs = vec![LedgerEntry::new(LANE, 2_000).with_whole(OUTPUT, 1_000)];

    assert_eq!(
        price_ledger(&ms, &history).expect("prices").micros(),
        4_000,
        "card B, correctly"
    );
    assert_eq!(
        price_ledger(&secs, &history).expect("prices").micros(),
        16_000,
        "card A, because 2,000 milliseconds is before card B's instant"
    );
}

#[test]
fn an_overflowing_total_refuses_rather_than_saturating() {
    // A rate that still fits the integer nano-unit rate (1e16 micro-units a token is 1e19
    // nano-units, inside `u64`), against a count near the top of the range.
    let card = RateCard::from_micro_rates([(LaneClass::new(LANE, OUTPUT), 1.0e16)], 0);
    let history = History::opening(card, 0);
    let huge = Count::from_micros(i128::MAX / 2);
    let slice = vec![LedgerEntry::new(LANE, 0).with_count(OUTPUT, huge)];
    assert_eq!(
        price_ledger(&slice, &history),
        Err(MoneyError::Overflow),
        "a saturated total is a wrong total that looks like a right one"
    );
}

#[test]
fn money_spells_itself_without_a_float() {
    assert_eq!(Money::from_micros(34_510).to_decimal_string(), "0.034510");
    assert_eq!(
        Money::from_micros(1_000_000).to_decimal_string(),
        "1.000000"
    );
    assert_eq!(Money::from_micros(-1).to_decimal_string(), "-0.000001");
    assert_eq!(Money::ZERO.to_decimal_string(), "0.000000");
}
