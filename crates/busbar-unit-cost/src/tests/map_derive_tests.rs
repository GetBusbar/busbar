// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MAP-SHAPED DERIVATION, PROVED AGAINST THE CARD IT WILL PRICE.**
//!
//! Every cell below is the retiring engine's own pricing cell, COPIED here verbatim in its
//! arithmetic and re-asked of this crate's card and this crate's derivation. That is deliberate and
//! it is the byte-identity proof: for the whole time both bodies exist, the same fourteen questions
//! are answered on both sides, and the day the engine's copy is deleted the answers do not move
//! because these already gave them. A deletion that removes the only cells covering an arithmetic is
//! a deletion that removed the arithmetic's proof with it; this file is what makes the engine's
//! removable.
//!
//! The two cells at the end of it are the DIVERGENCES the design named — the two places where the
//! engine's fold and this crate's are not the same text — each pinned as a cell that says exactly
//! why the difference cannot change a figure a deployment sees.

use std::collections::BTreeMap;

use crate::rate::RESERVED_CLASSES;
use crate::tests::{CACHE_READ, CACHE_WRITE, INPUT, OUTPUT};
use crate::{
    derive_spend_micros_units, derive_spend_minor_units, CurrencyCode, LaneClass, RateCard,
    TierRates,
};

/// A card resolved the way a deployment's is: through [`RateCard::from_config`], over per-lane
/// [`TierRates`], which is the exact constructor the retiring engine relays its configured
/// `rate_card:` section into. Nothing here reaches a constructor production cannot.
fn card(entries: &[(&str, f64, f64)]) -> RateCard {
    card4(
        &entries
            .iter()
            .map(|(m, i, o)| (*m, [*i, *o, 0.0, 0.0]))
            .collect::<Vec<_>>(),
    )
}

/// The same, naming all four reserved rates.
fn card4(entries: &[(&str, [f64; 4])]) -> RateCard {
    RateCard::from_config(
        Some(entries.iter().map(|(m, r)| {
            (
                *m,
                TierRates {
                    input: r[0],
                    output: r[1],
                    cache_read: r[2],
                    cache_write: r[3],
                },
            )
        })),
        0,
    )
}

/// A card that is not there, with a flat per-request fee.
fn absent(fee: i64) -> RateCard {
    RateCard::absent(fee)
}

/// A name-keyed reserved-four quantity map — the shape a 1.5.5 ledger row stores. Zero classes are
/// omitted, which is the row's own sparse invariant.
fn toks4(input: u64, output: u64, cache_read: u64, cache_write: u64) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for (k, v) in [
        (INPUT, input),
        (OUTPUT, output),
        (CACHE_READ, cache_read),
        (CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            m.insert(k.to_string(), v);
        }
    }
    m
}

fn toks(input: u64, output: u64) -> BTreeMap<String, u64> {
    toks4(input, output, 0, 0)
}

/// The cent derivation, at the currency a 1.5.5 deployment's figures are in.
fn cents<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a BTreeMap<String, u64>)>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    derive_spend_minor_units(
        card,
        CurrencyCode::USD,
        lanes,
        fee_requests,
        include_request_fee,
    )
}

/// The micro projection of the same sum.
fn micros<'a>(
    card: &RateCard,
    lanes: impl Iterator<Item = (&'a str, &'a BTreeMap<String, u64>)>,
    fee_requests: u64,
    include_request_fee: bool,
) -> i64 {
    derive_spend_micros_units(
        card,
        CurrencyCode::USD,
        lanes,
        fee_requests,
        include_request_fee,
    )
}

// ── the fourteen ─────────────────────────────────────────────────────────────────────────────────

/// ABSENT rate card => token pricing is 0 for every lane; only the flat per-request fee counts.
/// The all-or-nothing OFF arm.
#[test]
fn absent_rate_card_prices_tokens_at_zero() {
    let c = absent(3);
    assert!(!c.pricing_enabled());
    assert!(!c.lane_unpriced("anything"), "no card = nothing to miss");
    let t = toks(1_000_000, 1_000_000);
    assert_eq!(
        cents(&c, [("anything", &t)].into_iter(), 5, true),
        15,
        "tokens derive to 0; 5 requests x 3c fee remain"
    );
}

/// PRESENT rate card: derivation is integer nano-unit math over the class split. gpt-5 at 2.5 utok
/// input / 10 utok output: 1M input + 1M output = 2.5 + 10 units = 1250 cents.
#[test]
fn present_rate_card_derives_integer_spend() {
    let c = card(&[("gpt-5", 2.5, 10.0)]);
    assert!(c.pricing_enabled());
    let t = toks(1_000_000, 1_000_000);
    assert_eq!(cents(&c, [("gpt-5", &t)].into_iter(), 0, false), 1250);
    // Micro projection: 12.5 units = 12_500_000 micro-units.
    assert_eq!(
        micros(&c, [("gpt-5", &t)].into_iter(), 0, false),
        12_500_000
    );
}

/// Sub-micro precision survives the nano scale: 3.125 utok/token x 8 tokens = 25 micro-units
/// exactly (no truncation at the micro boundary).
#[test]
fn nano_scale_keeps_sub_micro_precision() {
    let c = card4(&[("m", [3.125, 0.0, 0.0, 0.0])]);
    let t = toks(8, 0);
    assert_eq!(micros(&c, [("m", &t)].into_iter(), 0, false), 25);
}

/// A lane NOT in a present card is UNPRICED (the admission path rejects it), and the derive path
/// prices it at 0 — the only way such a row exists is a ledger written under a previous config.
#[test]
fn unknown_lane_with_card_is_unpriced_and_derives_zero() {
    let c = card(&[("gpt-5", 1.0, 1.0)]);
    assert!(c.lane_unpriced("mystery-model"));
    assert!(!c.lane_unpriced("gpt-5"));
    let t = toks(1_000_000, 0);
    assert_eq!(cents(&c, [("mystery-model", &t)].into_iter(), 0, false), 0);
}

/// REPRICE-ON-READ: the ledger (quantities) is fixed; deriving under a corrected card yields the
/// corrected spend — there is no stored amount to migrate.
#[test]
fn reprice_on_read_recomputes_derived_spend() {
    let t = toks(1_000_000, 0);
    let wrong = card(&[("m", 10.0, 0.0)]);
    let fixed = card(&[("m", 5.0, 0.0)]);
    assert_eq!(cents(&wrong, [("m", &t)].into_iter(), 0, false), 1000);
    assert_eq!(
        cents(&fixed, [("m", &t)].into_iter(), 0, false),
        500,
        "same quantities, corrected rate: derived spend halves on the next read"
    );
}

/// A cent total past `i64::MAX` SATURATES at `i64::MAX` (fail-closed: an astronomical ledger
/// blocks). A wrapping cast would land NEGATIVE, be floored to 0, and derive as FREE — bypassing
/// every budget cap.
#[test]
fn derive_spend_cents_saturates_never_wraps_free() {
    // 1e15 micro-units/token -> 1e18 nano-units/token; x u64::MAX tokens ~= 1.8e37 nanos
    // -> ~1.8e30 cents, far past i64::MAX.
    let c = card(&[("m", 1e15, 0.0)]);
    let t = toks(u64::MAX, 0);
    assert_eq!(
        cents(&c, [("m", &t)].into_iter(), 0, false),
        i64::MAX,
        "an over-i64 cent total must pin at i64::MAX (blocks), never wrap toward 0 (free)"
    );
    assert_eq!(micros(&c, [("m", &t)].into_iter(), 0, false), i64::MAX);
}

/// EACH CLASS AGAINST ITS OWN RATE — cache-read quantities at the cache-read rate, cache-write at
/// the cache-write rate, never swapped. Cache-write is typically 8x cache-read, so a transposed
/// mapping would over- or under-bill every cached request; the counts are chosen so any swap of two
/// classes changes the total.
#[test]
fn four_class_card_prices_each_class_against_its_own_rate() {
    let c = card4(&[(
        "quad",
        [
            1.0, // 1000 nano/unit
            2.0, // 2000
            0.5, //  500
            4.0, // 4000
        ],
    )]);
    let t = toks4(
        10_000_000, // 10_000_000_000 nanos
        1_000_000,  //  2_000_000_000
        2_000_000,  //  1_000_000_000
        500_000,    //  2_000_000_000
    );
    // sum 15_000_000_000 nanos / 10_000_000 = 1500 cents exactly.
    assert_eq!(
        cents(&c, [("quad", &t)].into_iter(), 0, false),
        1500,
        "each class must bill against its own rate; a swapped cache_read/cache_write mapping changes this"
    );
    let r = c.lane_rates("quad", CurrencyCode::USD).unwrap();
    assert_eq!(
        (
            r.nanos_per_unit(INPUT),
            r.nanos_per_unit(OUTPUT),
            r.nanos_per_unit(CACHE_READ),
            r.nanos_per_unit(CACHE_WRITE)
        ),
        (1_000, 2_000, 500, 4_000),
        "nano rates carry all four classes straight from the card"
    );
}

/// The cent derivation is an INTEGER DIVISION and TRUNCATES toward zero — a sub-cent remainder is
/// dropped, never rounded UP. 19_999 units at 1 utok = 1.9999 cents must derive to 1, not 2.
#[test]
fn cent_derivation_truncates_toward_zero_never_rounds_up() {
    let c = card(&[("m", 1.0, 0.0)]);
    assert_eq!(
        cents(&c, [("m", &toks(19_999, 0))].into_iter(), 0, false),
        1,
        "1.9999 cents must floor to 1, not round up to 2"
    );
    assert_eq!(
        cents(&c, [("m", &toks(20_000, 0))].into_iter(), 0, false),
        2,
        "exactly 2.0 cents is 2"
    );
    assert_eq!(
        cents(&c, [("m", &toks(20_001, 0))].into_iter(), 0, false),
        2,
        "2.0001 cents still floors to 2"
    );
}

/// Two lanes billed into ONE bucket accumulate NANOS first and divide to cents ONCE. Two lanes each
/// contributing half a cent sum to a whole cent; a per-lane floor would drop each to 0 and silently
/// under-charge every multi-lane bucket.
#[test]
fn sub_cent_contributions_across_lanes_sum_before_flooring() {
    // 5 utok/unit = 5000 nano/unit; 1000 units = 5_000_000 nanos = 0.5 cent each.
    let c = card(&[("a", 5.0, 0.0), ("b", 5.0, 0.0)]);
    let ta = toks(1_000, 0);
    let tb = toks(1_000, 0);
    assert_eq!(
        cents(&c, [("a", &ta)].into_iter(), 0, false),
        0,
        "one 0.5-cent lane alone floors to 0"
    );
    assert_eq!(
        cents(&c, [("a", &ta), ("b", &tb)].into_iter(), 0, false),
        1,
        "two 0.5-cent lanes sum to a whole cent — nanos accumulate before the single divide"
    );
}

/// A lane priced EXPLICITLY at zero (all four classes 0.0 in a present card) is a KNOWN lane that
/// derives 0 for any volume — distinct from an UNKNOWN lane (missing entry).
#[test]
fn explicit_zero_rate_lane_is_known_and_derives_zero() {
    let c = card4(&[("freebie", [0.0, 0.0, 0.0, 0.0])]);
    assert!(c.pricing_enabled());
    assert!(
        !c.lane_unpriced("freebie"),
        "an all-zero entry is present, not missing"
    );
    let t = toks4(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(
        cents(&c, [("freebie", &t)].into_iter(), 0, false),
        0,
        "a zero-rated lane bills nothing regardless of volume"
    );
}

/// A PARTIAL card: `lane_unpriced` is true ONLY for the missing lane, and a mixed derivation prices
/// the KNOWN lane and contributes 0 for the missing one — never a panic, and never the missing lane
/// priced by a sibling's rate.
#[test]
fn partial_card_prices_known_lanes_and_zeroes_the_missing_one() {
    let c = card(&[("priced", 2.0, 0.0)]);
    assert!(!c.lane_unpriced("priced"));
    assert!(c.lane_unpriced("absent"));
    let known = toks(1_000_000, 0); // 2 utok * 1M = 200 cents
    let missing = toks(9_999_999, 0);
    assert_eq!(
        cents(
            &c,
            [("priced", &known), ("absent", &missing)].into_iter(),
            0,
            false
        ),
        200,
        "only the priced lane contributes; the missing one derives 0"
    );
}

/// The flat per-request fee is `per_request_fee * fee_requests`, added ONLY when asked for. Both
/// the multiply and the add SATURATE, so a huge billable count can never wrap the fee negative
/// (which the floor would then turn into 0, billing an over-cap bucket as FREE).
#[test]
fn flat_fee_saturates_and_is_gated_by_the_flag() {
    let c = absent(i64::MAX);
    let z = toks(0, 0);
    assert_eq!(
        cents(&c, [("m", &z)].into_iter(), u64::MAX, true),
        i64::MAX,
        "i64::MAX fee * u64::MAX requests must pin at i64::MAX, never wrap toward 0"
    );
    assert_eq!(
        cents(&c, [("m", &z)].into_iter(), u64::MAX, false),
        0,
        "with include_request_fee=false the flat fee contributes nothing"
    );
}

/// A NEGATIVE configured per-request fee is clamped to 0 at resolve, so no request can ever be
/// billed a negative amount that would CREDIT a budget bucket back toward headroom.
#[test]
fn negative_per_request_fee_clamps_to_zero() {
    let c = absent(-5);
    assert_eq!(
        c.fee_schedule(CurrencyCode::USD)
            .map_or(0, |s| s.transaction_minor),
        0
    );
    assert_eq!(
        cents(&c, [("m", &toks(0, 0))].into_iter(), 100, true),
        0,
        "a negative fee must never credit a bucket: 100 requests at a clamped-0 fee is 0"
    );
}

/// The MICRO projection's flat-fee component is `cents * 10_000 * requests`, added only when asked
/// for — pinned against the cent-scale fee so the finer projection can never drift from the
/// ledger's cents.
#[test]
fn micro_projection_fee_is_cents_times_ten_thousand() {
    let c = absent(3);
    let z = toks(0, 0);
    // 3 cents/request * 5 requests = 15 cents = 150_000 micro-units.
    assert_eq!(micros(&c, [("m", &z)].into_iter(), 5, true), 150_000);
    assert_eq!(
        cents(&c, [("m", &z)].into_iter(), 5, true),
        15,
        "the same fee in cents is 15 — the micro projection is exactly 10_000x"
    );
    assert_eq!(
        micros(&c, [("m", &z)].into_iter(), 5, false),
        0,
        "flag off: no fee in the micro projection either"
    );
}

/// BUDGET-CAP BOUNDARY, in the exact cents the admission decision compares (`derived >= cap`): a
/// quantity chosen to land the derived spend EXACTLY on an integer cap derives to precisely that
/// integer, and a larger one derives strictly above it.
#[test]
fn derived_spend_lands_exactly_on_an_integer_budget_cap() {
    // 1 utok = 1000 nano/unit; 1_000_000 units = 1_000_000_000 nanos = 100 cents exactly.
    let c = card(&[("m", 1.0, 0.0)]);
    assert_eq!(
        cents(&c, [("m", &toks(1_000_000, 0))].into_iter(), 0, false),
        100,
        "spend lands exactly on the integer cap value the budget check compares against"
    );
    assert_eq!(
        cents(&c, [("m", &toks(1_010_000, 0))].into_iter(), 0, false),
        101,
        "one full cent more of quantity derives strictly above the cap"
    );
}

// ── the two divergences ──────────────────────────────────────────────────────────────────────────

/// **DIVERGENCE 1, AND WHY IT CANNOT BE REACHED: OPEN CLASSES.**
///
/// The retiring engine's fold prices the RESERVED FOUR and stops. This crate's line-shaped fold
/// ([`crate::LaneRates::nanos`]) prices every class a report carries, open ones included. The two
/// therefore disagree — for a card that names an open class.
///
/// No configured card does. The only constructors a deployment reaches are
/// [`RateCard::from_config`] and its currency-carrying spelling, and both fan a lane's
/// [`TierRates`] out over exactly [`RESERVED_CLASSES`]; the one way to price a fifth class is
/// [`RateCard::set_rate`], and nothing outside a test calls it. So the map fold's narrowing to the
/// reserved four is not a policy difference from the line fold, it is the same answer on every card
/// that exists.
///
/// This cell pins BOTH halves, because a claim of the form "they agree because the other case
/// cannot arise" is worth exactly as much as its second clause: a `from_config` card prices an open
/// class at zero through both folds, and a `set_rate` card is the one place they part company. The
/// day something in production reaches `set_rate`, the second assertion is the record of what that
/// change costs.
#[test]
fn open_class_prices_only_through_set_rate() {
    const OPEN: &str = "audio_seconds";
    let mut units = toks(1_000, 0);
    units.insert(OPEN.to_string(), 1_000);

    // A CONFIGURED card: the open class is not on it, so it prices at nothing — and the reserved
    // fold and a full fold over the same card agree to the byte.
    let configured = card(&[("m", 1.0, 0.0)]);
    let lane = configured.lane_rates("m", CurrencyCode::USD).unwrap();
    assert_eq!(
        lane.nanos_per_unit(OPEN),
        0,
        "from_config names four classes"
    );
    assert_eq!(
        lane.reserved_units_nanos(&units),
        1_000_000,
        "1_000 units at 1000 nanos; the open class contributes nothing"
    );
    assert_eq!(
        lane.nanos(&crate::tests::lines(&[(INPUT, 1_000), (OPEN, 1_000)])),
        1_000_000,
        "the line fold over the same card agrees: an unnamed class is a zero rate"
    );

    // A `set_rate` card is the ONLY way the two part company, and nothing in production builds one.
    let mut open_priced = configured.clone();
    open_priced.set_rate(LaneClass::new("m", OPEN), CurrencyCode::USD, 5.0);
    let lane = open_priced.lane_rates("m", CurrencyCode::USD).unwrap();
    assert_eq!(
        lane.reserved_units_nanos(&units),
        1_000_000,
        "the map fold prices the reserved four and stops"
    );
    assert_eq!(
        lane.nanos(&crate::tests::lines(&[(INPUT, 1_000), (OPEN, 1_000)])),
        6_000_000,
        "the line fold prices the open class too — the whole of the divergence, unreachable from config"
    );
}

/// **DIVERGENCE 2, AND WHY IT IS A FIX RATHER THAN A CHANGE: PLAIN ADD vs SATURATING ADD.**
///
/// The retiring engine's fold accumulates with a plain `+`. This crate's accumulates with
/// `saturating_add`. BELOW THE ACCUMULATOR'S TOP THEY ARE THE SAME NUMBER — that is what makes the
/// substitution a byte-identity move for every figure any deployment has ever seen, and it is
/// asserted here across the boundaries rather than argued.
///
/// ABOVE it they differ, and the difference is the point: a plain add panics in a debug build and
/// WRAPS in a release one, landing a colossal ledger back near zero — an over-the-top spend
/// deriving as nearly free and escaping every budget cap. Saturating pins it at the top, which is an
/// astronomically over-cap figure that blocks. The second assertion is that fix, stated as the
/// behaviour it buys rather than as a note.
#[test]
fn saturating_add_matches_plain_add_below_overflow() {
    let c = card4(&[("m", [1.0, 2.0, 0.5, 4.0])]);
    let lane = c.lane_rates("m", CurrencyCode::USD).unwrap();

    // Below the top, the fold is a plain sum of four products and the two adds cannot differ.
    for quantities in [
        [0, 0, 0, 0],
        [1, 1, 1, 1],
        [19_999, 0, 0, 0],
        [10_000_000, 1_000_000, 2_000_000, 500_000],
        [
            u32::MAX as u64,
            u32::MAX as u64,
            u32::MAX as u64,
            u32::MAX as u64,
        ],
    ] {
        let units = toks4(quantities[0], quantities[1], quantities[2], quantities[3]);
        let plain: u128 = RESERVED_CLASSES
            .iter()
            .zip(quantities)
            .map(|(class, n)| u128::from(n) * u128::from(lane.nanos_per_unit(class)))
            .sum();
        assert_eq!(
            lane.reserved_units_nanos(&units),
            plain,
            "below overflow the saturating fold is the plain sum, to the byte"
        );
    }

    // Above it, four maximal products are past the top of the accumulator (1.8e16 micro-units is
    // 1.8e19 nano-units per unit, and that times u64::MAX is already most of a u128, so two of the
    // four exhaust it). Saturating pins; a plain add would wrap toward zero, which is the bug this
    // is the fix for.
    let huge = card4(&[("m", [1.8e16, 1.8e16, 1.8e16, 1.8e16])]);
    let lane = huge.lane_rates("m", CurrencyCode::USD).unwrap();
    let units = toks4(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(
        lane.reserved_units_nanos(&units),
        u128::MAX,
        "an over-u128 nano total pins at the top (blocks), never wraps toward 0 (free)"
    );
}
