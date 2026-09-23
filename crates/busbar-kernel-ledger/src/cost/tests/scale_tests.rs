// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ONE SCALE**, and the fact that nothing can name a second one.
//!
//! This file replaces `currency_tests.rs`. #66 (`BUSBAR-1.6.0.md:528`, owner-locked) rules that
//! money is UNITLESS abstract cost with no currency type and no symbol, and the owner restated it
//! on 2026-09-23: *"currency is just a label … 1.50 is it. not label. thats a display issue for
//! user."* The deleted file asserted the opposite — that a card prices one cell in several
//! currencies natively, and that each currency truncates at its own divisor.
//!
//! **Every figure this file asserts is a figure the deleted file already asserted at USD**, which
//! was the only scale any deployment ever read at: `minor_of`'s boundaries, the cent projection,
//! the explicit-zero fee's `0.005000` and the named fee's `0.125000` are carried over unchanged.
//! The rows that moved were the ones that asked for a SECOND scale, and a second scale is exactly
//! what #66 removes.

use super::*;
use crate::cost::{
    micros_of, minor_of, LaneClass, RateCard, MICROS_PER_CENT, NANOS_PER_CENT, NANOS_PER_MICRO,
    STANDARD_TIER_BP,
};

/// **THE SCALE IS A CONSTANT, NOT A CHOICE.** Ten million nano-units to one minor unit, which is
/// the divisor every 1.5.5 cent projection used — so every figure that release produced comes out
/// of this tree bit-identical.
///
/// There is no argument, no table and no lookup that could answer differently. That is the property
/// the deleted `minor_exponent` table did NOT have: it answered 0 for JPY and 3 for BHD, so the
/// same rate figures on the same card became a hundred times more or less money depending on a
/// three-letter string a request body could carry.
#[test]
fn the_one_scale_is_ten_million_nanos_and_nothing_can_name_another() {
    assert_eq!(NANOS_PER_CENT, 10_000_000);
    // The three scale constants are one statement, not three: a micro-unit is a thousand
    // nano-units and a minor unit is ten thousand micro-units.
    assert_eq!(NANOS_PER_MICRO, 1_000);
    assert_eq!(
        i64::try_from(NANOS_PER_CENT / NANOS_PER_MICRO).expect("the ratio fits"),
        MICROS_PER_CENT
    );
}

/// **ONE TRUNCATION, AT THE ONE DIVISOR, AT THE BOUNDARY.** Carried over verbatim from the deleted
/// file's USD rows: just under, exactly at, and just over two minor units; the floor; and the
/// saturation that stops an over-the-top ledger wrapping negative and billing as free.
#[test]
fn the_minor_projection_truncates_once_at_the_one_boundary() {
    assert_eq!(minor_of(19_999_999), 1);
    assert_eq!(minor_of(20_000_000), 2);
    assert_eq!(minor_of(20_000_001), 2);
    assert_eq!(minor_of(2_000_000_000), 200);

    // The micro projection is a scale of the ACCUMULATOR, not of the minor unit, and it is still
    // unfloored where the minor projection floors.
    assert_eq!(micros_of(2_000_000_000), 2_000_000);
    assert_eq!(minor_of(u128::MAX), i64::MAX, "saturates, never wraps");
}

/// The legacy cent spelling and the minor projection are ONE function. They were the same function
/// at USD before #66 and they are the same function outright now; if they ever stopped being,
/// every 1.5.5 figure would move.
#[test]
fn the_cent_projection_is_the_minor_projection() {
    for nanos in [0u128, 1, 9_999_999, 10_000_000, 123_456_789, u128::MAX] {
        assert_eq!(crate::cost::cents_of(nanos), minor_of(nanos));
    }
}

/// **A FEE IS ALWAYS A FIGURE, NEVER A SILENCE** — #77(5) (`BUSBAR-1.6.0.md:420`): *"free is an
/// EXPLICIT zero row, never silent"*.
///
/// The defect the deleted file guarded was a card that named a currency for its RATES and was
/// silent about the FEE in it: the fee came out of a map that did not hold the key, was read as
/// zero, and every request's fees billed at nothing with nothing said. #66 removed the axis that
/// hole lived on. A card now carries exactly one fee, every constructor sets it, and there is no
/// key that can be absent — so the silence is IMPOSSIBLE rather than merely refused, which is the
/// stronger of the two postures.
///
/// **The two figures are the deleted file's, unchanged**: `0.005000` for the zero-fee card and
/// `0.125000` for the same card with the fee named.
#[test]
fn a_fee_of_nothing_is_an_explicit_zero_row_and_a_named_fee_bills() {
    use crate::cost::{price_ledger, LedgerEntry};

    let slice = vec![LedgerEntry::new("m", 0)
        .with_whole(INPUT, 1_000)
        .with_fee_count(4)];

    // THE EXPLICIT-FREE CONTROL: a fee CONFIGURED at zero is legitimately free and must price, not
    // refuse. Without this arm a rule that refused everything would satisfy the arm below.
    let mut free = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 0);
    free.set_fee(0);
    assert_eq!(free.fee(), 0);
    let priced_free = price_ledger(&slice, &History::opening(free, 0))
        .expect("an explicit zero fee row is free, not unpriced");
    assert_eq!(priced_free.to_decimal_string(), "0.005000");

    // And the same card with the fee named bills it — the money the old silence gave away.
    let mut charged = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 0);
    charged.set_fee(3);
    assert_eq!(charged.fee(), 3);
    let priced_fee =
        price_ledger(&slice, &History::opening(charged, 0)).expect("the card names a fee");
    assert_eq!(priced_fee.to_decimal_string(), "0.125000");

    // A NEGATIVE configured fee clamps at resolve, once, and can never credit a budget back
    // toward headroom.
    let mut negative = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 0);
    negative.set_fee(-7);
    assert_eq!(negative.fee(), 0);
    assert_eq!(RateCard::absent(-7).fee(), 0);
}

/// **BILLING OFF IS THE ONE EXEMPTION** (#42 `BUSBAR-1.6.0.md:367`: *"rate_card ABSENT ⇒ NOT billed
/// … A silent 0 is ONLY ever returned when rate_card is absent"*).
///
/// It exempts the TOKENS and not the flat fee: an uncarded node prices every class at nothing and
/// still posts the fee it configured, which is exactly what such a deployment is billed. Both arms
/// are asserted, because a rule that zeroed everything and a rule that zeroed only the tokens read
/// the same on a card whose fee is zero.
#[test]
fn an_absent_card_prices_tokens_at_nothing_and_still_posts_its_fee() {
    use crate::cost::{price_ledger, LedgerEntry};

    let slice = vec![LedgerEntry::new("m", 0)
        .with_whole(INPUT, 1_000)
        .with_fee_count(4)];

    let carded = RateCard::absent(0);
    assert!(!carded.pricing_enabled());
    let nothing = price_ledger(&slice, &History::opening(carded, 0))
        .expect("billing off answers zero rather than refusing");
    assert!(nothing.is_zero(), "an uncarded node bills no tokens");

    // Four fees at three minor units: 4 × 3 × 10_000_000 nano-units, read out at micro scale.
    let with_fee = RateCard::absent(3);
    let fee_only = price_ledger(&slice, &History::opening(with_fee, 0))
        .expect("billing off still posts the flat fee");
    assert_eq!(fee_only.to_decimal_string(), "0.120000");
}

/// The read posture and the settlement posture agree on a priced card, and the whole answer is the
/// one scale applied once. The same figures the deleted file asserted for its USD read.
#[test]
fn a_priced_card_reads_and_settles_at_the_one_scale() {
    // 1000 units at 2.0 micro-units each is 2_000_000 nano-units; three minor units of fee is
    // 30_000_000 nano-units at ten million a minor unit.
    let card = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 2.0)], 3);
    let report = usage(&[(INPUT, 1_000)]);
    let read = priced(&card, "m", &report, 1, STANDARD_TIER_BP);
    assert_eq!(read.pre_tier_nanos, 2_000_000 + 30_000_000);
    assert_eq!(read.minor(), 3);
    assert!(read.unpriced_classes().is_empty());

    let history = History::opening(card, 0);
    let posting = Posting::from_usage("m", &report, 1, STANDARD_TIER_BP, 0, 0);
    let settled = crate::cost::price_fail_closed(&history.current(), &posting)
        .expect("a fully priced card settles");
    assert_eq!(settled.priced_nanos, read.priced_nanos);
}
