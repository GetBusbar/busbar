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
//! was the only scale any deployment ever read at: the minor projection's boundaries, the cent projection,
//! the explicit-zero fee's `0.005000` and the named fee's `0.125000` are carried over unchanged.
//! The rows that moved were the ones that asked for a SECOND scale, and a second scale is exactly
//! what #66 removes.

use super::fixtures::*;
use busbar_kernel_ledger::cost::{History, LaneClass, Posting, RateCard, STANDARD_TIER_BP};

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
    assert_eq!(minor(&read), 3);
    assert!(read.unpriced_classes().is_empty());

    let history = History::opening(card, 0);
    let posting = Posting::from_usage("m", &report, 1, STANDARD_TIER_BP, 0, 0);
    let settled = busbar_kernel_ledger::cost::price_fail_closed(&history.current(), &posting)
        .expect("a fully priced card settles");
    assert_eq!(settled.priced_nanos, read.priced_nanos);
}
