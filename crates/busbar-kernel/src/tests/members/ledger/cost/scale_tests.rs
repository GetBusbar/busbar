// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::fixtures::*;
use busbar_kernel_ledger::cost::{History, LaneClass, Posting, RateCard, STANDARD_TIER_BP};

#[test]
fn a_priced_card_reads_and_settles_at_the_one_scale() {
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
