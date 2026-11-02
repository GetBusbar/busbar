// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::fixtures::*;
use busbar_kernel_ledger::cost::{
    price, Author, CardEntryDraft, History, HistorySeq, LaneClass, Posting, RateCard,
    STANDARD_TIER_BP,
};

#[test]
fn an_appended_entry_prices_later_instants_and_moves_nothing_earlier() {
    let at_boot = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 10.0)], 0);
    let corrected = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 0);

    let mut history = History::opening(at_boot, 0);
    assert_eq!(history.head(), Some(HistorySeq(0)));
    let second = history.append(CardEntryDraft {
        effective_from: 5_000,
        effective_until: None,
        card: corrected,
        appended_at: 5_000,
        author: Author::Config { policy_epoch: 1 },
    });
    assert_eq!(
        second,
        HistorySeq(1),
        "the seq is dense and assigned on append"
    );

    let report = usage(&[(INPUT, 1_000_000)]);
    let before = Posting::from_usage("m", &report, 0, STANDARD_TIER_BP, 4_999, 4_999);
    let after = Posting::from_usage("m", &report, 0, STANDARD_TIER_BP, 5_000, 5_000);

    let view = history.current();
    let earlier = price(&view, &before).expect("entry zero covers it");
    let later = price(&view, &after).expect("entry one covers it");
    assert_eq!(earlier.card_seq, HistorySeq(0));
    assert_eq!(
        minor(&earlier),
        1000,
        "the unit that arrived first did not move"
    );
    assert_eq!(later.card_seq, HistorySeq(1));
    assert_eq!(
        minor(&later),
        500,
        "the unit that arrived after pays the new rate"
    );

    let at_zero = history.snapshot(HistorySeq(0));
    assert_eq!(
        minor(&price(&at_zero, &after).expect("entry zero is open-ended")),
        1000,
        "a snapshot taken before the edit cannot see the edit"
    );
}

#[test]
fn the_spend_fold_refuses_an_overflow() {
    let card = card4("m", [1e15; 4], 0);
    let history = History::opening(card, 0);
    let counts = [
        (INPUT, u64::MAX),
        (OUTPUT, u64::MAX),
        (CACHE_READ, u64::MAX),
        (CACHE_WRITE, u64::MAX),
    ];
    let posting = Posting::from_usage("m", &usage(&counts), 0, STANDARD_TIER_BP, 0, 0);
    assert_eq!(
        price(&history.current(), &posting),
        Err(busbar_kernel_ledger::cost::Unpriceable::Overflow),
        "the settlement lookup's figure is the spend fold's: an overflow refuses"
    );
    let entry = counts.iter().fold(
        busbar_kernel_ledger::cost::LedgerEntry::new("m", 0),
        |e, (c, q)| e.with_whole(*c, *q),
    );
    assert_eq!(
        busbar_kernel_ledger::cost::price_exact(&[entry], &history.current()),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "the read refuses the same consumption"
    );
}
