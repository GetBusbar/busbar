// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated history and the lookup over it: appending never rewrites, the resolution rule takes
//! the highest covering seq, a snapshot answers the same way forever, a hole is a refusal, and a
//! cached figure never wins over a lookup.

use super::fixtures::*;
use busbar_kernel_ledger::cost::{
    price, price_fail_closed, Author, CachedPrice, CardEntryDraft, History, HistorySeq, LaneClass,
    Posting, RateCard, Unpriceable, STANDARD_TIER_BP,
};

/// A card pricing one class on one lane at a named rate.
fn card_at(micro: f64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", INPUT), micro)], 0)
}

/// A history with three entries: the opening one, an ordinary edit, and a back-dated amendment that
/// overlaps both. Written once because every resolution case reads it.
fn overlapping_history() -> History {
    let mut history = History::opening(card_at(1.0), 0);
    history.append(CardEntryDraft {
        effective_from: 100,
        effective_until: None,
        card: card_at(2.0),
        appended_at: 100,
        author: Author::Config { policy_epoch: 1 },
    });
    history.append(CardEntryDraft {
        effective_from: 50,
        effective_until: Some(150),
        card: card_at(3.0),
        appended_at: 900,
        author: Author::Amend {
            operator_fingerprint: "op-1".to_string(),
            reason_hash: [7u8; 32],
        },
    });
    history
}

/// **APPEND-ONLY.** Appending assigns the next dense seq and touches nothing that is already there:
/// every earlier entry's seq, interval, card, write time and author are the same objects afterwards
/// as before. A history that closed the previous open entry on append would fail this, which is why
/// it does not close it — the resolution rule makes closing unnecessary.
#[test]
fn appending_assigns_the_next_seq_and_rewrites_nothing() {
    let mut history = History::opening(card_at(1.0), 42);
    let snapshot_before: Vec<(HistorySeq, u64, Option<u64>, u64)> = history
        .entries()
        .iter()
        .map(|e| {
            (
                e.seq(),
                e.effective_from(),
                e.effective_until(),
                e.appended_at(),
            )
        })
        .collect();

    let seq = history.append(CardEntryDraft {
        effective_from: 100,
        effective_until: None,
        card: card_at(2.0),
        appended_at: 100,
        author: Author::Config { policy_epoch: 1 },
    });
    assert_eq!(seq, HistorySeq(1));
    assert_eq!(history.head(), Some(HistorySeq(1)));
    assert_eq!(history.len(), 2);

    let snapshot_after: Vec<(HistorySeq, u64, Option<u64>, u64)> = history.entries()[..1]
        .iter()
        .map(|e| {
            (
                e.seq(),
                e.effective_from(),
                e.effective_until(),
                e.appended_at(),
            )
        })
        .collect();
    assert_eq!(
        snapshot_before, snapshot_after,
        "the entry that was already there is untouched, including its open end"
    );
    assert_eq!(history.entries()[0].author(), &Author::Opening);

    // And the rate the first entry holds is still the first entry's rate.
    let at_zero = history.snapshot(HistorySeq(0));
    assert_eq!(
        price(&at_zero, &posting_at("m", 100, &[(INPUT, 1_000)]))
            .expect("entry zero is open-ended")
            .pre_tier_nanos,
        1_000_000,
    );
}

/// An empty history has no head, and asking for one does not answer zero. Zero is a real entry
/// number belonging to a real opening entry; a head that lied about it would let a caller snapshot
/// an entry that is not there and read a hole as a card.
#[test]
fn an_empty_history_has_no_head_and_prices_nothing() {
    let history = History::new();
    assert_eq!(history.head(), None);
    assert!(history.is_empty());
    let posting = posting_at("m", 1_000, &[(INPUT, 1)]);
    assert_eq!(
        price(&history.current(), &posting),
        Err(Unpriceable::NoCardInForce { at: 1_000 })
    );
}

/// A snapshot sees exactly the entries with `seq <= at`, so an older snapshot cannot see a newer
/// amendment and answers today what it answered when the invoice was cut. Two reads at the same
/// snapshot are the same answer; two reads at different snapshots differ, and the reader is told
/// which snapshot it read.
#[test]
fn a_snapshot_answers_the_same_way_forever() {
    let history = overlapping_history();
    let posting = posting_at("m", 120, &[(INPUT, 1_000)]);

    let at_one = history.snapshot(HistorySeq(1));
    let at_two = history.snapshot(HistorySeq(2));
    assert_eq!(at_one.seq(), HistorySeq(1));
    assert_eq!(
        at_one.entries().len(),
        2,
        "a snapshot cannot see the future"
    );

    let older = price(&at_one, &posting).expect("covered");
    let newer = price(&at_two, &posting).expect("covered");
    assert_eq!(
        (older.card_seq, older.pre_tier_nanos),
        (HistorySeq(1), 2_000_000)
    );
    assert_eq!(
        (newer.card_seq, newer.pre_tier_nanos),
        (HistorySeq(2), 3_000_000)
    );

    // Asked again, byte for byte the same.
    assert_eq!(price(&at_one, &posting).expect("covered"), older);
}

/// **A HOLE IS A REFUSAL, NOT A ZERO.** An instant no entry covers cannot be priced, and the
/// lookup says so rather than answering nothing — a zero would bill a gap in the record as a free
/// request, which is the one answer that can never be corrected later.
#[test]
fn an_instant_no_entry_covers_is_a_refusal() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 100,
        effective_until: Some(200),
        card: card_at(1.0),
        appended_at: 100,
        author: Author::Config { policy_epoch: 0 },
    });
    let view = history.current();
    assert!(view.card_at(99).is_none());
    assert!(view.card_at(200).is_none());
    assert!(view.card_at(150).is_some());

    let posting = posting_at("m", 99, &[(INPUT, 1_000_000)]);
    assert_eq!(
        price(&view, &posting),
        Err(Unpriceable::NoCardInForce { at: 99 })
    );
}

/// **A CACHED PRICE NEVER WINS OVER A LOOKUP.** The cache is hand-corrupted to a hundredfold figure
/// and the answer does not move, because the figure a reader must use is derived from the
/// quantities and the history and the cache is not on that path at all.
///
/// The divergence is reported, so the caller can correct the cache and journal that it did — but
/// what it reports is the lookup's number either way.
#[test]
fn a_corrupted_cache_never_becomes_the_bill() {
    let history = History::opening(card_at(2.0), 0);
    let view = history.current();
    let mut posting =
        Posting::from_usage("m", &usage(&[(INPUT, 1_000)]), 0, STANDARD_TIER_BP, 0, 0);

    let honest = price(&view, &posting).expect("covered");
    assert_eq!(honest.priced_nanos, 2_000_000);
    posting.cached = Some(honest.as_cache(HistorySeq(0)));
    assert!(!posting.cache_diverges(&honest));
    assert_eq!(posting.priced_nanos(&view), Ok(2_000_000));

    // A hundredfold corruption of the stored figure.
    posting.cached = Some(CachedPrice {
        history_seq: HistorySeq(0),
        card_seq: HistorySeq(0),
        pre_tier_nanos: 200_000_000,
        priced_nanos: 200_000_000,
    });
    let after = price(&view, &posting).expect("covered");
    assert_eq!(
        after, honest,
        "the lookup answers the quantities and the history, whatever the cache says"
    );
    assert_eq!(
        posting.priced_nanos(&view),
        Ok(2_000_000),
        "the figure a reader must use did not move"
    );
    assert!(
        posting.cache_diverges(&after),
        "and the divergence is reported rather than swallowed"
    );
}

/// The two postures over one lookup: a read reports an unpriced lane per row, and a settlement that
/// must fail closed refuses it. The refusing posture performs no arithmetic of its own — the figure
/// it would have returned is the reading posture's, exactly.
#[test]
fn the_fail_closed_posture_refuses_an_unpriced_lane_without_a_second_arithmetic() {
    let history = History::opening(
        RateCard::from_micro_rates([(LaneClass::new("known", INPUT), 5.0)], 2),
        0,
    );
    let view = history.current();
    let posting = posting_at("mystery", 0, &[(INPUT, 1_000_000)]);

    let read = price(&view, &posting).expect("a read reports it");
    assert!(read.lane_unpriced);
    assert_eq!(
        read.pre_tier_nanos, 0,
        "the fee count is zero on this posting"
    );

    assert_eq!(
        price_fail_closed(&view, &posting),
        Err(Unpriceable::LaneUnpriced {
            card_seq: HistorySeq(0),
            lane: "mystery".to_string(),
        })
    );
    // A lane the card DOES name passes both postures with the same answer.
    let known = posting_at("known", 0, &[(INPUT, 1_000_000)]);
    assert_eq!(price_fail_closed(&view, &known), price(&view, &known));
}
