// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated history and the lookup over it: appending never rewrites, the resolution rule takes
//! the highest covering seq, a snapshot answers the same way forever, a hole is a refusal, and a
//! cached figure never wins over a lookup.

use super::*;
use crate::{
    price, price_fail_closed, Author, CachedPrice, CardEntryDraft, CurrencyCode, History,
    HistorySeq, LaneClass, Posting, RateCard, Unpriceable,
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
        price(
            &at_zero,
            &posting_at("m", 100, &[(INPUT, 1_000)]),
            CurrencyCode::USD
        )
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
        price(&history.current(), &posting, CurrencyCode::USD),
        Err(Unpriceable::NoCardInForce { at: 1_000 })
    );
}

/// **THE RESOLUTION RULE.** Among the entries a snapshot can see whose interval covers an instant,
/// the one with the HIGHEST SEQ wins — not the one that starts latest, and not the one that was
/// dated latest.
///
/// The three-entry history is built so that every reading disagrees: at instant 120 the amendment
/// (seq 2, dated 50) covers it and so does the ordinary edit (seq 1, dated 100). Resolving by date
/// would pick seq 1; resolving by seq picks seq 2, which is the entry that was WRITTEN last and is
/// therefore the operator's latest word.
#[test]
fn card_at_resolves_overlap_by_the_highest_covering_seq() {
    let history = overlapping_history();
    let view = history.current();

    // Before the amendment's window: only the opening entry covers it.
    assert_eq!(view.card_at(10).expect("covered").0, HistorySeq(0));
    // Inside the amendment's window and before the ordinary edit: entries 0 and 2 cover it.
    assert_eq!(view.card_at(60).expect("covered").0, HistorySeq(2));
    // Inside the amendment's window AND the ordinary edit's: all three cover it, 2 wins.
    assert_eq!(view.card_at(120).expect("covered").0, HistorySeq(2));
    // Past the amendment's exclusive end: entries 0 and 1 cover it, 1 wins.
    assert_eq!(view.card_at(150).expect("covered").0, HistorySeq(1));
    assert_eq!(view.card_at(1_000_000).expect("covered").0, HistorySeq(1));

    // The interval's ends are inclusive-exclusive, exactly.
    assert_eq!(view.card_at(49).expect("covered").0, HistorySeq(0));
    assert_eq!(view.card_at(50).expect("covered").0, HistorySeq(2));
    assert_eq!(view.card_at(149).expect("covered").0, HistorySeq(2));
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

    let older = price(&at_one, &posting, CurrencyCode::USD).expect("covered");
    let newer = price(&at_two, &posting, CurrencyCode::USD).expect("covered");
    assert_eq!(
        (older.card_seq, older.pre_tier_nanos),
        (HistorySeq(1), 2_000_000)
    );
    assert_eq!(
        (newer.card_seq, newer.pre_tier_nanos),
        (HistorySeq(2), 3_000_000)
    );

    // Asked again, byte for byte the same.
    assert_eq!(
        price(&at_one, &posting, CurrencyCode::USD).expect("covered"),
        older
    );
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
        price(&view, &posting, CurrencyCode::USD),
        Err(Unpriceable::NoCardInForce { at: 99 })
    );
}

/// The opening entry is effective from instant ZERO, which is what makes a hole impossible for a
/// migrated deployment: every instant a pre-migration row could carry is covered by it, including
/// the ones that carry no instant finer than a UTC day and land at zero.
#[test]
fn the_opening_entry_covers_every_instant_including_zero() {
    let history = History::opening(card_at(1.0), 1_700_000_000_000);
    let view = history.current();
    for t in [0u64, 1, 1_700_000_000_000, u64::MAX] {
        assert_eq!(
            view.card_at(t).expect("the opening entry is open-ended").0,
            HistorySeq(0),
            "instant {t} is covered"
        );
    }
    assert_eq!(history.entries()[0].author(), &Author::Opening);
    assert_eq!(
        history.entries()[0].appended_at(),
        1_700_000_000_000,
        "the seal's wall clock, which is NOT the effective instant"
    );
    assert_eq!(history.entries()[0].effective_from(), 0);
}

/// A back-dated amendment is visible AS a back-date, because the instant it prices from and the
/// instant it was written are two fields. A configuration write has them equal; an amendment has
/// the write strictly later. One field would have made a correction of the past indistinguishable
/// from a price that was always there.
#[test]
fn a_back_dated_entry_is_visible_as_one() {
    let history = overlapping_history();
    let config = &history.entries()[1];
    let amend = &history.entries()[2];
    assert_eq!(config.effective_from(), config.appended_at());
    assert!(amend.appended_at() > amend.effective_from());
    match amend.author() {
        Author::Amend {
            operator_fingerprint,
            reason_hash,
        } => {
            assert_eq!(operator_fingerprint, "op-1");
            assert_eq!(reason_hash, &[7u8; 32]);
        }
        other => panic!("the amendment's author is an amendment, not {other:?}"),
    }
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
    let mut posting = Posting::from_usage(
        "m",
        &usage(&[(INPUT, 1_000)]),
        0,
        &crate::TieredAt::STANDARD,
        0,
        0,
    );

    let honest = price(&view, &posting, CurrencyCode::USD).expect("covered");
    assert_eq!(honest.priced_nanos, 2_000_000);
    posting.cached = Some(honest.as_cache(HistorySeq(0)));
    assert!(!posting.cache_diverges(&honest));
    assert_eq!(
        posting.priced_nanos(&view, CurrencyCode::USD),
        Ok(2_000_000)
    );

    // A hundredfold corruption of the stored figure.
    posting.cached = Some(CachedPrice {
        history_seq: HistorySeq(0),
        card_seq: HistorySeq(0),
        currency: CurrencyCode::USD,
        pre_tier_nanos: 200_000_000,
        priced_nanos: 200_000_000,
    });
    let after = price(&view, &posting, CurrencyCode::USD).expect("covered");
    assert_eq!(
        after, honest,
        "the lookup answers the quantities and the history, whatever the cache says"
    );
    assert_eq!(
        posting.priced_nanos(&view, CurrencyCode::USD),
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

    let read = price(&view, &posting, CurrencyCode::USD).expect("a read reports it");
    assert!(read.lane_unpriced);
    assert_eq!(
        read.pre_tier_nanos, 0,
        "the fee count is zero on this posting"
    );

    assert_eq!(
        price_fail_closed(&view, &posting, CurrencyCode::USD),
        Err(Unpriceable::LaneUnpriced {
            card_seq: HistorySeq(0),
            lane: "mystery".to_string(),
        })
    );
    // A lane the card DOES name passes both postures with the same answer.
    let known = posting_at("known", 0, &[(INPUT, 1_000_000)]);
    assert_eq!(
        price_fail_closed(&view, &known, CurrencyCode::USD),
        price(&view, &known, CurrencyCode::USD)
    );
}

/// A snapshot above the head sees the whole history rather than refusing: the refusal for a seq
/// that does not exist yet belongs at the endpoint that took the parameter, not in the arithmetic.
#[test]
fn a_snapshot_above_the_head_sees_the_whole_history() {
    let history = overlapping_history();
    let above = history.snapshot(HistorySeq(99));
    assert_eq!(above.entries().len(), 3);
    assert_eq!(above.card_at(120).expect("covered").0, HistorySeq(2));
}
