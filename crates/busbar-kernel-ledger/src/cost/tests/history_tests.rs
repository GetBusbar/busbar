// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated history and the lookup over it: appending never rewrites, the resolution rule takes
//! the highest covering seq, a snapshot answers the same way forever, a hole is a refusal, and a
//! cached figure never wins over a lookup.

use super::*;
use crate::cost::{Author, CardEntryDraft, History, HistorySeq, LaneClass, RateCard};

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

/// A snapshot above the head sees the whole history rather than refusing: the refusal for a seq
/// that does not exist yet belongs at the endpoint that took the parameter, not in the arithmetic.
#[test]
fn a_snapshot_above_the_head_sees_the_whole_history() {
    let history = overlapping_history();
    let above = history.snapshot(HistorySeq(99));
    assert_eq!(above.entries().len(), 3);
    assert_eq!(above.card_at(120).expect("covered").0, HistorySeq(2));
}
