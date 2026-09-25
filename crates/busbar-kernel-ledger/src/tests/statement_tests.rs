// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Statements cut as of a snapshot.
//!
//! The claim proved here is the one the whole design rests on. A statement re-derives its figures
//! from the quantities and never sums a cached price — so the answer does not depend on whether the
//! recompute has been round yet, and hand-corrupting every cache in the book leaves it untouched.
//! An amendment reprices a window as a dated VIEW (#77(3)); it books no adjusting line (#77(2)).

use crate::cost::{Author, CardEntryDraft, History, HistorySeq, LaneClass, RateCard};
use busbar_contract::caps::MeterClassId;

use crate::recompute::{
    price_line, DerivedPrice, Divergence, HistoryArchive, Posting, PostingOrigin, PricedLine,
    SealedHistory,
};
use crate::totals::{totals_as_of, WindowStart};

use super::fixtures::key;

const LANE: &str = "lane-a";
const WINDOW: WindowStart = 1_767_225_600;
/// Inside the amended interval.
const EARLY_MS: u64 = 1_767_225_600_000;
/// Outside it, so a statement can prove an amendment moved SOME lines and not all of them.
const LATE_MS: u64 = 1_767_229_200_000;
const TIER_BP: u32 = 9_000;
const FINGERPRINT: &str = "op-1";
const REASON: [u8; 32] = [9u8; 32];

fn card(rate_in: f64, rate_out: f64) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, "tokens_in"), rate_in),
            (LaneClass::new(LANE, "tokens_out"), rate_out),
        ],
        1,
    )
}

/// The history before any amendment: one opening entry over all time.
fn opening() -> History {
    History::opening(card(2.0, 5.0), 0)
}

/// The history after one: a dated entry over the early instant only, at doubled rates.
///
/// The interval is deliberately narrow. An amendment that covered every line would prove nothing
/// about whether the affected set is computed from the histories or simply assumed to be "all of
/// them".
fn amended() -> History {
    let mut history = opening();
    history.append(CardEntryDraft {
        effective_from: EARLY_MS - 1_000,
        effective_until: Some(EARLY_MS + 1_000),
        card: card(4.0, 10.0),
        appended_at: LATE_MS,
        author: Author::Amend {
            operator_fingerprint: FINGERPRINT.to_string(),
            reason_hash: REASON,
        },
    });
    history
}

fn archive_of(history: History) -> SealedHistory {
    SealedHistory::new(history)
}

/// A line arriving at `arrived_ms`, with its cache filled from the history it is settled under.
fn line(node_seq: u64, arrived_ms: u64, archive: &SealedHistory) -> Posting {
    let mut line = Posting {
        node: 1,
        node_seq,
        key: key("b"),
        window_start: WINDOW,
        lane: LANE.to_string(),
        lines: vec![
            PricedLine {
                class: MeterClassId::new("tokens_in"),
                quantity: 1_000,
            },
            PricedLine {
                class: MeterClassId::new("tokens_out"),
                quantity: 200,
            },
        ],
        fee_count: 1,
        tier_bp: TIER_BP,
        arrived_ms,
        cached: DerivedPrice::default(),
        origin: PostingOrigin::Client,
    };
    let head = archive.head().expect("the fixture's archive has a head");
    let view = archive.view_at(head).expect("and a snapshot at it");
    let priced = price_line(&line, &view, TIER_BP).expect("the fixture prices");
    line.cached = DerivedPrice {
        history_seq: head,
        card_seq: priced.card_seq,
        pre_tier_nanos: priced.pre_tier_nanos as i128,
        priced_nanos: priced.priced_nanos as i128,
    };
    line
}

/// Two lines: one inside the interval an amendment will cover, one outside it.
fn book(archive: &SealedHistory) -> Vec<Posting> {
    vec![line(1, EARLY_MS, archive), line(2, LATE_MS, archive)]
}

#[test]
fn a_statement_re_derives_from_the_quantities_and_never_sums_a_cached_price() {
    // THE RULE, red-proofed the only way it can be: corrupt every cached figure in the book and
    // assert the statement does not move. A statement that added the caches up would move by
    // exactly the corruption; this one cannot see it at all.
    let archive = archive_of(opening());
    let head = archive.head().unwrap();
    let view = archive.view_at(head).unwrap();
    let mut lines = book(&archive);

    let honest = totals_as_of(&view, WINDOW, lines.iter());
    assert!(
        honest.total_nanos() > 0,
        "a statement of nothing would agree with an unimplemented lookup"
    );

    for line in &mut lines {
        line.cached.priced_nanos = 999_999_999;
        line.cached.pre_tier_nanos = -1;
    }
    let over_a_corrupted_book = totals_as_of(&view, WINDOW, lines.iter());
    assert_eq!(
        honest, over_a_corrupted_book,
        "the read path must not be able to see a cache at all"
    );
}

#[test]
fn a_statement_is_cut_as_of_a_snapshot_and_two_snapshots_differ_by_the_lines_the_amendment_touched()
{
    let archive = archive_of(amended());
    let lines = book(&archive_of(opening()));

    let before = totals_as_of(
        &archive.view_at(HistorySeq::OPENING).unwrap(),
        WINDOW,
        lines.iter(),
    );
    let after = totals_as_of(
        &archive.view_at(archive.head().unwrap()).unwrap(),
        WINDOW,
        lines.iter(),
    );

    assert_eq!(before.history_seq, HistorySeq::OPENING);
    assert_eq!(after.history_seq, HistorySeq(1));
    assert!(
        after.total_nanos() > before.total_nanos(),
        "the amendment doubled the rate on the early line"
    );
    assert_eq!(
        before.row(&key("b")).lines,
        2,
        "both lines are on both statements — an amendment reprices, it does not remove"
    );
    assert_eq!(after.row(&key("b")).lines, 2);

    // Cut the same statement again and get the same figures. This is the reproducibility claim:
    // name the two inputs and the same answer comes back forever.
    let again = totals_as_of(
        &archive.view_at(HistorySeq::OPENING).unwrap(),
        WINDOW,
        lines.iter(),
    );
    assert_eq!(before, again);
}

#[test]
fn a_statement_lists_the_lines_it_could_not_price_rather_than_counting_them_as_zero() {
    // A hole is a refusal. A statement that silently omitted an unpriceable line would read as a
    // smaller bill rather than as an incomplete one, which is the difference between an operator
    // seeing a problem and an operator not seeing one.
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: LATE_MS,
        effective_until: None,
        card: card(2.0, 5.0),
        appended_at: 0,
        author: Author::Opening,
    });
    let archive = archive_of(history);
    let view = archive.view_at(archive.head().unwrap()).unwrap();
    let lines = book(&archive_of(opening()));

    let statement = totals_as_of(&view, WINDOW, lines.iter());
    assert_eq!(statement.unpriceable.len(), 1);
    assert_eq!(
        statement.unpriceable[0].why,
        Divergence::NoCardInForce { at: EARLY_MS }
    );
    assert_eq!(
        statement.row(&key("b")).lines,
        1,
        "the line that could price is on the statement; the one that could not is named instead"
    );
}

/// **A STATEMENT NAMES ONE WINDOW AND NEVER SUMS TWO.**
///
/// This is what remains of the guard that used to filter on window AND currency. #66 removed the
/// currency half — money is unitless, so there is no denomination a line could belong to and
/// therefore nothing to segregate by — and the window half is the whole of it now. A line from
/// another window belongs on another statement; counting it here would put yesterday's traffic on
/// today's bill.
#[test]
fn a_statement_names_one_window_and_never_sums_two() {
    let archive = archive_of(opening());
    let view = archive.view_at(archive.head().unwrap()).unwrap();
    let mut lines = book(&archive);
    lines[1].window_start = WINDOW + 86_400;

    let statement = totals_as_of(&view, WINDOW, lines.iter());
    assert_eq!(
        statement.row(&key("b")).lines,
        1,
        "a line in another window belongs on another statement, not in this sum"
    );
    assert_eq!(statement.window, WINDOW);
    // And the statement cut over the OTHER window carries exactly the other line.
    let next = totals_as_of(&view, WINDOW + 86_400, lines.iter());
    assert_eq!(next.row(&key("b")).lines, 1);
    assert_ne!(
        statement.row(&key("b")).priced_nanos,
        0,
        "both statements are real figures, not two empty ones agreeing"
    );
}
