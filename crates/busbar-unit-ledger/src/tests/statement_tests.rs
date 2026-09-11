// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Statements cut as of a snapshot, and the adjusting entries an amendment owes.
//!
//! Two claims are proved here, and they are the two the whole design rests on. A statement
//! re-derives its figures from the quantities and never sums a cached price — so the answer does
//! not depend on whether the recompute has been round yet, and hand-corrupting every cache in the
//! book leaves it untouched. And an amendment moves money by emitting an adjusting entry rather
//! than by editing a line — so `settled` does not move, `adjustments` does, and the identity's
//! residual is zero on both sides of it with no new term.

use std::collections::BTreeMap;

use busbar_caps::MeterClassId;
use busbar_unit_cost::{
    Author, CardEntryDraft, CurrencyCode, History, HistorySeq, LaneClass, RateCard, TariffScope,
};

use crate::identity::residual;
use crate::recompute::{
    price_line, DerivedPrice, Divergence, HistoryArchive, Posting, PostingOrigin, PricedLine,
    SealedHistory,
};
use crate::settle::{adjusting_entries, Ledger};
use crate::totals::{totals_as_of, Totals, WindowStart};

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
    let mut tiers = BTreeMap::new();
    tiers.insert(key("b"), TIER_BP);
    SealedHistory { history, tiers }
}

/// A line arriving at `arrived_ms`, with its cache filled from the history it is settled under.
fn line(node_seq: u64, arrived_ms: u64, archive: &SealedHistory) -> Posting {
    let mut line = Posting {
        scope: TariffScope::node(),
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
        currency: CurrencyCode::USD,
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

    let honest = totals_as_of(&view, WINDOW, CurrencyCode::USD, lines.iter());
    assert!(
        honest.total_nanos() > 0,
        "a statement of nothing would agree with an unimplemented lookup"
    );

    for line in &mut lines {
        line.cached.priced_nanos = 999_999_999;
        line.cached.pre_tier_nanos = -1;
    }
    let over_a_corrupted_book = totals_as_of(&view, WINDOW, CurrencyCode::USD, lines.iter());
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
        CurrencyCode::USD,
        lines.iter(),
    );
    let after = totals_as_of(
        &archive.view_at(archive.head().unwrap()).unwrap(),
        WINDOW,
        CurrencyCode::USD,
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
        CurrencyCode::USD,
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

    let statement = totals_as_of(&view, WINDOW, CurrencyCode::USD, lines.iter());
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

#[test]
fn a_statement_names_one_currency_and_never_sums_two() {
    let archive = archive_of(opening());
    let view = archive.view_at(archive.head().unwrap()).unwrap();
    let yen = CurrencyCode::new("JPY").expect("JPY is three upper-case letters");
    let mut lines = book(&archive);
    lines[1].currency = yen;

    let usd = totals_as_of(&view, WINDOW, CurrencyCode::USD, lines.iter());
    assert_eq!(
        usd.row(&key("b")).lines,
        1,
        "a line denominated in another currency belongs on another statement, not in this sum"
    );
    assert_eq!(usd.currency, CurrencyCode::USD);
}

#[test]
fn an_amendment_emits_one_adjusting_entry_per_affected_balance_and_none_for_the_untouched() {
    let history = amended();
    let before = history.snapshot(HistorySeq::OPENING);
    let after = history.current();
    let lines = book(&archive_of(opening()));

    let entries = adjusting_entries(&before, &after, FINGERPRINT, REASON, lines.iter());
    assert_eq!(entries.len(), 1, "one balance, one window, one entry");
    let entry = &entries[0];

    assert_eq!(entry.key, key("b"));
    assert_eq!(entry.window, WINDOW);
    assert_eq!(entry.currency, CurrencyCode::USD);
    assert_eq!(entry.from_seq, HistorySeq::OPENING);
    assert_eq!(entry.to_seq, HistorySeq(1));
    assert_eq!(entry.old_card_seq, HistorySeq::OPENING);
    assert_eq!(entry.new_card_seq, HistorySeq(1));
    assert_eq!(entry.operator_fingerprint, FINGERPRINT);
    assert_eq!(entry.reason_hash, REASON);
    assert_eq!(
        entry.postings, 1,
        "only the line inside the amended interval; the late one resolves to the same entry it \
         always did, so it is not affected and the record says so"
    );
    assert_eq!(entry.delta, entry.new_nanos - entry.old_nanos);
    assert!(entry.delta > 0, "the amendment doubled the rate");
    assert!(entry.old_nanos > 0 && entry.new_nanos > 0);
    assert_eq!(entry.fee_count, 1);
    // The quantities the entry summarises are on it, in class order, so it is readable without the
    // lines it describes.
    assert_eq!(
        entry
            .quantities
            .iter()
            .map(|q| (q.class.as_str(), q.quantity))
            .collect::<Vec<_>>(),
        vec![("tokens_in", 1_000), ("tokens_out", 200)]
    );
}

#[test]
fn an_amendment_that_moved_nothing_emits_nothing() {
    // A history append over a window nobody used is a history append and nothing else. A zero-delta
    // record would be noise in the one journal an auditor reads line by line.
    let history = opening();
    let view = history.current();
    let lines = book(&archive_of(opening()));
    assert!(adjusting_entries(&view, &view, FINGERPRINT, REASON, lines.iter()).is_empty());
}

#[test]
fn an_amendment_does_not_move_settled_and_the_residual_stays_zero_through_it() {
    // THE IDENTITY CLAIM, and the reason the entry rides `adjustments`. A booked line is never
    // rewritten, so `settled` may not move by a nano-unit; the delta rides the cell the identity
    // already carries; and because the same delta is drawn, both sides move together and the
    // residual is what it was.
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_draw(&k, WINDOW, 1_000);
    ledger.book_mut().entry(k.clone(), WINDOW).settled = 600;
    ledger
        .book_mut()
        .entry(k.clone(), WINDOW)
        .open_slice_remainders = 400;

    let since = Totals::zero();
    let was = ledger.book().get(&k, WINDOW);
    assert!(
        residual(&since, &was).holds(),
        "the fixture has to balance before the amendment or the test proves nothing"
    );

    let history = amended();
    let entries = adjusting_entries(
        &history.snapshot(HistorySeq::OPENING),
        &history.current(),
        FINGERPRINT,
        REASON,
        book(&archive_of(opening())).iter(),
    );
    assert_eq!(entries.len(), 1);
    let delta = entries[0].delta;
    for entry in &entries {
        ledger.record_repricing(entry);
    }

    let now = ledger.book().get(&k, WINDOW);
    assert_eq!(
        now.settled, was.settled,
        "a booked line is never rewritten, so settled does not move"
    );
    assert_eq!(
        now.adjustments,
        was.adjustments + delta,
        "the delta rides the adjustments cell the identity already had"
    );
    assert_eq!(now.drawn, was.drawn + delta);
    assert!(
        residual(&since, &now).holds(),
        "the residual stays zero through the amendment: {}",
        residual(&since, &now)
    );
}

#[test]
fn an_amendment_that_lowered_the_bill_gives_the_delta_back() {
    // The other direction, because a correction that could only ever raise a bill would be a
    // correction an operator could not use for the case they most need it.
    let mut history = opening();
    history.append(CardEntryDraft {
        effective_from: EARLY_MS - 1_000,
        effective_until: Some(EARLY_MS + 1_000),
        card: card(1.0, 2.0),
        appended_at: LATE_MS,
        author: Author::Amend {
            operator_fingerprint: FINGERPRINT.to_string(),
            reason_hash: REASON,
        },
    });
    let entries = adjusting_entries(
        &history.snapshot(HistorySeq::OPENING),
        &history.current(),
        FINGERPRINT,
        REASON,
        book(&archive_of(opening())).iter(),
    );
    assert_eq!(entries.len(), 1);
    assert!(entries[0].delta < 0, "the bill went down");

    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_draw(&k, WINDOW, 1_000);
    ledger.record_slice_spent(&k, WINDOW, 1_000);
    ledger.book_mut().entry(k.clone(), WINDOW).settled = 1_000;
    let was = ledger.book().get(&k, WINDOW);
    assert!(
        residual(&Totals::zero(), &was).holds(),
        "the fixture has to balance before the amendment or the test proves nothing"
    );
    ledger.record_repricing(&entries[0]);
    let now = ledger.book().get(&k, WINDOW);
    assert_eq!(now.settled, was.settled);
    assert!(now.adjustments < 0 && now.drawn < was.drawn);
    assert!(residual(&Totals::zero(), &now).holds());
}

#[test]
fn two_amendments_over_one_window_are_computed_one_against_the_next() {
    // "Never rewritten" requires this: the second amendment's entry states what the balance was
    // under the FIRST one, not what it was originally. Otherwise the two corrections would
    // double-count the same movement.
    let mut history = amended();
    history.append(CardEntryDraft {
        effective_from: EARLY_MS - 1_000,
        effective_until: Some(EARLY_MS + 1_000),
        card: card(8.0, 20.0),
        appended_at: LATE_MS + 1,
        author: Author::Amend {
            operator_fingerprint: FINGERPRINT.to_string(),
            reason_hash: REASON,
        },
    });
    let lines = book(&archive_of(opening()));

    let first = adjusting_entries(
        &history.snapshot(HistorySeq::OPENING),
        &history.snapshot(HistorySeq(1)),
        FINGERPRINT,
        REASON,
        lines.iter(),
    );
    let second = adjusting_entries(
        &history.snapshot(HistorySeq(1)),
        &history.snapshot(HistorySeq(2)),
        FINGERPRINT,
        REASON,
        lines.iter(),
    );
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(
        second[0].old_nanos, first[0].new_nanos,
        "the second correction starts from where the first left the balance"
    );
    assert_eq!(second[0].old_card_seq, HistorySeq(1));
    assert_eq!(second[0].new_card_seq, HistorySeq(2));

    // And the two deltas compose: applying both leaves the balance where one amendment straight to
    // the final card would have.
    let straight = adjusting_entries(
        &history.snapshot(HistorySeq::OPENING),
        &history.snapshot(HistorySeq(2)),
        FINGERPRINT,
        REASON,
        lines.iter(),
    );
    assert_eq!(straight[0].delta, first[0].delta + second[0].delta);
}
