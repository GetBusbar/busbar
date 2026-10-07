// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Statements cut as of a snapshot.
//!
//! The claim proved here is the one the whole design rests on. A statement re-derives its figures
//! from the quantities: a booked line carries no price at all (#71, #77(3)), so there is nothing but
//! the quantities and the dated history for it to read.
//! An amendment reprices a window as a dated VIEW (#77(3)); it books no adjusting line (#77(2)).

use crate::cost::{Author, CardEntryDraft, History, HistorySeq, LaneClass, RateCard};
use busbar_contract::caps::MeterClassId;

use crate::cost::HistoryView;
use crate::recompute::{Divergence, Posting, PostingOrigin, PricedLine};
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

/// The dated history a statement is cut against, as the fixtures read it.
struct Archive(History);

impl Archive {
    fn head(&self) -> Option<HistorySeq> {
        self.0.head()
    }

    fn view_at(&self, at: HistorySeq) -> Option<HistoryView<'_>> {
        let head = self.0.head()?;
        (at <= head).then(|| self.0.snapshot(at))
    }
}

fn archive_of(history: History) -> Archive {
    Archive(history)
}

/// A line arriving at `arrived_ms`: quantities and an instant, and no price.
fn line(node_seq: u64, arrived_ms: u64) -> Posting {
    Posting {
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
        origin: PostingOrigin::Client,
    }
}

/// Two lines: one inside the interval an amendment will cover, one outside it.
fn book() -> Vec<Posting> {
    vec![line(1, EARLY_MS), line(2, LATE_MS)]
}

#[test]
fn a_statement_is_cut_as_of_a_snapshot_and_two_snapshots_differ_by_the_lines_the_amendment_touched()
{
    let archive = archive_of(amended());
    let lines = book();

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
    let lines = book();

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
    let mut lines = book();
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

/// **A LANE THE CARD DOES NOT NAME IS UNPRICEABLE, NOT FEE-ONLY** (#42, `BUSBAR-1.6.0.md:2222`:
/// *"a hit class not priced ⇒ REFUSE … FAILS if billing-on & unpriced"*).
///
/// The read lookup used to answer such a line with its fee alone, and the statement summed that
/// onto the row as if it were the bill: the card present, the lane absent, every token the line
/// carried priced at nothing and not one of them named. The line is now listed under the lane it
/// was served on, and the row carries nothing of it.
#[test]
fn a_lane_the_card_does_not_name_is_listed_unpriceable_and_moves_no_row() {
    let archive = archive_of(opening());
    let view = archive.view_at(archive.head().unwrap()).unwrap();
    let mut lines = book();
    lines[1].lane = "lane-unnamed".to_string();

    let statement = totals_as_of(&view, WINDOW, lines.iter());
    assert_eq!(
        statement.unpriceable,
        vec![crate::totals::Unpriced {
            node: 1,
            node_seq: 2,
            why: Divergence::LaneUnpriced {
                card_seq: HistorySeq::OPENING,
                lane: "lane-unnamed".to_string(),
            },
        }],
        "the unnamed lane is a refusal, named, and never a line of fees"
    );
    let row = statement.row(&key("b"));
    assert_eq!(row.lines, 1, "only the priced line is on the row");
    assert_eq!(
        row.fee_count, 1,
        "the unpriceable line's fee is not counted on the row"
    );
}

/// **EVERY CLASS THE CARD CANNOT PRICE IS LISTED** — none of them dropped, and the line that hit
/// them moves no row.
///
/// Two classes the card names no price for, on a lane it does name: the statement used to price
/// the line at its fee and its priced classes and drop the other two without a word, so the served
/// totals view (which trusts this list) published a smaller bill. Both are named now, one entry
/// each.
#[test]
fn every_class_the_card_cannot_price_is_listed_and_the_line_moves_no_row() {
    let archive = archive_of(opening());
    let view = archive.view_at(archive.head().unwrap()).unwrap();
    let mut lines = book();
    lines[1].lines.push(PricedLine {
        class: MeterClassId::new("class-x"),
        quantity: 7,
    });
    lines[1].lines.push(PricedLine {
        class: MeterClassId::new("class-y"),
        quantity: 9,
    });

    let statement = totals_as_of(&view, WINDOW, lines.iter());
    let named: Vec<&Divergence> = statement.unpriceable.iter().map(|u| &u.why).collect();
    assert_eq!(
        named,
        vec![
            &Divergence::ClassUnpriced {
                card_seq: HistorySeq::OPENING,
                lane: LANE.to_string(),
                class: "class-x".to_string(),
            },
            &Divergence::ClassUnpriced {
                card_seq: HistorySeq::OPENING,
                lane: LANE.to_string(),
                class: "class-y".to_string(),
            },
        ],
        "both unpriced classes are named, in the order the line carried them"
    );
    assert!(statement
        .unpriceable
        .iter()
        .all(|u| u.node == 1 && u.node_seq == 2));
    assert_eq!(
        statement.row(&key("b")).lines,
        1,
        "the line that hit an unpriced class is not summed onto the row"
    );
}

/// The one silent zero #42 allows: NO card at all. A deployment that configured no rate card is
/// not billed, so its lines price at their fee and nothing is unpriceable.
#[test]
fn with_no_card_at_all_nothing_is_unpriceable() {
    let archive = archive_of(History::opening(RateCard::absent(1), 0));
    let view = archive.view_at(archive.head().unwrap()).unwrap();
    let mut lines = book();
    lines[1].lane = "lane-unnamed".to_string();

    let statement = totals_as_of(&view, WINDOW, lines.iter());
    assert!(statement.unpriceable.is_empty());
    assert_eq!(statement.row(&key("b")).lines, 2);
}
