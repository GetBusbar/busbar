// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The recompute as an arbiter: the lookup wins, the cache is corrected, and a head that did not
//! move is what tells a hand edit from an amendment.

use std::collections::BTreeMap;

use busbar_caps::MeterClassId;
use busbar_unit_cost::{
    Author, CardEntryDraft, CurrencyCode, FeeTerms, History, HistorySeq, LaneClass, RateCard,
    TariffScope,
};

use crate::recompute::{
    apply_tier, price_line, recheck, recompute, DerivedPrice, Divergence, HistoryArchive, Posting,
    PostingOrigin, PricedLine, SealedHistory, Verdict, Watermark, BASIS_POINTS,
};

use super::fixtures::key;

/// The lane every line in this module is served on.
const LANE: &str = "lane-a";
/// The instant every line arrives at, unless a test moves it on purpose.
const ARRIVED_MS: u64 = 1_767_225_600_000;
/// The tier the fixture's bucket is on: a discount, not the neutral value, because `apply_tier` at
/// ten thousand basis points is the identity function and a fixture priced only there would pass
/// with the whole tier projection missing.
const DISCOUNT_TIER_BP: u32 = 9_000;

/// The card the opening entry seals: two classes on one lane, and a flat fee.
fn opening_card() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, "tokens_in"), 2.0),
            (LaneClass::new(LANE, "tokens_out"), 5.0),
        ],
        1,
    )
}

/// The card an amendment writes over the opening one: every rate doubled, so a line that repriced
/// is a visibly different number rather than the same one.
fn amended_card() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, "tokens_in"), 4.0),
            (LaneClass::new(LANE, "tokens_out"), 10.0),
        ],
        1,
    )
}

/// A one-entry history: the opening card, effective from instant zero, open-ended.
fn archive() -> SealedHistory {
    let mut tiers = BTreeMap::new();
    tiers.insert(key("b"), DISCOUNT_TIER_BP);
    SealedHistory {
        history: History::opening(opening_card(), 0),
        tiers,
    }
}

/// The same archive with a second entry appended over the instant the fixture's lines arrive at —
/// an amendment, which is what moves the head.
fn amended_archive() -> SealedHistory {
    let mut archive = archive();
    archive.history.append(CardEntryDraft {
        effective_from: ARRIVED_MS - 1_000,
        effective_until: Some(ARRIVED_MS + 1_000),
        card: amended_card(),
        appended_at: ARRIVED_MS + 60_000,
        author: Author::Amend {
            operator_fingerprint: "op-1".to_string(),
            reason_hash: [7u8; 32],
        },
    });
    archive
}

/// A line whose cache agrees with the lookup, under `archive`.
///
/// The cache is filled FROM the lookup rather than from a hand-written number, because the
/// arithmetic is the cost unit's and re-stating it here would be a second copy of it — which is the
/// exact defect the single-pricing-site rule exists to prevent. What this module tests is the
/// arbitration, not the multiply.
fn correct_line(node_seq: u64) -> Posting {
    let mut line = Posting {
        scope: TariffScope::node(),
        node: 1,
        node_seq,
        key: key("b"),
        window_start: 1,
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
        tier_bp: DISCOUNT_TIER_BP,
        arrived_ms: ARRIVED_MS,
        currency: CurrencyCode::USD,
        cached: DerivedPrice::default(),
        origin: PostingOrigin::Client,
    };
    refresh(&mut line, &archive());
    line
}

/// Fill a line's cache from the lookup under `archive`, and its `card_seq` with what resolved.
fn refresh(line: &mut Posting, archive: &SealedHistory) {
    let head = archive.head().expect("the fixture's archive has a head");
    let view = archive.view_at(head).expect("and a snapshot at it");
    let priced = price_line(line, &view, archive.tier_bp(&line.key)).expect("the fixture prices");
    line.cached = DerivedPrice {
        history_seq: head,
        card_seq: priced.card_seq,
        pre_tier_nanos: priced.pre_tier_nanos as i128,
        priced_nanos: priced.priced_nanos as i128,
    };
}

#[test]
fn a_correctly_priced_line_agrees() {
    let outcome = recheck(&correct_line(1), &archive());
    assert!(outcome.agrees(), "unexpected findings: {outcome:?}");
    assert!(
        outcome.cached_price_is_not_zero(),
        "a fixture whose money is zero would agree with an unimplemented lookup"
    );
}

impl crate::recompute::Recheck {
    /// A guard on the fixture rather than on the code: a line priced at nothing agrees with every
    /// possible bug, so the tests that assert agreement assert this too.
    fn cached_price_is_not_zero(&self) -> bool {
        self.corrected.is_some_and(|p| p.priced_nanos > 0)
    }
}

#[test]
fn the_lookup_wins_and_the_cache_is_corrected_rather_than_only_reported() {
    // The whole change of posture in one test. Under the sealed-policy model a disagreement was an
    // alarm and nothing else, because the recompute did not know which figure was right. Under a
    // dated history it does: the quantities are immutable and the history is append-only, so the
    // lookup over them IS the amount.
    let mut lines = vec![correct_line(1)];
    let was = lines[0].cached;
    lines[0].cached.priced_nanos += 1;

    let pass = recompute(Watermark::start(), &mut lines, &archive());
    assert_eq!(pass.corrected, 1, "the stale figure is put back");
    assert_eq!(lines[0].cached, was, "and put back to what the lookup says");
    assert!(
        pass.findings
            .iter()
            .any(|f| matches!(f.divergence, Divergence::Priced { .. })),
        "the correction is still reported: a silent fix is a fix nobody can audit"
    );
}

#[test]
fn a_head_that_moved_makes_a_stale_cache_ordinary_and_a_head_that_did_not_makes_it_an_alarm() {
    // Two halves of the same line, and the ONLY difference between them is whether the history has
    // been amended behind it. That is the whole discrimination: a cache going stale under a head
    // that advanced is what an amendment does, and a cache going stale under a head that did not
    // move cannot be anything but somebody's hand.
    let line = correct_line(1);

    let amended = amended_archive();
    let after_amendment = recheck(&line, &amended);
    assert_eq!(after_amendment.verdict, Verdict::Stale);
    assert!(
        !after_amendment.agrees(),
        "the amended card is a different number"
    );
    assert!(
        amended.head() > Some(line.history_seq()),
        "the fixture's premise: the head has advanced past the snapshot the line was settled under"
    );

    let mut tampered = correct_line(1);
    tampered.cached.priced_nanos -= 5;
    let under_an_unmoved_head = recheck(&tampered, &archive());
    assert_eq!(under_an_unmoved_head.verdict, Verdict::Alarm);
    assert!(!under_an_unmoved_head.agrees());
}

#[test]
fn a_pass_of_stale_caches_does_not_alarm_and_one_hand_edit_does() {
    // The operational consequence: after an amendment an operator must not be paged for every line
    // it touched, and must be paged for the one line nothing touched.
    let mut lines: Vec<Posting> = (1..=5).map(correct_line).collect();
    let pass = recompute(Watermark::start(), &mut lines, &amended_archive());
    assert!(!pass.is_clean(), "the amended card moved every figure");
    assert_eq!(pass.corrected, 5);
    assert!(
        !pass.alarms(),
        "an amendment catching up is a journal line, not a page"
    );

    let mut one = vec![correct_line(1)];
    one[0].cached.pre_tier_nanos += 3;
    let pass = recompute(Watermark::start(), &mut one, &archive());
    assert!(pass.alarms(), "nothing legitimate can have moved this one");
}

#[test]
fn a_hand_corrupted_quantity_moves_both_figures() {
    let mut line = correct_line(1);
    line.lines[0].quantity += 1;
    let outcome = recheck(&line, &archive());
    let kinds: Vec<_> = outcome.divergences.iter().collect();
    assert!(
        kinds
            .iter()
            .any(|d| matches!(d, Divergence::PreTier { .. }))
            && kinds.iter().any(|d| matches!(d, Divergence::Priced { .. })),
        "the pre-tier figure and the priced one both move: {kinds:?}"
    );
}

#[test]
fn a_tier_the_line_invented_is_found() {
    let mut line = correct_line(1);
    line.tier_bp = BASIS_POINTS;
    let outcome = recheck(&line, &archive());
    assert!(outcome
        .divergences
        .iter()
        .any(|d| matches!(d, Divergence::Tier { .. })));
    // And the money does NOT move, which is the point: the lookup priced at the SEALED tier rather
    // than at the one the line asserted, so the cached amount is still right and only the claim
    // about the tier is wrong. A recompute that had priced at the line's own tier would have agreed
    // with a line that invented a discount for itself.
    assert!(!outcome
        .divergences
        .iter()
        .any(|d| matches!(d, Divergence::Priced { .. })));
}

#[test]
fn the_fee_line_is_zero_for_work_no_client_asked_for() {
    let client = correct_line(1);
    let mut internal = correct_line(1);
    internal.origin = PostingOrigin::Internal;
    refresh(&mut internal, &archive());
    assert!(
        internal.cached.priced_nanos < client.cached.priced_nanos,
        "an internally originated line must not be charged the request fee"
    );
    assert!(recheck(&internal, &archive()).agrees());
}

#[test]
fn on_a_deployment_with_no_rate_card_the_fee_line_is_what_gets_checked() {
    // No class prices at all. Every class line prices at zero, so the fee line is the whole amount
    // and the recompute is checking exactly it.
    let archive = SealedHistory::new(History::opening(
        RateCard::absent_in(CurrencyCode::USD, FeeTerms::flat(250)),
        0,
    ));
    let mut line = correct_line(1);
    line.tier_bp = BASIS_POINTS;
    line.fee_count = 3;
    refresh(&mut line, &archive);
    assert!(line.cached.priced_nanos > 0, "the fee still posts");
    assert!(recheck(&line, &archive).agrees());

    line.cached.priced_nanos += 1;
    assert!(!recheck(&line, &archive).agrees());
}

#[test]
fn a_line_priced_under_a_history_nobody_kept_is_itself_a_finding() {
    let mut line = correct_line(1);
    line.cached.history_seq = HistorySeq(999);
    assert_eq!(
        recheck(&line, &archive()).divergences,
        vec![Divergence::HistoryMissing {
            seq: HistorySeq(999)
        }]
    );
}

#[test]
fn a_hole_in_the_history_is_a_refusal_and_never_a_zero() {
    // A history whose only entry starts AFTER the line's instant. Pricing that instant at nothing
    // is how a gap in the record becomes free service, so it refuses instead.
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: ARRIVED_MS + 1,
        effective_until: None,
        card: opening_card(),
        appended_at: 0,
        author: Author::Opening,
    });
    let outcome = recheck(&correct_line(1), &SealedHistory::new(history));
    assert_eq!(
        outcome.divergences,
        vec![Divergence::NoCardInForce { at: ARRIVED_MS }]
    );
    assert!(
        outcome.corrected.is_none(),
        "an unpriceable line's cache is left alone: overwriting it with a refusal would be the \
         zero this variant exists to refuse to write"
    );
}

#[test]
fn a_currency_the_card_does_not_name_is_never_converted() {
    // The card prices USD. The line is denominated in yen. There is no cross-rate in this path and
    // this refusal is what stands where one would have gone.
    let yen = CurrencyCode::new("JPY").expect("JPY is three upper-case letters");
    let mut line = correct_line(1);
    line.currency = yen;
    let outcome = recheck(&line, &archive());
    assert!(
        matches!(
            outcome.divergences.as_slice(),
            [Divergence::CurrencyNotPriced { currency, .. }] if *currency == yen
        ),
        "expected a refusal, got {:?}",
        outcome.divergences
    );
    assert!(
        outcome.corrected.is_none(),
        "never a converted figure and never a zero"
    );
}

#[test]
fn a_card_seq_the_line_did_not_resolve_to_is_found() {
    let mut line = correct_line(1);
    line.cached.card_seq = HistorySeq(41);
    assert!(recheck(&line, &archive())
        .divergences
        .iter()
        .any(|d| matches!(d, Divergence::CardSeq { .. })));
}

#[test]
fn a_line_from_before_the_history_reads_as_priced_under_the_opening_entry() {
    // A row migrated from the previous release carries no instant finer than the UTC day and no
    // history number at all. It was earned under the one card the migration sealed, so it reads at
    // the opening entry — which is effective from instant zero with no end, so no legacy row can
    // fall in a hole however coarse its instant is.
    let mut line = correct_line(1);
    line.arrived_ms = 0;
    refresh(&mut line, &archive());
    assert!(line.is_pre_history());
    assert_eq!(line.card_seq(), HistorySeq::OPENING);
    assert!(recheck(&line, &archive()).agrees());
}

#[test]
fn the_watermark_reaches_the_head_every_pass() {
    let mut lines: Vec<Posting> = (1..=50).map(correct_line).collect();
    let pass = recompute(Watermark::start(), &mut lines, &archive());
    assert!(pass.is_clean());
    assert_eq!(pass.checked, 50);
    assert_eq!(pass.corrected, 0);
    assert_eq!(
        pass.history_seq,
        Some(HistorySeq::OPENING),
        "the pass says which history it repriced against, so a reconciliation entry carrying it is \
         re-derivable without inferring the head from the lines"
    );
    assert_eq!(pass.watermark, Watermark::from_pairs([(1, 50)]));

    // A second pass over the same lines checks nothing, because the watermark is already there.
    let again = recompute(pass.watermark.clone(), &mut lines, &archive());
    assert_eq!(again.checked, 0);
    assert_eq!(again.watermark, pass.watermark);
}

#[test]
fn a_line_edited_before_the_last_checkpoint_still_alarms() {
    // The reason the watermark is a line and not a checkpoint. A checkpoint here would be far ahead
    // of the edit, and repricing "since the last checkpoint" would never look at it again.
    let mut lines: Vec<Posting> = (1..=100).map(correct_line).collect();
    lines[3].cached.priced_nanos -= 7;

    let pass = recompute(Watermark::start(), &mut lines, &archive());
    assert_eq!(pass.checked, 100, "the whole run is repriced, not a tail");
    assert_eq!(pass.findings.len(), 1);
    assert_eq!(pass.findings[0].node_seq, 4);
    assert_eq!(pass.findings[0].verdict, Verdict::Alarm);
    assert_eq!(
        pass.watermark,
        Watermark::from_pairs([(1, 100)]),
        "the watermark reaches the head even though a line diverged"
    );
}

#[test]
fn one_bad_line_does_not_stop_the_ones_after_it_being_checked() {
    let mut lines: Vec<Posting> = (1..=10).map(correct_line).collect();
    lines[2].cached.priced_nanos += 1;
    lines[8].cached.priced_nanos += 1;
    let pass = recompute(Watermark::start(), &mut lines, &archive());
    assert_eq!(
        pass.findings.len(),
        2,
        "an early alarm must not hide a later one"
    );
}

#[test]
fn a_watermark_that_survives_a_restart_resumes_where_it_stopped() {
    let mut lines: Vec<Posting> = (1..=20).map(correct_line).collect();
    let first = recompute(Watermark::start(), &mut lines[..10], &archive());
    assert_eq!(first.checked, 10);
    // The reconciliation entry carried the watermark across the restart; the second pass sees the
    // whole run and checks only what is new.
    let second = recompute(first.watermark, &mut lines, &archive());
    assert_eq!(second.checked, 10);
    assert_eq!(second.watermark.mark_for(1), Some(20));
}

#[test]
fn the_tier_multiplies_before_it_divides() {
    // A tier applied by dividing first rounds small amounts to nothing, which is a real way to lose
    // money one nano-unit at a time.
    assert_eq!(apply_tier(1, 9_999), 0);
    assert_eq!(apply_tier(10_000, 9_999), 9_999);
    assert_eq!(apply_tier(3, 5_000), 1);
    assert_eq!(apply_tier(-10_000, 9_000), -9_000);
}

/// The tier multiplier saturates too, so a pre-tier figure at the ceiling does not wrap on the way
/// through the multiply-before-divide.
#[test]
fn the_tier_multiplier_saturates_rather_than_wrapping() {
    // A wrap here flips the sign, which is how a ceiling figure would come back as a credit.
    assert_eq!(
        apply_tier(i128::MAX, BASIS_POINTS),
        i128::MAX / i128::from(BASIS_POINTS)
    );
    assert_eq!(
        apply_tier(i128::MIN, BASIS_POINTS),
        i128::MIN / i128::from(BASIS_POINTS)
    );
    // And the ordinary figures are untouched.
    assert_eq!(apply_tier(10_000, 9_999), 9_999);
}

/// A figure too large to hold is a DISAGREEMENT, not a wrap.
///
/// The recompute is the arbiter the rest of the money path is checked against, so it is the last
/// place that may answer with a wrapped number: a product of a hostile quantity and an absurd price
/// that wrapped into the cached figure would report a clean pass over a line that is wrong. It
/// saturates instead, exactly as the pricing path it is checking already does, and a saturated
/// figure can only ever disagree.
#[test]
fn a_figure_too_large_to_hold_is_reported_rather_than_wrapped() {
    let archive = SealedHistory::new(History::opening(
        RateCard::from_micro_rates([(LaneClass::new(LANE, "tokens_in"), 1.0e16)], 0),
        0,
    ));
    let mut line = correct_line(1);
    line.tier_bp = BASIS_POINTS;
    line.lines = vec![
        PricedLine {
            class: MeterClassId::new("tokens_in"),
            quantity: u64::MAX,
        },
        PricedLine {
            class: MeterClassId::new("tokens_in"),
            quantity: u64::MAX,
        },
    ];
    line.cached = DerivedPrice::default();

    let outcome = recheck(&line, &archive);
    assert!(
        outcome
            .corrected
            .is_some_and(|p| p.priced_nanos > i128::from(u64::MAX)),
        "the figure saturates upward and is reported as a disagreement, got {outcome:?}"
    );
    assert!(!outcome.agrees());
}

/// The watermark is PER NODE, and the reason is that lines arrive interleaved.
///
/// A single `(node, node_seq)` pair compared lexicographically is a watermark that, the moment it
/// passes the highest node, is ahead of every later line every lower-numbered node will ever write.
/// Those lines are then skipped forever and never repriced, and the pass reports itself clean over a
/// corrupted amount — the recompute answering "nothing wrong here" about a line it declined to look
/// at.
#[test]
fn a_later_line_from_a_lower_numbered_node_is_still_repriced() {
    // Tick one: two nodes, interleaved, both correct.
    let mut tick_one = Vec::new();
    for seq in 1..=2u64 {
        for node in 1..=2u64 {
            let mut p = correct_line(seq);
            p.node = node;
            tick_one.push(p);
        }
    }
    let first = recompute(Watermark::start(), &mut tick_one, &archive());
    assert!(first.is_clean());
    assert_eq!(first.checked, 4);

    // Tick two: one more line from each node, and the one from the LOWER-numbered node has had its
    // cached amount edited by hand.
    let mut tick_two = tick_one.clone();
    let mut corrupted = correct_line(3);
    corrupted.node = 1;
    corrupted.cached.priced_nanos -= 11;
    tick_two.push(corrupted);
    let mut fine = correct_line(3);
    fine.node = 2;
    tick_two.push(fine);

    let second = recompute(first.watermark, &mut tick_two, &archive());
    assert_eq!(
        second.checked, 2,
        "both new lines are owed a recompute, whichever node wrote them"
    );
    assert_eq!(second.findings.len(), 1);
    assert_eq!(
        (second.findings[0].node, second.findings[0].node_seq),
        (1, 3)
    );
    assert!(second.alarms());
}

#[test]
fn a_run_across_two_nodes_orders_by_node_then_sequence() {
    let mut lines = Vec::new();
    for node in 1..=2u64 {
        for seq in 1..=3u64 {
            let mut p = correct_line(seq);
            p.node = node;
            lines.push(p);
        }
    }
    let pass = recompute(Watermark::start(), &mut lines, &archive());
    assert_eq!(pass.checked, 6);
    // Both nodes reached their own head: node 2 at three, and node 1 at three as well rather than
    // stranded behind the higher-numbered node's progress.
    assert_eq!(pass.watermark, Watermark::from_pairs([(1, 3), (2, 3)]));
    assert_eq!(pass.watermark.mark_for(2), Some(3));
    assert_eq!(pass.watermark.nodes(), 2);
}

#[test]
fn a_mark_only_ever_moves_forward() {
    // A line that arrives behind a number already recomputed must not re-open the ones after it.
    let mut watermark = Watermark::from_pairs([(1, 9)]);
    watermark.advance(1, 4);
    assert_eq!(watermark.mark_for(1), Some(9));
    let mut behind = correct_line(4);
    behind.node = 1;
    assert!(!watermark.is_behind(&behind));
    assert_eq!(watermark.to_string(), "1/9");
    assert_eq!(Watermark::start().to_string(), "nothing recomputed yet");
}

/// **A ROW BOOKED AT A POOL'S SCOPE RECOMPUTES AT THAT POOL'S SCHEDULE, OFF THE ROW ALONE.**
///
/// The recompute is the ledger's audit: it re-prices a booked line against the sealed history and
/// reports where the cache and the lookup disagree. Once a scoped amount can be charged, a
/// recompute that read the node's schedule for every row would DISAGREE with every correctly
/// settled scoped line — and the direction of that disagreement is a node reporting its own books
/// as wrong. So the scope travels onto the cost unit's posting with the quantities, and this cell
/// is the proof: the same line, twice, differing in nothing but the scope its row recorded.
///
/// A `price_line` that dropped the scope answers the same figure for both and the `assert_ne!`
/// collapses.
#[test]
fn a_line_booked_at_a_pool_scope_recomputes_at_that_pools_schedule() {
    let mut scoped_card = opening_card();
    scoped_card.set_scope_terms(
        CurrencyCode::USD,
        TariffScope::pool("busy"),
        FeeTerms {
            transaction: 250,
            ..FeeTerms::default()
        },
    );
    let mut tiers = BTreeMap::new();
    tiers.insert(key("b"), DISCOUNT_TIER_BP);
    let archive = SealedHistory {
        history: History::opening(scoped_card, 0),
        tiers,
    };
    let head = archive.head().expect("the fixture's archive has a head");
    let view = archive.view_at(head).expect("and a snapshot at it");

    let mut at_node = correct_line(1);
    at_node.scope = TariffScope::node();
    let mut at_pool = correct_line(1);
    at_pool.scope = TariffScope::pool("busy");

    let node_nanos = price_line(&at_node, &view, archive.tier_bp(&at_node.key))
        .expect("the fixture prices")
        .priced_nanos;
    let pool_nanos = price_line(&at_pool, &view, archive.tier_bp(&at_pool.key))
        .expect("the fixture prices")
        .priced_nanos;
    assert_ne!(
        node_nanos, pool_nanos,
        "a recompute that read one schedule for every row would report every scoped line as wrong"
    );

    // AND THE RECOMPUTE AGREES WITH ITS OWN SETTLEMENT. The cache is filled from the same lookup,
    // so a line settled at the pool's schedule and re-read a year later is not a finding.
    refresh(&mut at_pool, &archive);
    let outcome = recheck(&at_pool, &archive);
    assert!(outcome.agrees(), "unexpected findings: {outcome:?}");
    assert!(outcome.cached_price_is_not_zero());
}
