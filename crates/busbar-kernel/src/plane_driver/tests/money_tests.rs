// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION MONEY SEAM over the real governance book (an in-memory store) and a real cost
//! model: the end ledgers the far-end-reported counts once, in the arrival window; an estimate never
//! bills; a cancel bill is ledgered and the later end ledgers nothing twice; an undelivered end
//! refunds the flat fee; finish-unit never cuts and cut-stream cuts at the tightest budget; an
//! abandoned end goes to the root's posting site.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::plane::{UnitCount, CANCEL_OK_PARTIAL, UNITS_ESTIMATED, UNITS_REPORTED};
use busbar_contract::caps::OriginKind;
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::governance::{MemoryStore, WINDOW_TOTAL};
use crate::plane_driver::{CancelBill, CancelCause};
use crate::registry::Generation;

const NOW: u64 = 1_700_000_000;
const INPUT: u32 = 0;

fn ctx(key: u64) -> UnitCtx {
    UnitCtx {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// A cost model: one group `g` capping spend at `budget_cents` over all time, a card pricing model
/// `m`'s input at 1 micro-unit per token, and a flat fee of `fee` cents per request.
fn cost(budget_cents: Option<u64>, fee: i64) -> Arc<CostModel> {
    let limits = budget_cents
        .map(|amount| {
            vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount,
                per: Some(LimitWindow::Month),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }]
        })
        .unwrap_or_default();
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            limits,
            ..Default::default()
        },
    )]);
    let card = BTreeMap::from([(
        "m".to_string(),
        crate::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 1.0,
            ..Default::default()
        },
    )]);
    Arc::new(CostModel::resolve_parts(Some(&card), fee, &groups))
}

fn key() -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "k".into(),
        generation_hash: "h:k".into(),
        name: "k".into(),
        enabled: true,
        group: Some("g".into()),
        revision: 1,
        ..Default::default()
    })
}

#[derive(Default)]
struct Posted(AtomicU64);
impl EndPost for Posted {
    fn post(&self, _: &UnitCtx, _: Ended) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Rig {
    gov: Arc<GovState>,
    money: PlaneMoney,
    posted: Arc<Posted>,
    cost: Arc<CostModel>,
    key: Arc<VirtualKey>,
}

fn rig(budget_cents: Option<u64>, fee: i64, mode: ExhaustionMode) -> Rig {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("gov"));
    let posted = Arc::new(Posted::default());
    let money = PlaneMoney::new(gov.clone(), posted.clone());
    let (cost, key) = (cost(budget_cents, fee), key());
    money.open(
        UnitKey::new(1),
        UnitMoney {
            key: key.clone(),
            cost: cost.clone(),
            pool: String::new(),
            model: "m".into(),
            classes: Arc::from(vec!["input".to_string(), "output".to_string()]),
            arrived: NOW,
            mode,
        },
    );
    Rig {
        gov,
        money,
        posted,
        cost,
        key,
    }
}

fn reported(amount: u64) -> [UnitCount; 1] {
    [UnitCount {
        class: INPUT,
        source: UNITS_REPORTED,
        amount,
    }]
}

/// The key bucket's ledgered tokens, and its spend in cents (the flat fee included).
fn usage(r: &Rig) -> (u64, i64) {
    let u = r
        .gov
        .derived_bucket_usage(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
        .expect("usage");
    (u.tokens, u.spend_cents)
}

#[test]
fn the_end_ledgers_the_last_reported_counts_once() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    for n in [10, 60, 100] {
        assert_eq!(
            r.money.checkpoint(&ctx(1), &reported(n)),
            Checkpoint::Continue
        );
    }
    assert_eq!(
        usage(&r).0,
        0,
        "a running report is a checkpoint, never a ledger line"
    );
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).0, 100, "the last cumulative count, once");
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).0, 100, "a closed unit ledgers nothing again");
}

#[test]
fn an_estimate_never_bills() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let estimated = [UnitCount {
        class: INPUT,
        source: UNITS_ESTIMATED,
        amount: 500,
    }];
    let _ = r.money.checkpoint(&ctx(1), &estimated);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).0, 0);
}

#[test]
fn a_cancel_bill_is_ledgered_and_the_end_adds_nothing() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(80));
    r.money.cancelled(
        &ctx(1),
        &CancelBill {
            cause: CancelCause::ClientGone,
            disposition: CANCEL_OK_PARTIAL,
            far_end_answered: true,
            streamed: true,
            billed: vec![(INPUT, 70)],
        },
    );
    assert_eq!(usage(&r).0, 70, "the bill's counts");
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(
        usage(&r).0,
        70,
        "the end does not ledger the unit a second time"
    );
}

#[test]
fn an_undelivered_end_refunds_the_flat_fee() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    r.gov
        .try_admit(&r.cost, &r.key, "", NOW)
        .expect("admitted, the fee charged");
    assert_eq!(usage(&r).1, 5);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 0, "1.5.5's non-2xx refund of the request fee");
}

#[test]
fn a_delivered_end_keeps_the_flat_fee() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    r.gov.try_admit(&r.cost, &r.key, "", NOW).expect("admitted");
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).1, 5);
}

/// finish-unit (the default, 1.5.5) never cuts, however far past the budget the unit runs.
#[test]
fn finish_unit_never_cuts() {
    let r = rig(Some(1), 0, ExhaustionMode::FinishUnit);
    assert_eq!(
        r.money.checkpoint(&ctx(1), &reported(1_000_000)),
        Checkpoint::Continue
    );
}

/// cut-stream cuts once the reported counts, priced at the card, reach the tightest budget left:
/// 1 cent = 10 000 micro-units = 10 000 input tokens at 1 micro-unit each.
#[test]
fn cut_stream_cuts_at_the_tightest_budget() {
    let r = rig(Some(1), 0, ExhaustionMode::CutStream);
    assert_eq!(
        r.money.checkpoint(&ctx(1), &reported(9_999)),
        Checkpoint::Continue
    );
    assert_eq!(
        r.money.checkpoint(&ctx(1), &reported(10_000)),
        Checkpoint::Cut
    );
    let estimated = [UnitCount {
        class: INPUT,
        source: UNITS_ESTIMATED,
        amount: 1_000_000,
    }];
    let r = rig(Some(1), 0, ExhaustionMode::CutStream);
    assert_eq!(
        r.money.checkpoint(&ctx(1), &estimated),
        Checkpoint::Continue,
        "an estimate never cuts"
    );
}

/// A unit with no budget in play never runs dry.
#[test]
fn cut_stream_without_a_budget_never_cuts() {
    let r = rig(None, 0, ExhaustionMode::CutStream);
    assert_eq!(
        r.money.checkpoint(&ctx(1), &reported(u64::MAX / 2)),
        Checkpoint::Continue
    );
}

#[test]
fn an_abandoned_end_goes_to_the_roots_posting_site() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(r.posted.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        r.money.open_units(),
        0,
        "a unit with no count closes at once"
    );
}

fn bill(cause: CancelCause, amount: u64) -> CancelBill {
    CancelBill {
        cause,
        disposition: CANCEL_OK_PARTIAL,
        far_end_answered: true,
        streamed: true,
        billed: vec![(INPUT, amount)],
    }
}

/// A report whose counts do not add up in a u64 is a plane fault: never kept, never billed wrapped,
/// and the unit is cut (fail closed) whatever its mode.
#[test]
fn a_report_that_overflows_is_cut_and_never_kept() {
    for mode in [ExhaustionMode::FinishUnit, ExhaustionMode::CutStream] {
        let r = rig(None, 0, mode);
        let _ = r.money.checkpoint(&ctx(1), &reported(40));
        let twice = [
            UnitCount {
                class: INPUT,
                source: UNITS_REPORTED,
                amount: u64::MAX,
            },
            UnitCount {
                class: INPUT,
                source: UNITS_REPORTED,
                amount: 2,
            },
        ];
        assert_eq!(
            r.money.checkpoint(&ctx(1), &twice),
            Checkpoint::Cut,
            "{mode:?}"
        );
        r.money.settle_end(UnitKey::new(1), 200);
        assert_eq!(usage(&r).0, 40, "{mode:?}: the last report that added up");
    }
}

/// The sum that bills is checked, and a fail-closed ledger saturates: never wrapped, never zero.
#[test]
fn class_sums_are_checked_and_the_fallback_saturates() {
    let classes = ["input".to_string()];
    let counts = [(INPUT, u64::MAX), (INPUT, 2)];
    assert_eq!(super::named(&classes, &counts, u64::checked_add), None);
    assert_eq!(
        super::named(&classes, &counts, |a, b| Some(a.saturating_add(b))).unwrap()["input"],
        u64::MAX
    );
    assert_eq!(
        super::named(&classes, &[(INPUT, 3), (INPUT, 4)], u64::checked_add).unwrap()["input"],
        7
    );
}

/// EXACTLY ONCE, every path: complete (and a second end), abandon after the route finished, abandon
/// mid-route then its cancel bill (either order), cancel then end. Every path closes the unit.
#[test]
fn every_path_ledgers_a_unit_exactly_once_and_closes_it() {
    // Complete, then a second end.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(10));
    r.money.finished(&ctx(1));
    r.money.settle_end(UnitKey::new(1), 200);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!((usage(&r).0, r.money.open_units()), (10, 0), "complete");

    // The route finished, then the caller left during the exit.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(20));
    r.money.finished(&ctx(1));
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(
        (usage(&r).0, r.money.open_units()),
        (20, 0),
        "abandon after finish"
    );

    // The caller left mid-route: the end is posted, then the sweep's cancel bill.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(30));
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(
        r.money.open_units(),
        1,
        "the unit waits for its cancel bill"
    );
    r.money
        .cancelled(&ctx(1), &bill(CancelCause::ClientGone, 25));
    r.money
        .cancelled(&ctx(1), &bill(CancelCause::ClientGone, 25));
    assert_eq!(
        (usage(&r).0, r.money.open_units()),
        (25, 0),
        "abandon then bill"
    );

    // The bill first, then the posted end.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(30));
    r.money
        .cancelled(&ctx(1), &bill(CancelCause::ClientGone, 25));
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(
        (usage(&r).0, r.money.open_units()),
        (25, 0),
        "bill then abandon"
    );

    // A cancel the unit returns from (a deadline), then its end.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(30));
    r.money.cancelled(&ctx(1), &bill(CancelCause::Deadline, 5));
    r.money.settle_end(UnitKey::new(1), 504);
    assert_eq!(
        (usage(&r).0, r.money.open_units()),
        (5, 0),
        "cancel then end"
    );
}

/// A cancelled unit that returns undelivered (a deadline before any answer: the caller gets a
/// non-2xx) is refunded its flat fee, as 1.5.5 refunded every non-2xx finish; a unit whose caller
/// went away is refunded nothing.
#[test]
fn a_cancelled_undelivered_unit_is_refunded_once_and_an_abandoned_one_never() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    r.gov.try_admit(&r.cost, &r.key, "", NOW).expect("admitted");
    r.money.cancelled(
        &ctx(1),
        &CancelBill {
            cause: CancelCause::Deadline,
            disposition: CANCEL_OK_PARTIAL,
            far_end_answered: false,
            streamed: false,
            billed: Vec::new(),
        },
    );
    r.money.settle_end(UnitKey::new(1), 504);
    assert_eq!(usage(&r).1, 0, "the fee refunded");
    r.money.settle_end(UnitKey::new(1), 504);
    assert_eq!(usage(&r).1, 0, "and once");

    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    r.gov.try_admit(&r.cost, &r.key, "", NOW).expect("admitted");
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(
        usage(&r).1,
        5,
        "a caller that went away keeps the fee charged"
    );
}
