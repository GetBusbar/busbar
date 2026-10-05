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

use busbar_contract::abi::plane::{
    UnitCount, CANCEL_OK_PARTIAL, UNITS_ESTIMATED, UNITS_FLOOR, UNITS_REPORTED,
};
use busbar_contract::caps::{OriginKind, ReasonCode};
use busbar_contract::records::VirtualKey;
use busbar_contract::UnitKey;

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::governance::{MemoryStore, WINDOW_TOTAL};
use crate::plane_driver::CancelBill;
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
    Arc::new(cost_model(budget_cents, fee))
}

/// [`cost`], unshared.
fn cost_model(budget_cents: Option<u64>, fee: i64) -> CostModel {
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
    let rate = || crate::config::RateEntryCfg {
        input_utok: 1.0,
        output_utok: 1.0,
        ..Default::default()
    };
    // `m2` is the member a failed-over unit is served by.
    let card = BTreeMap::from([("m".to_string(), rate()), ("m2".to_string(), rate())]);
    CostModel::resolve_parts(Some(&card), fee, &groups)
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
    /// The unit 1 the rig opened, before any admission charged it.
    unit: UnitMoney,
}

/// Admit unit 1 through the real admission (its fee charged), and re-open it carrying that charge,
/// as the composition root opens a unit it has admitted.
fn admit(r: &Rig) {
    let grant = (r.gov.try_admit(&r.cost, &r.key, "", NOW)).expect("admitted, the fee charged");
    let unit = UnitMoney {
        charge: grant.charge().clone(),
        ..r.unit.clone()
    };
    r.money.open(UnitKey::new(1), unit);
}

fn rig(budget_cents: Option<u64>, fee: i64, mode: ExhaustionMode) -> Rig {
    rig_with(budget_cents, fee, mode, FeeRefund::CallerStatus)
}

fn rig_with(budget_cents: Option<u64>, fee: i64, mode: ExhaustionMode, rule: FeeRefund) -> Rig {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("gov"));
    let posted = Arc::new(Posted::default());
    let money = PlaneMoney::new(gov.clone(), posted.clone());
    let (cost, key) = (cost(budget_cents, fee), key());
    let unit = UnitMoney {
        key: key.clone(),
        cost: cost.clone(),
        pool: String::new(),
        model: "m".into(),
        classes: Arc::from(vec![
            "input".to_string(),
            "output".to_string(),
            busbar_contract::plane::PER_REQUEST.to_string(),
        ]),
        arrived: NOW,
        mode,
        fee: rule,
        charge: Default::default(),
    };
    money.open(UnitKey::new(1), unit.clone());
    Rig {
        gov,
        money,
        posted,
        cost,
        key,
        unit,
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
            cause: ReasonCode::ClientGone,
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
    admit(&r);
    assert_eq!(usage(&r).1, 5);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 0, "1.5.5's non-2xx refund of the request fee");
}

#[test]
fn a_delivered_end_keeps_the_flat_fee() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    admit(&r);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).1, 5);
}

// A plane new in 1.6.0 decides its fee refund through its own fee-unit report; the class at index 2 is its declared fee unit.

const FEE_UNIT: u32 = 2;

fn plane_fees() -> FeeRefund {
    FeeRefund::PlaneFeeUnits(Arc::from(vec![FEE_UNIT]))
}

fn fee_reported(amount: u64) -> UnitCount {
    UnitCount {
        class: FEE_UNIT,
        source: UNITS_REPORTED,
        amount,
    }
}

/// The plane reported no fee unit: the fee charged at admission is refunded, whatever the status.
/// RED: under the caller-status rule a 200 end keeps the fee.
#[test]
fn a_plane_that_reports_no_fee_unit_has_its_fee_refunded() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let _ = r.money.checkpoint(&ctx(1), &[fee_reported(0)]);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).1, 0, "the plane decides: no fee unit, no fee");
}

/// The plane reported its fee unit: the fee stays, even on a non-2xx end (the plane decides, not
/// the caller status). RED: under the caller-status rule a 503 end refunds it.
#[test]
fn a_plane_that_reports_its_fee_unit_keeps_the_fee() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let _ = r.money.checkpoint(&ctx(1), &[fee_reported(1)]);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 5, "the plane reported its fee unit");
}

/// RED arm: a fee unit's count is never ledgered as usage. The card prices `input` and
/// `output` only, so a fee count reaching the ledger as usage would make the bucket's spend a
/// refusal (#42) and its tokens would not be the input alone.
#[test]
fn a_fee_unit_count_is_never_ledgered_as_usage() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let report = [
        UnitCount {
            class: INPUT,
            source: UNITS_REPORTED,
            amount: 40,
        },
        fee_reported(1),
    ];
    let _ = r.money.checkpoint(&ctx(1), &report);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(
        usage(&r),
        (40, 5),
        "the input counts and the admission's fee, nothing else"
    );
}

// THE SERVING MEMBER (v1.5.5 crates/busbar/src/proxy/usage.rs `record_resp_usage` :31-40 and
// `ledger_and_meter` :99-106): a delivered response meters one request against the SERVING lane's
// config model and provider, tokens or none, and its tokens ledger under that model.

fn metering_rows(r: &Rig) -> Vec<busbar_contract::records::MeteringRow> {
    r.gov.flush_metering();
    r.gov
        .metering_for(crate::governance::metering_bucket(NOW))
        .expect("metering read")
}

/// A delivered unit that reported no token still meters ONE request against its serving member.
/// RED: without the end's metering the row is absent.
#[test]
fn a_delivered_zero_token_unit_meters_one_request() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.served(&ctx(1), "m", "acme");
    r.money.settle_end(UnitKey::new(1), 200);
    let rows = metering_rows(&r);
    assert_eq!(rows.len(), 1, "one metering row");
    let row = &rows[0];
    assert_eq!(
        (row.model.as_str(), row.provider.as_str(), row.requests),
        ("m", "acme", 1)
    );
    assert_eq!((row.tokens_input, row.tokens_output), (0, 0));
}

/// A unit that failed over ledgers AND meters under the member that served it, never the model
/// it was opened under. RED: without `served` the tokens sit under `m` and nothing meters.
#[test]
fn a_failed_over_unit_ledgers_and_meters_under_the_serving_member() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(40));
    r.money.served(&ctx(1), "m2", "fallback");
    r.money.settle_end(UnitKey::new(1), 200);
    let rows = metering_rows(&r);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].model.as_str(),
            rows[0].provider.as_str(),
            rows[0].requests,
            rows[0].tokens_input
        ),
        ("m2", "fallback", 1, 40)
    );
    let models: Vec<String> = r
        .gov
        .bucket_model_tokens(&r.cost, &r.key.id, WINDOW_TOTAL, NOW)
        .into_iter()
        .map(|(model, _)| model)
        .collect();
    assert_eq!(
        models,
        vec!["m2".to_string()],
        "ledgered under the serving model"
    );
}

/// A plane-qualified lane meters its request on the row the class mirror keys it by:
/// `(subject, plane)`, never a second row under the qualified string.
#[test]
fn a_plane_lane_unit_meters_on_the_planes_row() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.served(&ctx(1), "tp\u{1f}srv_read", "unused");
    r.money.settle_end(UnitKey::new(1), 200);
    let rows = metering_rows(&r);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (
            rows[0].model.as_str(),
            rows[0].provider.as_str(),
            rows[0].requests
        ),
        ("srv_read", "tp", 1)
    );
}

/// An undelivered end meters nothing (1.5.5 metered delivered responses only).
#[test]
fn an_undelivered_end_meters_nothing() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.served(&ctx(1), "m", "acme");
    r.money.settle_end(UnitKey::new(1), 503);
    assert!(metering_rows(&r).is_empty());
}

/// A cancelled stream meters only when its bill carries a reported count (1.5.5's drop path).
#[test]
fn a_cancelled_stream_meters_only_a_reported_bill() {
    let bill = |billed: Vec<(u32, u64)>| CancelBill {
        cause: ReasonCode::ClientGone,
        disposition: CANCEL_OK_PARTIAL,
        far_end_answered: true,
        streamed: true,
        billed,
    };
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.served(&ctx(1), "m", "acme");
    r.money.cancelled(&ctx(1), &bill(vec![(INPUT, 0)]));
    assert!(metering_rows(&r).is_empty(), "a zero bill meters nothing");
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.served(&ctx(1), "m", "acme");
    r.money.cancelled(&ctx(1), &bill(vec![(INPUT, 30)]));
    let rows = metering_rows(&r);
    assert_eq!((rows.len(), rows[0].tokens_input), (1, 30));
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

fn bill(cause: ReasonCode, amount: u64) -> CancelBill {
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
        .cancelled(&ctx(1), &bill(ReasonCode::ClientGone, 25));
    r.money
        .cancelled(&ctx(1), &bill(ReasonCode::ClientGone, 25));
    assert_eq!(
        (usage(&r).0, r.money.open_units()),
        (25, 0),
        "abandon then bill"
    );

    // The bill first, then the posted end.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(30));
    r.money
        .cancelled(&ctx(1), &bill(ReasonCode::ClientGone, 25));
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(
        (usage(&r).0, r.money.open_units()),
        (25, 0),
        "bill then abandon"
    );

    // A cancel the unit returns from (a deadline), then its end.
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(30));
    r.money
        .cancelled(&ctx(1), &bill(ReasonCode::DeadlineExceeded, 5));
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
    admit(&r);
    r.money.cancelled(
        &ctx(1),
        &CancelBill {
            cause: ReasonCode::DeadlineExceeded,
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
    admit(&r);
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(
        usage(&r).1,
        5,
        "a caller that went away keeps the fee charged"
    );
}

fn floor(class: u32, amount: u64) -> UnitCount {
    UnitCount {
        class,
        source: UNITS_FLOOR,
        amount,
    }
}

/// THE USAGE FLOOR (Q24/Q28): a delivered reply whose far-end usage could not be read bills the
/// plane's floor, never 0, exactly as a reported count does. RED: a filter that bills only
/// `UNITS_REPORTED` drops the floor and the unit ledgers 0.
#[test]
fn a_floor_count_bills_like_a_reported_one() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &[floor(INPUT, 51)]);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).0, 51, "the floor bills, once");
}

/// A cancelled stream bills its floor counts as it bills its reported ones (the four cancel rules
/// still decide WHETHER anything bills); an estimate beside them never bills.
#[test]
fn a_cancel_bill_carries_the_floor_counts_and_never_an_estimate() {
    let facts = crate::plane_driver::cancel::Facts {
        far_end_answered: true,
        streamed: true,
        units: vec![
            floor(INPUT, 40),
            UnitCount {
                class: FEE_UNIT,
                source: UNITS_ESTIMATED,
                amount: 9,
            },
        ],
    };
    let bill = CancelBill::new(ReasonCode::ClientGone, Some(CANCEL_OK_PARTIAL), &facts);
    assert_eq!(bill.billed, vec![(INPUT, 40)]);
}

/// A plane whose fee unit arrives as a floor count of 1 keeps its fee, as a reported 1 does: the
/// one billing rule ([`busbar_contract::abi::plane::units_bill`]) decides the fee unit too.
#[test]
fn a_fee_unit_floor_count_keeps_the_fee() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let _ = r.money.checkpoint(&ctx(1), &[floor(FEE_UNIT, 1)]);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 5, "a floor fee unit keeps the fee");
}

/// THE SESSION MONEY GUARD, kept by K6-4: a session on a unit whose money facts the root never
/// opened is refused at its open, as `Unpriced`: no session runs unbilled.
#[test]
fn a_session_on_a_unit_with_no_money_facts_is_refused() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    assert_eq!(r.money.session_opened(&ctx(2)), Err(ReasonCode::Unpriced));
}

/// K6-4 (THE DESIGN §7, "A session is one unit with one line"): each turn's cumulative counts are a
/// checkpoint, never a line; the session's end writes ONE line of its last cumulative counts, and
/// the unit's own end then ledgers nothing twice.
#[test]
fn a_session_writes_one_line_of_its_last_cumulative_counts_at_its_end() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    assert_eq!(r.money.session_opened(&ctx(1)), Ok(()));
    for n in [30, 75, 120] {
        assert_eq!(
            r.money.checkpoint(&ctx(1), &reported(n)),
            Checkpoint::Continue
        );
    }
    assert_eq!(usage(&r).0, 0, "a turn is a checkpoint, never a line");
    r.money.session_ended(&ctx(1));
    assert_eq!(usage(&r).0, 120, "the session's one line");
    r.money.session_ended(&ctx(1));
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).0, 120, "nothing is ledgered twice");
    assert_eq!(r.money.open_units(), 0, "the unit's end closes it");
}

/// A cancel on either side of a session bills nothing of its own: the near side's facts never
/// see the far end answer, so its cancel bill is empty, and a session that took it as its line
/// would serve audio and bill none. The session's end bills its last cumulative counts. RED before
/// K6-4: the side's empty bill was the session's only line.
#[test]
fn a_cancelled_side_does_not_replace_the_sessions_line() {
    for cause in [ReasonCode::ClientGone, ReasonCode::OverBudget] {
        let r = rig(None, 0, ExhaustionMode::FinishUnit);
        assert_eq!(r.money.session_opened(&ctx(1)), Ok(()));
        let _ = r.money.checkpoint(&ctx(1), &reported(90));
        r.money.cancelled(
            &ctx(1),
            &CancelBill {
                cause,
                disposition: CANCEL_OK_PARTIAL,
                far_end_answered: false,
                streamed: false,
                billed: Vec::new(),
            },
        );
        r.money.cancelled(&ctx(1), &bill(cause, 40));
        assert_eq!(usage(&r).0, 0, "{cause:?}: a side's bill is not the line");
        r.money.session_ended(&ctx(1));
        assert_eq!(usage(&r).0, 90, "{cause:?}: what the session served");
    }
}

/// The caller went away before the session's cleanup ran: its end is posted once, and the
/// session's one line is written by the cleanup, which closes the unit.
#[test]
fn an_abandoned_session_is_billed_by_its_cleanup_and_closes() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    assert_eq!(r.money.session_opened(&ctx(1)), Ok(()));
    let _ = r.money.checkpoint(&ctx(1), &reported(55));
    r.money.abandoned(&ctx(1), Ended::AlreadySettled);
    assert_eq!(r.posted.0.load(Ordering::SeqCst), 1);
    assert_eq!(usage(&r).0, 0);
    r.money.session_ended(&ctx(1));
    assert_eq!(usage(&r).0, 55);
    assert_eq!(r.money.open_units(), 0);
}

/// A session's estimate never bills, and its floor counts bill like reported ones.
#[test]
fn a_sessions_line_carries_reported_and_floor_counts_never_an_estimate() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    assert_eq!(r.money.session_opened(&ctx(1)), Ok(()));
    let _ = r.money.checkpoint(
        &ctx(1),
        &[
            UnitCount {
                class: INPUT,
                source: UNITS_ESTIMATED,
                amount: 500,
            },
            floor(1, 7),
        ],
    );
    r.money.session_ended(&ctx(1));
    assert_eq!(usage(&r).0, 7);
}

/// A SESSION'S FEE IS REFUNDED WHEN ITS OPEN FAILS, AS ITS OWN FEE UNIT (ARCHITECT Q-L5-FEE (A);
/// Q17-6; TODO row 17): a session plane declares `per_session` as its fee unit and a billable class.
/// A session whose far end never answered reports no fee unit, and its end gives back ONE
/// `per_session` from the plane's fee lane; a session whose far end answered reports it `1` and
/// keeps its fee. The fee unit is never ledgered as usage.
#[test]
fn a_session_whose_open_failed_is_refunded_its_per_session_fee() {
    use busbar_contract::plane::PER_SESSION;
    use busbar_kernel_ledger::cost::{plane_fee_lane, PlaneFees};
    let fees = crate::config::PlaneFeesMap::from([(
        "sp".to_string(),
        PlaneFees {
            per_request: 0,
            per_session: 40,
        },
    )]);
    let cost = Arc::new(cost_model(None, 0).with_plane_fees(&fees));
    let pool = format!("sp{}", crate::governance::PLANE_LANE_SEP);
    let spend = |gov: &GovState| {
        gov.derived_bucket_usage(&cost, "k", WINDOW_TOTAL, true, NOW)
            .expect("usage")
            .spend_cents
    };
    let one = BTreeMap::from([(PER_SESSION.to_string(), 1)]);
    for (answered, kept) in [(false, 0), (true, 40)] {
        let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("gov"));
        let money = PlaneMoney::new(gov.clone(), Arc::new(Posted::default()));
        money.open(
            UnitKey::new(1),
            UnitMoney {
                key: key(),
                cost: cost.clone(),
                pool: pool.clone(),
                model: "m".into(),
                classes: Arc::from(vec![
                    "input".to_string(),
                    "output".to_string(),
                    PER_SESSION.to_string(),
                ]),
                arrived: NOW,
                mode: ExhaustionMode::FinishUnit,
                fee: plane_fees(),
                charge: Default::default(),
            },
        );
        // The session's fee, charged at its open on the plane's fee lane.
        gov.record_usage(&cost, &key(), "", &plane_fee_lane("sp"), &one, NOW);
        assert_eq!(spend(&gov), 40, "the session fee charged");
        assert_eq!(money.session_opened(&ctx(1)), Ok(()));
        if answered {
            let _ = money.checkpoint(&ctx(1), &[fee_reported(1), reported(7)[0]]);
        }
        money.session_ended(&ctx(1));
        money.settle_end(UnitKey::new(1), 101);
        assert_eq!(
            spend(&gov),
            kept,
            "answered={answered}: refunded only when the far end never answered"
        );
    }
}
