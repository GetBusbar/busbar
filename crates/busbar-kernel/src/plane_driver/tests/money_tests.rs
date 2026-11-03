// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
use crate::governance::WINDOW_TOTAL;
use crate::plane_driver::CancelBill;
use crate::registry::Generation;

const NOW: u64 = 1_700_000_000;
const INPUT: u32 = 0;

fn ctx(key: u64) -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

fn cost(budget_cents: Option<u64>, fee: i64) -> Arc<CostModel> {
    Arc::new(cost_model(budget_cents, fee))
}

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

    unit: UnitMoney,
}

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
    let gov = Arc::new(GovState::new(crate::real_store::store(), None).expect("gov"));
    let posted = Arc::new(Posted::default());
    let money = PlaneMoney::new(gov.clone(), posted.clone());
    let (cost, key) = (cost(budget_cents, fee), key());
    let unit = UnitMoney {
        key: key.clone(),
        cost: cost.clone(),
        pool: String::new(),
        lane: "m".into(),
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

#[test]
fn a_plane_that_reports_no_fee_unit_has_its_fee_refunded() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let _ = r.money.checkpoint(&ctx(1), &[fee_reported(0)]);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).1, 0, "the plane decides: no fee unit, no fee");
}

#[test]
fn a_plane_that_reports_its_fee_unit_keeps_the_fee() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let _ = r.money.checkpoint(&ctx(1), &[fee_reported(1)]);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 5, "the plane reported its fee unit");
}

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

fn group_month(r: &Rig, at: u64) -> (u64, i64) {
    let u = r
        .gov
        .derived_bucket_usage(
            &r.cost,
            "group:g@month",
            crate::governance::WINDOW_MONTH,
            true,
            at,
        )
        .expect("usage");
    (u.tokens, u.spend_cents)
}

fn a_later_window() -> u64 {
    let today = crate::store::now();
    assert_ne!(
        crate::governance::budget_window(crate::governance::WINDOW_MONTH, NOW),
        crate::governance::budget_window(crate::governance::WINDOW_MONTH, today),
        "test precondition: the arrival must be a different window than now"
    );
    today
}

#[test]
fn test_flat_fee_charge_and_refund_use_charged_at_window() {
    let r = rig_with(
        Some(1_000_000),
        30,
        ExhaustionMode::FinishUnit,
        plane_fees(),
    );
    let today = a_later_window();
    admit(&r);
    assert_eq!(
        group_month(&r, NOW).1,
        30,
        "admission charged the flat fee into the charged_at window"
    );
    assert_eq!(usage(&r).1, 30, "and onto the key");
    assert_eq!(group_month(&r, today).1, 0, "nothing in the now window");

    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(
        group_month(&r, NOW).1,
        0,
        "non-2xx refund must land in the charged_at window (net 0)"
    );
    assert_eq!(usage(&r).1, 0);
    assert_eq!(
        group_month(&r, today).1,
        0,
        "neither charge nor refund may leak into the wall-clock 'now' window (#29)"
    );
}

#[test]
fn test_nonstream_token_fee_uses_charged_at_window_not_clock() {
    let r = rig_with(Some(1_000_000), 0, ExhaustionMode::FinishUnit, plane_fees());
    let today = a_later_window();
    let report = [
        UnitCount {
            class: INPUT,
            source: UNITS_REPORTED,
            amount: 600,
        },
        UnitCount {
            class: 1,
            source: UNITS_REPORTED,
            amount: 400,
        },
        fee_reported(1),
    ];
    let _ = r.money.checkpoint(&ctx(1), &report);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(
        group_month(&r, NOW).0,
        1000,
        "token accrual must be attributed to the charged_at (header-arrival) window"
    );
    assert_eq!(
        group_month(&r, today).0,
        0,
        "token accrual must NOT leak into the wall-clock 'now' window (the #29 split bug)"
    );
    assert_eq!(
        usage(&r).0,
        1000,
        "the key's all-time bucket sees the tokens"
    );
}

#[test]
fn the_fee_unit_is_one_per_delivered_request_that_routed_upstream() {
    for (status, report, fee, why) in [
        (200u32, Some(1u64), 5i64, "delivered and routed upstream"),
        (200, Some(0), 0, "delivered, but no upstream leg"),
        (502, Some(0), 0, "routed upstream, but undelivered (502)"),
        (404, Some(0), 0, "routed upstream, but undelivered (404)"),
        (503, None, 0, "neither delivered nor routed"),
    ] {
        let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
        admit(&r);
        assert_eq!(usage(&r).1, 5, "{why}: the admission charged the fee");
        if let Some(n) = report {
            let _ = r.money.checkpoint(&ctx(1), &[fee_reported(n)]);
        }
        r.money.settle_end(UnitKey::new(1), status);
        assert_eq!(usage(&r).1, fee, "{why}");
    }
}

fn metering_rows(r: &Rig) -> Vec<busbar_contract::records::MeteringRow> {
    r.gov.flush_metering();
    r.gov
        .metering_for(crate::governance::metering_bucket(NOW))
        .expect("metering read")
}

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

#[test]
fn a_door_unit_arriving_at_a_bucket_boundary_is_metered_in_the_bucket_it_arrived_in() {
    use crate::governance::metering_bucket;
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let arrived = metering_bucket(NOW) - 1;
    assert_ne!(
        metering_bucket(arrived),
        metering_bucket(arrived + 1),
        "one second later is a different bucket, which is what makes this a straddle"
    );
    assert_ne!(
        metering_bucket(arrived),
        metering_bucket(crate::store::now()),
        "and the clock is in neither"
    );
    r.money.open(
        UnitKey::new(1),
        UnitMoney {
            arrived,
            ..r.unit.clone()
        },
    );
    let _ = r.money.checkpoint(&ctx(1), &reported(40));
    r.money.served(&ctx(1), "m", "acme");
    r.money.settle_end(UnitKey::new(1), 200);
    r.gov.flush_metering();
    let rows_in = |bucket| {
        r.gov
            .metering_for(bucket)
            .expect("metering read")
            .into_iter()
            .filter(|row| row.key_id == r.key.id)
            .count()
    };
    assert_eq!(
        rows_in(metering_bucket(arrived)),
        1,
        "the unit's figures land in the bucket it arrived in"
    );
    assert_eq!(
        rows_in(metering_bucket(arrived + 1)),
        0,
        "and nothing leaked into the bucket the clock was about to roll into"
    );
}

#[test]
fn a_stream_cut_by_its_far_end_bills_and_meters_what_its_plane_ledgered() {
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
    r.money.served(&ctx(1), "m", "acme");
    r.money.settle_end_as(
        UnitKey::new(1),
        UnitEnd {
            caller_status: 200,
            cut: true,
        },
    );
    let rows = metering_rows(&r);
    assert_eq!(rows.len(), 1, "a cut stream meters what it spent: {rows:?}");
    let row = &rows[0];
    assert_eq!(
        (row.model.as_str(), row.provider.as_str(), row.requests),
        ("m", "acme", 1)
    );
    assert_eq!(
        (row.tokens_input, row.tokens_output),
        (40, 0),
        "the row carries the tokens the plane ledgered"
    );
    let (tokens, spend) = usage(&r);
    assert_eq!(tokens, 40, "every token the plane ledgered bills");
    assert!(spend >= 5, "and the fee its plane reported stands: {spend}");
    let u = r
        .gov
        .derived_bucket_usage(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
        .expect("usage");
    assert_eq!(u.requests, 1, "the request unit counts once");
}

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
        .bucket_model_tokens(&r.key.id, WINDOW_TOTAL, NOW)
        .into_iter()
        .map(|(model, _)| model)
        .collect();
    assert_eq!(
        models,
        vec!["m2".to_string()],
        "ledgered under the serving model"
    );
}

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

#[test]
fn a_plane_named_lane_is_the_units_ledger_lane_not_its_route_entry() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.open(
        UnitKey::new(1),
        UnitMoney {
            lane: "tp\u{1f}srv".into(),
            ..r.unit.clone()
        },
    );
    let _ = r.money.checkpoint(&ctx(1), &reported(5));
    r.money.laned(&ctx(1), "other\u{1f}x");
    assert_eq!(
        r.money.serving(UnitKey::new(1)).as_deref(),
        Some("tp\u{1f}srv"),
        "a lane carrying the separator names nothing"
    );
    r.money.laned(&ctx(1), "srv_read");
    r.money.served(&ctx(1), "tp\u{1f}srv", "srv");
    assert_eq!(
        r.money.serving(UnitKey::new(1)).as_deref(),
        Some("tp\u{1f}srv_read"),
        "the plane's lane, qualified by its own key, holds over the serving member"
    );
    r.money.settle_end(UnitKey::new(1), 200);
    let rows = metering_rows(&r);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (
            rows[0].model.as_str(),
            rows[0].provider.as_str(),
            rows[0].requests
        ),
        ("srv_read", "tp", 1)
    );
    let models: Vec<String> = r
        .gov
        .bucket_model_tokens(&r.key.id, WINDOW_TOTAL, NOW)
        .into_iter()
        .map(|(model, _)| model)
        .collect();
    assert_eq!(
        models,
        vec!["tp\u{1f}srv_read".to_string()],
        "ledgered under the lane"
    );
}

#[test]
fn a_plane_units_declared_class_counts_reach_its_metering_row() {
    const CALLS: u32 = 0;
    const BYTES: u32 = 1;
    let r = rig_with(None, 0, ExhaustionMode::FinishUnit, plane_fees());
    r.money.open(
        UnitKey::new(1),
        UnitMoney {
            lane: "tp\u{1f}srv".into(),
            classes: Arc::from(vec![
                "calls".to_string(),
                "bytes".to_string(),
                busbar_contract::plane::PER_REQUEST.to_string(),
            ]),
            ..r.unit.clone()
        },
    );
    let report = [
        fee_reported(1),
        UnitCount {
            class: CALLS,
            source: UNITS_REPORTED,
            amount: 1,
        },
        UnitCount {
            class: BYTES,
            source: UNITS_REPORTED,
            amount: 37,
        },
    ];
    let _ = r.money.checkpoint(&ctx(1), &report);
    r.money.laned(&ctx(1), "srv_read");
    r.money.settle_end(UnitKey::new(1), 200);
    let rows = metering_rows(&r);
    let counts: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                row.model.as_str(),
                row.provider.as_str(),
                row.requests,
                row.usage_units.clone(),
            )
        })
        .collect();
    assert_eq!(
        counts,
        vec![(
            "srv_read",
            "tp",
            1,
            BTreeMap::from([("bytes".to_string(), 37), ("calls".to_string(), 1)]),
        )],
        "one request on the plane's row, carrying every declared class it reported and no fee unit"
    );
}

#[test]
fn a_unit_naming_no_lane_keeps_its_route_entry() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.laned(&ctx(1), "");
    r.money.served(&ctx(1), "tp\u{1f}srv", "srv");
    assert_eq!(
        r.money.serving(UnitKey::new(1)).as_deref(),
        Some("tp\u{1f}srv")
    );
}

#[test]
fn an_undelivered_end_meters_nothing() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    r.money.served(&ctx(1), "m", "acme");
    r.money.settle_end(UnitKey::new(1), 503);
    assert!(metering_rows(&r).is_empty());
}

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

#[test]
fn finish_unit_never_cuts() {
    let r = rig(Some(1), 0, ExhaustionMode::FinishUnit);
    assert_eq!(
        r.money.checkpoint(&ctx(1), &reported(1_000_000)),
        Checkpoint::Continue
    );
}

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

#[test]
fn every_path_ledgers_a_unit_exactly_once_and_closes_it() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &reported(10));
    r.money.finished(&ctx(1));
    r.money.settle_end(UnitKey::new(1), 200);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!((usage(&r).0, r.money.open_units()), (10, 0), "complete");

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

#[test]
fn a_floor_count_bills_like_a_reported_one() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let _ = r.money.checkpoint(&ctx(1), &[floor(INPUT, 51)]);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(usage(&r).0, 51, "the floor bills, once");
}

#[test]
fn a_cancel_bill_carries_the_floor_counts_and_never_an_estimate() {
    let facts = crate::plane_driver::cancel::Facts {
        headed: false,
        status: 0,
        far_end_answered: true,
        streamed: true,
        content: true,
        cut: false,
        relayed: false,
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

#[test]
fn a_fee_unit_floor_count_keeps_the_fee() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    admit(&r);
    let _ = r.money.checkpoint(&ctx(1), &[floor(FEE_UNIT, 1)]);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 5, "a floor fee unit keeps the fee");
}

#[test]
fn a_session_on_a_unit_with_no_money_facts_is_refused() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    assert_eq!(r.money.session_opened(&ctx(2)), Err(ReasonCode::Unpriced));
}

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
        let gov = Arc::new(GovState::new(crate::real_store::store(), None).expect("gov"));
        let money = PlaneMoney::new(gov.clone(), Arc::new(Posted::default()));
        money.open(
            UnitKey::new(1),
            UnitMoney {
                key: key(),
                cost: cost.clone(),
                pool: pool.clone(),
                lane: "m".into(),
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

#[test]
fn red_a_book_with_no_signing_key_lends_every_principal_its_own_reference() {
    let node = |material: Option<[u8; 32]>| {
        let gov = Arc::new(GovState::new(crate::real_store::store(), None).expect("gov"));
        let money = PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted::default()));
        let slot = money.caller_refs().expect("the book lends a slot");
        if let Some(m) = material {
            gov.bind_deployment_caller_ref(m);
        }
        let lent = |p: &str| {
            slot.read()
                .unwrap()
                .as_ref()
                .map(|k| k.caller_ref(p))
                .unwrap_or_default()
        };
        (lent("oidc:alice"), lent("oidc:bob"))
    };

    let (boot_alice, boot_bob) = node(None);
    assert!(!boot_alice.is_empty() && !boot_bob.is_empty());
    assert_ne!(boot_alice, boot_bob);
    let keyset = [7u8; 32];
    let (alice, bob) = node(Some(keyset));
    assert!(
        !alice.is_empty() && !bob.is_empty(),
        "a verified principal was lent nothing"
    );
    assert_ne!(alice, bob, "two principals share one reference");

    assert_eq!(node(Some(keyset)), (alice.clone(), bob));

    assert_ne!(node(Some([8u8; 32])).0, alice);
    assert_ne!(
        boot_alice, alice,
        "the keyset, once bound, keys the reference"
    );
}

#[test]
fn red_a_node_with_no_signing_key_and_no_signing_chain_lends_two_principals_two_references() {
    let gov = Arc::new(GovState::new(crate::real_store::store(), None).expect("gov"));
    let money = PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted::default()));
    let slot = money.caller_refs().expect("the book lends a slot");
    let lent = |p: &str| {
        slot.read()
            .unwrap()
            .as_ref()
            .map(|k| k.caller_ref(p))
            .unwrap_or_default()
    };
    let (alice, bob) = (lent("oidc:alice"), lent("oidc:bob"));
    assert!(
        !alice.is_empty() && !bob.is_empty(),
        "a verified principal was lent the empty reference"
    );
    assert_ne!(alice, bob, "two verified principals share one reference");
    assert_eq!(lent("oidc:alice"), alice, "one principal, one reference");
}

#[test]
fn the_signing_material_keys_the_reference_and_the_keyset_backs_it() {
    let gov = Arc::new(GovState::new(crate::real_store::store(), None).expect("gov"));
    let slot = gov.caller_ref_slot();
    gov.bind_deployment_caller_ref([7u8; 32]);
    let by_keyset = slot.read().unwrap().as_ref().unwrap().caller_ref("p");
    gov.set_signing_key(Some(
        crate::governance::signing::TokenSigner::from_secret_bytes(&[9u8; 32], "k"),
    ));
    let by_signer = slot.read().unwrap().as_ref().unwrap().caller_ref("p");
    assert_ne!(
        by_signer, by_keyset,
        "the signing material did not key the reference"
    );
    gov.set_signing_key(None);
    assert_eq!(
        slot.read().unwrap().as_ref().unwrap().caller_ref("p"),
        by_keyset
    );
}

fn signer_nine() -> Option<crate::governance::signing::TokenSigner> {
    use crate::governance::signing::TokenSigner;
    Some(TokenSigner::from_secret_bytes(&[9u8; 32], "k"))
}

fn lent_to_p(gov: &GovState) -> String {
    gov.caller_ref_slot()
        .read()
        .unwrap()
        .as_ref()
        .map(|k| k.caller_ref("p"))
        .unwrap_or_default()
}

fn booted(signer: Option<crate::governance::signing::TokenSigner>) -> GovState {
    let store: Arc<dyn RecordStore> = crate::real_store::store();
    GovState::new_with_signer(store, None, signer).expect("gov")
}

#[test]
fn a_node_built_with_a_signer_keys_the_reference_by_it_not_by_the_boot_key() {
    let first_boot = booted(signer_nine());
    let second_boot = booted(signer_nine());
    let by_signer = lent_to_p(&first_boot);
    assert!(!by_signer.is_empty());
    assert_eq!(
        lent_to_p(&second_boot),
        by_signer,
        "a per-boot key keyed a node built with a signer"
    );
    let keyless = booted(None);
    let by_boot = lent_to_p(&keyless);
    assert_ne!(by_boot, by_signer);
    keyless.set_signing_key(signer_nine());
    assert_eq!(lent_to_p(&keyless), by_signer);
}

#[test]
fn dropping_the_signer_with_no_keyset_falls_back_to_the_boot_key_never_to_nothing() {
    let gov = booted(None);
    let by_boot = lent_to_p(&gov);
    assert!(!by_boot.is_empty());
    gov.set_signing_key(signer_nine());
    assert_ne!(
        lent_to_p(&gov),
        by_boot,
        "the signer did not key the reference"
    );
    gov.set_signing_key(None);
    assert!(
        gov.caller_ref_slot().read().unwrap().is_some(),
        "dropping the signer emptied the slot"
    );
    assert_eq!(
        lent_to_p(&gov),
        by_boot,
        "dropping the signer did not fall back to the boot key"
    );
}

#[test]
fn the_checkpoint_check_agrees_with_the_checked_sums() {
    let unit = |class: u32, amount: u64| UnitCount {
        class,
        source: UNITS_REPORTED,
        amount,
    };
    let one = ["input".to_string(), "output".to_string()];
    let twice = ["input".to_string(), "input".to_string()];
    let cases: [(&[String], Vec<UnitCount>); 8] = [
        (&one[..], vec![]),
        (&one[..], vec![unit(0, 3), unit(1, 4)]),
        (&one[..], vec![unit(0, u64::MAX), unit(1, u64::MAX)]),
        (&one[..], vec![unit(0, u64::MAX), unit(0, 1)]),
        (&one[..], vec![unit(1, 1), unit(0, 2), unit(1, u64::MAX)]),
        (&one[..], vec![unit(7, u64::MAX), unit(7, u64::MAX)]),
        (&twice[..], vec![unit(0, u64::MAX), unit(1, 1)]),
        (
            &twice[..],
            vec![unit(0, u64::MAX / 2), unit(1, u64::MAX / 2)],
        ),
    ];
    for (classes, units) in &cases {
        let counts: Vec<(u32, u64)> = units.iter().map(|u| (u.class, u.amount)).collect();
        assert_eq!(
            super::adds_up(classes, units),
            super::named(classes, &counts, u64::checked_add).is_some(),
            "{classes:?} {counts:?}"
        );
    }
}

#[test]
fn units_over_every_shard_are_counted_and_closed() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let money = PlaneMoney::new(r.gov.clone(), r.posted.clone());
    let keys: Vec<u64> = (1..=3 * super::SHARDS as u64).collect();
    for k in &keys {
        money.open(UnitKey::new(*k), r.unit.clone());
    }
    assert_eq!(money.open_units(), keys.len());
    for k in &keys {
        assert_eq!(
            money.checkpoint(&ctx(*k), &reported(*k)),
            Checkpoint::Continue
        );
    }
    for k in &keys {
        money.settle_end(UnitKey::new(*k), 200);
    }
    assert_eq!(money.open_units(), 0, "every end closes its unit");
}

#[test]
fn served_requests_keep_each_units_pinned_group_until_settlement() {
    let r = rig(None, 0, ExhaustionMode::FinishUnit);
    let mut later_key = (*r.key).clone();
    later_key.group = Some("later".into());
    r.money.open(
        UnitKey::new(2),
        UnitMoney {
            key: Arc::new(later_key),
            ..r.unit.clone()
        },
    );
    r.money.served(&ctx(1), "m", "acme");
    r.money.served(&ctx(2), "m", "acme");
    r.money.settle_end(UnitKey::new(2), 200);
    r.money.settle_end(UnitKey::new(1), 200);
    let rows = metering_rows(&r);
    assert_eq!(
        rows.len(),
        2,
        "same key and serving lane retain both historical groups"
    );
    let counts: BTreeMap<_, _> = rows
        .into_iter()
        .map(|row| {
            assert!(row.pricing_version.is_empty());
            (row.key_group_at_use, row.requests)
        })
        .collect();
    assert_eq!(counts, [("g".into(), 1), ("later".into(), 1)].into());
}

fn admit_parent(r: &Rig) -> ParentMoney {
    let grant = Arc::new(
        r.gov
            .try_admit(&r.cost, &r.key, "", NOW)
            .expect("real admission"),
    );
    r.money
        .open_admitted(UnitKey::new(1), r.unit.clone(), grant);
    r.money
        .parent_money(UnitKey::new(1), &r.key)
        .expect("live admitted parent")
}

fn child(r: &Rig, parent: &ParentMoney, id: u64) -> Result<(), ReasonCode> {
    r.money.open_child(
        parent,
        UnitKey::new(id),
        "m".into(),
        r.unit.classes.clone(),
        r.unit.fee.clone(),
    )
}

#[test]
fn admitted_child_prices_nonzero_usage_under_exactly_one_real_fee() {
    let baseline = rig_with(None, 0, ExhaustionMode::FinishUnit, plane_fees());
    let _ = baseline.money.checkpoint(&ctx(1), &reported(1_000_000));
    baseline.money.settle_end(UnitKey::new(1), 200);
    let priced = usage(&baseline).1;
    assert!(priced > 0, "the media control has a real nonzero price");

    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    let parent = admit_parent(&r);
    child(&r, &parent, 2).expect("borrow real admission");
    assert_eq!(usage(&r).1, 5, "registration cannot charge a second fee");
    assert_eq!(r.money.session_opened(&ctx(2)), Ok(()));
    let _ = r
        .money
        .checkpoint(&ctx(2), &[reported(1_000_000)[0], fee_reported(1)]);
    r.money.settle_end(UnitKey::new(1), 503);
    assert_eq!(usage(&r).1, 5, "parent refund waits for the actual child");
    r.money.session_ended(&ctx(2));
    r.money.settle_end(UnitKey::new(2), 200);
    r.money.session_ended(&ctx(2));
    r.money.settle_end(UnitKey::new(2), 200);
    assert_eq!(
        usage(&r),
        (1_000_000, priced + 5),
        "one fee and one priced media line"
    );
    assert_eq!(r.money.open_units(), 0);
    let totals = r
        .gov
        .derived_bucket_usage(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
        .unwrap();
    assert_eq!(
        totals.requests, 1,
        "the real governor admitted exactly one request"
    );
}

#[test]
fn parent_and_all_children_must_finish_refundable_before_the_single_refund() {
    for child_first in [false, true] {
        let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
        let parent = admit_parent(&r);
        child(&r, &parent, 2).unwrap();
        child(&r, &parent, 3).unwrap();
        if child_first {
            r.money.settle_end(UnitKey::new(2), 503);
        } else {
            r.money.settle_end(UnitKey::new(1), 503);
        }
        assert_eq!(usage(&r).1, 5);
        if child_first {
            r.money.settle_end(UnitKey::new(1), 503);
        } else {
            r.money.settle_end(UnitKey::new(2), 503);
        }
        assert_eq!(usage(&r).1, 5, "the second child still owns participation");
        r.money.settle_end(UnitKey::new(3), 503);
        assert_eq!(usage(&r).1, 0, "all participants refundable: one refund");
        r.money.settle_end(UnitKey::new(1), 503);
        r.money.settle_end(UnitKey::new(2), 503);
        r.money.settle_end(UnitKey::new(3), 503);
        assert_eq!(
            usage(&r).1,
            0,
            "repeated terminal calls cannot refund again"
        );
    }
}

#[test]
fn child_cancellation_bills_its_actual_media_once_and_keeps_an_incurred_fee() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    let parent = admit_parent(&r);
    child(&r, &parent, 2).unwrap();
    let _ = r
        .money
        .checkpoint(&ctx(2), &[reported(90)[0], fee_reported(1)]);
    r.money
        .cancelled(&ctx(2), &bill(ReasonCode::ClientGone, 70));
    r.money
        .cancelled(&ctx(2), &bill(ReasonCode::ClientGone, 70));
    r.money.settle_end(UnitKey::new(1), 503);
    r.money.settle_end(UnitKey::new(2), 499);
    assert_eq!(usage(&r), (70, 5));
    assert_eq!(r.money.open_units(), 0);
}

#[test]
fn abandoned_child_closes_fee_participation_once_without_inventing_a_refund() {
    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    let parent = admit_parent(&r);
    child(&r, &parent, 2).unwrap();
    let _ = r.money.checkpoint(&ctx(2), &reported(55));
    r.money.abandoned(&ctx(2), Ended::AlreadySettled);
    r.money.settle_end(UnitKey::new(1), 503);
    r.money
        .cancelled(&ctx(2), &bill(ReasonCode::ClientGone, 40));
    r.money
        .cancelled(&ctx(2), &bill(ReasonCode::ClientGone, 40));
    r.money.settle_end(UnitKey::new(2), 503);
    assert_eq!(usage(&r), (40, 5));
    assert_eq!(r.money.open_units(), 0);
}

#[test]
fn parent_money_requires_the_actual_live_governor_registration() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    assert!(
        r.money.parent_money(UnitKey::new(1), &r.key).is_err(),
        "ordinary open is not an admission"
    );
    assert!(
        r.money.parent_money(UnitKey::new(99), &r.key).is_err(),
        "missing parent"
    );
    let parent = admit_parent(&r);
    let mut foreign = r.key.as_ref().clone();
    foreign.generation_hash = "another-generation".into();
    assert!(
        r.money.parent_money(UnitKey::new(1), &foreign).is_err(),
        "foreign billing key"
    );
    let other = rig(None, 5, ExhaustionMode::FinishUnit);
    let _other_parent = admit_parent(&other);
    assert!(
        child(&other, &parent, 2).is_err(),
        "foreign book's genuine parent"
    );
    assert!(
        child(&r, &parent, 1).is_err(),
        "parent cannot overwrite itself"
    );
    child(&r, &parent, 2).unwrap();
    assert!(
        child(&r, &parent, 2).is_err(),
        "cannot replace a registered child"
    );
    r.money.finished(&ctx(1));
    assert!(
        r.money.parent_money(UnitKey::new(1), &r.key).is_err(),
        "finished parent"
    );
    assert!(
        child(&r, &parent, 3).is_err(),
        "held token cannot revive finished parent"
    );
    r.money.settle_end(UnitKey::new(1), 200);
    assert!(child(&r, &parent, 3).is_err(), "closed parent");
    let _replacement = admit_parent(&r);
    assert!(
        child(&r, &parent, 3).is_err(),
        "same key reused by another real registration"
    );
}

#[test]
fn selecting_a_parent_lane_does_not_invalidate_real_admission_provenance() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    let parent = admit_parent(&r);
    r.money.served(&ctx(1), "m2", "provider");
    r.money.laned(&ctx(1), "m");
    child(&r, &parent, 17).expect("same-shard child after parent Arc changed");
    assert_eq!(r.money.serving(UnitKey::new(17)).as_deref(), Some("m"));
    let _ = r.money.checkpoint(&ctx(17), &reported(31));
    r.money.settle_end(UnitKey::new(1), 200);
    r.money.settle_end(UnitKey::new(17), 200);
    assert_eq!(usage(&r), (31, 5));
}

#[test]
fn child_exit_authority_requires_a_real_matching_live_child_even_after_parent_closes() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    let parent = admit_parent(&r);
    assert_eq!(r.money.validate_parent(&parent, &r.key), Ok(()));
    assert!(r
        .money
        .validate_child(&parent, UnitKey::new(2), &r.key)
        .is_err());
    child(&r, &parent, 2).unwrap();
    assert_eq!(
        r.money.validate_child(&parent, UnitKey::new(2), &r.key),
        Ok(())
    );
    let mut foreign = r.key.as_ref().clone();
    foreign.generation_hash = "foreign".into();
    assert!(r.money.validate_parent(&parent, &foreign).is_err());
    assert!(r
        .money
        .validate_child(&parent, UnitKey::new(2), &foreign)
        .is_err());
    assert!(r
        .money
        .validate_child(&parent, UnitKey::new(1), &r.key)
        .is_err());
    let other = rig(None, 5, ExhaustionMode::FinishUnit);
    let other_parent = admit_parent(&other);
    child(&other, &other_parent, 2).unwrap();
    assert!(r
        .money
        .validate_child(&other_parent, UnitKey::new(2), &r.key)
        .is_err());
    r.money.settle_end(UnitKey::new(1), 200);
    assert!(r.money.validate_parent(&parent, &r.key).is_err());
    assert_eq!(
        r.money.validate_child(&parent, UnitKey::new(2), &r.key),
        Ok(())
    );
    r.money.finished(&ctx(2));
    assert_eq!(
        r.money.validate_child(&parent, UnitKey::new(2), &r.key),
        Ok(()),
        "driver finished precedes teller terminal: retain the real child's exit authority"
    );
    r.money.settle_end(UnitKey::new(2), 200);
    assert!(r
        .money
        .validate_child(&parent, UnitKey::new(2), &r.key)
        .is_err());
    r.money.open(UnitKey::new(2), r.unit.clone());
    assert!(
        r.money
            .validate_child(&parent, UnitKey::new(2), &r.key)
            .is_err(),
        "a new ordinary registration cannot impersonate the actual child"
    );
}

#[test]
fn the_real_governor_concurrency_grant_lives_through_child_and_parent_authority() {
    let mut r = rig(None, 5, ExhaustionMode::FinishUnit);
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Concurrent,
                amount: 1,
                per: None,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    r.cost = Arc::new(CostModel::resolve_parts(None, 5, &groups));
    r.unit.cost = r.cost.clone();
    let parent = admit_parent(&r);
    assert_eq!(parent.grant.held(), 1, "an actual concurrent hold exists");
    child(&r, &parent, 2).unwrap();
    assert!(r.gov.try_admit(&r.cost, &r.key, "", NOW).is_err());
    r.money.settle_end(UnitKey::new(1), 200);
    assert!(
        r.gov.try_admit(&r.cost, &r.key, "", NOW).is_err(),
        "the child's real grant holds the cap"
    );
    r.money.settle_end(UnitKey::new(2), 200);
    assert!(
        r.gov.try_admit(&r.cost, &r.key, "", NOW).is_err(),
        "live host parent authority retains custody too"
    );
    drop(parent);
    assert!(
        r.gov.try_admit(&r.cost, &r.key, "", NOW).is_ok(),
        "the last real authority releases the actual gauge"
    );
}

#[test]
fn a_units_own_exit_authority_requires_its_actual_registered_governor_grant() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    let grant = Arc::new(r.gov.try_admit(&r.cost, &r.key, "", NOW).unwrap());
    assert!(
        r.money
            .validate_admitted(UnitKey::new(1), &r.key, &grant)
            .is_err(),
        "ordinary open is not admitted custody"
    );
    r.money
        .open_admitted(UnitKey::new(1), r.unit.clone(), grant.clone());
    let wrong = Arc::new(r.gov.try_admit(&r.cost, &r.key, "", NOW).unwrap());
    assert!(
        r.money
            .validate_admitted(UnitKey::new(1), &r.key, &wrong)
            .is_err(),
        "another actual grant for the same billing key is not this admission"
    );
    assert!(r
        .money
        .validate_admitted(UnitKey::new(99), &r.key, &grant)
        .is_err());
    let mut foreign = r.key.as_ref().clone();
    foreign.generation_hash = "foreign".into();
    assert!(r
        .money
        .validate_admitted(UnitKey::new(1), &foreign, &grant)
        .is_err());
    let parent = r.money.parent_money(UnitKey::new(1), &r.key).unwrap();
    child(&r, &parent, 2).unwrap();
    assert!(
        r.money
            .validate_admitted(UnitKey::new(2), &r.key, &grant)
            .is_err(),
        "shared child cannot impersonate its own governor admission"
    );
    assert_eq!(
        r.money.validate_admitted(UnitKey::new(1), &r.key, &grant),
        Ok(())
    );
    r.money.finished(&ctx(1));
    assert_eq!(
        r.money.validate_admitted(UnitKey::new(1), &r.key, &grant),
        Ok(()),
        "finished precedes the teller's terminal authority check"
    );
    r.money.settle_end(UnitKey::new(1), 200);
    assert!(r
        .money
        .validate_admitted(UnitKey::new(1), &r.key, &grant)
        .is_err());
    r.money
        .open_admitted(UnitKey::new(1), r.unit.clone(), wrong);
    assert!(
        r.money
            .validate_admitted(UnitKey::new(1), &r.key, &grant)
            .is_err(),
        "reused unit key cannot revive the settled authority"
    );
}

fn reserve_parent(r: &Rig) -> ReservationMoney {
    let grant = Arc::new(
        r.gov
            .try_admit(&r.cost, &r.key, "", NOW)
            .expect("real admission"),
    );
    r.money
        .open_admitted(UnitKey::new(1), r.unit.clone(), grant);
    r.money
        .reserve_admission(UnitKey::new(1), &r.key)
        .expect("reserve actual live admission")
}

fn adopt(r: &Rig, reservation: ReservationMoney, id: u64) -> Result<(), ReturnedReservation> {
    r.money.adopt_reserved(
        reservation,
        UnitKey::new(id),
        "m".into(),
        r.unit.classes.clone(),
        r.unit.fee.clone(),
        &r.key,
    )
}

#[test]
fn reserved_admission_becomes_priced_media_after_the_original_mint_has_settled() {
    let baseline = rig_with(None, 0, ExhaustionMode::FinishUnit, plane_fees());
    let _ = baseline.money.checkpoint(&ctx(1), &reported(1_000_000));
    baseline.money.settle_end(UnitKey::new(1), 200);
    let priced = usage(&baseline).1;
    assert!(priced > 0);

    let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
    let reservation = reserve_parent(&r);
    let parent = r.money.parent_money(UnitKey::new(1), &r.key).unwrap();
    let _ = r.money.checkpoint(&ctx(1), &[fee_reported(1)]);
    r.money.settle_end(UnitKey::new(1), 200);
    assert_eq!(
        r.money.open_units(),
        0,
        "the mint's actual registration has ended"
    );
    assert!(
        child(&r, &parent, 2).is_err(),
        "a live-parent token cannot revive the closed mint"
    );
    drop(parent);
    // The child deliberately has different class indices. Fee and media resolve by its names.
    let classes = Arc::from(vec![
        busbar_contract::plane::PER_REQUEST.to_string(),
        "input".into(),
        "output".into(),
    ]);
    assert!(r
        .money
        .adopt_reserved(
            reservation,
            UnitKey::new(2),
            "m".into(),
            classes,
            FeeRefund::PlaneFeeUnits(Arc::from(vec![0])),
            &r.key
        )
        .is_ok());
    assert_eq!(
        usage(&r).1,
        5,
        "adoption never asks the governor for a second fee"
    );
    assert_eq!(r.money.session_opened(&ctx(2)), Ok(()));
    let _ = r.money.checkpoint(
        &ctx(2),
        &[UnitCount {
            class: 1,
            source: UNITS_REPORTED,
            amount: 1_000_000,
        }],
    );
    r.money.session_ended(&ctx(2));
    r.money.settle_end(UnitKey::new(2), 200);
    r.money.settle_end(UnitKey::new(2), 200);
    assert_eq!(usage(&r), (1_000_000, priced + 5));
    let totals = r
        .gov
        .derived_bucket_usage(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
        .unwrap();
    assert_eq!(
        totals.requests, 1,
        "settled mint plus media is still one actual admission"
    );
    assert_eq!(r.money.open_units(), 0);
}

#[test]
fn unused_reservation_expiry_preserves_the_original_parents_fee_decision() {
    for incurred in [false, true] {
        let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
        let reservation = reserve_parent(&r);
        let _ = r
            .money
            .checkpoint(&ctx(1), &[fee_reported(u64::from(incurred))]);
        r.money.settle_end(UnitKey::new(1), 200);
        assert_eq!(
            usage(&r).1,
            5,
            "the real reservation keeps settlement pending"
        );
        assert_eq!(
            r.money.open_units(),
            0,
            "reservation is not a synthetic unit"
        );
        drop(reservation);
        assert_eq!(
            usage(&r).1,
            if incurred { 5 } else { 0 },
            "expiry incurs no fee of its own"
        );
        let totals = r
            .gov
            .derived_bucket_usage(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
            .unwrap();
        assert_eq!(
            totals.requests, 1,
            "expiry neither adds nor refunds a request"
        );
    }
}

#[test]
fn rejected_reserved_adoption_returns_the_unchanged_real_token_for_retry_or_cleanup() {
    for retry in [false, true] {
        let r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
        let reservation = reserve_parent(&r);
        r.money.settle_end(UnitKey::new(1), 503);
        let mut foreign_key = r.key.as_ref().clone();
        foreign_key.generation_hash = "foreign".into();
        let returned = match r.money.adopt_reserved(
            reservation,
            UnitKey::new(2),
            "m".into(),
            r.unit.classes.clone(),
            r.unit.fee.clone(),
            &foreign_key,
        ) {
            Err(returned) => returned,
            Ok(()) => panic!("foreign key must return custody"),
        };
        let (reason, reservation) = returned.into_parts();
        assert_eq!(reason, ReasonCode::Unpriced);
        assert_eq!((r.money.open_units(), usage(&r).1), (0, 5));
        let other = PlaneMoney::new(r.gov.clone(), Arc::new(Posted::default()));
        let returned = match other.adopt_reserved(
            reservation,
            UnitKey::new(2),
            "m".into(),
            r.unit.classes.clone(),
            r.unit.fee.clone(),
            &r.key,
        ) {
            Err(returned) => returned,
            Ok(()) => {
                panic!("even the same governor and full key cannot substitute a foreign book")
            }
        };
        let (_, reservation) = returned.into_parts();
        assert_eq!(
            (other.open_units(), r.money.open_units(), usage(&r).1),
            (0, 0, 5)
        );
        r.money.open(UnitKey::new(2), r.unit.clone());
        let returned = match adopt(&r, reservation, 2) {
            Err(returned) => returned,
            Ok(()) => panic!("existing destination must not be replaced"),
        };
        let (_, reservation) = returned.into_parts();
        assert_eq!(r.money.serving(UnitKey::new(2)).as_deref(), Some("m"));
        assert_eq!((r.money.open_units(), usage(&r).1), (1, 5));
        r.money.settle_end(UnitKey::new(2), 503);
        if retry {
            assert!(adopt(&r, reservation, 3).is_ok());
            let _ = r
                .money
                .checkpoint(&ctx(3), &[reported(7)[0], fee_reported(1)]);
            r.money.settle_end(UnitKey::new(3), 503);
            assert_eq!(
                usage(&r),
                (7, 5),
                "returned authority genuinely adopts once and bills"
            );
        } else {
            drop(reservation);
            assert_eq!(
                usage(&r),
                (0, 0),
                "returned unused authority cleans up and refunds once"
            );
        }
        assert_eq!(r.money.open_units(), 0);
        let totals = r
            .gov
            .derived_bucket_usage(&r.cost, &r.key.id, WINDOW_TOTAL, true, NOW)
            .unwrap();
        assert_eq!(totals.requests, 1);
    }
}

#[test]
fn reserving_requires_the_actual_live_original_admission() {
    let r = rig(None, 5, ExhaustionMode::FinishUnit);
    assert!(
        r.money.reserve_admission(UnitKey::new(1), &r.key).is_err(),
        "ordinary open has no actual grant"
    );
    assert!(
        r.money.reserve_admission(UnitKey::new(99), &r.key).is_err(),
        "missing parent"
    );
    let parent = admit_parent(&r);
    let mut foreign_key = r.key.as_ref().clone();
    foreign_key.generation_hash = "foreign".into();
    assert!(r
        .money
        .reserve_admission(UnitKey::new(1), &foreign_key)
        .is_err());
    child(&r, &parent, 2).unwrap();
    assert!(
        r.money.reserve_admission(UnitKey::new(2), &r.key).is_err(),
        "a shared child is not an original admission"
    );
    r.money.finished(&ctx(1));
    assert!(
        r.money.reserve_admission(UnitKey::new(1), &r.key).is_err(),
        "finished original cannot create new authority"
    );
    r.money.settle_end(UnitKey::new(1), 200);
    assert!(
        r.money.reserve_admission(UnitKey::new(1), &r.key).is_err(),
        "closed original cannot create new authority"
    );
}

#[test]
fn the_actual_reservation_grant_holds_concurrency_across_settled_mint_and_adoption() {
    for consume in [false, true] {
        let mut r = rig_with(None, 5, ExhaustionMode::FinishUnit, plane_fees());
        let groups = BTreeMap::from([(
            "g".to_string(),
            GroupCfg {
                enabled: true,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Concurrent,
                    amount: 1,
                    per: None,
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                    admission: None,
                    on_exhaustion: None,
                }],
                ..Default::default()
            },
        )]);
        r.cost = Arc::new(CostModel::resolve_parts(None, 5, &groups));
        r.unit.cost = r.cost.clone();
        let reservation = reserve_parent(&r);
        assert_eq!(
            reservation.grant.held(),
            1,
            "the reserved governor grant is real"
        );
        r.money.settle_end(UnitKey::new(1), 503);
        assert!(
            r.gov.try_admit(&r.cost, &r.key, "", NOW).is_err(),
            "reservation alone retains the actual concurrent hold"
        );
        if consume {
            assert!(adopt(&r, reservation, 2).is_ok());
            assert!(
                r.gov.try_admit(&r.cost, &r.key, "", NOW).is_err(),
                "adoption transfers the same real hold to its child"
            );
            r.money.settle_end(UnitKey::new(2), 503);
        } else {
            drop(reservation);
        }
        assert_eq!(
            usage(&r).1,
            0,
            "one pending parent fee refunded after its refundable child or unused expiry"
        );
        assert!(
            r.gov.try_admit(&r.cost, &r.key, "", NOW).is_ok(),
            "last child or unused expiry releases the actual concurrent hold"
        );
    }
}

#[test]
fn reserved_ticket_adoption_checks_receiving_authority_and_binding() {
    for mismatch in 0..13 {
        let r = rig(None, 7, ExhaustionMode::FinishUnit);
        let kernel = crate::teller::Kernel::new();
        let source_call = kernel.next_call();
        let store: Arc<dyn RecordStore> = crate::real_store::store();
        let identity = VerifiedTicketIdentity {
            id: "ticket-test".into(),
            principal: r.key.clone(),
            expires_at: NOW + 60,
            store: store.clone(),
            prefix: "test".into(),
            credential: "redacted".into(),
        };
        drop(reserve_parent(&r));
        let node = Arc::new(());
        let instance = Arc::new(());
        let reservation = r
            .money
            .reserve_ticket_admission(
                UnitKey::new(1),
                source_call,
                &r.key,
                &identity,
                node.clone(),
                instance.clone(),
            )
            .expect("actual source");
        assert!(reservation.matches(&identity));
        let spent = match SpentTicketReservation::after_redemption(reservation, &r.key) {
            Ok(spent) => spent,
            Err(_) => panic!("matching redeemed principal"),
        };
        r.money.settle_end(UnitKey::new(1), 200);
        let mut receiving = ctx(2);
        receiving.call = kernel.next_call();
        let grant = if mismatch == 1 {
            kernel.admit_token()
        } else {
            kernel.admit_token_for(receiving.call)
        };
        if mismatch == 2 {
            receiving.call = kernel.next_call();
        }
        if mismatch == 3 {
            receiving.key = UnitKey::new(1);
        }
        let principal = PrincipalId::new(if mismatch == 4 { "foreign" } else { "k" });
        let mut expected = r.key.as_ref().clone();
        if mismatch == 5 {
            expected.generation_hash.push('x');
        }
        let other_node = Arc::new(());
        let other_instance = Arc::new(());
        let other_store: Arc<dyn RecordStore> = crate::real_store::store();
        let other_money = PlaneMoney::new(r.gov.clone(), r.posted.clone());
        let outcome = spent.adopt(
            if mismatch == 9 {
                &other_money
            } else {
                &r.money
            },
            &receiving,
            &grant,
            &principal,
            &expected,
            "m".into(),
            r.unit.classes.clone(),
            r.unit.fee.clone(),
            if mismatch == 6 { &other_node } else { &node },
            if mismatch == 7 {
                &other_instance
            } else {
                &instance
            },
            if mismatch == 8 { &other_store } else { &store },
        );
        if (1..=9).contains(&mismatch) {
            assert!(outcome.is_err(), "mismatch {mismatch} must fail closed");
            drop(outcome);
        } else {
            let lineage = match outcome {
                Ok(lineage) => lineage,
                Err(_) => panic!("valid adoption"),
            };
            if mismatch == 10 {
                receiving.call = kernel.next_call();
            }
            if mismatch == 11 {
                receiving.key = UnitKey::new(3);
            }
            let terminal_principal = if mismatch == 12 {
                PrincipalId::new("foreign")
            } else {
                principal
            };
            let drawn = crate::settlement::requests_drawn_with_lineage(
                &receiving,
                &terminal_principal,
                true,
                Some(lineage),
            );
            if mismatch == 0 {
                assert_eq!(drawn, Ok(0), "real Client posting draws no second request");
            } else {
                assert!(drawn.is_err(), "stale terminal lineage {mismatch}");
            }
            assert_eq!(
                r.money.checkpoint(&ctx(2), &reported(1_000_000)),
                Checkpoint::Continue
            );
            r.money.settle_end(UnitKey::new(2), 200);
            assert_eq!(usage(&r).0, 1_000_000, "actual adopted usage priced once");
        }
    }
}

#[test]
fn reserved_ticket_holder_clones_share_one_financial_token() {
    let r = rig(None, 7, ExhaustionMode::FinishUnit);
    let kernel = crate::teller::Kernel::new();
    let identity = VerifiedTicketIdentity {
        id: "one-take".into(),
        principal: r.key.clone(),
        expires_at: NOW + 60,
        store: crate::real_store::store(),
        prefix: "test".into(),
        credential: "redacted".into(),
    };
    drop(reserve_parent(&r));
    let reservation = r
        .money
        .reserve_ticket_admission(
            UnitKey::new(1),
            kernel.next_call(),
            &r.key,
            &identity,
            Arc::new(()),
            Arc::new(()),
        )
        .expect("reserve");
    let spent = match SpentTicketReservation::after_redemption(reservation, &r.key) {
        Ok(spent) => spent,
        Err(_) => panic!("redeemed principal"),
    };
    let holder = crate::host_services::HostTicketAdmission::new(spent);
    let clone = holder.clone();
    r.money.settle_end(UnitKey::new(1), 500);
    let token = holder.take().expect("sole token");
    assert!(clone.take().is_none());
    assert_eq!(usage(&r).1, 7, "reservation retains original fee decision");
    drop(token);
    assert_eq!(
        usage(&r).1,
        0,
        "one final participation refunds exactly once"
    );
    drop(holder);
    drop(clone);
    assert_eq!(usage(&r).1, 0);
}
