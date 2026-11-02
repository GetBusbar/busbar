// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::governance::{LimitBlocked, MemoryStore, RecordStore, WINDOW_TOTAL};
use crate::registry::Generation;
use busbar_contract::abi::plane::{CANCEL_OK_PARTIAL, UNITS_REPORTED};
use busbar_contract::caps::OriginKind;
use busbar_contract::records::ScopeRef;
use busbar_kernel_ledger::cost::{PlaneFees, UnitRate};

const NOW: u64 = 1_700_000_000;
const A: &str = "group:g@total#pool:tier-a";
const B: &str = "group:g@total#pool:tier-b";
const ROOT: &str = "group:root@total";

struct Posted;
impl EndPost for Posted {
    fn post(&self, _: &UnitCtx, _: Ended) {}
}

struct Rig {
    store: Arc<MemoryStore>,
    gov: Arc<GovState>,
    cost: Arc<CostModel>,
    key: Arc<VirtualKey>,
    money: PlaneMoney,
}

fn rig() -> Rig {
    let limit = |amount, pool: Option<&str>| LimitCfg {
        metric: LimitMetric::Budget,
        amount,
        per: Some(LimitWindow::Total),
        scope: pool.map(ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    let groups = BTreeMap::from([
        (
            "g".into(),
            GroupCfg {
                parent: Some("root".into()),
                limits: vec![limit(10, Some("tier-a")), limit(2, Some("tier-b"))],
                ..Default::default()
            },
        ),
        (
            "root".into(),
            GroupCfg {
                limits: vec![limit(1_000, None)],
                ..Default::default()
            },
        ),
    ]);
    let rate = || crate::config::RateEntryCfg {
        input_utok: 1.0,
        units: BTreeMap::from([("bytes".into(), UnitRate::from_whole_micros(2).unwrap())]),
        ..Default::default()
    };
    let card = BTreeMap::from([
        ("m".into(), rate()),
        ("tp\u{1f}m".into(), rate()),
        ("tp\u{1f}fallback".into(), rate()),
    ]);
    let cost = Arc::new(
        CostModel::resolve_parts(Some(&card), 2, &groups).with_plane_fees(&BTreeMap::from([(
            "tp".into(),
            PlaneFees {
                per_request: 2,
                per_session: 0,
            },
        )])),
    );
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let key = Arc::new(VirtualKey {
        id: "k".into(),
        enabled: true,
        group: Some("g".into()),
        ..Default::default()
    });
    let money = PlaneMoney::new(gov.clone(), Arc::new(Posted));
    Rig {
        store,
        gov,
        cost,
        key,
        money,
    }
}

fn units(input: u64, bytes: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".into(), input), ("bytes".into(), bytes)])
}

fn counts(r: &Rig, bucket: &str, lane: &str) -> BTreeMap<String, u64> {
    r.gov
        .bucket_model_tokens(bucket, WINDOW_TOTAL, NOW)
        .into_iter()
        .find(|(model, _)| model == lane)
        .map(|(_, units)| units)
        .unwrap_or_default()
}

fn usage(r: &Rig, bucket: &str) -> (u64, i64) {
    let u = r
        .gov
        .derived_bucket_usage(&r.cost, bucket, WINDOW_TOTAL, true, NOW)
        .unwrap();
    (u.requests, u.spend_cents)
}

#[test]
fn admitted_qualified_pool_accrues_and_refunds_the_same_scope_as_a_bare_pool() {
    for (pool, lane) in [("tier-a", "m"), ("tp\u{1f}tier-a", "tp\u{1f}m")] {
        let r = rig();
        let grant = r.gov.try_admit(&r.cost, &r.key, pool, NOW).unwrap();
        for bucket in ["k", A, ROOT] {
            assert_eq!(usage(&r, bucket), (1, 2), "{pool}: admission fee");
        }
        r.gov.record_usage_served(
            &r.cost,
            &r.key,
            pool,
            lane,
            Some("provider"),
            &units(10_000, 3),
            NOW,
        );
        for bucket in ["k", A, ROOT] {
            assert_eq!(
                counts(&r, bucket, lane),
                units(10_000, 3),
                "{pool}: raw classes"
            );

            assert_eq!(usage(&r, bucket), (1, 3), "{pool}: served spend");
            let state = r
                .gov
                .budget_state(&r.cost, &r.key, NOW)
                .into_iter()
                .find(|b| b.bucket_id == bucket)
                .unwrap();
            assert_eq!(state.spend_micros_at_current_rate, 30_006);
            assert_eq!(
                r.gov
                    .derived_bucket_usage(&r.cost, bucket, WINDOW_TOTAL, true, NOW)
                    .unwrap()
                    .tokens,
                10_000
            );
        }
        assert_eq!(usage(&r, B), (0, 0), "another pool's bucket is untouched");
        assert!(r.gov.bucket_model_tokens(B, WINDOW_TOTAL, NOW).is_empty());
        r.gov.refund_charge(grant.charge());
        for bucket in ["k", A, ROOT] {
            assert_eq!(
                usage(&r, bucket),
                (1, 1),
                "refund preserves the admission count"
            );
            assert_eq!(
                counts(&r, bucket, lane),
                units(10_000, 3),
                "refund preserves usage"
            );
            assert_eq!(
                counts(&r, bucket, "tp\u{1f}")
                    .get("per_request")
                    .copied()
                    .unwrap_or(0),
                0
            );
        }
        r.gov.flush_budgets();
        for bucket in ["k", A, ROOT] {
            let row = r.store.get_usage(bucket, 0).unwrap();
            assert_eq!((row.requests, row.billable_requests), (1, 0));
            let model = row
                .models
                .iter()
                .find(|m| m.model == lane)
                .expect("stored serving lane");
            assert_eq!(model.usage_units, units(10_000, 3));
            if lane.contains('\u{1f}') {
                assert!(
                    row.models.iter().all(|m| m.model != "m"),
                    "plane identity survives flush"
                );
            }
        }
    }
}

fn ctx() -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(1),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

fn report(input: u64) -> [UnitCount; 3] {
    [
        UnitCount {
            class: 0,
            source: UNITS_REPORTED,
            amount: input,
        },
        UnitCount {
            class: 1,
            source: UNITS_REPORTED,
            amount: 3,
        },
        UnitCount {
            class: 2,
            source: UNITS_REPORTED,
            amount: 1,
        },
    ]
}

fn scoped_headroom(session: bool, pool: &str, lane: &str, other: &str) {
    let r = rig();

    let _prior = r.gov.try_admit(&r.cost, &r.key, pool, NOW).unwrap();
    r.gov.record_usage_served(
        &r.cost,
        &r.key,
        pool,
        lane,
        Some("provider"),
        &units(10_000, 3),
        NOW,
    );
    let _other = r.gov.try_admit(&r.cost, &r.key, other, NOW).unwrap();
    assert_eq!(usage(&r, B), (1, 2));
    let grant = r.gov.try_admit(&r.cost, &r.key, pool, NOW).unwrap();
    r.money.open(
        ctx().key,
        UnitMoney {
            key: r.key.clone(),
            cost: r.cost.clone(),
            pool: pool.into(),
            lane: lane.into(),
            classes: Arc::from(vec!["input".into(), "bytes".into(), "per_request".into()]),
            arrived: NOW,
            mode: ExhaustionMode::CutStream,
            fee: FeeRefund::PlaneFeeUnits(Arc::from(vec![2])),
            charge: grant.charge().clone(),
        },
    );
    if session {
        assert_eq!(r.money.session_opened(&ctx()), Ok(()));
    }

    let serving = if lane == "m" { "m" } else { "tp\u{1f}fallback" };
    r.money.served(&ctx(), serving, "provider");
    assert_eq!(r.money.serving(ctx().key).as_deref(), Some(serving));

    assert_eq!(
        r.money.checkpoint(&ctx(), &report(49_987)),
        Checkpoint::Continue,
        "the unrelated, depleted tier-b scope must not cut tier-a"
    );
    assert_eq!(
        r.money.checkpoint(&ctx(), &report(49_988)),
        Checkpoint::Cut,
        "tier-a's own remaining 49,994 micros must cut the stream"
    );
    assert_eq!(
        counts(&r, A, serving).get("input").copied().unwrap_or(0),
        if serving == lane { 10_000 } else { 0 },
        "checkpoints never accrue"
    );
    r.money.cancelled(
        &ctx(),
        &CancelBill {
            cause: ReasonCode::OverBudget,
            disposition: CANCEL_OK_PARTIAL,
            far_end_answered: true,
            streamed: true,
            billed: if session {
                vec![]
            } else {
                vec![(0, 49_988), (1, 3)]
            },
        },
    );
    if session {
        r.money.session_ended(&ctx());
        r.money.session_ended(&ctx());
    }
    r.money.settle_end(ctx().key, 200);
    r.money.settle_end(ctx().key, 200);
    assert_eq!(r.money.open_units(), 0);
    for bucket in ["k", A, ROOT] {
        let expected = if serving == lane {
            units(59_988, 6)
        } else {
            units(49_988, 3)
        };
        assert_eq!(
            counts(&r, bucket, serving),
            expected,
            "one final accrual per unit"
        );
        if serving != lane {
            assert_eq!(counts(&r, bucket, lane), units(10_000, 3));
        }
    }
    assert_eq!(usage(&r, A), (2, 10));
    assert!(
        matches!(
            r.gov.try_admit(&r.cost, &r.key, pool, NOW),
            Err(LimitBlocked::Limit { metric: "budget", pool: Some(blocked), .. }) if blocked == "tier-a"
        ),
        "the served scope's cap must also block the next admission"
    );
    assert_eq!(usage(&r, A), (2, 10), "a blocked admission charges nothing");
    assert_eq!(usage(&r, B), (1, 2));
    assert!(counts(&r, B, serving).is_empty());
    for bucket in ["k", ROOT] {
        assert_eq!(
            usage(&r, bucket),
            (3, 12),
            "unscoped ancestors keep all three requests"
        );
    }
    if pool.contains('\u{1f}') {
        assert_eq!(counts(&r, A, "tp\u{1f}")["per_request"], 2);
        assert_eq!(counts(&r, B, "tp\u{1f}")["per_request"], 1);
        r.gov.flush_metering();
        let rows = r
            .gov
            .metering_for(crate::governance::metering_bucket(NOW))
            .unwrap();
        let row = rows
            .iter()
            .find(|row| row.model == "fallback")
            .expect("served plane row");
        assert_eq!((row.provider.as_str(), row.requests), ("tp", 1));
        assert_eq!(row.usage_units, units(49_988, 3));
        assert!(rows.iter().all(|row| !row.model.contains('\u{1f}')));
    }
}

#[test]
fn a_qualified_pool_route_cuts_at_its_scoped_headroom_and_bills_once() {
    scoped_headroom(false, "tp\u{1f}tier-a", "tp\u{1f}m", "tp\u{1f}tier-b");
}

#[test]
fn a_qualified_pool_session_cuts_at_its_scoped_headroom_and_bills_once() {
    scoped_headroom(true, "tp\u{1f}tier-a", "tp\u{1f}m", "tp\u{1f}tier-b");
}

#[test]
fn the_bare_plane_keeps_the_same_scoped_headroom_and_counts() {
    for session in [false, true] {
        scoped_headroom(session, "tier-a", "m", "tier-b");
    }
}
