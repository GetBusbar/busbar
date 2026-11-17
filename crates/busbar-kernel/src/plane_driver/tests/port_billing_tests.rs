// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A request a plane serves over the port is a billed unit (IF §12.4): it is admitted through the caller key's
//! budget chain, opens as a unit on the plane money (so `PortMoney`'s checkpoint and end post to it), and its
//! settlement closes it exactly once.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::VirtualKey;
use busbar_plugin_abi::plane::{UsageRec, SRC_REPORTED};

use super::{Admit, PortBilling};
use crate::config::groups::{ExhaustionMode, GroupCfg};
use crate::cost::CostModel;
use crate::door::UnitKeyMint;
use crate::governance::{GovState, LimitBlocked};
use crate::plane_driver::usage::{Ending, SessionUsage};
use crate::plane_driver::{EndPost, PlaneMoney, UnitEnd};
use crate::teller::{Ended, UnitCtx};

const NOW: u64 = 1_700_000_000;

struct Posted;
impl EndPost for Posted {
    fn post(&self, _: &UnitCtx, _: Ended) {}
}

fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    futures::executor::block_on(future)
}

struct Rig {
    billing: PortBilling,
    money: Arc<PlaneMoney>,
    cost: Arc<CostModel>,
}

fn rig(groups: BTreeMap<String, GroupCfg>) -> Rig {
    let store = ready(crate::real_store::core());
    let gov = Arc::new(ready(GovState::new_with_core(store, None, None)).unwrap());
    let cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted)));
    let billing = PortBilling::new(
        Arc::clone(&money),
        gov,
        Arc::new(UnitKeyMint::default()),
        Arc::new(crate::plane_driver::CoreAudit),
    );
    Rig {
        billing,
        money,
        cost,
    }
}

fn key(group: Option<&str>) -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "k".into(),
        enabled: true,
        group: group.map(str::to_owned),
        ..Default::default()
    })
}

fn admit<'a>(r: &Rig, group: Option<&str>) -> Admit<'a> {
    Admit {
        instance: "mcp",
        classes: Arc::from(vec!["requests".to_string(), "tokens".to_string()]),
        key: key(group),
        cost: Arc::clone(&r.cost),
        mode: ExhaustionMode::FinishUnit,
        arrived: NOW,
    }
}

fn five_tokens() -> SessionUsage {
    let mut usage = SessionUsage::new();
    usage
        .answer(
            "tokens",
            UsageRec {
                amount: 5,
                scale: 0,
                source: SRC_REPORTED,
            },
        )
        .unwrap();
    usage
}

#[test]
fn an_admitted_request_opens_a_unit_on_the_money_and_its_settlement_closes_it_once() {
    let r = rig(BTreeMap::new());
    let unit = r.billing.open(admit(&r, None)).unwrap();
    assert_eq!(r.money.open_units(), 1);
    unit.money
        .ended(&unit.ctx, Ending::End, &five_tokens(), None);
    r.billing.settle(unit.ctx.key, super::end_of(200, true));
    assert_eq!(r.money.open_units(), 0, "the settlement closed the unit");
    r.billing.settle(unit.ctx.key, super::end_of(200, true));
    assert_eq!(r.money.open_units(), 0, "a second settlement is a no-op");
}

#[test]
fn a_cancelled_unit_is_closed_by_its_settlement_too() {
    let r = rig(BTreeMap::new());
    let unit = r.billing.open(admit(&r, None)).unwrap();
    unit.money
        .ended(&unit.ctx, Ending::Failed, &SessionUsage::new(), None);
    r.billing.settle(unit.ctx.key, super::end_of(502, true));
    assert_eq!(r.money.open_units(), 0);
}

#[test]
fn every_request_is_its_own_unit() {
    let r = rig(BTreeMap::new());
    let a = r.billing.open(admit(&r, None)).unwrap();
    let b = r.billing.open(admit(&r, None)).unwrap();
    assert_ne!(a.ctx.key, b.ctx.key);
    assert_eq!(r.money.open_units(), 2);
}

#[test]
fn pending_allocations_mint_distinct_units_without_opening_or_charging_money() {
    let r = rig(BTreeMap::new());
    let classes = admit(&r, None).classes;
    let first = r.billing.allocate(classes.clone());
    let second = r.billing.allocate(classes);
    assert_ne!(first.ctx.key, second.ctx.key);
    assert_eq!(r.money.open_units(), 0);
    let usage = ready(r.billing.gov.derived_bucket_usage_async(
        &r.cost,
        "k",
        crate::governance::WINDOW_TOTAL,
        true,
        NOW,
    ))
    .unwrap();
    assert_eq!(usage.requests, 0);
    assert_eq!(usage.spend_cents, 0);
    r.billing.settle(first.ctx.key, super::end_of(503, false));
    r.billing.settle(second.ctx.key, super::end_of(503, false));
    assert_eq!(r.money.open_units(), 0);
}

#[test]
fn a_frozen_group_refuses_the_request_before_any_unit_opens() {
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: false,
            ..GroupCfg::default()
        },
    )]);
    let r = rig(groups);
    let refused = r.billing.open(admit(&r, Some("g")));
    assert!(matches!(refused, Err(LimitBlocked::Disabled(_))));
    assert_eq!(r.money.open_units(), 0);
}

#[test]
fn the_unit_end_the_owner_settles_says_whether_anything_ran() {
    assert_eq!(
        super::end_of(200, true),
        UnitEnd {
            caller_status: 200,
            cut: false,
            refused_unspent: false
        }
    );
    assert_eq!(
        super::end_of(403, false),
        UnitEnd {
            caller_status: 403,
            cut: false,
            refused_unspent: true
        },
        "a refusal nothing ran under releases the request count"
    );
}

#[test]
fn a_native_child_uses_the_live_parent_admission_and_cannot_change_its_key() {
    let r = rig(BTreeMap::new());
    let parent = r.billing.open(admit(&r, None)).unwrap();
    let child = r
        .billing
        .child(
            parent.ctx.key,
            &key(None),
            "other",
            Arc::from(["tokens".into()]),
        )
        .unwrap();
    assert_ne!(parent.ctx.key, child.ctx.key);
    assert_eq!(
        child.ctx.origin,
        busbar_contract::caps::OriginKind::Nested {
            parent: parent.ctx.key
        }
    );
    assert_eq!(r.money.open_units(), 2);
    let foreign = VirtualKey {
        id: "foreign".into(),
        ..(*key(None)).clone()
    };
    assert!(r
        .billing
        .child(parent.ctx.key, &foreign, "other", Arc::from([]))
        .is_err());
    assert_eq!(r.money.open_units(), 2, "refusal must open nothing");
    r.billing.settle(parent.ctx.key, super::end_of(200, true));
    assert!(r
        .billing
        .child(parent.ctx.key, &key(None), "other", Arc::from([]))
        .is_err());
    child
        .money
        .ended(&child.ctx, Ending::End, &five_tokens(), None);
    r.billing.settle(child.ctx.key, super::end_of(200, true));
    assert_eq!(
        r.money.open_units(),
        0,
        "the child owns settlement after its parent ends"
    );
}

#[test]
fn a_native_child_does_not_take_a_second_concurrency_hold() {
    use crate::config::groups::{LimitCfg, LimitMetric};
    let r = rig(BTreeMap::from([(
        "g".into(),
        GroupCfg {
            limits: vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Concurrent,
                amount: 1,
                per: None,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                selected: None,
            }],
            ..GroupCfg::default()
        },
    )]));
    let parent = r.billing.open(admit(&r, Some("g"))).unwrap();
    assert!(r.billing.open(admit(&r, Some("g"))).is_err());
    let child = r
        .billing
        .child(parent.ctx.key, &key(Some("g")), "other", Arc::from([]))
        .unwrap();
    r.billing.settle(parent.ctx.key, super::end_of(200, true));
    assert!(
        r.billing.open(admit(&r, Some("g"))).is_err(),
        "child retains the original hold"
    );
    r.billing.settle(child.ctx.key, super::end_of(200, true));
    let next = r.billing.open(admit(&r, Some("g"))).unwrap();
    r.billing.settle(next.ctx.key, super::end_of(200, true));
}
