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

/// ci/owed/cut-root/MONEY-OWED.tsv row
/// `a_child_nested_after_the_budget_is_spent_is_refused_and_charged_nothing`. On the old door a
/// child nested after the budget of its parent was spent answered 429 over_budget and was charged
/// nothing. `PortBilling::child` shared the admission of the parent and read no budget, so a
/// native child opened however far over budget its key was: red at a2bfc51020. The child now
/// reads the budget (`GovState::budget_spent`), which is the v1.5.5 rule and the default taken
/// until the owner rules; if he accepts the difference instead, the read and this test go.
#[test]
fn a_native_child_nested_after_the_budget_is_spent_is_refused_and_charged_nothing() {
    let (r, _gov, parent) = parent_with_its_budget_spent();

    let child = r
        .billing
        .child(parent.ctx.key, &key(Some("g")), "other", Arc::from([]));
    assert!(
        child.is_err(),
        "a child nested after its parent's budget is spent must be refused"
    );
    assert_eq!(r.money.open_units(), 1, "the refused child opened no money");
    r.billing.settle(parent.ctx.key, super::end_of(200, true));
    assert_eq!(r.money.open_units(), 0);
}

/// PROOF-083, the exact-money half of the test above: the refusal is the budget's own
/// (`OverBudget`, not a provenance refusal), and the group's spend in the parent's window is
/// exactly the one flat fee before the child is asked, after it is refused and after the parent
/// settles. The refused child counted no request and billed no usage: nothing, not a cent.
#[test]
fn a_native_child_nested_after_budget_is_spent_is_refused_over_budget_and_billed_exactly_nothing() {
    let (r, gov, parent) = parent_with_its_budget_spent();
    let spend = || {
        gov.budget_state(&r.cost, &key(Some("g")), NOW)
            .into_iter()
            .find(|b| b.budget_group.as_deref() == Some("g"))
            .expect("the group's budget bucket")
            .spend_micros_at_current_rate
    };
    let one_flat_fee = BUDGET_FEE_CENTS * busbar_kernel_ledger::cost::MICROS_PER_CENT;
    assert_eq!(
        spend(),
        one_flat_fee,
        "precondition: the window holds exactly the one flat fee"
    );
    let (entries, counts) = gov.pending_metering_totals();
    let requests = counts.requests;

    let child = r
        .billing
        .child(parent.ctx.key, &key(Some("g")), "other", Arc::from([]));
    assert!(
        matches!(child, Err(busbar_contract::caps::ReasonCode::OverBudget)),
        "a child nested after its parent's budget is spent is refused on that budget"
    );
    assert_eq!(
        spend(),
        one_flat_fee,
        "the refused child is charged nothing"
    );
    let (entries_after, counts_after) = gov.pending_metering_totals();
    assert_eq!(entries_after, entries, "the refused child metered nothing");
    assert_eq!(
        counts_after.requests, requests,
        "the refused child counted no request"
    );
    assert_eq!(r.money.open_units(), 1, "the refused child opened no money");

    r.billing.settle(parent.ctx.key, super::end_of(200, true));
    assert_eq!(r.money.open_units(), 0);
    assert_eq!(
        spend(),
        one_flat_fee,
        "after the parent settles the window still holds exactly the one flat fee"
    );
}

/// The group's whole budget is one flat fee: the first ordinary admission spends it exactly.
const BUDGET_FEE_CENTS: i64 = 5;

/// A parent admitted while its group had budget, after which one ordinary request of the same key
/// spent that whole budget (a plane request charges its fee on the plane's own fee lane, which
/// this card prices at nothing). Returns the rig, its governor and the live parent.
fn parent_with_its_budget_spent() -> (Rig, Arc<GovState>, super::Unit) {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            limits: vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Budget,
                amount: 5,
                per: Some(LimitWindow::Month),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..GroupCfg::default()
        },
    )]);
    let store = ready(crate::real_store::core());
    let gov = Arc::new(ready(GovState::new_with_core(store, None, None)).unwrap());
    let cost = Arc::new(CostModel::resolve_parts(None, BUDGET_FEE_CENTS, &groups));
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted)));
    let billing = PortBilling::new(
        Arc::clone(&money),
        Arc::clone(&gov),
        Arc::new(UnitKeyMint::default()),
        Arc::new(crate::plane_driver::CoreAudit),
    );
    let r = Rig {
        billing,
        money,
        cost,
    };

    // The parent is admitted while the group still has budget (a plane request charges its fee
    // on the plane's own fee lane, which this card prices at nothing).
    let parent = r.billing.open(admit(&r, Some("g"))).unwrap();
    // One ordinary request of the same key then spends the whole budget with its flat fee.
    let _spent = gov
        .try_admit(&r.cost, &key(Some("g")), "", NOW)
        .expect("the budget covers exactly one flat fee");
    assert!(
        matches!(
            r.billing.open(admit(&r, Some("g"))),
            Err(LimitBlocked::Limit {
                metric: "budget",
                ..
            })
        ),
        "precondition: the group's budget is spent, so a new request of this key is refused on \
         budget"
    );
    assert_eq!(r.money.open_units(), 1, "only the parent is open");
    (r, gov, parent)
}
