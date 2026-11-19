// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG F4 on the native path. The exit walk listed open units only through the old
//! plane drivers registered for cleanup; a native serving generation registers none, so a native
//! unit still running at exit was reported by nobody. The generation binds its money seam to the
//! Node (`Node::bind_native_money`), and the Node reports every unit that seam still holds.

use std::sync::Arc;

use busbar_contract::UnitKey;
use busbar_kernel::governance::GovState;
use busbar_kernel::plane_driver::{EndPost, FeeRefund, PlaneMoney, UnitMoney};

use super::super::Node;

const ARRIVED: u64 = 1_700_000_000;

/// The seam's posting site is not what this test reads: ends post nowhere.
struct Quiet;
impl EndPost for Quiet {
    fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
}

/// Each open native unit is reported once, with the facts the `open_at_exit` line prints; a unit
/// that ended is not reported; a seam bound twice is walked once; a generation that is gone is
/// not walked at all.
#[tokio::test]
async fn a_native_unit_open_at_exit_is_reported_once_and_an_ended_one_is_not() {
    let node = Node::new();
    let gov = Arc::new(
        GovState::new_with_core(crate::root::real_store::core().await, None, None)
            .await
            .expect("governance builds"),
    );
    assert!(
        node.native_open_units().is_empty(),
        "a node with no native generation reports nothing"
    );
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(Quiet)));
    node.bind_native_money(&money);
    // A second binding of the same seam (a candidate rebuilt over it) must not list it twice.
    node.bind_native_money(&money);

    let cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        None,
        0,
        &std::collections::BTreeMap::new(),
    ));
    let key = Arc::new(busbar_kernel::governance::VirtualKey {
        id: "vk_open_at_exit".to_string(),
        generation_hash: "h:vk_open_at_exit".to_string(),
        name: "open at exit".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    });
    for unit in [71u64, 72] {
        money.open(
            UnitKey::new(unit),
            UnitMoney {
                key: Arc::clone(&key),
                cost: Arc::clone(&cost),
                pool: String::new(),
                lane: "m".into(),
                classes: Arc::from(vec!["input".to_string()]),
                arrived: ARRIVED,
                mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                fee: FeeRefund::CallerStatus,
                charge: Default::default(),
            },
        );
    }

    let open = node.native_open_units();
    let mut units: Vec<u64> = open.iter().map(|evidence| evidence.unit.get()).collect();
    units.sort_unstable();
    assert_eq!(
        units,
        [71, 72],
        "each open native unit is reported exactly once"
    );
    assert_eq!(node.native_open_unit_count(), 2);
    for evidence in &open {
        assert_eq!(evidence.money.key.id, "vk_open_at_exit");
        assert_eq!(evidence.money.lane, "m");
        assert_eq!(evidence.money.arrived, ARRIVED);
        assert!(!evidence.finished, "an open unit is not finished");
    }
    // The exit walk joins the evidence with the checkpoint book and loses none of it.
    let exit = gov.open_at_exit(open);
    assert_eq!(exit.units.len(), 2);

    money.settle_end(UnitKey::new(71), 200);
    let after: Vec<u64> = node
        .native_open_units()
        .iter()
        .map(|evidence| evidence.unit.get())
        .collect();
    assert_eq!(after, [72], "an ended unit is not reported as open");
    assert_eq!(node.native_open_unit_count(), 1);

    money.settle_end(UnitKey::new(72), 200);
    assert!(node.native_open_units().is_empty());

    // A generation that is gone is not walked, and binding the next one forgets it.
    drop(money);
    assert!(node.native_open_units().is_empty());
    assert_eq!(node.native_open_unit_count(), 0);
}
