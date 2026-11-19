// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG F4 on the boot generation (PROOF-007, PROOF-102). `compose_native` composes the
//! first serving generation's billing; its money seam must be bound to the Node, or a unit still
//! open in that generation at shutdown is reported by nobody (only reloaded candidates were bound).

use std::sync::Arc;

use busbar_contract::UnitKey;
use busbar_kernel::governance::GovState;
use busbar_kernel::plane_driver::{EndPost, FeeRefund, UnitMoney};

use crate::root::plane_node::Node;

const ARRIVED: u64 = 1_700_000_000;

/// The seam's posting site is not what this test reads: ends post nowhere.
struct Quiet;
impl EndPost for Quiet {
    fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
}

/// A unit open in the boot generation's money seam at shutdown is in the exit walk's evidence,
/// exactly once; once it has ended it is not.
#[tokio::test]
async fn a_boot_generation_unit_open_at_exit_is_reported() {
    let node = Node::new();
    let gov = Arc::new(
        GovState::new_with_core(crate::root::real_store::core().await, None, None)
            .await
            .expect("governance builds"),
    );
    let money = super::native_money(&node, &gov, Arc::new(Quiet));
    let key = Arc::new(busbar_kernel::governance::VirtualKey {
        id: "vk_boot_open_at_exit".to_string(),
        generation_hash: "h:vk_boot_open_at_exit".to_string(),
        name: "boot open at exit".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    });
    money.open(
        UnitKey::new(81),
        UnitMoney {
            key,
            cost: Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
                None,
                0,
                &std::collections::BTreeMap::new(),
            )),
            pool: String::new(),
            lane: "m".into(),
            classes: Arc::from(vec!["input".to_string()]),
            arrived: ARRIVED,
            mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
            fee: FeeRefund::CallerStatus,
            charge: Default::default(),
        },
    );

    let open = node.native_open_units();
    assert_eq!(
        open.iter()
            .map(|evidence| evidence.unit.get())
            .collect::<Vec<_>>(),
        [81],
        "the boot generation's open unit is reported at exit, once"
    );
    assert_eq!(open[0].money.key.id, "vk_boot_open_at_exit");
    assert_eq!(open[0].money.arrived, ARRIVED);
    assert_eq!(node.native_open_unit_count(), 1);
    assert_eq!(gov.open_at_exit(open).units.len(), 1);

    money.settle_end(UnitKey::new(81), 200);
    assert!(
        node.native_open_units().is_empty(),
        "an ended unit is not reported as open"
    );
}
