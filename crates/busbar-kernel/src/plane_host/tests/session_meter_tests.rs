// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/plane_host/session_meter.rs`.

use super::SessionAccount;
use crate::plane_host::{EngineHost, EngineHostImpl};
use std::sync::Arc;

const PLANE: &str = "sp";

/// A card with no model rates, no flat fee, and plane `sp` charging `fees.per_session: 40`.
fn session_fee_cost() -> crate::cost::CostModel {
    let mut fees = crate::config::PlaneFeesMap::from([(PLANE.to_string(), Default::default())]);
    if let Some(f) = fees.get_mut(PLANE) {
        f.per_session = 40;
    }
    crate::cost::CostModel::resolve_parts(None, 0, &std::collections::BTreeMap::new())
        .with_plane_fees(&fees)
}

fn key() -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: "k-session".to_string(),
        name: "k-session".to_string(),
        enabled: true,
        ..Default::default()
    }
}

/// Q17-6 (ARCHITECT ruling R4): through the engine's own host, a refunded open gives back exactly
/// its own session fee on the budget book; the other open keeps its fee.
#[test]
fn a_refunded_open_gives_back_its_session_fee_on_the_budget_book() {
    // The key is registered: the usage read answers only for a key the store holds.
    let store = Arc::new(crate::governance::MemoryStore::new());
    busbar_contract::records::RecordStore::put_key(&*store, &key()).expect("key stored");
    let gov =
        Arc::new(crate::governance::GovState::new(store, None).expect("memory store constructs"));
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(session_fee_cost())
        .build();
    let host: Arc<dyn EngineHost> = Arc::new(EngineHostImpl::new(app));
    let lane = format!("{PLANE}{}model", crate::governance::PLANE_LANE_SEP);
    let open = || {
        SessionAccount::open(Arc::clone(&host), Some(&key()), "pool", lane.clone())
            .expect("room on the chain")
            .expect("a governed host")
    };
    let spend = || {
        gov.usage_for(&session_fee_cost(), &key().id, host.clock_now_secs())
            .expect("usage read")
            .expect("the key's usage")
            .spend_cents
    };
    let (kept, failed) = (open(), open());
    assert_eq!(spend(), 80, "two counted opens at 40");
    failed.refund_open();
    assert_eq!(
        spend(),
        40,
        "the failed open's fee is back, the kept one stays"
    );
    drop(kept);
}
