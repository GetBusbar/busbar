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

/// Q17-6 (a): through the engine's own host, an opened account counts no session fee until its
/// session is served; served, it counts exactly one, however many serving sites mark it; and an
/// account that is never served (its provider dial, mint or broker failed) charges nothing.
#[test]
fn a_session_fee_counts_once_when_served_and_never_for_an_unserved_open() {
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
    assert_eq!(spend(), 0, "an opened session is not yet a served one");
    kept.served();
    kept.served();
    assert_eq!(spend(), 40, "one served session, one fee, counted once");
    drop(failed);
    assert_eq!(spend(), 40, "the session that never served charged nothing");
}
