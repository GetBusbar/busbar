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

/// A card whose group `g` holds a day budget of 50 and whose plane `sp` charges
/// `fees.per_session: 40`: a chain with room for one session fee and not for two.
fn near_dry_cost() -> crate::cost::CostModel {
    use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
    let mut fees = crate::config::PlaneFeesMap::from([(PLANE.to_string(), Default::default())]);
    if let Some(f) = fees.get_mut(PLANE) {
        f.per_session = 40;
    }
    let budget = LimitCfg {
        metric: LimitMetric::Budget,
        amount: 50,
        per: Some(LimitWindow::Day),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    let groups = std::collections::BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            limits: vec![budget],
            ..Default::default()
        },
    )]);
    crate::cost::CostModel::resolve_parts(None, 0, &groups).with_plane_fees(&fees)
}

/// Q44(5), the bound the owner was told: a session can pass its cap by AT MOST ONE session fee.
/// Sixteen opens race on a chain with room for one fee (budget 50, fee 40), and every open answers
/// before any session is served, as a real open does while its mint, SDP broker or dial is in flight
/// (up to 30 s). The fee is counted AT THE OPEN, under the same dry check, so the opens that pass the
/// check are the ones the chain still had room for: the spend ends at no more than the cap plus one
/// fee. RED with the fee counted at `served()`: every open passes a check that nothing has been
/// counted against yet, and the chain overshoots by sixteen fees.
#[test]
fn concurrent_opens_on_a_near_dry_chain_overshoot_by_at_most_one_session_fee() {
    const OPENERS: usize = 16;
    const CAP: i64 = 50;
    const FEE: i64 = 40;
    let key = busbar_contract::records::VirtualKey {
        group: Some("g".to_string()),
        ..key()
    };
    let store = Arc::new(crate::governance::MemoryStore::new());
    busbar_contract::records::RecordStore::put_key(&*store, &key).expect("key stored");
    let gov =
        Arc::new(crate::governance::GovState::new(store, None).expect("memory store constructs"));
    let app = crate::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(near_dry_cost())
        .build();
    let host: Arc<dyn EngineHost> = Arc::new(EngineHostImpl::new(app));
    let lane = format!("{PLANE}{}model", crate::governance::PLANE_LANE_SEP);
    let start = std::sync::Barrier::new(OPENERS);
    let accounts: Vec<SessionAccount> = std::thread::scope(|s| {
        let openers: Vec<_> = (0..OPENERS)
            .map(|_| {
                s.spawn(|| {
                    start.wait();
                    SessionAccount::open(Arc::clone(&host), Some(&key), "pool", lane.clone())
                        .ok()
                        .flatten()
                })
            })
            .collect();
        openers
            .into_iter()
            .filter_map(|o| o.join().expect("an opener thread"))
            .collect()
    });
    // Every open has answered; only now is any session served.
    for account in &accounts {
        account.served();
    }
    let spend = gov
        .usage_for(&near_dry_cost(), &key.id, host.clock_now_secs())
        .expect("usage read")
        .expect("the key's usage")
        .spend_cents;
    assert!(
        !accounts.is_empty(),
        "the premise: the chain had room for one session"
    );
    assert!(
        spend <= CAP + FEE,
        "{} of {OPENERS} racing opens passed a chain with room for one fee: spend {spend} overshoots \
         the cap {CAP} by more than one session fee ({FEE})",
        accounts.len()
    );
}
