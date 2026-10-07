// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/governance/session_meter.rs`.

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

/// TODO 17(b) (ARCHITECT R4): through the engine's own host, each open counts its session fee AT
/// THE OPEN; a failed open's refund gives back exactly its own fee on the budget book, once however
/// often it is asked; a served session's fee is final, and marking it served from every serving site
/// counts nothing more.
#[test]
fn a_failed_open_refunds_its_session_fee_exactly_once_and_a_served_one_keeps_it() {
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
    assert_eq!(spend(), 80, "two opens, each fee counted at the open");
    kept.served();
    kept.served();
    assert_eq!(spend(), 80, "serving counts nothing more");
    kept.refund_open();
    assert_eq!(spend(), 80, "a served session's fee is final");
    failed.refund_open();
    failed.refund_open();
    assert_eq!(
        spend(),
        40,
        "the failed open's fee is back exactly once; the kept one stays"
    );
    failed.served();
    assert_eq!(spend(), 40, "a refunded open stays refunded");
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
