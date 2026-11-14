// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::store::LaneRuntime;

#[test]
fn explicit_fixture_state_reaches_health_and_retains_admission_invariants() {
    let permits = Arc::new(Semaphore::new(3));
    let held = permits.clone().try_acquire_owned().unwrap();
    let lane = LaneData::from_test_parts(
        "member".into(),
        "route".into(),
        3,
        permits,
        true,
        7,
        150,
        4,
        true,
        "held-down".into(),
        11,
        12,
        13,
    );
    let exhausted = LaneData::from_test_parts(
        "exhausted".into(),
        "other".into(),
        2,
        Arc::new(Semaphore::new(2)),
        true,
        -5,
        0,
        0,
        false,
        String::new(),
        0,
        0,
        0,
    );
    let unlimited = LaneData::from_test_parts(
        "unlimited".into(),
        "last".into(),
        2,
        Arc::new(Semaphore::new(2)),
        false,
        99,
        0,
        0,
        false,
        String::new(),
        0,
        0,
        0,
    );
    let store = HealthState::new(vec![lane, exhausted, unlimited]);
    let snapshot = store.snapshot(0, 100);
    assert_eq!(
        (snapshot.member.as_str(), snapshot.route.as_str()),
        ("member", "route")
    );
    assert_eq!(
        (
            snapshot.max_concurrent,
            snapshot.free_slots,
            snapshot.inflight
        ),
        (3, 2, 1)
    );
    assert_eq!(
        (
            snapshot.budget,
            snapshot.ok,
            snapshot.err,
            snapshot.client_fault
        ),
        (7, 11, 12, 13)
    );
    assert!(snapshot.dead);
    assert_eq!(snapshot.dead_reason, "held-down");
    assert_eq!(snapshot.availability, Err(crate::store::Unavailable::Dead));
    assert_eq!(snapshot.streak, 4);
    assert_eq!(snapshot.cooldown_remaining_s, 50);
    drop(held);
    assert_eq!(
        store.snapshot(0, 100).free_slots,
        3,
        "the supplied semaphore is the live permit source"
    );
    let exhausted = store.snapshot(1, 100);
    assert_eq!(exhausted.budget, 0, "limited budgets still clamp at zero");
    assert_eq!(
        exhausted.availability,
        Err(crate::store::Unavailable::BudgetExhausted)
    );
    let unlimited = store.snapshot(2, 100);
    assert_eq!(
        unlimited.budget, -1,
        "unlimited lanes do not acquire a finite budget from fixture data"
    );
    assert!(unlimited.usable);
}
