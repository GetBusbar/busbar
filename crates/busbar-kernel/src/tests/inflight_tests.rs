// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::caps::{
    Grant, Hold, HoldCell, HoldCellState, OriginKind, PrincipalId, ReasonCode, StepName, UnitKey,
};

use super::{arrival_hold, ArrivalDoor, Enter, InFlight};
use crate::teller::Kernel;

struct TestDoor;

impl ArrivalDoor for TestDoor {
    fn arrival_hold(
        &self,
        principal: PrincipalId,
        token: &Grant<busbar_contract::caps::Admittance>,
    ) -> Hold {
        Hold::open(token, principal)
    }
}

fn principal() -> PrincipalId {
    PrincipalId::new("acct:inflight-test")
}

fn enter(key: UnitKey, kernel: &Kernel) -> Enter {
    Enter {
        key,
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        arrival: arrival_hold(kernel, &TestDoor, principal(), kernel.next_call()),
        now: 0,
    }
}

#[test]
fn a_duplicate_key_is_refused_and_the_original_entry_is_untouched() {
    let kernel = Kernel::new();
    let table = InFlight::new(64);
    let key = UnitKey::new(1);

    let first = table
        .insert(enter(key, &kernel))
        .expect("the first unit at a fresh key is admitted");
    assert_eq!(table.len(), 1);

    let refused = table
        .insert(enter(key, &kernel))
        .expect_err("a unit key already live in the table must be refused, not admitted twice");

    assert_eq!(refused.reason, ReasonCode::InFlight);
    assert_eq!(refused.step, StepName::Arrival);

    assert_eq!(table.len(), 1);

    let still_there = table
        .get(key)
        .expect("the original unit is still in the table");
    assert!(
        Arc::ptr_eq(&first, &still_there),
        "the table must still hold the FIRST unit's own slot, not a replacement"
    );
    assert_eq!(
        still_there.cell().state(),
        HoldCellState::Arrival,
        "the first unit's hold cell must be exactly as it was — never swapped out from under it"
    );

    let snapshot = table.snapshot();
    assert_eq!(
        snapshot.len(),
        1,
        "the sweep must still see exactly one live unit"
    );
    assert!(Arc::ptr_eq(&snapshot[0], &first));

    let returned = HoldCell::new(refused.hold);
    assert_eq!(returned.state(), HoldCellState::Arrival);
}

#[test]
fn two_distinct_keys_both_enter_normally() {
    let kernel = Kernel::new();
    let table = InFlight::new(64);

    let a = table
        .insert(enter(UnitKey::new(1), &kernel))
        .expect("a fresh key is admitted");
    let b = table
        .insert(enter(UnitKey::new(2), &kernel))
        .expect("a second, distinct key is admitted");

    assert_eq!(table.len(), 2);
    assert!(!Arc::ptr_eq(&a, &b));
}

#[test]
fn exempt_units_never_take_a_client_slot() {
    let kernel = Kernel::new();
    let table = InFlight::new(1);
    let mut admin = enter(UnitKey::new(10), &kernel);
    admin.admin_listener = true;
    let mut tick = enter(UnitKey::new(11), &kernel);
    tick.zero_hold_tick = true;
    let _admin = table
        .insert(admin)
        .expect("an admin unit is outside the cap");
    let _tick = table
        .insert(tick)
        .expect("a heartbeat unit is outside the cap");
    assert!(
        table.admits(&enter(UnitKey::new(12), &kernel)),
        "the one counted slot is free"
    );
    let _client = table
        .insert(enter(UnitKey::new(12), &kernel))
        .expect("the client takes the one counted slot");
    assert_eq!(table.len(), 3, "every live unit is in the table");
    let refused = table
        .insert(enter(UnitKey::new(13), &kernel))
        .expect_err("a second client finds the counted slot taken");
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    table.remove(UnitKey::new(10));
    table.remove(UnitKey::new(11));
    assert_eq!(table.len(), 1);
    assert!(
        !table.admits(&enter(UnitKey::new(14), &kernel)),
        "an exempt unit leaving frees no client slot"
    );
}
