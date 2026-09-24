// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED-before-GREEN: a duplicate unit key must be refused, not silently overwrite the slot
//! already at it.
//!
//! Before the fix, `InFlight::insert` handed a duplicate key straight to `HashMap::insert`, which
//! overwrites: the call returned `Ok`, `len()` stayed exactly where it was (the map's own size does
//! not grow on an overwrite), and the FIRST unit's slot — and the hold cell inside it — dropped out
//! of the table with nothing left holding a path to it. That is what "orphaned" means here: the
//! sweep walks `snapshot()`, `get()` is the only other way in, and both read the shard's map, so a
//! slot the map no longer points at is a slot nothing will ever settle.

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
        Hold::open(token, principal, 0)
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
        provider_of_open_session: false,
        zero_hold_tick: false,
        arrival: arrival_hold(kernel, &TestDoor, principal()),
        now: 0,
    }
}

#[test]
fn a_duplicate_key_is_refused_and_the_original_entry_is_untouched() {
    let kernel = Kernel::new();
    let table = InFlight::new(64, 0);
    let key = UnitKey::new(1);

    let first = table
        .insert(enter(key, &kernel))
        .expect("the first unit at a fresh key is admitted");
    assert_eq!(table.len(), 1);

    // The second unit carries the SAME key. RED before the fix: this came back `Ok`, silently
    // replacing the map entry. GREEN after: it is refused and the first entry never moves.
    let refused = table
        .insert(enter(key, &kernel))
        .expect_err("a unit key already live in the table must be refused, not admitted twice");

    assert_eq!(refused.reason, ReasonCode::InFlight);
    assert_eq!(refused.step, StepName::Arrival);

    // The count is exactly what it was — one live unit, not two and not zero. A duplicate that
    // silently overwrote would leave `len()` unchanged too, which is exactly why the next two
    // assertions (identity and reachability of the ORIGINAL slot) are the ones that actually catch
    // the bug rather than merely restating this one.
    assert_eq!(table.len(), 1);

    // The table still holds the FIRST unit's own slot — not a second slot built for the refused
    // request, and not nothing.
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

    // NOT ORPHANED: the sweep's own view of the table (`snapshot`) sees exactly the one live unit,
    // so there is still exactly one path to a hold that has to be released — never zero.
    let snapshot = table.snapshot();
    assert_eq!(
        snapshot.len(),
        1,
        "the sweep must still see exactly one live unit"
    );
    assert!(Arc::ptr_eq(&snapshot[0], &first));

    // The refused unit's OWN arrival hold comes back rather than vanishing, exactly as a full-table
    // refusal already hands its hold back — it can still be settled or voided by the caller.
    let returned = HoldCell::new(refused.hold);
    assert_eq!(returned.state(), HoldCellState::Arrival);
}

#[test]
fn two_distinct_keys_both_enter_normally() {
    // The base case the fix must not break: two units with DIFFERENT keys both admit, and the
    // count reflects both.
    let kernel = Kernel::new();
    let table = InFlight::new(64, 0);

    let a = table
        .insert(enter(UnitKey::new(1), &kernel))
        .expect("a fresh key is admitted");
    let b = table
        .insert(enter(UnitKey::new(2), &kernel))
        .expect("a second, distinct key is admitted");

    assert_eq!(table.len(), 2);
    assert!(!Arc::ptr_eq(&a, &b));
}

/// THE HEADER'S TAKE COUNT IS THE TREE'S (item 291).
///
/// The module doc tells a reader how many callers can take a hold out of a slot's cell, and a reader
/// auditing that every take settles stops counting at the number it states. It said two while the
/// tree held three (the exit path, a child's end into its parent, and the sweep). The count here is
/// every take off a slot's cell in the two files that hold the exit grant — whatever the grant is
/// spelled as — so the header and the code can no longer disagree without this going red.
#[test]
fn the_header_states_the_take_count_the_tree_holds() {
    let takes = [include_str!("../teller.rs"), include_str!("../tick.rs")]
        .iter()
        .map(|src| {
            src.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .filter(|l| l.contains(".cell.take(&") || l.contains(".cell().take(&"))
                .count()
        })
        .sum::<usize>();
    let header: String = include_str!("../inflight.rs")
        .lines()
        .take_while(|l| l.starts_with("//") || l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let words = ["zero", "one", "two", "three", "four", "five", "six"];
    let stated = words
        .iter()
        .position(|w| header.contains(&format!("exactly {w} callers ever take the hold")))
        .expect("the header states how many callers take the hold");
    assert_eq!(
        stated, takes,
        "the in-flight header says {} callers take the hold; the tree has {takes}",
        words[stated]
    );
}
