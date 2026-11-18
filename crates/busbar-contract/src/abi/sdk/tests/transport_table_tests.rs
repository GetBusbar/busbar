// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The token table: reached by token alone, never waited on by `reach`, and a token that outlived

use super::*;

/// A framing, as a transport holds one.
#[derive(Debug, PartialEq, Eq)]
struct Framing(u32);

/// The table holds what it was made for and no more: the next insert answers `None`, and a freed slot
/// is claimed again.
#[test]
fn the_nth_plus_one_insert_answers_none() {
    let table = Table::with_capacity(3);
    let tokens: Vec<u64> = (0..3)
        .map(|i| table.insert(Framing(i)).expect("room"))
        .collect();
    assert_eq!(table.insert(Framing(9)), None);
    assert_eq!(table.remove(tokens[1]), Ok(Framing(1)));
    let again = table.insert(Framing(9)).expect("the freed slot");
    assert_eq!(table.reach(again).as_deref().ok(), Some(&Framing(9)));
    assert_eq!(table.insert(Framing(10)), None);
}

/// A table of no slots holds nothing.
#[test]
fn a_table_of_no_slots_holds_nothing() {
    let table: Table<Framing> = Table::with_capacity(0);
    assert_eq!(table.insert(Framing(1)), None);
    assert_eq!(table.reach(1).err(), Some(Reach::Gone));
}

/// A framing another op holds is answered at once (`Busy`), never waited for; once it is let go
#[test]
fn a_held_framing_answers_busy_at_once() {
    let table = Table::with_capacity(8);
    let a = table.insert(Framing(1)).expect("a");
    let b = table.insert(Framing(2)).expect("b");
    let held = table.reach(a).expect("reach a");
    std::thread::scope(|s| {
        s.spawn(|| {
            assert_eq!(table.reach(a).err(), Some(Reach::Busy));
            assert_eq!(
                table.reach(b).as_deref().ok(),
                Some(&Framing(2)),
                "another framing is reached meanwhile"
            );
        });
    });
    drop(held);
    assert_eq!(table.reach(a).as_deref().ok(), Some(&Framing(1)));
}

/// `hold` waits for the op that holds the framing, then reaches what that op left.
#[test]
fn hold_waits_for_the_op_that_holds_it() {
    let table = Table::with_capacity(8);
    let a = table.insert(Framing(1)).expect("a");
    let mut held = table.reach(a).expect("reach a");
    std::thread::scope(|s| {
        let waiter = s.spawn(|| table.hold(a).map(|h| h.0));
        // While the op still holds the framing the waiter must stay parked in `hold`.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !waiter.is_finished(),
            "hold returned while the framing was held"
        );
        held.0 = 7;
        drop(held);
        assert_eq!(waiter.join().expect("waiter"), Ok(7));
    });
}

/// A finished framing's token reaches nothing, even once its slot holds a new framing; `remove`
#[test]
fn a_token_that_outlived_its_framing_reaches_nothing() {
    let table = Table::with_capacity(8);
    let a = table.insert(Framing(1)).expect("a");
    assert_eq!(table.remove(a), Ok(Framing(1)));
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    assert_eq!(table.hold(a).err(), Some(Reach::Gone));
    assert_eq!(table.remove(a).err(), Some(Reach::Gone));
    let b = table.insert(Framing(2)).expect("b reuses the slot");
    assert_ne!(a, b);
    assert_eq!(untoken(a).map(|t| t.0), untoken(b).map(|t| t.0));
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    assert!(table.reach(b).is_ok());
    assert_eq!(table.reach(0).err(), Some(Reach::Gone));
    assert_eq!(table.reach(u64::MAX).err(), Some(Reach::Gone));
}

/// A held framing released by its op gives its slot back to the next insert.
#[test]
fn a_released_framing_gives_its_slot_back() {
    let table = Table::with_capacity(8);
    let a = table.insert(Framing(1)).expect("a");
    let held = table.hold(a).expect("hold a");
    assert_eq!(held.release(), Framing(1));
    assert_eq!(table.reach(a).err(), Some(Reach::Gone));
    let b = table.insert(Framing(2)).expect("b");
    assert_eq!(untoken(a).map(|t| t.0), untoken(b).map(|t| t.0));
}

/// The texts an op answers with name what it reached for.
#[test]
fn the_reach_texts_name_what_was_reached_for() {
    assert_eq!(Reach::Gone.why("framing"), "no such framing");
    assert_eq!(
        Reach::Busy.why("framing"),
        "framing busy: another op holds it"
    );
}
