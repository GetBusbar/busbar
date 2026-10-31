// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The token table: reached by token alone, never waited on by `reach`, and a token that outlived
//! its value reaches nothing.

use super::*;

/// A framing, as a transport holds one.
#[derive(Debug, PartialEq, Eq)]
struct Framing(u32);

/// Slots fill each segment in turn, every index in exactly one place.
#[test]
fn every_index_has_one_place() {
    let mut seen = std::collections::HashSet::new();
    let mut expect = (0, 0);
    for i in 0..BASE * ((1 << 6) - 1) {
        let p = place(i);
        assert_eq!(p, expect, "index {i}");
        assert!(seen.insert(p));
        expect = if expect.1 + 1 == BASE << expect.0 {
            (expect.0 + 1, 0)
        } else {
            (expect.0, expect.1 + 1)
        };
    }
}

/// A framing another op holds is answered at once (`Busy`), never waited for; once it is let go
/// the next op reaches it. Another framing is reached meanwhile: no lock is shared.
#[test]
fn a_held_framing_answers_busy_at_once() {
    let table = Table::default();
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
    let table = Table::default();
    let a = table.insert(Framing(1)).expect("a");
    let mut held = table.reach(a).expect("reach a");
    std::thread::scope(|s| {
        let waiter = s.spawn(|| table.hold(a).map(|h| h.0));
        held.0 = 7;
        drop(held);
        assert_eq!(waiter.join().expect("waiter"), Ok(7));
    });
}

/// A finished framing's token reaches nothing, even once its slot holds a new framing; `remove`
/// answers what it held.
#[test]
fn a_token_that_outlived_its_framing_reaches_nothing() {
    let table = Table::default();
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
    let table = Table::default();
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
