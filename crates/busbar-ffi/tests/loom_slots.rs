// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-STALE under loom (IF §6.5, §14): a stale token racing a fresh insert into the same slot never
//! touches the new occupant. Runs only with `RUSTFLAGS="--cfg loom"` (the CI loom job).

#![cfg(loom)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::multiple_unsafe_ops_per_block)]

use busbar_ffi::Slots;
use loom::sync::Arc;
use loom::thread;

#[test]
fn a_stale_remove_never_reaches_a_new_occupant() {
    loom::model(|| {
        let slots = Arc::new(Slots::<u32>::new());
        let (index, generation) = slots.insert(1).expect("insert");
        assert_eq!(slots.remove(index, generation), Some(1));
        let fresh = {
            let slots = Arc::clone(&slots);
            thread::spawn(move || slots.insert(2).expect("insert"))
        };
        let stale = {
            let slots = Arc::clone(&slots);
            thread::spawn(move || slots.remove(index, generation))
        };
        assert_eq!(
            stale.join().expect("stale"),
            None,
            "a stale remove is a no-op"
        );
        let (again, newer) = fresh.join().expect("fresh");
        assert_ne!((again, newer), (index, generation));
        // SAFETY: both threads are joined, so this is the only entry for the new token (I6).
        assert_eq!(unsafe { slots.get_mut(again, newer) }.copied(), Some(2));
        // SAFETY: as above; the stale token never matches, so nothing is borrowed.
        assert!(unsafe { slots.get_mut(index, generation) }.is_none());
    });
}

#[test]
fn concurrent_inserts_take_distinct_slots() {
    loom::model(|| {
        let slots = Arc::new(Slots::<u32>::new());
        let first = {
            let slots = Arc::clone(&slots);
            thread::spawn(move || slots.insert(1).expect("insert"))
        };
        let second = slots.insert(2).expect("insert");
        let first = first.join().expect("first");
        assert_ne!(first.0, second.0, "two live values never share a slot");
        assert_eq!(slots.count_live(), 2);
    });
}
