// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT RELAYING A FAR-END ANSWER ALLOCATES (THE DESIGN section 11.2: "no allocation and no
//! blocking on the hot path"): a piece of the far end's answer is read as it passes and written
//! straight into the host's reply buffer, so relaying piece after piece of an answer allocates
//! nothing, however long the answer runs.

#![allow(unsafe_code)]

mod door_harness;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use busbar_contract::abi::mechanism::call::Outcome;
use door_harness::{open, Bufs, Given};

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded verbatim to the system allocator; the counter is a thread-local
// `Cell` of a plain integer, touched only on the allocating thread, and never reads or writes the
// memory being handed out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        // SAFETY: forwarded as given.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded as given.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        // SAFETY: forwarded as given.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = ALLOCS.with(Cell::get);
    f();
    ALLOCS.with(Cell::get) - before
}

/// RED (audit plane-decisions#8): 256 pieces of a 1 MiB answer, each 4 KiB, relayed through the
/// door: no allocation (predev kept the whole answer, growing a buffer, and copied each piece
/// again before writing it).
#[test]
fn relaying_an_answer_piece_by_piece_allocates_nothing() {
    let door = open(r#"{"models":{"jev":{"provider":"typesafe"}}}"#);
    let mut bufs = Bufs::new(1 << 16);
    assert_eq!(door.arrive(1, br#"{"state":{}}"#).outcome, Outcome::Ready);
    door.piece(1, Given::attempt(1), &mut bufs);
    door.piece(1, Given::caller(br#"{"state":{}}"#), &mut bufs);
    let head = door.piece(
        1,
        Given::far(Some(200), false, br#"{"answers":{"blob":""#),
        &mut bufs,
    );
    assert_eq!(head.outcome, Some(Outcome::Ready));
    let filler = [b'x'; 4096];
    let piece = Given::far(None, false, &filler);
    // Warm: one piece outside the window.
    door.piece(1, piece, &mut bufs);
    let mut relayed = 0;
    let count = allocations_of(|| {
        for _ in 0..256 {
            relayed += door.piece_bytes(1, piece, &mut bufs);
        }
    });
    assert_eq!(relayed, 256 * filler.len(), "every byte is relayed");
    assert_eq!(count, 0, "relaying 256 pieces allocated {count} times");
    let last = door.piece(
        1,
        Given::far(None, true, br#""},"usage":{"units":4}}"#),
        &mut bufs,
    );
    assert_eq!(last.units.first().map(|u| u.2), Some(4), "{last:?}");
}
