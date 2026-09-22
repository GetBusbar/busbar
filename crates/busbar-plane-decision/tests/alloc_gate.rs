//! What relaying an unchanged jev body is allowed to allocate.
//!
//! jev's `encode_egress` forwards the caller's body UNCHANGED — there is no task-identifier rewrite
//! the way A2A's relay has, because `systemone` mints no busbar-side identifier a later call would
//! need to substitute. So the honest allocation count is smaller than A2A's own pinned baseline: the
//! body is borrowed where it already lives, and the only copy this call makes is the envelope's
//! `content-type` field.

mod common;

use busbar_contract::plane::Plane;
use busbar_plane_decision::{ops, DecisionPlane};
use common::{sealed_destination, Scaffold};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

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
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
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

/// One well-formed `systemone` request body.
const BODY: &[u8] = br#"{"state":{"a":1},"context":{}}"#;

/// COMMITTED BASELINE — the exact allocation count of ONE `encode_egress`.
///
/// Two: the envelope's `content-type` field (the one arena copy this call genuinely needs) and the
/// envelope's own field list, which starts empty and takes its buffer on the first push — the same
/// two allocations `busbar-plane-a2a`'s own pinned baseline counts for the identical reason. The
/// request body itself is BORROWED where it already lives (`ArenaBytes::new`, not
/// `arena.alloc_bytes`), so relaying it costs nothing — jev has no A2A-style rewrite to spend a
/// second copy on.
const RELAY_ALLOCS: u64 = 2;

#[test]
fn an_unchanged_body_is_forwarded_without_a_copy() {
    let plane = DecisionPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = common::TestSeal;
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_SYSTEMONE,
        busbar_contract::bounded::Ir::new(BODY, &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    );
    let dest = sealed_destination();

    // One warm call outside the window, so nothing a first call sets up for the process is charged
    // to the measured one.
    let warm = plane
        .encode_egress(&unit, &dest, None, &ctx)
        .expect("an upstream destination is one this plane expresses a hop for");
    assert_eq!(warm.body.as_slice(), BODY);

    let mut measured = None;
    let count = allocations_of(|| {
        measured = Some(
            plane
                .encode_egress(&unit, &dest, None, &ctx)
                .expect("an upstream destination is one this plane expresses a hop for"),
        );
    });
    println!("relay allocations: {count}");
    assert_eq!(measured.expect("the call ran").body.as_slice(), BODY);
    assert_eq!(
        count, RELAY_ALLOCS,
        "the relay allocated {count} times, not {RELAY_ALLOCS}"
    );
}
