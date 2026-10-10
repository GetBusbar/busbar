//! What relaying an unchanged envelope is allowed to allocate.
//!
//! The caller's envelope goes to the agent unchanged unless a record leg came back naming the task
//! differently. The unchanged case is the common one, and a copy made on the way to a second copy
//! is work with no observable effect — invisible to every test that reads bytes, and invisible to a
//! stopwatch on a shared runner. An allocation COUNT sees it, and is the same number on every
//! machine, so it can be pinned.
//!
//! The bound is exact. The measured call is a pure synchronous function over bytes: no I/O, no
//! clock, no map iteration order. If an intentional change moves it, run with `--nocapture`, read
//! the printed count, and move the constant in the same commit.

mod common;

use busbar_contract::plane::Plane;
use busbar_plane_a2a::{ops, A2aPlane};
use common::{Scaffold, TestSeal};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations made by THIS thread since the counter was last read.
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// The system allocator, counting.
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

/// How many allocations one call made on this thread.
fn allocations_of(f: impl FnOnce()) -> u64 {
    let before = ALLOCS.with(Cell::get);
    f();
    ALLOCS.with(Cell::get) - before
}

/// One well-formed request of this protocol, carrying no task identifier to rewrite.
const BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user"}}}"#;

/// COMMITTED BASELINE — the exact allocation count of ONE `encode_egress` that rewrites nothing.
///
/// Two: the one arena copy the hop genuinely needs — the content-type field of the envelope the
/// body is sent under — and the envelope's own field list, which starts empty and takes its buffer
/// on the first push. The body itself is BORROWED where it already lives, so it costs nothing at
/// all; it used to be copied into the arena, which both spent the unit's whole bounded budget on a
/// second copy of what the unit was already holding and refused outright any request larger than
/// that budget.
const RELAY_ALLOCS: u64 = 2;

#[test]
fn an_unrewritten_envelope_is_copied_once() {
    let plane = A2aPlane::EMPTY;
    let scaffold = Scaffold::new("http");
    let ctx = scaffold.ctx();
    let seal = TestSeal;
    let unit = busbar_contract::unit::Unit::new(
        &seal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        busbar_contract::wire::Direction::Inbound,
        Some(common::principal()),
        ops::OP_MESSAGE_SEND,
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
    assert_eq!(
        warm.body.as_slice(),
        BODY,
        "with no task identifier to rewrite, the agent gets the caller's own bytes"
    );

    let mut measured = None;
    let count = allocations_of(|| {
        measured = Some(
            plane
                .encode_egress(&unit, &dest, None, &ctx)
                .expect("an upstream destination is one this plane expresses a hop for"),
        );
    });
    println!("unrewritten relay allocations: {count}");
    assert_eq!(
        measured.expect("the call ran").body.as_slice(),
        BODY,
        "with no task identifier to rewrite, the agent gets the caller's own bytes"
    );
    assert_eq!(
        count, RELAY_ALLOCS,
        "the relay allocated {count} times, not {RELAY_ALLOCS}: it is copying an envelope it \
         changes nothing about"
    );
}

/// A sealed destination, for the call that takes one.
fn sealed_destination() -> busbar_contract::dest::VerifiedDestination {
    let seal = TestSeal;
    busbar_contract::dest::VerifiedDestination::seal(
        &seal,
        busbar_contract::dest::DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("agent.example"),
            lane: busbar_contract::ids::LaneId::new("standard"),
        },
        "http",
        None,
    )
}
