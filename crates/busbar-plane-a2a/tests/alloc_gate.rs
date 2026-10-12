// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What relaying an unchanged envelope is allowed to allocate, on the door's relay.
//!
//! The caller's envelope goes to the agent unchanged unless a record leg came back naming the task
//! differently. The unchanged case is the common one, and a copy made on the way to a second copy
//! is work with no observable effect — invisible to every test that reads bytes, and invisible to a
//! stopwatch on a shared runner. An allocation COUNT sees it, and is the same number on every
//! machine, so it can be pinned (DoD item 6: a zero-allocation hot path).
//!
//! This is the pin the retired engine's relay carried (`encode_egress`, 2 allocations for the same
//! request), restored on the door's relay after the engine's deletion took it away (ARCHITECT
//! ruling on #787: a lost check, not deleted legacy). The bound is exact. The measured calls are
//! pure synchronous functions over bytes: no I/O, no clock, no map iteration order. If an
//! intentional change moves it, run with `--nocapture`, read the printed count, and move the
//! constant in the same commit, with the reason.

use busbar_plane_a2a::binding::Binding;
use busbar_plane_a2a::relay::{Answer, From, Piece, Relay};
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

/// One well-formed request of this protocol, carrying no task identifier to rewrite: the request
/// the retired engine's pin measured.
const BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user"}}}"#;

/// The agent's registered url.
const URL: &str = "https://agent.example/a2a";

/// COMMITTED BASELINE — the exact allocation count of ONE hop that rewrites nothing: the attempt's
/// head and the caller's body, through the door's relay.
///
/// Two, as the retired engine's relay: the attempt's field list, which takes its buffer on its
/// first field, and its target (the agent url's path). Every field the plane spells is borrowed
/// from its constant, the journal's url is the one the backend was named with, and the body is
/// LENT ([`Answer::ToFarEndLent`]): the door writes the caller's own piece, so the envelope is never
/// copied.
const RELAY_ALLOCS: u64 = 2;

/// A JSON-RPC hop for [`BODY`], bound and named as the door binds and names one before its first
/// attempt (outside any measured window).
fn hop() -> Relay {
    let envelope: serde_json::Value = serde_json::from_slice(BODY).expect("the request is JSON");
    let mut relay = Relay::new(serde_json::json!("1"), "0.3");
    relay.bind(Binding::JsonRpc, &envelope);
    relay.name_backend("planner", URL);
    relay
}

/// The relay's loop for one attempt: the kernel's ATTEMPT, then the caller's body, `plant` more
/// allocations made in the loop (the RED arm's).
fn relay_once(relay: &mut Relay, plant: usize) -> (Answer, Answer) {
    let attempt = relay.on_piece(Piece {
        from: From::Kernel(Some(URL)),
        bytes: &[],
        status: None,
        last: false,
    });
    for _ in 0..plant {
        std::hint::black_box(Box::new(0_u8));
    }
    let body = relay.on_piece(Piece {
        from: From::Caller,
        bytes: BODY,
        status: None,
        last: true,
    });
    (attempt, body)
}

#[test]
fn an_unrewritten_envelope_is_relayed_without_a_copy() {
    // One warm hop outside the window, so nothing a first call sets up for the process is charged
    // to the measured one.
    let (warm, warm_body) = relay_once(&mut hop(), 0);
    assert!(matches!(warm, Answer::Attempt(_)), "{warm:?}");
    assert_eq!(
        warm_body,
        Answer::ToFarEndLent,
        "with no task identifier to rewrite, the agent gets the caller's own bytes, lent"
    );

    let mut relay = hop();
    let mut measured = None;
    let count = allocations_of(|| measured = Some(relay_once(&mut relay, 0)));
    println!("unrewritten relay allocations: {count}");
    let (attempt, body) = measured.expect("the hop ran");
    let Answer::Attempt(attempt) = attempt else {
        panic!("an attempt: {attempt:?}");
    };
    assert_eq!((attempt.verb, attempt.target.as_str()), ("POST", "/a2a"));
    assert_eq!(
        body,
        Answer::ToFarEndLent,
        "with no task identifier to rewrite, the agent gets the caller's own bytes, lent"
    );
    assert_eq!(
        count, RELAY_ALLOCS,
        "the relay allocated {count} times, not {RELAY_ALLOCS}: it is copying an envelope it \
         changes nothing about, or spelling a field it could borrow"
    );

    // THE RED ARM: one allocation planted in the relay's loop is one the pin sees, so a relay that
    // starts allocating per hop fails it.
    let mut relay = hop();
    let planted = allocations_of(|| {
        let _ = relay_once(&mut relay, 1);
    });
    assert_eq!(
        planted,
        RELAY_ALLOCS + 1,
        "the counter must see an allocation planted in the relay's loop"
    );
    assert_ne!(planted, RELAY_ALLOCS, "a planted allocation fails the pin");
}
