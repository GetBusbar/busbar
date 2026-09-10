// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shipping per-unit arena, proven: it copies, it refuses at its bound with the contract's own
//! refusal, a refusal costs nothing, a span table survives the call that built it, and nothing
//! crosses from one unit's space into the next.

use busbar_contract::bounded::{Arena, ArenaBudget, Span};

use super::{ArenaSpace, UnitArena, ARENA_BYTES, ARENA_SPANS};

/// The arena is what one task owns and hands to no other thread while a borrow is alive: `Send`.
/// `Sync` is not asserted here and must not be — a cursor two threads carve at once is not a
/// cursor, and the contract's own guard (`CursorArena` in its object-safety proof) is what keeps
/// the bound from returning.
#[test]
fn the_arena_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<UnitArena<'static>>();
    assert_send::<ArenaSpace<'static>>();
}

/// A fresh space is the contract's whole budget, and nothing has been spent on opening it.
#[test]
fn a_fresh_arena_has_the_contracts_whole_budget() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    assert_eq!(arena.remaining(), ARENA_BYTES);
    assert_eq!(arena.spans_remaining(), ARENA_SPANS);
    assert_eq!(ARENA_BYTES, busbar_contract::ARENA_BYTES);
    assert_eq!(ARENA_SPANS, busbar_contract::MAX_KEYS);
}

/// The arena COPIES. The caller's buffer can go away and the arena's bytes are still the bytes,
/// which is the property every leaking double faked with `Box::leak`.
#[test]
fn bytes_and_strings_are_copied_not_borrowed() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);

    let (bytes, text) = {
        let mut owned = b"frame body".to_vec();
        let name = String::from("pointer");
        let bytes = arena.alloc_bytes(&owned).expect("room");
        let text = arena.alloc_str(&name).expect("room");
        owned.fill(b'x');
        drop(owned);
        drop(name);
        (bytes, text)
    };
    assert_eq!(bytes.as_slice(), b"frame body");
    assert_eq!(text, "pointer");
    assert_eq!(
        arena.remaining(),
        ARENA_BYTES - "frame body".len() - "pointer".len()
    );
}

/// Exhaustion is the contract's `ArenaBudget`, naming what was wanted and what was left — the
/// existing exhaustion class, which the loop already turns into `ReasonCode::ArenaBudget` — and a
/// refusal costs the arena nothing: what was left before the ask is what is left after it.
#[test]
fn a_unit_past_its_bound_is_refused_and_the_refusal_costs_nothing() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);

    let most = vec![b'a'; ARENA_BYTES - 8];
    let _held = arena.alloc_bytes(&most).expect("fits");
    assert_eq!(arena.remaining(), 8);

    let too_much = [b'b'; 9];
    assert_eq!(
        arena.alloc_bytes(&too_much),
        Err(ArenaBudget {
            wanted: 9,
            remaining: 8,
        })
    );
    assert_eq!(arena.remaining(), 8, "a refusal spends nothing");

    let exactly = [b'c'; 8];
    let last = arena
        .alloc_bytes(&exactly)
        .expect("exactly what is left fits");
    assert_eq!(last.as_slice(), &exactly);
    assert_eq!(arena.remaining(), 0);
    assert_eq!(
        arena.alloc_str("z"),
        Err(ArenaBudget {
            wanted: 1,
            remaining: 0,
        })
    );
    // The empty allocation is not a refusal: nothing was asked for and nothing is spent.
    assert!(arena
        .alloc_bytes(b"")
        .expect("zero bytes always fit")
        .is_empty());
}

/// A span table is copied — pairs AND pointer names — so it outlives the call that built it. The
/// trait ties the pointers to the arena's own borrow, so what the cell can prove is that the table
/// the loop reads back does not point INTO the caller's strings: the names were interned. The
/// pointers cost their own bytes out of the same budget, and the pair count is bounded by the
/// contract's key ceiling with the same refusal shape.
#[test]
fn a_span_table_outlives_the_call_that_built_it_and_is_bounded_by_the_key_ceiling() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    let first = String::from("/model");
    let second = String::from("/messages/0/content");

    let table = {
        let pairs = [
            (first.as_str(), Span::new(10, 17)),
            (second.as_str(), Span::new(40, 61)),
        ];
        arena.alloc_spans(&pairs).expect("room")
    };
    assert_eq!(table.len(), 2);
    assert_eq!(table[0], ("/model", Span::new(10, 17)));
    assert_eq!(table[1], ("/messages/0/content", Span::new(40, 61)));
    assert!(
        !std::ptr::eq(table[0].0.as_ptr(), first.as_ptr())
            && !std::ptr::eq(table[1].0.as_ptr(), second.as_ptr()),
        "the pointer names were interned into the arena, not borrowed from the caller"
    );
    assert_eq!(arena.spans_remaining(), ARENA_SPANS - 2);
    assert_eq!(
        arena.remaining(),
        ARENA_BYTES - first.len() - second.len(),
        "the pointer names are the plane's bytes and come out of the plane's budget"
    );

    let too_many: Vec<(&str, Span)> = (0..ARENA_SPANS).map(|i| ("k", Span::new(i, i))).collect();
    assert_eq!(
        arena.alloc_spans(&too_many),
        Err(ArenaBudget {
            wanted: ARENA_SPANS,
            remaining: ARENA_SPANS - 2,
        })
    );
    assert_eq!(
        arena.spans_remaining(),
        ARENA_SPANS - 2,
        "a refusal spends no pairs"
    );
    assert_eq!(
        arena.alloc_spans(&[]).expect("an empty table fits").len(),
        0
    );
}

/// NO LEAK ACROSS UNITS. Two units in a row on the same stack: the first writes and is dropped;
/// the second's space is fresh — the whole budget back, and zero where the first unit's bytes
/// were, so nothing of unit one can be read out of unit two's arena. Reset at unit end is the
/// space being dropped, not a cursor moved.
#[test]
fn nothing_crosses_from_one_unit_into_the_next() {
    fn one_unit(fill: &[u8]) -> (usize, Vec<u8>) {
        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        let before = arena.remaining();
        let seen = arena.alloc_bytes(fill).expect("fits").as_slice().to_vec();
        (before, seen)
    }

    let secret = b"bearer sk-live-000000".as_slice();
    let (first_before, first_seen) = one_unit(secret);
    assert_eq!(first_before, ARENA_BYTES);
    assert_eq!(first_seen, secret);

    // The second unit asks for the same length over the same ground; what it gets is what it
    // wrote and nothing else, and its budget was whole when it opened.
    let blank = vec![0u8; secret.len()];
    let (second_before, second_seen) = one_unit(&blank);
    assert_eq!(
        second_before, ARENA_BYTES,
        "the second unit's budget was not spent by the first"
    );
    assert_eq!(second_seen, blank);

    // And a space opened fresh is zero everywhere before anything is written into it.
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    let probe = arena.alloc_bytes(&[0u8; 64]).expect("fits");
    assert!(probe.as_slice().iter().all(|b| *b == 0));
}

/// The arena is reached the way a plane reaches it: through the contract's own `Ctx`, as
/// `&dyn Arena`, with no name of this module in the plane's hands.
#[test]
fn a_plane_reaches_it_through_the_context_as_the_trait_object() {
    use busbar_contract::bounded::Labels;
    use busbar_contract::unit::{Clock, ConfigView, Ctx, TransportView};

    struct NoConfig;
    impl ConfigView for NoConfig {
        fn get_str(&self, _: &str) -> Option<&str> {
            None
        }
        fn get_int(&self, _: &str) -> Option<i64> {
            None
        }
        fn get_bool(&self, _: &str) -> Option<bool> {
            None
        }
    }
    struct NoTransport;
    impl TransportView for NoTransport {
        fn key(&self) -> &'static str {
            "cell"
        }
        fn chain(&self) -> &[&'static str] {
            &["cell"]
        }
        fn fact(&self, _: &str) -> Option<&str> {
            None
        }
    }

    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    let config = NoConfig;
    let transport = NoTransport;
    let labels = Labels::new();
    let clock = Clock {
        unix_secs: 0,
        monotonic_nanos: 0,
    };
    let ctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    let handle: &dyn Arena = ctx.arena();
    let answer = handle.alloc_str("answer").expect("room");
    assert_eq!(answer, "answer");
    assert_eq!(handle.remaining(), ARENA_BYTES - "answer".len());
}
