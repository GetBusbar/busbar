// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-call scratch pad grows on demand, shrinks back, and never crashes on growth
//! (DECISIONS #41). These are the four properties #41 pins as its GREEN condition — grow, shrink,
//! never-crash-under-growth, and an abuse backstop that refuses ONE request without panicking —
//! plus the measured starting size the design requires be reported as a number.

use busbar_contract::scratch::Scratch;
use busbar_kernel::scratch::{ScratchPad, SCRATCH_ABUSE_CEILING_BYTES, SCRATCH_START_BYTES};

/// The measured STARTING size is a stated number, and it is the contract's own arena figure.
///
/// #41 requires the start be MEASURED and reported, not guessed. It is a perf hint — the common
/// per-call footprint across the planes — not a cap. The kernel's constant is the contract's
/// `ARENA_BYTES` so a plane sized against one and a pad sized against the other can never disagree.
#[test]
fn the_measured_starting_size_is_four_kibibytes() {
    assert_eq!(SCRATCH_START_BYTES, 4 * 1024, "the measured start is 4 KiB");
    assert_eq!(SCRATCH_START_BYTES, busbar_contract::ARENA_BYTES);
}

/// The pad hands back the exact bytes it was given, for each of the three allocation shapes.
///
/// A pad that grew but returned the wrong bytes would pass every size assertion and still be
/// useless, so correctness is pinned before growth.
#[test]
fn the_pad_hands_back_the_exact_bytes_it_was_given() {
    let pad = ScratchPad::new();

    let bytes = pad.alloc_bytes(b"a frame's worth of bytes").expect("room");
    assert_eq!(bytes.as_slice(), b"a frame's worth of bytes");

    let text = pad.alloc_str("hello, scratch").expect("room");
    assert_eq!(text, "hello, scratch");

    let spans = &[
        ("/model", busbar_kernel::grammar::Span::new(0, 4)),
        ("/messages", busbar_kernel::grammar::Span::new(4, 9)),
    ];
    let copied = pad.alloc_spans(spans).expect("room");
    assert_eq!(copied, spans);
}

/// The pad grows past its starting size for one big request — the jev ~5 KB case #41 exists to fix.
///
/// On the old fixed-4-KiB arena this was `ArenaExhausted`; here it is a heap grow and a served
/// request. The bytes come back whole, and the pad's backing capacity is now larger than the start.
#[test]
fn a_request_bigger_than_the_start_grows_the_pad_instead_of_refusing() {
    let pad = ScratchPad::new();
    let jev = vec![0xABu8; 5 * 1024]; // bigger than the 4 KiB start

    let landed = pad
        .alloc_bytes(&jev)
        .expect("a big request grows the pad, it does not refuse");
    assert_eq!(
        landed.as_slice(),
        jev.as_slice(),
        "the whole 5 KB came back"
    );
    assert!(
        pad.capacity() > SCRATCH_START_BYTES,
        "the pad grew past its starting size to fit the request"
    );
}

/// Many allocations that together exceed the start never crash: each grows a chunk as needed.
///
/// This is the never-crash-under-growth property. A pad that summed its allocations against a fixed
/// cap would refuse partway; a grow-on-demand pad serves every one.
#[test]
fn many_allocations_summing_past_the_start_never_crash() {
    let pad = ScratchPad::new();
    let chunk = vec![0x5Au8; 512];
    let rounds = (SCRATCH_START_BYTES / chunk.len()) * 4; // four starts' worth
    for i in 0..rounds {
        let got = pad
            .alloc_bytes(&chunk)
            .unwrap_or_else(|e| panic!("allocation {i} must not refuse: {e}"));
        assert_eq!(got.as_slice(), chunk.as_slice());
    }
    assert!(
        pad.capacity() > SCRATCH_START_BYTES,
        "the pad grew to hold four starts' worth of allocations"
    );
}

/// After a big request, a reset shrinks the pad back to its starting size so no worker hoards.
///
/// #41: "Shrinks back to the starting size after a big request (no worker permanently hoards)." A
/// reset after a request that stayed under the start is cheap and keeps the chunk; a reset after a
/// request that grew the pad drops the extra chunks and returns to the starting footprint.
#[test]
fn a_big_request_then_a_reset_shrinks_back_to_the_starting_size() {
    let fresh = ScratchPad::new().capacity();

    let mut pad = ScratchPad::new();
    pad.alloc_bytes(&vec![0u8; 64 * 1024])
        .expect("grows to fit");
    let grown = pad.capacity();
    assert!(grown > fresh, "the big request grew the pad");

    pad.reset();
    assert_eq!(
        pad.capacity(),
        fresh,
        "after the big request the pad shrank back to the starting size"
    );

    // And the shrunk pad still serves the next call.
    let after = pad.alloc_bytes(b"next call").expect("the pad still works");
    assert_eq!(after.as_slice(), b"next call");
}

/// A reset after a small request keeps the starting chunk — the relay-path common case is cheap.
#[test]
fn a_reset_after_a_small_request_keeps_the_starting_chunk() {
    let mut pad = ScratchPad::new();
    let start = pad.capacity();
    for _ in 0..1_000 {
        pad.alloc_bytes(b"another frame").expect("room every time");
        pad.reset();
    }
    assert_eq!(pad.capacity(), start, "a relaying session never grew");
    assert_eq!(pad.resets(), 1_000);
}

/// The abuse backstop refuses ONE request and never panics; the pad serves the next call normally.
///
/// #41: "a ceiling set absurdly high that only a runaway/attack could hit; on trip it cleanly
/// refuses THAT ONE request, never panics." The refusal names what was wanted and the ceiling it
/// would have crossed, and it is a value the loop carries — not an abort.
#[test]
fn the_abuse_backstop_refuses_one_request_and_serves_the_next() {
    let pad = ScratchPad::new();

    let refused = pad
        .alloc_bytes(&vec_of_len(SCRATCH_ABUSE_CEILING_BYTES + 1))
        .expect_err("a runaway allocation is refused");
    assert_eq!(refused.ceiling, SCRATCH_ABUSE_CEILING_BYTES);
    assert!(refused.wanted > SCRATCH_ABUSE_CEILING_BYTES);

    // The pad is untouched: the very next legitimate call is served.
    let ok = pad
        .alloc_bytes(b"a normal request")
        .expect("the pad still serves");
    assert_eq!(ok.as_slice(), b"a normal request");
}

/// The ceiling is absurdly high — far above any legitimate per-call footprint.
#[test]
fn the_abuse_ceiling_is_absurdly_high() {
    const {
        assert!(
            SCRATCH_ABUSE_CEILING_BYTES >= 128 * 1024 * 1024,
            "the backstop is a runaway guard, not a working cap"
        );
    }
    const {
        assert!(
            SCRATCH_ABUSE_CEILING_BYTES > SCRATCH_START_BYTES * 1_000,
            "the ceiling dwarfs the starting size"
        );
    }
}

/// A large-but-legitimate allocation that reports how much headroom is left to the ceiling.
#[test]
fn remaining_reports_headroom_to_the_ceiling_not_the_chunk() {
    let pad = ScratchPad::new();
    let before = pad.remaining();
    assert!(
        before >= SCRATCH_ABUSE_CEILING_BYTES - SCRATCH_START_BYTES,
        "a fresh pad reports nearly the whole ceiling as headroom, not one chunk"
    );
    pad.alloc_bytes(&vec![0u8; 8 * 1024]).expect("grows to fit");
    assert!(
        pad.remaining() < before,
        "the allocation reduced the headroom to the ceiling"
    );
}

/// Build a vector of a given length without materialising it twice on the stack.
fn vec_of_len(len: usize) -> Vec<u8> {
    vec![0u8; len]
}
