// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::scratch::Scratch;
use busbar_kernel::scratch::{ScratchPad, SCRATCH_ABUSE_CEILING_BYTES, SCRATCH_START_BYTES};

#[test]
fn the_measured_starting_size_is_four_kibibytes() {
    assert_eq!(SCRATCH_START_BYTES, 4 * 1024, "the measured start is 4 KiB");
    assert_eq!(SCRATCH_START_BYTES, busbar_contract::SCRATCH_BASE_BYTES);
}

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

#[test]
fn a_request_bigger_than_the_start_grows_the_pad_instead_of_refusing() {
    let pad = ScratchPad::new();
    let scratch_payload = vec![0xABu8; 5 * 1024];

    let landed = pad
        .alloc_bytes(&scratch_payload)
        .expect("a big request grows the pad, it does not refuse");
    assert_eq!(
        landed.as_slice(),
        scratch_payload.as_slice(),
        "the whole 5 KB came back"
    );
    assert!(
        pad.capacity() > SCRATCH_START_BYTES,
        "the pad grew past its starting size to fit the request"
    );
}

#[test]
fn many_allocations_summing_past_the_start_never_crash() {
    let pad = ScratchPad::new();
    let chunk = vec![0x5Au8; 512];
    let rounds = (SCRATCH_START_BYTES / chunk.len()) * 4;
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

    let after = pad.alloc_bytes(b"next call").expect("the pad still works");
    assert_eq!(after.as_slice(), b"next call");
}

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

#[test]
fn the_abuse_backstop_refuses_one_request_and_serves_the_next() {
    let pad = ScratchPad::new();

    let refused = pad
        .alloc_bytes(&vec_of_len(SCRATCH_ABUSE_CEILING_BYTES + 1))
        .expect_err("a runaway allocation is refused");
    assert_eq!(refused.ceiling, SCRATCH_ABUSE_CEILING_BYTES);
    assert!(refused.wanted > SCRATCH_ABUSE_CEILING_BYTES);

    let ok = pad
        .alloc_bytes(b"a normal request")
        .expect("the pad still serves");
    assert_eq!(ok.as_slice(), b"a normal request");
}

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

fn vec_of_len(len: usize) -> Vec<u8> {
    vec![0u8; len]
}
