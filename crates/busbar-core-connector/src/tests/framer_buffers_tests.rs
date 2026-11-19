// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A framing's buffers: what a framer is lent is the same room, every byte a zero, however the
//! zeros got there; a frame larger than the buffers still goes through them, and they neither
//! grow nor move.

use std::sync::Arc;

use busbar_contract::transport::codes::SIDE_DIAL;

use super::*;
use crate::support::TestDoor;

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[test]
fn a_framing_is_lent_the_whole_of_each_buffer_zeroed() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) = Framing::begin(door, SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    assert_eq!(f.bufs.wire.len(), WIRE_CAP);
    assert_eq!(f.bufs.frame.len(), FRAME_CAP);
    assert!(all_zero(&f.bufs.wire), "the wire buffer starts as zeros");
    assert!(all_zero(&f.bufs.frame), "the frame buffer starts as zeros");
    let sink = f.bufs.sink(At::now());
    assert_eq!(sink.wire_cap, WIRE_CAP);
    assert_eq!(sink.frame_cap, FRAME_CAP);
    assert_eq!(sink.pieces_cap, PIECES_CAP);
    assert_eq!(sink.heads_cap, HEADS_CAP);
}

#[test]
fn buffers_of_any_size_are_exactly_that_long_and_zeroed() {
    for (wire, frame) in [(0, 0), (1, 1), (7, 5), (4096, 4097), (WIRE_CAP, FRAME_CAP)] {
        let b = Buffers::new(wire, frame, 1);
        assert_eq!(b.wire.len(), wire.max(1));
        assert_eq!(b.frame.len(), frame.max(1));
        // Nothing spare past the length: the whole allocation is what is lent and what is wiped.
        assert_eq!(b.wire.capacity(), b.wire.len());
        assert_eq!(b.frame.capacity(), b.frame.len());
        assert!(all_zero(&b.wire) && all_zero(&b.frame));
    }
}

#[test]
fn the_wipe_a_drop_runs_zeroes_every_byte_of_both_buffers() {
    let mut b = Buffers::new(WIRE_CAP, FRAME_CAP, PIECES_CAP);
    b.wire.fill(0xA5);
    b.frame.fill(0x5A);
    b.wipe_bytes();
    assert_eq!(b.wire.len(), WIRE_CAP);
    assert_eq!(b.frame.len(), FRAME_CAP);
    assert!(all_zero(&b.wire), "every wire byte is wiped");
    assert!(all_zero(&b.frame), "every frame byte is wiped");

    let mut odd = [0xFF_u8; 13];
    wipe(&mut odd);
    assert!(all_zero(&odd));
    wipe(&mut []);
}

#[test]
fn a_frame_larger_than_the_buffers_goes_through_them_and_they_neither_grow_nor_move() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) =
        Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::plain_for_test()).unwrap();
    let (wire_at, frame_at) = (f.bufs.wire.as_ptr(), f.bufs.frame.as_ptr());
    let sent: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
    let y = f.emit(1, &sent, true, false).unwrap();
    assert_eq!(y.wire, sent);
    let y = f.ingest(&sent, true).unwrap();
    let got: Vec<u8> = y.pieces.iter().flat_map(|p| p.bytes.clone()).collect();
    assert_eq!(got, sent);
    assert!(
        door.count("emit") > 1,
        "re-called while the wire buffer was full"
    );
    assert!(
        door.count("ingest") > 1,
        "re-called while the frame buffer was full"
    );
    assert_eq!(f.bufs.wire.len(), WIRE_CAP);
    assert_eq!(f.bufs.frame.len(), FRAME_CAP);
    assert_eq!(f.bufs.wire.capacity(), WIRE_CAP);
    assert_eq!(f.bufs.frame.capacity(), FRAME_CAP);
    assert_eq!(
        f.bufs.wire.as_ptr(),
        wire_at,
        "the wire buffer is the one made at open"
    );
    assert_eq!(
        f.bufs.frame.as_ptr(),
        frame_at,
        "the frame buffer is the one made at open"
    );
}
