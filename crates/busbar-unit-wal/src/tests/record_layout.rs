// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frame itself: fixed stride, continuation, and a digest that catches an edit.

use crate::record::{
    decode_frame, FrameError, Record, FRAME_BYTES, FRAME_HEADER_BYTES, FRAME_MAGIC,
    FRAME_PAYLOAD_BYTES,
};

#[test]
fn every_frame_is_the_same_size_whatever_the_body_is() {
    for body_len in [0usize, 1, 415, 416, 417, 4096] {
        let record = Record::new(1, 1, vec![7u8; body_len]);
        let frames = record.encode();
        assert_eq!(frames.len(), record.frame_count());
        for frame in &frames {
            assert_eq!(frame.len(), FRAME_BYTES);
            assert_eq!(frame[0..4], FRAME_MAGIC);
        }
    }
}

#[test]
fn a_body_that_does_not_fit_continues_into_further_frames() {
    let body: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
    let record = Record::new(3, 9, body.clone());
    let frames = record.encode();
    assert_eq!(frames.len(), 3);

    let mut rebuilt = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let (header, payload) = decode_frame(frame).unwrap();
        assert_eq!(header.node, 3);
        assert_eq!(header.node_seq, 9);
        assert_eq!(header.part_index, index as u32);
        assert_eq!(header.part_count, 3);
        assert_eq!(header.more_parts, index + 1 < 3);
        rebuilt.extend_from_slice(payload);
    }
    assert_eq!(rebuilt, body, "the body comes back exactly as it went in");
}

#[test]
fn a_body_exactly_one_frame_long_takes_one_frame() {
    let record = Record::new(1, 1, vec![0u8; FRAME_PAYLOAD_BYTES]);
    assert_eq!(record.frame_count(), 1);
    let record = Record::new(1, 1, vec![0u8; FRAME_PAYLOAD_BYTES + 1]);
    assert_eq!(record.frame_count(), 2);
}

#[test]
fn an_empty_body_is_still_one_frame() {
    let record = Record::new(1, 1, Vec::new());
    let frames = record.encode();
    assert_eq!(frames.len(), 1);
    let (header, payload) = decode_frame(&frames[0]).unwrap();
    assert_eq!(header.payload_len, 0);
    assert!(payload.is_empty());
    assert!(!header.more_parts);
}

#[test]
fn editing_any_byte_of_a_frame_is_caught() {
    let record = Record::new(11, 22, vec![5u8; 100]);
    let frame = record.encode().remove(0);
    for offset in 0..FRAME_BYTES {
        let mut edited = frame;
        edited[offset] ^= 0x01;
        let result = decode_frame(&edited);
        assert!(
            result.is_err(),
            "a flip at byte {offset} of the frame went undetected"
        );
    }
}

#[test]
fn zeros_are_read_as_the_end_of_the_writes_and_not_as_damage() {
    let zeros = [0u8; FRAME_BYTES];
    assert_eq!(decode_frame(&zeros), Err(FrameError::NotAFrame));
}

#[test]
fn a_frame_whose_payload_length_is_impossible_is_refused_before_it_is_used() {
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[32..34].copy_from_slice(&((FRAME_PAYLOAD_BYTES + 1) as u16).to_le_bytes());
    assert!(matches!(
        decode_frame(&frame),
        Err(FrameError::PayloadTooLong { .. })
    ));
}

#[test]
fn a_frame_from_a_layout_this_build_does_not_know_stops_the_scan() {
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[4..6].copy_from_slice(&999u16.to_le_bytes());
    assert!(matches!(
        decode_frame(&frame),
        Err(FrameError::UnknownVersion { found: 999 })
    ));
}

#[test]
fn a_frame_claiming_a_part_outside_its_own_count_is_refused() {
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[24..28].copy_from_slice(&5u32.to_le_bytes());
    assert!(matches!(
        decode_frame(&frame),
        Err(FrameError::BadParts { .. })
    ));
}

#[test]
fn the_header_leaves_the_documented_amount_of_room_for_a_payload() {
    // The two constants are load-bearing for the fixed stride, so they are pinned rather than
    // recomputed from each other at every call site.
    assert_eq!(FRAME_HEADER_BYTES + FRAME_PAYLOAD_BYTES, FRAME_BYTES);
    assert_eq!(FRAME_BYTES, crate::MAX_RECORD_BYTES);
}
