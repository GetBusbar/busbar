// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frame itself: fixed stride, continuation, and a digest that catches an edit.

use crate::record::{
    decode_frame, unfinished_write, FrameError, Record, FRAME_BYTES, FRAME_END_MARK,
    FRAME_HEADER_BYTES, FRAME_MAGIC, FRAME_PAYLOAD_BYTES, FRAME_TRAILER_BYTES, FRAME_VERSION,
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
    // Re-sealed after the edit, so the header check passes and the bound behind it is what refuses
    // (an unsealed edit fails its header check first: `a_header_edit_fails_its_header_check`).
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[32..34].copy_from_slice(&((FRAME_PAYLOAD_BYTES + 1) as u16).to_le_bytes());
    crate::tests::fixtures::reseal(&mut frame);
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

/// Version 1 — the layout before the header check — was never released, so this build does not read
/// it: a frame claiming it is an unknown layout, sealed digest or not. Reading it would let a frame
/// relabelled 1 skip its header check.
#[test]
fn a_version_1_frame_is_a_layout_this_build_does_not_read() {
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[4..6].copy_from_slice(&1u16.to_le_bytes());
    // Re-sealed under the edit, so nothing but the version can refuse it.
    crate::tests::fixtures::reseal(&mut frame);
    assert_eq!(
        decode_frame(&frame),
        Err(FrameError::UnknownVersion { found: 1 })
    );
    assert!(crate::record::checked_header(&frame).is_none());
}

#[test]
fn a_frame_claiming_a_part_outside_its_own_count_is_refused() {
    // Re-sealed after the edit, so the header check passes and the bound behind it is what refuses.
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[24..28].copy_from_slice(&5u32.to_le_bytes());
    crate::tests::fixtures::reseal(&mut frame);
    assert!(matches!(
        decode_frame(&frame),
        Err(FrameError::BadParts { .. })
    ));
}

#[test]
fn the_header_leaves_the_documented_amount_of_room_for_a_payload() {
    // The constants are load-bearing for the fixed stride, so they are pinned rather than
    // recomputed from each other at every call site.
    assert_eq!(
        FRAME_HEADER_BYTES + FRAME_PAYLOAD_BYTES + FRAME_TRAILER_BYTES,
        FRAME_BYTES
    );
    assert_eq!(FRAME_HEADER_BYTES, 96);
    assert_eq!(FRAME_PAYLOAD_BYTES, 415);
    assert_eq!(FRAME_TRAILER_BYTES, 1);
    assert_eq!(FRAME_VERSION, 3);
    assert_eq!(FRAME_BYTES, crate::MAX_RECORD_BYTES);
}

/// Every frame ENDS with its end mark, and the end mark is never zero: it is the byte that says the
/// write reached the frame's end.
#[test]
fn every_frame_ends_with_its_end_mark() {
    assert_ne!(FRAME_END_MARK, 0);
    for body_len in [
        0usize,
        1,
        FRAME_PAYLOAD_BYTES,
        FRAME_PAYLOAD_BYTES + 1,
        1000,
    ] {
        let body: Vec<u8> = vec![0u8; body_len];
        for frame in Record::new(1, 1, body).encode() {
            assert_eq!(frame[FRAME_BYTES - 1], FRAME_END_MARK, "body of {body_len}");
        }
    }
}

/// **A WRITE THAT STOPS ANYWHERE INSIDE A FRAME LEAVES AN UNFINISHED WRITE; A WHOLE FRAME THAT
/// CHANGED NEVER IS ONE.** The two are what recovery tells a torn tail from an altered record by, so
/// both directions are walked at every byte: a frame cut at each offset (the rest the zeros the
/// segment claimed ahead) is unfinished and does not decode, and the same frame with any one byte
/// changed is not unfinished, wherever that byte is.
#[test]
fn a_write_stopped_at_any_byte_is_unfinished_and_a_changed_whole_frame_is_not() {
    // A payload ending in zeros: the case where the bytes alone could not have told a tear in the
    // payload from a whole frame.
    let mut body = vec![7u8; 300];
    body.extend_from_slice(&[0u8; 50]);
    let frame = Record::new(9, 4, body).encode_in_commit(true).remove(0);
    for stop in 0..FRAME_BYTES {
        let mut torn = [0u8; FRAME_BYTES];
        torn[..stop].copy_from_slice(&frame[..stop]);
        assert!(
            unfinished_write(&torn),
            "a write that stopped at byte {stop} is an unfinished write"
        );
        assert!(
            decode_frame(&torn).is_err(),
            "and is not read, at byte {stop}"
        );
    }
    assert!(decode_frame(&frame).is_ok());
    assert!(!unfinished_write(&frame), "a whole frame is not unfinished");
    for at in 0..FRAME_BYTES {
        let mut changed = frame;
        changed[at] ^= 0xFF;
        assert!(
            !unfinished_write(&changed),
            "a whole frame with byte {at} changed reads as an unfinished write"
        );
    }
}

/// A frame of a layout this build does not read is never an unfinished write of this one, even
/// with a zero last byte: its bytes are another build's to read, and recovery never cuts them.
#[test]
fn a_frame_of_another_layout_is_never_an_unfinished_write() {
    let mut frame = Record::new(1, 1, vec![1u8; 10]).encode().remove(0);
    frame[FRAME_BYTES - 1] = 0;
    for version in [1u16, 2] {
        frame[4..6].copy_from_slice(&version.to_le_bytes());
        assert!(!unfinished_write(&frame), "version {version}");
    }
}

/// The first frame of a group commit says so, and no other frame does: it is the frame whose
/// verifying presence past a damaged commit proves that commit was acknowledged.
#[test]
fn only_the_first_frame_of_a_commit_opens_it() {
    let record = Record::new(2, 5, vec![3u8; 1000]);
    let opening: Vec<bool> = record
        .encode_in_commit(true)
        .iter()
        .map(|f| decode_frame(f).unwrap().0.opens_commit)
        .collect();
    assert_eq!(opening, vec![true, false, false]);
    assert!(record
        .encode()
        .iter()
        .all(|f| !decode_frame(f).unwrap().0.opens_commit));
}

/// A frame whose header field is edited fails its HEADER CHECK before anything else is read: an edit
/// to the header never reads as a different record.
#[test]
fn a_header_edit_fails_its_header_check() {
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[24..28].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(decode_frame(&frame), Err(FrameError::HeaderMismatch));
}

/// A frame whose PAYLOAD is edited keeps its header check and its end mark and fails its digest: a
/// whole frame altered after it was written.
#[test]
fn a_payload_edit_is_an_altered_whole_frame() {
    let record = Record::new(1, 1, vec![1u8; 10]);
    let mut frame = record.encode().remove(0);
    frame[crate::record::FRAME_HEADER_BYTES] ^= 0xFF;
    assert_eq!(decode_frame(&frame), Err(FrameError::DigestMismatch));
    assert!(crate::record::checked_header(&frame).is_some());
    assert!(FrameError::DigestMismatch.is_altered_whole_frame(crate::record::FRAME_VERSION));
}

/// THE ON-DISK DIGESTS ARE SHA-256, BYTE FOR BYTE. The frame digest, the header check and the
/// journal's body digest are computed with ring (ONE crypto backend = ring), and a frame must carry
/// exactly the bytes an independent SHA-256 (RustCrypto `sha2`, a dev-dependency only) computes over
/// the same regions: the digest (header bytes 64..96) over the header up to it plus the payload area
/// and the end mark, and the 4-byte check (34..38) over bytes 0..34.
#[test]
fn the_frame_digest_and_header_check_are_sha256_byte_for_byte() {
    use sha2::Digest as _;
    let body: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
    for frame in Record::new(5, 11, body).encode() {
        let mut h = sha2::Sha256::new();
        h.update(&frame[0..64]);
        h.update(&frame[FRAME_HEADER_BYTES..]);
        let digest: [u8; 32] = h.finalize().into();
        assert_eq!(frame[64..96], digest);
        let check: [u8; 32] = sha2::Sha256::digest(&frame[0..34]).into();
        assert_eq!(frame[34..38], check[0..4]);
    }
    let witness: [u8; 32] = sha2::Sha256::digest(b"abc").into();
    assert_eq!(crate::journal::body_digest(b"abc"), witness);
}
