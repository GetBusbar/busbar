// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EVENT-STREAM DRIFT GUARD (#83a SD-3): the plane's copy of the framing codec encodes every
//! frame in the shared fixture `testing/plane-copies/eventstream-frames.json` byte for byte —
//! prelude, headers, payload and both CRC-32s — and decodes the same frames back from their
//! concatenation, including a trailing partial frame at every split and a malformed prelude. The
//! fixture is the host encoder's output, and the host's own suite holds its encoder to the same
//! file, so the two copies cannot drift apart without one of the two suites failing. Matching real
//! frames also pins the plane's own CRC-32 against the host's.

use super::*;

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/eventstream-frames.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
        .expect("fixture is JSON")
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    crate::hex::decode(v.as_str().expect("hex string")).expect("hex")
}

#[test]
fn encoded_frames_are_byte_identical_to_the_shared_fixture() {
    let doc = fixture();
    assert_eq!(doc["max_frame_bytes"], MAX_FRAME_BYTES as u64);
    for f in doc["frames"].as_array().expect("frames") {
        let event_type = f["event_type"].as_str().expect("event type");
        assert_eq!(
            encode_frame(event_type, &bytes(&f["payload_hex"])),
            bytes(&f["frame_hex"]),
            "encode_frame differs for {event_type:.40}"
        );
    }
}

#[test]
fn exception_frames_are_byte_identical_to_the_shared_fixture() {
    for f in fixture()["exception_frames"]
        .as_array()
        .expect("exception frames")
    {
        let exception = f["exception_type"].as_str().expect("type");
        let message = f["message"].as_str().expect("message");
        assert_eq!(
            encode_exception_frame(exception, message),
            bytes(&f["frame_hex"]),
            "encode_exception_frame differs for {exception}"
        );
    }
}

#[test]
fn decoding_the_shared_frames_recovers_them() {
    let doc = fixture();
    let mut stream = Vec::new();
    let mut expected = Vec::new();
    for f in doc["frames"].as_array().expect("frames") {
        let frame = bytes(&f["frame_hex"]);
        if frame.is_empty() {
            continue; // an event type too long for its header is dropped by the encoder
        }
        stream.extend_from_slice(&frame);
        expected.push((
            f["event_type"].as_str().expect("event type").to_string(),
            bytes(&f["payload_hex"]),
        ));
    }
    let whole = stream.len();
    let (mut buf, mut sink) = (stream.clone(), Vec::new());
    let (frames, status, consumed) = drain_frames_checked(&mut buf, Some(&mut sink));
    assert_eq!(frames, expected);
    assert_eq!(status, DrainStatus::Ok);
    assert_eq!(consumed, whole);
    assert_eq!(sink, stream);
    assert!(buf.is_empty());
    // A partial frame at every early split is left buffered, never decoded.
    for split in (0..stream.len().min(400)).step_by(7) {
        let mut part = stream[..split].to_vec();
        let (frames, status, consumed) = drain_frames_checked(&mut part, None);
        assert_eq!(status, DrainStatus::Ok, "split {split}");
        assert_eq!(part.len(), split - consumed, "split {split}");
        assert!(expected.starts_with(&frames), "split {split}");
    }
    // A malformed prelude (a total length past the frame cap) abandons the stream.
    let mut bad = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
    let (_, status, _) = drain_frames_checked(&mut bad, None);
    assert_eq!(status, DrainStatus::MalformedPrelude);
    assert!(bad.is_empty());
}
