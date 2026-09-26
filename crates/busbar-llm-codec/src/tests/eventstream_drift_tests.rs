// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EVENT-STREAM DRIFT GUARD (#83a SD-3): the plane's copy of the framing codec encodes every
//! frame byte-identical to the host's copy — prelude, headers, payload and both CRC-32s — and decodes
//! the same frames, statuses and consumed counts from the same bytes, including a malformed prelude
//! and a trailing partial frame. The host's encoder uses the `crc32fast` crate, so a match here also
//! pins the plane's own CRC-32 against it on real frames.

use super::*;
use busbar_kernel::eventstream as host;

fn events() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("messageStart", br#"{"role":"assistant"}"#.to_vec()),
        (
            "contentBlockDelta",
            r#"{"contentBlockIndex":0,"delta":{"text":"hi é [x] {y}"}}"#
                .as_bytes()
                .to_vec(),
        ),
        ("messageStop", br#"{"stopReason":"end_turn"}"#.to_vec()),
        (
            "metadata",
            br#"{"usage":{"inputTokens":3,"outputTokens":5,"totalTokens":8}}"#.to_vec(),
        ),
        ("chunk", Vec::new()),
        ("x", vec![0u8, 1, 2, 255, 254, 10, 13]),
        ("contentBlockDelta", vec![b'a'; 70_000]),
    ]
}

#[test]
fn encoded_frames_are_byte_identical_to_the_host_encoder() {
    for (event_type, payload) in events() {
        assert_eq!(
            encode_frame(event_type, &payload),
            host::encode_frame(event_type, &payload),
            "encode_frame differs for {event_type}"
        );
    }
    // An event type too long for the one-byte-length header block is dropped by both.
    let long = "e".repeat(300);
    assert_eq!(encode_frame(&long, b"{}"), host::encode_frame(&long, b"{}"));
}

#[test]
fn exception_frames_are_byte_identical_to_the_host_encoder() {
    for (exception, message) in [
        ("throttlingException", "Too many requests"),
        ("internalServerException", "boom \"quoted\" \u{e9}"),
        ("validationException", ""),
    ] {
        assert_eq!(
            encode_exception_frame(exception, message),
            host::encode_exception_frame(exception, message),
            "encode_exception_frame differs for {exception}"
        );
    }
}

#[test]
fn decoding_agrees_with_the_host_decoder() {
    let mut stream = Vec::new();
    for (event_type, payload) in events() {
        stream.extend_from_slice(&host::encode_frame(event_type, &payload));
    }
    stream.extend_from_slice(&host::encode_exception_frame(
        "throttlingException",
        "slow down",
    ));
    // Every split point of the first few hundred bytes, so a partial frame is left behind at each
    // boundary the reassembler can meet.
    for split in (0..stream.len().min(400)).step_by(7) {
        let (mut plane_buf, mut host_buf) = (stream[..split].to_vec(), stream[..split].to_vec());
        let (mut plane_sink, mut host_sink) = (Vec::new(), Vec::new());
        let plane = drain_frames_checked(&mut plane_buf, Some(&mut plane_sink));
        let hostd = host::drain_frames_checked(&mut host_buf, Some(&mut host_sink));
        assert_eq!(plane.0, hostd.0, "frames differ at split {split}");
        assert_eq!(plane.2, hostd.2, "consumed count differs at split {split}");
        assert_eq!(
            plane.1 == DrainStatus::Ok,
            hostd.1 == host::DrainStatus::Ok,
            "status differs at split {split}"
        );
        assert_eq!(plane_buf, host_buf, "residue differs at split {split}");
        assert_eq!(
            plane_sink, host_sink,
            "verbatim sink differs at split {split}"
        );
    }
    let (mut plane_buf, mut host_buf) = (stream.clone(), stream.clone());
    let plane = drain_frames_checked(&mut plane_buf, None);
    let hostd = host::drain_frames_checked(&mut host_buf, None);
    assert_eq!(plane.0, hostd.0);
    assert_eq!(plane.2, hostd.2);
    assert_eq!(plane.0.len(), events().len() + 1);
    // A malformed prelude (a total length past the frame cap) abandons the stream on both.
    let mut bad = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
    let mut host_bad = bad.clone();
    let plane = drain_frames_checked(&mut bad, None);
    let hostd = host::drain_frames_checked(&mut host_bad, None);
    assert_eq!(plane.1, DrainStatus::MalformedPrelude);
    assert_eq!(hostd.1, host::DrainStatus::MalformedPrelude);
    assert_eq!(bad, host_bad);
    assert_eq!(MAX_FRAME_BYTES, host::MAX_FRAME_BYTES);
}
