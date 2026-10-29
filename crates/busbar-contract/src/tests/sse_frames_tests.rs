// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The event-stream frame reassembler. The cases are plane-a2a's `SseReader` battery
//! (`tests/sse_tests.rs`), over the reassembler both it and plane-llm's stream readers frame with.

use super::*;

/// Every frame `chunks` complete, fed in order.
fn frames(chunks: &[&[u8]]) -> (Vec<Vec<u8>>, SseFrames) {
    let mut r = SseFrames::new();
    let mut out = Vec::new();
    for chunk in chunks {
        r.push(chunk);
        while let Some(frame) = r.next_frame() {
            out.push(frame.to_vec());
        }
    }
    (out, r)
}

/// All three of the spec's line terminators end a line, so all nine of their pairings end a frame.
#[test]
fn every_spec_line_terminator_pairing_ends_a_frame() {
    let cases: &[(&str, &str)] = &[
        ("data: a\r\rrest", "data: a\r\r"),
        ("data: a\n\rrest", "data: a\n\r"),
        ("data: a\r\n\rrest", "data: a\r\n\r"),
        ("data: a\n\r\nrest", "data: a\n\r\n"),
        ("data: a\r\n\n", "data: a\r\n\n"),
        ("data: a\n\r\n", "data: a\n\r\n"),
        ("data: a\n\nrest", "data: a\n\n"),
        ("data: a\r\n\r\nrest", "data: a\r\n\r\n"),
    ];
    for (input, framed) in cases {
        let (out, _) = frames(&[input.as_bytes()]);
        assert_eq!(out, vec![framed.as_bytes().to_vec()], "input {input:?}");
    }
    // The lone trailing CR is not yet knowable (it may still turn out to be a CRLF), so it frames
    // nothing until more bytes arrive.
    let (out, _) = frames(&[b"data: a\r"]);
    assert!(
        out.is_empty(),
        "a bare trailing CR must wait for more bytes, not frame early"
    );
}

/// A terminator split across a chunk boundary still ends the frame: the scan resumes three bytes
/// behind where it stopped.
#[test]
fn a_terminator_split_across_chunks_still_frames() {
    for (head, tail, framed, leftover) in [
        ("data: a\r\n", "\r\n", "data: a\r\n\r\n", ""),
        ("data: a\r\n\r", "\n", "data: a\r\n\r\n", ""),
        ("data: a\n", "\n", "data: a\n\n", ""),
        // A bare CR ending the tail is itself ambiguous, so the tail carries one more,
        // unambiguous byte after it; that byte is not part of the terminator and stays pending.
        ("data: a\r", "\rx", "data: a\r\r", "x"),
    ] {
        let (out, r) = frames(&[head.as_bytes()]);
        assert!(out.is_empty(), "a partial terminator waits ({head:?})");
        let (out, r) = {
            let mut r = r;
            r.push(tail.as_bytes());
            let mut out = Vec::new();
            while let Some(frame) = r.next_frame() {
                out.push(frame.to_vec());
            }
            (out, r)
        };
        assert_eq!(
            out,
            vec![framed.as_bytes().to_vec()],
            "a terminator straddling the chunk boundary still ends the frame ({head:?}+{tail:?})"
        );
        assert_eq!(
            r.pending(),
            leftover.len(),
            "only the disambiguating byte (if any) stays held ({head:?}+{tail:?})"
        );
    }
}

/// An unterminated frame trickled a byte at a time is scanned once: each scan resumes where the
/// last stopped, so the work is linear in the bytes fed, not bytes x chunks.
#[test]
fn a_frame_trickled_byte_by_byte_is_scanned_once() {
    const N: usize = 8192;
    let mut r = SseFrames::new();
    for _ in 0..N {
        r.push(b"x");
        assert!(r.next_frame().is_none(), "no terminator yet, so no frame");
        assert_eq!(
            r.scanned,
            r.buffer().len(),
            "the next scan starts at the end"
        );
    }
    assert_eq!(r.pending(), N, "every byte is still held");
    r.push(b"\n\n");
    assert_eq!(r.next_frame().map(<[u8]>::len), Some(N + 2));
    assert_eq!(r.pending(), 0);
}

/// One chunk of many small frames frames them all without moving the buffer once per frame: the
/// framed prefix is dropped once, at the next push.
#[test]
fn many_frames_in_one_chunk_are_dropped_once() {
    const N: usize = 4096;
    let chunk = "\n\n".repeat(N).into_bytes();
    let mut r = SseFrames::new();
    r.push(&chunk);
    let mut spans = Vec::new();
    while let Some(span) = r.next_span() {
        spans.push(span);
    }
    assert_eq!(spans.len(), N, "every \"\\n\\n\" pair is its own frame");
    assert_eq!(r.pending(), 0, "the whole chunk was framed");
    assert_eq!(r.buffer().len(), chunk.len(), "nothing moved while framing");
    assert_eq!(spans.last(), Some(&(chunk.len() - 2..chunk.len())));
    r.push(b"data: b");
    assert_eq!(r.buffer(), b"data: b", "the framed prefix went at the push");
}

/// Frames come out whole and in order however the bytes are chunked, each lent from the buffer.
#[test]
fn frames_are_whole_and_in_order_however_chunked() {
    let stream: &[u8] = b"event: a\ndata: {\"n\":1}\n\n: ping\r\n\r\ndata: x\rdata: y\r\r";
    let want: Vec<Vec<u8>> = vec![
        b"event: a\ndata: {\"n\":1}\n\n".to_vec(),
        b": ping\r\n\r\n".to_vec(),
        b"data: x\rdata: y\r\r".to_vec(),
    ];
    for size in 1..=stream.len() {
        let chunks: Vec<&[u8]> = stream.chunks(size).collect();
        let (mut out, mut r) = frames(&chunks);
        // The trailing bare CR waits: the last frame is whole once a byte shows it is not a CRLF.
        assert_eq!(out, want[..2], "chunked by {size}");
        assert_eq!(r.pending(), want[2].len(), "chunked by {size}");
        r.push(b"x");
        out.extend(r.next_frame().map(<[u8]>::to_vec));
        assert_eq!(out, want, "chunked by {size}");
        assert_eq!(r.pending(), 1, "chunked by {size}");
    }
}
