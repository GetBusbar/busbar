// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the neutral SSE frame reader (`proxy/sse.rs`).

use super::*;

/// A dropped non-UTF-8 frame is an operator-facing warn on a served path, so it carries a
/// registered `BUSBAR-NNNN` code an operator can look up — the drop itself is unchanged. Emitted
/// twice because a warn callsite's interest is cached process-wide and a concurrent test's
/// dispatcher can make the FIRST emission through this scoped subscriber invisible.
#[test]
fn test_non_utf8_frame_drop_carries_diag_code() {
    use crate::diagnostics::PLANE_SSE_FRAME_NOT_UTF8;
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        let mut r = SseReader::default();
        let first = r.feed(b"data: \xff\xfe\n\n");
        let _ = r.feed(b"data: \xff\xfe\n\n");
        first
    });

    assert!(
        out.is_empty(),
        "a non-UTF-8 frame is still dropped, not relayed"
    );
    let banner = PLANE_SSE_FRAME_NOT_UTF8.banner().to_string();
    assert!(
        cap.contains(&banner),
        "the dropped-frame warning must carry diag={banner}; captured: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("dropping a non-UTF-8 SSE frame"),
        "the message text is preserved; captured: {:?}",
        cap.messages()
    );
}

/// An event trickled across many chunks must cost work proportional to its BYTES, not to bytes ×
/// chunks. Upstream responses are untrusted, and the relay bounds only `pending()` against the
/// operator's body cap — a cap that is megabyte-scale — so a backend that dribbles a near-cap
/// unterminated event in TCP-sized pieces would otherwise burn a quadratic number of byte
/// comparisons on the relay thread before the ceiling stopped it.
///
/// The bound is generous (16 bytes of scan per byte fed) because the point is the SHAPE: a
/// full-buffer rescan per chunk walks ~3·N²/2 bytes for N chunks, which is four orders of magnitude
/// past this bound at the size used here.
#[test]
fn test_feed_scan_work_is_linear_in_bytes_fed() {
    const N: usize = 8192;
    let payload = vec![b'x'; N]; // no terminator anywhere: every chunk leaves the buffer pending

    let mut r = SseReader::default();
    let _ = take_scanned_bytes();
    for byte in payload.chunks(1) {
        assert!(r.feed(byte).is_empty(), "no terminator yet, so no event");
    }
    let scanned = take_scanned_bytes();

    assert_eq!(
        r.pending(),
        N,
        "every byte is still held awaiting a terminator"
    );
    assert!(
        scanned <= 16 * N,
        "scanning {N} bytes across {N} chunks walked {scanned} bytes — the scan restarts at byte \
         zero on every chunk (quadratic) instead of resuming where it left off"
    );
}

/// All three of the spec's line terminators end a line, so all nine of their pairings end a frame —
/// mirroring `busbar-transport-sse::proto`'s `every_spec_line_terminator_pairing_ends_a_frame` over
/// `SseReader::feed` rather than the bare scanner. A bare-CR stream (or one mixing terminators
/// across the frame boundary) must frame exactly like an LF/CRLF one.
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
        let mut r = SseReader::default();
        let out = r.feed(input.as_bytes());
        assert_eq!(out, vec![framed.to_string()], "input {input:?}");
    }

    // The lone trailing CR is not yet knowable — it may still turn out to be a CRLF — so it
    // returns nothing until more bytes arrive.
    let mut r = SseReader::default();
    assert!(
        r.feed(b"data: a\r").is_empty(),
        "a bare trailing CR must wait for more bytes, not frame early"
    );
}

/// The cursor rewind must not let a terminator SPLIT across a chunk boundary slip past: the longest
/// terminator is four bytes, so resuming three bytes behind the previous end is exactly enough.
/// Passes before and after the cursor exists — it guards the fix, not the defect.
#[test]
fn test_terminator_split_across_chunks_still_frames() {
    for (head, tail, framed, leftover) in [
        ("data: a\r\n", "\r\n", "data: a\r\n\r\n", ""),
        ("data: a\r\n\r", "\n", "data: a\r\n\r\n", ""),
        ("data: a\n", "\n", "data: a\n\n", ""),
        // A bare CR ending the tail is ITSELF ambiguous (it may still turn out to be a CRLF), so
        // the tail carries one more, unambiguous byte after it; that byte is not part of the
        // terminator and stays pending.
        ("data: a\r", "\rx", "data: a\r\r", "x"),
    ] {
        let mut r = SseReader::default();
        assert!(
            r.feed(head.as_bytes()).is_empty(),
            "a partial terminator waits for the rest ({head:?})"
        );
        let out = r.feed(tail.as_bytes());
        assert_eq!(
            out,
            vec![framed.to_string()],
            "a terminator straddling the chunk boundary still ends the event ({head:?}+{tail:?})"
        );
        assert_eq!(
            r.pending(),
            leftover.len(),
            "only the disambiguating byte (if any) stays buffered ({head:?}+{tail:?})"
        );
    }
}

/// `feed` drained from the front once PER FRAME (`self.buf.drain(..pos + len)`), and reset `scanned`
/// to 0 on every drain — so one chunk holding many small events cost quadratic memmove (a full
/// rescan-from-zero AND a full-tail memmove, once per frame). One chunk of many trivial ("\n\n")
/// events must cost work proportional to the chunk's BYTES, not to bytes × frames.
///
/// The tally is taken AT the drain (`SseReader::drain_front`), so a second drain inside the same
/// `feed` counts a second time and the assertion below is exact rather than a budget: one feed
/// drains the buffer once, and that one drain walks exactly the bytes fed. A per-frame front-drain
/// would walk ~N²/2 bytes for N frames.
#[test]
fn test_feed_drain_work_is_linear_in_bytes_fed() {
    const N: usize = 4096;
    let chunk = "\n\n".repeat(N).into_bytes();
    let total = chunk.len();

    let mut r = SseReader::default();
    let _ = take_drained_bytes();
    let out = r.feed(&chunk);
    let drained = take_drained_bytes();

    assert_eq!(out.len(), N, "every \"\\n\\n\" pair is its own frame");
    assert_eq!(r.pending(), 0, "the whole chunk was framed");
    assert_eq!(
        drained, total,
        "feeding {total} bytes as {N} frames in one chunk drained {drained} bytes — one feed() must \
         drain the buffer exactly once, not once per frame (quadratic)"
    );
}

/// A frame that was framed by a bare-CR terminator must still split into fields on a bare-CR line
/// break — `str::lines()` only splits on LF/CRLF, so a bare-CR frame yielded NO data at all (the
/// A2A relay then answered 502), and a multi-field bare-CR frame swallowed later fields into the
/// first value.
#[test]
fn test_sse_data_splits_on_bare_cr() {
    assert_eq!(
        sse_data("event: message\rdata: {\"a\":1}\r\r"),
        Some("{\"a\":1}".to_string())
    );
    // Two `data:` lines joined by a bare CR must still concatenate with `\n`, not swallow the
    // second line into the first's value.
    assert_eq!(
        sse_data("data: line1\rdata: line2\r\r"),
        Some("line1\nline2".to_string())
    );
    // LF and CRLF frames stay byte-identical to today.
    assert_eq!(
        sse_data("event: message\ndata: {\"a\":1}\n\n"),
        Some("{\"a\":1}".to_string())
    );
    assert_eq!(
        sse_data("data: line1\r\ndata: line2\r\n\r\n"),
        Some("line1\nline2".to_string())
    );
}
