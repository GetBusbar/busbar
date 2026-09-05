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

/// The cursor rewind must not let a terminator SPLIT across a chunk boundary slip past: the longest
/// terminator is four bytes, so resuming three bytes behind the previous end is exactly enough.
/// Passes before and after the cursor exists — it guards the fix, not the defect.
#[test]
fn test_terminator_split_across_chunks_still_frames() {
    for (head, tail) in [
        ("data: a\r\n", "\r\n"),
        ("data: a\r\n\r", "\n"),
        ("data: a\n", "\n"),
        ("data: a\r", "\r"),
    ] {
        let mut r = SseReader::default();
        assert!(
            r.feed(head.as_bytes()).is_empty(),
            "a partial terminator waits for the rest ({head:?})"
        );
        let out = r.feed(tail.as_bytes());
        assert_eq!(
            out,
            vec![format!("{head}{tail}")],
            "a terminator straddling the chunk boundary still ends the event ({head:?}+{tail:?})"
        );
        assert_eq!(r.pending(), 0, "the framed event left the buffer");
    }
}
