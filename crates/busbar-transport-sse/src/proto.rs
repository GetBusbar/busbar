// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SSE frame terminator and frame parser, ported from `busbar_substrate::proto` (moved here
//! per the design's own rule: "adding a transport" means the wire-level pieces that only a
//! transport needs move into the transport crate, verbatim in behaviour). `busbar-substrate` is
//! outside this delivery's ownership, so its copy is left for that crate's own owner to retire;
//! this is the transport-owned copy `sse` actually runs on.

/// The length of the line terminator starting at `i`, or `None` when `i` does not begin one.
///
/// The event-stream grammar names three: CRLF, a lone LF, and a lone CR. A CR at the very end of
/// the buffer is not yet knowable — the LF that would make it a CRLF may still be in flight — so it
/// reads as "no terminator here", which is the answer that makes a caller wait for more bytes
/// rather than split a CRLF down the middle.
fn terminator_len(buf: &[u8], i: usize) -> Option<usize> {
    match buf.get(i)? {
        b'\n' => Some(1),
        b'\r' => match buf.get(i + 1) {
            Some(b'\n') => Some(2),
            Some(_) => Some(1),
            None => None,
        },
        _ => None,
    }
}

/// Find the first SSE frame terminator (a blank line) in `buf` at or after `start`, returning
/// `(offset, terminator_len)` where `offset` is the byte index of the first terminator byte and the
/// length spans BOTH line terminators that make the blank line, alongside how many bytes of `buf`
/// this call examined — the pair a caller uses to pin the scan's own complexity class without a
/// process-global counter racing every other test in the binary. `None` when no complete blank line
/// is present yet.
///
/// All three of the spec's terminators are recognised, in every pairing: `\n\n` and `\r\n\r\n` are
/// the two the providers emit, and `\r\r`, `\n\r`, `\r\n\r` and `\r\r\n` are the rest of the
/// grammar.
///
/// A re-segmenting reader appends to its buffer and asks again; without a resume point it re-proves
/// the prefix it already proved, once per arriving chunk, which is quadratic in the frame size. The
/// caller passes the prefix it has already cleared, REWOUND BY THREE — the most of a four-byte
/// terminator a previous look can have left straddling the boundary.
///
/// The search jumps between CR and LF bytes rather than stepping every position; a terminator
/// begins with one of the two, so no candidate is skipped.
#[must_use]
pub fn find_frame_terminator_from(buf: &[u8], start: usize) -> (Option<(usize, usize)>, usize) {
    let mut i = start.min(buf.len());
    let scanned = buf.len() - i;
    let found = loop {
        let Some(rel) = memchr::memchr2(b'\r', b'\n', &buf[i..]) else {
            break None;
        };
        let at = i + rel;
        let Some(first) = terminator_len(buf, at) else {
            // Only reachable for a trailing CR: not a terminator yet, and nothing past it to scan.
            break None;
        };
        if let Some(second) = terminator_len(buf, at + first) {
            break Some((at, first + second));
        }
        // A line ended here but the next one is not blank: resume past the terminator itself, so a
        // CRLF is never re-read as a bare CR followed by a bare LF.
        i = at + first;
    };
    (found, scanned)
}

/// Split `buf` into lines on the same grammar [`terminator_len`] recognises — CRLF, a lone LF, or
/// a lone CR — rather than `str::lines`'s LF-only rule. Unlike the streaming scan above, a frame
/// handed here is already complete (its own trailing blank line was stripped when it was carved
/// out of the buffer), so a CR at the very end IS a terminator, not a "wait for more" ambiguity;
/// this never yields the empty final line a trailing terminator would otherwise leave behind.
fn split_frame_lines(buf: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < buf.len() {
        match buf[i] {
            b'\r' => {
                lines.push(&buf[start..i]);
                i += if buf.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            b'\n' => {
                lines.push(&buf[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < buf.len() {
        lines.push(&buf[start..]);
    }
    lines
}

/// Parse one SSE frame into `(event_type, data_payload)`. `event_type` is "" when the frame has
/// no `event:` line (OpenAI style). Multiple `data:` lines in a single frame are concatenated with
/// `\n` per the SSE spec. Returns `None` if the frame carries no `data:` line (including a frame
/// with only an `event:` line) or is invalid UTF-8.
#[must_use]
pub fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    // UTF-8 is validated once, over the whole frame; every split point below lands on a `\r` or
    // `\n` byte, both single-byte ASCII, which can only ever be a boundary in valid UTF-8 (a
    // continuation byte's top bit is always set), so each piece stays valid UTF-8 on its own.
    std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in split_frame_lines(frame) {
        let line = std::str::from_utf8(line).expect("ascii-boundary split of valid utf-8");
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        return None;
    }
    Some((event_type, data_lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole-buffer scan, which is the resuming scan started at zero. The cells below are about
    /// WHERE a frame boundary is rather than about resuming, so they ask for it in that shape and
    /// the resume point stays the streaming caller's concern.
    fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
        find_frame_terminator_from(buf, 0).0
    }

    #[test]
    fn finds_lf_lf_and_crlf_crlf_terminators() {
        assert_eq!(find_frame_terminator(b"data: a\n\nrest"), Some((7, 2)));
        assert_eq!(find_frame_terminator(b"data: a\r\n\r\nrest"), Some((7, 4)));
        assert_eq!(find_frame_terminator(b"data: a"), None);
    }

    /// All three of the spec's line terminators end a line, so all nine of their pairings end a
    /// frame. The event-stream grammar names CRLF, a lone LF and a lone CR, and dispatch happens on
    /// a blank line — which is any terminator immediately followed by another. A scanner that
    /// branched on LF alone never dispatched a CR-terminated stream at all: the buffer just grew
    /// for the life of the connection.
    #[test]
    fn every_spec_line_terminator_pairing_ends_a_frame() {
        assert_eq!(find_frame_terminator(b"data: a\r\rrest"), Some((7, 2)));
        assert_eq!(find_frame_terminator(b"data: a\n\rrest"), Some((7, 2)));
        assert_eq!(find_frame_terminator(b"data: a\r\n\rrest"), Some((7, 3)));
        assert_eq!(find_frame_terminator(b"data: a\r\rrest\n\n"), Some((7, 2)));
        // One terminator is not a blank line: the frame has not ended.
        assert_eq!(find_frame_terminator(b"data: a\r\nrest"), None);
        // A CRLF is ONE terminator, never two: mis-splitting it is the only real risk here.
        assert_eq!(find_frame_terminator(b"a\r\nb\r\n\r\nc"), Some((4, 4)));
        // A lone trailing CR is not yet knowable — it may still turn out to be a CRLF.
        assert_eq!(find_frame_terminator(b"data: a\r"), None);
    }

    #[test]
    fn parses_anthropic_and_openai_shapes() {
        assert_eq!(
            parse_sse_frame(b"event: message\ndata: {\"a\":1}"),
            Some(("message".to_string(), "{\"a\":1}".to_string()))
        );
        assert_eq!(
            parse_sse_frame(b"data: {\"a\":1}"),
            Some((String::new(), "{\"a\":1}".to_string()))
        );
        assert_eq!(parse_sse_frame(b"event: ping"), None);
    }

    #[test]
    fn joins_multiple_data_lines() {
        assert_eq!(
            parse_sse_frame(b"data: line1\ndata: line2"),
            Some((String::new(), "line1\nline2".to_string()))
        );
    }

    /// A bare CR is a legal line ending per the event-stream grammar, same as CRLF and LF. A
    /// scanner that only recognised `\n` (as `str::lines` does) drops a CR-only frame's data lines
    /// entirely, silently, at whatever reads the frame's return value.
    #[test]
    fn parses_a_cr_only_frame() {
        assert_eq!(
            parse_sse_frame(b"event: message\rdata: {\"a\":1}\r\r"),
            Some(("message".to_string(), "{\"a\":1}".to_string()))
        );
    }

    /// A frame whose lines end on different terminators must not have them fused into one
    /// corrupted payload: each `data:` line is its own line, joined afterwards with `\n`, exactly
    /// as the all-LF and all-CRLF cells above are.
    #[test]
    fn a_mixed_terminator_frame_does_not_corrupt_the_payload() {
        assert_eq!(
            parse_sse_frame(b"data: a\rdata: b\n"),
            Some((String::new(), "a\nb".to_string()))
        );
    }
}
