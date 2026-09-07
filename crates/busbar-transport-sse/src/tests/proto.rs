//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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
