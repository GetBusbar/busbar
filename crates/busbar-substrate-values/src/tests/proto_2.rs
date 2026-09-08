//! Tests for `proto.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The event-stream grammar names three line terminators — CRLF, a lone LF, a lone CR — and a
/// blank line is any terminator immediately followed by any terminator (nine pairings). A
/// scanner that only recognised `\n\n`/`\r\n\r\n` never framed a bare-CR stream, or a stream
/// mixing terminators across the frame boundary, at all.
#[test]
fn every_spec_line_terminator_pairing_ends_a_frame() {
    assert_eq!(find_frame_terminator(b"data: a\r\rrest"), Some((7, 2)));
    assert_eq!(find_frame_terminator(b"data: a\n\rrest"), Some((7, 2)));
    assert_eq!(find_frame_terminator(b"data: a\r\n\rrest"), Some((7, 3)));
    assert_eq!(find_frame_terminator(b"data: a\n\r\nrest"), Some((7, 3)));
    assert_eq!(find_frame_terminator(b"data: a\r\n\n"), Some((7, 3)));
    assert_eq!(find_frame_terminator(b"data: a\n\r\n"), Some((7, 3)));
    // One terminator is not a blank line: the frame has not ended.
    assert_eq!(find_frame_terminator(b"data: a\r\nrest"), None);
    // A CRLF is ONE terminator, never two: mis-splitting it is the only real risk here.
    assert_eq!(find_frame_terminator(b"a\r\nb\r\n\r\nc"), Some((4, 4)));
    // A lone trailing CR is not yet knowable — it may still turn out to be a CRLF.
    assert_eq!(find_frame_terminator(b"data: a\r"), None);
    // The existing LF/CRLF offsets stay byte-identical.
    assert_eq!(find_frame_terminator(b"data: a\n\nrest"), Some((7, 2)));
    assert_eq!(find_frame_terminator(b"data: a\r\n\r\nrest"), Some((7, 4)));
    assert_eq!(find_frame_terminator(b"data: a"), None);
}

/// `parse_sse_frame` used `str::lines()`, which does not split on a bare CR — a bare-CR frame
/// (correctly framed by `find_frame_terminator` above) yielded no `data:` line at all, and a
/// multi-field bare-CR frame swallowed later fields into the first value.
#[test]
fn parse_sse_frame_splits_on_bare_cr() {
    assert_eq!(
        parse_sse_frame(b"event: message\rdata: {\"a\":1}"),
        Some(("message".to_string(), "{\"a\":1}".to_string()))
    );
    assert_eq!(
        parse_sse_frame(b"data: line1\rdata: line2"),
        Some((String::new(), "line1\nline2".to_string()))
    );
    // CRLF and LF frames stay byte-identical to today.
    assert_eq!(
        parse_sse_frame(b"event: message\r\ndata: {\"a\":1}\r\n"),
        Some(("message".to_string(), "{\"a\":1}".to_string()))
    );
    assert_eq!(
        parse_sse_frame(b"data: line1\ndata: line2"),
        Some((String::new(), "line1\nline2".to_string()))
    );
}

/// The cheap `event:`-name probe split on LF alone, so a bare-CR frame came back as the WHOLE
/// frame body (`message_delta\rdata: {…}`). The Anthropic same-protocol fast path matches that
/// name against its usage-bearing set, so a bare-CR stream's usage frames were skipped and the
/// request billed zero. The probe now walks the same terminator grammar the parser does.
#[test]
fn sse_event_type_splits_on_bare_cr() {
    assert_eq!(
        sse_event_type(b"event: message_delta\rdata: {\"x\":1}\r\r"),
        "message_delta"
    );
    assert_eq!(
        sse_event_type(b"event: message_start\rdata: {}"),
        "message_start"
    );
    // The LAST `event:` line still wins across a bare-CR frame.
    assert_eq!(sse_event_type(b"event: a\revent: b\rdata: {}"), "b");
    // LF / CRLF / no-event frames stay byte-identical to today.
    assert_eq!(
        sse_event_type(b"event: message_delta\ndata: {}\n\n"),
        "message_delta"
    );
    assert_eq!(
        sse_event_type(b"event: message_delta\r\ndata: {}\r\n\r\n"),
        "message_delta"
    );
    assert_eq!(sse_event_type(b"data: {}\n\n"), "");
    assert_eq!(sse_event_type(b""), "");
}
