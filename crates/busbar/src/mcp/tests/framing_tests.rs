// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FRAMING, FED HOSTILE INPUT.
//!
//! The framer is the first thing a peer's bytes touch, and it decides where one message ends and the
//! next begins. Every attack on it is the same attack: make the two ends of the connection disagree
//! about that boundary. So the tests here are about splits, sizes and resynchronisation, and the
//! recurring assertion is that the framer would rather STOP than guess where it is in the stream.

use super::super::framing::{FrameError, FrameReader, Framing};

fn drain(r: &mut FrameReader) -> Vec<Result<String, FrameError>> {
    let mut out = Vec::new();
    while let Some(f) = r.next_frame() {
        out.push(f.map(|f| String::from_utf8_lossy(&f.payload).into_owned()));
    }
    out
}

// Newline-delimited (stdio) -----------------------------------------------------------------------

#[test]
fn newline_framing_cuts_one_message_per_line() {
    let mut r = FrameReader::new(Framing::Lines, 1024);
    r.push(b"{\"a\":1}\n{\"b\":2}\n");
    let got = drain(&mut r);
    assert_eq!(got, vec![Ok("{\"a\":1}".into()), Ok("{\"b\":2}".into())]);
}

#[test]
fn a_frame_split_byte_by_byte_reassembles_identically() {
    // The transport chooses the chunk boundaries, and an adversarial one chooses the worst ones. The
    // framer must be indifferent to them: one byte at a time is the worst case, so it is the test.
    let whole = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
    let mut r = FrameReader::new(Framing::Lines, 1024);
    let mut got = Vec::new();
    for b in whole {
        r.push(&[*b]);
        got.extend(drain(&mut r));
    }
    assert_eq!(
        got,
        vec![Ok(
            String::from_utf8_lossy(&whole[..whole.len() - 1]).into_owned()
        )]
    );
}

#[test]
fn a_truncated_frame_is_not_delivered_until_its_terminator_arrives() {
    let mut r = FrameReader::new(Framing::Lines, 1024);
    r.push(b"{\"jsonrpc\":\"2.0\",\"id\"");
    assert!(
        drain(&mut r).is_empty(),
        "an unterminated frame is not a frame"
    );
    r.push(b":1,\"method\":\"ping\"}\n");
    assert_eq!(
        drain(&mut r),
        vec![Ok(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}".into()
        )]
    );
}

#[test]
fn end_of_stream_on_a_partial_frame_is_an_error_not_a_frame() {
    // The half-message left in the buffer at EOF is the one an attacker most wants delivered: it is
    // whatever prefix of a message they could make us accept. It is a truncation, and it is reported.
    let mut r = FrameReader::new(Framing::Lines, 1024);
    r.push(b"{\"jsonrpc\":\"2.0\"");
    assert_eq!(r.finish(), Err(FrameError::TruncatedAtEof(16)));
}

#[test]
fn end_of_stream_on_a_clean_boundary_is_not_an_error() {
    let mut r = FrameReader::new(Framing::Lines, 1024);
    r.push(b"{}\n");
    let _ = drain(&mut r);
    assert_eq!(r.finish(), Ok(()));
}

#[test]
fn a_crlf_terminator_is_accepted_and_the_carriage_return_is_not_part_of_the_frame() {
    let mut r = FrameReader::new(Framing::Lines, 1024);
    r.push(b"{\"a\":1}\r\n");
    assert_eq!(drain(&mut r), vec![Ok("{\"a\":1}".into())]);
}

#[test]
fn blank_lines_are_skipped_rather_than_delivered_as_empty_frames() {
    // Keepalives. Delivering them as frames would make every reader downstream carry an "ignore the
    // empty one" special case, which is the sort of rule one reader eventually forgets.
    let mut r = FrameReader::new(Framing::Lines, 1024);
    r.push(b"\n\n{\"a\":1}\n\n");
    assert_eq!(drain(&mut r), vec![Ok("{\"a\":1}".into())]);
}

#[test]
fn an_oversized_frame_is_refused_and_the_reader_refuses_to_resynchronise() {
    // THE RESYNC TRAP. After a frame that never terminates within the limit, the reader does not
    // know where it is in the stream. Skipping to the next newline hands the attacker the boundary:
    // they choose where our next "message" starts, inside a payload they wrote. So the reader
    // poisons instead, and the connection is the thing that gets restarted.
    let mut r = FrameReader::new(Framing::Lines, 32);
    r.push(&[b'x'; 64]);
    let got = drain(&mut r);
    assert_eq!(
        got,
        vec![Err(FrameError::FrameTooLarge {
            limit: 32,
            seen: 64
        })]
    );
    r.push(b"\n{\"innocent\":true}\n");
    assert_eq!(
        drain(&mut r),
        vec![Err(FrameError::Poisoned)],
        "a poisoned reader must never deliver another frame"
    );
    assert_eq!(r.finish(), Err(FrameError::Poisoned));
}

#[test]
fn the_buffer_never_grows_past_the_limit_no_matter_how_much_is_pushed() {
    // Unbounded buffering IS the denial of service; the size cap is not a tidiness rule.
    let mut r = FrameReader::new(Framing::Lines, 128);
    for _ in 0..1000 {
        r.push(&[b'x'; 1024]);
        let _ = drain(&mut r);
        assert!(
            r.buffered() <= 128,
            "buffered {} bytes with a 128 byte limit",
            r.buffered()
        );
    }
}

#[test]
fn a_frame_exactly_at_the_limit_is_accepted_and_one_byte_more_is_not() {
    let mut at = FrameReader::new(Framing::Lines, 8);
    at.push(b"12345678\n");
    assert_eq!(drain(&mut at), vec![Ok("12345678".into())]);

    let mut over = FrameReader::new(Framing::Lines, 8);
    over.push(b"123456789\n");
    assert_eq!(
        drain(&mut over),
        vec![Err(FrameError::FrameTooLarge { limit: 8, seen: 9 })]
    );
}

// Server-sent events ------------------------------------------------------------------------------

#[test]
fn an_sse_event_is_delivered_at_the_blank_line_with_its_event_name() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n");
    let f = r.next_frame().expect("an event").expect("well formed");
    assert_eq!(f.event.as_deref(), Some("message"));
    assert_eq!(
        String::from_utf8_lossy(&f.payload),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"
    );
    assert!(r.next_frame().is_none());
}

#[test]
fn sse_data_lines_are_joined_with_newlines_in_order() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b"data: {\"a\":\ndata: 1}\n\n");
    let f = r.next_frame().expect("an event").expect("well formed");
    assert_eq!(String::from_utf8_lossy(&f.payload), "{\"a\":\n1}");
}

#[test]
fn an_sse_comment_is_a_keepalive_and_dispatches_nothing() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b": keepalive\n\n: another\n\n");
    assert!(drain(&mut r).is_empty());
    assert_eq!(r.finish(), Ok(()));
}

#[test]
fn an_sse_event_with_no_data_dispatches_nothing() {
    // Per the event-stream rules the data buffer being empty means no dispatch. Emitting an empty
    // payload instead would hand the JSON-RPC parser a frame that is guaranteed to fail, once per
    // keepalive, and the error log would be noise rather than signal.
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b"event: ping\n\n");
    assert!(drain(&mut r).is_empty());
}

#[test]
fn sse_tolerates_a_missing_space_after_the_field_colon_and_crlf_lines() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b"event:message\r\ndata:{\"a\":1}\r\n\r\n");
    let f = r.next_frame().expect("an event").expect("well formed");
    assert_eq!(f.event.as_deref(), Some("message"));
    assert_eq!(String::from_utf8_lossy(&f.payload), "{\"a\":1}");
}

#[test]
fn unknown_sse_fields_are_ignored_and_do_not_leak_into_the_payload() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b"id: 42\nretry: 1000\nsomething: else\ndata: {\"a\":1}\n\n");
    let f = r.next_frame().expect("an event").expect("well formed");
    assert_eq!(String::from_utf8_lossy(&f.payload), "{\"a\":1}");
}

#[test]
fn an_sse_event_that_never_ends_is_bounded_by_the_same_limit() {
    // The blank-line terminator is peer-controlled, so an event that simply never terminates is the
    // SSE spelling of the unbounded-buffer attack. Same cap, same poison, same reason.
    let mut r = FrameReader::new(Framing::Sse, 64);
    r.push(b"data: ");
    r.push(&[b'x'; 512]);
    let got = drain(&mut r);
    assert!(
        matches!(got.first(), Some(Err(FrameError::FrameTooLarge { .. }))),
        "got {got:?}"
    );
    r.push(b"\n\ndata: {}\n\n");
    assert_eq!(drain(&mut r), vec![Err(FrameError::Poisoned)]);
}

#[test]
fn an_sse_event_split_across_chunks_reassembles() {
    let whole = b"event: message\ndata: {\"id\":1}\n\n";
    let mut r = FrameReader::new(Framing::Sse, 1024);
    let mut got = Vec::new();
    for b in whole {
        r.push(&[*b]);
        got.extend(drain(&mut r));
    }
    assert_eq!(got, vec![Ok("{\"id\":1}".into())]);
}

#[test]
fn a_leading_byte_order_mark_is_stripped_once() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push("\u{feff}data: {\"a\":1}\n\n".as_bytes());
    let f = r.next_frame().expect("an event").expect("well formed");
    assert_eq!(String::from_utf8_lossy(&f.payload), "{\"a\":1}");
}

#[test]
fn sse_end_of_stream_mid_event_is_a_truncation() {
    let mut r = FrameReader::new(Framing::Sse, 1024);
    r.push(b"data: {\"a\":1}\n");
    assert!(drain(&mut r).is_empty(), "no blank line, no dispatch");
    assert!(matches!(r.finish(), Err(FrameError::TruncatedAtEof(_))));
}
