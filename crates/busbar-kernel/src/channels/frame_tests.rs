// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6 CH_FRAME_*: how a channel's byte stream is split into messages and how a message is written.

use super::frame::{frame, Framer, Framing, Overlong, MAX_MESSAGE};

fn texts(messages: Vec<Box<[u8]>>) -> Vec<String> {
    messages
        .into_iter()
        .map(|m| String::from_utf8(m.into_vec()).unwrap())
        .collect()
}

#[test]
fn a_framing_code_names_one_framing_and_an_unknown_one_none() {
    assert_eq!(Framing::of(0), Some(Framing::None));
    assert_eq!(Framing::of(1), Some(Framing::Ndjson));
    assert_eq!(Framing::of(2), Some(Framing::Sse));
    assert_eq!(Framing::of(3), None);
}

#[test]
fn ndjson_is_one_message_per_line_across_reads_with_the_carriage_return_and_blank_lines_dropped() {
    let mut framer = Framer::new(Framing::Ndjson);
    assert!(framer.push(b"{\"a\":").unwrap().is_empty());
    assert_eq!(
        texts(framer.push(b"1}\r\n\n  \n{\"b\":2}\n{\"c\"").unwrap()),
        ["{\"a\":1}", "{\"b\":2}"]
    );
    assert_eq!(texts(framer.push(b":3}\n").unwrap()), ["{\"c\":3}"]);
}

#[test]
fn ndjson_keeps_a_last_line_the_child_never_terminated() {
    let mut framer = Framer::new(Framing::Ndjson);
    assert!(framer.push(b"{\"last\":true}").unwrap().is_empty());
    assert_eq!(
        framer.finish().as_deref(),
        Some(&b"{\"last\":true}"[..]),
        "the child exited without a newline"
    );
    assert_eq!(framer.finish(), None);
}

#[test]
fn no_framing_is_one_message_per_read() {
    let mut framer = Framer::new(Framing::None);
    assert_eq!(texts(framer.push(b"ab\ncd").unwrap()), ["ab\ncd"]);
    assert!(framer.push(b"").unwrap().is_empty());
    assert_eq!(framer.finish(), None);
}

#[test]
fn sse_is_one_message_per_event_data_joined_by_newlines() {
    let mut framer = Framer::new(Framing::Sse);
    let events = framer
        .push(b": keep-alive\n\ndata: {\"a\":\ndata: 1}\nid: 7\nretry: 100\n\ndata:x\n\n")
        .unwrap();
    assert_eq!(texts(events), ["{\"a\":\n1}", "x"]);
}

#[test]
fn sse_events_split_across_reads_and_crlf_lines_are_whole() {
    let mut framer = Framer::new(Framing::Sse);
    assert!(framer.push(b"data: he").unwrap().is_empty());
    assert!(framer.push(b"llo\r\n").unwrap().is_empty());
    assert_eq!(texts(framer.push(b"\r\n").unwrap()), ["hello"]);
    assert_eq!(
        framer.finish(),
        None,
        "an event no blank line ended is not one"
    );
}

#[test]
fn a_named_sse_event_other_than_message_keeps_its_name_for_the_plane() {
    let mut framer = Framer::new(Framing::Sse);
    let events = framer
        .push(b"event: endpoint\ndata: /messages?s=1\n\nevent: message\ndata: m\n\n")
        .unwrap();
    assert_eq!(texts(events), ["event: endpoint\ndata: /messages?s=1", "m"]);
}

#[test]
fn an_event_with_no_data_is_nothing() {
    let mut framer = Framer::new(Framing::Sse);
    assert!(framer.push(b"event: ping\n\n").unwrap().is_empty());
}

#[test]
fn a_message_that_never_ends_is_refused_not_buffered_without_bound() {
    let mut framer = Framer::new(Framing::Ndjson);
    assert_eq!(framer.push(&vec![b'x'; MAX_MESSAGE + 1]), Err(Overlong));
    let mut whole = Framer::new(Framing::None);
    assert_eq!(whole.push(&vec![b'x'; MAX_MESSAGE + 1]), Err(Overlong));
}

#[test]
fn a_message_is_written_the_way_its_framing_reads_back() {
    assert_eq!(frame(Framing::None, b"ab"), b"ab");
    assert_eq!(frame(Framing::Ndjson, b"{\"a\":1}"), b"{\"a\":1}\n");
    let written = frame(Framing::Sse, b"one\ntwo");
    assert_eq!(written, b"data: one\ndata: two\n\n");
    let mut back = Framer::new(Framing::Sse);
    assert_eq!(texts(back.push(&written).unwrap()), ["one\ntwo"]);
}
