// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6 CH_FRAME_*: how a channel's byte stream is split into messages and how a message is written.

use super::frame::{Framer, Framing, Overlong, MAX_MESSAGE};

fn texts(messages: Vec<bytes::Bytes>) -> Vec<String> {
    messages
        .into_iter()
        .map(|m| String::from_utf8(m.to_vec()).unwrap())
        .collect()
}

fn funded_framer(framing: Framing) -> Framer {
    Framer::new(
        framing,
        super::budget::ChannelBudget::new()
            .instance()
            .unit()
            .storage(),
    )
    .unwrap()
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
    let mut framer = funded_framer(Framing::Ndjson);
    assert!(framer.push(b"{\"a\":").unwrap().is_empty());
    assert_eq!(
        texts(framer.push(b"1}\r\n\n  \n{\"b\":2}\n{\"c\"").unwrap()),
        ["{\"a\":1}", "{\"b\":2}"]
    );
    assert_eq!(texts(framer.push(b":3}\n").unwrap()), ["{\"c\":3}"]);
}

#[test]
fn ndjson_keeps_a_last_line_the_child_never_terminated() {
    let mut framer = funded_framer(Framing::Ndjson);
    assert!(framer.push(b"{\"last\":true}").unwrap().is_empty());
    assert_eq!(
        framer.finish().unwrap().as_deref(),
        Some(&b"{\"last\":true}"[..]),
        "the child exited without a newline"
    );
    assert_eq!(framer.finish().unwrap(), None);
}

#[test]
fn no_framing_is_one_message_per_read() {
    let mut framer = funded_framer(Framing::None);
    assert_eq!(texts(framer.push(b"ab\ncd").unwrap()), ["ab\ncd"]);
    assert!(framer.push(b"").unwrap().is_empty());
    assert_eq!(framer.finish().unwrap(), None);
}

#[test]
fn sse_is_one_message_per_event_data_joined_by_newlines() {
    let mut framer = funded_framer(Framing::Sse);
    let events = framer
        .push(b": keep-alive\n\ndata: {\"a\":\ndata: 1}\nid: 7\nretry: 100\n\ndata:x\n\n")
        .unwrap();
    assert_eq!(texts(events), ["{\"a\":\n1}", "x"]);
}

#[test]
fn sse_events_split_across_reads_and_crlf_lines_are_whole() {
    let mut framer = funded_framer(Framing::Sse);
    assert!(framer.push(b"data: he").unwrap().is_empty());
    assert!(framer.push(b"llo\r\n").unwrap().is_empty());
    assert_eq!(texts(framer.push(b"\r\n").unwrap()), ["hello"]);
    assert_eq!(
        framer.finish().unwrap(),
        None,
        "an event no blank line ended is not one"
    );
}

#[test]
fn a_named_sse_event_other_than_message_keeps_its_name_for_the_plane() {
    let mut framer = funded_framer(Framing::Sse);
    let events = framer
        .push(b"event: endpoint\ndata: /messages?s=1\n\nevent: message\ndata: m\n\n")
        .unwrap();
    assert_eq!(texts(events), ["event: endpoint\ndata: /messages?s=1", "m"]);
}

#[test]
fn an_event_with_no_data_is_nothing() {
    let mut framer = funded_framer(Framing::Sse);
    assert!(framer.push(b"event: ping\n\n").unwrap().is_empty());
}

#[test]
fn a_message_that_never_ends_is_refused_not_buffered_without_bound() {
    let mut framer = funded_framer(Framing::Ndjson);
    assert_eq!(framer.push(&vec![b'x'; MAX_MESSAGE + 1]), Err(Overlong));
    let mut whole = funded_framer(Framing::None);
    assert_eq!(whole.push(&vec![b'x'; MAX_MESSAGE + 1]), Err(Overlong));
}

#[test]
fn completed_frames_keep_the_original_credit_until_the_last_alias_drops() {
    let process = super::budget::ChannelBudget::new();
    let unit = process.instance().unit();
    let mut framer = Framer::new(Framing::Ndjson, unit.storage()).unwrap();
    let mut input = b"one\ntwo\n".as_slice();
    let first = framer.feed(&mut input).unwrap().unwrap();
    assert_eq!(first.as_ref(), b"one");
    assert_eq!(input, b"two\n", "one completed frame at a time");
    let alias = first.clone();
    let charged = process.used().bytes;
    assert!(charged >= first.len());
    let second = framer.feed(&mut input).unwrap().unwrap();
    assert_eq!(second.as_ref(), b"two");
    drop((framer, first, second, unit));
    assert_eq!(process.used().bytes, charged);
    assert_eq!(alias.as_ref(), b"one");
    drop(alias);
    assert_eq!(process.used(), super::budget::Claim::default());
}

#[test]
fn framing_refuses_general_exhaustion_without_consuming_the_reply_reserve() {
    use super::budget::{ChannelBudget, Claim, REPLY_BYTES, UNIT_BYTES};
    let process = ChannelBudget::new();
    let unit = process.instance().unit();
    let held = unit
        .storage()
        .try_reserve(UNIT_BYTES - REPLY_BYTES)
        .unwrap();
    let mut framer = Framer::new(Framing::Ndjson, unit.storage()).unwrap();
    assert_eq!(framer.feed(&mut b"x\n".as_slice()), Err(Overlong));
    let protected = unit
        .reserve_reply(
            Claim {
                bytes: REPLY_BYTES,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(process.used().bytes, UNIT_BYTES);
    drop((held, protected, framer));
    assert_eq!(process.used(), Claim::default());
}
