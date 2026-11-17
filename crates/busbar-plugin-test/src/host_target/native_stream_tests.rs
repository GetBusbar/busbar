// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::transport::{MSG_BINARY, MSG_FIN, MSG_TEXT};

#[test]
fn native_upgrade_preserves_coalesced_leftover_after_bodyless_framing() {
    for length in ["", "Content-Length: 0\r\n", "Content-Length: 000\r\n"] {
        let input = format!("GET /echo HTTP/1.1\r\nHost: peer.test\r\n{length}\r\n");
        let mut bytes = input.as_bytes().to_vec();
        bytes.extend_from_slice(b"\x81\x00");
        let (head, used) = upgrade_head(&bytes, 16).unwrap().unwrap();
        assert_eq!(&bytes[used..], b"\x81\x00");
        assert!(!head.as_bytes().is_empty());
        assert!(upgrade_head(&bytes[..input.len() - 1], 16)
            .unwrap()
            .is_none());
    }
}

#[test]
fn native_upgrade_rejects_body_framing_before_any_body_arrives() {
    for framing in [
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length: 0\r\nContent-Length: 1\r\n",
        "Content-Length: +0\r\n",
        "Content-Length: 0,0\r\n",
        "Content-Length: \r\n",
        "Content-Length: x\r\n",
    ] {
        let bytes = format!("GET /echo HTTP/1.1\r\nHost: peer.test\r\n{framing}\r\n");
        assert!(upgrade_head(bytes.as_bytes(), 16).is_err(), "{framing}");
    }
}

#[test]
fn native_message_echo_preserves_kind_fin_fragments_and_empty_messages() {
    for kind in [MSG_TEXT, MSG_BINARY] {
        let mut state = EchoState::new(2, 3, 32);
        state.body(7, kind, b"ab").unwrap();
        assert_eq!(state.next(), None);
        state.body(7, kind | MSG_FIN, b"cd").unwrap();
        assert_eq!(
            state.next(),
            Some(Message {
                stream: 7,
                flags: kind | MSG_FIN,
                bytes: b"abcd".to_vec()
            })
        );
        state.body(7, kind | MSG_FIN, b"").unwrap();
        assert_eq!(state.next().unwrap().bytes, b"");
    }
}

#[test]
fn native_message_subject_refuses_byte_streams_and_fragment_kind_changes() {
    let mut state = EchoState::new(2, 3, 32);
    assert_eq!(state.body(7, 0, b"body"), Err(Failure::UnsupportedBodyMode));
    state.body(7, MSG_TEXT, b"first").unwrap();
    assert_eq!(
        state.body(7, MSG_BINARY | MSG_FIN, b"second"),
        Err(Failure::Shape)
    );
}

#[test]
fn native_full_consumes_current_message_and_never_replays_it() {
    let mut state = EchoState::new(2, 3, 32);
    state.body(7, MSG_BINARY | MSG_FIN, b"first").unwrap();
    assert_eq!(state.next().unwrap().bytes, b"first");
    state.full(7).unwrap();
    state.body(7, MSG_BINARY | MSG_FIN, b"next").unwrap();
    assert_eq!(state.next(), None);
    state.writable(7);
    assert_eq!(state.next().unwrap().bytes, b"next");
    assert_eq!(state.next(), None);
}

#[test]
fn native_empty_messages_and_zero_byte_streams_have_finite_object_bounds() {
    let mut state = EchoState::new(2, 2, 32);
    state.body(7, MSG_TEXT | MSG_FIN, b"one").unwrap();
    state.next().unwrap();
    state.full(7).unwrap();
    state.body(7, MSG_TEXT | MSG_FIN, b"").unwrap();
    state.body(7, MSG_TEXT | MSG_FIN, b"").unwrap();
    assert_eq!(state.body(7, MSG_TEXT | MSG_FIN, b""), Err(Failure::Limit));
    state.end(7);
    state.body(8, MSG_TEXT, b"").unwrap();
    state.body(9, MSG_TEXT, b"").unwrap();
    assert_eq!(state.body(10, MSG_TEXT, b""), Err(Failure::Limit));
}

#[test]
fn native_callback_budget_counts_empty_records_before_copying() {
    let mut batch = Batch::default();
    batch.capture(TransportOut::Write(b""), 2, 32);
    batch.capture(TransportOut::Write(b""), 2, 32);
    assert_eq!(batch.failure, None);
    batch.capture(TransportOut::Write(b""), 2, 32);
    assert_eq!(batch.failure, Some(Failure::Limit));
}
