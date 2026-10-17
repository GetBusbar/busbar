// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host side of a framer: a full sink is re-called with no new bytes until every byte is out,
//! once and in order; a deadline and the end are carried; `locate` and `encode` answer.

use std::sync::Arc;

use busbar_contract::abi::transport::{SIDE_ACCEPT, SIDE_DIAL};

use super::*;
use crate::support::{Knobs, TestDoor};

#[test]
fn a_full_sink_is_re_called_until_every_byte_is_out() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
    f.bufs = Buffers::new(7, 5, 1);
    let sent: Vec<u8> = (0..200).collect();
    let y = f.emit(1, &sent, true, false).unwrap();
    assert_eq!(y.wire, sent);
    let y = f.ingest(&sent, true).unwrap();
    let got: Vec<u8> = y.pieces.iter().flat_map(|p| p.bytes.clone()).collect();
    assert_eq!(got, sent);
    assert!(y.pieces.last().unwrap().end_of_frame);
    assert!(y.ended);
    assert!(door.count("ingest") > 1, "re-called while it owed more");
}

/// WS-DIAL (ARCHITECT Q-L5B-WS-DIAL 2026-10-03): a dialled framing's `begin` is handed the dial's
/// opening head fields (`BeginIn::fields`), in order; a framing begun without any hands none.
#[test]
fn a_dial_hands_its_opening_head_fields_to_begin() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let opening = vec![
        ("authorization".to_string(), b"Bearer k".to_vec()),
        ("x-mode".to_string(), b"realtime".to_vec()),
    ];
    let _ = Framing::begin_with(
        door.clone(),
        SIDE_DIAL,
        "t",
        &Established::default(),
        &opening,
    )
    .unwrap();
    let _ = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
    let begun = door.begun_fields.lock().unwrap();
    assert_eq!(
        *begun,
        vec![
            vec![
                (b"authorization".to_vec(), b"Bearer k".to_vec()),
                (b"x-mode".to_vec(), b"realtime".to_vec()),
            ],
            Vec::new(),
        ]
    );
}

/// RED (C19-TAIL U5): a piece the framer states as text (`PIECE_TEXT`) is read up as text; one it
/// does not is binary.
#[test]
fn a_text_piece_is_read_as_text() {
    for text in [true, false] {
        let door = Arc::new(TestDoor::new(
            "ws",
            &["ws"],
            &[],
            Knobs {
                text,
                ..Knobs::default()
            },
        ));
        let (mut f, _) = Framing::begin(door, SIDE_DIAL, "t", &Established::default()).unwrap();
        let y = f.ingest(b"{}", false).unwrap();
        assert_eq!(y.pieces.len(), 1);
        assert_eq!(y.pieces[0].text, text, "stated text={text}");
    }
}

#[test]
fn a_refusals_neutral_status_reaches_the_framer_on_every_re_call() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
    f.bufs = Buffers::new(7, 5, 1);
    let sent: Vec<u8> = (0..200).collect();
    let y = f.refuse(Some(1), &sent, 401).unwrap();
    assert_eq!(y.wire, sent);
    let statuses = door.refused_statuses.lock().unwrap().clone();
    assert!(statuses.len() > 1, "re-called while it owed more");
    assert!(statuses.iter().all(|s| *s == 401), "{statuses:?}");
}

#[test]
fn a_stated_deadline_is_carried() {
    let door = Arc::new(TestDoor::new(
        "bytes",
        &["bytes"],
        &[],
        Knobs {
            silence: Some(std::time::Duration::from_secs(1)),
            ..Knobs::default()
        },
    ));
    let (_, y) = Framing::begin(door, SIDE_DIAL, "t", &Established::default()).unwrap();
    let at = y.deadline_ns.expect("a deadline");
    assert!(at > now_ns());
}

#[test]
fn locate_and_encode_answer() {
    let door = TestDoor::new(
        "sec",
        &["sec"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            ..Knobs::default()
        },
    );
    let l = locate(&door, "127.0.0.1:443").unwrap();
    assert_eq!(l.authority, "127.0.0.1:443");
    assert_eq!(l.name.as_deref(), Some("localhost"));
    assert!(l.secure);
    assert_eq!(encode(&door, &[], b"body").unwrap(), b"body");
}

/// RED: a framer that offers protocols for a secured target is located: the host gives its offer a
/// buffer (a framer answering short for want of one never located an https target).
#[test]
fn a_framer_offering_protocols_for_a_secured_target_is_located() {
    let door = TestDoor::new(
        "sec",
        &["sec"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            offer: Some(b"\x02h2\x08http/1.1"),
            ..Knobs::default()
        },
    );
    let l = locate(&door, "127.0.0.1:443").expect("located");
    assert_eq!(l.authority, "127.0.0.1:443");
    assert!(l.secure);
}

/// RED: an ACCEPTED framing's head slots come out typed (method, target, an absent authority),
/// never as field lines; the same request slots on a DIALLED framing are the other side's, and
/// refused.
#[test]
fn an_accepted_framing_yields_its_request_head_typed() {
    let knobs = Knobs {
        head: true,
        ..Knobs::default()
    };
    let door = Arc::new(TestDoor::new("bytes", &["bytes"], &[], knobs));
    let (_, y) = Framing::begin(door.clone(), SIDE_ACCEPT, "", &Established::default()).unwrap();
    assert_eq!(
        y.heads,
        [Head {
            stream: 1,
            method: Some(b"GET".to_vec()),
            target: Some(b"/v1".to_vec()),
            ..Head::default()
        }]
    );
    let dialled = Framing::begin(door, SIDE_DIAL, "t", &Established::default());
    assert!(
        dialled.is_err(),
        "a dialled framing carries no request slots"
    );
}

/// RED: the host reassembles a stream's field block and never takes PIECE_CONTINUED on the framer's
/// word. A line ended with CR LF then a "continued" `:path` is a smuggled pseudo-field, refused; a
/// continued piece with nothing before it is refused; a continuation inside a name is refused.
#[test]
fn a_continued_field_piece_is_judged_by_the_host_not_the_framer() {
    let mut l = FieldLines::default();
    assert_eq!(l.piece(1, false, false, b"x: y\r\n"), Ok(()));
    assert!(
        l.piece(1, true, true, b":path: /admin\r\n").is_err(),
        "smuggle"
    );
    let mut l = FieldLines::default();
    assert!(l.piece(1, true, true, b"rest\r\n").is_err(), "orphan");
    let mut l = FieldLines::default();
    assert_eq!(l.piece(1, false, false, b"x-lo"), Ok(()));
    assert!(
        l.piece(1, true, true, b"ng: v\r\n").is_err(),
        "inside a name"
    );
    let mut l = FieldLines::default();
    assert!(
        l.piece(1, false, true, b":path: /\r\n").is_err(),
        "pseudo-field"
    );
    assert!(
        l.piece(2, false, true, b"x: 1\r").is_err(),
        "ends inside a line"
    );
}

/// A long value split across pieces reassembles byte-identically, and the stream's next block
/// starts clean.
#[test]
fn a_long_value_split_across_pieces_reassembles_byte_identically() {
    let block = b"x-long: abcdefghij\r\nx-b: 2\r\n";
    let mut l = FieldLines::default();
    let parts: [(&[u8], bool, bool); 4] = [
        (&block[..10], false, false),
        (&block[10..18], true, false),
        (&block[18..19], true, false),
        (&block[19..], true, true),
    ];
    let mut joined = Vec::new();
    for (bytes, continued, end) in parts {
        assert_eq!(l.piece(7, continued, end, bytes), Ok(()));
        joined.extend_from_slice(bytes);
    }
    assert_eq!(joined, block);
    assert_eq!(
        l.piece(7, false, true, b""),
        Ok(()),
        "an empty block after it"
    );
}

/// RED: a payload piece inside a stream's open field block is refused; a failed stream drops its
/// open block, so its state does not outlive it (and the same stream id may start clean).
#[test]
fn a_payload_piece_inside_an_open_block_is_refused_and_a_failure_drops_the_block() {
    let fields = |continued, end| FieldPiece::Fields { continued, end };
    let mut l = FieldLines::default();
    assert_eq!(l.take(3, fields(false, false), b"x: y\r\n"), Ok(()));
    assert!(
        l.take(3, FieldPiece::Payload, b"body").is_err(),
        "payload inside"
    );
    assert_eq!(
        l.take(4, FieldPiece::Payload, b"body"),
        Ok(()),
        "another stream"
    );
    assert_eq!(l.take(3, fields(false, false), b"x-lo"), Ok(()));
    assert_eq!(l.take(3, FieldPiece::Failed, b"reset"), Ok(()));
    assert!(l.open.is_empty(), "the failed stream's block is gone");
    assert_eq!(l.take(3, fields(false, true), b"a: b\r\n"), Ok(()));
    assert_eq!(l.take(3, FieldPiece::Payload, b"body"), Ok(()));
}
