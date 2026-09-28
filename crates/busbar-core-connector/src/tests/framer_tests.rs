// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host side of a framer: a full sink is re-called with no new bytes until every byte is out,
//! once and in order; a deadline and the end are carried; `locate` and `encode` answer.

use std::sync::Arc;

use busbar_contract::abi::transport::SIDE_DIAL;

use super::*;
use crate::support::{Knobs, TestDoor};

#[test]
fn a_full_sink_is_re_called_until_every_byte_is_out() {
    let door = Arc::new(TestDoor::identity("bytes"));
    let (mut f, _) = Framing::begin(door.clone(), SIDE_DIAL, "t", &Established::default()).unwrap();
    f.bufs = Buffers::new(7, 5, 1);
    let sent: Vec<u8> = (0..200).collect();
    let y = f.emit(1, &sent, true).unwrap();
    assert_eq!(y.wire, sent);
    let y = f.ingest(&sent, true).unwrap();
    let got: Vec<u8> = y.pieces.iter().flat_map(|p| p.bytes.clone()).collect();
    assert_eq!(got, sent);
    assert!(y.pieces.last().unwrap().end_of_frame);
    assert!(y.ended);
    assert!(door.count("ingest") > 1, "re-called while it owed more");
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
