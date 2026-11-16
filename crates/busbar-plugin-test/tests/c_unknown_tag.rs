// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNKNOWN-TAG (ABI-MIN3-INTERFACE §14): an unknown or retired tag reaches the positional decoder unchanged and
//! is FAULT UnknownTag there. The reader arm is W1-A1's (merged); the decoder arm is the host's answer parse.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::records::Records;

/// A record by hand: head (tag, reserved 0, len), body, zero padding to 8.
fn record(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&tag.to_ne_bytes());
    bytes.extend_from_slice(&0u16.to_ne_bytes());
    let len = u32::try_from(body.len()).expect("small body");
    bytes.extend_from_slice(&len.to_ne_bytes());
    bytes.extend_from_slice(body);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes
}

#[test]
fn the_reader_hands_retired_and_unknown_tags_through() {
    let mut bytes = record(0x000A, b"");
    bytes.extend(record(0x01FF, b"abc"));
    let recs: Vec<_> = Records::new(&bytes)
        .collect::<Result<_, _>>()
        .expect("framing is sound");
    assert_eq!(recs.len(), 2);
    assert_eq!((recs[0].tag, recs[0].body), (0x000A, &b""[..]));
    assert_eq!((recs[1].tag, recs[1].body), (0x01FF, &b"abc"[..]));
}

/// The host's answer parse is the positional decoder of the generic layer: a retired tag (0x000A), an undefined
/// generic tag, a tag above the kind range, ERROR outside a FAIL tail and a TOKEN that is not first are FAULT
/// UnknownTag; a kind tag passes to the kind decoder.
#[test]
fn the_positional_decoder_answers_fault_unknown_tag() {
    use busbar_plugin_abi::fail::FaultReason;
    use busbar_plugin_abi::host::Answer;
    use busbar_plugin_abi::records::tag;
    use busbar_plugin_abi::types::Status;

    for bad in [
        0x000A,
        0x0099,
        0x0200,
        tag::ERROR,
        tag::NEED,
        tag::NEED_RES,
        tag::FAIL,
    ] {
        let mut bytes = record(tag::TEXT, b"x");
        bytes.extend(record(bad, &[0; 8]));
        assert_eq!(
            Answer::parse(Status::OK, &bytes).err(),
            Some(FaultReason::UnknownTag(bad)),
            "{bad:#06x}"
        );
    }
    let mut late_token = record(tag::TEXT, b"x");
    late_token.extend(record(tag::TOKEN, &7u64.to_ne_bytes()));
    assert_eq!(
        Answer::parse(Status::OK, &late_token).err(),
        Some(FaultReason::UnknownTag(tag::TOKEN))
    );
    let kind = record(0x01FF, b"abc");
    let answer = Answer::parse(Status::OK, &kind).expect("kind tags are the kind decoder's");
    assert_eq!(answer.records().count(), 1);
}
