// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTED BODY LEAVES THIS UNIT AS A HANDLE AND A COUNT, NEVER AS BYTES.
//!
//! This unit says of itself that it "reads no body", and until the outcome carried anything about
//! one that was easy to keep and impossible to check: the outcome described the answer — which
//! member, what the transport made of it, how many frames — and said nothing at all about what it
//! carried, so the money side had nothing to read and the plane's own tap was the only thing that
//! knew. Adding the body to the outcome is the moment that claim could have been broken, because
//! the obvious way to let the meter read a body is to hand it the body.
//!
//! It is not handed the body. It is handed the LEASE the stream is held under and the COUNT the
//! relay made while the frames went past. The cell below relays an answer far larger than the
//! per-unit arena and asserts both halves of that: the bytes are counted in full, and the number
//! is the only thing that comes back.

use busbar_contract::ARENA_BYTES;

use super::harness::{frame, Script};
use super::{member, Node};
use crate::ports::DestinationId;
use crate::wire::RouteOutcome;
use busbar_contract_transport::wire::StatusClass;

/// One frame of the scripted answer. Four of these is more than the arena.
fn chunk(n: usize) -> String {
    "x".repeat(n)
}

/// An answer bigger than the unit's own 4 KiB comes back as a count and a lease.
#[test]
fn the_relay_counts_a_body_the_unit_could_never_have_held() {
    let frame_bytes = 3 * 1024;
    let frames = 4;
    let total = (frame_bytes * frames) as u64;
    assert!(
        total > ARENA_BYTES as u64,
        "the cell is only worth anything if the answer could not have been buffered: \
         {total} against {ARENA_BYTES}"
    );

    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script(
        "a",
        Script::Frames(
            (0..frames)
                .map(|_| frame(Some(StatusClass::Success), &chunk(frame_bytes)))
                .collect(),
        ),
    );

    let outcome = node.route("primary");
    let RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("the answer is delivered: {outcome:?}");
    };

    assert_eq!(
        delivered.carried.bytes(),
        total,
        "every byte the relay saw go past is counted, and none of them is kept"
    );
    assert_eq!(
        delivered.carried.frames(),
        delivered.frames as u64,
        "the completion's frame count is the relay's own, not a second reading"
    );
    assert!(
        delivered.carried.dimensions().is_empty(),
        "a per-class dimension is the plane's declared locator over a decoded answer, and this \
         unit decodes none: it hands each frame to the plane's codec and counts"
    );
    assert_eq!(
        delivered.body.get(),
        0,
        "the body is NAMED — the stream of the connection the answer came back on — and the name \
         is the whole of what leaves here"
    );
}
