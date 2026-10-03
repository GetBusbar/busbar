// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the pick costs per member.
//!
//! The weighted floor runs once per hop of every route walk, so anything it does per OFFERED MEMBER
//! is paid on the request path times pool membership. The pool name is a borrowed `&str` for the
//! whole walk, and there is no reason for a turn of the rotation to own a copy of it once per
//! member. This crate forbids unsafe, so the count cannot be taken with a counting allocator; what
//! is measured instead is the shape that decides it — how many keys carry a pool name at all.

use super::harness::{ok_frames, Script};
use super::{member, Node};
use busbar_kernel_egress::ports::DestinationId;

/// The request's own bytes are rendered once and handed to the wire where they lie.
///
/// The transport renders the envelope into the arena — that is what the arena is for, and it is the
/// only allocation the hot path is meant to make for these bytes. Copying them straight back out
/// into an owned buffer pays for the whole request body a second time on the money path and gives
/// the wire a buffer the arena never saw. The address is the proof: the same allocation is the same
/// address, and a copy is somewhere else.
#[test]
fn the_bytes_that_go_on_the_wire_are_the_arenas_own_and_not_a_copy_of_them() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script("a", Script::Frames(ok_frames()));

    assert!(node.route("primary").is_delivered());

    let encoded = node.transport.encoded_at.lock().unwrap().clone();
    let written = node.transport.written_at.lock().unwrap().clone();
    assert_eq!(encoded.len(), 1, "one envelope was rendered");
    assert_eq!(
        written, encoded,
        "the wire was handed the arena's own bytes rather than a second copy of them"
    );
}
