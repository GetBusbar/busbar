// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The lane cross-check, reached the way a request reaches it.
//!
//! The rule itself is asserted directly elsewhere. What is asserted HERE is that a dialled attempt
//! actually runs it: the check sits at the end of assembly, after the egress-auth unit has had the
//! envelope, and it is the last thing between a decorated request and the wire. A decoration that
//! moved the lane is a request re-priced onto somebody else's lane, and an attempt that assembled
//! without running the check would send it — every direct assertion about the rule still passing.
//!
//! So each test below drives a whole walk and reads what the client got: a lane the trust unit did
//! not seal ends the attempt before any byte leaves, and nothing is recorded against the
//! destination, because nothing was sent to it.

use super::harness::{ok_frames, Script};
use super::{member, Node};
use crate::wire::{KIND_API_ERROR, STATUS_INTERNAL_ERROR};
use busbar_contract::DestinationId;

/// A node whose envelope carries the lane in `host`, with one member on lane `a`.
fn lane_carrying_node() -> Node {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script("a", Script::Frames(ok_frames()));
    // The deployment reads the lane out of `host`, the plane writes it there, and the egress-auth
    // fixture knows the same field name.
    node.lane_field = Some("host");
    *node.plane.lane_field.lock().unwrap() = Some("host".to_string());
    *node.egress_auth.lane_field.lock().unwrap() = Some("host".to_string());
    node
}

/// The ordinary case: the decoration leaves the lane alone and the answer is delivered.
#[test]
fn a_decoration_that_leaves_the_lane_alone_reaches_the_upstream() {
    let node = lane_carrying_node();
    let outcome = node.route("primary");
    assert!(
        outcome.is_delivered(),
        "the envelope names the lane the trust unit sealed: {outcome:?}"
    );
    assert_eq!(
        node.transport.dialled.lock().unwrap().len(),
        1,
        "and it was dialled once"
    );
}

/// A decoration that MOVES the lane is refused before any byte leaves. This is the check the
/// attempt runs on the post-decoration request, and it is the whole reason the decoration is a
/// separate step rather than something the plane did on the way out.
#[test]
fn a_decoration_that_moves_the_lane_never_reaches_the_wire() {
    let node = lane_carrying_node();
    // The egress-auth unit rewrites the lane field to a lane the trust unit never sealed on this
    // destination — an attempt that skipped the cross-check would price the request on it.
    *node.egress_auth.rewrite_lane_to.lock().unwrap() = Some("somebody-elses-lane".to_string());

    let outcome = node.route("primary");
    let shed = outcome
        .shed()
        .expect("the attempt must not assemble a request onto a lane nobody sealed");
    assert_eq!(shed.status, STATUS_INTERNAL_ERROR);
    assert_eq!(shed.kind, KIND_API_ERROR);

    assert!(
        node.transport.written.lock().unwrap().is_empty(),
        "nothing may go on the wire once the lane fails to match the seal"
    );
    assert!(
        node.breaker
            .outcomes("primary", DestinationId::new(0))
            .is_empty(),
        "and nothing is recorded against a destination that was never sent to"
    );
}

/// The same refusal reached through a case difference — the exact bypass available to anyone who
/// could pick the capitalisation, since envelope field names are case-insensitive on the wire.
#[test]
fn the_check_is_not_escaped_by_the_capitalisation_of_the_field() {
    let mut node = lane_carrying_node();
    // The deployment spells the field one way; the plane writes it the other. A case-sensitive
    // check would find no field at all and wave the request through.
    node.lane_field = Some("HOST");

    *node.egress_auth.rewrite_lane_to.lock().unwrap() = Some("somebody-elses-lane".to_string());

    let outcome = node.route("primary");
    assert_eq!(
        outcome
            .shed()
            .expect("the differently-spelled field is the same field")
            .status,
        STATUS_INTERNAL_ERROR
    );
    assert!(node.transport.written.lock().unwrap().is_empty());
}

/// A deployment whose envelope carries no lane at all has nothing to cross-check, and the attempt
/// proceeds. The check is a rule about a named field, not a requirement that one exist.
#[test]
fn a_deployment_that_names_no_lane_field_has_nothing_to_check() {
    let mut node = lane_carrying_node();
    node.lane_field = None;
    // Even with the decoration moving the value, there is no field the deployment reads a lane out
    // of, so there is no lane to disagree about.
    *node.egress_auth.rewrite_lane_to.lock().unwrap() = Some("somebody-elses-lane".to_string());

    let outcome = node.route("primary");
    assert!(
        outcome.is_delivered(),
        "a deployment that names no lane field has no cross-check to fail: {outcome:?}"
    );
}
