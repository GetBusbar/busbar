// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WALK HANDS BACK THE RELAY; IT DOES NOT RUN IT.
//!
//! ## What was there
//!
//! `deliver` ran the whole relay inside the attempt: it took the first frame and then looped on the
//! stream until the answer was over, so the walk could not return until the last frame had gone
//! past. The record's hold was therefore a hold over a body that was already drained, and "the hold
//! is not released when Route returns, so the Meter step in between reads a body that is still the
//! unit's" was true only because nothing could tell the difference.
//!
//! It also had no other choice. This crate has no runtime and must not grow one: the clock and the
//! sleep are ports precisely so a cell drives the whole unit on one thread with no timer wheel. A
//! relay the unit SPAWNED would be a unit that had learned how the node schedules.
//!
//! ## What is there now
//!
//! The walk answers with the answer's HEAD and a [`BodyPump`](crate::BodyPump) — the connection,
//! the stream, the permit and the budget guard, and the four borrowed seams the loop reads. It is
//! an ordinary future and it names no runtime, exactly as the walk itself does not; the ROOT drives
//! it, because the root is what already owns the transport runtime the frames are arriving on.
//!
//! Two cells below state the pair of facts that makes the hold mean something:
//!
//!   * the walk RETURNS with the body undrained — the delivered answer's count is zero frames and
//!     zero bytes, and the pump is there;
//!   * and the completion the meter reads afterwards is the whole answer, every byte of it.
//!
//! ## And what the plane fills
//!
//! A completion carries what the answer was worth PER DIMENSION THE PLANE DECLARED, and until now
//! that list was always empty. It was empty for a good reason — this unit reads no body — and the
//! answer is not to make it read one: the plane hands back a decoded `Response` on every frame, and
//! `Plane::meter` is a pure function of exactly that value. So the plane's own declared locators
//! are evaluated over the plane's own decoded answer, on the record's context, at the one instant
//! both exist. The unit holds a value the plane made and asks the plane what is in it.
//!
//! RED at this base, and every error is the finding:
//!
//!   no method named `route_head_and_pump` found for struct `Node` in the current scope
//!   no method named `route_and_drain` found for struct `Node` in the current scope
//!   no method named `report_usage` found for struct `Arc<harness::TestPlane>` in the current scope
//!   no method named `head` found for reference `&Delivered` in the current scope
//!
//! There is no relay this unit can hand back, so there is no instant at which a body is held and
//! undrained, and there is no way for a plane's four declared dimensions to reach a meter.

use busbar_caps::MeterClassId;
use busbar_contract::{FinishClass, StatusAt};
use busbar_contract_transport::wire::StatusClass;

use super::harness::{frame, Script};
use super::{member, Node};
use crate::ports::DestinationId;
use crate::wire::RouteOutcome;

/// One frame of the scripted answer.
fn chunk(n: usize) -> String {
    "x".repeat(n)
}

/// THE WALK RETURNS BEFORE THE BODY IS DRAINED, AND THE METER STILL READS THE WHOLE ANSWER.
///
/// Both halves in one cell, because either on its own is satisfiable by the wrong thing: a walk
/// that returns early and loses the rest of the answer would pass the first, and the shape that was
/// there passed the second.
#[test]
fn the_walk_returns_undrained_and_the_completion_is_still_whole() {
    let frame_bytes = 3 * 1024;
    let frames = 4;
    let total = (frame_bytes * frames) as u64;

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

    node.route_head_and_pump("primary", |outcome, pump| {
        let RouteOutcome::Delivered(delivered) = &outcome else {
            panic!("the answer is delivered: {outcome:?}");
        };
        assert_eq!(
            delivered.carried.bytes(),
            0,
            "THE WALK HAS RETURNED AND NOTHING HAS BEEN RELAYED YET. A count here would mean the \
             walk had drained the body before answering, which is the shape this cell replaced"
        );
        assert_eq!(delivered.carried.frames(), 0);
        let lease = delivered.body;

        let pump = pump.expect("a delivered answer leaves a relay behind it for the root to drive");
        let carried = crate::race::block_on(pump.drain());

        assert_eq!(
            carried.bytes(),
            total,
            "and once the root has driven the pump, every byte the relay saw is counted"
        );
        assert_eq!(carried.frames(), frames as u64);
        assert_eq!(
            lease.get(),
            0,
            "the body is NAMED across the whole of it — one lease, before the pump and after"
        );
    });
}

/// THE PLANE'S FOUR DECLARED DIMENSIONS REACH THE COMPLETION AS FOUR NUMBERS.
///
/// The unit does not read them off the body. It hands each frame to the plane's codec, and where
/// the codec answers with a decoded response it asks the plane's own metering face what that
/// response was worth — in the plane's own declared classes, as quantities and never as an amount.
#[test]
fn the_plane_fills_every_dimension_it_declared() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.plane.report_usage(vec![
        (MeterClassId::new("tokens_in"), 11),
        (MeterClassId::new("tokens_out"), 7),
        (MeterClassId::new("cache_read"), 512),
        (MeterClassId::new("cache_write"), 64),
    ]);
    node.transport.script(
        "a",
        Script::Frames(vec![
            frame(Some(StatusClass::Success), "hello"),
            frame(None, "end"),
        ]),
    );

    let carried = node.route_and_drain("primary").1;
    let seen: Vec<(MeterClassId, u64)> = carried
        .dimensions()
        .iter()
        .map(|d| (d.class, d.units))
        .collect();
    assert_eq!(
        seen,
        vec![
            (MeterClassId::new("tokens_in"), 11),
            (MeterClassId::new("tokens_out"), 7),
            (MeterClassId::new("cache_read"), 512),
            (MeterClassId::new("cache_write"), 64),
        ],
        "four declared classes, four quantities, in the plane's own declaration order"
    );
}

/// THE MUTATION: a plane that reads one dimension short is one number short at the meter.
#[test]
fn a_plane_that_reads_one_dimension_short_reaches_the_meter_short() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.plane.report_usage(vec![
        (MeterClassId::new("tokens_in"), 11),
        (MeterClassId::new("tokens_out"), 7),
        (MeterClassId::new("cache_write"), 64),
    ]);
    node.transport.script(
        "a",
        Script::Frames(vec![
            frame(Some(StatusClass::Success), "hello"),
            frame(None, "end"),
        ]),
    );

    let carried = node.route_and_drain("primary").1;
    assert_eq!(carried.dimensions().len(), 3);
    assert!(
        carried
            .dimensions()
            .iter()
            .all(|d| d.class != MeterClassId::new("cache_read")),
        "the missing dimension is absent rather than zero, which is a different statement and the \
         one a price can tell apart"
    );
}

/// A PLANE THAT DECLARES NOTHING FILLS NOTHING, and the unit is unbothered.
///
/// The control plane declares no meter classes at all. A relay that invented a line for it would be
/// a relay that had decided what an administrative verb is worth.
#[test]
fn a_plane_that_declares_no_dimensions_reports_none() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport
        .script("a", Script::Frames(vec![frame(None, "end")]));
    let carried = node.route_and_drain("primary").1;
    assert!(carried.dimensions().is_empty());
}

/// THE SECOND SOURCE IS REAL: a mid-stream cut has a SUCCESS status and an ERROR finish.
///
/// This is the case the kernel's dispute arm exists for, and until the delivered answer carried the
/// plane's own reading of the body it was unreachable on every plane at once: every leg derived the
/// finish from the status, so the two sources were one source and could not disagree.
///
/// The head that comes off the walk here disagrees with itself in the only way that matters. The
/// transport read `Success` off the first frame — the client saw a 200 and got part of an answer —
/// and the plane read an error envelope off a later frame, which is what a real upstream sends when
/// it gives up half way through a stream it has already committed to.
#[test]
fn a_mid_stream_cut_gives_the_head_two_sources_that_disagree() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script(
        "a",
        Script::Frames(vec![
            frame(Some(StatusClass::Success), "hello"),
            frame(None, "cut"),
        ]),
    );

    let (outcome, _) = node.route_and_drain("primary");
    let RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("the client saw the answer start: {outcome:?}");
    };
    let head = delivered.head(Some(StatusAt::FirstFrame));
    assert_eq!(
        head.status,
        Some(StatusClass::Success),
        "the transport's own reading of the frame the client saw"
    );
    assert_eq!(
        head.finish,
        Some(FinishClass::Error),
        "and the PLANE's own reading of how the answer ended, which is not that number classified"
    );
    assert!(head.delivered, "the client has part of the answer");
    assert_ne!(
        head.finish.map(|f| f != FinishClass::Error),
        head.status.map(|s| s == StatusClass::Success),
        "two sources, one each, disagreeing — which is the whole of what makes the kernel's \
         dispute arm reachable"
    );
}

/// A WHOLE ANSWER'S TWO SOURCES AGREE, so the cell above reads the disagreement and not the
/// presence of a finish.
#[test]
fn a_whole_answer_gives_the_head_two_sources_that_agree() {
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.transport.script(
        "a",
        Script::Frames(vec![
            frame(Some(StatusClass::Success), "hello"),
            frame(None, "end"),
        ]),
    );
    let (outcome, _) = node.route_and_drain("primary");
    let RouteOutcome::Delivered(delivered) = &outcome else {
        panic!("delivered: {outcome:?}");
    };
    let head = delivered.head(Some(StatusAt::FirstFrame));
    assert_eq!(head.status, Some(StatusClass::Success));
    assert_eq!(head.finish, Some(FinishClass::Complete));
}
