// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A request body is bounded by its BYTES, and by nothing else.
//!
//! The frame ceiling (`MAX_NEEDMORE_FRAMES`) bounds a session-transport HANDSHAKE: a peer that
//! answers "not a whole frame yet" forever holds a session slot, so the run of consecutive "not
//! yet" answers is refused at the ceiling. A request body arriving in many chunks looks the same
//! from a distance, and the two have been confused before -- which is what makes the claim worth a
//! test rather than a doc comment.
//!
//! The claim has two halves and this file drives both against the SHIPPED path:
//!
//!   1. On `http` and `sse` the frame ceiling is not merely un-hit, it is UNREACHABLE. Both
//!      transports declare `SESSION = false`, so the pump is handed no session slot, and the run of
//!      "not yet" answers is a property of a session slot: with none, `ask_again` is false whatever
//!      the count. Driven here well past the ceiling on both transports.
//!   2. What DOES bound the body is the operator's `limits.request_body_max_bytes`, counted in
//!      actual bytes against the node's spill budget, and it refuses at the same byte however the
//!      bytes were split -- one chunk, or many thousands more chunks than the frame ceiling.

use busbar_caps::ReasonCode;
use busbar_contract::transport::TransportMeta;
use busbar_kernel::grammar::DeepestPointer;
use busbar_kernel::inflight::InFlight;
use busbar_kernel::pump::{
    BodySpool, Direction, Dispatch, Scheduler, Shape, SpillBudget, StreamId, MAX_NEEDMORE_FRAMES,
};
use busbar_substrate::config::limits::{
    DEFAULT_REQUEST_BODY_MAX_BYTES, REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR,
};
use busbar_transport_http::HttpTransport;
use busbar_transport_sse::SseTransport;

/// The knob the binding names, at the values it names them.
#[test]
fn the_body_cap_is_the_operators_and_its_default_and_ceiling_are_the_documented_ones() {
    assert_eq!(
        DEFAULT_REQUEST_BODY_MAX_BYTES,
        32 * 1024 * 1024,
        "default 32 MiB"
    );
    assert_eq!(
        REQUEST_BODY_MAX_BYTES_CEIL,
        1024 * 1024 * 1024,
        "ceiling 1 GiB"
    );
    const { assert!(REQUEST_BODY_MAX_BYTES_FLOOR < DEFAULT_REQUEST_BODY_MAX_BYTES) };
}

/// Neither shipped one-shot transport carries a session, so neither can reach the frame ceiling.
///
/// This is the structural half. `Scheduler::ask_again` keeps the run of consecutive "not yet"
/// answers ON THE SESSION SLOT; a transport that declares `SESSION = false` is dispatched with
/// `None` and the run does not exist to be counted. The assertion is on the shipped transports'
/// own declarations, so a transport that grows a session tomorrow turns this red rather than
/// silently acquiring a cap on its bodies.
#[test]
fn the_frame_ceiling_is_unreachable_on_the_two_transports_that_carry_no_session() {
    // A compile-time assertion, because the fact is a compile-time one: a transport that grows a
    // session tomorrow does not fail this run, it fails the build.
    const {
        assert!(
            !<HttpTransport as TransportMeta>::SESSION,
            "http carries no session"
        )
    };
    const {
        assert!(
            !<SseTransport as TransportMeta>::SESSION,
            "sse carries no session"
        )
    };

    let table = InFlight::new(8, 0);
    let scheduler = Scheduler::default();

    // Four times the ceiling, on the stream each transport would use, with no session in hand.
    for transport in [
        <HttpTransport as TransportMeta>::KEY,
        <SseTransport as TransportMeta>::KEY,
    ] {
        for frame in 0..(MAX_NEEDMORE_FRAMES * 4) {
            let verdict = scheduler.dispatch(
                None,
                &table,
                StreamId(1),
                Direction::Inbound,
                Shape::NeedMore,
            );
            assert_eq!(
                verdict,
                Dispatch::Wait,
                "{transport}: frame {frame} past a ceiling of {MAX_NEEDMORE_FRAMES} still waits",
            );
        }
    }
}

/// The body's one refusal is the byte cap, and it lands on the same byte at any chunk count.
///
/// Driven twice over the SAME cap: once in a single chunk, once in single-byte chunks -- far more
/// chunks than `MAX_NEEDMORE_FRAMES`, so a frame-count bound applied to spooling would fire long
/// before the byte cap does. Both runs refuse on the byte after the cap, with the spill-budget
/// reason and never the stall reason, and both have spooled exactly the cap when they do.
#[test]
fn a_body_is_refused_at_request_body_max_bytes_whatever_its_chunk_count() {
    // The operator's floor stands in for the configured cap: it is a real, settable value of
    // `limits.request_body_max_bytes` and it is thousands of chunks past the frame ceiling.
    let cap = REQUEST_BODY_MAX_BYTES_FLOOR;
    assert!(
        cap > MAX_NEEDMORE_FRAMES,
        "the cap has to be past the frame ceiling for this to prove anything"
    );

    // One chunk of exactly the cap: accepted. The chunk after it: refused.
    let budget = SpillBudget::new(cap);
    let mut whole = BodySpool::new(None, DeepestPointer::EndOfBody);
    whole
        .push(&vec![b'x'; cap], &budget)
        .expect("a body of exactly the cap is accepted");
    assert_eq!(whole.len(), cap);
    assert_eq!(whole.push(b"x", &budget), Err(ReasonCode::SpillBudget));
    whole.release(&budget);
    assert_eq!(budget.used(), 0);

    // The same cap, one byte per chunk. 65,536 chunks is 256 times the frame ceiling.
    let budget = SpillBudget::new(cap);
    let mut dribbled = BodySpool::new(None, DeepestPointer::EndOfBody);
    for byte in 0..cap {
        assert_eq!(
            dribbled.push(b"x", &budget),
            Ok(()),
            "chunk {byte} of {cap} is accepted; the chunk COUNT bounds nothing",
        );
    }
    assert_eq!(dribbled.len(), cap, "the same bytes as the single chunk");
    assert_eq!(
        dribbled.push(b"x", &budget),
        Err(ReasonCode::SpillBudget),
        "the refusal is the byte budget, on the same byte, and never ReasonCode::Stalled",
    );
    dribbled.release(&budget);
    assert_eq!(budget.used(), 0);
}
