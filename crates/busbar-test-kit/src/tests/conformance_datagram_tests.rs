// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATAGRAM FRAMER'S SCRIPT (`conformance/datagram.rs`): an honest answer reads as the line the
//! contract requires, and a datagram framer that misbehaves fails the script — an answer the
//! lane's rules refuse, an opening that does not hold what its inputs declare, a `begin` that reads
//! no lane, a `finish` that does not end.

use super::*;
use crate::conformance::{judge as contract, output, Step};

fn called(outcome: Outcome) -> Called {
    Called {
        outcome,
        error: None,
        lease: 0,
        recall: None,
    }
}

/// An answer yielding `piece` (its bytes and flags, on stream 0) as `h`'s frame, `routes` routes,
/// the yield `flags` and the terms' `role`.
fn answer(
    h: &mut Host,
    piece: Option<(&[u8], u16)>,
    routes: u32,
    flags: u32,
    role: u32,
) -> FramerOut {
    let mut o: FramerOut = output();
    if let Some((bytes, piece_flags)) = piece {
        h.sink.frame[..bytes.len()].copy_from_slice(bytes);
        h.sink.pieces[0].stream = 0;
        h.sink.pieces[0].offset = 0;
        h.sink.pieces[0].len = bytes.len() as u64;
        h.sink.pieces[0].flags = piece_flags;
        o.yielded.pieces_len = 1;
        o.yielded.frame_len = bytes.len() as u64;
    }
    if routes != 0 {
        h.sink.wire[0] = 1;
        h.routes[0] = DatagramRoute {
            offset: 0,
            len: 1,
            path: 1,
            lane: busbar_contract::abi::transport::LANE_CLEAR,
        };
        o.yielded.wire_len = 1;
    }
    o.datagram.routes_len = routes;
    o.yielded.flags = flags;
    o.datagram.terms.role = role;
    o
}

fn begun(h: &Host, c: &Called, o: &FramerOut, contains: &[Vec<u8>]) -> String {
    format!(
        "{} framing={} {}",
        crate::conformance::called(c),
        true,
        h.yielded(c, o, contains)
    )
}

const OFFER: &[u8] = b"an opening description: address 198.51.100.1 40000";

fn contains() -> Vec<Vec<u8>> {
    vec![b"opening".to_vec(), b"198.51.100.1 40000".to_vec()]
}

/// GREEN: a dialled begin that yields one end-of-frame piece holding every declared string, and
/// routes nothing, reads as the line the contract requires.
#[test]
fn an_honest_dialled_begin_reads_as_the_required_line() {
    let mut h = Host::new();
    let flags = PIECE_END_OF_FRAME | PIECE_TEXT;
    let o = answer(&mut h, Some((OFFER, flags)), 0, 0, HANDSHAKE_NONE);
    let c = called(Outcome::Ready);
    assert_eq!(
        begun(&h, &c, &o, &contains()),
        ready_line(Some(true), &[described(flags)], 0, HANDSHAKE_NONE)
    );
}

/// RED: an opening that does not hold what the inputs declare is not the required line.
#[test]
fn an_opening_missing_a_declared_string_is_refused() {
    let mut h = Host::new();
    let flags = PIECE_END_OF_FRAME;
    let o = answer(
        &mut h,
        Some((b"an opening, elsewhere", flags)),
        0,
        0,
        HANDSHAKE_NONE,
    );
    let c = called(Outcome::Ready);
    assert_ne!(
        begun(&h, &c, &o, &contains()),
        ready_line(Some(true), &[described(flags)], 0, HANDSHAKE_NONE)
    );
}

/// RED: a FAILED answer that still routes a datagram breaks the lane's rules, and the line says so.
#[test]
fn a_failed_answer_that_routes_breaks_the_lane() {
    let mut h = Host::new();
    let o = answer(&mut h, None, 1, 0, HANDSHAKE_NONE);
    let line = h.yielded(&called(Outcome::Failed), &o, &[]);
    assert!(!line.starts_with("lane=ok"), "{line}");
}

/// RED: rendezvous terms that name a role and carry no credentials break the lane's rules.
#[test]
fn half_stated_terms_break_the_lane() {
    let mut h = Host::new();
    let flags = PIECE_END_OF_FRAME;
    let o = answer(&mut h, Some((OFFER, flags)), 0, 0, HANDSHAKE_ANSWERS);
    let line = h.yielded(&called(Outcome::Ready), &o, &[]);
    assert!(!line.starts_with("lane=ok"), "{line}");
}

fn step(label: &str, answer: String) -> Vec<Step> {
    vec![Step {
        label: label.into(),
        answer,
        crossed: 1,
        pinned: 1,
        resumes: 0,
    }]
}

/// RED: a datagram framer that begins without a lane fails the script.
#[test]
#[should_panic(expected = "begin without a lane")]
fn a_begin_that_reads_no_lane_fails_the_script() {
    let want = vec![("begin without a lane".to_owned(), Want::Starts("Failed "))];
    contract(
        &step(
            "begin without a lane",
            ready_line(Some(true), &[], 0, HANDSHAKE_NONE),
        ),
        &want,
    );
}

/// RED: a `finish` that does not end the framing fails the script; the one that ends passes.
#[test]
fn a_finish_that_does_not_end_fails_the_script() {
    let want = vec![(
        "finish".to_owned(),
        Want::Is(ready_line(None, &[], YIELD_ENDED, HANDSHAKE_NONE)),
    )];
    let mut h = Host::new();
    let ended = answer(&mut h, None, 0, YIELD_ENDED, HANDSHAKE_NONE);
    let c = called(Outcome::Ready);
    let line = format!(
        "{} {}",
        crate::conformance::called(&c),
        h.yielded(&c, &ended, &[])
    );
    contract(&step("finish", line), &want);
    let open = answer(&mut h, None, 0, 0, HANDSHAKE_NONE);
    let line = format!(
        "{} {}",
        crate::conformance::called(&c),
        h.yielded(&c, &open, &[])
    );
    let refused = std::panic::catch_unwind(|| contract(&step("finish", line), &want));
    assert!(refused.is_err(), "a finish that does not end passed");
}
