// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the datagram lane's validators (`check_datagram`, `check_terms`, `check_keying`):
//! one per rule and arm, each failing if its check is removed.

use std::mem::{size_of, zeroed};

use crate::abi::mechanism::call::Outcome::{Failed, Ready};
use crate::abi::mechanism::check::{fault, Fault, Rule};
use crate::abi::transport::check::{check_datagram, check_keying, check_terms};
use crate::abi::transport::*;

fn z<T>() -> T {
    // SAFETY: every shape here is plain C data (integers, raw pointers); all-zero is valid.
    unsafe { zeroed() }
}

fn f(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(fault(rule, field))
}

fn span(offset: u64, len: u64) -> FrameSpan {
    FrameSpan { offset, len }
}

/// An answer that wrote `wire` wire bytes and `frame` frame bytes.
fn answer(wire: u64, frame: u64) -> FramerOut {
    let mut o: FramerOut = z();
    o.yielded.wire_len = wire;
    o.yielded.frame_len = frame;
    o
}

fn route(offset: u64, len: u64, path: u32, lane: u32) -> DatagramRoute {
    DatagramRoute {
        offset,
        len,
        path,
        lane,
    }
}

/// Terms a rendezvous answer carries: four credentials and a 32-byte fingerprint in 64 frame
/// bytes.
fn terms() -> RendezvousTerms {
    RendezvousTerms {
        role: HANDSHAKE_ANSWERS,
        _reserved: 0,
        local_user: span(0, 4),
        local_secret: span(4, 22),
        remote_user: span(26, 4),
        remote_secret: span(30, 2),
        peer_fingerprint: span(32, FINGERPRINT_BYTES),
        candidates: span(64, 0),
    }
}

#[test]
fn a_stream_framers_zeroed_yield_passes() {
    assert_eq!(check_datagram(Ready, &answer(10, 10), &[], 0), Ok(()));
    assert_eq!(check_datagram(Failed, &answer(0, 0), &[], 0), Ok(()));
}

#[test]
fn routes_above_their_buffer_or_the_ceiling_are_fault() {
    let mut o = answer(100, 0);
    o.datagram.routes_len = 2;
    let rs = [route(0, 10, 1, LANE_CLEAR); 2];
    assert_eq!(
        check_datagram(Ready, &o, &rs, 1),
        f(Rule::OverCap, "datagram.routes_len")
    );
    assert_eq!(check_datagram(Ready, &o, &rs, 2), Ok(()));
    o.datagram.routes_len = u32::try_from(MAX_ROUTES + 1).expect("fits");
    assert_eq!(
        check_datagram(Ready, &o, &rs, u64::MAX),
        f(Rule::OverCap, "datagram.routes_len")
    );
}

#[test]
fn every_route_is_one_nonempty_datagram_inside_the_wire_to_a_path_on_a_send_lane() {
    let mut o = answer(100, 0);
    o.datagram.routes_len = 1;
    let one = |r: DatagramRoute| check_datagram(Ready, &o, &[r], 1);
    assert_eq!(one(route(0, 100, 7, LANE_CLEAR)), Ok(()));
    assert_eq!(one(route(0, 100, 7, LANE_SECURED)), Ok(()));
    assert_eq!(
        one(route(0, 0, 7, LANE_CLEAR)),
        f(Rule::Missing, "datagram.route.len")
    );
    assert_eq!(
        one(route(90, 11, 7, LANE_CLEAR)),
        f(Rule::SpanOutOfBounds, "datagram.route.bytes")
    );
    assert_eq!(
        one(route(u64::MAX, 2, 7, LANE_CLEAR)),
        f(Rule::SpanOutOfBounds, "datagram.route.bytes")
    );
    assert_eq!(
        one(route(0, 10, 0, LANE_CLEAR)),
        f(Rule::Missing, "datagram.route.path")
    );
    assert_eq!(
        one(route(0, 10, 7, LANE_RENDEZVOUS)),
        f(Rule::UnknownCode, "datagram.route.lane"),
        "a session description is never sent on the port"
    );
    assert_eq!(
        one(route(0, 10, 7, 0)),
        f(Rule::UnknownCode, "datagram.route.lane")
    );
}

#[test]
fn a_failed_answer_routes_nothing_and_asks_for_nothing() {
    let mut o = answer(0, 0);
    o.datagram.routes_len = 1;
    assert_eq!(
        check_datagram(Failed, &o, &[route(0, 1, 1, LANE_CLEAR)], 1),
        f(Rule::Contradiction, "datagram.failed_routed")
    );
    let mut asks = answer(0, 0);
    asks.datagram.request = PATH_REQUEST_BIND;
    asks.datagram.request_to = 3;
    assert_eq!(
        check_datagram(Failed, &asks, &[], 0),
        f(Rule::Contradiction, "datagram.failed_routed")
    );
}

#[test]
fn a_path_request_names_exactly_the_paths_its_kind_needs() {
    let ask = |request: u32, from: u32, to: u32| {
        let mut o = answer(0, 0);
        o.datagram.request = request;
        o.datagram.request_from = from;
        o.datagram.request_to = to;
        check_datagram(Ready, &o, &[], 0)
    };
    let paths = f(Rule::Contradiction, "datagram.request.paths");
    assert_eq!(ask(PATH_REQUEST_BIND, 0, 3), Ok(()));
    assert_eq!(
        ask(PATH_REQUEST_BIND, 2, 3),
        paths,
        "a bind moves from nothing"
    );
    assert_eq!(ask(PATH_REQUEST_BIND, 0, 0), paths, "a bind names its path");
    assert_eq!(ask(PATH_REQUEST_REBIND, 2, 3), Ok(()));
    assert_eq!(
        ask(PATH_REQUEST_REBIND, 0, 3),
        paths,
        "a rebind names the bound path"
    );
    assert_eq!(
        ask(PATH_REQUEST_REBIND, 3, 3),
        paths,
        "a rebind moves somewhere"
    );
    assert_eq!(
        ask(PATH_REQUEST_NONE, 0, 3),
        paths,
        "no request names no path"
    );
    assert_eq!(
        ask(PATH_REQUEST_REBIND + 1, 2, 3),
        f(Rule::UnknownCode, "datagram.request")
    );
}

#[test]
fn rendezvous_terms_are_absent_whole_or_complete_inside_the_frame() {
    assert_eq!(check_terms(&RendezvousTerms::default(), 0), Ok(()));
    assert_eq!(check_terms(&terms(), 64), Ok(()));
    let stray = RendezvousTerms {
        remote_user: span(0, 4),
        ..RendezvousTerms::default()
    };
    assert_eq!(
        check_terms(&stray, 64),
        f(Rule::SpanNotAbsent, "datagram.terms.remote_user")
    );
    let mut no_user = terms();
    no_user.local_user = span(0, 0);
    assert_eq!(
        check_terms(&no_user, 64),
        f(Rule::Missing, "datagram.terms.local_user")
    );
    assert_eq!(
        check_terms(&terms(), 63),
        f(Rule::SpanOutOfBounds, "datagram.terms.peer_fingerprint")
    );
    let mut short = terms();
    short.peer_fingerprint = span(32, FINGERPRINT_BYTES - 1);
    assert_eq!(
        check_terms(&short, 64),
        f(Rule::Contradiction, "datagram.terms.peer_fingerprint.len")
    );
    let mut role = terms();
    role.role = HANDSHAKE_ANSWERS + 1;
    assert_eq!(
        check_terms(&role, 64),
        f(Rule::UnknownCode, "datagram.terms.role")
    );
    let stray_candidates = RendezvousTerms {
        candidates: span(0, 9),
        ..RendezvousTerms::default()
    };
    assert_eq!(
        check_terms(&stray_candidates, 64),
        f(Rule::SpanNotAbsent, "datagram.terms.candidates")
    );
    let mut advertised = terms();
    advertised.candidates = span(64, 15);
    assert_eq!(check_terms(&advertised, 79), Ok(()));
    assert_eq!(
        check_terms(&advertised, 78),
        f(Rule::SpanOutOfBounds, "datagram.terms.candidates")
    );
    // The answer's own check reaches the terms, against the frame bytes it wrote.
    let mut o = answer(0, 63);
    o.datagram.terms = terms();
    assert_eq!(
        check_datagram(Ready, &o, &[], 0),
        f(Rule::SpanOutOfBounds, "datagram.terms.peer_fingerprint")
    );
    o.yielded.frame_len = 64;
    assert_eq!(check_datagram(Ready, &o, &[], 0), Ok(()));
}

#[test]
fn the_keying_material_item_is_its_own_size_a_profile_and_bounded_bytes() {
    let bytes = [7_u8; MAX_KEYING_BYTES as usize + 1];
    let item = |size: usize, profile: u32, ptr: *const u8, len: usize| KeyingMaterial {
        size: u32::try_from(size).expect("fits"),
        profile,
        bytes: ptr,
        len,
    };
    let own = size_of::<KeyingMaterial>();
    assert_eq!(check_keying(&item(own, 7, bytes.as_ptr(), 56)), Ok(()));
    assert_eq!(
        check_keying(&item(own - 8, 7, bytes.as_ptr(), 56)),
        f(Rule::Foreign, "keying.size")
    );
    assert_eq!(
        check_keying(&item(own, 0, bytes.as_ptr(), 56)),
        f(Rule::Missing, "keying.profile")
    );
    assert_eq!(
        check_keying(&item(own, 7, bytes.as_ptr(), 0)),
        f(Rule::Missing, "keying.len")
    );
    assert_eq!(
        check_keying(&item(own, 7, bytes.as_ptr(), bytes.len())),
        f(Rule::OverMax, "keying.len")
    );
    assert_eq!(
        check_keying(&item(own, 7, std::ptr::null(), 56)),
        f(Rule::NullWithCount, "keying.bytes")
    );
}

#[test]
fn the_lanes_and_requests_are_distinct_codes() {
    let lanes = [LANE_CLEAR, LANE_SECURED, LANE_RENDEZVOUS];
    for (i, a) in lanes.iter().enumerate() {
        assert_ne!(*a, 0, "zero is the call that ingests nothing");
        assert!(lanes[i + 1..].iter().all(|b| a != b));
    }
    assert_eq!(PATH_REQUEST_NONE, 0, "a zeroed yield asks for nothing");
    assert_eq!(HANDSHAKE_NONE, 0, "a zeroed yield carries no terms");
}
