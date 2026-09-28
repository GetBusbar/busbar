// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the transport answer validators: one per rule, each failing if its check is removed.

use std::mem::zeroed;

use super::*;
use crate::abi::mechanism::call::Outcome::{Failed, Ready};

fn z<T>() -> T {
    // SAFETY: every answer shape is plain C data (integers, raw pointers, `Option<fn>`); all-zero
    // is a valid value of each.
    unsafe { zeroed() }
}

#[test]
fn a_needed_size_above_u32_max_is_fault() {
    let mut o: ListenOut = z();
    o.addr_len = u64::from(u32::MAX) + 1;
    assert_eq!(check_listen(Ready, &o, 64), Err(Fault::OverMax));
    o.addr_len = 65;
    assert_eq!(
        check_listen(Ready, &o, 64),
        Ok(()),
        "a needed size is a re-call, not a fault"
    );
}

#[test]
fn failed_with_a_length_that_fits_is_fault() {
    let mut o: AcceptOut = z();
    o.peer_len = 8;
    assert_eq!(check_accept(Failed, &o, 64), Err(Fault::WastedRecall));
    assert_eq!(check_accept(Ready, &o, 64), Ok(()));
    let mut a: ArrivalOut = z();
    a.peer_len = 8;
    assert_eq!(check_arrival(Failed, &a, 64), Err(Fault::WastedRecall));
}

#[test]
fn a_read_above_its_buffer_is_fault() {
    let mut o: IoOut = z();
    o.len = 65;
    assert_eq!(check_io(Ready, &o, 64), Err(Fault::OverCap));
    o.len = 1;
    assert_eq!(check_io(Failed, &o, 64), Err(Fault::WastedRecall));
    assert_eq!(check_io(Ready, &o, 64), Ok(()));
}

#[test]
fn locate_secure_is_a_flag_and_no_name_is_allowed() {
    let mut o: LocateOut = z();
    o.name_len = u64::MAX;
    assert_eq!(check_locate(Ready, &o, 8, 8), Ok(()));
    o.secure = 2;
    assert_eq!(check_locate(Ready, &o, 8, 8), Err(Fault::UnknownCode));
}

fn piece(offset: u64, len: u64) -> FramePiece {
    let mut p: FramePiece = z();
    p.offset = offset;
    p.len = len;
    p
}

#[test]
fn a_framer_sink_overrun_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.wire_len = 9;
    assert_eq!(check_framer(Ready, &o, &[], 8, 8, 8), Err(Fault::OverCap));
    o.yielded.wire_len = 0;
    o.yielded.pieces_len = 9;
    assert_eq!(check_framer(Ready, &o, &[], 8, 8, 8), Err(Fault::OverCap));
}

#[test]
fn a_framer_unknown_flag_or_unstated_deadline_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.flags = 8;
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        Err(Fault::UnknownCode)
    );
    o.yielded.flags = YIELD_HAS_DEADLINE;
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        Err(Fault::UnknownCode)
    );
    o.yielded.next_deadline_ns = 5;
    assert_eq!(check_framer(Ready, &o, &[], 8, 8, 8), Ok(()));
}

#[test]
fn a_failed_framer_answer_that_wrote_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 1;
    assert_eq!(
        check_framer(Failed, &o, &[], 8, 8, 8),
        Err(Fault::WastedRecall)
    );
}

#[test]
fn a_piece_outside_the_frame_bytes_is_fault_with_checked_arithmetic() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 4;
    o.yielded.pieces_len = 1;
    assert_eq!(check_framer(Ready, &o, &[piece(2, 2)], 8, 8, 8), Ok(()));
    assert_eq!(
        check_framer(Ready, &o, &[piece(2, 3)], 8, 8, 8),
        Err(Fault::PieceOutOfFrame)
    );
    assert_eq!(
        check_framer(Ready, &o, &[piece(u64::MAX, 2)], 8, 8, 8),
        Err(Fault::PieceOutOfFrame)
    );
    let mut bad = piece(0, 1);
    bad.status_class = STATUS_OTHER + 1;
    assert_eq!(
        check_framer(Ready, &o, &[bad], 8, 8, 8),
        Err(Fault::UnknownCode)
    );
}

#[test]
fn an_unwritten_or_unknown_cancel_disposition_is_fault() {
    assert_eq!(check_cancel(0), Err(Fault::UnknownCode));
    assert_eq!(check_cancel(4), Err(Fault::UnknownCode));
    assert_eq!(check_cancel(CANCEL_PARTIAL), Ok(()));
}

#[test]
fn facts_of_a_foreign_size_are_fault() {
    let mut f: ConnFacts = z();
    assert_eq!(check_facts(&f), Err(Fault::UnknownCode));
    f.size = std::mem::size_of::<ConnFacts>() as u32;
    assert_eq!(check_facts(&f), Ok(()));
}

fn tail() -> TransportTail {
    let mut t: TransportTail = z();
    t.role = ROLE_CARRIER;
    // Never dereferenced: `check_tail` judges counts against pointers, not the pointees.
    t.claims = std::ptr::NonNull::dangling().as_ptr();
    t.claims_len = 1;
    t
}

#[test]
fn the_role_is_exactly_one_and_agrees_with_composes_over() {
    assert_eq!(check_tail(&tail()), Ok(()));
    let mut t = tail();
    t.role = 0;
    assert_eq!(check_tail(&t), Err(Fault::NotExactlyOne));
    t.role = ROLE_CARRIER | ROLE_FRAMER;
    assert_eq!(check_tail(&t), Err(Fault::NotExactlyOne));
    let mut f = tail();
    f.role = ROLE_FRAMER;
    assert_eq!(
        check_tail(&f),
        Err(Fault::NotExactlyOne),
        "a framer composes over a carrier"
    );
}

#[test]
fn a_tail_list_counted_with_a_null_pointer_is_fault() {
    let mut t = tail();
    t.settings_len = 1;
    assert_eq!(check_tail(&t), Err(Fault::NullWithCount));
    let mut t = tail();
    t.claims = std::ptr::null();
    assert_eq!(check_tail(&t), Err(Fault::NullWithCount));
}

#[test]
fn a_tail_without_claims_or_with_unknown_bits_is_fault() {
    let mut t = tail();
    t.claims_len = 0;
    assert_eq!(check_tail(&t), Err(Fault::Missing));
    let mut t = tail();
    t.claims_len = MAX_CLAIMS as usize + 1;
    assert_eq!(check_tail(&t), Err(Fault::OverMax));
    let mut t = tail();
    t.facts = 4;
    assert_eq!(check_tail(&t), Err(Fault::UnknownCode));
    let mut t = tail();
    t.framing = 2;
    assert_eq!(check_tail(&t), Err(Fault::UnknownCode));
}
