// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the transport answer validators: one per rule and arm, each failing if its check is
//! removed.

use std::mem::zeroed;
use std::ptr::{null, NonNull};

use super::*;
use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready};
use crate::abi::mechanism::check::fault;
use crate::abi::transport::*;

fn z<T>() -> T {
    // SAFETY: every answer shape is plain C data (integers, raw pointers); all-zero is a valid
    // value of each.
    unsafe { zeroed() }
}

fn f(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(fault(rule, field))
}

#[test]
fn listen_and_accept_have_no_short_path_over_cap_is_fault() {
    let mut l: ListenOut = z();
    l.addr_written = MAX_ADDR + 1;
    assert_eq!(
        check_listen(&l, MAX_ADDR),
        f(Rule::OverCap, "listen.addr_written")
    );
    l.addr_written = MAX_ADDR;
    assert_eq!(check_listen(&l, MAX_ADDR), Ok(()));
    let mut a: AcceptOut = z();
    a.peer_written = MAX_ADDR + 1;
    assert_eq!(
        check_accept(&a, MAX_ADDR),
        f(Rule::OverCap, "accept.peer_written")
    );
}

#[test]
fn arrival_follows_m_sb() {
    let mut o: ArrivalOut = z();
    o.peer_needed = 64;
    assert_eq!(
        check_arrival(Ready, &o, 16),
        f(Rule::NeededNotFailed, "arrival.peer")
    );
    assert_eq!(
        check_arrival(Pending, &o, 16),
        f(Rule::NeededNotFailed, "arrival.peer")
    );
    assert_eq!(check_arrival(Failed, &o, 16), Ok(()), "the short answer");
    assert_eq!(
        check_arrival(Failed, &o, 64),
        f(Rule::WastedRecall, "arrival.peer")
    );
    o.peer_needed = MAX_ADDR + 1;
    assert_eq!(
        check_arrival(Failed, &o, 16),
        f(Rule::OverMax, "arrival.peer")
    );
    let mut w: ArrivalOut = z();
    w.peer_written = 17;
    assert_eq!(
        check_arrival(Ready, &w, 16),
        f(Rule::OverCap, "arrival.peer")
    );
}

#[test]
fn a_read_above_its_buffer_is_fault() {
    let mut o: IoOut = z();
    o.len = 65;
    assert_eq!(check_io(&o, 64), f(Rule::OverCap, "io.len"));
}

#[test]
fn locate_flags_and_the_name_arms_are_checked() {
    let mut o: LocateOut = z();
    assert_eq!(check_locate(Ready, &o, 8, 8), Ok(()));
    o.secure = 2;
    assert_eq!(
        check_locate(Ready, &o, 8, 8),
        f(Rule::UnknownCode, "locate.secure")
    );
    let mut o: LocateOut = z();
    o.has_name = 2;
    assert_eq!(
        check_locate(Ready, &o, 8, 8),
        f(Rule::UnknownCode, "locate.has_name")
    );
    let mut o: LocateOut = z();
    o.name_written = 1;
    assert_eq!(
        check_locate(Ready, &o, 8, 8),
        f(Rule::Contradiction, "locate.name_without_has_name")
    );
    let mut o: LocateOut = z();
    o.authority_needed = 9;
    assert_eq!(
        check_locate(Ready, &o, 8, 8),
        f(Rule::NeededNotFailed, "locate.authority")
    );
    let mut o: LocateOut = z();
    o.has_name = 1;
    o.name_needed = 8;
    assert_eq!(
        check_locate(Failed, &o, 8, 8),
        f(Rule::WastedRecall, "locate")
    );
}

#[test]
fn locate_is_one_multi_dimension_short_answer() {
    let mut o: LocateOut = z();
    o.has_name = 1;
    o.authority_needed = 9;
    o.name_needed = 3;
    assert_eq!(
        check_locate(Failed, &o, 8, 8),
        Ok(()),
        "one short, the other reports its size"
    );
    o.authority_needed = 8;
    assert_eq!(
        check_locate(Failed, &o, 8, 8),
        f(Rule::WastedRecall, "locate")
    );
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
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        f(Rule::OverCap, "framer.wire_len")
    );
    let mut o: FramerOut = z();
    o.yielded.frame_len = 9;
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        f(Rule::OverCap, "framer.frame_len")
    );
    let mut o: FramerOut = z();
    o.yielded.pieces_len = 9;
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        f(Rule::OverCap, "framer.pieces_len")
    );
}

#[test]
fn a_framer_unknown_flag_or_unstated_deadline_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.flags = 8;
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        f(Rule::UnknownCode, "framer.flags")
    );
    o.yielded.flags = YIELD_HAS_DEADLINE;
    assert_eq!(
        check_framer(Ready, &o, &[], 8, 8, 8),
        f(Rule::Contradiction, "framer.next_deadline_ns")
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
        f(Rule::Contradiction, "framer.failed_wrote")
    );
}

#[test]
fn a_piece_outside_the_frame_or_with_unknown_codes_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 4;
    o.yielded.pieces_len = 1;
    assert_eq!(check_framer(Ready, &o, &[piece(2, 2)], 8, 8, 8), Ok(()));
    assert_eq!(
        check_framer(Ready, &o, &[piece(2, 3)], 8, 8, 8),
        f(Rule::SpanOutOfBounds, "framer.piece.bytes")
    );
    assert_eq!(
        check_framer(Ready, &o, &[piece(u64::MAX, 2)], 8, 8, 8),
        f(Rule::SpanOutOfBounds, "framer.piece.bytes")
    );
    let mut bad = piece(0, 1);
    bad.flags = 8;
    assert_eq!(
        check_framer(Ready, &o, &[bad], 8, 8, 8),
        f(Rule::UnknownCode, "framer.piece.flags")
    );
    let mut bad = piece(0, 1);
    bad.status_class = STATUS_OTHER + 1;
    assert_eq!(
        check_framer(Ready, &o, &[bad], 8, 8, 8),
        f(Rule::UnknownCode, "framer.piece.status_class")
    );
}

#[test]
fn an_unwritten_or_unknown_cancel_disposition_is_fault() {
    assert_eq!(check_cancel(0), f(Rule::UnknownCode, "cancel.disposition"));
    assert_eq!(check_cancel(4), f(Rule::UnknownCode, "cancel.disposition"));
    assert_eq!(check_cancel(CANCEL_PARTIAL), Ok(()));
}

#[test]
fn facts_of_a_foreign_size_are_fault() {
    let mut c: ConnFacts = z();
    assert_eq!(check_facts(&c), f(Rule::Foreign, "facts.size"));
    c.size = std::mem::size_of::<ConnFacts>() as u32;
    assert_eq!(check_facts(&c), Ok(()));
}

fn tail() -> TransportTail {
    let mut t: TransportTail = z();
    t.role = ROLE_CARRIER;
    // Never dereferenced: `check_tail` judges counts against pointers, not the pointees.
    t.claims = NonNull::dangling().as_ptr();
    t.claims_len = 1;
    t
}

#[test]
fn the_role_is_exactly_one_and_agrees_with_composes_over() {
    assert_eq!(check_tail(&tail()), Ok(()));
    let mut t = tail();
    t.role = 0;
    assert_eq!(check_tail(&t), f(Rule::NotExactlyOne, "tail.role"));
    t.role = ROLE_CARRIER | ROLE_FRAMER;
    assert_eq!(check_tail(&t), f(Rule::NotExactlyOne, "tail.role"));
    let mut t = tail();
    t.role = ROLE_FRAMER;
    assert_eq!(check_tail(&t), f(Rule::Contradiction, "tail.composes_over"));
}

#[test]
fn every_tail_list_counted_with_a_null_pointer_is_fault() {
    let mut t = tail();
    t.role = ROLE_FRAMER;
    t.composes_over_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.composes_over"));
    let mut t = tail();
    t.claims = null();
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.claims"));
    let mut t = tail();
    t.upgrades_to_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.upgrades_to"));
    let mut t = tail();
    t.status_rows_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.status_rows"));
    let mut t = tail();
    t.settings_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.settings"));
    let mut t = tail();
    t.handoff_to.len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.handoff_to"));
}

#[test]
fn a_tail_without_claims_or_with_unknown_codes_is_fault() {
    let mut t = tail();
    t.claims_len = 0;
    assert_eq!(check_tail(&t), f(Rule::Missing, "tail.claims"));
    let mut t = tail();
    t.claims_len = MAX_CLAIMS as usize + 1;
    assert_eq!(check_tail(&t), f(Rule::OverMax, "tail.claims"));
    let mut t = tail();
    t.facts = 4;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.facts"));
    let mut t = tail();
    t.framing = 2;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.framing"));
}

fn claim() -> Claim {
    let mut c: Claim = z();
    c.key = AbiStr {
        ptr: b"k".as_ptr(),
        len: 1,
    };
    c
}

#[test]
fn every_claim_element_is_checked() {
    assert_eq!(check_claims(&[claim()]), Ok(()));
    assert_eq!(check_claims(&[z()]), f(Rule::Missing, "claim.key"));
    let mut c = claim();
    c.facts_len = 1;
    assert_eq!(check_claims(&[c]), f(Rule::NullWithCount, "claim.facts"));
    let mut c = claim();
    c.selector_forms.len = 1;
    assert_eq!(
        check_claims(&[c]),
        f(Rule::NullWithCount, "claim.selector_forms")
    );
    let mut c = claim();
    c.session = 2;
    assert_eq!(check_claims(&[c]), f(Rule::UnknownCode, "claim.session"));
    let mut c = claim();
    c.session_bound = 2;
    assert_eq!(
        check_claims(&[c]),
        f(Rule::UnknownCode, "claim.session_bound")
    );
    let mut c = claim();
    c.unit0_trigger = 7;
    assert_eq!(
        check_claims(&[c]),
        f(Rule::UnknownCode, "claim.unit0_trigger")
    );
    let mut c = claim();
    c.status_at = STATUS_AT_TERMINAL + 1;
    assert_eq!(check_claims(&[c]), f(Rule::UnknownCode, "claim.status_at"));
}

fn row(claim: u32, lo: u32, hi: u32, class: u32) -> StatusRow {
    StatusRow {
        claim,
        lo,
        hi,
        class,
    }
}

#[test]
fn every_status_row_is_checked() {
    assert_eq!(check_status_rows(&[row(0, 200, 299, 1)], 1), Ok(()));
    assert_eq!(
        check_status_rows(&[row(1, 200, 299, 1)], 1),
        f(Rule::IndexOutOfRange, "status_row.claim")
    );
    assert_eq!(
        check_status_rows(&[row(0, 300, 299, 1)], 1),
        f(Rule::Contradiction, "status_row.lo_hi")
    );
    assert_eq!(
        check_status_rows(&[row(0, 200, 299, 0)], 1),
        f(Rule::UnknownCode, "status_row.class")
    );
    assert_eq!(
        check_status_rows(&[row(0, 200, 299, 5)], 1),
        f(Rule::UnknownCode, "status_row.class")
    );
}

#[test]
fn every_setting_is_checked() {
    let mut s: SettingDecl = z();
    assert_eq!(check_settings(&[s]), f(Rule::Missing, "setting.path"));
    s.path = AbiStr {
        ptr: b"p".as_ptr(),
        len: 1,
    };
    assert_eq!(check_settings(&[s]), f(Rule::UnknownCode, "setting.kind"));
    s.kind = SETTING_FLAG;
    assert_eq!(check_settings(&[s]), Ok(()));
    s.default.len = 1;
    assert_eq!(
        check_settings(&[s]),
        f(Rule::NullWithCount, "setting.default")
    );
}

#[test]
fn a_null_string_element_in_composes_over_upgrades_to_or_claim_facts_is_fault() {
    let bad = AbiStr {
        ptr: null(),
        len: 1,
    };
    let good = AbiStr {
        ptr: b"k".as_ptr(),
        len: 1,
    };
    assert_eq!(check_composes_over(&[good]), Ok(()));
    assert_eq!(
        check_composes_over(&[good, bad]),
        f(Rule::NullWithCount, "composes_over.name")
    );
    assert_eq!(
        check_upgrades_to(&[bad]),
        f(Rule::NullWithCount, "upgrades_to.name")
    );
    assert_eq!(
        check_claim_facts(&[bad]),
        f(Rule::NullWithCount, "claim.fact")
    );
}
