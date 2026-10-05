// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED arms for the transport answer validators: one per rule and arm, each failing if its check is
//! removed.

use std::mem::zeroed;
use std::ptr::{null, NonNull};

use super::*;
use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::call::Outcome::{Failed, Pending, Ready, Refused};
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
    assert_eq!(check_locate(Ready, &o, 8, 8, 16, &[]), Ok(()));
    o.secure = 2;
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, &[]),
        f(Rule::UnknownCode, "locate.secure")
    );
    let mut o: LocateOut = z();
    o.has_name = 2;
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, &[]),
        f(Rule::UnknownCode, "locate.has_name")
    );
    let mut o: LocateOut = z();
    o.name_written = 1;
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, &[]),
        f(Rule::Contradiction, "locate.name_without_has_name")
    );
    let mut o: LocateOut = z();
    o.authority_needed = 9;
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, &[]),
        f(Rule::NeededNotFailed, "locate.authority")
    );
    let mut o: LocateOut = z();
    o.has_name = 1;
    o.name_needed = 8;
    assert_eq!(
        check_locate(Failed, &o, 8, 8, 16, &[]),
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
        check_locate(Failed, &o, 8, 8, 16, &[]),
        Ok(()),
        "one short, the other reports its size"
    );
    o.authority_needed = 8;
    assert_eq!(
        check_locate(Failed, &o, 8, 8, 16, &[]),
        f(Rule::WastedRecall, "locate")
    );
}

/// The framer's protocol offer is the handshake's ProtocolNameList: it partitions exactly into
/// non-empty ids, it is a third short-buffer dimension, and the agreed protocol is one it offered.
#[test]
fn locate_answers_an_alpn_offer_the_connector_can_trust() {
    let offer = b"\x02h2\x08http/1.1";
    let mut o: LocateOut = z();
    o.alpn_written = offer.len() as u64;
    assert_eq!(check_locate(Ready, &o, 8, 8, 16, offer), Ok(()));
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, b"\x02h2\x00"),
        f(Rule::Missing, "locate.alpn.id")
    );
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, b"\x09http/1.1"),
        f(Rule::SpanOutOfBounds, "locate.alpn.id")
    );
    o.alpn_written = 17;
    assert_eq!(
        check_locate(Ready, &o, 8, 8, 16, offer),
        f(Rule::OverCap, "locate.alpn")
    );
    let mut o: LocateOut = z();
    o.alpn_needed = 20;
    assert_eq!(
        check_locate(Failed, &o, 8, 8, 16, &[]),
        Ok(()),
        "short: re-call with 20"
    );
    assert_eq!(check_agreed(offer, b"h2"), Ok(()));
    assert_eq!(check_agreed(offer, b"http/1.1"), Ok(()));
    assert_eq!(check_agreed(offer, b""), Ok(()));
    assert_eq!(
        check_agreed(b"\x08http/1.1", b"h2"),
        f(Rule::Contradiction, "facts.agreed_protocol")
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

/// A stream ends with an EMPTY piece, and a failed stream with a STREAM_FAILED piece; each is the
/// stream's last piece, so each carries END_OF_FRAME. Either without it is FAULT.
#[test]
fn a_stream_end_or_failure_without_end_of_frame_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 4;
    o.yielded.pieces_len = 1;
    let mut end = piece(4, 0);
    end.flags = PIECE_END_OF_FRAME;
    assert_eq!(check_framer(Ready, &o, &[end], 8, 8, 8), Ok(()));
    end.flags = 0;
    assert_eq!(
        check_framer(Ready, &o, &[end], 8, 8, 8),
        f(Rule::Contradiction, "framer.piece.end_without_end_of_frame")
    );
    let mut failed = piece(0, 4);
    failed.flags = PIECE_STREAM_FAILED | PIECE_END_OF_FRAME;
    assert_eq!(check_framer(Ready, &o, &[failed], 8, 8, 8), Ok(()));
    failed.flags = PIECE_STREAM_FAILED;
    assert_eq!(
        check_framer(Ready, &o, &[failed], 8, 8, 8),
        f(Rule::Contradiction, "framer.piece.end_without_end_of_frame")
    );
}

/// A head is a FIELDS frame, framed even when empty (an empty fields piece is an empty head, not
/// the stream's end); a field block is never a failure's reason.
#[test]
fn a_fields_piece_is_a_head_never_a_failure() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 4;
    o.yielded.pieces_len = 1;
    let mut head = piece(0, 4);
    head.flags = PIECE_FIELDS | PIECE_END_OF_FRAME | PIECE_HAS_CODE;
    assert_eq!(check_framer(Ready, &o, &[head], 8, 8, 8), Ok(()));
    let mut empty = piece(4, 0);
    empty.flags = PIECE_FIELDS | PIECE_END_OF_FRAME;
    assert_eq!(check_framer(Ready, &o, &[empty], 8, 8, 8), Ok(()));
    head.flags = PIECE_FIELDS | PIECE_STREAM_FAILED | PIECE_END_OF_FRAME;
    assert_eq!(
        check_framer(Ready, &o, &[head], 8, 8, 8),
        f(Rule::Contradiction, "framer.piece.fields_failed")
    );
}

/// The field block reads back line by line, in order, a repeated name on its own lines; a
/// malformed tail ends the reading.
#[test]
fn a_field_block_reads_back_in_order() {
    let block = b"x-b: 1\r\nx-b: 2\r\nx-a: v: w\r\nbroken";
    let got: Vec<_> = fields::lines(block).collect();
    assert_eq!(
        got,
        [
            (&b"x-b"[..], &b"1"[..]),
            (&b"x-b"[..], &b"2"[..]),
            (&b"x-a"[..], &b"v: w"[..])
        ]
    );
    assert_eq!(fields::lines(b"").count(), 0);
}

/// Hop-by-hop: the fixed list, and every field a `connection` field names, without case.
#[test]
fn hop_by_hop_is_the_list_and_what_connection_names() {
    let none: [&[u8]; 0] = [];
    for name in fields::HOP_BY_HOP {
        assert!(fields::hop_by_hop(name, none));
    }
    assert!(!fields::hop_by_hop("x-request-id", none));
    let nominated: [&[u8]; 1] = [b"keep-alive, X-Hop"];
    assert!(fields::hop_by_hop("x-hop", nominated));
    assert!(!fields::hop_by_hop("x-request-id", nominated));
}

/// RED: a pseudo-field never enters a field block, wherever its line starts: at a piece that starts
/// a line, after a CR LF, or after a CR LF split across pieces. A piece that continues a line may
/// start with `:` (a value's own byte).
#[test]
fn a_pseudo_field_in_a_field_block_is_fault() {
    let frame = b":path: /\r\nx: 1\r\n:authority: a\r\n\n:m";
    let at = |offset: u64, len: u64, flags: u16| {
        let mut p = piece(offset, len);
        p.flags = PIECE_FIELDS | flags;
        p
    };
    let pseudo = f(Rule::Foreign, "framer.piece.pseudo_field");
    assert_eq!(check_framer_fields(&[at(0, 10, 0)], frame), pseudo);
    assert_eq!(check_framer_fields(&[at(10, 18, 0)], frame), pseudo);
    assert_eq!(
        check_framer_fields(&[at(31, 3, PIECE_CONTINUED)], frame),
        pseudo
    );
    // `x: 1\r\n` alone, and a continued piece that opens with a value's `:`.
    assert_eq!(check_framer_fields(&[at(10, 6, 0)], frame), Ok(()));
    assert_eq!(
        check_framer_fields(&[at(5, 5, PIECE_CONTINUED)], frame),
        Ok(())
    );
    // Payload is never read as fields.
    assert_eq!(check_framer_fields(&[piece(0, 10)], frame), Ok(()));
}

/// PIECE_CONTINUED belongs to a field block only.
#[test]
fn a_continued_piece_outside_a_field_block_is_fault() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 4;
    o.yielded.pieces_len = 1;
    let mut p = piece(0, 4);
    p.flags = PIECE_CONTINUED | PIECE_END_OF_FRAME;
    assert_eq!(
        check_framer(Ready, &o, &[p], 8, 8, 8),
        f(Rule::Contradiction, "framer.piece.continued_not_fields")
    );
    p.flags |= PIECE_FIELDS;
    assert_eq!(check_framer(Ready, &o, &[p], 8, 8, 8), Ok(()));
}

/// PIECE_TEXT is a fact about a message's bytes (C19-TAIL U5): on a payload piece it passes; on an
/// empty piece (a stream's end), a field block or a failed stream's reason it is FAULT.
#[test]
fn text_rides_a_message_piece_only() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 4;
    o.yielded.pieces_len = 1;
    let mut message = piece(0, 4);
    message.flags = PIECE_TEXT;
    assert_eq!(check_framer(Ready, &o, &[message], 8, 8, 8), Ok(()));
    message.flags = PIECE_TEXT | PIECE_END_OF_FRAME;
    assert_eq!(check_framer(Ready, &o, &[message], 8, 8, 8), Ok(()));
    for (p, flags) in [
        (piece(4, 0), PIECE_TEXT | PIECE_END_OF_FRAME),
        (piece(0, 4), PIECE_TEXT | PIECE_FIELDS | PIECE_END_OF_FRAME),
        (
            piece(0, 4),
            PIECE_TEXT | PIECE_STREAM_FAILED | PIECE_END_OF_FRAME,
        ),
    ] {
        let p = FramePiece { flags, ..p };
        assert_eq!(
            check_framer(Ready, &o, &[p], 8, 8, 8),
            f(Rule::Contradiction, "framer.piece.text_not_message"),
            "{flags:#x}"
        );
    }
}

/// A stream's head slots: within the capacity, one per stream, every slot inside the frame bytes
/// written; a method and a target together (an accepted head) or both absent (a dialled answer's
/// reason alone).
#[test]
fn head_slots_lie_in_the_frame_and_pair_method_with_target() {
    let mut o: FramerOut = z();
    o.yielded.frame_len = 14;
    o.yielded.heads_len = 1;
    let span = |offset, len| FrameSpan { offset, len };
    let accepted = HeadSlots {
        stream: 1,
        method: span(0, 3),
        target: span(3, 9),
        ..HeadSlots::default()
    };
    let dialled = HeadSlots {
        stream: 1,
        reason: span(12, 2),
        ..HeadSlots::default()
    };
    assert_eq!(check_head_slots(&o, &[accepted], 4), Ok(()));
    assert_eq!(check_head_slots(&o, &[dialled], 4), Ok(()));
    assert_eq!(
        check_head_slots(&o, &[accepted], 0),
        f(Rule::OverCap, "framer.heads_len")
    );
    let mut bad = accepted;
    bad.target = span(3, 12);
    assert_eq!(
        check_head_slots(&o, &[bad], 4),
        f(Rule::SpanOutOfBounds, "framer.head.target")
    );
    bad = dialled;
    bad.reason = span(12, 3);
    assert_eq!(
        check_head_slots(&o, &[bad], 4),
        f(Rule::SpanOutOfBounds, "framer.head.reason")
    );
    for (method, target) in [
        (FrameSpan::default(), span(3, 9)),
        (span(0, 3), FrameSpan::default()),
    ] {
        bad = HeadSlots {
            method,
            target,
            ..accepted
        };
        assert_eq!(
            check_head_slots(&o, &[bad], 4),
            f(Rule::Contradiction, "framer.head.method_without_target")
        );
    }
    o.yielded.heads_len = 2;
    assert_eq!(
        check_head_slots(&o, &[accepted, dialled], 4),
        f(Rule::Contradiction, "framer.head.stream_twice")
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
    bad.flags = 1 << 8;
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
    assert_eq!(
        check_cancel(Ready, 0),
        f(Rule::UnknownCode, "cancel.disposition")
    );
    assert_eq!(
        check_cancel(Ready, 4),
        f(Rule::UnknownCode, "cancel.disposition")
    );
    assert_eq!(check_cancel(Ready, CANCEL_PARTIAL), Ok(()));
    // Another outcome answers no disposition: unwritten passes, a written one is FAULT.
    assert_eq!(check_cancel(Failed, 0), Ok(()));
    assert_eq!(check_cancel(Pending, 0), Ok(()));
    assert_eq!(
        check_cancel(Refused, CANCEL_PARTIAL),
        f(Rule::Contradiction, "cancel.disposition")
    );
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
    t.claim_rows = NonNull::dangling().as_ptr();
    t.claim_rows_len = 1;
    t
}

#[test]
fn the_role_is_exactly_one_and_a_carrier_composes_over_nothing() {
    assert_eq!(check_tail(&tail()), Ok(()));
    let mut t = tail();
    t.role = 0;
    assert_eq!(check_tail(&t), f(Rule::NotExactlyOne, "tail.role"));
    t.role = ROLE_CARRIER | ROLE_FRAMER;
    assert_eq!(check_tail(&t), f(Rule::NotExactlyOne, "tail.role"));
    // A carrier that names a layer beneath it contradicts itself: it is the bottom of its stack.
    let mut t = tail();
    let under = [AbiStr {
        ptr: b"tcp".as_ptr(),
        len: 3,
    }];
    t.composes_over = under.as_ptr();
    t.composes_over_len = 1;
    assert_eq!(check_tail(&t), f(Rule::Contradiction, "tail.composes_over"));
    // The same list on a framer is its composition.
    t.role = ROLE_FRAMER;
    assert_eq!(check_tail(&t), Ok(()));
}

/// A framer that composes over nothing frames directly over the host's socket.
#[test]
fn a_framer_with_no_composes_over_frames_over_the_host_socket() {
    let mut t = tail();
    t.role = ROLE_FRAMER;
    assert_eq!(check_tail(&t), Ok(()));
}

#[test]
fn every_tail_list_counted_with_a_null_pointer_is_fault() {
    let mut t = tail();
    t.role = ROLE_FRAMER;
    t.composes_over_len = 1;
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.composes_over"));
    let mut t = tail();
    t.claim_rows = null();
    assert_eq!(check_tail(&t), f(Rule::NullWithCount, "tail.claim_rows"));
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
    t.claim_rows_len = 0;
    assert_eq!(check_tail(&t), f(Rule::Missing, "tail.claim_rows"));
    let mut t = tail();
    t.claim_rows_len = MAX_CLAIMS as usize + 1;
    assert_eq!(check_tail(&t), f(Rule::OverMax, "tail.claim_rows"));
    let mut t = tail();
    t.facts = 4;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.facts"));
    let mut t = tail();
    t.framing = 2;
    assert_eq!(check_tail(&t), f(Rule::UnknownCode, "tail.framing"));
}

fn claim() -> Claim {
    z()
}

/// THE ONE SOURCE OF CLAIM NAMES: a transport's tail carries exactly one row per scheme its
/// Statement names (row `i` describes `claims[i]`), and a row carries no name of its own. RED: a
/// tail with a row the Statement does not name, or a name with no row, is refused.
#[test]
fn a_tail_has_exactly_one_row_per_claim_the_statement_names() {
    let t = tail();
    assert_eq!(check_claim_rows(1, &t), Ok(()));
    assert_eq!(
        check_claim_rows(2, &t),
        f(Rule::Contradiction, "tail.claim_rows")
    );
    assert_eq!(
        check_claim_rows(0, &t),
        f(Rule::Contradiction, "tail.claim_rows")
    );
}

#[test]
fn every_claim_element_is_checked() {
    assert_eq!(check_claims(&[claim()]), Ok(()));
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

fn route(methods: u32, path_form: u32, path: &'static str) -> route::RouteMatch {
    route::RouteMatch {
        methods,
        path_form,
        path: AbiStr {
            ptr: path.as_ptr(),
            len: path.len(),
        },
        fields: null(),
        fields_len: 0,
        rung: 0,
        _reserved: 0,
    }
}

/// RED: a route's shape — a method set inside the vocabulary and not empty, a known path form, a
/// bounded predicate list — is judged before any string is read.
#[test]
fn a_route_shape_is_checked() {
    use route::*;
    assert_eq!(
        check_route(&route(METHOD_POST, PATH_EXACT, "/v1/messages")),
        Ok(())
    );
    assert_eq!(
        check_route(&route(0, PATH_EXACT, "/x")),
        f(Rule::Missing, "route.methods")
    );
    assert_eq!(
        check_route(&route(METHOD_ANY + 1, PATH_EXACT, "/x")),
        f(Rule::UnknownCode, "route.methods")
    );
    assert_eq!(
        check_route(&route(METHOD_GET, PATH_CONTAINS + 1, "/x")),
        f(Rule::UnknownCode, "route.path_form")
    );
    let mut r = route(METHOD_GET, PATH_EXACT, "/x");
    r.fields_len = 1;
    assert_eq!(check_route(&r), f(Rule::NullWithCount, "route.fields"));
    let bad = [FieldPredicate {
        op: FIELD_VALUE_PREFIX + 1,
        _reserved: 0,
        name: AbiStr {
            ptr: null(),
            len: 0,
        },
        value: AbiStr {
            ptr: null(),
            len: 0,
        },
    }];
    assert_eq!(
        check_route_fields(&bad),
        f(Rule::UnknownCode, "route.field.op")
    );
}

/// RED: a route's content — a rooted path for the exact, pattern and prefix forms, a pattern that
/// keeps the syntax, lower-case field-name tokens, and a value exactly where the op wants one.
#[test]
fn a_route_content_is_checked() {
    use route::*;
    let v = |path_form, path, fields: Vec<(u32, &'static str, &'static [u8])>| RouteView {
        methods: METHOD_POST,
        path_form,
        path,
        fields,
        rung: 0,
    };
    assert_eq!(
        check_route_view(&v(PATH_EXACT, "/v1/messages", vec![])),
        Ok(())
    );
    assert_eq!(
        check_route_view(&v(PATH_SUFFIX, ":countTokens", vec![])),
        Ok(())
    );
    assert_eq!(
        check_route_view(&v(PATH_EXACT, "", vec![])),
        f(Rule::Missing, "route.path")
    );
    assert_eq!(
        check_route_view(&v(PATH_PREFIX, "v1", vec![])),
        f(Rule::UnknownCode, "route.path")
    );
    assert_eq!(
        check_route_view(&v(PATH_PATTERN, "/a/{*rest}/b", vec![])),
        f(Rule::UnknownCode, "route.path.pattern")
    );
    assert_eq!(
        check_route_view(&v(
            PATH_EXACT,
            "/x",
            vec![(FIELD_PRESENT, "Authorization", b"")]
        )),
        f(Rule::UnknownCode, "route.field.name")
    );
    assert_eq!(
        check_route_view(&v(
            PATH_EXACT,
            "/x",
            vec![(FIELD_PRESENT, "authorization", b"x")]
        )),
        f(Rule::Contradiction, "route.field.value")
    );
    assert_eq!(
        check_route_view(&v(
            PATH_EXACT,
            "/x",
            vec![(FIELD_VALUE_PREFIX, "authorization", b"")]
        )),
        f(Rule::Contradiction, "route.field.value")
    );
}

fn fault_row(claim: u32, lo: u32, hi: u32, fault: u32) -> FaultRow {
    FaultRow {
        claim,
        lo,
        hi,
        fault,
    }
}

#[test]
fn every_fault_row_is_checked() {
    let hard = u32::from(FAULT_HARD);
    assert_eq!(check_fault_rows(&[fault_row(0, 1, 9, hard)], 1), Ok(()));
    assert_eq!(
        check_fault_rows(&[fault_row(1, 1, 9, hard)], 1),
        f(Rule::IndexOutOfRange, "fault_row.claim")
    );
    assert_eq!(
        check_fault_rows(&[fault_row(0, 9, 1, hard)], 1),
        f(Rule::Contradiction, "fault_row.lo_hi")
    );
    // A row that reads nothing is no row: a code off the table already reads none.
    assert_eq!(
        check_fault_rows(&[fault_row(0, 1, 9, u32::from(FAULT_NONE))], 1),
        f(Rule::UnknownCode, "fault_row.fault")
    );
    assert_eq!(
        check_fault_rows(&[fault_row(0, 1, 9, hard + 1)], 1),
        f(Rule::UnknownCode, "fault_row.fault")
    );
}

/// THE RED ARM AT LOAD: a claim that states status rows states fault rows too. A framer with status
/// rows and no fault table would have every failure read as the caller's, and its destinations would
/// never trip.
#[test]
fn a_claim_with_status_rows_and_no_fault_rows_is_refused() {
    let status = [row(0, 200, 299, 1), row(1, 200, 299, 1)];
    let caller = u32::from(FAULT_CALLER);
    assert_eq!(
        check_fault_cover(&status, &[]),
        f(Rule::Missing, "tail.fault_rows")
    );
    assert_eq!(
        check_fault_cover(&status, &[fault_row(0, 400, 499, caller)]),
        f(Rule::Missing, "tail.fault_rows"),
        "the second claim has none"
    );
    assert_eq!(
        check_fault_cover(
            &status,
            &[
                fault_row(0, 400, 499, caller),
                fault_row(1, 400, 499, caller)
            ]
        ),
        Ok(())
    );
    // A tail that classes nothing owes nothing.
    assert_eq!(check_fault_cover(&[], &[]), Ok(()));
}

#[test]
fn a_pieces_fault_reading_is_known_and_reads_its_code() {
    let yielded = |frame_len: u64, pieces_len: u32| {
        let mut o: FramerOut = z();
        o.yielded.frame_len = frame_len;
        o.yielded.pieces_len = pieces_len;
        o
    };
    let mut p = piece(0, 1);
    p.flags = PIECE_END_OF_FRAME | PIECE_HAS_CODE;
    p.fault = FAULT_TRANSIENT;
    assert_eq!(check_framer(Ready, &yielded(1, 1), &[p], 8, 8, 8), Ok(()));
    p.fault = FAULT_HARD + 1;
    assert_eq!(
        check_framer(Ready, &yielded(1, 1), &[p], 8, 8, 8),
        f(Rule::UnknownCode, "framer.piece.fault")
    );
    // A reading with no code to read is a contradiction.
    p.fault = FAULT_CALLER;
    p.flags = PIECE_END_OF_FRAME;
    assert_eq!(
        check_framer(Ready, &yielded(1, 1), &[p], 8, 8, 8),
        f(Rule::Contradiction, "framer.piece.fault_without_code")
    );
}
