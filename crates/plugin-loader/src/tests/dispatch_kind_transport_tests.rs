// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind's adapter: each checked op answers GREEN and RED through `Kind::check`, a
//! piece count one past the host's cap is FAULT before any slice exists, a foreign `in` is FAULT,
//! every slot has a name, and only `arrival` and `locate` have a short answer.

use std::mem::{size_of, zeroed};
use std::ptr::NonNull;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelOut};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FrameSpan, FramerOut, FramerSink, FramingIn, HeadSlots,
    IngestIn, IoOut, ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn,
    CANCEL_COMPLETED, CANCEL_NOTHING_MOVED, MAX_ADDR, PIECE_END_OF_FRAME, PIECE_FIELDS, SLOTS,
    YIELD_MORE,
};

use crate::dispatch::kinds::transport::Transport;
use crate::dispatch::{Answer, Kind};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data (integers, raw pointers); all-zero is a valid
    // value of each.
    unsafe { zeroed() }
}

fn f(rule: Rule, field: &'static str) -> Result<(), Fault> {
    Err(fault(rule, field))
}

/// An answer of `slot` over the test's own `in` and `out`.
fn answer<I, O>(s: u32, outcome: Outcome, i: &I, o: &O) -> Answer<'static> {
    // SAFETY: `i` and `o` are live for the answer's use in each test and nobody writes them.
    unsafe {
        Answer::new(
            s,
            outcome,
            std::ptr::from_ref(i).cast(),
            size_of::<I>(),
            std::ptr::from_ref(o).cast(),
            size_of::<O>(),
        )
    }
}

// ── carrier ──

#[test]
fn listen_green_and_red_no_short_path() {
    let mut i: ListenIn = z();
    i.addr_cap = MAX_ADDR as usize;
    let mut o: ListenOut = z();
    o.addr_written = MAX_ADDR;
    assert_eq!(
        Transport::check(&answer(slot::LISTEN, Outcome::Ready, &i, &o)),
        Ok(())
    );
    o.addr_written = MAX_ADDR + 1;
    let a = answer(slot::LISTEN, Outcome::Failed, &i, &o);
    assert_eq!(
        Transport::check(&a),
        f(Rule::OverCap, "listen.addr_written")
    );
    assert!(!Transport::short(&a), "listen has no short path");
}

#[test]
fn accept_green_and_red_no_short_path() {
    let mut i: AcceptIn = z();
    i.peer_cap = MAX_ADDR as usize;
    let mut o: AcceptOut = z();
    o.peer_written = 16;
    assert_eq!(
        Transport::check(&answer(slot::ACCEPT, Outcome::Ready, &i, &o)),
        Ok(())
    );
    o.peer_written = MAX_ADDR + 1;
    let a = answer(slot::ACCEPT, Outcome::Failed, &i, &o);
    assert_eq!(
        Transport::check(&a),
        f(Rule::OverCap, "accept.peer_written")
    );
    assert!(!Transport::short(&a), "accept has no short path");
}

#[test]
fn read_and_write_green_and_red() {
    let mut r: ReadIn = z();
    r.cap = 32;
    let mut o: IoOut = z();
    o.len = 32;
    assert_eq!(
        Transport::check(&answer(slot::READ, Outcome::Ready, &r, &o)),
        Ok(())
    );
    o.len = 33;
    assert_eq!(
        Transport::check(&answer(slot::READ, Outcome::Failed, &r, &o)),
        f(Rule::OverCap, "io.len")
    );
    let mut w: WriteIn = z();
    w.len = 8;
    o.len = 8;
    assert_eq!(
        Transport::check(&answer(slot::WRITE, Outcome::Ready, &w, &o)),
        Ok(())
    );
    o.len = 9;
    assert_eq!(
        Transport::check(&answer(slot::WRITE, Outcome::Ready, &w, &o)),
        f(Rule::OverCap, "io.len")
    );
}

#[test]
fn arrival_green_red_and_short() {
    let mut i: ArrivalIn = z();
    i.peer_cap = 16;
    let mut o: ArrivalOut = z();
    o.peer_written = 16;
    assert_eq!(
        Transport::check(&answer(slot::ARRIVAL, Outcome::Ready, &i, &o)),
        Ok(())
    );
    o.peer_written = 0;
    o.peer_needed = 64;
    assert_eq!(
        Transport::check(&answer(slot::ARRIVAL, Outcome::Ready, &i, &o)),
        f(Rule::NeededNotFailed, "arrival.peer")
    );
    let a = answer(slot::ARRIVAL, Outcome::Failed, &i, &o);
    assert_eq!(Transport::check(&a), Ok(()));
    assert!(Transport::short(&a));
}

#[test]
fn dial_flush_and_shut_have_no_per_answer_rule() {
    let o: ConnOut = z();
    let h: OutHead = z();
    for outcome in [Outcome::Ready, Outcome::Failed] {
        assert_eq!(
            Transport::check(&answer(slot::DIAL, outcome, &z::<DialIn>(), &o)),
            Ok(())
        );
        assert_eq!(
            Transport::check(&answer(slot::FLUSH, outcome, &z::<ConnIn>(), &h)),
            Ok(())
        );
        assert_eq!(
            Transport::check(&answer(slot::SHUT, outcome, &z::<ShutIn>(), &h)),
            Ok(())
        );
    }
}

// ── framer ──

#[test]
fn locate_green_red_and_short() {
    let mut i: LocateIn = z();
    i.authority_cap = 32;
    i.name_cap = 32;
    let mut o: LocateOut = z();
    o.authority_written = 10;
    o.has_name = 1;
    o.name_written = 5;
    o.secure = 1;
    assert_eq!(
        Transport::check(&answer(slot::LOCATE, Outcome::Ready, &i, &o)),
        Ok(())
    );
    o.has_name = 0;
    assert_eq!(
        Transport::check(&answer(slot::LOCATE, Outcome::Ready, &i, &o)),
        f(Rule::Contradiction, "locate.name_without_has_name")
    );
    let mut o: LocateOut = z();
    o.authority_needed = 64;
    let a = answer(slot::LOCATE, Outcome::Failed, &i, &o);
    assert_eq!(Transport::check(&a), Ok(()));
    assert!(Transport::short(&a));
}

fn piece(offset: u64, len: u64) -> FramePiece {
    let mut p: FramePiece = z();
    p.offset = offset;
    p.len = len;
    p.flags = PIECE_END_OF_FRAME;
    p
}

fn sink(pieces: &mut [FramePiece]) -> FramerSink {
    let mut s: FramerSink = z();
    s.wire_cap = 64;
    s.frame_cap = 64;
    s.pieces = pieces.as_mut_ptr();
    s.pieces_cap = pieces.len();
    s
}

/// One framer op's answer over a given `out` and outcome.
type FramerCall = Box<dyn Fn(&FramerOut, Outcome) -> Answer>;

/// Every framer op's slot, with an `in` of its own struct carrying `sink`.
fn framer_ins(s: FramerSink) -> Vec<(u32, FramerCall)> {
    fn with<I: 'static>(slot: u32, i: I) -> (u32, FramerCall) {
        let i = Box::leak(Box::new(i));
        (
            slot,
            Box::new(move |o, outcome| answer(slot, outcome, &*i, o)),
        )
    }
    let mut begin: BeginIn = z();
    begin.sink = s;
    let mut ingest: IngestIn = z();
    ingest.sink = s;
    let mut emit: EmitIn = z();
    emit.sink = s;
    let mut encode: EncodeIn = z();
    encode.sink = s;
    let mut refuse: RefuseIn = z();
    refuse.sink = s;
    let mut finish: FinishIn = z();
    finish.sink = s;
    let mut framing: FramingIn = z();
    framing.sink = s;
    let mut adopt: AdoptIn = z();
    adopt.sink = s;
    vec![
        with(slot::BEGIN, begin),
        with(slot::INGEST, ingest),
        with(slot::EMIT, emit),
        with(slot::ENCODE, encode),
        with(slot::REFUSE, refuse),
        with(slot::FINISH, finish),
        with(slot::DETACH, framing),
        with(slot::ADOPT, adopt),
        with(slot::TIMER, framing),
    ]
}

#[test]
fn every_framer_op_green_and_red() {
    let mut pieces = [piece(0, 4), piece(4, 4)];
    let ins = framer_ins(sink(&mut pieces));
    assert_eq!(ins.len(), 9);
    for (s, a) in &ins {
        let mut o: FramerOut = z();
        o.yielded.wire_len = 64;
        o.yielded.frame_len = 8;
        o.yielded.pieces_len = 2;
        o.yielded.flags = YIELD_MORE;
        assert_eq!(Transport::check(&a(&o, Outcome::Ready)), Ok(()), "slot {s}");
        assert!(!Transport::short(&a(&o, Outcome::Failed)), "slot {s}");
        o.yielded.frame_len = 7;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Ready)),
            f(Rule::SpanOutOfBounds, "framer.piece.bytes"),
            "slot {s}"
        );
        o.yielded.frame_len = 8;
        o.yielded.wire_len = 65;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Ready)),
            f(Rule::OverCap, "framer.wire_len"),
            "slot {s}"
        );
        o.yielded.wire_len = 1;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Failed)),
            f(Rule::Contradiction, "framer.failed_wrote"),
            "slot {s}"
        );
    }
}

#[test]
fn framer_pieces_one_past_the_cap_fault_before_any_slice() {
    let mut s: FramerSink = z();
    s.pieces = NonNull::<FramePiece>::dangling().as_ptr();
    s.pieces_cap = 4;
    for (slot, a) in &framer_ins(s) {
        let mut o: FramerOut = z();
        o.yielded.pieces_len = 5;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Ready)),
            f(Rule::OverCap, "framer.pieces_len"),
            "slot {slot}"
        );
    }
}

/// RED, through the one dispatcher: a field block carrying a pseudo-field (`:path`) is FAULT on
/// every framer op, and an accepted stream's request head is held to its slots.
#[test]
fn a_pseudo_field_or_a_bad_request_head_faults_every_framer_op() {
    let mut frame = *b":path: /\r\nx: 1\r\nGET/v1";
    let mut pieces = [piece(0, 16)];
    pieces[0].flags |= PIECE_FIELDS;
    let mut heads = [HeadSlots {
        stream: 0,
        method: FrameSpan { offset: 16, len: 3 },
        target: FrameSpan { offset: 19, len: 3 },
        ..HeadSlots::default()
    }];
    let mut s = sink(&mut pieces);
    s.frame = frame.as_mut_ptr();
    s.frame_cap = frame.len();
    s.heads = heads.as_mut_ptr();
    s.heads_cap = heads.len();
    for (slot, a) in &framer_ins(s) {
        let mut o: FramerOut = z();
        o.yielded.frame_len = 22;
        o.yielded.pieces_len = 1;
        o.yielded.heads_len = 1;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Ready)),
            f(Rule::Foreign, "framer.piece.pseudo_field"),
            "slot {slot}"
        );
    }
    pieces[0].offset = 10;
    pieces[0].len = 6;
    let s = {
        let mut s = sink(&mut pieces);
        s.frame = frame.as_mut_ptr();
        s.frame_cap = frame.len();
        s.heads = heads.as_mut_ptr();
        s.heads_cap = heads.len();
        s
    };
    for (slot, a) in &framer_ins(s) {
        let mut o: FramerOut = z();
        o.yielded.frame_len = 22;
        o.yielded.pieces_len = 1;
        o.yielded.heads_len = 1;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Ready)),
            Ok(()),
            "slot {slot}"
        );
        o.yielded.frame_len = 21;
        assert_eq!(
            Transport::check(&a(&o, Outcome::Ready)),
            f(Rule::SpanOutOfBounds, "framer.head.target"),
            "slot {slot}"
        );
    }
}

// ── cancel ──

#[test]
fn cancel_green_and_red_on_its_disposition() {
    let i: InHead = z();
    let mut o: CancelOut = z();
    for d in [CANCEL_NOTHING_MOVED, CANCEL_COMPLETED] {
        o.disposition = d;
        assert_eq!(
            Transport::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
            Ok(())
        );
    }
    for d in [0, CANCEL_COMPLETED + 1] {
        o.disposition = d;
        assert_eq!(
            Transport::check(&answer(life::CANCEL, Outcome::Ready, &i, &o)),
            f(Rule::UnknownCode, "cancel.disposition")
        );
    }
}

// ── foreign sizes ──

#[test]
fn an_in_smaller_than_the_ops_struct_is_foreign() {
    let i: InHead = z();
    let o = [0u64; 32];
    for s in [
        slot::LISTEN,
        slot::ACCEPT,
        slot::READ,
        slot::WRITE,
        slot::ARRIVAL,
        slot::LOCATE,
        slot::BEGIN,
        slot::INGEST,
        slot::EMIT,
        slot::ENCODE,
        slot::REFUSE,
        slot::FINISH,
        slot::DETACH,
        slot::ADOPT,
        slot::TIMER,
    ] {
        let r = Transport::check(&answer(s, Outcome::Ready, &i, &o));
        assert_eq!(r, f(Rule::Foreign, "in"), "slot {s}");
    }
}

#[test]
fn an_out_smaller_than_the_ops_struct_is_foreign() {
    let mut i: LocateIn = z();
    i.authority_cap = 8;
    let o: OutHead = z();
    assert_eq!(
        Transport::check(&answer(slot::LOCATE, Outcome::Ready, &i, &o)),
        f(Rule::Foreign, "out")
    );
}

// ── names, identity ──

#[test]
fn every_slot_has_a_name() {
    for s in 0..SLOTS {
        assert_ne!(Transport::op_name(s), "op", "slot {s}");
    }
    assert_eq!(Transport::op_name(slot::TIMER), "timer");
}

#[test]
fn the_kind_is_transport_and_times_out_failed() {
    assert_eq!(Transport::CODE, KindCode::Transport);
    assert_eq!(Transport::TIMEOUT, Outcome::Failed);
}

// ── the tail the registry view reads ──

/// A transport's tail is read and checked at bind: none refuses the load; a framer over the host's
/// socket states its claims and no layer.
#[test]
fn the_tail_is_read_at_bind_and_a_missing_one_refuses() {
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::transport::{Claim, TransportTail, ROLE_FRAMER};

    use crate::dispatch::kinds::transport::TransportFacts;

    let bare: Statement = statement("t", "0", 1);
    assert!(Transport::context(&bare).is_err(), "no tail, no load");

    let claims: [Claim; 2] = [
        Claim {
            selector_forms: abi_str(""),
            egress_selector_forms: abi_str(""),
            facts: std::ptr::null(),
            facts_len: 0,
            status_namespace: abi_str(""),
            session: 0,
            session_bound: 0,
            unit0_trigger: 0,
            status_at: 0,
            _reserved: 0,
        },
        Claim {
            selector_forms: abi_str(""),
            egress_selector_forms: abi_str(""),
            facts: std::ptr::null(),
            facts_len: 0,
            status_namespace: abi_str(""),
            session: 0,
            session_bound: 0,
            unit0_trigger: 0,
            status_at: 0,
            _reserved: 0,
        },
    ];
    let mut tail: TransportTail = z();
    tail.head = KindTailHead {
        size: size_of::<TransportTail>() as u32,
        _reserved: 0,
    };
    tail.role = ROLE_FRAMER;
    tail.claim_rows = claims.as_ptr();
    tail.claim_rows_len = 2;
    let names = [abi_str("one"), abi_str("two")];
    let st = Statement {
        kind_tail: std::ptr::from_ref(&tail).cast::<KindTailHead>(),
        claims: names.as_ptr(),
        claims_len: names.len(),
        ..bare
    };
    let ctx = Transport::context(&st)
        .expect("a framer tail binds")
        .expect("a context");
    let facts = ctx
        .downcast_ref::<TransportFacts>()
        .expect("the transport facts");
    assert_eq!(facts.claims, ["one", "two"]);
    assert!(facts.composes_over.is_empty());
    assert_eq!(facts.role, ROLE_FRAMER);
    // The names are the Statement's: a tail whose rows outnumber them is refused at bind.
    let one_name = Statement {
        claims_len: 1,
        ..st
    };
    assert!(Transport::context(&one_name).is_err(), "two rows, one name");
}

/// THE UPGRADE LINES ARE READ OFF THE CLAIM ROWS (ARCHITECT ruling Q128 U7): a claim whose row states
/// `unit0_trigger = UNIT0_UPGRADE` is an upgrade line, and a claim that states anything else is not —
/// RED: the same scheme with the trigger left at 0 yields an EMPTY upgrade set, so the host mounts no
/// upgrade line for it.
#[test]
fn an_upgrade_line_is_a_claim_whose_unit_zero_opens_at_the_upgrade() {
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::transport::{Claim, TransportTail, ROLE_FRAMER, UNIT0_UPGRADE};

    use crate::dispatch::kinds::transport::TransportFacts;

    let upgrades_of = |trigger: u8| -> Vec<&'static str> {
        let claims: [Claim; 1] = [Claim {
            selector_forms: abi_str(""),
            egress_selector_forms: abi_str(""),
            facts: std::ptr::null(),
            facts_len: 0,
            status_namespace: abi_str(""),
            session: 1,
            session_bound: 0,
            unit0_trigger: trigger,
            status_at: 0,
            _reserved: 0,
        }];
        let mut tail: TransportTail = z();
        tail.head = KindTailHead {
            size: size_of::<TransportTail>() as u32,
            _reserved: 0,
        };
        tail.role = ROLE_FRAMER;
        tail.claim_rows = claims.as_ptr();
        tail.claim_rows_len = 1;
        let names = [abi_str("up")];
        let st = Statement {
            kind_tail: std::ptr::from_ref(&tail).cast::<KindTailHead>(),
            claims: names.as_ptr(),
            claims_len: names.len(),
            ..statement("t", "0", 1)
        };
        let ctx = Transport::context(&st)
            .expect("a framer tail binds")
            .expect("a context");
        ctx.downcast_ref::<TransportFacts>()
            .expect("the transport facts")
            .upgrades
            .clone()
    };
    assert_eq!(
        upgrades_of(UNIT0_UPGRADE),
        ["up"],
        "the upgrade claim is a line"
    );
    assert!(
        upgrades_of(0).is_empty(),
        "RED: a claim that does not open at the upgrade is no upgrade line"
    );
}

/// THE FAULT TABLE AT BIND (busbar ARCHITECT breaker ruling Q1). A claim that classes its answers
/// states what they mean to the breaker too: a tail with status rows and no fault table is refused,
/// whether it was built before the table was appended (its size stops short of it, so the host
/// reads it absent) or after (it states none). A claim with a fault table binds; a tail with no
/// status rows owes none, so a carrier built before the append still binds.
#[test]
fn a_classed_claim_without_a_fault_table_is_refused_at_bind() {
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::transport::{
        Claim, FaultRow, StatusRow, TransportTail, FAULT_HARD, ROLE_CARRIER, ROLE_FRAMER,
        STATUS_CALLER_FAULT,
    };

    let claims: [Claim; 1] = [Claim {
        selector_forms: abi_str(""),
        egress_selector_forms: abi_str(""),
        facts: std::ptr::null(),
        facts_len: 0,
        status_namespace: abi_str("numbering"),
        session: 0,
        session_bound: 0,
        unit0_trigger: 0,
        status_at: 0,
        _reserved: 0,
    }];
    let status = [StatusRow {
        claim: 0,
        lo: 1,
        hi: 9,
        class: u32::from(STATUS_CALLER_FAULT),
    }];
    let faults = [FaultRow {
        claim: 0,
        lo: 1,
        hi: 9,
        fault: u32::from(FAULT_HARD),
    }];
    let names = [abi_str("one")];
    let bind = |tail: &TransportTail| {
        let st = Statement {
            kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
            claims: names.as_ptr(),
            claims_len: names.len(),
            ..statement("t", "0", 1)
        };
        Transport::context(&st).map(|_| ())
    };
    let mut tail: TransportTail = z();
    tail.head = KindTailHead {
        size: size_of::<TransportTail>() as u32,
        _reserved: 0,
    };
    tail.role = ROLE_FRAMER;
    tail.claim_rows = claims.as_ptr();
    tail.claim_rows_len = 1;
    tail.status_rows = status.as_ptr();
    tail.status_rows_len = 1;

    // RED: status rows, no fault table.
    let refused = bind(&tail).expect_err("a classed claim with no fault table is refused");
    assert!(refused.contains("fault_rows"), "{refused}");

    // GREEN: the same claim with its fault table.
    tail.fault_rows = faults.as_ptr();
    tail.fault_rows_len = 1;
    assert!(
        bind(&tail).is_ok(),
        "a classed claim with a fault table binds"
    );

    // A tail built before the append: the host reads its fault table as absent, so the same
    // status rows refuse it...
    tail.head.size = std::mem::offset_of!(TransportTail, fault_rows) as u32;
    assert!(
        bind(&tail).is_err(),
        "a pre-append framer that classes is refused"
    );
    // ...and a pre-append carrier that classes nothing still binds.
    tail.role = ROLE_CARRIER;
    tail.status_rows = std::ptr::null();
    tail.status_rows_len = 0;
    assert!(
        bind(&tail).is_ok(),
        "a pre-append tail that owes no fault table binds"
    );

    // A fault row that reads nothing is no row: refused.
    tail.head.size = size_of::<TransportTail>() as u32;
    let none = [FaultRow {
        fault: 0,
        ..faults[0]
    }];
    tail.fault_rows = none.as_ptr();
    tail.fault_rows_len = 1;
    assert!(bind(&tail).is_err(), "a FAULT_NONE row is refused");
}

/// RED (ARCHITECT ruling (c) on #953: compiled-in = dropped-in, one contract and one path): a
/// DROPPED-IN transport's offered points are read off its Statement's `extensions` at load, through
/// the same reader a linked door's are (`check_offered_points`, from `tail_facts`): a transport
/// stating `{Peer}` offers `{Peer}`, one stating no record `{Head, HeadBody}`, and a record of
/// another length refuses the load.
#[test]
fn a_dropped_in_transports_offered_points_are_read_off_its_statement() {
    use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::mechanism::extensions::encode;
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::transport::{Claim, TransportTail, EXT_OFFERED_POINTS, ROLE_FRAMER};

    use crate::dispatch::kinds::transport::TransportFacts;

    let offered = |extensions: &[u8]| -> Result<AuthPoints, String> {
        let claims: [Claim; 1] = [Claim {
            selector_forms: abi_str(""),
            egress_selector_forms: abi_str(""),
            facts: std::ptr::null(),
            facts_len: 0,
            status_namespace: abi_str(""),
            session: 0,
            session_bound: 0,
            unit0_trigger: 0,
            status_at: 0,
            _reserved: 0,
        }];
        let mut tail: TransportTail = z();
        tail.head = KindTailHead {
            size: size_of::<TransportTail>() as u32,
            _reserved: 0,
        };
        tail.role = ROLE_FRAMER;
        tail.claim_rows = claims.as_ptr();
        tail.claim_rows_len = 1;
        let names = [abi_str("own")];
        let st = Statement {
            kind_tail: std::ptr::from_ref(&tail).cast::<KindTailHead>(),
            claims: names.as_ptr(),
            claims_len: names.len(),
            extensions: Blob {
                ptr: if extensions.is_empty() {
                    std::ptr::null()
                } else {
                    extensions.as_ptr()
                },
                len: extensions.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            },
            ..statement("t", "0", 1)
        };
        let ctx = Transport::context(&st)?.expect("a context");
        Ok(ctx
            .downcast_ref::<TransportFacts>()
            .expect("the transport facts")
            .offered)
    };
    let record = |v: &[u8]| encode(&[(EXT_OFFERED_POINTS, v)]);
    assert_eq!(
        offered(&record(&POINT_PEER.to_le_bytes())),
        Ok(AuthPoints::PEER),
        "a transport stating {{Peer}} offers {{Peer}}"
    );
    assert_eq!(
        offered(&[]),
        Ok(AuthPoints(POINT_HEAD | POINT_HEAD_BODY)),
        "no record offers {{Head, HeadBody}}"
    );
    assert!(
        offered(&record(&[1, 0])).is_err(),
        "a short record refuses the load"
    );
}

/// RED (#65, #74): a dial's `begin` carrying the binding's auth handle is admitted only for the
/// framer it was minted for, at the published generation, with its mac as minted; a malformed
/// binding is refused too. Every refusal is before the crossing.
#[test]
fn a_dial_begin_with_a_foreign_stale_or_forged_binding_ref_is_refused() {
    use crate::dispatch::auth_handle::{generation, mint_auth_ref};
    use busbar_contract::abi::host::service::AuthRef;
    use busbar_contract::abi::transport::{POINT_HEAD, SIDE_ACCEPT, SIDE_DIAL};
    let (framer, other) = (40, 41);
    let admit = |i: &BeginIn, owner: u64| {
        Transport::admit(
            slot::BEGIN,
            std::ptr::from_ref(i).cast(),
            size_of::<BeginIn>(),
            owner,
        )
    };
    let mut i: BeginIn = z();
    i.side = SIDE_DIAL;
    i.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    assert_eq!(admit(&i, framer), None, "a binding with no auth");
    i.points = POINT_HEAD;
    i.auth = mint_auth_ref(framer, generation(), 9).expect("minted");
    assert_eq!(admit(&i, framer), None, "the framer's own handle");
    assert_eq!(admit(&i, other), Some(Outcome::Refused), "another owner's");
    let mut stale = i;
    stale.auth = mint_auth_ref(framer, generation().wrapping_sub(1), 9).expect("minted");
    assert_eq!(admit(&stale, framer), Some(Outcome::Refused), "stale");
    let mut forged = i;
    forged.auth.mac ^= 1 << 17;
    assert_eq!(admit(&forged, framer), Some(Outcome::Refused), "forged");
    let mut unbound = i;
    unbound.auth = AuthRef::NONE;
    assert_eq!(
        admit(&unbound, framer),
        Some(Outcome::Refused),
        "points with no handle"
    );
    let mut accept = i;
    accept.side = SIDE_ACCEPT;
    assert_eq!(
        admit(&accept, framer),
        Some(Outcome::Refused),
        "a handle on accept"
    );
    // Only `begin` is judged, and only a frame that holds a `BeginIn`.
    assert_eq!(
        Transport::admit(
            slot::INGEST,
            std::ptr::from_ref(&forged).cast(),
            size_of::<BeginIn>(),
            framer
        ),
        None
    );
}

/// RED (/status row 192 B; #65, #74; THE DESIGN §6 steps 3 and 4): an accepting `begin` is lent
/// its listener's guest list only with every line's handle minted for THE TRANSPORT THAT FRAMES IT,
/// at the published generation, with its mac as minted: a line of another owner (the root's own
/// identity among them), of another generation or forged is REFUSED before the crossing, and so is
/// a malformed table (`check_lines`: a handle-less line, a count behind NULL, lines on a dial).
#[test]
fn red_an_accept_begin_is_lent_only_lines_minted_for_its_own_transport() {
    use crate::dispatch::auth_handle::{generation, mint_auth_ref};
    use busbar_contract::abi::host::service::{AuthRef, SCHEME_PLAIN};
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::transport::route::{LineEntry, RouteMatch, METHOD_ANY, PATH_PREFIX};
    use busbar_contract::abi::transport::{POINT_HEAD, SIDE_ACCEPT, SIDE_DIAL};
    let (framer, other) = (40, 41);
    let admit = |i: &BeginIn, owner: u64| {
        Transport::admit(
            slot::BEGIN,
            std::ptr::from_ref(i).cast(),
            size_of::<BeginIn>(),
            owner,
        )
    };
    let path = b"/v1";
    let line = |id: u32, auth: AuthRef| LineEntry {
        line: id,
        points: POINT_HEAD,
        auth,
        body_limit: 0,
        route: RouteMatch {
            methods: METHOD_ANY,
            path_form: PATH_PREFIX,
            path: AbiStr {
                ptr: path.as_ptr(),
                len: path.len(),
            },
            fields: std::ptr::null(),
            fields_len: 0,
            rung: 0,
            _reserved: 0,
        },
    };
    let minted = |owner: u64, generation: u64, id: u64| {
        mint_auth_ref(owner, generation, id).expect("minted")
    };
    let begin = |lines: &[LineEntry]| {
        let mut i: BeginIn = z();
        i.side = SIDE_ACCEPT;
        i.scheme = SCHEME_PLAIN;
        i.lines = lines.as_ptr();
        i.lines_len = lines.len();
        i
    };
    let own = [
        line(0, minted(framer, generation(), 5)),
        line(1, minted(framer, generation(), 6)),
    ];
    assert_eq!(
        admit(&begin(&own), framer),
        None,
        "lines minted for the transport that frames them"
    );
    assert_eq!(
        admit(&begin(&own), other),
        Some(Outcome::Refused),
        "another transport's lines"
    );
    let rooted = [line(0, minted(0, generation(), 5))];
    assert_eq!(
        admit(&begin(&rooted), framer),
        Some(Outcome::Refused),
        "lines keyed by the root's own identity"
    );
    let stale = [
        line(0, minted(framer, generation(), 5)),
        line(1, minted(framer, generation().wrapping_sub(1), 6)),
    ];
    assert_eq!(
        admit(&begin(&stale), framer),
        Some(Outcome::Refused),
        "a stale line"
    );
    let mut forged = own;
    forged[1].auth.mac ^= 1 << 17;
    assert_eq!(
        admit(&begin(&forged), framer),
        Some(Outcome::Refused),
        "a forged line"
    );
    let unbound = [line(0, AuthRef::NONE)];
    assert_eq!(
        admit(&begin(&unbound), framer),
        Some(Outcome::Refused),
        "a line with no handle"
    );
    let mut hidden = begin(&own);
    hidden.lines = std::ptr::null();
    assert_eq!(
        admit(&hidden, framer),
        Some(Outcome::Refused),
        "a count behind NULL"
    );
    let mut dialled = begin(&own);
    dialled.side = SIDE_DIAL;
    assert_eq!(
        admit(&dialled, framer),
        Some(Outcome::Refused),
        "lines on a dial"
    );
}

/// RED: a `begin` whose scheme is undeclared (`0`, a zeroed `in`) or unknown is REFUSED before
/// the crossing, on every side; a declared scheme is admitted.
#[test]
fn a_begin_with_an_undeclared_scheme_is_refused() {
    use busbar_contract::abi::host::service::{SCHEME_PLAIN, SCHEME_SECURE};
    use busbar_contract::abi::transport::{SIDE_ACCEPT, SIDE_ACCEPT_STREAM, SIDE_DIAL};
    let admit = |i: &BeginIn| {
        Transport::admit(
            slot::BEGIN,
            std::ptr::from_ref(i).cast(),
            size_of::<BeginIn>(),
            40,
        )
    };
    for side in [SIDE_DIAL, SIDE_ACCEPT, SIDE_ACCEPT_STREAM] {
        let mut i: BeginIn = z();
        i.side = side;
        assert_eq!(admit(&i), Some(Outcome::Refused), "an undeclared scheme");
        i.scheme = SCHEME_SECURE + 1;
        assert_eq!(admit(&i), Some(Outcome::Refused), "an unknown scheme");
        for scheme in [SCHEME_PLAIN, SCHEME_SECURE] {
            i.scheme = scheme;
            assert_eq!(admit(&i), None, "a declared scheme");
        }
    }
}

/// RED (the opening body's length): an `emit` whose `body_len` breaks the contract (a length with
/// `body_len_known` `0`, a flag past `1`, a padding byte) is the host's own fault and never
/// crosses; a known length, and no length at all, cross.
#[test]
fn an_emit_whose_body_length_breaks_the_contract_never_crosses() {
    let admit = |i: &EmitIn| {
        Transport::admit(
            slot::EMIT,
            std::ptr::from_ref(i).cast(),
            size_of::<EmitIn>(),
            40,
        )
    };
    let mut i: EmitIn = z();
    assert_eq!(admit(&i), None, "no length stated");
    i.body_len_known = 1;
    i.body_len = 12;
    assert_eq!(admit(&i), None, "a whole body's length");
    let mut streamed = i;
    streamed.body_len_known = 0;
    assert_eq!(
        admit(&streamed),
        Some(Outcome::Fault),
        "a length a streamed body states"
    );
    let mut flag = i;
    flag.body_len_known = 2;
    assert_eq!(admit(&flag), Some(Outcome::Fault), "a flag past 1");
    let mut pad = i;
    pad._body_len_reserved = 1;
    assert_eq!(admit(&pad), Some(Outcome::Fault), "the padding");
}

/// RED (deadline classes, the op contracts): a TICKETED framer crossing is stamped with the class
/// its op's contract states, `Stream` for `begin`, `ingest` and `emit` (a pending auth call inside
/// one runs under the stream's deadline), never the carrier's `Connection`; a carrier's ticketed
/// I/O keeps `Connection`; a ticket-less crossing is `Call`.
#[test]
fn a_ticketed_framer_crossing_is_stamped_with_its_contracts_class() {
    use crate::dispatch::plugin::stamped_class;
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    let real = Ticket {
        slot: 3,
        generation: 7,
    };
    for s in [slot::BEGIN, slot::INGEST, slot::EMIT] {
        assert_eq!(
            stamped_class::<Transport>(s, real),
            DeadlineClass::Stream,
            "{} on a ticket",
            Transport::op_name(s)
        );
        assert_eq!(
            stamped_class::<Transport>(s, Ticket::NONE),
            DeadlineClass::Call,
            "{} ticket-less",
            Transport::op_name(s)
        );
    }
    for s in [slot::READ, slot::WRITE, slot::DIAL, slot::ACCEPT] {
        assert_eq!(
            stamped_class::<Transport>(s, real),
            DeadlineClass::Connection,
            "{} on a ticket",
            Transport::op_name(s)
        );
    }
}

/// RED (audit contract-src #11): every string list a transport's tail states is judged at bind by
/// its own contract check, so a name counted over a NULL pointer refuses the load. The claims a
/// connection may upgrade to (`check_upgrades_to`) and each claim row's fact keys
/// (`check_claim_facts`) were never judged by the host.
#[test]
fn red_a_null_upgrade_name_or_claim_fact_refuses_the_bind() {
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::door::{abi_str, statement};
    use busbar_contract::abi::transport::{Claim, TransportTail, ROLE_FRAMER};

    let broken = AbiStr {
        ptr: std::ptr::null(),
        len: 3,
    };
    let bind = |upgrades: &[AbiStr], facts: &[AbiStr]| -> Result<(), String> {
        let claims: [Claim; 1] = [Claim {
            selector_forms: abi_str(""),
            egress_selector_forms: abi_str(""),
            facts: if facts.is_empty() {
                std::ptr::null()
            } else {
                facts.as_ptr()
            },
            facts_len: facts.len(),
            status_namespace: abi_str(""),
            session: 0,
            session_bound: 0,
            unit0_trigger: 0,
            status_at: 0,
            _reserved: 0,
        }];
        let mut tail: TransportTail = z();
        tail.head = KindTailHead {
            size: size_of::<TransportTail>() as u32,
            _reserved: 0,
        };
        tail.role = ROLE_FRAMER;
        tail.claim_rows = claims.as_ptr();
        tail.claim_rows_len = 1;
        if !upgrades.is_empty() {
            tail.upgrades_to = upgrades.as_ptr();
            tail.upgrades_to_len = upgrades.len();
        }
        let names = [abi_str("own")];
        let st = Statement {
            kind_tail: std::ptr::from_ref(&tail).cast::<KindTailHead>(),
            claims: names.as_ptr(),
            claims_len: names.len(),
            ..statement("t", "0", 1)
        };
        Transport::context(&st).map(|_| ())
    };
    let good = [abi_str("next-claim")];
    assert_eq!(bind(&good, &good), Ok(()), "named lists bind");
    assert!(
        bind(&[abi_str("next-claim"), broken], &[]).is_err(),
        "an upgrade name counted over a NULL pointer bound"
    );
    assert!(
        bind(&[], &[broken]).is_err(),
        "a claim fact key counted over a NULL pointer bound"
    );
}
