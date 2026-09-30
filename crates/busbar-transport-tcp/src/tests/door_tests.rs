// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity framer, driven through its own table the way the host drives it: every answer is
//! judged by the kind's `check_framer`, a full sink is back-pressure re-called with no new bytes,
//! and every byte comes out exactly once, in order.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::check::{check_framer, check_tail};
use busbar_contract::abi::transport::{
    slot, AdoptIn, BeginIn, ConnOut, DialIn, EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut,
    FramerSink, FramingIn, IngestIn, LocateIn, LocateOut, Ops, TransportTail, PIECE_END_OF_FRAME,
    ROLE_FRAMER, SIDE_ACCEPT, YIELD_ENDED, YIELD_MORE,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(t: &'static str) -> AbiStr {
    AbiStr {
        ptr: t.as_ptr(),
        len: t.len(),
    }
}

fn ops() -> &'static Ops {
    let d: *const Door = super::door();
    // SAFETY: the door answers a `'static` door whose table is this kind's `Ops`.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    )
    .outcome()
}

/// The host: an open instance, one framing, and a sink of the given capacities.
struct Host {
    inst: *mut c_void,
    framing: u64,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    /// Everything the framer answered: wire bytes, and frame bytes with their pieces' flags.
    wire_log: Vec<u8>,
    frames: Vec<(Vec<u8>, u16)>,
    flags: u32,
}

impl Host {
    fn new(wire: usize, frame: usize, pieces: usize) -> Self {
        let mut i: OpenIn = z();
        let mut o: OpenOut = z();
        let r = call(
            ops().head.open,
            std::ptr::null_mut(),
            &mut i,
            &mut o,
            life::OPEN,
        );
        assert_eq!(r, Outcome::Ready);
        let mut h = Self {
            inst: o.instance,
            framing: 0,
            wire: vec![0; wire],
            frame: vec![0; frame],
            pieces: vec![z(); pieces],
            wire_log: Vec::new(),
            frames: Vec::new(),
            flags: 0,
        };
        let mut i: BeginIn = z();
        i.side = SIDE_ACCEPT;
        i.sink = h.sink();
        let mut o: FramerOut = z();
        let r = call(ops().begin, h.inst, &mut i, &mut o, slot::BEGIN);
        h.framing = o.framing;
        h.take(r, &o);
        h
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
        }
    }

    fn take(&mut self, r: Outcome, o: &FramerOut) -> Outcome {
        let n = o.yielded.pieces_len as usize;
        check_framer(
            r,
            o,
            &self.pieces[..n],
            self.wire.len() as u64,
            self.frame.len() as u64,
            self.pieces.len() as u64,
        )
        .expect("the answer passes the kind's check");
        self.wire_log
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        for p in &self.pieces[..n] {
            assert_eq!(p.stream, 0, "a byte stream has one stream");
            let at = p.offset as usize;
            self.frames
                .push((self.frame[at..at + p.len as usize].to_vec(), p.flags));
        }
        self.flags = o.yielded.flags;
        r
    }

    /// Re-call `index` with no new bytes until it stops owing.
    fn drain(&mut self, index: u32) {
        while self.flags & YIELD_MORE != 0 {
            let mut o: FramerOut = z();
            let r = if index == slot::INGEST {
                let mut i: IngestIn = z();
                i.framing = self.framing;
                i.sink = self.sink();
                call(ops().ingest, self.inst, &mut i, &mut o, index)
            } else {
                let mut i: EmitIn = z();
                i.framing = self.framing;
                i.sink = self.sink();
                call(ops().emit, self.inst, &mut i, &mut o, index)
            };
            assert_eq!(self.take(r, &o), Outcome::Ready);
        }
    }

    fn ingest(&mut self, bytes: &[u8], end: bool) {
        let mut i: IngestIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end = u32::from(end);
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(ops().ingest, self.inst, &mut i, &mut o, slot::INGEST);
        assert_eq!(self.take(r, &o), Outcome::Ready);
        self.drain(slot::INGEST);
    }

    fn emit(&mut self, bytes: &[u8]) {
        let mut i: EmitIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = 1;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(ops().emit, self.inst, &mut i, &mut o, slot::EMIT);
        assert_eq!(self.take(r, &o), Outcome::Ready);
        self.drain(slot::EMIT);
    }

    fn joined(&self) -> Vec<u8> {
        self.frames.iter().flat_map(|(b, _)| b.clone()).collect()
    }
}

#[test]
fn the_tail_is_a_framer_over_the_host_socket() {
    let st = super::STATEMENT;
    // SAFETY: the Statement's kind tail is this crate's `'static` `TransportTail`.
    let tail = unsafe { &*st.kind_tail.cast::<TransportTail>() };
    assert_eq!(tail.role, ROLE_FRAMER);
    assert_eq!(tail.composes_over_len, 0);
    assert_eq!(check_tail(tail), Ok(()));
}

#[test]
fn one_read_is_one_frame_byte_exact() {
    let mut h = Host::new(64, 64, 4);
    h.ingest(b"hello, far side", false);
    assert_eq!(
        h.frames,
        vec![(b"hello, far side".to_vec(), PIECE_END_OF_FRAME)]
    );
    h.ingest(b"again", false);
    assert_eq!(h.frames.len(), 2, "a second read is a second frame");
    assert_eq!(h.joined(), b"hello, far sideagain");
    assert_eq!(h.flags & YIELD_ENDED, 0);
}

#[test]
fn a_full_frame_sink_is_back_pressure_and_every_byte_comes_out_once() {
    let mut h = Host::new(64, 3, 1);
    let sent: Vec<u8> = (0..=250).collect();
    h.ingest(&sent, false);
    assert_eq!(h.joined(), sent, "every byte, once, in order");
    let ends = h
        .frames
        .iter()
        .filter(|(_, f)| f & PIECE_END_OF_FRAME != 0)
        .count();
    assert_eq!(ends, 1, "the read is one frame, ended by its last piece");
    assert_ne!(h.frames.last().unwrap().1 & PIECE_END_OF_FRAME, 0);
}

#[test]
fn emit_is_the_wire_and_a_full_wire_sink_is_back_pressure() {
    let mut h = Host::new(5, 8, 1);
    let sent: Vec<u8> = (0..=99).collect();
    h.emit(&sent);
    assert_eq!(h.wire_log, sent);
    assert!(h.frames.is_empty());
}

#[test]
fn the_far_sides_end_ends_the_connection_after_its_bytes() {
    let mut h = Host::new(64, 2, 1);
    h.ingest(b"last", true);
    assert_eq!(h.joined(), b"last");
    assert_eq!(h.flags, YIELD_ENDED);
}

#[test]
fn encode_is_the_body_and_fields_are_refused() {
    let mut h = Host::new(64, 8, 1);
    let body = b"raw bytes";
    let mut i: EncodeIn = z();
    i.body = body.as_ptr();
    i.body_len = body.len();
    i.sink = h.sink();
    let mut o: FramerOut = z();
    let r = call(ops().encode, h.inst, &mut i, &mut o, slot::ENCODE);
    assert_eq!(r, Outcome::Ready);
    assert_eq!(&h.wire[..o.yielded.wire_len as usize], body);
    let fields = [Field {
        name: s("host"),
        value: s("x"),
    }];
    i.fields = fields.as_ptr();
    i.fields_len = 1;
    let mut o: FramerOut = z();
    let r = call(ops().encode, h.inst, &mut i, &mut o, slot::ENCODE);
    assert_eq!(r, Outcome::Failed);
    assert_eq!(o.yielded.wire_len, 0);
}

#[test]
fn locate_reads_host_and_port_and_offers_nothing() {
    let h = Host::new(1, 1, 1);
    for (target, want) in [
        ("127.0.0.1:5432", "127.0.0.1:5432"),
        ("tcp://db.internal:5432", "db.internal:5432"),
        ("[::1]:6379", "[::1]:6379"),
    ] {
        let mut buf = [0_u8; 64];
        let mut i: LocateIn = z();
        i.target = s(target);
        i.authority_buf = buf.as_mut_ptr();
        i.authority_cap = buf.len();
        let mut o: LocateOut = z();
        let r = call(ops().locate, h.inst, &mut i, &mut o, slot::LOCATE);
        assert_eq!(r, Outcome::Ready, "{target}");
        assert_eq!(&buf[..o.authority_written as usize], want.as_bytes());
        assert_eq!((o.secure, o.has_name), (0, 0));
    }
    let mut i: LocateIn = z();
    i.target = s("http://x/y");
    let mut o: LocateOut = z();
    assert_eq!(
        call(ops().locate, h.inst, &mut i, &mut o, slot::LOCATE),
        Outcome::Failed
    );
    // A short authority buffer answers what it needs and writes nothing.
    let mut buf = [0_u8; 2];
    let mut i: LocateIn = z();
    i.target = s("127.0.0.1:1");
    i.authority_buf = buf.as_mut_ptr();
    i.authority_cap = buf.len();
    let mut o: LocateOut = z();
    assert_eq!(
        call(ops().locate, h.inst, &mut i, &mut o, slot::LOCATE),
        Outcome::Failed
    );
    assert_eq!((o.authority_needed, o.authority_written), (11, 0));
}

#[test]
fn detach_hands_back_the_unanswered_bytes_and_adopt_answers_them_first() {
    // A pieceless sink: the ingested bytes stay owed, unanswered.
    let mut h = Host::new(8, 8, 0);
    let mut i: IngestIn = z();
    i.framing = h.framing;
    i.bytes = b"upgrade-leftover".as_ptr();
    i.len = 16;
    i.sink = h.sink();
    let mut o: FramerOut = z();
    let r = call(ops().ingest, h.inst, &mut i, &mut o, slot::INGEST);
    assert_eq!(h.take(r, &o), Outcome::Ready);
    assert_eq!(h.flags, YIELD_MORE);
    let mut left = Vec::new();
    loop {
        let mut i: FramingIn = z();
        i.framing = h.framing;
        i.sink = h.sink();
        let mut o: FramerOut = z();
        let r = call(ops().detach, h.inst, &mut i, &mut o, slot::DETACH);
        assert_eq!(r, Outcome::Ready);
        left.extend_from_slice(&h.frame[..o.yielded.frame_len as usize]);
        if o.yielded.flags == YIELD_ENDED {
            break;
        }
    }
    assert_eq!(left, b"upgrade-leftover");

    let mut g = Host::new(8, 64, 1);
    let mut i: AdoptIn = z();
    i.leftover = left.as_ptr();
    i.leftover_len = left.len();
    i.sink = g.sink();
    let mut o: FramerOut = z();
    let r = call(ops().adopt, g.inst, &mut i, &mut o, slot::ADOPT);
    g.framing = o.framing;
    assert_eq!(g.take(r, &o), Outcome::Ready);
    assert_eq!(g.joined(), b"upgrade-leftover");
}

#[test]
fn finish_forgets_the_framing() {
    let mut h = Host::new(8, 8, 1);
    let mut i: FinishIn = z();
    i.framing = h.framing;
    i.sink = h.sink();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().finish, h.inst, &mut i, &mut o, slot::FINISH),
        Outcome::Ready
    );
    assert_eq!(o.yielded.flags, YIELD_ENDED);
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().finish, h.inst, &mut i, &mut o, slot::FINISH),
        Outcome::Failed
    );
}

#[test]
fn every_carrier_op_is_refused_the_socket_is_the_hosts() {
    let h = Host::new(1, 1, 1);
    let mut i: DialIn = z();
    let mut o: ConnOut = z();
    assert_eq!(
        call(ops().dial, h.inst, &mut i, &mut o, slot::DIAL),
        Outcome::Refused
    );
}
