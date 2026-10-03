// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio LINE FRAMER, driven through its own table the way the host's connector drives it over
//! a program's pipes: every answer judged by the kind's `check_framer`, a full sink re-called with
//! no new bytes. One frame per line; a message goes out as one line; a stdio target is never
//! located (the connector spawns the program). An integration test, so the crate itself keeps
//! `#![deny(unsafe_code)]`: driving a raw table is the host's side.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::check::{check_framer, check_tail};
use busbar_contract::abi::transport::{
    slot, BeginIn, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, IngestIn, LocateIn,
    LocateOut, Ops, TransportTail, PIECE_END_OF_FRAME, ROLE_FRAMER, SIDE_DIAL, YIELD_ENDED,
    YIELD_MORE,
};
use busbar_transport_stdio::door::{door, MAX_LINE_BYTES, STATEMENT};

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
    let d: *const Door = door();
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
    wire_log: Vec<u8>,
    /// Whole frames, as the pieces built them.
    frames: Vec<Vec<u8>>,
    partial: Vec<u8>,
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
            partial: Vec::new(),
            flags: 0,
        };
        let mut i: BeginIn = z();
        i.side = SIDE_DIAL;
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
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    fn take(&mut self, r: Outcome, o: &FramerOut) -> Outcome {
        if r != Outcome::Ready {
            return r;
        }
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
            assert_eq!(p.stream, 0);
            let at = p.offset as usize;
            self.partial
                .extend_from_slice(&self.frame[at..at + p.len as usize]);
            if p.flags & PIECE_END_OF_FRAME != 0 {
                self.frames.push(std::mem::take(&mut self.partial));
            }
        }
        self.flags = o.yielded.flags;
        r
    }

    fn drain(&mut self) {
        while self.flags & YIELD_MORE != 0 {
            let mut o: FramerOut = z();
            let mut i: IngestIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let r = call(ops().ingest, self.inst, &mut i, &mut o, slot::INGEST);
            assert_eq!(self.take(r, &o), Outcome::Ready);
        }
    }

    fn ingest(&mut self, bytes: &[u8], end: bool) -> Outcome {
        let mut i: IngestIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end = u32::from(end);
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(ops().ingest, self.inst, &mut i, &mut o, slot::INGEST);
        let r = self.take(r, &o);
        if r == Outcome::Ready {
            self.drain();
        }
        r
    }

    fn emit(&mut self, bytes: &[u8], end: bool) -> Outcome {
        let mut i: EmitIn = z();
        i.framing = self.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end);
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(ops().emit, self.inst, &mut i, &mut o, slot::EMIT);
        self.take(r, &o)
    }
}

#[test]
fn the_tail_is_a_framer_composing_over_nothing() {
    let st = STATEMENT;
    // SAFETY: the Statement's kind tail is this crate's `'static` `TransportTail`.
    let tail = unsafe { &*st.kind_tail.cast::<TransportTail>() };
    assert_eq!(tail.role, ROLE_FRAMER);
    assert_eq!(tail.composes_over_len, 0);
    assert_eq!(check_tail(tail), Ok(()));
}

#[test]
fn every_line_is_one_frame_with_its_newline_stripped() {
    let mut h = Host::new(64, 64, 4);
    assert_eq!(h.ingest(b"{\"id\":1}\n{\"id\"", false), Outcome::Ready);
    assert_eq!(h.frames, vec![b"{\"id\":1}".to_vec()]);
    assert_eq!(h.ingest(b":2}\r\n\nlast", false), Outcome::Ready);
    assert_eq!(
        h.frames,
        vec![b"{\"id\":1}".to_vec(), b"{\"id\":2}".to_vec(), Vec::new()],
        "a carriage return before the newline is stripped; an empty line is an empty frame"
    );
    assert_eq!(h.flags & YIELD_ENDED, 0);
    // The far side's end: the unterminated rest is its last frame, then the connection ends.
    assert_eq!(h.ingest(b"", true), Outcome::Ready);
    assert_eq!(h.frames.last().unwrap(), b"last");
    assert_eq!(h.flags, YIELD_ENDED);
}

#[test]
fn a_small_sink_is_back_pressure_and_every_line_comes_out_whole_once() {
    let mut h = Host::new(64, 3, 1);
    let lines: Vec<Vec<u8>> = (0..5).map(|n| vec![b'a' + n; 7]).collect();
    let mut sent = Vec::new();
    for l in &lines {
        sent.extend_from_slice(l);
        sent.push(b'\n');
    }
    assert_eq!(h.ingest(&sent, false), Outcome::Ready);
    assert_eq!(h.frames, lines);
}

#[test]
fn a_message_goes_out_as_one_line_once_its_last_piece_arrives() {
    let mut h = Host::new(64, 8, 1);
    assert_eq!(h.emit(b"{\"jsonrpc\"", false), Outcome::Ready);
    assert!(h.wire_log.is_empty(), "nothing before the message is whole");
    assert_eq!(h.emit(b":\"2.0\"}", true), Outcome::Ready);
    assert_eq!(h.wire_log, b"{\"jsonrpc\":\"2.0\"}\n");
}

#[test]
fn a_message_that_is_not_one_line_is_refused_before_a_byte_is_written() {
    let mut h = Host::new(64, 8, 1);
    assert_ne!(h.emit(b"two\nlines", true), Outcome::Ready);
    assert_ne!(h.emit(b"ends-in-cr\r", true), Outcome::Ready);
    assert!(h.wire_log.is_empty());
}

#[test]
fn a_line_past_the_ceiling_fails_the_framing() {
    let mut h = Host::new(64, 64, 4);
    let long = vec![b'x'; MAX_LINE_BYTES + 1];
    assert_ne!(h.ingest(&long, false), Outcome::Ready);
}

#[test]
fn a_stdio_target_is_never_located_and_an_envelope_is_its_body_as_one_line() {
    let mut h = Host::new(64, 8, 1);
    let mut auth = [0_u8; 64];
    let mut i: LocateIn = z();
    i.target = s("/bin/cat");
    i.authority_buf = auth.as_mut_ptr();
    i.authority_cap = auth.len();
    let mut o: LocateOut = z();
    assert_ne!(
        call(ops().locate, h.inst, &mut i, &mut o, slot::LOCATE),
        Outcome::Ready
    );
    let body = b"{\"id\":1}";
    let mut i: EncodeIn = z();
    i.body = body.as_ptr();
    i.body_len = body.len();
    i.sink = h.sink();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().encode, h.inst, &mut i, &mut o, slot::ENCODE),
        Outcome::Ready
    );
    assert_eq!(&h.wire[..o.yielded.wire_len as usize], b"{\"id\":1}\n");
    let fields = [Field {
        name: s("host"),
        value: s("x"),
    }];
    let mut i: EncodeIn = z();
    i.fields = fields.as_ptr();
    i.fields_len = fields.len();
    i.sink = h.sink();
    let mut o: FramerOut = z();
    assert_ne!(
        call(ops().encode, h.inst, &mut i, &mut o, slot::ENCODE),
        Outcome::Ready
    );
}
