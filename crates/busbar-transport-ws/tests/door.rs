// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `ws` DOOR, ON THE TRANSPORT KIND'S TABLE: the same door, compiled in and dropped in, driven the same way.
//!
//! The test is the HOST, and it holds BOTH ends: one framing dialled and one accepted, on the same
//! door, with the host carrying each one's wire bytes to the other exactly as a connector carries
//! them over a socket. Every answer is judged by the kind's own `check_framer`. The exchange: the
//! upgrade, one message each way, and an orderly close that ends the far side's stream and its
//! connection. It runs through the linked door and through the cdylib `cargo test` built from
//! `examples/ws_door.rs`, through a roomy sink and through one so small every op is re-called.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{AbiStr, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::abi::transport::check::check_framer;
use busbar_contract::abi::transport::{
    slot, BeginIn, EmitIn, FinishIn, FramePiece, FramerOut, FramerSink, IngestIn, Ops,
    CLOSE_NORMAL, EMIT_TEXT, PIECE_END_OF_FRAME, PIECE_TEXT, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED,
    YIELD_MORE,
};

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I`/`O` lead with their heads.
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*std::ptr::from_mut(o).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    let r = (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
    r.outcome()
}

/// One end: its framing, and everything it has said so far.
#[derive(Default)]
struct End {
    framing: u64,
    wire: Vec<u8>,
    frames: Vec<(Vec<u8>, bool)>,
    /// Per frame in `frames`: every message-bearing piece of it carried `PIECE_TEXT`.
    text: Vec<bool>,
    ended: bool,
}

struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    caps: (usize, usize, usize),
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    /// Every frame byte either end answered, in order: the re-call comparison reads it.
    log: Vec<u8>,
}

impl Host {
    fn open(ops: &'static Ops, caps: (usize, usize, usize)) -> Self {
        let mut i: OpenIn = z();
        let mut o: OpenOut = z();
        assert_eq!(
            call(
                ops.head.open,
                std::ptr::null_mut(),
                &mut i,
                &mut o,
                life::OPEN
            ),
            Outcome::Ready
        );
        Self {
            ops,
            inst: o.instance,
            caps,
            wire: vec![0; caps.0],
            frame: vec![0; caps.1],
            pieces: vec![z(); caps.2],
            log: Vec::new(),
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.caps.0,
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.caps.1,
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.caps.2,
            now_monotonic_ns: 3_000_000_000,
            now_unix_ns: 1_790_000_000_000_000_000,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// Take an answer into `end`; `true` = it asked to be called again.
    fn take(&mut self, r: Outcome, o: &FramerOut, end: &mut End) -> bool {
        assert_eq!(r, Outcome::Ready);
        let n = o.yielded.pieces_len as usize;
        check_framer(
            r,
            o,
            &self.pieces[..n],
            self.caps.0 as u64,
            self.caps.1 as u64,
            self.caps.2 as u64,
        )
        .expect("the answer passes the kind's check");
        end.wire
            .extend_from_slice(&self.wire[..o.yielded.wire_len as usize]);
        for p in &self.pieces[..n] {
            let b = &self.frame[p.offset as usize..(p.offset + p.len) as usize];
            self.log.extend_from_slice(b);
            match end.frames.last_mut() {
                Some((open, false)) => open.extend_from_slice(b),
                _ => {
                    end.frames.push((b.to_vec(), false));
                    end.text.push(true);
                }
            }
            if !b.is_empty() {
                *end.text.last_mut().expect("a frame") &= p.flags & PIECE_TEXT != 0;
            }
            if p.flags & PIECE_END_OF_FRAME != 0 {
                end.frames.last_mut().expect("a frame").1 = true;
            }
        }
        end.ended |= o.yielded.flags & YIELD_ENDED != 0;
        o.yielded.flags & YIELD_MORE != 0
    }

    fn begin(&mut self, side: u32, target: &'static str) -> End {
        let mut end = End::default();
        let mut i: BeginIn = z();
        i.side = side;
        i.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
        end.framing = o.framing;
        let more = self.take(r, &o, &mut end);
        self.again(more, &mut end);
        end
    }

    /// The `YIELD_MORE` re-call: an `ingest` with no new bytes, until the framing has said it all.
    fn again(&mut self, mut more: bool, end: &mut End) {
        let mut calls = 0;
        while more {
            calls += 1;
            assert!(calls < 100_000, "a re-call never ran dry");
            let mut i: IngestIn = z();
            i.framing = end.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
            more = self.take(r, &o, end);
        }
    }

    /// Carry what `from` has written to `to`.
    fn carry(&mut self, from: &mut End, to: &mut End) {
        let bytes = std::mem::take(&mut from.wire);
        self.hear(to, &bytes);
    }

    /// `to` ingests `bytes` off its wire.
    fn hear(&mut self, to: &mut End, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut i: IngestIn = z();
        i.framing = to.framing;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
        let more = self.take(r, &o, to);
        self.again(more, to);
    }

    fn say(&mut self, end: &mut End, message: &'static str) {
        let r = self.emit(end, message.as_bytes(), 0);
        let more = self.take(r.0, &r.1, end);
        self.again(more, end);
    }

    /// One whole message from `end`, its `EmitIn::flags` as given; the raw answer.
    fn emit(&mut self, end: &End, message: &[u8], flags: u32) -> (Outcome, FramerOut) {
        let mut i: EmitIn = z();
        i.framing = end.framing;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.flags = flags;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        (r, o)
    }

    fn finish(&mut self, end: &mut End) {
        let mut i: FinishIn = z();
        i.framing = end.framing;
        i.reason = CLOSE_NORMAL;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.finish, self.inst, &mut i, &mut o, slot::FINISH);
        let more = self.take(r, &o, end);
        self.again(more, end);
    }

    fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
    }
}

fn texts(e: &End) -> Vec<String> {
    e.frames
        .iter()
        .filter(|(b, whole)| *whole && !b.is_empty())
        .map(|(b, _)| String::from_utf8_lossy(b).into_owned())
        .collect()
}

/// The whole exchange; answers every frame byte either end said, for the re-call comparison.
fn exchange(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) -> Vec<u8> {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    assert!(
        String::from_utf8_lossy(&dial.wire).starts_with("GET /stream HTTP/1.1\r\n"),
        "a dialled framing opens with the upgrade request"
    );
    host.carry(&mut dial, &mut accept);
    assert!(String::from_utf8_lossy(&accept.wire).starts_with("HTTP/1.1 101"));
    host.carry(&mut accept, &mut dial);
    host.say(&mut dial, "hello");
    host.carry(&mut dial, &mut accept);
    host.say(&mut accept, "world");
    host.carry(&mut accept, &mut dial);
    println!(
        "PROOF {label}: accepted end heard {:?}, dialled end heard {:?}",
        texts(&accept),
        texts(&dial)
    );
    assert_eq!(texts(&accept), ["hello"]);
    assert_eq!(texts(&dial), ["world"]);
    host.finish(&mut dial);
    host.carry(&mut dial, &mut accept);
    let last = accept.frames.last().expect("frames");
    println!(
        "PROOF {label}: after the dialled end's close the accepted end's stream ended={} connection ended={}",
        last.0.is_empty() && last.1,
        accept.ended
    );
    assert!(
        last.0.is_empty() && last.1,
        "the stream ends with an empty piece"
    );
    assert!(accept.ended, "and the connection with YIELD_ENDED");
    let log = host.log.clone();
    host.close();
    log
}

/// One client message as the wire carries it: FIN, `opcode`, masked with the all-zero key (so the
/// payload is its own masking), a payload under 126 bytes.
fn client_message(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![0x80 | opcode, 0x80 | payload.len() as u8, 0, 0, 0, 0];
    m.extend_from_slice(payload);
    m
}

/// RED (C19-TAIL U5): a TEXT message arrives as text (`PIECE_TEXT` on every piece of it) and a
/// BINARY one as binary. On the parent the door stated no text bit, so a text frame arrived as
/// binary.
fn text_and_binary(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    host.hear(&mut accept, &client_message(0x1, b"{\"t\":1}"));
    host.hear(&mut accept, &client_message(0x2, b"\x01\x02\x03"));
    println!(
        "PROOF {label}: frames {:?} text {:?}",
        accept.frames, accept.text
    );
    assert_eq!(
        accept.frames,
        [
            (b"{\"t\":1}".to_vec(), true),
            (b"\x01\x02\x03".to_vec(), true)
        ]
    );
    assert_eq!(
        accept.text,
        [true, false],
        "the text message arrives as text, the binary one as binary"
    );
    host.close();
}

/// RED (C19-TAIL U5 write): a message emitted with `EMIT_TEXT` goes out under the TEXT opcode (the
/// far end hears it as text), one without it as BINARY; text that is not UTF-8 is refused, never
/// sent under a promise it breaks. On the parent every emit went out BINARY.
fn written_as_text(label: &str, ops: &'static Ops, caps: (usize, usize, usize)) {
    let mut host = Host::open(ops, caps);
    let mut dial = host.begin(SIDE_DIAL, "ws://svc.test/stream");
    let mut accept = host.begin(SIDE_ACCEPT, "");
    host.carry(&mut dial, &mut accept);
    host.carry(&mut accept, &mut dial);
    for (message, flags) in [(&b"{\"t\":1}"[..], EMIT_TEXT), (&b"\x01\x02"[..], 0)] {
        let (r, o) = host.emit(&dial, message, flags);
        let more = host.take(r, &o, &mut dial);
        host.again(more, &mut dial);
        host.carry(&mut dial, &mut accept);
    }
    println!(
        "PROOF {label}: heard {:?} text {:?}",
        accept.frames, accept.text
    );
    assert_eq!(
        accept.frames,
        [(b"{\"t\":1}".to_vec(), true), (b"\x01\x02".to_vec(), true)]
    );
    assert_eq!(accept.text, [true, false], "written as text, heard as text");
    let (r, _) = host.emit(&dial, b"\xff\xfe", EMIT_TEXT);
    assert_ne!(r, Outcome::Ready, "text that is not UTF-8 is refused");
    host.close();
}

#[test]
fn a_message_written_as_text_goes_out_as_text_through_both_doors() {
    let (d, _lib) = dropped();
    for (image, ops) in [("linked", linked()), ("dropped", d)] {
        written_as_text(&format!("{image} roomy"), ops, (64 * 1024, 64 * 1024, 64));
        written_as_text(&format!("{image} tight"), ops, (7, 3, 1));
    }
}

#[test]
fn a_text_message_arrives_as_text_through_both_doors() {
    let (d, _lib) = dropped();
    for (image, ops) in [("linked", linked()), ("dropped", d)] {
        text_and_binary(&format!("{image} roomy"), ops, (64 * 1024, 64 * 1024, 64));
        text_and_binary(&format!("{image} tight"), ops, (7, 3, 1));
    }
}

fn linked() -> &'static Ops {
    let d = busbar_transport_ws::door::door();
    // SAFETY: the door's `'static` table.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn dropped() -> (&'static Ops, &'static libloading::Library) {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = format!(
        "{}ws_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = [
        profile.join("examples").join(&file),
        profile.join("examples").join("deps").join(&file),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| panic!("the dropped-in image ({file}) is not built"));
    // SAFETY: our own example, built by this `cargo test`.
    let lib: &'static libloading::Library = Box::leak(Box::new(
        unsafe { libloading::Library::new(path) }.expect("load"),
    ));
    // SAFETY: the one exported symbol, a `DoorFn`.
    let door: libloading::Symbol<'_, extern "C" fn() -> *const Door> =
        unsafe { lib.get(DOOR_SYMBOL) }.expect("the door symbol");
    let d = door();
    // SAFETY: the dropped-in door's `'static` table.
    (unsafe { &*(*d).ops.cast::<Ops>() }, lib)
}

#[test]
fn the_linked_and_the_dropped_in_door_frame_the_same() {
    let (d, _lib) = dropped();
    let l = linked();
    assert!(!std::ptr::eq(l, d), "two images");
    for (image, ops) in [("linked", l), ("dropped", d)] {
        let roomy = exchange(&format!("{image} roomy"), ops, (64 * 1024, 64 * 1024, 64));
        let tight = exchange(&format!("{image} tight"), ops, (7, 3, 1));
        println!(
            "PROOF {image}: the re-called exchange answered the same {} frame bytes: {}",
            roomy.len(),
            roomy == tight
        );
        assert_eq!(
            roomy, tight,
            "a re-call answers nothing twice and drops nothing"
        );
    }
}
