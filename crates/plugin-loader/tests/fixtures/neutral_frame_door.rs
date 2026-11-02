// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement, RawSlot};
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FaultRow, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn,
    IoOut, ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, StatusRow,
    TransportTail, WriteIn, CANCEL_NOTHING_MOVED, FAULT_CALLER, FRAME_PIECE_SIZE, FRAMING_STREAM,
    PIECE_END_OF_FRAME, ROLE_FRAMER, SIDE_ACCEPT_STREAM, STATUS_OTHER, STATUS_SUCCESS,
    UNIT0_FIRST_BYTES, YIELD_ENDED, YIELD_MORE,
};
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::SelectorForm;

pub const KEY: &str = "frame";

const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Port];
const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[abi_str(tfacts::PEER)];

const NONE: AbiStr = AbiStr::ZERO;

const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

const CLAIMS: &[Claim] = &[Claim {
    selector_forms: AbiStr {
        ptr: SELECTOR_CODES.as_ptr(),
        len: SELECTOR_CODES.len(),
    },
    egress_selector_forms: abi_str(""),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: abi_str(KEY),
    session: 1,
    unit0_trigger: UNIT0_FIRST_BYTES,
    ..Claim::ZERO
}];

const STATUS_ROWS: &[StatusRow] = &[
    StatusRow {
        class: STATUS_SUCCESS as u32,
        ..StatusRow::ZERO
    },
    StatusRow {
        lo: 1,
        hi: 9,
        class: STATUS_OTHER as u32,
        ..StatusRow::ZERO
    },
];

const FAULT_ROWS: &[FaultRow] = &[FaultRow {
    lo: 1,
    hi: 9,
    fault: FAULT_CALLER as u32,
    ..FaultRow::ZERO
}];

const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        ..KindTailHead::ZERO
    },

    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: STATUS_ROWS.as_ptr(),
    status_rows_len: STATUS_ROWS.len(),
    fault_rows: FAULT_ROWS.as_ptr(),
    fault_rows_len: FAULT_ROWS.len(),

    frame_piece_size: FRAME_PIECE_SIZE,
    ..TransportTail::ZERO
};

pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

pub struct Instance {
    framings: Mutex<HashMap<u64, Framing>>,
    next: AtomicU64,
}

/// One connection's framing: the bytes owed to each side and not yet answered.
#[derive(Default)]
struct Framing {
    /// Bytes the far side sent, not yet answered as frame bytes.
    inbound: VecDeque<u8>,
    /// The far side ended.
    ended: bool,
    /// Bytes owed to the far side, not yet answered as wire bytes.
    outbound: VecDeque<u8>,
    /// Begun on `SIDE_ACCEPT_STREAM`: one stream of length-byte messages.
    stream: bool,
    /// One stream's message bytes ingested and not yet whole, or emitted and not yet ended.
    reading: Vec<u8>,
    writing: Vec<u8>,
    /// One stream's close was answered (a refusal); `finish` owes nothing more.
    closed: bool,
}

fn instance<'a>(p: *mut c_void) -> &'a Instance {
    // SAFETY: the host passes back the pointer `open` answered, until `close`.
    unsafe { &*p.cast::<Instance>() }
}

fn raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: host-borrowed input of `len` bytes, valid for the call.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn text(s: &AbiStr) -> &[u8] {
    raw(s.ptr, s.len)
}

fn err(out: &mut OutHead, text: &'static str) {
    out.error = abi_str(text);
}

pub struct Validate;
impl RawSlot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    unsafe fn call(_: *mut c_void, _: &ValidateIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

pub struct Open;
impl RawSlot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    unsafe fn call(_: *mut c_void, _: &OpenIn, o: &mut OpenOut) -> Outcome {
        o.instance = Box::into_raw(Box::new(Instance {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }))
        .cast();
        Outcome::Ready
    }
}

pub struct Close;
impl RawSlot for Close {
    type In = InHead;
    type Out = OutHead;
    unsafe fn call(p: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        if !p.is_null() {
            // SAFETY: `open`'s box, closed once.
            drop(unsafe { Box::from_raw(p.cast::<Instance>()) });
        }
        Outcome::Ready
    }
}

pub struct Cancel;
impl RawSlot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    unsafe fn call(_: *mut c_void, _: &CancelIn, o: &mut CancelOut) -> Outcome {
        o.disposition = CANCEL_NOTHING_MOVED;
        Outcome::Ready
    }
}

macro_rules! answer {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        #[doc = concat!("`", stringify!($name), "`.")]
        pub struct $name;
        impl RawSlot for $name {
            type In = $in;
            type Out = $out;
            unsafe fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                $outcome
            }
        }
    };
}

answer!(Refresh, RefreshIn, OutHead, Outcome::Ready);
answer!(Retire, GenIn, OutHead, Outcome::Ready);
answer!(Tick, TickIn, TickOut, Outcome::Ready);
answer!(Drive, DriveIn, OutHead, Outcome::Ready);
answer!(Release, ReleaseIn, OutHead, Outcome::Ready);

answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);

pub struct Locate;
impl RawSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    unsafe fn call(_: *mut c_void, i: &LocateIn, o: &mut LocateOut) -> Outcome {
        let target = text(&i.target);
        let authority = target.strip_prefix(b"frame://").unwrap_or(target);
        if authority.is_empty() || authority.contains(&b'/') {
            err(&mut o.head, "locate: the target is not host:port");
            return Outcome::Failed;
        }
        o.secure = 0;
        o.has_name = 0;
        if authority.len() > i.authority_cap {
            o.authority_needed = authority.len() as u64;
            err(&mut o.head, "locate: the authority buffer is too small");
            return Outcome::Failed;
        }
        // SAFETY: a host buffer of `authority_cap` bytes, checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(authority.as_ptr(), i.authority_buf, authority.len());
        }
        o.authority_written = authority.len() as u64;
        Outcome::Ready
    }
}

pub struct Begin;
impl RawSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &BeginIn, o: &mut FramerOut) -> Outcome {
        const OPENING: &[u8] =
            b"trailer: frame-status, frame-reason, frame-message, frame-details\r\n";
        let inst = instance(p);
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        let mut framing = Framing {
            stream: i.side == SIDE_ACCEPT_STREAM,
            ..Framing::default()
        };
        if framing.stream {
            framing.outbound.extend(OPENING);
        }

        framing.answer(&i.sink, o);
        inst.framings
            .lock()
            .expect("framings")
            .insert(token, framing);
        o.framing = token;
        Outcome::Ready
    }
}

pub struct Adopt;
impl RawSlot for Adopt {
    type In = AdoptIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &AdoptIn, o: &mut FramerOut) -> Outcome {
        let inst = instance(p);
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        let mut f = Framing::default();
        f.take_inbound(raw(i.leftover, i.leftover_len));
        let mut framings = inst.framings.lock().expect("framings");
        let f = framings.entry(token).or_insert(f);
        o.framing = token;
        f.answer(&i.sink, o);
        Outcome::Ready
    }
}

fn with(
    p: *mut c_void,
    token: u64,
    sink: &FramerSink,
    o: &mut FramerOut,
    op: impl FnOnce(&mut Framing),
) -> Outcome {
    let mut framings = instance(p).framings.lock().expect("framings");
    let Some(f) = framings.get_mut(&token) else {
        err(&mut o.head, "no such framing");
        return Outcome::Failed;
    };
    op(f);
    f.answer(sink, o);
    Outcome::Ready
}

pub struct Ingest;
impl RawSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &IngestIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let mut framings = instance(p).framings.lock().expect("framings");
        if let Some(f) = framings.get_mut(&i.framing).filter(|f| f.stream) {
            f.reading.extend_from_slice(bytes);
            return f.messages(&i.sink, o);
        }
        drop(framings);
        with(p, i.framing, &i.sink, o, |f| {
            f.take_inbound(bytes);
            f.ended |= i.end != 0;
        })
    }
}

pub struct Emit;
impl RawSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &EmitIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let ends = i.end_of_frame != 0;
        with(p, i.framing, &i.sink, o, |f| {
            if !f.stream {
                f.outbound.extend(bytes);
                return;
            }
            f.writing.extend_from_slice(bytes);
            if ends {
                let message = std::mem::take(&mut f.writing);
                f.outbound.push_back(message.len() as u8);
                f.outbound.extend(message);
            }
        })
    }
}

pub struct Refuse;
impl RawSlot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &RefuseIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let status = i.status;
        with(p, i.framing, &i.sink, o, |f| {
            if !f.stream {
                f.outbound.extend(bytes);
                return;
            }
            f.closed = true;
            f.outbound.extend(
                format!(
                    ":status: 200\r\nframe-status: {status}\r\nframe-reason: {}\r\n",
                    String::from_utf8_lossy(bytes)
                )
                .into_bytes(),
            );
        })
    }
}

pub struct Timer;
impl RawSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
        with(p, i.framing, &i.sink, o, |_| {})
    }
}

pub struct Finish;
impl RawSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &FinishIn, o: &mut FramerOut) -> Outcome {
        let removed = instance(p)
            .framings
            .lock()
            .expect("framings")
            .remove(&i.framing);
        let Some(f) = removed else {
            err(&mut o.head, "finish: no such framing");
            return Outcome::Failed;
        };
        if f.stream && !f.closed {
            let all = raw(i.final_bytes, i.final_bytes_len);
            let at = |s: busbar_contract::abi::mechanism::call::Span| {
                all.get(s.offset as usize..s.offset as usize + s.len as usize)
                    .unwrap_or_default()
            };
            let details: String = at(i.final_details)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let block = format!(
                "frame-status: {}\r\nframe-message: {}\r\nframe-details: {details}\r\n",
                i.final_status,
                String::from_utf8_lossy(at(i.final_message))
            );
            if block.len() > i.sink.wire_cap {
                err(
                    &mut o.head,
                    "finish: the wire buffer is smaller than the block",
                );
                return Outcome::Failed;
            }
            // SAFETY: a host buffer of `wire_cap` bytes, checked above.
            unsafe { std::ptr::copy_nonoverlapping(block.as_ptr(), i.sink.wire, block.len()) };
            o.yielded.wire_len = block.len() as u64;
        }
        o.yielded.flags = YIELD_ENDED;
        Outcome::Ready
    }
}

pub struct Detach;
impl RawSlot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    unsafe fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
        let mut framings = instance(p).framings.lock().expect("framings");
        let Some(f) = framings.get_mut(&i.framing) else {
            err(&mut o.head, "detach: no such framing");
            return Outcome::Failed;
        };
        let n = f.inbound.len().min(i.sink.frame_cap);
        copy_out(&mut f.inbound, i.sink.frame, n);
        o.yielded.frame_len = n as u64;
        if f.inbound.is_empty() {
            framings.remove(&i.framing);
            o.yielded.flags = YIELD_ENDED;
        } else {
            o.yielded.flags = YIELD_MORE;
        }
        Outcome::Ready
    }
}

pub struct Encode;
impl RawSlot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    unsafe fn call(_: *mut c_void, i: &EncodeIn, o: &mut FramerOut) -> Outcome {
        if i.fields_len != 0 {
            err(&mut o.head, "encode: a byte stream carries no fields");
            return Outcome::Failed;
        }
        let body = raw(i.body, i.body_len);
        if body.len() > i.sink.wire_cap {
            err(
                &mut o.head,
                "encode: the wire buffer is smaller than the body",
            );
            return Outcome::Failed;
        }
        // SAFETY: a host buffer of `wire_cap` bytes, checked above.
        unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), i.sink.wire, body.len()) };
        o.yielded.wire_len = body.len() as u64;
        Outcome::Ready
    }
}

fn copy_out(from: &mut VecDeque<u8>, to: *mut u8, n: usize) {
    if n == 0 {
        return;
    }
    let (a, b) = from.as_slices();
    let first = a.len().min(n);
    // SAFETY: `to` is a host buffer of at least `n` bytes (every caller bounds `n` by its cap).
    unsafe {
        std::ptr::copy_nonoverlapping(a.as_ptr(), to, first);
        std::ptr::copy_nonoverlapping(b.as_ptr(), to.add(first), n - first);
    }
    from.drain(..n);
}

impl Framing {
    fn messages(&mut self, sink: &FramerSink, o: &mut FramerOut) -> Outcome {
        let (mut at, mut n) = (0usize, 0usize);
        while let Some(&len) = self.reading.first() {
            let len = usize::from(len);
            if self.reading.len() < 1 + len || at + len > sink.frame_cap || n >= sink.pieces_cap {
                break;
            }
            let message: Vec<u8> = self.reading.drain(..=len).skip(1).collect();
            // SAFETY: host buffers of `frame_cap` bytes and `pieces_cap` pieces, bounded above.
            unsafe {
                std::ptr::copy_nonoverlapping(message.as_ptr(), sink.frame.add(at), len);
                sink.pieces.add(n).write(FramePiece {
                    stream: 1,
                    offset: at as u64,
                    len: len as u64,
                    flags: PIECE_END_OF_FRAME,
                    ..FramePiece::ZERO
                });
            }
            at += len;
            n += 1;
        }
        o.yielded.frame_len = at as u64;
        o.yielded.pieces_len = n as u32;
        Outcome::Ready
    }

    fn take_inbound(&mut self, bytes: &[u8]) {
        self.inbound.extend(bytes);
    }

    fn answer(&mut self, sink: &FramerSink, o: &mut FramerOut) {
        let y = &mut o.yielded;
        let wire = self.outbound.len().min(sink.wire_cap);
        copy_out(&mut self.outbound, sink.wire, wire);
        y.wire_len = wire as u64;
        if !self.inbound.is_empty() && sink.pieces_cap > 0 && sink.frame_cap > 0 {
            let n = self.inbound.len().min(sink.frame_cap);
            copy_out(&mut self.inbound, sink.frame, n);
            let whole = self.inbound.is_empty();
            let flags = if whole { PIECE_END_OF_FRAME } else { 0 };
            // SAFETY: a host buffer of `pieces_cap >= 1` pieces.
            unsafe {
                sink.pieces.write(FramePiece {
                    len: n as u64,
                    flags,
                    ..FramePiece::ZERO
                });
            }
            y.frame_len = n as u64;
            y.pieces_len = 1;
        }
        let owed = !self.outbound.is_empty() || !self.inbound.is_empty();
        y.flags = if owed {
            YIELD_MORE
        } else if self.ended {
            YIELD_ENDED
        } else {
            0
        };
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Validate,
        open: Open,
        refresh: Refresh,
        retire: Retire,
        tick: Tick,
        drive: Drive,
        cancel: Cancel,
        release: Release,
        close: Close,
    },
    kind_ops: {
        listen: Listen,
        accept: Accept,
        dial: Dial,
        read: Read,
        write: Write,
        flush: Flush,
        shut: Shut,
        arrival: Arrival,
        locate: Locate,
        begin: Begin,
        ingest: Ingest,
        emit: Emit,
        encode: Encode,
        refuse: Refuse,
        finish: Finish,
        detach: Detach,
        adopt: Adopt,
        timer: Timer,
    },
}

busbar_contract::export_door!(door);
