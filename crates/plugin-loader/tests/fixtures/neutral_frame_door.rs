// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FRAME DOOR: a test double that frames the host's socket (it composes over nothing),
//! for the tests that need such a door beside their binary (the loader's dropped-in door through
//! the registry, the connector driving a dropped-in socket framer, the root's dropped-in wire in the
//! one fold). It lives with the tests and names no transport (spec Part 5 log, 2026-09-25 S10: "a
//! plugin tests itself; the kernel never tests or names a plugin"), so no plugin leaving this repo
//! takes these tests' fixture with it. An example, not a crate: `cargo test` builds it and it never
//! ships.
//!
//! An IDENTITY framer on the transport kind's table (`busbar_contract::abi::transport`): the bytes
//! the far side sent are one frame on stream `0` (the far side's end is `YIELD_ENDED`), the bytes
//! handed to `emit`/`refuse` are the wire bytes, `encode` renders an envelope as its body alone
//! (fields are refused), `detach`/`adopt` hand unconsumed bytes across, and `locate` reads
//! `host:port` (or `frame://host:port`). No op pends or asks for a deadline; a full sink is
//! back-pressure (`YIELD_MORE`). Every carrier op is refused: the socket is the host's.

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
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail,
    WriteIn, CANCEL_NOTHING_MOVED, FRAMING_STREAM, PIECE_END_OF_FRAME, ROLE_FRAMER,
    UNIT0_FIRST_BYTES, YIELD_ENDED, YIELD_MORE,
};
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::SelectorForm;

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The claim this entry answers for: a neutral scheme no transport serves.
pub const KEY: &str = "frame";

/// The selector forms the claim reads: the port it arrived on.
const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Port];
const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[abi_str(tfacts::PEER)];

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The schemes this door claims, by name: the Statement's `claims`, the one place they are stated.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
const CLAIMS: &[Claim] = &[Claim {
    selector_forms: AbiStr {
        ptr: SELECTOR_CODES.as_ptr(),
        len: SELECTOR_CODES.len(),
    },
    egress_selector_forms: abi_str(""),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: NONE,
    session: 1,
    session_bound: 0,
    unit0_trigger: UNIT0_FIRST_BYTES,
    status_at: 0,
    _reserved: 0,
}];

const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
    fault_rows: std::ptr::null(),
    fault_rows_len: 0,
};

/// The door's Statement: the identity framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// The framings this instance holds.
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

// ── the lifecycle ────────────────────────────────────────────────────────────────────────────────

/// `validate`: this framer reads no setting.
pub struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &ValidateIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

/// `open`.
pub struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, _: &OpenIn, o: &mut OpenOut) -> Outcome {
        o.instance = Box::into_raw(Box::new(Instance {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }))
        .cast();
        Outcome::Ready
    }
}

/// `close`.
pub struct Close;
impl Slot for Close {
    type In = InHead;
    type Out = OutHead;
    fn call(p: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        if !p.is_null() {
            // SAFETY: `open`'s box, closed once.
            drop(unsafe { Box::from_raw(p.cast::<Instance>()) });
        }
        Outcome::Ready
    }
}

/// `cancel`: no framer op pends, so nothing is ever in flight to cancel.
pub struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(_: *mut c_void, _: &CancelIn, o: &mut CancelOut) -> Outcome {
        o.disposition = CANCEL_NOTHING_MOVED;
        Outcome::Ready
    }
}

macro_rules! answer {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        #[doc = concat!("`", stringify!($name), "`.")]
        pub struct $name;
        impl Slot for $name {
            type In = $in;
            type Out = $out;
            fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
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

// A framer is not a carrier: the socket is the host's, so every carrier op is refused.
answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`: `host:port` or `frame://host:port` is the authority; no name, no connection security.
pub struct Locate;
impl Slot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    fn call(_: *mut c_void, i: &LocateIn, o: &mut LocateOut) -> Outcome {
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

/// `begin`: either side; nothing is owed to the far side first.
pub struct Begin;
impl Slot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, _: &BeginIn, o: &mut FramerOut) -> Outcome {
        let inst = instance(p);
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        inst.framings
            .lock()
            .expect("framings")
            .insert(token, Framing::default());
        o.framing = token;
        Outcome::Ready
    }
}

/// `adopt`: the bytes another framer left unconsumed are this connection's first frame.
pub struct Adopt;
impl Slot for Adopt {
    type In = AdoptIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &AdoptIn, o: &mut FramerOut) -> Outcome {
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

/// Run `op` on the framing `token` names and answer what it owes into `sink`.
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

/// `ingest`: the bytes are one frame on stream `0`; the far side's end ends the connection.
pub struct Ingest;
impl Slot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &IngestIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        with(p, i.framing, &i.sink, o, |f| {
            f.take_inbound(bytes);
            f.ended |= i.end != 0;
        })
    }
}

/// `emit`: the bytes are the wire bytes.
pub struct Emit;
impl Slot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &EmitIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        with(p, i.framing, &i.sink, o, |f| f.outbound.extend(bytes))
    }
}

/// `refuse`: the refusal's bytes are the wire bytes.
pub struct Refuse;
impl Slot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &RefuseIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        with(p, i.framing, &i.sink, o, |f| f.outbound.extend(bytes))
    }
}

/// `timer`: this framer asks for no deadline; a call answers what is still owed.
pub struct Timer;
impl Slot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
        with(p, i.framing, &i.sink, o, |_| {})
    }
}

/// `finish`: the framing is forgotten; no frame follows.
pub struct Finish;
impl Slot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FinishIn, o: &mut FramerOut) -> Outcome {
        let removed = instance(p)
            .framings
            .lock()
            .expect("framings")
            .remove(&i.framing);
        if removed.is_none() {
            err(&mut o.head, "finish: no such framing");
            return Outcome::Failed;
        }
        o.yielded.flags = YIELD_ENDED;
        Outcome::Ready
    }
}

/// `detach`: every byte ingested and not yet answered, into `frame`, and the framing is forgotten.
/// A sink too small for them answers `YIELD_MORE` and keeps the framing until the rest is taken.
pub struct Detach;
impl Slot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
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

/// `encode`: a byte stream has no head, so the envelope is its body; fields are refused.
pub struct Encode;
impl Slot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    fn call(_: *mut c_void, i: &EncodeIn, o: &mut FramerOut) -> Outcome {
        if i.fields_len != 0 {
            err(&mut o.head, "encode: a byte stream carries no fields");
            return Outcome::Failed;
        }
        let body = raw(i.body, i.body_len);
        if body.len() > i.sink.wire_cap {
            // `encode` renders a whole message at once: the host gives it room for the body.
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

/// Move `n` bytes off the front of `from` into the host buffer at `to`.
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
    fn take_inbound(&mut self, bytes: &[u8]) {
        self.inbound.extend(bytes);
    }

    /// Answer into `sink` what this framing owes: wire bytes, then the inbound frame as one piece
    /// (the one that drains it ends the frame), then the connection's end once nothing is left.
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
                    stream: 0,
                    offset: 0,
                    len: n as u64,
                    code: 0,
                    status_class: 0,
                    flags,
                    fault: 0,
                    retry_after_secs: 0,
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
