// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `ws` DOOR: this transport's framer ([`WsFramer`], tungstenite over an in-memory pipe) on the
//! transport kind's table (`busbar_contract::abi::transport`), compiled in or dropped in through
//! the one door.
//!
//! Each framer op is the framer's own method, answered into the host's sink. What does not fit the
//! sink waits in the framing's queue and goes out on the `YIELD_MORE` re-call, which carries no new
//! bytes. A WebSocket connection carries one message stream (stream `0`): each message is a frame,
//! and when the connection's frames end the stream ends with an empty piece and the answer carries
//! `YIELD_ENDED`.
//!
//! The connector owns the socket and connection security; `locate` tells it where a target is and
//! whether it asks for security (`wss`). Both sides frame: a dialled framing opens with the upgrade
//! request, an accepted one answers it, and `adopt` takes over a stream another framer detached
//! with the upgrade request it held.

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::Mutex;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, SettingDecl, ShutIn,
    TransportTail, WriteIn, CANCEL_NOTHING_MOVED, CLOSE_CAPACITY_EXHAUSTED, CLOSE_DRAIN,
    CLOSE_PEER_CLOSED, CLOSE_POISONED, CLOSE_REVOKED, CLOSE_TIMEOUT, CLOSE_TRANSPORT_FAILED,
    EMIT_TEXT, FRAMING_STREAM, PIECE_END_OF_FRAME, PIECE_TEXT, ROLE_FRAMER, SETTING_COUNT,
    SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::registry::DEFAULT_REQUEST_BODY_MAX_BYTES;
use busbar_contract::transport::wire::CloseReason;
use busbar_contract::transport::{
    BytesOut, ConnFacts, Framed, Framer, FramerOut as Out, HostTime, Side,
};

use crate::framer::WsFramer;

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The setting this transport reads, at its 1.5.5 path: the message ceiling.
pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The schemes `ws` claims, by name: the Statement's `claims`, the one place they are stated.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(
    <crate::WsFramer as busbar_contract::TransportMeta>::KEY,
)];

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
const CLAIMS: &[Claim] = &[Claim {
    selector_forms: abi_str(""),
    egress_selector_forms: abi_str(""),
    facts: std::ptr::null(),
    facts_len: 0,
    status_namespace: NONE,
    session: 1,
    session_bound: 0,
    unit0_trigger: 0,
    status_at: 0,
    _reserved: 0,
}];

/// What `ws` composes over, as the transport's own declaration states it.
const OVER: &[&str] = <crate::WsFramer as busbar_contract::TransportMeta>::COMPOSES_OVER;
const COMPOSES_OVER: &[AbiStr] = &[abi_str(OVER[0]), abi_str(OVER[1])];

const SETTINGS: &[SettingDecl] = &[SettingDecl {
    path: abi_str(BODY_MAX_BYTES),
    kind: SETTING_COUNT,
    _reserved: 0,
    default: abi_str("33554432"),
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
    composes_over: COMPOSES_OVER.as_ptr(),
    composes_over_len: COMPOSES_OVER.len(),
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
    settings: SETTINGS.as_ptr(),
    settings_len: SETTINGS.len(),
};

/// The door's Statement: the `ws` framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement("ws", env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// One frame piece waiting for the host.
struct Piece {
    stream: u64,
    bytes: Vec<u8>,
    end_of_frame: bool,
    /// The bytes belong to a text message (`PIECE_TEXT`).
    text: bool,
}

/// What one framing owes the host and has not been able to hand it.
#[derive(Default)]
struct Owed {
    wire: VecDeque<u8>,
    pieces: VecDeque<Piece>,
    ended: bool,
    deadline: Option<u64>,
    error: String,
}

/// The framer and what each framing owes.
pub struct Instance {
    framer: WsFramer,
    owed: Mutex<HashMap<u64, Owed>>,
}

/// The framer's output for one op, collected before it goes to the sink.
struct Collect<'a> {
    owed: &'a mut Owed,
    now: HostTime,
}

impl Out for Collect<'_> {
    fn send(&mut self, bytes: &[u8]) {
        self.owed.wire.extend(bytes);
    }
    fn frame(&mut self, piece: Framed<'_>) {
        self.owed.pieces.push_back(Piece {
            stream: piece.stream.0,
            bytes: piece.bytes.to_vec(),
            end_of_frame: piece.end_of_frame,
            text: piece.text,
        });
    }
    fn end(&mut self) {
        if !self.owed.ended {
            // The one stream's frames are over: its empty last piece, then the connection's end.
            self.owed.pieces.push_back(Piece {
                stream: 0,
                bytes: Vec::new(),
                end_of_frame: true,
                text: false,
            });
        }
        self.owed.ended = true;
    }
    fn now(&self) -> HostTime {
        self.now
    }
    fn wake_at(&mut self, monotonic_nanos: Option<u64>) {
        self.owed.deadline = monotonic_nanos;
    }
}

impl BytesOut for Collect<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.owed.wire.extend(bytes);
    }
}

fn read_settings(b: &Blob) -> Result<usize, &'static str> {
    let text: &[u8] = if b.ptr.is_null() || b.len == 0 {
        b"{}"
    } else {
        // SAFETY: the host's blob, valid for the call.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
    };
    let v: serde_json::Value = serde_json::from_slice(text).map_err(|_| "settings: not JSON")?;
    match v.get(BODY_MAX_BYTES) {
        None => Ok(DEFAULT_REQUEST_BODY_MAX_BYTES),
        Some(x) => x
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("settings: a value is not of its declared kind"),
    }
}

fn instance<'a>(p: *mut c_void) -> &'a Instance {
    // SAFETY: the host passes back the pointer `open` answered, until `close`.
    unsafe { &*p.cast::<Instance>() }
}

fn text(s: &AbiStr) -> &[u8] {
    if s.ptr.is_null() {
        return &[];
    }
    // SAFETY: host-borrowed input, valid for the call.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }
}

fn raw<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: host-borrowed for the call.
    unsafe { std::slice::from_raw_parts(p, n) }
}

fn time(sink: &FramerSink) -> HostTime {
    HostTime {
        monotonic_nanos: sink.now_monotonic_ns,
        unix_nanos: sink.now_unix_ns,
    }
}

fn side_of(side: u32) -> Option<Side> {
    match side {
        SIDE_ACCEPT => Some(Side::Accept),
        SIDE_DIAL => Some(Side::Dial),
        _ => None,
    }
}

fn reason_of(code: u32) -> CloseReason {
    match code {
        CLOSE_PEER_CLOSED => CloseReason::PeerClosed,
        CLOSE_DRAIN => CloseReason::Drain,
        CLOSE_POISONED => CloseReason::Poisoned,
        CLOSE_REVOKED => CloseReason::Revoked,
        CLOSE_TIMEOUT => CloseReason::Timeout,
        CLOSE_TRANSPORT_FAILED => CloseReason::TransportFailed,
        CLOSE_CAPACITY_EXHAUSTED => CloseReason::CapacityExhausted,
        _ => CloseReason::Normal,
    }
}

/// The connection-security facts the old framer shape reads: the protocol agreed and the claim.
fn facts_of(p: *const busbar_contract::abi::transport::ConnFacts) -> ConnFacts {
    if p.is_null() {
        return ConnFacts::default();
    }
    // SAFETY: host-borrowed for the call.
    let f = unsafe { &*p };
    let s = |a: &AbiStr| (!a.ptr.is_null()).then(|| String::from_utf8_lossy(text(a)).into_owned());
    ConnFacts {
        sni: s(&f.offered_name),
        alpn: s(&f.agreed_protocol),
        claim: s(&f.claim),
        ..ConnFacts::default()
    }
}

// ── the lifecycle ────────────────────────────────────────────────────────────────────────────────

/// `validate`.
pub struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, i: &ValidateIn, o: &mut OutHead) -> Outcome {
        match read_settings(&i.settings) {
            Ok(_) => Outcome::Ready,
            Err(e) => {
                o.error = abi_str(e);
                Outcome::Failed
            }
        }
    }
}

/// `open`.
pub struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, i: &OpenIn, o: &mut OpenOut) -> Outcome {
        match read_settings(&i.settings) {
            Ok(max) => {
                o.instance = Box::into_raw(Box::new(Instance {
                    framer: WsFramer::new(max),
                    owed: Mutex::new(HashMap::new()),
                }))
                .cast();
                Outcome::Ready
            }
            Err(e) => {
                o.head.error = abi_str(e);
                Outcome::Failed
            }
        }
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

// A framer is not a carrier: every carrier op is refused. Nothing upgrades out of a WebSocket.
answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);
answer!(Detach, FramingIn, FramerOut, Outcome::Refused);

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`.
pub struct Locate;
impl Slot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    fn call(p: *mut c_void, i: &LocateIn, o: &mut LocateOut) -> Outcome {
        let Ok(target) = std::str::from_utf8(text(&i.target)) else {
            o.head.error = abi_str("locate: the target is not text");
            return Outcome::Failed;
        };
        let Ok(at) = instance(p).framer.locate(target) else {
            o.head.error = abi_str("locate: the target is not a ws or wss URL");
            return Outcome::Failed;
        };
        let name = at.server_name.clone().unwrap_or_default();
        // The ALPN offer on a secured connection: the opening handshake is a version-1.1 upgrade.
        let offer: &[u8] = if at.secure { b"\x08http/1.1" } else { &[] };
        o.secure = u32::from(at.secure);
        o.has_name = u32::from(at.server_name.is_some());
        if at.authority.len() > i.authority_cap
            || name.len() > i.name_cap
            || offer.len() > i.alpn_cap
        {
            o.authority_needed = at.authority.len() as u64;
            o.name_needed = if at.server_name.is_some() {
                name.len() as u64
            } else {
                0
            };
            o.alpn_needed = offer.len() as u64;
            o.head.error = abi_str("locate: a host buffer is too small");
            return Outcome::Failed;
        }
        // SAFETY: host buffers of the stated capacity, checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(
                at.authority.as_ptr(),
                i.authority_buf,
                at.authority.len(),
            );
            std::ptr::copy_nonoverlapping(name.as_ptr(), i.name_buf, name.len());
            if !offer.is_empty() {
                std::ptr::copy_nonoverlapping(offer.as_ptr(), i.alpn_buf, offer.len());
            }
        }
        o.authority_written = at.authority.len() as u64;
        o.name_written = name.len() as u64;
        o.alpn_written = offer.len() as u64;
        Outcome::Ready
    }
}

/// Run a framer method that opens a framing, then answer what it produced.
fn opening(
    p: *mut c_void,
    sink: &FramerSink,
    o: &mut FramerOut,
    open: impl FnOnce(&WsFramer, &mut Collect<'_>) -> Result<u64, String>,
) -> Outcome {
    let inst = instance(p);
    let mut owed = Owed::default();
    let mut c = Collect {
        owed: &mut owed,
        now: time(sink),
    };
    match open(&inst.framer, &mut c) {
        Ok(token) => {
            o.framing = token;
            let mut all = inst.owed.lock().expect("owed");
            let slot = all.entry(token).or_default();
            *slot = owed;
            fill(slot, sink, o);
            Outcome::Ready
        }
        Err(_) => {
            o.head.error = abi_str("the framing could not be opened");
            Outcome::Failed
        }
    }
}

/// Run a framer method on framing `token`, then answer what it produced (and what was owed).
fn framing(
    p: *mut c_void,
    token: u64,
    sink: &FramerSink,
    o: &mut FramerOut,
    op: impl FnOnce(&WsFramer, &mut Collect<'_>) -> Result<(), String>,
) -> Outcome {
    let inst = instance(p);
    let mut all = inst.owed.lock().expect("owed");
    let Some(owed) = all.get_mut(&token) else {
        o.head.error = abi_str("no such framing");
        return Outcome::Failed;
    };
    let mut c = Collect {
        owed,
        now: time(sink),
    };
    if let Err(e) = op(&inst.framer, &mut c) {
        let owed = all.get_mut(&token).expect("held");
        if owed.wire.is_empty() && owed.pieces.is_empty() {
            owed.error = e;
            o.head.error = AbiStr {
                ptr: owed.error.as_ptr(),
                len: owed.error.len(),
            };
            return Outcome::Failed;
        }
        // What the failing op produced still goes out; the connection's end follows it.
        owed.ended = true;
    }
    fill(all.get_mut(&token).expect("held"), sink, o);
    Outcome::Ready
}

/// `begin`.
pub struct Begin;
impl Slot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &BeginIn, o: &mut FramerOut) -> Outcome {
        let Some(side) = side_of(i.side) else {
            o.head.error = abi_str("begin: the side is neither accept nor dial");
            return Outcome::Failed;
        };
        let target = String::from_utf8_lossy(text(&i.target)).into_owned();
        let facts = facts_of(i.facts);
        opening(p, &i.sink, o, |f, c| {
            f.open(side, &target, &facts, c)
                .map_err(|e| format!("{e:?}"))
        })
    }
}

/// `adopt`.
pub struct Adopt;
impl Slot for Adopt {
    type In = AdoptIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &AdoptIn, o: &mut FramerOut) -> Outcome {
        let Some(side) = side_of(i.side) else {
            o.head.error = abi_str("adopt: the side is neither accept nor dial");
            return Outcome::Failed;
        };
        let facts = facts_of(i.facts);
        let leftover = raw(i.leftover, i.leftover_len);
        opening(p, &i.sink, o, |f, c| {
            f.adopt(side, &facts, leftover, c)
                .map_err(|e| format!("{e:?}"))
        })
    }
}

/// `ingest`.
pub struct Ingest;
impl Slot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &IngestIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let end = i.end != 0;
        framing(p, i.framing, &i.sink, o, |f, c| {
            // A `YIELD_MORE` re-call carries no new bytes: nothing reaches the machine.
            if bytes.is_empty() && !end {
                return Ok(());
            }
            f.ingest(i.framing, bytes, end, c)
                .map_err(|e| format!("{e:?}"))
        })
    }
}

/// `emit`.
pub struct Emit;
impl Slot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &EmitIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let eof = i.end_of_frame != 0;
        framing(p, i.framing, &i.sink, o, |f, c| {
            if bytes.is_empty() && !eof {
                return Ok(());
            }
            f.emit(
                i.framing,
                StreamId(i.stream),
                bytes,
                eof,
                i.flags & EMIT_TEXT != 0,
                c,
            )
            .map_err(|e| format!("{e:?}"))
        })
    }
}

/// `refuse`.
pub struct Refuse;
impl Slot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &RefuseIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        let stream = (i.has_stream != 0).then_some(StreamId(i.stream));
        framing(p, i.framing, &i.sink, o, |f, c| {
            f.refusal(i.framing, stream, bytes, c)
                .map_err(|e| format!("{e:?}"))
        })
    }
}

/// `timer`.
pub struct Timer;
impl Slot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
        framing(p, i.framing, &i.sink, o, |f, c| {
            f.tick(i.framing, c).map_err(|e| format!("{e:?}"))
        })
    }
}

/// `finish`: the framer writes its close, and the framing is gone once what it owes is out.
pub struct Finish;
impl Slot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FinishIn, o: &mut FramerOut) -> Outcome {
        let reason = reason_of(i.reason);
        let out = framing(p, i.framing, &i.sink, o, |f, c| {
            f.close(i.framing, reason, c);
            c.owed.ended = true;
            Ok(())
        });
        if o.yielded.flags & YIELD_MORE == 0 {
            instance(p).owed.lock().expect("owed").remove(&i.framing);
        }
        out
    }
}

/// `encode`: a WebSocket message is its payload.
pub struct Encode;
impl Slot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    fn call(_: *mut c_void, i: &EncodeIn, o: &mut FramerOut) -> Outcome {
        let body = raw(i.body, i.body_len);
        if body.len() > i.sink.wire_cap {
            o.head.error = abi_str("encode: the message is larger than the wire buffer");
            return Outcome::Failed;
        }
        // SAFETY: the host's wire buffer, of the capacity checked above.
        unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), i.sink.wire, body.len()) };
        o.yielded.wire_len = body.len() as u64;
        Outcome::Ready
    }
}

/// Hand the host what the framing owes it, as far as the sink holds.
fn fill(owed: &mut Owed, sink: &FramerSink, o: &mut FramerOut) {
    let w = owed.wire.len().min(sink.wire_cap);
    for (k, b) in owed.wire.drain(..w).enumerate() {
        // SAFETY: `k < w <= wire_cap`.
        unsafe { sink.wire.add(k).write(b) };
    }
    let y = &mut o.yielded;
    y.wire_len = w as u64;
    let mut frame_len = 0_usize;
    let mut n = 0_usize;
    while n < sink.pieces_cap {
        let Some(piece) = owed.pieces.front_mut() else {
            break;
        };
        let room = sink.frame_cap - frame_len;
        let take = piece.bytes.len().min(room);
        if take == 0 && !piece.bytes.is_empty() {
            break;
        }
        let whole = take == piece.bytes.len();
        // SAFETY: host buffers of the stated capacities; `take <= room`, `n < pieces_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(piece.bytes.as_ptr(), sink.frame.add(frame_len), take);
            sink.pieces.add(n).write(FramePiece {
                stream: piece.stream,
                offset: frame_len as u64,
                len: take as u64,
                code: 0,
                status_class: 0,
                flags: if whole && piece.end_of_frame {
                    PIECE_END_OF_FRAME
                } else {
                    0
                } | if piece.text && take > 0 {
                    PIECE_TEXT
                } else {
                    0
                },
                _reserved: 0,
                retry_after_secs: 0,
            });
        }
        frame_len += take;
        n += 1;
        if whole {
            owed.pieces.pop_front();
        } else {
            piece.bytes.drain(..take);
        }
    }
    y.frame_len = frame_len as u64;
    y.pieces_len = n as u32;
    let more = !owed.wire.is_empty() || !owed.pieces.is_empty();
    let mut flags = 0;
    if more {
        flags |= YIELD_MORE;
    } else if owed.ended {
        flags |= YIELD_ENDED;
    }
    if let Some(at) = owed.deadline {
        flags |= YIELD_HAS_DEADLINE;
        y.next_deadline_ns = at;
    }
    y.flags = flags;
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
