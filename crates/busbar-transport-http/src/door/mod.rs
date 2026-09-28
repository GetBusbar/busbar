// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `http` DOOR: this transport as a FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`), compiled in or dropped in through the one door.
//!
//! A framer frames; it does not dial. The connector owns the socket, connection security and the
//! protocol offer (`h2,http/1.1`, or `http/1.1` alone under the http1-only key, or no offer at all
//! for a cleartext prior-knowledge upstream), and tells this framer what was agreed in
//! [`ConnFacts::agreed_protocol`]. From there each op is one step of [`engine::Framing`]:
//!
//! * `locate` reads a target URL: its authority, the name offered to the far end, and whether it
//!   asks for connection security (`https`);
//! * `begin` opens a dialled framing speaking the agreed protocol, and hands the host the bytes the
//!   far end is owed first (the HTTP/2 connection preface and settings);
//! * `encode` renders an envelope as ONE HTTP/1.1 request message, the bytes the egress
//!   cross-check reads; `emit` takes that message on a stream and sends it on the connection as
//!   whichever HTTP the connection speaks;
//! * `ingest` takes what the far end sent; `timer` is the host's clock reaching a deadline the
//!   framer asked for. Each answers the wire bytes owed and the frame pieces completed.
//!
//! A response arrives as frames on its stream: the HEAD frame (an HTTP/1.1 status line and the
//! fields, carrying the status code, its class and any `Retry-After`), one frame per body chunk,
//! the trailer section as one frame, and then an EMPTY frame that says the response is whole.
//!
//! No op pends. An op that has nothing more to do answers what it has, with the next instant it
//! must be called at when hyper is waiting on a timer.
//!
//! The accepted side is not this door's: an ingress request is served by the kernel's own door,
//! so `begin` for [`SIDE_ACCEPT`] is refused, and so are `refuse`, `detach`, `adopt` and every
//! carrier op.

pub mod engine;

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome};
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
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, SettingDecl, ShutIn,
    StatusRow, TransportTail, WriteIn, CANCEL_NOTHING_MOVED, FRAMING_STREAM, PIECE_END_OF_FRAME,
    PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER, PIECE_STREAM_FAILED, ROLE_FRAMER, SETTING_COUNT,
    SETTING_FLAG, SIDE_DIAL, STATUS_AT_FIRST_FRAME, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT,
    STATUS_OTHER, STATUS_SUCCESS, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};
use busbar_contract::transport::registry::{
    facts as tfacts, status_ns, DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
};

use engine::{Framing, Posture, Proto};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The settings this transport reads, at their 1.5.5 paths.
pub mod setting {
    /// Force cleartext HTTP/2 prior knowledge.
    pub const H2_PRIOR_KNOWLEDGE: &str = "advanced.upstream_h2_prior_knowledge";
    /// Pin the connection to HTTP/1.1.
    pub const HTTP1_ONLY: &str = "advanced.upstream_http1_only";
    /// The ceiling on one exchange up to the response head, in seconds.
    pub const REQUEST_TIMEOUT_SECS: &str = "limits.upstream_request_timeout_secs";
    /// The largest request message and response body carried, in bytes.
    pub const BODY_MAX_BYTES: &str = "limits.request_body_max_bytes";
}

const SELECTOR_CODES: [u8; crate::claims::SELECTOR_FORMS.len()] =
    form_codes(crate::claims::SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[
    abi_str(tfacts::PATH),
    abi_str(tfacts::METHOD),
    abi_str(tfacts::AUTHORITY),
    abi_str(tfacts::PEER),
];

const fn bytes_str(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

const CLAIMS: &[Claim] = &[Claim {
    key: abi_str(<crate::HttpTransport as busbar_contract::TransportMeta>::KEY),
    selector_forms: bytes_str(&SELECTOR_CODES),
    egress_selector_forms: abi_str(""),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: abi_str(status_ns::HTTP),
    session: 0,
    session_bound: 0,
    unit0_trigger: 0,
    status_at: STATUS_AT_FIRST_FRAME,
    _reserved: 0,
}];

/// What `http` composes over, as the transport's own declaration states it.
const COMPOSES_OVER: &[AbiStr] = &[abi_str(
    <crate::HttpTransport as busbar_contract::TransportMeta>::COMPOSES_OVER[0],
)];

const STATUS_ROWS: &[StatusRow] = &[
    StatusRow {
        claim: 0,
        lo: 200,
        hi: 299,
        class: STATUS_SUCCESS as u32,
    },
    StatusRow {
        claim: 0,
        lo: 400,
        hi: 499,
        class: STATUS_CALLER_FAULT as u32,
    },
    StatusRow {
        claim: 0,
        lo: 500,
        hi: 599,
        class: STATUS_FAR_END_FAULT as u32,
    },
];

const SETTINGS: &[SettingDecl] = &[
    SettingDecl {
        path: abi_str(setting::H2_PRIOR_KNOWLEDGE),
        kind: SETTING_FLAG,
        _reserved: 0,
        default: abi_str("false"),
    },
    SettingDecl {
        path: abi_str(setting::HTTP1_ONLY),
        kind: SETTING_FLAG,
        _reserved: 0,
        default: abi_str("false"),
    },
    SettingDecl {
        path: abi_str(setting::REQUEST_TIMEOUT_SECS),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str("300"),
    },
    SettingDecl {
        path: abi_str(setting::BODY_MAX_BYTES),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str("33554432"),
    },
];

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

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
    claims: CLAIMS.as_ptr(),
    claims_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: STATUS_ROWS.as_ptr(),
    status_rows_len: STATUS_ROWS.len(),
    settings: SETTINGS.as_ptr(),
    settings_len: SETTINGS.len(),
};

/// The door's Statement: the `http` framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    ..statement("http", env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// What `open` read from the settings, and the framings it holds.
pub struct Instance {
    posture: Posture,
    prior_knowledge: bool,
    http1_only: bool,
    framings: Mutex<HashMap<u64, Arc<Mutex<Held>>>>,
    next: AtomicU64,
}

/// One framing and the error text its last failed op answered (valid until the next call).
struct Held {
    framing: Framing,
    error: String,
}

/// The settings, parsed; `Err` names the first one that is not what its declaration says.
fn read_settings(b: &Blob) -> Result<(Posture, bool, bool), &'static str> {
    let text: &[u8] = if b.ptr.is_null() || b.len == 0 {
        b"{}"
    } else {
        // SAFETY: the host's blob, valid for the call.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
    };
    let v: serde_json::Value = serde_json::from_slice(text).map_err(|_| "settings: not JSON")?;
    let flag = |k: &'static str| match v.get(k) {
        None => Ok(false),
        Some(x) => x.as_bool().ok_or(k),
    };
    let count = |k: &'static str, d: u64| match v.get(k) {
        None => Ok(d),
        Some(x) => x.as_u64().ok_or(k),
    };
    let err = |_| "settings: a value is not of its declared kind";
    let prior = flag(setting::H2_PRIOR_KNOWLEDGE).map_err(err)?;
    let h1 = flag(setting::HTTP1_ONLY).map_err(err)?;
    let secs = count(setting::REQUEST_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS).map_err(err)?;
    let max = count(
        setting::BODY_MAX_BYTES,
        DEFAULT_REQUEST_BODY_MAX_BYTES as u64,
    )
    .map_err(err)?;
    Ok((
        Posture {
            // 1.5.5's egress client: keep-alive ping every 30s, 10s to answer, adaptive window on.
            keep_alive_interval: Some(Duration::from_secs(30)),
            keep_alive_timeout: Duration::from_secs(10),
            adaptive_window: true,
            head_timeout: Duration::from_secs(secs),
            max_body_bytes: usize::try_from(max).unwrap_or(usize::MAX),
        },
        prior,
        h1,
    ))
}

fn instance<'a>(p: *mut c_void) -> &'a Instance {
    // SAFETY: the host passes back the pointer `open` answered, until `close`.
    unsafe { &*p.cast::<Instance>() }
}

fn err(out: &mut OutHead, text: &'static str) {
    out.error = abi_str(text);
}

fn text(s: &AbiStr) -> &[u8] {
    if s.ptr.is_null() {
        return &[];
    }
    // SAFETY: host-borrowed input, valid for the call.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }
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
                err(o, e);
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
            Ok((posture, prior_knowledge, http1_only)) => {
                o.instance = Box::into_raw(Box::new(Instance {
                    posture,
                    prior_knowledge,
                    http1_only,
                    framings: Mutex::new(HashMap::new()),
                    next: AtomicU64::new(1),
                }))
                .cast();
                Outcome::Ready
            }
            Err(e) => {
                err(&mut o.head, e);
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

/// `tick`: the framings keep their own deadlines, so the instance asks for no tick.
pub struct Tick;
impl Slot for Tick {
    type In = TickIn;
    type Out = TickOut;
    fn call(_: *mut c_void, _: &TickIn, _: &mut TickOut) -> Outcome {
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
answer!(Drive, DriveIn, OutHead, Outcome::Ready);
answer!(Release, ReleaseIn, OutHead, Outcome::Ready);

// A framer is not a carrier: every carrier op is refused.
answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);
// No refusal, detach or adoption on a dialled HTTP connection.
answer!(Refuse, RefuseIn, FramerOut, Outcome::Refused);
answer!(Detach, FramingIn, FramerOut, Outcome::Refused);
answer!(Adopt, AdoptIn, FramerOut, Outcome::Refused);

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`.
pub struct Locate;
impl Slot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    fn call(_: *mut c_void, i: &LocateIn, o: &mut LocateOut) -> Outcome {
        let Ok(uri) = std::str::from_utf8(text(&i.target))
            .ok()
            .and_then(|t| t.parse::<http::Uri>().ok())
            .ok_or(())
        else {
            err(&mut o.head, "locate: the target is not a URL");
            return Outcome::Failed;
        };
        let secure = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => {
                err(
                    &mut o.head,
                    "locate: the target's scheme is not http or https",
                );
                return Outcome::Failed;
            }
        };
        let Some(host) = uri.host() else {
            err(&mut o.head, "locate: the target names no host");
            return Outcome::Failed;
        };
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        o.secure = u32::from(secure);
        o.has_name = 1;
        if authority.len() > i.authority_cap || host.len() > i.name_cap {
            o.authority_needed = authority.len() as u64;
            o.name_needed = host.len() as u64;
            err(&mut o.head, "locate: a host buffer is too small");
            return Outcome::Failed;
        }
        // SAFETY: host buffers of the stated capacity, checked above.
        unsafe {
            std::ptr::copy_nonoverlapping(authority.as_ptr(), i.authority_buf, authority.len());
            std::ptr::copy_nonoverlapping(host.as_ptr(), i.name_buf, host.len());
        }
        o.authority_written = authority.len() as u64;
        o.name_written = host.len() as u64;
        Outcome::Ready
    }
}

/// `begin`.
pub struct Begin;
impl Slot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &BeginIn, o: &mut FramerOut) -> Outcome {
        let inst = instance(p);
        if i.side != SIDE_DIAL {
            err(&mut o.head, "begin: http frames dialled connections only");
            return Outcome::Refused;
        }
        let agreed = if i.facts.is_null() {
            &[][..]
        } else {
            // SAFETY: host-borrowed for the call.
            text(unsafe { &(*i.facts).agreed_protocol })
        };
        let proto = match agreed {
            b"h2" => Proto::H2,
            b"http/1.1" => Proto::H1,
            b"" if inst.prior_knowledge && !inst.http1_only => Proto::H2,
            b"" => Proto::H1,
            _ => {
                err(
                    &mut o.head,
                    "begin: the agreed protocol is not http/1.1 or h2",
                );
                return Outcome::Refused;
            }
        };
        let Ok(target) = std::str::from_utf8(text(&i.target)) else {
            err(&mut o.head, "begin: the target is not text");
            return Outcome::Failed;
        };
        let Ok(framing) = Framing::dial(target, proto, inst.posture, i.sink.now_monotonic_ns)
        else {
            err(&mut o.head, "begin: the target is not a URL");
            return Outcome::Failed;
        };
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        let held = Arc::new(Mutex::new(Held {
            framing,
            error: String::new(),
        }));
        inst.framings
            .lock()
            .expect("framings")
            .insert(token, held.clone());
        o.framing = token;
        let mut h = held.lock().expect("framing");
        step(&mut h, &i.sink, o, |_| Ok(()))
    }
}

/// `ingest`.
pub struct Ingest;
impl Slot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &IngestIn, o: &mut FramerOut) -> Outcome {
        let bytes = raw(i.bytes, i.len);
        with(p, i.framing, &i.sink, o, |f| {
            f.ingest(bytes, i.end != 0);
            Ok(())
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
        with(p, i.framing, &i.sink, o, |f| f.emit(i.stream, bytes))
    }
}

/// `timer`.
pub struct Timer;
impl Slot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    fn call(p: *mut c_void, i: &FramingIn, o: &mut FramerOut) -> Outcome {
        with(p, i.framing, &i.sink, o, |_| Ok(()))
    }
}

/// `finish`.
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
        o.yielded.flags = YIELD_ENDED;
        if removed.is_some() {
            Outcome::Ready
        } else {
            o.yielded.flags = 0;
            err(&mut o.head, "finish: no such framing");
            Outcome::Failed
        }
    }
}

/// `encode`: one HTTP/1.1 request message into the wire buffer.
pub struct Encode;
impl Slot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    fn call(_: *mut c_void, i: &EncodeIn, o: &mut FramerOut) -> Outcome {
        let fields: &[busbar_contract::abi::transport::Field] = if i.fields.is_null() {
            &[]
        } else {
            // SAFETY: host-borrowed for the call.
            unsafe { std::slice::from_raw_parts(i.fields, i.fields_len) }
        };
        let mut pairs = Vec::with_capacity(fields.len());
        for f in fields {
            let Ok(name) = std::str::from_utf8(text(&f.name)) else {
                err(&mut o.head, "encode: a field name is not text");
                return Outcome::Failed;
            };
            pairs.push((name, text(&f.value)));
        }
        let Ok(bytes) = crate::transport::render_envelope(&pairs, raw(i.body, i.body_len)) else {
            err(
                &mut o.head,
                "encode: the envelope cannot be expressed on this wire",
            );
            return Outcome::Failed;
        };
        if bytes.len() > i.sink.wire_cap {
            err(
                &mut o.head,
                "encode: the rendered message is larger than the wire buffer",
            );
            return Outcome::Failed;
        }
        // SAFETY: the host's wire buffer, of the capacity checked above.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.sink.wire, bytes.len()) };
        o.yielded.wire_len = bytes.len() as u64;
        Outcome::Ready
    }
}

fn raw<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: host-borrowed for the call.
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// Run `f` on framing `token`, then drive it and fill the sink.
fn with(
    p: *mut c_void,
    token: u64,
    sink: &FramerSink,
    o: &mut FramerOut,
    f: impl FnOnce(&mut Framing) -> Result<(), engine::Failure>,
) -> Outcome {
    let held = instance(p)
        .framings
        .lock()
        .expect("framings")
        .get(&token)
        .cloned();
    let Some(held) = held else {
        err(&mut o.head, "no such framing");
        return Outcome::Failed;
    };
    let mut h = held.lock().expect("framing");
    step(&mut h, sink, o, f)
}

fn step(
    h: &mut Held,
    sink: &FramerSink,
    o: &mut FramerOut,
    f: impl FnOnce(&mut Framing) -> Result<(), engine::Failure>,
) -> Outcome {
    if let Err(e) = f(&mut h.framing) {
        return failed(h, o, e.0);
    }
    h.framing.drive(sink.now_monotonic_ns, sink.now_unix_ns);
    let pending = h.framing.wire_pending() || !h.framing.pieces().is_empty();
    if let Some(e) = h.framing.failure().cloned() {
        if !pending {
            return failed(h, o, e.0);
        }
    }
    fill(&mut h.framing, sink, o);
    Outcome::Ready
}

fn failed(h: &mut Held, o: &mut FramerOut, text: String) -> Outcome {
    h.error = text;
    o.head.error = AbiStr {
        ptr: h.error.as_ptr(),
        len: h.error.len(),
    };
    Outcome::Failed
}

/// Hand the host what the framing owes it, as far as the sink holds.
fn fill(f: &mut Framing, sink: &FramerSink, o: &mut FramerOut) {
    let wire = f.take_wire(sink.wire_cap);
    if !wire.is_empty() {
        // SAFETY: the host's wire buffer; `take_wire` took at most its capacity.
        unsafe { std::ptr::copy_nonoverlapping(wire.as_ptr(), sink.wire, wire.len()) };
    }
    let y = &mut o.yielded;
    y.wire_len = wire.len() as u64;
    let mut frame_len = 0_usize;
    let mut n = 0_usize;
    while n < sink.pieces_cap {
        let Some(piece) = f.pieces().front_mut() else {
            break;
        };
        let room = sink.frame_cap - frame_len;
        let take = piece.bytes.len().min(room);
        if take == 0 && !piece.bytes.is_empty() {
            break;
        }
        let whole = take == piece.bytes.len();
        let mut flags = if whole { PIECE_END_OF_FRAME } else { 0 };
        // A failure frame may span pieces like any other; its LAST piece says the stream failed.
        if piece.failed && whole {
            flags |= PIECE_STREAM_FAILED;
        }
        let mut fp = FramePiece {
            stream: piece.stream,
            offset: frame_len as u64,
            len: take as u64,
            status_code: 0,
            status_class: 0,
            flags: 0,
            _reserved: [0; 2],
            retry_after_secs: 0,
        };
        if let Some(code) = piece.status {
            flags |= PIECE_HAS_CODE;
            fp.status_code = u32::from(code);
            fp.status_class = class_of(code);
        }
        if let Some(secs) = piece.retry_after_secs {
            flags |= PIECE_HAS_RETRY_AFTER;
            fp.retry_after_secs = secs;
        }
        fp.flags = flags;
        // SAFETY: host buffers of the stated capacities; `take <= room`, `n < pieces_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(piece.bytes.as_ptr(), sink.frame.add(frame_len), take);
            sink.pieces.add(n).write(fp);
        }
        frame_len += take;
        n += 1;
        if whole {
            f.pieces().pop_front();
        } else {
            let rest = piece.bytes.slice(take..);
            piece.bytes = rest;
        }
    }
    y.frame_len = frame_len as u64;
    y.pieces_len = n as u32;
    let more = f.wire_pending() || !f.pieces().is_empty();
    let mut flags = 0;
    if more {
        flags |= YIELD_MORE;
    }
    if let Some(at) = f.next_deadline() {
        flags |= YIELD_HAS_DEADLINE;
        y.next_deadline_ns = at;
    }
    if !more && f.ended() {
        flags |= YIELD_ENDED;
    }
    y.flags = flags;
}

fn class_of(code: u16) -> u8 {
    match code {
        200..=299 => STATUS_SUCCESS,
        400..=499 => STATUS_CALLER_FAULT,
        500..=599 => STATUS_FAR_END_FAULT,
        _ => STATUS_OTHER,
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

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
