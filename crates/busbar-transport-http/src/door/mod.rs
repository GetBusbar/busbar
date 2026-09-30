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
//! and then an EMPTY frame that says the response is whole. A trailer section is not handed up:
//! 1.5.5's client read a response through reqwest, which yields data only.
//!
//! `locate` also answers this framer's protocol offer for a secured connection (ALPN, most
//! preferred first): `h2, http/1.1`, or `http/1.1` alone under the http1-only key, exactly as
//! 1.5.5's client offered. The connector offers it and hands back what was agreed.
//!
//! One clock bounds each exchange, as 1.5.5's `limits.upstream_request_timeout_secs` did: from the
//! attempt's start (the deadline the caller stamps on `emit`) to the response body's end.
//!
//! No op pends. An op that has nothing more to do answers what it has, with the next instant it
//! must be called at when hyper is waiting on a timer.
//!
//! Every slot is a `SafeSlot` on the SDK's safe surface: the instance is the SDK's typed
//! `sdk::Instance<Instance>`, host-lent bytes and host buffers go through `Lent` and `HostBuf`, and
//! this crate holds no `unsafe`.
//!
//! The accepted side is not this door's: an ingress request is served by the kernel's own door,
//! so `begin` for [`SIDE_ACCEPT`] is refused, and so are `refuse`, `detach`, `adopt` and every
//! carrier op.

pub mod engine;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::sdk::{self as sdk, HostBuf, Lent, Out, Safe, SafeSlot};
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

/// The schemes `http` claims, by name: the Statement's `claims`, the one place they are stated.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(
    <crate::HttpTransport as busbar_contract::TransportMeta>::KEY,
)];

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
const CLAIMS: &[Claim] = &[Claim {
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
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
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
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
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
}

/// The settings blob's bytes, parsed; `Err` names the first one that is not what its declaration
/// says. An absent blob reads as `{}`.
fn read_settings(bytes: &[u8]) -> Result<(Posture, bool, bool), &'static str> {
    let text: &[u8] = if bytes.is_empty() { b"{}" } else { bytes };
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
            request_timeout: Duration::from_secs(secs),
            max_body_bytes: usize::try_from(max).unwrap_or(usize::MAX),
        },
        prior,
        h1,
    ))
}

/// One slot body on the SDK's safe surface, over this framer's [`Instance`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Instance;
            fn call(
                $inst: sdk::Instance<'_, Instance>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome $body
        }
    };
}

// ── the lifecycle ────────────────────────────────────────────────────────────────────────────────

slot!(
    /// `validate`.
    Validate, ValidateIn, OutHead, |_, i, o| {
        match read_settings(i.field(|x| &x.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(e) => {
                o.error(e);
                Outcome::Failed
            }
        }
    }
);

slot!(
    /// `open`.
    Open, OpenIn, OpenOut, |instance, i, o| {
        match read_settings(i.field(|x| &x.settings).bytes()) {
            Ok((posture, prior_knowledge, http1_only)) => {
                instance.open(Instance {
                    posture,
                    prior_knowledge,
                    http1_only,
                    framings: Mutex::new(HashMap::new()),
                    next: AtomicU64::new(1),
                });
                Outcome::Ready
            }
            Err(e) => {
                o.error(e);
                Outcome::Failed
            }
        }
    }
);

slot!(
    /// `close`: answering READY, the SDK drops the instance.
    Close, InHead, OutHead, |_, _, _out| { Outcome::Ready }
);

slot!(
    /// `cancel`: no framer op pends, so nothing is ever in flight to cancel.
    Cancel, CancelIn, CancelOut, |_, _, o| {
        o.set(|x| &x.disposition, CANCEL_NOTHING_MOVED);
        Outcome::Ready
    }
);

slot!(
    /// `tick`: the framings keep their own deadlines, so the instance asks for no tick.
    Tick, TickIn, TickOut, |_, _, _out| { Outcome::Ready }
);

macro_rules! answer {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        slot!(
            #[doc = concat!("`", stringify!($name), "`.")]
            $name,
            $in,
            $out,
            |_, _, _out| { $outcome }
        );
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

/// 1.5.5's client's protocol offer (ALPN), in the handshake's ProtocolNameList encoding.
const OFFER_H2_H1: &[u8] = b"\x02h2\x08http/1.1";
/// The same under the http1-only key.
const OFFER_H1: &[u8] = b"\x08http/1.1";

/// The protocol offer `locate` answers: none in the clear, else 1.5.5's by the http1-only key.
fn offer_for(secure: bool, http1_only: bool) -> &'static [u8] {
    match (secure, http1_only) {
        (false, _) => &[],
        (true, true) => OFFER_H1,
        (true, false) => OFFER_H2_H1,
    }
}

/// `locate`.
pub struct Locate;
impl SafeSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    type State = Instance;
    fn call(
        p: sdk::Instance<'_, Instance>,
        i: Lent<'_, LocateIn>,
        mut o: Out<'_, LocateOut>,
    ) -> Outcome {
        let Ok(uri) = std::str::from_utf8(i.field(|x| &x.target).bytes())
            .ok()
            .and_then(|t| t.parse::<http::Uri>().ok())
            .ok_or(())
        else {
            o.error("locate: the target is not a URL");
            return Outcome::Failed;
        };
        let secure = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => {
                o.error("locate: the target's scheme is not http or https");
                return Outcome::Failed;
            }
        };
        let Some(host) = uri.host() else {
            o.error("locate: the target names no host");
            return Outcome::Failed;
        };
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        // The offer exists only where a handshake does: on a secured connection.
        let offer = offer_for(secure, p.get().is_some_and(|x| x.http1_only));
        o.set(|x| &x.secure, u32::from(secure));
        o.set(|x| &x.has_name, 1);
        let (mut a, mut n, mut l) = (i.authority_buf(), i.name_buf(), i.alpn_buf());
        a.extend(authority.as_bytes());
        n.extend(host.as_bytes());
        l.extend(offer);
        // One short answer for all three buffers, each at its full size.
        let short = !(a.fits() && n.fits() && l.fits());
        let (aw, and) = a.settle(short);
        let (nw, nnd) = n.settle(short);
        let (lw, lnd) = l.settle(short);
        o.set(|x| &x.authority_written, aw as u64);
        o.set(|x| &x.authority_needed, and as u64);
        o.set(|x| &x.name_written, nw as u64);
        o.set(|x| &x.name_needed, nnd as u64);
        o.set(|x| &x.alpn_written, lw as u64);
        o.set(|x| &x.alpn_needed, lnd as u64);
        if short {
            o.error("locate: a host buffer is too small");
            return Outcome::Failed;
        }
        Outcome::Ready
    }
}

/// `begin`.
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    type State = Instance;
    fn call(
        p: sdk::Instance<'_, Instance>,
        i: Lent<'_, BeginIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(inst) = p.get() else {
            return Outcome::Failed;
        };
        if i.side != SIDE_DIAL {
            o.error("begin: http frames dialled connections only");
            return Outcome::Refused;
        }
        let agreed = i
            .facts()
            .map_or(&[][..], |f| f.field(|x| &x.agreed_protocol).bytes());
        let proto = match agreed {
            b"h2" => Proto::H2,
            b"http/1.1" => Proto::H1,
            b"" if inst.prior_knowledge && !inst.http1_only => Proto::H2,
            b"" => Proto::H1,
            _ => {
                o.error("begin: the agreed protocol is not http/1.1 or h2");
                return Outcome::Refused;
            }
        };
        let Ok(target) = std::str::from_utf8(i.field(|x| &x.target).bytes()) else {
            o.error("begin: the target is not text");
            return Outcome::Failed;
        };
        let Ok(framing) = Framing::dial(target, proto, inst.posture, i.sink.now_monotonic_ns)
        else {
            o.error("begin: the target is not a URL");
            return Outcome::Failed;
        };
        let token = inst.next.fetch_add(1, Ordering::Relaxed);
        let held = Arc::new(Mutex::new(Held { framing }));
        inst.framings
            .lock()
            .expect("framings")
            .insert(token, held.clone());
        o.set(|x| &x.framing, token);
        let mut h = held.lock().expect("framing");
        step(&mut h, i.field(|x| &x.sink), &mut o, |_| Ok(()))
    }
}

/// `ingest`.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    type State = Instance;
    fn call(
        p: sdk::Instance<'_, Instance>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.ingest(bytes, i.end != 0);
            Ok(())
        })
    }
}

/// `emit`.
pub struct Emit;
impl SafeSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    type State = Instance;
    fn call(
        p: sdk::Instance<'_, Instance>,
        i: Lent<'_, EmitIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        let (now, deadline) = (i.sink.now_monotonic_ns, i.deadline_ns);
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.emit(i.stream, bytes, now, deadline)
        })
    }
}

/// `timer`.
pub struct Timer;
impl SafeSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    type State = Instance;
    fn call(
        p: sdk::Instance<'_, Instance>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(&p, i.framing, i.field(|x| &x.sink), &mut o, |_| Ok(()))
    }
}

/// `finish`.
pub struct Finish;
impl SafeSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    type State = Instance;
    fn call(
        p: sdk::Instance<'_, Instance>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let removed = p
            .get()
            .and_then(|inst| inst.framings.lock().expect("framings").remove(&i.framing));
        o.set(|x| &x.yielded.flags, YIELD_ENDED);
        if removed.is_some() {
            Outcome::Ready
        } else {
            o.set(|x| &x.yielded.flags, 0);
            o.error("finish: no such framing");
            Outcome::Failed
        }
    }
}

/// `encode`: one HTTP/1.1 request message into the wire buffer.
pub struct Encode;
impl SafeSlot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    type State = Instance;
    fn call(
        _: sdk::Instance<'_, Instance>,
        i: Lent<'_, EncodeIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let fields = i.fields();
        let mut pairs = Vec::with_capacity(fields.len());
        for f in fields.iter() {
            let Ok(name) = f.field(|x| &x.name).as_str() else {
                o.error("encode: a field name is not text");
                return Outcome::Failed;
            };
            pairs.push((name, f.field(|x| &x.value).bytes()));
        }
        let Ok(bytes) = crate::transport::render_envelope(&pairs, i.body()) else {
            o.error("encode: the envelope cannot be expressed on this wire");
            return Outcome::Failed;
        };
        let mut wire = i.field(|x| &x.sink).wire();
        if bytes.len() > wire.cap() {
            o.error("encode: the rendered message is larger than the wire buffer");
            return Outcome::Failed;
        }
        wire.extend(&bytes);
        o.set(|x| &x.yielded.wire_len, wire.written() as u64);
        Outcome::Ready
    }
}

/// Run `f` on framing `token`, then drive it and fill the sink.
fn with(
    p: &sdk::Instance<'_, Instance>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Framing) -> Result<(), engine::Failure>,
) -> Outcome {
    let held = p
        .get()
        .and_then(|inst| inst.framings.lock().expect("framings").get(&token).cloned());
    let Some(held) = held else {
        o.error("no such framing");
        return Outcome::Failed;
    };
    let mut h = held.lock().expect("framing");
    step(&mut h, sink, o, f)
}

fn step(
    h: &mut Held,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    f: impl FnOnce(&mut Framing) -> Result<(), engine::Failure>,
) -> Outcome {
    if let Err(e) = f(&mut h.framing) {
        return failed(o, e.0);
    }
    h.framing.drive(sink.now_monotonic_ns, sink.now_unix_ns);
    let pending = h.framing.wire_pending() || !h.framing.pieces().is_empty();
    if let Some(e) = h.framing.failure().cloned() {
        if !pending {
            return failed(o, e.0);
        }
    }
    fill(&mut h.framing, sink, o);
    Outcome::Ready
}

fn failed(o: &mut Out<'_, FramerOut>, text: String) -> Outcome {
    o.fail(Refusal::failed(text))
}

/// Hand the host what the framing owes it, as far as the sink holds.
fn fill(f: &mut Framing, sink: Lent<'_, FramerSink>, o: &mut Out<'_, FramerOut>) {
    let mut wire_buf = sink.wire();
    let wire = f.take_wire(wire_buf.cap());
    wire_buf.extend(&wire);
    let mut y = o.get().yielded;
    y.wire_len = wire_buf.written() as u64;
    let (mut frame, mut pieces): (HostBuf<'_, u8>, HostBuf<'_, FramePiece>) =
        (sink.frame(), sink.pieces());
    let mut frame_len = 0_usize;
    let mut n = 0_usize;
    while n < pieces.cap() {
        let Some(piece) = f.pieces().front_mut() else {
            break;
        };
        let room = frame.cap() - frame_len;
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
            _reserved: 0,
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
        // `take <= room` and `n < pieces_cap`: both fit.
        frame.extend(&piece.bytes[..take]);
        pieces.push(fp);
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
    o.set(|x| &x.yielded, y);
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
        validate: Safe<Validate>,
        open: Safe<Open>,
        refresh: Safe<Refresh>,
        retire: Safe<Retire>,
        tick: Safe<Tick>,
        drive: Safe<Drive>,
        cancel: Safe<Cancel>,
        release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
