// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S SCRIPT: a claim/frame script any transport answers, driven as the kernel
//! drives a transport door (`root::doors::Dispatched`: `open`, the awaited `ready`, then every
//! framer op through `Plugin::call`). Ported from lane-conf-transport's
//! `transport_door_conformance_tests.rs` (one script of the whole table, a TIGHT sink re-driven on
//! `YIELD_MORE`, equal transcripts, exact crossings) with every byte and every expected framing
//! moved into the plugin's inputs. Inputs (`conformance.json`):
//!
//! A byte input is a JSON string (its UTF-8 bytes) or `{ "hex": "<bytes>" }`.
//!
//! ```json
//! { "settings": <the settings it opens over>,
//!   "transport": {
//!     "locate": "refused" | {
//!         "reads":   [{ "target": "<a target it reads>", "authority": "<what it dials>", "secure": false,
//!                       "has_name": false /* optional: it names the far end a certificate is checked against */ }, ...],
//!         "refuses": ["<a target it refuses: FAILED>", ...] },
//!     "dial": {
//!         "target":  "<what begin dials>",          /* optional, default "": a wire whose
//!                                                       dial reads a target (ws) names it */
//!         "opening": "<what begin writes>",         /* optional, default "": a wire that opens
//!                                                       with bytes of its own (ws's upgrade
//!                                                       request) states them */
//!         "answer":  "<far bytes before the emit>", /* optional: the far side's opening answer
//!                                                       (ws's 101), read before the first frame */
//!         "answer_frames": ["<what it yields>", ...], /* optional, default none: the frames the
//!                                                       answer yields (ws: the switching
//!                                                       response's head, HEAD-FIELDS) */
//!         "emit":   "<one frame the host emits>",   "wire":   "<the wire bytes it becomes>",
//!         "request": { "fields": [["<name>", "<value>"], ...], "body": "<body>" },
//!                                                    /* optional, in place of emit: the request
//!                                                       the host encodes, its head merged with
//!                                                       the framer's own head lines (locate's
//!                                                       defaults) whose names it lacks, then
//!                                                       the body's content-length where locate
//!                                                       states it (states_length) */
//!         "ingest": "<bytes from the far side>",    "frames": ["<the frames they are>", ...],
//!         "ingest_wire": "<what reading them writes>", /* optional: the far side closed in them
//!                                                       and the close is answered (ws); the
//!                                                       frames end there */
//!         "ingest_ends": false,                     /* optional, default true: whether what
//!                                                       ingest_wire writes ends the connection */
//!         "finish": "<what finish writes>",         /* optional, default "" (ws's close) */
//!         "deadline": ["begin", "emit", "ingest"] },/* optional: the answers that carry
//!                                                       YIELD_HAS_DEADLINE (`true`: the emit's) */
//!     "encode": [{ "body": "<body>", "fields": [["<name>", "<value>"], ...],
//!                  "wire": "<the rendering>" | null /* FAILED */ }, ...],
//!     "refuse": "refused" /* a framer that frames DIALLED connections only: `begin` on the
//!                            accept side answers REFUSED, so there is no accepted framing to
//!                            refuse on and none to upgrade; `detach` and `adopt` must then be
//!                            "refused" too (and no "handoff" object) */ | {
//!                 "bytes": "<a refusal>", "wire": "<the wire bytes it becomes>",
//!                 "begin":   "<what begin on the accept side writes>",       /* optional (h2) */
//!                 "refused": true, /* optional: the refuse op answers REFUSED (a call-per-path
//!                                     wire refuses a call, never a connection); "wire" is
//!                                     then "" */
//!                 "ends": true,                                       /* optional: it closes */
//!                 "opening": "<far bytes the accepted framing reads first>",  /* optional */
//!                 "answer":  "<what reading them writes>" },                 /* optional */
//!     "handoff": "refused" | {
//!         "ingest":   "<bytes ingested once through the tight sink, then the upgrade>",
//!         "detached": "<what detach hands back: ingested and not yet answered>",
//!         "adopt":    "<the leftover another stack gave up>",
//!         "frames":   ["<the frames the adopted leftover is>", ...] }
//!     /* or, the two halves of a handoff as separate capabilities (a wire may take an upgrade it
//!        never gives one up for, as ws does): */
//!     "detach": "refused" | { "ingest": "...", "detached": "..." },
//!     "adopt":  "refused" | { "leftover": "...", "frames": [...], "wire": "<what it writes>" } } }
//! ```
//!
//! THE PINS (M6/contract). Every step is one ticket-less crossing but:
//! * `facts` and `ready` without a stated `ready` ([`super::ready_step`]): 0, no op;
//! * `begin unopened` and `begin after close`: 0, the dispatcher answers an op on an instance that
//!   is not open (REFUSED) or closed (FAULT) without a crossing;
//! * `locate short`: 2, the authority buffer of one byte answers SHORT and the ONE re-call
//!   ([`Plugin::recall`]) with the size it named is +1;
//! * a re-driven framer op (`begin`, `emit`, `ingest`, `refuse`, `detach`, `adopt`, `finish`): one
//!   crossing per
//!   sink-full, the host calling again with no new bytes while the framer answers `YIELD_MORE`
//!   (the ABI's backpressure, never a short buffer): `ceil(bytes / cap)` of what the sink must
//!   carry, at least 1, over a sink of [`TIGHT_WIRE`] wire bytes, [`TIGHT_FRAME`] frame bytes and
//!   ONE piece (so every frame's pieces are counted alone).
//!
//! THE SCRIPT IS CHOSEN BY THE DECLARED ROLE ([`script_for`]): a stream FRAMER runs the framer script
//! above; a framer whose tail states `FRAMING_DATAGRAM` runs the datagram script
//! (`super::datagram`: its every call carries the host's lane); a CARRIER runs the carrier script (`super::carrier`: listen/accept, dial, read, write, flush,
//! shut and arrival over the suite's host I/O). An unknown role fails the suite.

use busbar_contract::abi::mechanism::call::{Field, OutHead, Outcome};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn,
    PIECE_END_OF_FRAME, ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE,
    YIELD_MORE,
};

use super::{
    abi_bytes, asis, closed, crossings, dispatcher, input, load, opened, output, refreshed, Fold,
    Leg, Subject, Want,
};
use crate::dispatch::{Bind, Dispatcher};
use busbar_contract::abi::transport::ROLE_CARRIER;
use serde_json::Value;

/// The script a transport's declared role runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Script {
    /// The stream framer script (this module).
    Framer,
    /// The datagram framer script (`super::datagram`): a framer whose tail states
    /// `FRAMING_DATAGRAM`, every call of which carries the host's datagram lane.
    Datagram,
    /// The carrier script (`super::carrier`).
    Carrier,
}

/// Which script a transport's declared `role` runs, and for a framer, which framing its tail
/// states (`datagram`). Any other role is not a transport this suite knows, and fails.
///
/// # Errors
///
/// The role is no known role.
pub(super) fn script_for(role: u32, datagram: bool) -> Result<Script, String> {
    match role {
        ROLE_FRAMER if datagram => Ok(Script::Datagram),
        ROLE_FRAMER => Ok(Script::Framer),
        ROLE_CARRIER => Ok(Script::Carrier),
        other => Err(format!(
            "UnknownRole: the transport declares role {other}, neither ROLE_CARRIER nor ROLE_FRAMER"
        )),
    }
}
use crate::dispatch::kinds::transport::{Transport, TransportFacts};
use crate::dispatch::{Called, Frame, InFrame, OutFrame, Plugin};

/// The tight sink's wire bytes.
pub const TIGHT_WIRE: usize = 4;
/// The tight sink's frame bytes.
pub const TIGHT_FRAME: usize = 3;
/// The ample sink's bytes (each buffer): room for any script input.
const AMPLE: usize = 4096;
/// A re-drive that has not ended after this many calls is a framer that never drains.
const MAX_REDRIVE: usize = 4096;

// ---- the inputs ----

/// One byte-string input: a JSON string's UTF-8 bytes, or `{ "hex": "<bytes>" }` for bytes a JSON
/// string cannot hold (a binary frame's header, say).
pub(super) fn text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: transport.{what} is missing"),
        serde_json::Value::Object(o) if o.len() == 1 && o.contains_key("hex") => o["hex"]
            .as_str()
            .and_then(unhex)
            .unwrap_or_else(|| panic!("conformance.json: transport.{what}.hex is not hex")),
        other => other.to_string().into_bytes(),
    }
}

/// `hex`'s bytes (two digits a byte, either case); `None` for anything else.
fn unhex(hex: &str) -> Option<Vec<u8>> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// An optional input: absent is empty.
fn opt_text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    if v.is_null() {
        Vec::new()
    } else {
        text(v, what)
    }
}

fn texts(v: &serde_json::Value, what: &str) -> Vec<Vec<u8>> {
    v.as_array()
        .unwrap_or_else(|| panic!("conformance.json: transport.{what} must be an array"))
        .iter()
        .map(|x| text(x, what))
        .collect()
}

pub(super) fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `ceil(len / cap)`, at least 1: the crossings a re-driven op makes to carry `len` bytes.
fn sinkfuls(len: usize, cap: usize) -> u64 {
    len.div_ceil(cap).max(1) as u64
}

/// The crossings a re-driven op makes to answer `frames` one piece at a time.
fn frame_sinkfuls(frames: &[Vec<u8>]) -> u64 {
    frames
        .iter()
        .map(|f| f.len().div_ceil(TIGHT_FRAME).max(1) as u64)
        .sum::<u64>()
        .max(1)
}

// ---- the host's sink ----

/// The host's buffers for framer ops.
pub(super) struct Sink {
    pub(super) wire: Vec<u8>,
    pub(super) frame: Vec<u8>,
    pub(super) pieces: Vec<FramePiece>,
}

impl Sink {
    pub(super) fn new(wire: usize, frame: usize, pieces: usize) -> Self {
        let piece = FramePiece {
            stream: 0,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            fault: 0,
            flags: 0,
            retry_after_secs: 0,
            declared_len: 0,
        };
        Self {
            wire: vec![0; wire],
            frame: vec![0; frame],
            pieces: vec![piece; pieces],
        }
    }

    /// The tight sink: every op that owes more than it holds answers `YIELD_MORE`.
    fn tight() -> Self {
        Self::new(TIGHT_WIRE, TIGHT_FRAME, 1)
    }

    fn ample() -> Self {
        Self::new(AMPLE, AMPLE, 16)
    }

    pub(super) fn raw(&mut self) -> FramerSink {
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
}

/// What a (re-driven) framer op answered, gathered across its calls.
#[derive(Default)]
struct Yielded {
    /// The last call's outcome and error text.
    last: String,
    outcome: Option<Outcome>,
    wire: Vec<u8>,
    /// Whole frames (their last piece carried `PIECE_END_OF_FRAME`), and the piece flags seen.
    frames: Vec<Vec<u8>>,
    /// A frame begun and not ended.
    partial: Vec<u8>,
    /// Frame bytes answered with no piece (what `detach` hands back).
    raw: Vec<u8>,
    flags: u32,
    framing: u64,
}

impl Yielded {
    fn take(&mut self, c: &Called, o: &FramerOut, sink: &Sink) {
        let text = c
            .error
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        self.last = format!("{:?} lease={} err={text:?}", c.outcome, c.lease != 0);
        self.outcome = Some(c.outcome);
        self.flags = o.yielded.flags;
        if o.framing != 0 {
            self.framing = o.framing;
        }
        if c.outcome != Outcome::Ready {
            return;
        }
        // The dispatcher's kind check held every length within its buffer before this reads it.
        let wire_len = (o.yielded.wire_len as usize).min(sink.wire.len());
        self.wire.extend_from_slice(&sink.wire[..wire_len]);
        let frame_len = (o.yielded.frame_len as usize).min(sink.frame.len());
        let pieces = (o.yielded.pieces_len as usize).min(sink.pieces.len());
        if pieces == 0 {
            self.raw.extend_from_slice(&sink.frame[..frame_len]);
        }
        for p in &sink.pieces[..pieces] {
            let at = p.offset as usize;
            let bytes = sink
                .frame
                .get(at..at + p.len as usize)
                .unwrap_or_else(|| panic!("a piece past the frame bytes: {p:?}"));
            self.partial.extend_from_slice(bytes);
            if p.flags & PIECE_END_OF_FRAME != 0 {
                self.frames.push(std::mem::take(&mut self.partial));
            }
        }
    }

    fn ready(&self) -> bool {
        self.outcome == Some(Outcome::Ready)
    }

    /// The transcript line: deterministic (no framing token, only whether one was minted).
    fn line(&self) -> String {
        let frames: Vec<String> = self.frames.iter().map(|f| lossy(f)).collect();
        format!(
            "{} wire={:?} frames={frames:?} partial={:?} raw={:?} flags={} framing={}",
            self.last,
            lossy(&self.wire),
            lossy(&self.partial),
            lossy(&self.raw),
            self.flags,
            self.framing != 0
        )
    }
}

// ---- the framer ops ----

/// One framer op, by what it carries.
#[derive(Clone, Copy)]
enum Op<'a> {
    Begin(u32, &'a [u8]),
    Ingest(&'a [u8], bool),
    Emit(&'a [u8], bool),
    Refuse(&'a [u8]),
    Encode(&'a [u8], &'a [Field]),
    Adopt(&'a [u8]),
    Finish,
    Detach,
    Timer,
}

impl Op<'_> {
    /// The re-call a `YIELD_MORE` asks for: the same op with no new bytes. An `adopt` minted its
    /// framing on its first call, so what it still owes is answered by a `timer` on it.
    fn again(self) -> Self {
        match self {
            Op::Ingest(_, end) => Op::Ingest(&[], end),
            // The host's re-call carries no bytes and completes no frame (as the connector's does).
            Op::Emit(..) => Op::Emit(&[], false),
            Op::Refuse(_) => Op::Refuse(&[]),
            Op::Adopt(_) | Op::Begin(..) => Op::Timer,
            other => other,
        }
    }
}

pub(super) fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (Called, O) {
    let mut f = Frame::new(i, output::<O>());
    let c = p.call(s, &mut f);
    (c, f.out)
}

/// One crossing of `op` on `framing` into `sink`.
fn cross(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> (Called, FramerOut) {
    let raw = sink.raw();
    match op {
        Op::Begin(side, target) => {
            let mut i: BeginIn = input();
            (i.side, i.sink, i.target) = (side, raw, abi_bytes(target));
            // The suite runs no connection security: its connections ride in the clear.
            i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
            go(p, slot::BEGIN, i)
        }
        Op::Ingest(bytes, end) => {
            let mut i: IngestIn = input();
            (i.framing, i.bytes, i.len, i.end, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::INGEST, i)
        }
        Op::Emit(bytes, end) => {
            let mut i: EmitIn = input();
            (i.framing, i.bytes, i.len, i.end_of_frame, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::EMIT, i)
        }
        Op::Refuse(bytes) => {
            let mut i: RefuseIn = input();
            (i.framing, i.bytes, i.len, i.sink) = (framing, bytes.as_ptr(), bytes.len(), raw);
            go(p, slot::REFUSE, i)
        }
        Op::Encode(body, fields) => {
            let mut i: EncodeIn = input();
            (i.body, i.body_len, i.sink) = (body.as_ptr(), body.len(), raw);
            (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
            go(p, slot::ENCODE, i)
        }
        Op::Adopt(leftover) => {
            let mut i: AdoptIn = input();
            (i.side, i.leftover, i.leftover_len, i.sink) =
                (SIDE_ACCEPT, leftover.as_ptr(), leftover.len(), raw);
            go(p, slot::ADOPT, i)
        }
        Op::Finish => {
            let mut i: FinishIn = input();
            (i.framing, i.sink) = (framing, raw);
            go(p, slot::FINISH, i)
        }
        Op::Detach | Op::Timer => {
            let mut i: FramingIn = input();
            (i.framing, i.sink) = (framing, raw);
            let s = if matches!(op, Op::Detach) {
                slot::DETACH
            } else {
                slot::TIMER
            };
            go(p, s, i)
        }
    }
}

/// `op` once, gathered.
fn once(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> Yielded {
    let mut y = Yielded::default();
    let (c, o) = cross(p, framing, op, sink);
    y.take(&c, &o, sink);
    y
}

/// `op`, then its re-call for as long as the sink was too small (`YIELD_MORE`): the host's own
/// re-drive.
fn pump(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> Yielded {
    let mut y = Yielded::default();
    let (c, o) = cross(p, framing, op, sink);
    y.take(&c, &o, sink);
    let framing = if framing == 0 { y.framing } else { framing };
    let mut n = 0;
    while y.ready() && y.flags & YIELD_MORE != 0 {
        n += 1;
        assert!(n < MAX_REDRIVE, "a framer answered YIELD_MORE {n} times");
        let (c, o) = cross(p, framing, op.again(), sink);
        y.take(&c, &o, sink);
    }
    y
}

/// The ops of the role a framer does not play, in slot order: each is the SDK's REFUSED stub
/// (abi/transport: "a transport fills the slots of the role it does not play with a stub that
/// answers REFUSED"). One crossing each.
const CARRIER_OPS: [&str; 8] = [
    "listen", "accept", "dial", "read", "write", "flush", "shut", "arrival",
];

pub(super) fn carrier_ops(p: &Plugin<Transport>) -> [Outcome; 8] {
    [
        go::<_, ListenOut>(p, slot::LISTEN, input::<ListenIn>())
            .0
            .outcome,
        go::<_, AcceptOut>(p, slot::ACCEPT, input::<AcceptIn>())
            .0
            .outcome,
        go::<_, ConnOut>(p, slot::DIAL, input::<DialIn>()).0.outcome,
        go::<_, IoOut>(p, slot::READ, input::<ReadIn>()).0.outcome,
        go::<_, IoOut>(p, slot::WRITE, input::<WriteIn>()).0.outcome,
        go::<_, OutHead>(p, slot::FLUSH, input::<ConnIn>())
            .0
            .outcome,
        go::<_, OutHead>(p, slot::SHUT, input::<ShutIn>()).0.outcome,
        go::<_, ArrivalOut>(p, slot::ARRIVAL, input::<ArrivalIn>())
            .0
            .outcome,
    ]
}

pub(super) fn carrier_line(outcomes: &[Outcome; 8]) -> String {
    CARRIER_OPS
        .iter()
        .zip(outcomes)
        .map(|(op, o)| format!("{op}={o:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One head line, its name and its value.
type HeadLine = (Vec<u8>, Vec<u8>);

/// THE FRAMER'S OWN HEAD LINES at `target` (`LocateIn::defaults_buf`), read as the connector reads
/// them: its line, and the lines, `name: value` each, in the framer's order. A dial that states its
/// request as fields and a body has them merged into the request's head before it is encoded, as
/// the host's walk adds each one its request does not carry before the auth signs the head (THE
/// DESIGN section 6, step 5).
fn located_defaults(p: &Plugin<Transport>, target: &[u8]) -> (String, (Vec<HeadLine>, bool)) {
    let (mut authority, mut name, mut alpn, mut defaults) = (
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
    );
    let mut i: LocateIn = input();
    i.target = abi_bytes(target);
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    (i.defaults_buf, i.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = p.call(slot::LOCATE, &mut f);
    let written = (f.out.defaults_written as usize).min(defaults.len());
    let lines: Vec<HeadLine> = if c.outcome == Outcome::Ready {
        defaults[..written]
            .split(|b| *b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .filter(|l| !l.is_empty())
            .filter_map(|l| {
                let at = l.iter().position(|b| *b == b':')?;
                let value = &l[at + 1..];
                let start = value.iter().position(|b| *b != b' ').unwrap_or(value.len());
                Some((l[..at].to_vec(), value[start..].to_vec()))
            })
            .collect()
    } else {
        Vec::new()
    };
    let states_length = c.outcome == Outcome::Ready && f.out.states_length != 0;
    let line = format!(
        "{:?} defaults={} states_length={states_length}",
        c.outcome,
        lines.len()
    );
    (line, (lines, states_length))
}

/// One `locate` of `target` with an authority buffer of `cap` bytes: its line, and its SHORT
/// answer's re-call token with the size it named.
pub(super) fn locate(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
) -> (String, Option<(crate::dispatch::Recall, u64)>) {
    locate_on(p, target, cap, None)
}

/// [`locate`], or with `recall` THE ONE RE-CALL of a SHORT `locate` (its authority buffer of the
/// size it named).
fn locate_on(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
    recall: Option<crate::dispatch::Recall>,
) -> (String, Option<(crate::dispatch::Recall, u64)>) {
    let (mut authority, mut name, mut alpn) =
        (vec![0_u8; cap], vec![0_u8; AMPLE], vec![0_u8; AMPLE]);
    let mut i: LocateIn = input();
    i.target = abi_bytes(target);
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    // The framer's own head lines, lent AMPLE as the host lends them: a framer that states lines
    // answers SHORT on a buffer that cannot hold them, and this probe pins the authority alone.
    let mut defaults = vec![0_u8; AMPLE];
    (i.defaults_buf, i.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = match recall {
        Some(token) => p.recall(token, slot::LOCATE, &mut f),
        None => p.call(slot::LOCATE, &mut f),
    };
    let (o, text) = (&f.out, c.error.as_deref().map(String::from_utf8_lossy));
    let written = (o.authority_written as usize).min(authority.len());
    let authority = if c.outcome == Outcome::Ready {
        lossy(&authority[..written])
    } else {
        String::new()
    };
    let line = format!(
        "{:?} err={:?} authority={authority:?} secure={} has_name={} short={}",
        c.outcome,
        text.unwrap_or_default(),
        o.secure != 0,
        o.has_name != 0,
        c.recall.is_some()
    );
    let needed = o.authority_needed;
    (line, c.recall.map(|r| (r, needed)))
}

fn ready_locate(authority: &[u8], secure: bool, has_name: bool) -> String {
    format!(
        "Ready err=\"\" authority={:?} secure={secure} has_name={has_name} short=false",
        lossy(authority)
    )
}

/// The transport door, loaded on `leg` over `b`, and the tail it states.
pub(super) fn loaded(s: &Subject, leg: Leg, b: Bind) -> (Plugin<Transport>, TransportFacts) {
    let p = load::<Transport>(s, leg, b).expect("the transport door loads");
    let facts = p
        .context::<TransportFacts>()
        .cloned()
        .expect("a transport states its tail");
    (p, facts)
}

/// A transport script's `facts` line: the host's record and the tail the door states.
pub(super) fn facts_line(p: &Plugin<Transport>, f: &TransportFacts) -> String {
    format!(
        "{} role={} claims={:?} composes_over={:?}",
        super::facts(p),
        f.role,
        f.claims,
        f.composes_over
    )
}

/// THE FRAMER SCRIPTS' HEAD (stream and datagram): `facts`, `begin` (by `begin`) refused before
/// `open` without a crossing, the lifecycle's head ([`opened`]), and the eight carrier ops of the
/// role it does not play, REFUSED, one crossing each.
pub(super) fn framer_opened(
    sc: &mut super::Script<'_>,
    (s, p, d): (&Subject, &Plugin<Transport>, &Dispatcher),
    settings: &[u8],
    facts: String,
    begin: &dyn Fn() -> String,
) {
    sc.line("facts", 0, || facts);
    // 0: the dispatcher refuses an op on an instance that is not open, without a crossing.
    sc.judged("begin unopened", 0, Want::Starts("Refused "), begin);
    opened(sc, (s, p, d), settings, &asis);
    sc.judged(
        "carrier ops",
        8,
        Want::Is(carrier_line(&[Outcome::Refused; 8])),
        || carrier_line(&carrier_ops(p)),
    );
}

/// THE FRAMER SCRIPTS' TAIL: `tick`, `refresh`, `close`, then `begin` (by `begin`) on the closed
/// instance answered FAULT without a crossing.
pub(super) fn framer_closed(
    sc: &mut super::Script<'_>,
    p: &Plugin<Transport>,
    settings: &[u8],
    begin: &dyn Fn() -> String,
) {
    refreshed(sc, p, None, settings, &asis);
    closed(sc, p, &asis);
    // 0: a closed instance answers FAULT without a crossing.
    sc.judged("begin after close", 0, Want::Starts("Fault "), begin);
}

/// What a READY framer op's line is, given what it yielded.
fn yielded_line(wire: &[u8], frames: &[Vec<u8>], raw: &[u8], flags: u32, framing: bool) -> String {
    let frames: Vec<String> = frames.iter().map(|f| lossy(f)).collect();
    format!(
        "Ready lease=false err=\"\" wire={:?} frames={frames:?} partial=\"\" raw={:?} flags={flags} framing={framing}",
        lossy(wire),
        lossy(raw)
    )
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("transport");
    assert!(k.is_object(), "conformance.json has no `transport` inputs");
    let settings = leg.settings(s);

    let d = dispatcher();
    let (p, facts) = loaded(s, leg, s.bind(&d, "transport"));
    match script_for(facts.role, facts.datagram) {
        Ok(Script::Framer) => {}
        Ok(Script::Datagram) => {
            drop(p);
            return super::datagram::fold(s, leg);
        }
        Ok(Script::Carrier) => {
            drop(p);
            return super::carrier::fold(s, leg);
        }
        Err(why) => panic!("{why}"),
    }
    let mut sc = super::Script::new(crossings(&p));
    let begin = || once(&p, 0, Op::Begin(SIDE_DIAL, b""), &mut Sink::ample()).line();

    // ── the Statement, an op before `open`, the lifecycle, `ready`, the role it does not play ──
    framer_opened(
        &mut sc,
        (s, &p, &d),
        &settings,
        facts_line(&p, &facts),
        &begin,
    );

    // ── locate: the targets it reads, the ONE short re-call, the targets it refuses ──
    match &k["locate"] {
        Value::String(v) if v == "refused" => {
            sc.judged("locate", 1, Want::Starts("Refused "), || {
                locate(&p, b"conformance", AMPLE).0
            });
        }
        l => {
            let reads = l["reads"]
                .as_array()
                .expect("conformance.json: transport.locate.reads must be an array");
            assert!(!reads.is_empty(), "transport.locate.reads is empty");
            for (n, read) in reads.iter().enumerate() {
                let target = text(&read["target"], "locate.reads.target");
                let authority = text(&read["authority"], "locate.reads.authority");
                let secure = read["secure"].as_bool().unwrap_or(false);
                let has_name = read["has_name"].as_bool().unwrap_or(false);
                let want = Want::Is(ready_locate(&authority, secure, has_name));
                sc.judged(&format!("locate #{n}"), 1, want, || {
                    locate(&p, &target, AMPLE).0
                });
            }
            let target = text(&reads[0]["target"], "locate.reads.target");
            let authority = text(&reads[0]["authority"], "locate.reads.authority");
            let secure = reads[0]["secure"].as_bool().unwrap_or(false);
            let has_name = reads[0]["has_name"].as_bool().unwrap_or(false);
            assert!(
                authority.len() > 1,
                "transport.locate.reads[0].authority must be longer than one byte"
            );
            let want = Want::Is(format!(
                "needed={} then {}",
                authority.len(),
                ready_locate(&authority, secure, has_name)
            ));
            // 2: the one-byte authority buffer answers SHORT; the ONE re-call is +1.
            sc.judged("locate short", 2, want, || {
                let (first, token) = locate(&p, &target, 1);
                let Some((token, needed)) = token else {
                    return format!("{first} (no re-call)");
                };
                let again = locate_on(&p, &target, needed as usize, Some(token)).0;
                format!("needed={needed} then {again}")
            });
            for (n, t) in texts(&l["refuses"], "locate.refuses").iter().enumerate() {
                sc.judged(
                    &format!("locate refused #{n}"),
                    1,
                    Want::Starts("Failed "),
                    || locate(&p, t, AMPLE).0,
                );
            }
        }
    }

    // ── a dialled framing: out through a tight wire, in through a tight frame, the far end ──
    let dial = &k["dial"];
    let wire = text(&dial["wire"], "dial.wire");
    let (ingest, frames) = (
        text(&dial["ingest"], "dial.ingest"),
        texts(&dial["frames"], "dial.frames"),
    );
    let target = opt_text(&dial["target"], "dial.target");
    let opening = opt_text(&dial["opening"], "dial.opening");
    let mut tight = Sink::tight();
    // A wire whose dialled framing holds a deadline (a request-response wire: the attempt's one
    // clock; a call-per-path wire: the call's) states which answers carry YIELD_HAS_DEADLINE:
    // `"deadline": ["begin", "emit", "ingest"]` (any of them), or `true` for the emit's alone.
    let armed = |step: &str| -> u32 {
        let on = match &dial["deadline"] {
            Value::Bool(b) => *b && step == "emit",
            Value::Array(a) => a.iter().any(|v| v.as_str() == Some(step)),
            _ => false,
        };
        if on {
            YIELD_HAS_DEADLINE
        } else {
            0
        }
    };
    // A wire that opens with bytes of its own writes them at begin, re-driven by `timer`.
    let want = begin_dial_want(dial, armed("begin"));
    let pinned = sinkfuls(opening.len(), TIGHT_WIRE);
    let token = sc.step_judged("begin dial", pinned, want, || {
        let y = pump(&p, 0, Op::Begin(SIDE_DIAL, &target), &mut tight);
        (y.line(), y.framing)
    });
    // The far side's opening answer, read before the first frame: it writes nothing, and yields
    // exactly the frames `answer_frames` states (a wire that hands its answer's head up, HEAD-FIELDS:
    // ws's switching response), none where it states none.
    if !dial["answer"].is_null() {
        let answer = text(&dial["answer"], "dial.answer");
        let heard = if dial["answer_frames"].is_null() {
            Vec::new()
        } else {
            texts(&dial["answer_frames"], "dial.answer_frames")
        };
        let want = Want::Is(yielded_line(&[], &heard, &[], 0, false));
        sc.judged("dial answer", frame_sinkfuls(&heard), want, || {
            pump(&p, token, Op::Ingest(&answer, false), &mut tight).line()
        });
    }
    // THE REQUEST THE DIAL SENDS: `dial.emit` as the message bytes, or `dial.request` (`fields` and
    // `body`) encoded by the framer itself with its own head lines merged in, as the host's walk
    // merges them: the request's fields, then each line the framer states whose name the request
    // does not carry, then the body's length where the framer states it (THE DESIGN section 6,
    // step 5).
    let emit = if dial["request"].is_null() {
        text(&dial["emit"], "dial.emit")
    } else {
        let request = &dial["request"];
        let body = opt_text(&request["body"], "dial.request.body");
        let mut named: Vec<HeadLine> = request["fields"]
            .as_array()
            .map(|fs| {
                fs.iter()
                    .map(|f| {
                        (
                            text(&f[0], "dial.request.fields name"),
                            text(&f[1], "dial.request.fields value"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (defaults, states_length) =
            sc.step("dial defaults", 1, || located_defaults(&p, &target));
        for (name, value) in defaults {
            if !named.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
                named.push((name, value));
            }
        }
        // Where the framer states its body's length, the body's `content-length` LAST, for a
        // non-empty body whose head carries none, as the host's walk adds it.
        if states_length
            && !body.is_empty()
            && !named
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(b"content-length"))
        {
            named.push((
                b"content-length".to_vec(),
                body.len().to_string().into_bytes(),
            ));
        }
        let fields: Vec<Field> = named
            .iter()
            .map(|(n, v)| Field {
                name: abi_bytes(n),
                value: abi_bytes(v),
            })
            .collect();
        sc.step("dial encode", 1, || {
            let y = once(&p, 0, Op::Encode(&body, &fields), &mut Sink::ample());
            (y.line(), y.wire)
        })
    };
    let want = Want::Is(yielded_line(&wire, &[], &[], armed("emit"), false));
    sc.judged("emit", sinkfuls(wire.len(), TIGHT_WIRE), want, || {
        pump(&p, token, Op::Emit(&emit, true), &mut tight).line()
    });
    // What reading them writes back (a ws close answered), absent = nothing.
    let answered = opt_text(&dial["ingest_wire"], "dial.ingest_wire");
    let ingest_calls = sinkfuls(answered.len(), TIGHT_WIRE).max(frame_sinkfuls(&frames));
    // What reading them writes ends the connection (a ws close answered) unless the wire states
    // `"ingest_ends": false` (h2: the settings acknowledged, the connection carries on).
    let ends = !dial["ingest_wire"].is_null() && dial["ingest_ends"].as_bool().unwrap_or(true);
    let ingest_flags = armed("ingest") | if ends { YIELD_ENDED } else { 0 };
    let want = Want::Is(yielded_line(&answered, &frames, &[], ingest_flags, false));
    sc.judged("ingest", ingest_calls, want, || {
        pump(&p, token, Op::Ingest(&ingest, false), &mut tight).line()
    });
    let want = Want::Is(yielded_line(&[], &[], &[], YIELD_ENDED, false));
    sc.judged("ingest end", 1, want, || {
        pump(&p, token, Op::Ingest(&[], true), &mut tight).line()
    });
    let finish = opt_text(&dial["finish"], "dial.finish");
    let want = Want::Is(yielded_line(&finish, &[], &[], YIELD_ENDED, false));
    sc.judged("finish", sinkfuls(finish.len(), TIGHT_WIRE), want, || {
        pump(&p, token, Op::Finish, &mut tight).line()
    });
    sc.judged("finish again", 1, Want::Starts("Failed "), || {
        once(&p, token, Op::Finish, &mut tight).line()
    });

    // ── encode: one rendering per case, in a sink with room for it ──
    let cases = k["encode"]
        .as_array()
        .expect("conformance.json: transport.encode must be an array");
    for (n, case) in cases.iter().enumerate() {
        let body = text(&case["body"], "encode.body");
        let named: Vec<(Vec<u8>, Vec<u8>)> = case["fields"]
            .as_array()
            .map(|fs| {
                fs.iter()
                    .map(|f| {
                        (
                            text(&f[0], "encode.fields name"),
                            text(&f[1], "encode.fields value"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let fields: Vec<Field> = named
            .iter()
            .map(|(n, v)| Field {
                name: abi_bytes(n),
                value: abi_bytes(v),
            })
            .collect();
        let want = match &case["wire"] {
            Value::Null => Want::Starts("Failed "),
            v => Want::Is(yielded_line(&text(v, "encode.wire"), &[], &[], 0, false)),
        };
        sc.judged(&format!("encode #{n}"), 1, want, || {
            once(&p, 0, Op::Encode(&body, &fields), &mut Sink::ample()).line()
        });
    }

    // A framer that frames dialled connections only states `"refuse": "refused"`: its accept
    // side answers REFUSED, and it has no accepted framing to refuse on or to upgrade.
    if refused(&k["refuse"]) {
        dial_only(&mut sc, &p, k);
    } else {
        // ── a refusal's bytes are the wire; a timer owes nothing more ──
        let refuse = &k["refuse"];
        let (bytes, wire) = (
            text(&refuse["bytes"], "refuse.bytes"),
            text(&refuse["wire"], "refuse.wire"),
        );
        // A wire whose accepted framing opens with bytes of its own (h2: the server's settings)
        // states them as `refuse.begin`; begin is re-driven by `timer` while they do not fit.
        let accept_opening = opt_text(&refuse["begin"], "refuse.begin");
        let want = Want::Is(yielded_line(&accept_opening, &[], &[], 0, true));
        let pinned = sinkfuls(accept_opening.len(), TIGHT_WIRE);
        let token = sc.step_judged("begin accept", pinned, want, || {
            let y = pump(&p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
            (y.line(), y.framing)
        });
        // A wire whose accepted framing must be opened before it can carry a refusal (ws: the upgrade
        // request, answered with the switch) reads its opening first.
        if !refuse["opening"].is_null() {
            let opening = text(&refuse["opening"], "refuse.opening");
            let answer = opt_text(&refuse["answer"], "refuse.answer");
            let want = Want::Is(yielded_line(&answer, &[], &[], 0, false));
            sc.judged(
                "accept opening",
                sinkfuls(answer.len(), TIGHT_WIRE),
                want,
                || pump(&p, token, Op::Ingest(&opening, false), &mut tight).line(),
            );
        }
        // A wire that refuses a call but never a connection (a call-per-path wire) states
        // `"refused": true`: the refuse op answers REFUSED and writes nothing. A wire whose refusal
        // closes its connection (ws: the refusal message, then its close) states `"ends": true`;
        // its connection is over, and a timer on it fails.
        let refuses_none = refuse["refused"].as_bool().unwrap_or(false);
        let ends = refuse["ends"].as_bool().unwrap_or(false);
        let ended = if ends { YIELD_ENDED } else { 0 };
        let want = if refuses_none {
            Want::Starts("Refused ")
        } else {
            Want::Is(yielded_line(&wire, &[], &[], ended, false))
        };
        sc.judged("refuse", sinkfuls(wire.len(), TIGHT_WIRE), want, || {
            pump(&p, token, Op::Refuse(&bytes), &mut tight).line()
        });
        let want = if ends {
            Want::Starts("Failed ")
        } else {
            Want::Is(yielded_line(&[], &[], &[], 0, false))
        };
        sc.judged("timer", 1, want, || {
            pump(&p, token, Op::Timer, &mut tight).line()
        });
        sc.judged("finish refused", 1, Want::Starts("Ready "), || {
            once(&p, token, Op::Finish, &mut tight).line()
        });
        // ── the upgrade: what was ingested and not answered is handed back, and adopted ──
        let token = sc.step_judged("begin upgrade", 1, Want::Starts("Ready "), || {
            let y = once(&p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
            (y.line(), y.framing)
        });
        upgrade(&mut sc, &p, k, token);
    }
    sc.judged("ingest on no framing", 1, Want::Starts("Failed "), || {
        once(&p, u64::MAX, Op::Ingest(b"x", false), &mut tight).line()
    });

    // ── the rest of the lifecycle; a closed instance serves nothing ──
    framer_closed(&mut sc, &p, &settings, &begin);
    sc.fold()
}

/// Whether an input states `"refused"`.
fn refused(v: &Value) -> bool {
    matches!(v, Value::String(s) if s == "refused")
}

/// THE UPGRADE, as ONE capability (`handoff`: what was ingested and not answered is handed back,
/// and adopted; or both refused) or as TWO (`detach`, `adopt`: a wire may give up a stream it
/// framed, take one another stack gave up, both, or neither; ws takes an upgrade and never gives
/// one up).
fn upgrade(sc: &mut super::Script<'_>, p: &Plugin<Transport>, k: &Value, token: u64) {
    let mut tight = Sink::tight();
    let whole = &k["handoff"];
    let refused_ = || once(p, 0, Op::Adopt(b"conformance"), &mut Sink::tight()).line();
    if refused(whole) {
        sc.judged("detach", 1, Want::Starts("Refused "), || {
            once(p, token, Op::Detach, &mut tight).line()
        });
        sc.judged("adopt", 1, Want::Starts("Refused "), refused_);
        sc.judged("finish upgrade", 1, Want::Starts("Ready "), || {
            once(p, token, Op::Finish, &mut tight).line()
        });
        return;
    }
    // The two halves' inputs: `handoff`'s own, or `detach`'s and `adopt`'s.
    let (detach, of, adopt, adopt_of, leftover) = if whole.is_null() {
        (&k["detach"], "detach", &k["adopt"], "adopt", "leftover")
    } else {
        (whole, "handoff", whole, "handoff", "adopt")
    };
    if refused(detach) {
        sc.judged("detach", 1, Want::Starts("Refused "), || {
            once(p, token, Op::Detach, &mut tight).line()
        });
    } else {
        let ingest = text(&detach["ingest"], &format!("{of}.ingest"));
        let detached = text(&detach["detached"], &format!("{of}.detached"));
        // 1: ingested once; the host stops re-driving it, it is upgrading.
        sc.judged("ingest before upgrade", 1, Want::Starts("Ready "), || {
            once(p, token, Op::Ingest(&ingest, false), &mut tight).line()
        });
        let want = Want::Is(yielded_line(&[], &[], &detached, YIELD_ENDED, false));
        sc.judged(
            "detach",
            sinkfuls(detached.len(), TIGHT_FRAME),
            want,
            || pump(p, token, Op::Detach, &mut tight).line(),
        );
    }
    // The halves finish the upgraded framing before another stack's leftover is adopted.
    if whole.is_null() {
        sc.judged("finish upgrade", 1, Want::Starts("Ready "), || {
            once(p, token, Op::Finish, &mut tight).line()
        });
    }
    if refused(adopt) {
        sc.judged("adopt", 1, Want::Starts("Refused "), refused_);
        return;
    }
    let left = text(&adopt[leftover], &format!("{adopt_of}.{leftover}"));
    let frames = texts(&adopt["frames"], &format!("{adopt_of}.frames"));
    // What adopting writes: the halves' `adopt.wire`; a whole handoff's adopt writes nothing.
    let wire = if whole.is_null() {
        opt_text(&adopt["wire"], "adopt.wire")
    } else {
        Vec::new()
    };
    let crossings = sinkfuls(wire.len(), TIGHT_WIRE).max(frame_sinkfuls(&frames));
    let want = Want::Is(yielded_line(&wire, &frames, &[], 0, true));
    let adopted = sc.step_judged("adopt", crossings, want, || {
        let y = pump(p, 0, Op::Adopt(&left), &mut tight);
        (y.line(), y.framing)
    });
    sc.judged("finish adopted", 1, Want::Starts("Ready "), || {
        once(p, adopted, Op::Finish, &mut tight).line()
    });
}

/// A framer that frames DIALLED connections only (`"refuse": "refused"`): `begin` on the accept
/// side answers REFUSED, and so do `detach` and `adopt`, which must be stated "refused" (an upgrade
/// needs an accepted framing to give up or take).
fn dial_only(sc: &mut super::Script<'_>, p: &Plugin<Transport>, k: &Value) {
    assert!(
        k["handoff"].is_null() && refused(&k["detach"]) && refused(&k["adopt"]),
        "conformance.json: a framer whose accept side is refused states \"detach\": \"refused\" and \
         \"adopt\": \"refused\" (and no \"handoff\")"
    );
    let mut tight = Sink::tight();
    sc.judged("begin accept", 1, Want::Starts("Refused "), || {
        once(p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight).line()
    });
    sc.judged("detach", 1, Want::Starts("Refused "), || {
        once(p, 0, Op::Detach, &mut tight).line()
    });
    sc.judged("adopt", 1, Want::Starts("Refused "), || {
        once(p, 0, Op::Adopt(b"conformance"), &mut tight).line()
    });
}

/// THE DIAL'S OPENING: a door that speaks first on dial writes exactly the bytes its inputs
/// declare in `dial.opening` at `begin`, and a door whose inputs declare none writes nothing. Bytes
/// the inputs do not declare fail the step: an undeclared opening is refused, never waved through.
fn begin_dial_want(dial: &Value, flags: u32) -> Want {
    let opening = opt_text(&dial["opening"], "dial.opening");
    Want::Is(yielded_line(&opening, &[], &[], flags, true))
}

#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_transport_opening_tests.rs"]
mod opening_tests;
#[cfg(all(test, loader_self_tests))]
#[path = "../tests/conformance_transport_role_tests.rs"]
mod role_tests;
