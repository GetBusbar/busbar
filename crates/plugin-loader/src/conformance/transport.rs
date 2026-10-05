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
//!         "reads":   [{ "target": "<a target it reads>", "authority": "<what it dials>", "secure": false }, ...],
//!         "refuses": ["<a target it refuses: FAILED>", ...] },
//!     "dial": {
//!         "target":  "<what begin dials>",          /* optional, default "": a wire whose
//!                                                       dial reads a target (ws) names it */
//!         "opening": "<what begin writes>",         /* optional, default "": a wire that opens
//!                                                       with bytes of its own (ws's upgrade
//!                                                       request) states them */
//!         "answer":  "<far bytes before the emit>", /* optional: the far side's opening answer
//!                                                       (ws's 101), read before the first frame */
//!         "emit":   "<one frame the host emits>",   "wire":   "<the wire bytes it becomes>",
//!         "ingest": "<bytes from the far side>",    "frames": ["<the frames they are>", ...],
//!         "finish": "<what finish writes>" },       /* optional, default "" (ws's close) */
//!     "encode": [{ "body": "<body>", "fields": [["<name>", "<value>"], ...],
//!                  "wire": "<the rendering>" | null /* FAILED */ }, ...],
//!     "refuse": { "bytes": "<a refusal>", "wire": "<the wire bytes it becomes>",
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
//! THE SCRIPT IS CHOSEN BY THE DECLARED ROLE ([`script_for`]): a FRAMER runs the framer script above.
//! A CARRIER is REFUSED with a named error for now: this is an INTERIM GUARD ONLY, until branch
//! `p2-transport-carrier` (stage B of p2-transport-stack, ARCHITECT ruling: TRANSPORT-STACK (2)'s
//! carrier surface, listen/accept/dial/read/write/close/arrival over host io) lands the carrier
//! script and the carriers' real slots. An unknown role fails the suite.

use busbar_contract::abi::mechanism::call::{AbiStr, Field, OutHead, Outcome};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn,
    PIECE_END_OF_FRAME, ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_MORE,
};

use super::{
    bind, close, crossings, dispatcher, input, load, open, output, ready_step, refresh, tick,
    validate, Fold, Leg, Recorder, Subject,
};
use busbar_contract::abi::transport::ROLE_CARRIER;

/// Which script a transport's declared `role` runs, or why none does. A FRAMER runs the framer
/// script. A CARRIER is refused by name: INTERIM GUARD ONLY, until branch `p2-transport-carrier`
/// (stage B of p2-transport-stack) lands the carrier script (TRANSPORT-STACK (2): listen/accept,
/// dial, read, write, close, arrival facts, poll-shaped with the host waker). Any other role is not a
/// transport this suite knows, and fails.
///
/// # Errors
///
/// The role is a carrier (no carrier script yet) or no known role.
pub(super) fn script_for(role: u32) -> Result<(), String> {
    match role {
        ROLE_FRAMER => Ok(()),
        ROLE_CARRIER => Err(
            "CarrierScriptPending: the transport declares ROLE_CARRIER and the carrier script \
             lands with branch p2-transport-carrier (stage B of p2-transport-stack); the suite \
             refuses rather than run the framer script over a carrier"
                .to_owned(),
        ),
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
fn text(v: &serde_json::Value, what: &str) -> Vec<u8> {
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

fn lossy(b: &[u8]) -> String {
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
struct Sink {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
}

impl Sink {
    fn new(wire: usize, frame: usize, pieces: usize) -> Self {
        let piece = FramePiece {
            stream: 0,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            fault: 0,
            flags: 0,
            retry_after_secs: 0,
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

    fn raw(&mut self) -> FramerSink {
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
    Emit(&'a [u8]),
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
            Op::Emit(_) => Op::Emit(&[]),
            Op::Refuse(_) => Op::Refuse(&[]),
            Op::Adopt(_) | Op::Begin(..) => Op::Timer,
            other => other,
        }
    }
}

fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (Called, O) {
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
            (i.side, i.sink) = (side, raw);
            i.target = AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            };
            go(p, slot::BEGIN, i)
        }
        Op::Ingest(bytes, end) => {
            let mut i: IngestIn = input();
            (i.framing, i.bytes, i.len, i.end, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::INGEST, i)
        }
        Op::Emit(bytes) => {
            let mut i: EmitIn = input();
            (i.framing, i.bytes, i.len, i.end_of_frame, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), 1, raw);
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

fn carrier_ops(p: &Plugin<Transport>) -> [Outcome; 8] {
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

fn carrier_line(outcomes: &[Outcome; 8]) -> String {
    CARRIER_OPS
        .iter()
        .zip(outcomes)
        .map(|(op, o)| format!("{op}={o:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One `locate` of `target` with an authority buffer of `cap` bytes: its line, and its SHORT
/// answer's re-call token with the size it named.
fn locate(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
) -> (String, Option<(crate::dispatch::Recall, u64)>) {
    let (mut authority, mut name, mut alpn) =
        (vec![0_u8; cap], vec![0_u8; AMPLE], vec![0_u8; AMPLE]);
    let mut i: LocateIn = input();
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = p.call(slot::LOCATE, &mut f);
    let line = locate_line(&c, &f.out, &authority);
    let needed = f.out.authority_needed;
    (line, c.recall.map(|r| (r, needed)))
}

fn locate_line(c: &Called, o: &LocateOut, authority: &[u8]) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let written = (o.authority_written as usize).min(authority.len());
    let authority = if c.outcome == Outcome::Ready {
        lossy(&authority[..written])
    } else {
        String::new()
    };
    format!(
        "{:?} err={text:?} authority={authority:?} secure={} has_name={} short={}",
        c.outcome,
        o.secure != 0,
        o.has_name != 0,
        c.recall.is_some()
    )
}

/// The ONE re-call of a SHORT `locate`, with an authority buffer of the size it named.
fn relocate(
    p: &Plugin<Transport>,
    token: crate::dispatch::Recall,
    target: &[u8],
    needed: u64,
) -> String {
    let (mut authority, mut name, mut alpn) = (
        vec![0_u8; needed as usize],
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
    );
    let mut i: LocateIn = input();
    i.target = AbiStr {
        ptr: target.as_ptr(),
        len: target.len(),
    };
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = p.recall(token, slot::LOCATE, &mut f);
    locate_line(&c, &f.out, &authority)
}

fn ready_locate(authority: &[u8], secure: bool) -> String {
    format!(
        "Ready err=\"\" authority={:?} secure={secure} has_name=false short=false",
        lossy(authority)
    )
}

/// What the contract requires of one step's answer.
enum Want {
    /// Exactly this line.
    Is(String),
    /// A line that starts so.
    Starts(&'static str),
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
    let settings = s.settings();

    let d = dispatcher();
    let p = load::<Transport>(s, leg, bind(&d, "transport")).expect("the transport door loads");
    let facts = p
        .context::<TransportFacts>()
        .cloned()
        .expect("a transport states its tail");
    if let Err(why) = script_for(facts.role) {
        panic!("{why}");
    }
    let mut want: Vec<(String, Want)> = Vec::new();
    let mut r = Recorder::new(crossings(&p));

    // ── the Statement, and an op before `open` ──
    r.line("facts", 0, || {
        format!(
            "{:?} {} max_inflight={} role={} claims={:?} composes_over={:?}",
            p.kind(),
            p.name(),
            p.max_inflight(),
            facts.role,
            facts.claims,
            facts.composes_over
        )
    });
    // 0: the dispatcher refuses an op on an instance that is not open, without a crossing.
    r.line("begin unopened", 0, || {
        once(&p, 0, Op::Begin(SIDE_DIAL, b""), &mut Sink::ample()).line()
    });
    want.push(("begin unopened".into(), Want::Starts("Refused ")));

    // ── lifecycle, then `ready` right after `open` answered READY ──
    r.line("validate", 1, || super::called(&validate(&p, &settings)));
    r.line("open", 1, || super::called(&open(&p, &settings)));
    for l in ["validate", "open"] {
        want.push((l.into(), Want::Starts("Ready ")));
    }
    ready_step(&mut r, s, &p, &d);

    // ── the role it does not play ──
    // 8: the eight carrier ops, one crossing each.
    r.line("carrier ops", 8, || carrier_line(&carrier_ops(&p)));
    want.push((
        "carrier ops".into(),
        Want::Is(carrier_line(&[Outcome::Refused; 8])),
    ));

    // ── locate: the targets it reads, the ONE short re-call, the targets it refuses ──
    match &k["locate"] {
        serde_json::Value::String(v) if v == "refused" => {
            r.line("locate", 1, || locate(&p, b"conformance", AMPLE).0);
            want.push(("locate".into(), Want::Starts("Refused ")));
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
                let label = format!("locate #{n}");
                r.line(&label, 1, || locate(&p, &target, AMPLE).0);
                want.push((label, Want::Is(ready_locate(&authority, secure))));
            }
            let target = text(&reads[0]["target"], "locate.reads.target");
            let authority = text(&reads[0]["authority"], "locate.reads.authority");
            let secure = reads[0]["secure"].as_bool().unwrap_or(false);
            assert!(
                authority.len() > 1,
                "transport.locate.reads[0].authority must be longer than one byte"
            );
            // 2: the one-byte authority buffer answers SHORT; the ONE re-call is +1.
            r.line("locate short", 2, || {
                let (first, token) = locate(&p, &target, 1);
                let Some((token, needed)) = token else {
                    return format!("{first} (no re-call)");
                };
                format!(
                    "needed={needed} then {}",
                    relocate(&p, token, &target, needed)
                )
            });
            want.push((
                "locate short".into(),
                Want::Is(format!(
                    "needed={} then {}",
                    authority.len(),
                    ready_locate(&authority, secure)
                )),
            ));
            for (n, t) in texts(&l["refuses"], "locate.refuses").iter().enumerate() {
                let label = format!("locate refused #{n}");
                r.line(&label, 1, || locate(&p, t, AMPLE).0);
                want.push((label, Want::Starts("Failed ")));
            }
        }
    }

    // ── a dialled framing: out through a tight wire, in through a tight frame, the far end ──
    let dial = &k["dial"];
    let (emit, wire) = (
        text(&dial["emit"], "dial.emit"),
        text(&dial["wire"], "dial.wire"),
    );
    let (ingest, frames) = (
        text(&dial["ingest"], "dial.ingest"),
        texts(&dial["frames"], "dial.frames"),
    );
    let target = opt_text(&dial["target"], "dial.target");
    let opening = opt_text(&dial["opening"], "dial.opening");
    let mut tight = Sink::tight();
    // A wire that opens with bytes of its own writes them at begin, re-driven by `timer`.
    let token = r.step("begin dial", sinkfuls(opening.len(), TIGHT_WIRE), || {
        let y = pump(&p, 0, Op::Begin(SIDE_DIAL, &target), &mut tight);
        (y.line(), y.framing)
    });
    want.push((
        "begin dial".into(),
        Want::Is(yielded_line(&opening, &[], &[], 0, true)),
    ));
    // The far side's opening answer, read before the first frame: it writes and yields nothing.
    if !dial["answer"].is_null() {
        let answer = text(&dial["answer"], "dial.answer");
        r.line("dial answer", 1, || {
            pump(&p, token, Op::Ingest(&answer, false), &mut tight).line()
        });
        want.push((
            "dial answer".into(),
            Want::Is(yielded_line(&[], &[], &[], 0, false)),
        ));
    }
    r.line("emit", sinkfuls(wire.len(), TIGHT_WIRE), || {
        pump(&p, token, Op::Emit(&emit), &mut tight).line()
    });
    want.push((
        "emit".into(),
        Want::Is(yielded_line(&wire, &[], &[], 0, false)),
    ));
    r.line("ingest", frame_sinkfuls(&frames), || {
        pump(&p, token, Op::Ingest(&ingest, false), &mut tight).line()
    });
    want.push((
        "ingest".into(),
        Want::Is(yielded_line(&[], &frames, &[], 0, false)),
    ));
    r.line("ingest end", 1, || {
        pump(&p, token, Op::Ingest(&[], true), &mut tight).line()
    });
    want.push((
        "ingest end".into(),
        Want::Is(yielded_line(&[], &[], &[], YIELD_ENDED, false)),
    ));
    let finish = opt_text(&dial["finish"], "dial.finish");
    r.line("finish", sinkfuls(finish.len(), TIGHT_WIRE), || {
        pump(&p, token, Op::Finish, &mut tight).line()
    });
    want.push((
        "finish".into(),
        Want::Is(yielded_line(&finish, &[], &[], YIELD_ENDED, false)),
    ));
    r.line("finish again", 1, || {
        once(&p, token, Op::Finish, &mut tight).line()
    });
    want.push(("finish again".into(), Want::Starts("Failed ")));

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
                name: AbiStr {
                    ptr: n.as_ptr(),
                    len: n.len(),
                },
                value: AbiStr {
                    ptr: v.as_ptr(),
                    len: v.len(),
                },
            })
            .collect();
        let label = format!("encode #{n}");
        r.line(&label, 1, || {
            once(&p, 0, Op::Encode(&body, &fields), &mut Sink::ample()).line()
        });
        let w = match &case["wire"] {
            serde_json::Value::Null => Want::Starts("Failed "),
            v => Want::Is(yielded_line(&text(v, "encode.wire"), &[], &[], 0, false)),
        };
        want.push((label, w));
    }

    // ── a refusal's bytes are the wire; a timer owes nothing more ──
    let refuse = &k["refuse"];
    let (bytes, wire) = (
        text(&refuse["bytes"], "refuse.bytes"),
        text(&refuse["wire"], "refuse.wire"),
    );
    let token = r.step("begin accept", 1, || {
        let y = once(&p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
        (y.line(), y.framing)
    });
    want.push((
        "begin accept".into(),
        Want::Is(yielded_line(&[], &[], &[], 0, true)),
    ));
    // A wire whose accepted framing must be opened before it can carry a refusal (ws: the upgrade
    // request, answered with the switch) reads its opening first.
    if !refuse["opening"].is_null() {
        let opening = text(&refuse["opening"], "refuse.opening");
        let answer = opt_text(&refuse["answer"], "refuse.answer");
        r.line("accept opening", sinkfuls(answer.len(), TIGHT_WIRE), || {
            pump(&p, token, Op::Ingest(&opening, false), &mut tight).line()
        });
        want.push((
            "accept opening".into(),
            Want::Is(yielded_line(&answer, &[], &[], 0, false)),
        ));
    }
    r.line("refuse", sinkfuls(wire.len(), TIGHT_WIRE), || {
        pump(&p, token, Op::Refuse(&bytes), &mut tight).line()
    });
    want.push((
        "refuse".into(),
        Want::Is(yielded_line(&wire, &[], &[], 0, false)),
    ));
    r.line("timer", 1, || pump(&p, token, Op::Timer, &mut tight).line());
    want.push((
        "timer".into(),
        Want::Is(yielded_line(&[], &[], &[], 0, false)),
    ));
    r.line("finish refused", 1, || {
        once(&p, token, Op::Finish, &mut tight).line()
    });
    want.push(("finish refused".into(), Want::Starts("Ready ")));

    // ── the upgrade: what was ingested and not answered is handed back, and adopted ──
    let token = r.step("begin upgrade", 1, || {
        let y = once(&p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
        (y.line(), y.framing)
    });
    want.push(("begin upgrade".into(), Want::Starts("Ready ")));
    if k["handoff"].is_null() {
        halves(&mut r, &mut want, &p, k, token);
    } else {
        whole_handoff(&mut r, &mut want, &p, k, token);
    }
    r.line("ingest on no framing", 1, || {
        once(&p, u64::MAX, Op::Ingest(b"x", false), &mut tight).line()
    });
    want.push(("ingest on no framing".into(), Want::Starts("Failed ")));

    // ── the rest of the lifecycle; a closed instance serves nothing ──
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", super::called(&c))
    });
    r.line("refresh", 1, || super::called(&refresh(&p, &settings)));
    r.line("close", 1, || super::called(&close(&p)));
    for l in ["refresh", "close"] {
        want.push((l.into(), Want::Starts("Ready ")));
    }
    // 0: a closed instance answers FAULT without a crossing.
    r.line("begin after close", 0, || {
        once(&p, 0, Op::Begin(SIDE_DIAL, b""), &mut Sink::ample()).line()
    });
    want.push(("begin after close".into(), Want::Starts("Fault ")));

    let fold = r.fold();
    contract(&fold, &want);
    fold
}

/// THE UPGRADE AS ONE CAPABILITY (`handoff`): what was ingested and not answered is handed back,
/// and adopted; or both refused.
fn whole_handoff(
    r: &mut Recorder,
    want: &mut Vec<(String, Want)>,
    p: &Plugin<Transport>,
    k: &serde_json::Value,
    token: u64,
) {
    let mut tight = Sink::tight();
    match &k["handoff"] {
        serde_json::Value::String(v) if v == "refused" => {
            r.line("detach", 1, || {
                once(p, token, Op::Detach, &mut tight).line()
            });
            r.line("adopt", 1, || {
                once(p, 0, Op::Adopt(b"conformance"), &mut tight).line()
            });
            for l in ["detach", "adopt"] {
                want.push((l.into(), Want::Starts("Refused ")));
            }
            r.line("finish upgrade", 1, || {
                once(p, token, Op::Finish, &mut tight).line()
            });
            want.push(("finish upgrade".into(), Want::Starts("Ready ")));
        }
        h => {
            let ingest = text(&h["ingest"], "handoff.ingest");
            let detached = text(&h["detached"], "handoff.detached");
            let leftover = text(&h["adopt"], "handoff.adopt");
            let frames = texts(&h["frames"], "handoff.frames");
            // 1: ingested once; the host stops re-driving it, it is upgrading.
            r.line("ingest before upgrade", 1, || {
                once(p, token, Op::Ingest(&ingest, false), &mut tight).line()
            });
            want.push(("ingest before upgrade".into(), Want::Starts("Ready ")));
            r.line("detach", sinkfuls(detached.len(), TIGHT_FRAME), || {
                pump(p, token, Op::Detach, &mut tight).line()
            });
            want.push((
                "detach".into(),
                Want::Is(yielded_line(&[], &[], &detached, YIELD_ENDED, false)),
            ));
            let adopted = r.step("adopt", frame_sinkfuls(&frames), || {
                let y = pump(p, 0, Op::Adopt(&leftover), &mut tight);
                (y.line(), y.framing)
            });
            want.push((
                "adopt".into(),
                Want::Is(yielded_line(&[], &frames, &[], 0, true)),
            ));
            r.line("finish adopted", 1, || {
                once(p, adopted, Op::Finish, &mut tight).line()
            });
            want.push(("finish adopted".into(), Want::Starts("Ready ")));
        }
    }
}

/// THE UPGRADE AS TWO CAPABILITIES (`detach`, `adopt`): a wire may give up a stream it framed, take
/// one another stack gave up, both, or neither (ws takes an upgrade and never gives one up).
fn halves(
    r: &mut Recorder,
    want: &mut Vec<(String, Want)>,
    p: &Plugin<Transport>,
    k: &serde_json::Value,
    token: u64,
) {
    let mut tight = Sink::tight();
    match &k["detach"] {
        serde_json::Value::String(v) if v == "refused" => {
            r.line("detach", 1, || {
                once(p, token, Op::Detach, &mut tight).line()
            });
            want.push(("detach".into(), Want::Starts("Refused ")));
        }
        d => {
            let ingest = text(&d["ingest"], "detach.ingest");
            let detached = text(&d["detached"], "detach.detached");
            r.line("ingest before upgrade", 1, || {
                once(p, token, Op::Ingest(&ingest, false), &mut tight).line()
            });
            want.push(("ingest before upgrade".into(), Want::Starts("Ready ")));
            r.line("detach", sinkfuls(detached.len(), TIGHT_FRAME), || {
                pump(p, token, Op::Detach, &mut tight).line()
            });
            want.push((
                "detach".into(),
                Want::Is(yielded_line(&[], &[], &detached, YIELD_ENDED, false)),
            ));
        }
    }
    r.line("finish upgrade", 1, || {
        once(p, token, Op::Finish, &mut tight).line()
    });
    want.push(("finish upgrade".into(), Want::Starts("Ready ")));
    match &k["adopt"] {
        serde_json::Value::String(v) if v == "refused" => {
            r.line("adopt", 1, || {
                once(p, 0, Op::Adopt(b"conformance"), &mut tight).line()
            });
            want.push(("adopt".into(), Want::Starts("Refused ")));
        }
        a => {
            let leftover = text(&a["leftover"], "adopt.leftover");
            let frames = texts(&a["frames"], "adopt.frames");
            let wire = opt_text(&a["wire"], "adopt.wire");
            let crossings = sinkfuls(wire.len(), TIGHT_WIRE).max(frame_sinkfuls(&frames));
            let adopted = r.step("adopt", crossings, || {
                let y = pump(p, 0, Op::Adopt(&leftover), &mut tight);
                (y.line(), y.framing)
            });
            want.push((
                "adopt".into(),
                Want::Is(yielded_line(&wire, &frames, &[], 0, true)),
            ));
            r.line("finish adopted", 1, || {
                once(p, adopted, Op::Finish, &mut tight).line()
            });
            want.push(("finish adopted".into(), Want::Starts("Ready ")));
        }
    }
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: every step's
/// answer is the one the transport's inputs and the ABI require (the bytes on the wire, the frames
/// and their ends, the connection's end, the refusals).
fn contract(fold: &Fold, want: &[(String, Want)]) {
    for (label, w) in want {
        let got = fold
            .iter()
            .find(|s| &s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"));
        match w {
            Want::Is(line) => assert_eq!(got, line.as_str(), "{label}"),
            Want::Starts(prefix) => assert!(got.starts_with(prefix), "{label}: {got}"),
        }
    }
}

#[cfg(test)]
mod role_tests {
    use super::script_for;
    use busbar_contract::abi::transport::{ROLE_CARRIER, ROLE_FRAMER};

    /// A framer runs the framer script; a carrier is refused BY NAME (the interim guard until
    /// `p2-transport-carrier`); an unknown role fails. RED arms: the carrier and the unknown role.
    #[test]
    fn the_script_is_chosen_by_the_declared_role() {
        assert_eq!(script_for(ROLE_FRAMER), Ok(()));
        let carrier = script_for(ROLE_CARRIER).expect_err("RED: a carrier is refused");
        assert!(carrier.starts_with("CarrierScriptPending"), "{carrier}");
        assert!(carrier.contains("p2-transport-carrier"), "{carrier}");
        for role in [0, ROLE_CARRIER | ROLE_FRAMER, 7] {
            let e = script_for(role).expect_err("RED: an unknown role fails");
            assert!(e.starts_with("UnknownRole"), "{e}");
        }
    }
}
