// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S SCRIPT. Every plane op of `abi/plane/` through the one dispatcher, in the order
//! the kernel drives a unit: `validate`, `open` (the kernel's `Plugin<Plane>::open`, the first
//! generation's snapshot copied at the crossing, under the deployment's public URL when the inputs
//! name one), `ready`, `hydrate`, `start`, `arrive` (claimed, unclaimed), the unit's pieces (the
//! ATTEMPT, the caller's body, the far end's answer: whole, through a narrow reply buffer with its
//! `more` re-calls, and once SHORT with its one re-call), an empty caller body, the SESSIONS the
//! inputs name (each a unit on one claim, driven step by step: its arrival, its pieces from either
//! side, `drive`, `project`), `refusal`, `serve`, `project`, `drive`, `release`, `tick`, `cancel`,
//! `refresh` (the next generation's snapshot), `retire` and `close`.
//!
//! Inputs (`conformance.json`; every byte the plane is handed or must answer is the plugin's):
//!
//! ```json
//! { "settings": <the settings it opens over (generation 1)>,
//!   "plane": {
//!     "bad_settings": [<settings `validate` must refuse, naming why; dealt to it as
//!                       `{<declaring section>: <settings>}`, the stage-3g shape>, ...],
//!     "refresh_settings": <the settings generation 2 is refreshed over>,
//!     "public_url": "<the deployment's public base URL>",   // optional: handed to `open`
//!     "open_claims":    [["<verb>", "<target>"], ...],   // generation 1's snapshot claims
//!     "refresh_claims": [["<verb>", "<target>"], ...],   // generation 2's
//!     "member": "<the pool member an ATTEMPT names>",
//!     "pool": "<the pool an ATTEMPT names>",              // optional
//!     "caller_ref": "<the caller's reference>",           // optional: on every piece
//!     "claimed":   { "unit": 7, "method": "POST", "target": "/v1/x",  // arrive: READY
//!                    "claim": 0,                          // optional: the snapshot claim (0)
//!                    "fields": [["<name>", "<value>"], ...],          // optional: its head
//!                    "route": { "class": "pool", "entry": "<name>" } },  // optional: named
//!     "unclaimed": { "unit": 8, "method": "GET", "target": "/v1/y", "status": 404,  // refused
//!                    "claim": 9, "fields": [...] },       // optional, as `claimed`'s
//!     "request":     "<the caller's body>",
//!     "request_out": "<what the plane sends the far end for it>",
//!     "far_end": { "status": 200, "fields": [["<name>", "<value>"], ...],
//!                  "answer": "<the far end's whole answer>",
//!                  "answer_out": "<what the plane relays to the caller>",
//!                  "units": [[<billable class>, <amount>], ...] },   // reported at the last piece
//!     "narrow": { "unit": 9, "reply_cap": 16, "more": 3 },  // the answer `reply_cap` bytes at a time
//!     "short":  { "unit": 11,                // the answer over a units buffer of capacity 0
//!                 "buffer": "fields" },      // optional: over a fields buffer of capacity 0
//!     "empty":  { "unit": 10, "outcome": "Refused" },        // optional: a caller body that ended empty
//!     "sessions": [                          // optional: units driven step by step
//!       { "name": "<unique>", "unit": 20, "claim": 2,
//!         "stream": 20,                      // optional: a live session's stream (0 = a request unit)
//!         "reply_cap": 65536,                // optional
//!         "steps": [
//!           { "label": "<unique in the session>",
//!             // ONE of:
//!             "arrive": { "method": "GET", "target": "/s", "fields": [...], "body": <bytes> },
//!             "piece": { "from": "caller" | "far_end" | "kernel", "attempt": 1, "last": true,
//!                        "status": 200, "fields": [...], "bytes": <bytes>,
//!                        "short": "units" | "fields" },   // met at capacity 0, then re-called
//!             "drive": true,
//!             "project": { "target": "/s", "body": <bytes>, "rewrite": <bytes> },
//!             "want": { "outcome": "Ready", ... } } ] } ],
//!     "refusal": { "status": 403, "text": "denied", "reply": "<the dialect's error body>" } } }
//! ```
//!
//! `<bytes>` is a string, or an array of parts each a string or `{ "repeat": "<text>", "times": n }`
//! (a large payload stated small). A session step's `want` names its outcome (required) and any of:
//! `to_far_end`, `done`, `more`, `status`, `verb`, `target`, `need`, `emitted` (exact),
//! `emitted_has` (substrings), `fields` (`[["<name>", "<value>"], ...]`, exact), `units`
//! (`[[<class>, <amount>], ...]`, reported, exact), `route` (`{ "class", "entry" }`), `streams`
//! (what `drive` names), `body_has` (substrings of the projected body) and `rewritten`.
//!
//! THE PINS. Every step is ONE ticket-less crossing (`Plugin::call`), but:
//! * `ready` ([`super::ready_step`]): 0 when the door states none;
//! * `arrive unopened` and `open again`: 0, the host answers REFUSED without a crossing (no
//!   instance yet; one `open` per instance);
//! * `far_end short`, and a session piece met `short`: 2, the short answer and its ONE re-call
//!   (`Plugin::recall`, the short-buffer rule on `OutHead`);
//! * `arrive after close`: 0, a closed instance answers FAULT without a crossing.
//!
//! The narrow answer's `more` re-calls are each their own step of one crossing, as many as the
//! inputs pin (`narrow.more`), so a plane that writes fewer bytes per piece than the buffer holds
//! crosses more often than pinned and is refused. A session's `more` re-call is a piece step of
//! its own (`from` the side, no bytes, no flags), pinned the same way.

use busbar_contract::abi::hook::{MessageView, SignalEntry};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, OutHead, Span, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_GATE,
    ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_POOL, ROUTE_SCOPE, SPAN_ABSENT, UNITS_REPORTED,
};
use serde_json::Value;

use super::{
    called, close, crossings, dispatcher, input, json, load, output, ready_step, release, tick,
    validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::plane::{OwnedSnapshot, Plane};
use crate::dispatch::{Called, Frame, Plugin};

/// The capacity of each of the host's per-piece lists (units, record writes, fields).
const CAP: usize = 8;
/// A session's reply buffer when its inputs name none.
const SESSION_REPLY_CAP: usize = 1 << 16;

fn text(v: &Value, what: &str) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Null => panic!("conformance.json: plane.{what} is missing"),
        other => other.to_string().into_bytes(),
    }
}

/// An optional string input: absent is `None`.
fn optional(v: &Value, what: &str) -> Option<Vec<u8>> {
    (!v.is_null()).then(|| text(v, what))
}

/// `<bytes>`: a string, or parts each a string or `{ "repeat": "<text>", "times": n }`; absent is
/// none.
fn bytes(v: &Value, what: &str) -> Vec<u8> {
    match v {
        Value::Null => Vec::new(),
        Value::Array(parts) => parts
            .iter()
            .flat_map(|p| {
                if p.is_object() {
                    let times = usize::try_from(num(&p["times"], what)).unwrap_or(usize::MAX);
                    text(&p["repeat"], what).repeat(times)
                } else {
                    text(p, what)
                }
            })
            .collect(),
        other => text(other, what),
    }
}

fn num(v: &Value, what: &str) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| panic!("conformance.json: plane.{what} must be a number"))
}

/// An optional number input: absent is `or`.
fn num_or(v: &Value, what: &str, or: u64) -> u64 {
    if v.is_null() {
        or
    } else {
        num(v, what)
    }
}

fn small(v: u64, what: &str) -> u32 {
    u32::try_from(v).unwrap_or_else(|_| panic!("conformance.json: plane.{what} is too large"))
}

fn pairs(v: &Value, what: &str) -> Vec<(String, String)> {
    v.as_array()
        .unwrap_or_else(|| panic!("conformance.json: plane.{what} must be an array of pairs"))
        .iter()
        .map(|p| match p.as_array().map(Vec::as_slice) {
            Some([a, b]) => (
                a.as_str().map_or_else(|| a.to_string(), String::from),
                b.as_str().map_or_else(|| b.to_string(), String::from),
            ),
            _ => panic!("conformance.json: plane.{what} holds a non-pair"),
        })
        .collect()
}

/// Optional pairs: absent is none.
fn pairs_or_none(v: &Value, what: &str) -> Vec<(String, String)> {
    if v.is_null() {
        Vec::new()
    } else {
        pairs(v, what)
    }
}

/// Head fields over `pairs`' bytes.
fn field_list(pairs: &[(String, String)]) -> Vec<Field> {
    pairs
        .iter()
        .map(|(n, v)| Field {
            name: abi(n.as_bytes()),
            value: abi(v.as_bytes()),
        })
        .collect()
}

/// A host buffer element, zeroed.
fn z<T: Copy>() -> T {
    // SAFETY: called only for the plane ABI's plain C structs (`UnitCount`, `RecordWrite`,
    // `OutField`, `SignalEntry`, `MessageView`): integers, spans, pointers and unions of integers,
    // for which all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn abi(b: &[u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// Text the plane answered in its own memory, read at once (valid until its next call).
fn read(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the kind's check admitted the answer; the plane's text is valid until the
    // instance's next call, and it is read before any.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

fn at(buf: &[u8], s: Span) -> String {
    let (from, len) = (s.offset as usize, s.len as usize);
    buf.get(from..from + len).map_or_else(
        || "<OUTSIDE>".into(),
        |b| String::from_utf8_lossy(b).into_owned(),
    )
}

/// What `ArriveOut::route` names.
fn route_class(route: u8) -> String {
    match route {
        ROUTE_POOL => "pool".into(),
        ROUTE_DIRECT => "direct".into(),
        ROUTE_LOCAL => "local".into(),
        ROUTE_SCOPE => "scope".into(),
        other => other.to_string(),
    }
}

/// A generation snapshot as one line: its generation and its claims, `VERB TARGET` each.
fn snapshot(s: Option<&OwnedSnapshot>) -> String {
    s.map_or_else(
        || "snapshot=none".into(),
        |s| {
            format!(
                "gen={} claims=[{}] routes={}",
                s.generation,
                claims(
                    s.claims
                        .iter()
                        .map(|c| (c.verb.as_str(), c.target.as_str()))
                ),
                s.admin_routes.len()
            )
        },
    )
}

fn claims<'a>(c: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    c.map(|(v, t)| format!("{v} {t}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The host's buffers for one unit's pieces.
struct Piece {
    reply: Vec<u8>,
    units: [UnitCount; CAP],
    records: [RecordWrite; CAP],
    fields: [OutField; CAP],
    arena: [u8; 1024],
}

/// One piece handed to the plane.
#[derive(Clone, Copy)]
struct Given<'a> {
    unit: u64,
    /// A live session's stream; `0` for a request unit.
    stream: u64,
    /// The snapshot claim the unit arrived on.
    claim: u32,
    from: u32,
    flags: u32,
    bytes: &'a [u8],
    attempt_no: u32,
    /// With `PIECE_HAS_STATUS`: the far end's status and kept head fields.
    status: u32,
    head: &'a [Field],
}

/// What every piece carries beside its own: the member (and pool) an ATTEMPT names, and the
/// caller's reference.
struct Carried {
    member: Vec<u8>,
    pool: Option<Vec<u8>>,
    caller_ref: Option<Vec<u8>>,
}

/// The host list a SHORT answer is met with at capacity 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Buffer {
    Units,
    Fields,
}

impl Buffer {
    fn of(v: &Value, what: &str) -> Option<Self> {
        match v.as_str() {
            None if v.is_null() => None,
            Some("units") => Some(Self::Units),
            Some("fields") => Some(Self::Fields),
            _ => panic!("conformance.json: plane.{what} must be \"units\" or \"fields\""),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Units => "units",
            Self::Fields => "fields",
        }
    }

    /// The (units, fields) capacities a piece meets.
    const fn caps(self) -> (usize, usize) {
        match self {
            Self::Units => (0, CAP),
            Self::Fields => (CAP, 0),
        }
    }

    fn needed(self, o: &OnPieceOut) -> u32 {
        match self {
            Self::Units => o.units_needed,
            Self::Fields => o.fields_needed,
        }
    }
}

impl Piece {
    fn new(reply_cap: usize) -> Box<Self> {
        Box::new(Self {
            reply: vec![0; reply_cap],
            units: [z(); CAP],
            records: [z(); CAP],
            fields: [z(); CAP],
            arena: [0; 1024],
        })
    }

    fn frame(
        &mut self,
        g: Given<'_>,
        (units_cap, fields_cap): (usize, usize),
        c: &Carried,
    ) -> Frame<OnPieceIn, OnPieceOut> {
        let mut i: OnPieceIn = input();
        (i.unit, i.from, i.flags, i.bytes) = (g.unit, g.from, g.flags, octets(g.bytes));
        (i.stream, i.claim) = (g.stream, g.claim);
        (i.attempt_no, i.member) = (g.attempt_no, abi(&c.member));
        if let (Some(pool), true) = (&c.pool, g.from == FROM_KERNEL && g.attempt_no > 0) {
            i.pool = abi(pool);
        }
        if let Some(r) = &c.caller_ref {
            i.caller_ref = abi(r);
        }
        if g.flags & PIECE_HAS_STATUS != 0 {
            i.status_code = g.status;
            (i.head_fields, i.head_fields_len) = (g.head.as_ptr(), g.head.len());
        }
        (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
        (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), units_cap);
        (i.records_buf, i.records_cap) = (self.records.as_mut_ptr(), self.records.len());
        (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), fields_cap);
        (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
        Frame::new(i, output())
    }

    fn fields(&self, o: &OnPieceOut) -> Vec<String> {
        self.fields[..(o.fields_written as usize).min(CAP)]
            .iter()
            .map(|f| format!("{}={}", at(&self.arena, f.name), at(&self.arena, f.value)))
            .collect()
    }

    fn units(&self, o: &OnPieceOut) -> Vec<String> {
        self.units[..(o.units_written as usize).min(CAP)]
            .iter()
            .map(|u| format!("{}:{}:{}", u.class, u.amount, u.source == UNITS_REPORTED))
            .collect()
    }

    fn emitted(&self, o: &OnPieceOut) -> String {
        let n = usize::try_from(o.emitted).map_or(self.reply.len(), |n| n.min(self.reply.len()));
        String::from_utf8_lossy(&self.reply[..n]).into_owned()
    }

    /// What the plane answered and wrote, as one line.
    fn line(&self, c: &Called, o: &OnPieceOut) -> String {
        format!(
            "{} emitted={} more={} to_far_end={} done={} status={} verb={} target={} \
             fields={:?} units={:?}",
            called(c),
            self.emitted(o),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
            self.fields(o),
            self.units(o),
        )
    }

    /// [`Piece::line`] with the need a far-bound answer rides: a session step's line.
    fn session_line(&self, c: &Called, o: &OnPieceOut) -> String {
        format!(
            "{} emitted={} more={} to_far_end={} done={} status={} verb={} target={} need={} \
             fields={:?} units={:?}",
            called(c),
            self.emitted(o),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
            o.need,
            self.fields(o),
            self.units(o),
        )
    }
}

/// `on_piece` of `g` over `piece`'s buffers, the lists at `caps`.
fn on_piece(
    p: &Plugin<Plane>,
    piece: &mut Piece,
    g: Given<'_>,
    caps: (usize, usize),
    c: &Carried,
) -> (Called, Frame<OnPieceIn, OnPieceOut>) {
    let mut f = piece.frame(g, caps, c);
    let called = p.call(slot::ON_PIECE, &mut f);
    (called, f)
}

/// `g` met with `buffer` at capacity 0: SHORT, then its ONE re-call with room (two crossings).
fn short_then(
    p: &Plugin<Plane>,
    piece: &mut Piece,
    g: Given<'_>,
    buffer: Buffer,
    c: &Carried,
    line: fn(&Piece, &Called, &OnPieceOut) -> String,
) -> String {
    let (first, mut f) = on_piece(p, piece, g, buffer.caps(), c);
    let head = format!(
        "{} {}_needed={} recall={}",
        called(&first),
        buffer.name(),
        buffer.needed(&f.out),
        first.recall.is_some()
    );
    let Some(token) = first.recall else {
        return format!("{head} then=no-recall");
    };
    (f.input.units_cap, f.input.fields_cap) = (CAP, CAP);
    let again = p.recall(token, slot::ON_PIECE, &mut f);
    format!("{head} then={}", line(piece, &again, &f.out))
}

/// An arrival the inputs state: its unit, claim, request line and head.
struct Arrival {
    unit: u64,
    claim: u32,
    method: Vec<u8>,
    target: Vec<u8>,
    fields: Vec<(String, String)>,
    /// The line names the route the arrival routes over.
    route: bool,
}

impl Arrival {
    fn of(a: &Value, what: &str) -> Self {
        Self {
            unit: num(&a["unit"], what),
            claim: small(num_or(&a["claim"], what, 0), what),
            method: text(&a["method"], what),
            target: text(&a["target"], what),
            fields: pairs_or_none(&a["fields"], what),
            route: a["route"].is_object(),
        }
    }
}

fn arrive(p: &Plugin<Plane>, a: &Arrival, body: &[u8]) -> String {
    let mut units = [z::<UnitCount>(); 4];
    let head = field_list(&a.fields);
    let mut f: Frame<ArriveIn, ArriveOut> = Frame::new(input(), output());
    (f.input.unit, f.input.claim) = (a.unit, a.claim);
    (f.input.method, f.input.target) = (abi(&a.method), abi(&a.target));
    if !head.is_empty() {
        (f.input.fields, f.input.fields_len) = (head.as_ptr(), head.len());
    }
    f.input.body = octets(body);
    (f.input.units_buf, f.input.units_cap) = (units.as_mut_ptr(), units.len());
    let c = p.call(slot::ARRIVE, &mut f);
    let line = format!(
        "{} op_class={} principal_required={} dialect={} units={} refusal={} status={}",
        called(&c),
        f.out.op_class,
        f.out.principal_need == PRINCIPAL_REQUIRED,
        f.out.dialect,
        f.out.units_written,
        f.out.refusal,
        f.out.refusal_status
    );
    if a.route {
        format!(
            "{line} route={} entry={}",
            route_class(f.out.route),
            read(f.out.pool)
        )
    } else {
        line
    }
}

/// One step of a session.
enum Act {
    Arrive(Arrival, Vec<u8>),
    Piece {
        from: u32,
        flags: u32,
        attempt_no: u32,
        status: u32,
        head: Vec<(String, String)>,
        bytes: Vec<u8>,
        short: Option<Buffer>,
    },
    Drive,
    Project {
        target: Vec<u8>,
        body: Vec<u8>,
        rewrite: Option<Vec<u8>>,
    },
}

/// A unit the inputs drive step by step (`plane.sessions[]`).
struct Session {
    name: String,
    unit: u64,
    stream: u64,
    claim: u32,
    reply_cap: usize,
    steps: Vec<(String, Act)>,
}

impl Session {
    fn all(v: &Value) -> Vec<Self> {
        let Some(list) = v.as_array() else {
            assert!(
                v.is_null(),
                "conformance.json: plane.sessions must be an array"
            );
            return Vec::new();
        };
        let all: Vec<Self> = list
            .iter()
            .enumerate()
            .map(|(i, s)| Self::of(s, i))
            .collect();
        let mut names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            all.len(),
            "conformance.json: two plane.sessions share a name"
        );
        all
    }

    fn of(s: &Value, i: usize) -> Self {
        let what = format!("sessions[{i}]");
        let name = String::from_utf8(text(&s["name"], &format!("{what}.name")))
            .expect("conformance.json: a session's name is UTF-8");
        assert!(
            !name.is_empty(),
            "conformance.json: plane.{what}.name is empty"
        );
        let unit = num(&s["unit"], &format!("{what}.unit"));
        let claim = small(num_or(&s["claim"], &what, 0), &format!("{what}.claim"));
        let steps: Vec<(String, Act)> = s["steps"]
            .as_array()
            .unwrap_or_else(|| panic!("conformance.json: plane.{what}.steps must be an array"))
            .iter()
            .enumerate()
            .map(|(j, st)| Self::step(st, &format!("{what}.steps[{j}]"), unit, claim))
            .collect();
        let mut labels: Vec<&str> = steps.iter().map(|(l, _)| l.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            steps.len(),
            "conformance.json: two steps of plane.{what} share a label"
        );
        Self {
            name,
            unit,
            stream: num_or(&s["stream"], &format!("{what}.stream"), 0),
            claim,
            reply_cap: usize::try_from(num_or(
                &s["reply_cap"],
                &format!("{what}.reply_cap"),
                SESSION_REPLY_CAP as u64,
            ))
            .unwrap_or(SESSION_REPLY_CAP),
            steps,
        }
    }

    fn step(st: &Value, what: &str, unit: u64, claim: u32) -> (String, Act) {
        let label = String::from_utf8(text(&st["label"], &format!("{what}.label")))
            .expect("conformance.json: a step's label is UTF-8");
        assert!(
            st["want"]["outcome"].is_string(),
            "conformance.json: plane.{what}.want.outcome is missing"
        );
        let acts = ["arrive", "piece", "drive", "project"];
        let named: Vec<&str> = acts.into_iter().filter(|a| !st[*a].is_null()).collect();
        let act = match named.as_slice() {
            ["arrive"] => {
                let a = &st["arrive"];
                let w = format!("{what}.arrive");
                Act::Arrive(
                    Arrival {
                        unit,
                        claim,
                        method: text(&a["method"], &w),
                        target: text(&a["target"], &w),
                        fields: pairs_or_none(&a["fields"], &w),
                        route: true,
                    },
                    bytes(&a["body"], &w),
                )
            }
            ["piece"] => {
                let p = &st["piece"];
                let w = format!("{what}.piece");
                let from = match p["from"].as_str() {
                    Some("caller") => FROM_CALLER,
                    Some("far_end") => FROM_FAR_END,
                    Some("kernel") => FROM_KERNEL,
                    _ => panic!(
                        "conformance.json: plane.{w}.from must be \"caller\", \"far_end\" or \
                         \"kernel\""
                    ),
                };
                let status = small(num_or(&p["status"], &w, 0), &w);
                let mut flags = 0;
                if p["last"].as_bool() == Some(true) {
                    flags |= PIECE_LAST;
                }
                if !p["status"].is_null() {
                    flags |= PIECE_HAS_STATUS;
                }
                Act::Piece {
                    from,
                    flags,
                    attempt_no: small(num_or(&p["attempt"], &w, 0), &w),
                    status,
                    head: pairs_or_none(&p["fields"], &w),
                    bytes: bytes(&p["bytes"], &w),
                    short: Buffer::of(&p["short"], &format!("{w}.short")),
                }
            }
            ["drive"] => Act::Drive,
            ["project"] => {
                let p = &st["project"];
                let w = format!("{what}.project");
                Act::Project {
                    target: bytes(&p["target"], &w),
                    body: bytes(&p["body"], &w),
                    rewrite: (!p["rewrite"].is_null()).then(|| bytes(&p["rewrite"], &w)),
                }
            }
            _ => panic!("conformance.json: plane.{what} names exactly one of {acts:?}"),
        };
        (label, act)
    }
}

/// `drive`: the streams of the sessions with output of their own.
fn drive(p: &Plugin<Plane>) -> String {
    let mut sessions = [0_u64; CAP];
    let mut f: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(input(), output());
    (f.input.sessions_buf, f.input.sessions_cap) = (sessions.as_mut_ptr(), sessions.len());
    let c = p.call(life::DRIVE, &mut f);
    format!(
        "{} streams={:?}",
        called(&c),
        &sessions[..(f.out.sessions_written as usize).min(CAP)]
    )
}

/// `project` of a session's unit: the view's signals, whether a rewrite was applied, and the
/// projected body (last on the line).
fn project(
    p: &Plugin<Plane>,
    s: &Session,
    target: &[u8],
    body: &[u8],
    rewrite: Option<&[u8]>,
) -> String {
    let mut arena = vec![0_u8; 4096];
    let mut signals = [z::<SignalEntry>(); CAP];
    let mut turns = [z::<MessageView>(); CAP];
    let mut f: Frame<ProjectIn, ProjectOut> = Frame::new(input(), output());
    (f.input.claim, f.input.unit) = (s.claim, s.unit);
    (f.input.target, f.input.body) = (abi(target), octets(body));
    if let Some(r) = rewrite {
        f.input.rewrite = json(r);
    }
    (f.input.signals_buf, f.input.signals_cap) = (signals.as_mut_ptr(), signals.len());
    (f.input.messages_buf, f.input.messages_cap) = (turns.as_mut_ptr(), turns.len());
    (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
    let c = p.call(slot::PROJECT, &mut f);
    let span = |s: Span| (s.offset != SPAN_ABSENT && s.len != 0).then(|| at(&arena, s));
    format!(
        "{} rewritten={} signals={} body={}",
        called(&c),
        span(f.out.rewritten).is_some(),
        f.out.view.signals_len,
        span(f.out.body).unwrap_or_default()
    )
}

/// THE SESSIONS LEG: each session's steps, in order, each its own step of the fold
/// (`<name> <label>`), pinned at one crossing (a piece met `short`: two).
fn sessions(r: &mut Recorder<'_>, p: &Plugin<Plane>, all: &[Session], c: &Carried) {
    for s in all {
        let mut piece = Piece::new(s.reply_cap);
        for (label, act) in &s.steps {
            let label = format!("{} {label}", s.name);
            match act {
                Act::Arrive(a, body) => r.line(&label, 1, || arrive(p, a, body)),
                Act::Drive => r.line(&label, 1, || drive(p)),
                Act::Project {
                    target,
                    body,
                    rewrite,
                } => r.line(&label, 1, || {
                    project(p, s, target, body, rewrite.as_deref())
                }),
                Act::Piece {
                    from,
                    flags,
                    attempt_no,
                    status,
                    head,
                    bytes,
                    short,
                } => {
                    let head = field_list(head);
                    let g = Given {
                        unit: s.unit,
                        stream: s.stream,
                        claim: s.claim,
                        from: *from,
                        flags: *flags,
                        bytes,
                        attempt_no: *attempt_no,
                        status: *status,
                        head: &head,
                    };
                    match short {
                        None => r.line(&label, 1, || {
                            let (called, f) = on_piece(p, &mut piece, g, (CAP, CAP), c);
                            piece.session_line(&called, &f.out)
                        }),
                        Some(b) => r.line(&label, 2, || {
                            short_then(p, &mut piece, g, *b, c, Piece::session_line)
                        }),
                    }
                }
            }
        }
    }
}

/// The script's fixtures, read once from `inputs.plane`.
struct Inputs {
    bad: Vec<Vec<u8>>,
    refresh: Vec<u8>,
    public_url: Option<Vec<u8>>,
    carried: Carried,
    claimed: Arrival,
    unclaimed: Arrival,
    request: Vec<u8>,
    status: u32,
    head: Vec<(String, String)>,
    answer: Vec<u8>,
    narrow: (u64, usize, u64),
    short: (u64, Buffer),
    empty: Option<u64>,
    sessions: Vec<Session>,
    refusal: (u32, Vec<u8>),
}

impl Inputs {
    fn of(k: &Value) -> Self {
        assert!(k.is_object(), "conformance.json has no `plane` inputs");
        let bad: Vec<Vec<u8>> = k["bad_settings"]
            .as_array()
            .expect("conformance.json: plane.bad_settings must be an array")
            .iter()
            .map(|v| text(v, "bad_settings[]"))
            .collect();
        assert!(
            !bad.is_empty(),
            "conformance.json: plane.bad_settings is empty"
        );
        let f = &k["far_end"];
        Self {
            bad,
            refresh: text(&k["refresh_settings"], "refresh_settings"),
            public_url: optional(&k["public_url"], "public_url"),
            carried: Carried {
                member: text(&k["member"], "member"),
                pool: optional(&k["pool"], "pool"),
                caller_ref: optional(&k["caller_ref"], "caller_ref"),
            },
            claimed: Arrival::of(&k["claimed"], "claimed"),
            unclaimed: Arrival::of(&k["unclaimed"], "unclaimed"),
            request: text(&k["request"], "request"),
            status: small(num(&f["status"], "far_end.status"), "far_end.status"),
            head: pairs(&f["fields"], "far_end.fields"),
            answer: text(&f["answer"], "far_end.answer"),
            narrow: (
                num(&k["narrow"]["unit"], "narrow.unit"),
                num(&k["narrow"]["reply_cap"], "narrow.reply_cap") as usize,
                num(&k["narrow"]["more"], "narrow.more"),
            ),
            short: (
                num(&k["short"]["unit"], "short.unit"),
                Buffer::of(&k["short"]["buffer"], "short.buffer").unwrap_or(Buffer::Units),
            ),
            empty: k["empty"]
                .is_object()
                .then(|| num(&k["empty"]["unit"], "empty.unit")),
            sessions: Session::all(&k["sessions"]),
            refusal: (
                small(
                    num(&k["refusal"]["status"], "refusal.status"),
                    "refusal.status",
                ),
                text(&k["refusal"]["text"], "refusal.text"),
            ),
        }
    }
}

/// The ATTEMPT piece of `unit` on `claim`: from the kernel, no bytes, attempt 1.
fn attempt(unit: u64, claim: u32) -> Given<'static> {
    Given {
        unit,
        stream: 0,
        claim,
        from: FROM_KERNEL,
        flags: 0,
        bytes: b"",
        attempt_no: 1,
        status: 0,
        head: &[],
    }
}

/// A piece of the far end's answer to `unit` on `claim`, its status and kept head fields given on
/// the piece that states them.
fn far_end<'a>(
    unit: u64,
    claim: u32,
    flags: u32,
    bytes: &'a [u8],
    (status, head): (u32, &'a [Field]),
) -> Given<'a> {
    Given {
        unit,
        stream: 0,
        claim,
        from: FROM_FAR_END,
        flags,
        bytes,
        attempt_no: 0,
        status,
        head,
    }
}

/// `open` of generation 1 over `settings`, under `public_url` when one is named.
fn open(p: &Plugin<Plane>, settings: &[u8], public_url: Option<&[u8]>) -> String {
    let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
    (f.input.open.generation, f.input.open.settings) = (1, json(settings));
    if let Some(url) = public_url {
        f.input.public_url = abi(url);
    }
    let (c, snap) = p.open(&mut f);
    format!("{} {}", called(&c), snapshot(snap.as_ref()))
}

fn generation(p: &Plugin<Plane>, s: u32, generation: u64) -> String {
    let mut g: Frame<GenIn, OutHead> = Frame::new(input(), output());
    g.input.generation = generation;
    called(&p.call(s, &mut g))
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = Inputs::of(s.kind_inputs("plane"));
    let settings = leg.settings(s);
    let head = field_list(&k.head);
    let answered = (k.status, head.as_slice());
    let url = k.public_url.as_deref();
    let (c, claim) = (&k.carried, k.claimed.claim);

    let d = dispatcher();
    let p = load::<Plane>(s, leg, s.bind(&d, "plane")).expect("the plane door loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("facts", 0, || {
        format!(
            "{:?} {} max_inflight={}",
            p.kind(),
            p.name(),
            p.max_inflight()
        )
    });
    // `validate` is handed the blob stage 3g deals a plane: `{<declaring section>: <settings>}`
    // (`config_validate::deal`, `Seat::Verbs`); `open` and `refresh` take the section as written.
    let section = p.served().section;
    let dealt = |b: &[u8]| -> Vec<u8> {
        let value: Value = serde_json::from_slice(b).expect("conformance.json settings are JSON");
        serde_json::to_vec(&serde_json::json!({ section: value })).expect("a dealt blob")
    };
    for (i, b) in k.bad.iter().enumerate() {
        r.line(&format!("validate bad #{i}"), 1, || {
            called(&validate(&p, &dealt(b)))
        });
    }
    r.line("validate", 1, || called(&validate(&p, &dealt(&settings))));
    // No instance yet: the host refuses without a crossing.
    r.line("arrive unopened", 0, || arrive(&p, &k.claimed, &k.request));
    r.line("open", 1, || open(&p, &settings, url));
    ready_step(&mut r, s, &p, &d);
    // One open per instance: the host refuses without a crossing.
    r.line("open again", 0, || open(&p, &settings, url));
    r.line("hydrate", 1, || generation(&p, slot::HYDRATE, 1));
    r.line("start", 1, || generation(&p, slot::START, 1));
    r.line("arrive claimed", 1, || arrive(&p, &k.claimed, &k.request));
    r.line("arrive unclaimed", 1, || {
        arrive(&p, &k.unclaimed, &k.request)
    });

    let unit = k.claimed.unit;
    let whole = PIECE_HAS_STATUS | PIECE_LAST;
    let room = (CAP, CAP);
    // One unit: the ATTEMPT, the caller's body, the far end's whole answer.
    let mut piece = Piece::new(1024);
    for (label, g) in [
        ("attempt", attempt(unit, claim)),
        (
            "body",
            Given {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                bytes: &k.request,
                attempt_no: 0,
                ..attempt(unit, claim)
            },
        ),
        ("far_end", far_end(unit, claim, whole, &k.answer, answered)),
    ] {
        r.line(label, 1, || {
            let (called, f) = on_piece(&p, &mut piece, g, room, c);
            piece.line(&called, &f.out)
        });
    }

    // Another, whose answer is written `reply_cap` bytes at a time, then paid out by `more`.
    let (narrow_unit, cap, more) = k.narrow;
    let mut narrow = Piece::new(cap);
    r.line("narrow attempt", 1, || {
        let (called, f) = on_piece(&p, &mut narrow, attempt(narrow_unit, claim), room, c);
        narrow.line(&called, &f.out)
    });
    r.line("narrow far_end", 1, || {
        let g = far_end(narrow_unit, claim, whole, &k.answer, answered);
        let (called, f) = on_piece(&p, &mut narrow, g, room, c);
        narrow.line(&called, &f.out)
    });
    for i in 0..more {
        r.line(&format!("narrow more #{i}"), 1, || {
            let g = far_end(narrow_unit, claim, 0, b"", answered);
            let (called, f) = on_piece(&p, &mut narrow, g, room, c);
            narrow.line(&called, &f.out)
        });
    }

    // Another, whose answer meets a units (or fields) buffer of capacity 0: SHORT, then its one
    // re-call.
    let (short_unit, buffer) = k.short;
    let mut short = Piece::new(1024);
    r.line("short attempt", 1, || {
        let (called, f) = on_piece(&p, &mut short, attempt(short_unit, claim), room, c);
        short.line(&called, &f.out)
    });
    r.line("far_end short", 2, || {
        let g = far_end(short_unit, claim, whole, &k.answer, answered);
        short_then(&p, &mut short, g, buffer, c, Piece::line)
    });

    // A caller body that ended empty.
    if let Some(empty) = k.empty {
        r.line("empty", 1, || {
            let g = Given {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                attempt_no: 0,
                ..attempt(empty, claim)
            };
            let (called, f) = on_piece(&p, &mut piece, g, room, c);
            piece.line(&called, &f.out)
        });
    }

    sessions(&mut r, &p, &k.sessions, c);

    r.line("refusal", 1, || {
        let (mut reply, mut arena) = ([0_u8; 512], [0_u8; 256]);
        let mut fields = [z::<OutField>(); 2];
        let mut f: Frame<RefusalIn, RefusalOut> = Frame::new(input(), output());
        (f.input.cause, f.input.status, f.input.text) =
            (REFUSAL_GATE, k.refusal.0, abi(&k.refusal.1));
        (f.input.reply_buf, f.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (f.input.fields_buf, f.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut f);
        let written: Vec<String> = fields[..(f.out.fields_written as usize).min(2)]
            .iter()
            .map(|x| format!("{}={}", at(&arena, x.name), at(&arena, x.value)))
            .collect();
        format!(
            "{} reply={} fields={written:?} status={}",
            called(&c),
            String::from_utf8_lossy(&reply[..(f.out.reply_written as usize).min(reply.len())]),
            f.out.status
        )
    });
    r.line("serve", 1, || {
        let (mut reply, mut arena) = ([0_u8; 512], [0_u8; 256]);
        let mut fields = [z::<OutField>(); 2];
        let mut f: Frame<ServeIn, ServeOut> = Frame::new(input(), output());
        (f.input.reply_buf, f.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (f.input.fields_buf, f.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::SERVE, &mut f);
        format!(
            "{} status={} reply_written={}",
            called(&c),
            f.out.status,
            f.out.reply_written
        )
    });
    r.line("project", 1, || {
        let mut arena = [0_u8; 256];
        let mut signals = [z::<SignalEntry>(); 4];
        let mut f: Frame<ProjectIn, ProjectOut> = Frame::new(input(), output());
        (f.input.claim, f.input.target) = (claim, abi(&k.claimed.target));
        f.input.body = octets(&k.request);
        (f.input.signals_buf, f.input.signals_cap) = (signals.as_mut_ptr(), signals.len());
        (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::PROJECT, &mut f);
        format!("{} signals={}", called(&c), f.out.view.signals_len)
    });
    r.line("drive", 1, || {
        let mut sessions = [0_u64; 4];
        let mut f: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(input(), output());
        (f.input.sessions_buf, f.input.sessions_cap) = (sessions.as_mut_ptr(), sessions.len());
        let c = p.call(life::DRIVE, &mut f);
        format!("{} sessions={}", called(&c), f.out.sessions_written)
    });
    // A plane answers under no lease: the release of none.
    r.line("release none", 1, || called(&release(&p, 0)));
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1_000);
        format!("{} next={next}", called(&c))
    });
    r.line("cancel", 1, || {
        let mut f: Frame<
            busbar_contract::abi::plane::PlaneCancelIn,
            busbar_contract::abi::plane::PlaneCancelOut,
        > = Frame::new(input(), output());
        let c = p.call(life::CANCEL, &mut f);
        format!("{} disposition={}", called(&c), f.out.cancel.disposition)
    });
    // The refresh's frame carries no public URL: the instance keeps the one its `open` was handed.
    let refresh = |what: &[u8]| {
        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(input(), output());
        (f.input.generation, f.input.settings) = (2, json(what));
        let (c, snap) = p.refresh(&mut f);
        format!("{} {}", called(&c), snapshot(snap.as_ref()))
    };
    r.line("refresh", 1, || refresh(&k.refresh));
    r.line("retire", 1, || generation(&p, life::RETIRE, 1));
    r.line("close", 1, || called(&close(&p)));
    // Closed: the host answers FAULT without a crossing.
    r.line("arrive after close", 0, || {
        arrive(&p, &k.claimed, &k.request)
    });
    let fold = r.fold();
    contract(&fold, s.kind_inputs("plane"));
    fold
}

/// The step labelled `label`'s answer.
fn answer<'f>(fold: &'f Fold, label: &str) -> &'f str {
    fold.iter()
        .find(|s| s.label == label)
        .map(|s| s.answer.as_str())
        .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
}

/// `[[<class>, <amount>], ...]` as a piece's line writes reported units.
fn reported(v: &Value, what: &str) -> String {
    let units: Vec<String> = pairs(v, what)
        .iter()
        .map(|(class, amount)| format!("{class}:{amount}:true"))
        .collect();
    format!("units={units:?}")
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: no answer the
/// kind's check refused (FAULT) but after `close`; the settings judged at `validate`; one `open`
/// per instance; each generation's snapshot holds the claims the inputs state; a claimed request
/// arrives READY (over the route the inputs name, when they name one) and an unclaimed one is
/// refused at its status; the ATTEMPT goes to the far end; the caller's body and the far end's
/// answer are relayed as the inputs state, with the far end's count REPORTED at its last piece
/// (whole, paid out through a narrow buffer, and after a short answer's re-call alike); every
/// session step answers as its `want` states; the refusal speaks the dialect; the lifecycle
/// answers READY.
fn contract(fold: &Fold, k: &Value) {
    let at = |label: &str| answer(fold, label);
    let str_of = |v: &Value, what: &str| String::from_utf8(text(v, what)).expect("UTF-8 input");
    for s in fold {
        if s.label != "arrive after close" {
            assert!(!s.answer.starts_with("Fault "), "{}: {}", s.label, s.answer);
        }
    }
    for label in [
        "validate",
        "open",
        "hydrate",
        "start",
        "arrive claimed",
        "attempt",
        "body",
        "far_end",
        "narrow attempt",
        "narrow far_end",
        "short attempt",
        "refusal",
        "drive",
        "release none",
        "tick",
        "cancel",
        "refresh",
        "retire",
        "close",
    ] {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    let refused = at("validate bad #0");
    assert!(
        !refused.starts_with("Ready ") && refused.len() > "Refused lease=false ".len(),
        "a refused validate names why: {refused}"
    );
    assert!(
        at("arrive unopened").starts_with("Refused "),
        "{}",
        at("arrive unopened")
    );
    assert!(
        at("open again").starts_with("Refused "),
        "one open per instance: {}",
        at("open again")
    );
    assert!(
        at("arrive after close").starts_with("Fault "),
        "{}",
        at("arrive after close")
    );

    let want_claims = |what: &str| {
        let c = pairs(&k[what], what);
        claims(c.iter().map(|(v, t)| (v.as_str(), t.as_str())))
    };
    assert!(
        at("open").contains(&format!("gen=1 claims=[{}] ", want_claims("open_claims"))),
        "open: {}",
        at("open")
    );
    assert!(
        at("refresh").contains(&format!(
            "gen=2 claims=[{}] ",
            want_claims("refresh_claims")
        )),
        "refresh: {}",
        at("refresh")
    );

    if let Some(route) = k["claimed"]["route"].as_object() {
        let want = format!(
            " route={} entry={}",
            str_of(&route["class"], "claimed.route.class"),
            str_of(&route["entry"], "claimed.route.entry")
        );
        assert!(
            at("arrive claimed").ends_with(&want),
            "a claimed request routes over{want}: {}",
            at("arrive claimed")
        );
    }
    let status = num(&k["unclaimed"]["status"], "unclaimed.status");
    let unclaimed = at("arrive unclaimed");
    assert!(
        !unclaimed.starts_with("Ready ") && unclaimed.ends_with(&format!(" status={status}")),
        "an unclaimed request is refused at {status}: {unclaimed}"
    );
    for label in ["attempt", "narrow attempt", "short attempt"] {
        assert!(
            at(label).contains(" to_far_end=true "),
            "{label}: {}",
            at(label)
        );
    }
    let request_out = str_of(&k["request_out"], "request_out");
    assert!(
        at("body").contains(&format!(" emitted={request_out} more=0 to_far_end=true ")),
        "body: {}",
        at("body")
    );

    let f = &k["far_end"];
    let answer_out = str_of(&f["answer_out"], "far_end.answer_out");
    let units = reported(&f["units"], "far_end.units");
    let fs = num(&f["status"], "far_end.status");
    let whole = at("far_end");
    assert!(
        whole.contains(&format!(
            " emitted={answer_out} more=0 to_far_end=false done=true status={fs} "
        )) && whole.ends_with(&units),
        "the far end's whole answer, relayed with its count ({units}): {whole}"
    );

    // The narrow answer: its pieces, in order, are the whole answer; only the last is done.
    let more = num(&k["narrow"]["more"], "narrow.more");
    let mut pieces = vec![at("narrow far_end").to_string()];
    pieces.extend((0..more).map(|i| at(&format!("narrow more #{i}")).to_string()));
    let mut relayed = String::new();
    for (i, line) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        let emitted = line
            .split_once(" emitted=")
            .and_then(|(_, rest)| rest.split_once(" more="))
            .map(|(e, _)| e)
            .unwrap_or_else(|| panic!("narrow piece #{i}: {line}"));
        relayed.push_str(emitted);
        let tail = if last {
            " more=0 to_far_end=false done=true "
        } else {
            " more=1 to_far_end=false done=false "
        };
        assert!(
            line.starts_with("Ready ") && line.contains(tail),
            "narrow piece #{i}: {line}"
        );
    }
    assert_eq!(
        relayed, answer_out,
        "the narrow pieces relay the whole answer"
    );
    assert!(
        pieces[0].ends_with(&units),
        "the count rides the first narrow write: {}",
        pieces[0]
    );

    // The short answer: FAILED with the room it needs and a re-call token, then the whole answer.
    let short = at("far_end short");
    let buffer = Buffer::of(&k["short"]["buffer"], "short.buffer").unwrap_or(Buffer::Units);
    assert!(
        short.starts_with("Failed ")
            && !short.contains(&format!(" {}_needed=0 ", buffer.name()))
            && short.contains(" recall=true then=Ready ")
            && short.contains(&format!(
                " emitted={answer_out} more=0 to_far_end=false done=true "
            ))
            && short.ends_with(&units),
        "a short answer, re-called once with room: {short}"
    );

    if k["empty"].is_object() {
        let want = str_of(&k["empty"]["outcome"], "empty.outcome");
        assert!(
            at("empty").starts_with(&format!("{want} ")),
            "empty: {}",
            at("empty")
        );
    }
    sessions_contract(fold, &k["sessions"]);
    if let Some(reply) = k["refusal"]["reply"].as_str() {
        assert!(
            at("refusal").contains(&format!(" reply={reply} ")),
            "refusal: {}",
            at("refusal")
        );
    }
}

/// Every session step answered as its `want` states (`plane.sessions[].steps[].want`).
fn sessions_contract(fold: &Fold, sessions: &Value) {
    for s in sessions.as_array().into_iter().flatten() {
        let name = s["name"].as_str().unwrap_or_default();
        for st in s["steps"].as_array().into_iter().flatten() {
            let label = format!("{name} {}", st["label"].as_str().unwrap_or_default());
            let short = st["piece"]["short"].as_str();
            judge(&label, answer(fold, &label), &st["want"], short);
        }
    }
}

/// The keys a session step's `want` may name.
const WANTS: &[&str] = &[
    "outcome",
    "to_far_end",
    "done",
    "more",
    "status",
    "verb",
    "target",
    "need",
    "emitted",
    "emitted_has",
    "fields",
    "units",
    "route",
    "streams",
    "body_has",
    "rewritten",
];

/// `line` (step `label`'s answer) answers as `want` states; a step met `short` answered FAILED with
/// the room it needs and a re-call token first, and `want` is its re-call's answer.
fn judge(label: &str, line: &str, want: &Value, short: Option<&str>) {
    let want = want
        .as_object()
        .unwrap_or_else(|| panic!("conformance.json: step '{label}' states no want"));
    for key in want.keys() {
        assert!(
            WANTS.contains(&key.as_str()),
            "conformance.json: step '{label}' wants '{key}', which is none of {WANTS:?}"
        );
    }
    let line = match short {
        Some(buffer) => {
            assert!(
                line.starts_with("Failed ")
                    && !line.contains(&format!(" {buffer}_needed=0 "))
                    && line.contains(" recall=true then="),
                "{label}: a short answer names the room it needs and is re-called once: {line}"
            );
            line.split_once(" then=").map_or(line, |(_, then)| then)
        }
        None => line,
    };
    let scalar = |v: &Value| v.as_str().map_or_else(|| v.to_string(), String::from);
    let has = |needle: &str, what: &str| {
        assert!(
            line.contains(needle),
            "{label}: wants {what} `{}`: {line}",
            needle.trim()
        );
    };
    for (key, v) in want {
        match key.as_str() {
            "outcome" => assert!(
                line.starts_with(&format!("{} ", scalar(v))),
                "{label}: wants {}: {line}",
                scalar(v)
            ),
            "emitted" => has(&format!(" emitted={} more=", scalar(v)), key),
            "emitted_has" | "body_has" => {
                for s in v.as_array().into_iter().flatten() {
                    has(&scalar(s), key);
                }
            }
            "fields" => {
                let fields: Vec<String> = pairs(v, "sessions[].steps[].want.fields")
                    .iter()
                    .map(|(n, v)| format!("{n}={v}"))
                    .collect();
                has(&format!(" fields={fields:?} "), key);
            }
            "units" => {
                let units = reported(v, "sessions[].steps[].want.units");
                assert!(line.ends_with(&units), "{label}: wants {units}: {line}");
            }
            "route" => {
                let route = format!(
                    " route={} entry={}",
                    scalar(&v["class"]),
                    v["entry"].as_str().unwrap_or_default()
                );
                assert!(line.ends_with(&route), "{label}: wants{route}: {line}");
            }
            "streams" => {
                let streams: Vec<u64> = v
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|s| num(s, "sessions[].steps[].want.streams[]"))
                    .collect();
                let want = format!("streams={streams:?}");
                assert!(line.ends_with(&want), "{label}: wants {want}: {line}");
            }
            _ => has(&format!(" {key}={} ", scalar(v)), key),
        }
    }
}

#[cfg(test)]
#[path = "../tests/conformance_plane_sessions_tests.rs"]
mod tests;
