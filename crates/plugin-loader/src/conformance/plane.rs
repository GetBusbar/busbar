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
//!     "host": { "entitled": [...], "trusted": [...] },     // optional: the kernel services served
//!     "attempt": { "to_far_end": false },                  // optional: the ATTEMPT is taken, the
//!                                                          // request rides the caller's body
//!     "arrive_each": true,                                 // optional: every unit arrives first
//!     "claimed":   { "unit": 7, "method": "POST", "target": "/v1/x",  // arrive: READY
//!                    "claim": 0,                          // optional: the snapshot claim (0)
//!                    "fields": [["<name>", "<value>"], ...],          // optional: its head
//!                    "route": { "class": "pool", "entry": "<name>",     // optional: named
//!                               "flags": ["session"] } },                 // optional: its bits
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
//!         "ticket": true,                    // optional: it cancels on its ticket
//!         "steps": [
//!           { "label": "<unique in the session>",
//!             // ONE of:
//!             "arrive": { "method": "GET", "target": "/s", "fields": [...], "body": <bytes> },
//!             "piece": { "from": "caller" | "far_end" | "kernel", "attempt": 1, "last": true,
//!                        "status": 200, "fields": [...], "bytes": <bytes>,
//!                        "short": "units" | "fields" },   // met at capacity 0, then re-called
//!             "drive": true,
//!             "project": { "target": "/s", "body": <bytes>, "rewrite": <bytes> },
//!             "tick": { "now_ns": <n>,       // on a driver ticket
//!                       "wakes": true },     // optional: it wakes the driver, so `drive` crosses
//!             "cancel": true,                // of the op on the session's ticket
//!             "want": { "outcome": "Ready", ... } } ] } ],
//!     "refusal": { "status": 403, "text": "denied", "reply": "<the dialect's error body>" } } }
//! ```
//!
//! `<bytes>` is a string, or an array of parts each a string or `{ "repeat": "<text>", "times": n }`
//! (a large payload stated small). A session step's `want` names its outcome (required) and any of:
//! `to_far_end`, `done`, `more`, `status`, `verb`, `target`, `need`, `emitted` (exact),
//! `emitted_has` (substrings), `fields` (`[["<name>", "<value>"], ...]`, exact), `units`
//! (`[[<class>, <amount>], ...]`, reported, exact), `route` (`{ "class", "entry" }`),
//! `route_flags` (`["once" | "session" | "stream", ...]`), `ready` (the stream ids `drive`
//! names), `body_has` (substrings of the projected body), `rewritten`, `next` (the tick `tick`
//! asks for), `disposition` (`cancel`'s), `lane` (the ledger lane a piece's answer names; `""` =
//! none), `records` (its record writes, `[["put" | "audit", <kind>, "<key>", "<value>"], ...]`, a
//! value that is not printable text as `hex:` and its bytes; `[]` = none) and `turns` (the prompt
//! turns `project` writes, `[["<role>", "<text>"], ...]`; `[]` = none). A piece's line names its
//! lane and records, and a project line its turns, only when the answer carries them.
//!
//! THE HOST (`plane.host`, `plane_host.rs`): the leg's dispatcher serves `entitlement.check` and
//! `trust.serves` from the tables the inputs state, `clock.now` at `0`, and refuses every other
//! service, so a plane that gates what a caller may see and call on the kernel's answers runs its
//! gating here. Stating none, the dispatcher serves what it serves today.
//!
//! `arrive_each`: the narrow, short and empty units arrive (as the claimed one, steps `<leg>
//! arrive`) and the narrow and short ones send the caller's body after their ATTEMPT (`<leg>
//! body`, judged as `body`), for a plane that holds a unit's state from its arrival.
//!
//! Every session is a unit on a ticket of its own, minted for it and recycled after its last step
//! (below), so its pieces' heads name it; a session with a `cancel` step names `ticket`, and the
//! `cancel` names that ticket in `CancelIn::ticket`. A `tick` step crosses on the instance's DRIVER
//! ticket, as the kernel ticks an instance, so a session past its ceiling owes its end to `drive`
//! and a collection; a tick that `wakes` its driver is pinned at two, the tick and the `drive` the
//! dispatcher calls on the woken ticket.
//!
//! THE CROSSINGS ARE THE KERNEL'S (THE DESIGN §11.4: one table, as production drives it). A unit's
//! pieces (`on_piece`) are SUBMITTED on the unit's own ticket, every piece of the unit on that one
//! ticket, as the kernel's plane driver submits them (`dispatch::plane_calls`); `serve` is submitted
//! on a request ticket; `tick` on the instance's DRIVER ticket, and `drive` is crossed by a WAKE
//! of that ticket, as every production `drive` is. So a piece that waits
//! (a may-pend host service, or the plane's own upstream) answers PENDING and is RESUMED on its
//! wake (§11.2; a may-pend service on a ticket-less op is REFUSED, §11.12), and every buffer a
//! submitted op names is LENT to it through the dispatcher's lending submit (§2). The pure ops
//! (`arrive`, `refusal`, `project`) and the lifecycle are ticket-less crossings (`Plugin::call`),
//! as the kernel makes them. A resume is reported, never pinned (Q-P4-5).
//!
//! THE PINS. Every step is ONE first invocation, but:
//! * `ready` ([`super::ready_step`]): 0 when the door states none;
//! * `arrive unopened` and `open again`: 0, the host answers REFUSED without a crossing (no
//!   instance yet; one `open` per instance);
//! * `far_end short`, and a session piece met `short`: 2, the short answer and its ONE re-call,
//!   re-submitted on the unit's ticket with room (the short-buffer rule on `OutHead`);
//! * `arrive after close`: 0, a closed instance answers FAULT without a crossing.
//!
//! The narrow answer's `more` re-calls are each their own step of one crossing, as many as the
//! inputs pin (`narrow.more`), so a plane that writes fewer bytes per piece than the buffer holds
//! crosses more often than pinned and is refused. A session's `more` re-call is a piece step of
//! its own (`from` the side, no bytes, no flags), pinned the same way.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{MessageView, SignalEntry};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Field, OutHead, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneCancelIn, PlaneCancelOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, RECORD_AUDIT,
    RECORD_PUT, REFUSAL_GATE, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_ONCE, ROUTE_POOL, ROUTE_SCOPE,
    ROUTE_SESSION, ROUTE_STREAM, SPAN_ABSENT, UNITS_REPORTED,
};
use serde_json::Value;

use super::{
    answered, called, close, crossings, dispatcher, input, json, load, on_ticket_frame, output,
    ready_step, release, submit_on, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::plane::{OwnedSnapshot, Plane};
use crate::dispatch::{now_ns, Called, DispatchConfig, Dispatcher, Frame, Lent, Plugin};

#[path = "plane_host.rs"]
mod host;

/// The capacity of each of the host's per-piece lists (units, record writes, fields).
const CAP: usize = 8;
/// How long a submitted op may wait (PENDING) before its deadline cancels it: well past every wait
/// a conforming plane makes, so a plane that never wakes fails the step instead of hanging the run.
const OP_DEADLINE: Duration = Duration::from_secs(30);

/// The deadline of an op submitted now.
fn deadline() -> u64 {
    now_ns().saturating_add(u64::try_from(OP_DEADLINE.as_nanos()).unwrap_or(u64::MAX))
}
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

/// A record write's key or value as the line shows it: its text, when it is printable UTF-8;
/// else `hex:` and its bytes in lower-case hex.
fn shown(buf: &[u8], s: Span) -> String {
    let (from, len) = (s.offset as usize, s.len as usize);
    let Some(b) = buf.get(from..from + len) else {
        return "<OUTSIDE>".into();
    };
    match std::str::from_utf8(b) {
        Ok(t) if !t.chars().any(char::is_control) => t.to_string(),
        _ => format!(
            "hex:{}",
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        ),
    }
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

/// What `ArriveOut::route_flags` states, by name; a bit the ABI does not name, as its number.
fn route_flags(flags: u8) -> Vec<String> {
    let mut named: Vec<String> = [
        (ROUTE_ONCE, "once"),
        (ROUTE_SESSION, "session"),
        (ROUTE_STREAM, "stream"),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| (*name).to_string())
    .collect();
    let other = flags & !(ROUTE_ONCE | ROUTE_SESSION | ROUTE_STREAM);
    if other != 0 {
        named.push(other.to_string());
    }
    named
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

/// THE MEMORY ONE PIECE LENDS THE PLANE: the host's buffers (reply, units, record writes, fields,
/// arena) and the piece's own bytes, head fields and carried names. Built in place in the `Arc`
/// that is lent to the op (THE DESIGN §2), so its pointers stay valid however the op ends.
struct Piece {
    reply: Vec<u8>,
    units: [UnitCount; CAP],
    records: [RecordWrite; CAP],
    fields: [OutField; CAP],
    arena: [u8; 1024],
    bytes: Vec<u8>,
    _head: Vec<(String, String)>,
    head: Vec<Field>,
    member: Vec<u8>,
    pool: Option<Vec<u8>>,
    caller_ref: Option<Vec<u8>>,
}

// SAFETY: the raw pointers in `head` point into `_head`, owned by the same `Piece`; nothing
// mutates a lent `Piece` but the plane's writes into its buffers, which the host reads only after
// the op completes.
unsafe impl Send for Piece {}
// SAFETY: as above.
unsafe impl Sync for Piece {}

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
    head: &'a [(String, String)],
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
    /// `g`'s piece, `reply_cap` bytes of reply buffer, its frame with the lists at `caps`: the
    /// memory lent, and the frame over it.
    fn lent(
        reply_cap: usize,
        g: Given<'_>,
        (units_cap, fields_cap): (usize, usize),
        c: &Carried,
    ) -> (Arc<Self>, Frame<OnPieceIn, OnPieceOut>) {
        let mut piece = Arc::new(Self {
            reply: vec![0; reply_cap],
            units: [z(); CAP],
            records: [z(); CAP],
            fields: [z(); CAP],
            arena: [0; 1024],
            bytes: g.bytes.to_vec(),
            _head: g.head.to_vec(),
            head: Vec::new(),
            member: c.member.clone(),
            pool: c.pool.clone(),
            caller_ref: c.caller_ref.clone(),
        });
        let me = Arc::get_mut(&mut piece).expect("a piece not yet lent is unshared");
        me.head = field_list(&me._head);
        let mut i: OnPieceIn = input();
        (i.unit, i.from, i.flags, i.bytes) = (g.unit, g.from, g.flags, octets(&me.bytes));
        (i.stream, i.claim) = (g.stream, g.claim);
        (i.attempt_no, i.member) = (g.attempt_no, abi(&me.member));
        if let (Some(pool), true) = (&me.pool, g.from == FROM_KERNEL && g.attempt_no > 0) {
            i.pool = abi(pool);
        }
        if let Some(r) = &me.caller_ref {
            i.caller_ref = abi(r);
        }
        if g.flags & PIECE_HAS_STATUS != 0 {
            i.status_code = g.status;
            (i.head_fields, i.head_fields_len) = (me.head.as_ptr(), me.head.len());
        }
        (i.reply_buf, i.reply_cap) = (me.reply.as_mut_ptr(), me.reply.len());
        (i.units_buf, i.units_cap) = (me.units.as_mut_ptr(), units_cap);
        (i.records_buf, i.records_cap) = (me.records.as_mut_ptr(), me.records.len());
        (i.fields_buf, i.fields_cap) = (me.fields.as_mut_ptr(), fields_cap);
        (i.arena_buf, i.arena_cap) = (me.arena.as_mut_ptr(), me.arena.len());
        (piece, Frame::new(i, output()))
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
    /// The ledger lane the answer names and its record writes, each written only when the answer
    /// carries one (` lane=<lane>`, ` records=[..]`).
    fn ledger(&self, o: &OnPieceOut) -> String {
        let mut out = String::new();
        if o.lane.len != 0 {
            out.push_str(&format!(" lane={}", at(&self.arena, o.lane)));
        }
        let records: Vec<String> = self.records[..(o.records_written as usize).min(CAP)]
            .iter()
            .map(|r| {
                let op = match r.op {
                    RECORD_PUT => "put".to_string(),
                    RECORD_AUDIT => "audit".to_string(),
                    other => other.to_string(),
                };
                format!(
                    "{op}:{}:{}={}",
                    r.kind,
                    shown(&self.arena, r.key),
                    shown(&self.arena, r.value)
                )
            })
            .collect();
        if !records.is_empty() {
            out.push_str(&format!(" records={records:?}"));
        }
        out
    }

    fn session_line(&self, c: &Called, o: &OnPieceOut) -> String {
        format!(
            "{} emitted={} more={} to_far_end={} done={} status={} verb={} target={} need={}{} \
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
            self.ledger(o),
            self.fields(o),
            self.units(o),
        )
    }
}

/// ONE UNIT AS THE KERNEL DRIVES IT: its ticket, on which every piece of the unit (and the one
/// re-call a short answer earns) is submitted, and its reply buffer's capacity.
struct Unit {
    ticket: Ticket,
    reply_cap: usize,
}

impl Unit {
    /// A unit on a fresh request ticket of `d`'s.
    ///
    /// # Panics
    /// When no ticket is free.
    fn mint(d: &Dispatcher, reply_cap: usize) -> Self {
        Self {
            ticket: d.mint(0).expect("a unit's ticket is minted"),
            reply_cap,
        }
    }

    /// The unit is over: its ticket recycled.
    fn end(self, d: &Dispatcher) {
        d.recycle(self.ticket);
    }
}

/// One piece's answer: as the host reads it, whether it was SHORT, the memory it was lent and the
/// frame back (`None` when the op was faulted mid-crossing).
struct Pieced {
    called: Called,
    short: bool,
    piece: Arc<Piece>,
    frame: Option<Box<Frame<OnPieceIn, OnPieceOut>>>,
}

impl Pieced {
    /// The plane's `out` (an all-zero one when no frame came back).
    fn out(&self) -> OnPieceOut {
        self.frame.as_ref().map_or_else(output, |f| f.out)
    }

    fn line(&self, line: fn(&Piece, &Called, &OnPieceOut) -> String) -> String {
        line(&self.piece, &self.called, &self.out())
    }
}

/// `on_piece` of `g`, the lists at `caps`, SUBMITTED ON THE UNIT'S TICKET as the kernel's plane
/// driver submits it (Stream class, the piece's memory lent to the op): a piece that answers
/// PENDING is resumed on its wake until it answers.
fn on_piece(
    p: &Plugin<Plane>,
    d: &Dispatcher,
    unit: &Unit,
    g: Given<'_>,
    caps: (usize, usize),
    c: &Carried,
) -> Pieced {
    let (piece, f) = Piece::lent(unit.reply_cap, g, caps, c);
    let done = submit_on(
        p,
        d,
        unit.ticket,
        slot::ON_PIECE,
        f,
        (DeadlineClass::Stream, deadline()),
        Arc::clone(&piece) as Lent,
        Duration::ZERO,
    );
    Pieced {
        called: answered(&done),
        short: done.short,
        piece,
        frame: done.frame,
    }
}

/// `g` met with `buffer` at capacity 0: SHORT, then its ONE re-call with room, re-submitted on the
/// unit's ticket over the same memory (two crossings).
fn short_then(
    p: &Plugin<Plane>,
    d: &Dispatcher,
    unit: &Unit,
    g: Given<'_>,
    buffer: Buffer,
    c: &Carried,
    line: fn(&Piece, &Called, &OnPieceOut) -> String,
) -> String {
    let first = on_piece(p, d, unit, g, buffer.caps(), c);
    let head = format!(
        "{} {}_needed={} recall={}",
        called(&first.called),
        buffer.name(),
        buffer.needed(&first.out()),
        first.short
    );
    let (true, Some(mut f)) = (first.short, first.frame) else {
        return format!("{head} then=no-recall");
    };
    (f.input.units_cap, f.input.fields_cap) = (CAP, CAP);
    let again = submit_on(
        p,
        d,
        unit.ticket,
        slot::ON_PIECE,
        *f,
        (DeadlineClass::Stream, deadline()),
        Arc::clone(&first.piece) as Lent,
        Duration::ZERO,
    );
    let out = again.frame.as_ref().map_or_else(output, |f| f.out);
    format!(
        "{head} then={}",
        line(&first.piece, &answered(&again), &out)
    )
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
    /// The same arrival for another unit.
    fn for_unit(&self, unit: u64) -> Self {
        Self {
            unit,
            claim: self.claim,
            method: self.method.clone(),
            target: self.target.clone(),
            fields: self.fields.clone(),
            route: self.route,
        }
    }

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
            "{line} route_flags={:?} route={} entry={}",
            route_flags(f.out.route_flags),
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
    /// `tick` at `now_ns`; `wakes`: its driver ticket is woken, so `drive` crosses on it too.
    Tick {
        now_ns: u64,
        wakes: bool,
    },
    Cancel,
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
        let ticket = s["ticket"].as_bool() == Some(true);
        assert!(
            ticket || !steps.iter().any(|(_, a)| matches!(a, Act::Cancel)),
            "conformance.json: plane.{what} cancels on its ticket, so it names `\"ticket\": true`"
        );
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
        let acts = ["arrive", "piece", "drive", "project", "tick", "cancel"];
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
            ["tick"] => Act::Tick {
                now_ns: num(&st["tick"]["now_ns"], &format!("{what}.tick.now_ns")),
                wakes: st["tick"]["wakes"].as_bool() == Some(true),
            },
            ["cancel"] => Act::Cancel,
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

/// `drive` AS THE KERNEL'S WAKES DRIVE IT (THE DESIGN §11.4): the instance's DRIVER ticket woken,
/// as a host service's completion wakes it, so the dispatcher crosses `drive` on it in the kind's
/// own frame (its head and its `driver` field name the driver, so a service that pends inside
/// registers there, and a PENDING drive is RESUMED on its next wake). Its answer (the first that
/// is not PENDING) and the streams it named, collected as the kernel collects them. `None` (no
/// driver ticket: the instance is not open) answers REFUSED without a crossing.
fn drive(p: &Plugin<Plane>, driver: Option<Ticket>) -> (Called, Vec<u64>) {
    use busbar_contract::abi::mechanism::call::Outcome;
    let answer = |outcome, error: Option<&[u8]>| Called {
        outcome,
        error: error.map(<[u8]>::to_vec),
        lease: 0,
        recall: None,
    };
    let Some(driver) = driver else {
        return (
            answer(Outcome::Refused, Some(b"no driver ticket")),
            Vec::new(),
        );
    };
    let driven = &p.inner.driven;
    let seen = driven.answers();
    crate::dispatch::ticket::host_wake(p.inner.ctx(), driver);
    match driven.answered_after(seen, OP_DEADLINE) {
        Some(outcome) => (answer(outcome, None), driven.drain()),
        None => (
            answer(Outcome::Fault, Some(b"the woken driver never answered")),
            Vec::new(),
        ),
    }
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
    let turns: Vec<String> = turns[..f.out.prompt.messages_len.min(CAP)]
        .iter()
        .map(|t| format!("{}:{}", read(t.role), read(t.text)))
        .collect();
    let turns = if turns.is_empty() {
        String::new()
    } else {
        format!(" turns={turns:?}")
    };
    format!(
        "{} rewritten={} signals={}{turns} body={}",
        called(&c),
        span(f.out.rewritten).is_some(),
        f.out.view.signals_len,
        span(f.out.body).unwrap_or_default()
    )
}

/// How long a `tick` that wakes its driver ticket waits for the `drive` the wake calls.
const WAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// `tick` at `now_ns` on the instance's DRIVER TICKET (`driver`), as the kernel ticks an instance
/// (its head names the driver, so a session that now owes its end names it). When the inputs say it
/// `wakes`, the dispatcher calls `drive` on the woken driver ticket, and the step waits (at most
/// [`WAKE_WAIT`]) for that second crossing's answer, so it is counted in this step; the names that
/// `drive` answered are collected there, as the kernel collects them, so a later `drive` step
/// reads only its own. `None` (no driver ticket: the instance is not open) crosses nothing.
fn tick_on_driver(
    p: &Plugin<Plane>,
    d: &Dispatcher,
    driver: Option<Ticket>,
    now_ns: u64,
    wakes: bool,
) -> String {
    let Some(driver) = driver else {
        return "no-driver-ticket".into();
    };
    let driven = &p.inner.driven;
    let seen = driven.answers();
    let done = d.tick(p, driver, now_ns).wait_done();
    if wakes {
        let _ = driven.answered_after(seen, WAKE_WAIT);
        let _ = driven.drain();
    }
    let next = done.frame.as_ref().map_or(0, |f| f.out.next_tick_ns);
    format!("{} next={next}", called(&answered(&done)))
}

/// `cancel` of the op on `ticket` (a session's): its disposition and the record writes it carried.
fn cancel(p: &Plugin<Plane>, ticket: Ticket) -> String {
    let mut records = [z::<RecordWrite>(); CAP];
    let mut arena = [0_u8; 1024];
    let mut f: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(input(), output());
    f.input.cancel.ticket = ticket;
    (f.input.records_buf, f.input.records_cap) = (records.as_mut_ptr(), records.len());
    (f.input.arena_buf, f.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
    let c = p.call(life::CANCEL, &mut f);
    format!(
        "{} disposition={} records={}",
        called(&c),
        f.out.cancel.disposition,
        f.out.records_written
    )
}

/// THE SESSIONS LEG: each session's steps, in order, each its own step of the fold
/// (`<name> <label>`), pinned at one crossing (a piece met `short`: two).
fn sessions(
    r: &mut Recorder<'_>,
    (p, d, driver): (&Plugin<Plane>, &Dispatcher, Option<Ticket>),
    all: &[Session],
    c: &Carried,
) {
    for s in all {
        let unit = Unit::mint(d, s.reply_cap);
        for (label, act) in &s.steps {
            let label = format!("{} {label}", s.name);
            match act {
                Act::Arrive(a, body) => r.line(&label, 1, || arrive(p, a, body)),
                Act::Drive => r.line(&label, 1, || {
                    let (c, ready) = drive(p, driver);
                    format!("{} ready={ready:?}", called(&c))
                }),
                Act::Tick { now_ns, wakes } => {
                    r.line(&label, 1 + u64::from(*wakes), || {
                        tick_on_driver(p, d, driver, *now_ns, *wakes)
                    });
                }
                Act::Cancel => r.line(&label, 1, || cancel(p, unit.ticket)),
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
                    let g = Given {
                        unit: s.unit,
                        stream: s.stream,
                        claim: s.claim,
                        from: *from,
                        flags: *flags,
                        bytes,
                        attempt_no: *attempt_no,
                        status: *status,
                        head,
                    };
                    match short {
                        None => r.line(&label, 1, || {
                            on_piece(p, d, &unit, g, (CAP, CAP), c).line(Piece::session_line)
                        }),
                        Some(b) => r.line(&label, 2, || {
                            short_then(p, d, &unit, g, *b, c, Piece::session_line)
                        }),
                    }
                }
            }
        }
        unit.end(d);
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
    /// Every unit of the script arrives (as the claimed one) and sends the caller's body after its
    /// ATTEMPT, for a plane that holds a unit's state from its arrival.
    arrive_each: bool,
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
            arrive_each: k["arrive_each"].as_bool() == Some(true),
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
    (status, head): (u32, &'a [(String, String)]),
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
    let answer = (k.status, k.head.as_slice());
    let url = k.public_url.as_deref();
    let (c, claim) = (&k.carried, k.claimed.claim);

    // The kernel services the plugin's inputs state (`plane.host`), served on the leg's dispatcher;
    // stating none, a dispatcher that serves none.
    let d = host::Host::of(&s.kind_inputs("plane")["host"]).map_or_else(dispatcher, |h| {
        std::sync::Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            std::sync::Arc::new(h),
        ))
    });
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
    // The instance's DRIVER ticket, as the kernel mints it once the instance is open: `drive` and
    // `tick` are submitted on it.
    let driver = d.driver(&p, 0);
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
    let one = Unit::mint(&d, 1024);
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
        ("far_end", far_end(unit, claim, whole, &k.answer, answer)),
    ] {
        r.line(label, 1, || {
            on_piece(&p, &d, &one, g, room, c).line(Piece::line)
        });
    }
    one.end(&d);

    // Another, whose answer is written `reply_cap` bytes at a time, then paid out by `more`.
    let (narrow_unit, cap, more) = k.narrow;
    let narrow = Unit::mint(&d, cap);
    // With `arrive_each`, a unit arrives first and its caller's body follows its ATTEMPT (through
    // the whole unit's buffers).
    let arrives = |r: &mut Recorder<'_>, what: &str, unit: u64| {
        if k.arrive_each {
            r.line(&format!("{what} arrive"), 1, || {
                arrive(&p, &k.claimed.for_unit(unit), &k.request)
            });
        }
    };
    let sends = |r: &mut Recorder<'_>, what: &str, unit: u64, on: &Unit| {
        if k.arrive_each {
            r.line(&format!("{what} body"), 1, || {
                let g = Given {
                    from: FROM_CALLER,
                    flags: PIECE_LAST,
                    bytes: &k.request,
                    attempt_no: 0,
                    ..attempt(unit, claim)
                };
                on_piece(&p, &d, on, g, room, c).line(Piece::line)
            });
        }
    };
    arrives(&mut r, "narrow", narrow_unit);
    r.line("narrow attempt", 1, || {
        on_piece(&p, &d, &narrow, attempt(narrow_unit, claim), room, c).line(Piece::line)
    });
    sends(&mut r, "narrow", narrow_unit, &narrow);
    r.line("narrow far_end", 1, || {
        let g = far_end(narrow_unit, claim, whole, &k.answer, answer);
        on_piece(&p, &d, &narrow, g, room, c).line(Piece::line)
    });
    for i in 0..more {
        r.line(&format!("narrow more #{i}"), 1, || {
            let g = far_end(narrow_unit, claim, 0, b"", answer);
            on_piece(&p, &d, &narrow, g, room, c).line(Piece::line)
        });
    }
    narrow.end(&d);

    // Another, whose answer meets a units (or fields) buffer of capacity 0: SHORT, then its one
    // re-call.
    let (short_unit, buffer) = k.short;
    let short = Unit::mint(&d, 1024);
    arrives(&mut r, "short", short_unit);
    r.line("short attempt", 1, || {
        on_piece(&p, &d, &short, attempt(short_unit, claim), room, c).line(Piece::line)
    });
    sends(&mut r, "short", short_unit, &short);
    r.line("far_end short", 2, || {
        let g = far_end(short_unit, claim, whole, &k.answer, answer);
        short_then(&p, &d, &short, g, buffer, c, Piece::line)
    });
    short.end(&d);

    // A caller body that ended empty.
    if let Some(empty) = k.empty {
        let unit = Unit::mint(&d, 1024);
        arrives(&mut r, "empty", empty);
        r.line("empty", 1, || {
            let g = Given {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                attempt_no: 0,
                ..attempt(empty, claim)
            };
            on_piece(&p, &d, &unit, g, room, c).line(Piece::line)
        });
        unit.end(&d);
    }

    sessions(&mut r, (&p, &d, driver), &k.sessions, c);

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
        // On a request ticket, its buffers lent to the op, as the kernel serves an admin route.
        let mut lend = Arc::new(ServeLend {
            reply: [0; 512],
            arena: [0; 256],
            fields: [z(); 2],
        });
        let me = Arc::get_mut(&mut lend).expect("unshared");
        let mut f: Frame<ServeIn, ServeOut> = Frame::new(input(), output());
        (f.input.reply_buf, f.input.reply_cap) = (me.reply.as_mut_ptr(), me.reply.len());
        (f.input.fields_buf, f.input.fields_cap) = (me.fields.as_mut_ptr(), me.fields.len());
        (f.input.arena_buf, f.input.arena_cap) = (me.arena.as_mut_ptr(), me.arena.len());
        let (c, f) = on_ticket_frame(
            &p,
            &d,
            slot::SERVE,
            f,
            DeadlineClass::Call,
            deadline(),
            lend as Lent,
        );
        let out = f.map_or_else(output, |f| f.out);
        format!(
            "{} status={} reply_written={}",
            called(&c),
            out.status,
            out.reply_written
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
        let (c, named) = drive(&p, driver);
        format!("{} sessions={}", called(&c), named.len())
    });
    // A plane answers under no lease: the release of none.
    r.line("release none", 1, || called(&release(&p, 0)));
    r.line("tick", 1, || match driver {
        Some(driver) => {
            let done = d.tick(&p, driver, 1_000).wait_done();
            let next = done.frame.as_ref().map_or(0, |f| f.out.next_tick_ns);
            format!("{} next={next}", called(&answered(&done)))
        }
        None => "Refused lease=false no driver ticket next=0".to_string(),
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
    if let Some(driver) = driver {
        d.recycle(driver);
    }
    let fold = r.fold();
    contract(&fold, s.kind_inputs("plane"));
    fold
}

/// The memory a `serve` lends the plane: its reply, fields and arena buffers.
struct ServeLend {
    reply: [u8; 512],
    arena: [u8; 256],
    fields: [OutField; 2],
}

// SAFETY: plain buffers the plane writes and the host reads only after the op completes.
unsafe impl Send for ServeLend {}
// SAFETY: as above.
unsafe impl Sync for ServeLend {}

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
        if let Some(flags) = route["flags"].as_array() {
            let flags: Vec<String> = flags
                .iter()
                .map(|f| str_of(f, "claimed.route.flags[]"))
                .collect();
            let want = format!(" route_flags={flags:?} ");
            assert!(
                at("arrive claimed").contains(&want),
                "a claimed request states{want}: {}",
                at("arrive claimed")
            );
        }
    }
    let status = num(&k["unclaimed"]["status"], "unclaimed.status");
    let unclaimed = at("arrive unclaimed");
    assert!(
        !unclaimed.starts_with("Ready ") && unclaimed.ends_with(&format!(" status={status}")),
        "an unclaimed request is refused at {status}: {unclaimed}"
    );
    attempts_and_bodies(fold, k);

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

/// THE ATTEMPTS AND THE CALLER'S BODIES: each ATTEMPT goes to the far end (or, for a plane that
/// writes the request on the caller's body, `plane.attempt.to_far_end: false`, is taken with nothing
/// sent); each unit that arrived (`plane.arrive_each`) arrived READY; every caller's body is
/// relayed as `request_out`.
fn attempts_and_bodies(fold: &Fold, k: &Value) {
    let at = |label: &str| answer(fold, label);
    let str_of = |v: &Value, what: &str| String::from_utf8(text(v, what)).expect("UTF-8 input");
    let far = k["attempt"]["to_far_end"].as_bool().unwrap_or(true);
    for label in ["attempt", "narrow attempt", "short attempt"] {
        assert!(
            at(label).contains(&format!(" to_far_end={far} ")),
            "{label}: {}",
            at(label)
        );
    }
    let request_out = str_of(&k["request_out"], "request_out");
    let mut bodies = vec!["body"];
    if k["arrive_each"].as_bool() == Some(true) {
        bodies.extend(["narrow body", "short body"]);
        for label in ["narrow arrive", "short arrive"] {
            assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
        }
    }
    for label in bodies {
        assert!(
            at(label).contains(&format!(" emitted={request_out} more=0 to_far_end=true ")),
            "{label}: {}",
            at(label)
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
    "ready",
    "body_has",
    "rewritten",
    "route_flags",
    "next",
    "disposition",
    "lane",
    "records",
    "turns",
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
            "lane" | "records" | "turns" => {
                let shown = match (key.as_str(), v) {
                    ("lane", _) => scalar(v),
                    (_, Value::Array(list)) if list.is_empty() => String::new(),
                    ("records", _) => {
                        let rows: Vec<String> = v
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(|r| match r.as_array().map(Vec::as_slice) {
                                Some([op, kind, k, val]) => format!(
                                    "{}:{}:{}={}",
                                    scalar(op),
                                    scalar(kind),
                                    scalar(k),
                                    scalar(val)
                                ),
                                _ => panic!(
                                    "conformance.json: step '{label}' wants records as \
                                     [\"<op>\", <kind>, \"<key>\", \"<value>\"] rows"
                                ),
                            })
                            .collect();
                        format!("{rows:?}")
                    }
                    _ => {
                        let rows: Vec<String> = pairs(v, "sessions[].steps[].want.turns")
                            .iter()
                            .map(|(role, text)| format!("{role}:{text}"))
                            .collect();
                        format!("{rows:?}")
                    }
                };
                if shown.is_empty() {
                    assert!(
                        !line.contains(&format!(" {key}=")),
                        "{label}: wants no {key}: {line}"
                    );
                } else {
                    has(&format!(" {key}={shown} "), key);
                }
            }
            "route_flags" => {
                let flags: Vec<String> = v.as_array().into_iter().flatten().map(scalar).collect();
                has(&format!(" route_flags={flags:?} "), key);
            }
            "next" => {
                let want = format!(" next={}", scalar(v));
                assert!(line.ends_with(&want), "{label}: wants{want}: {line}");
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
            "ready" => {
                let ready: Vec<u64> = v
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|s| num(s, "sessions[].steps[].want.ready[]"))
                    .collect();
                let want = format!("ready={ready:?}");
                assert!(line.ends_with(&want), "{label}: wants {want}: {line}");
            }
            _ => has(&format!(" {key}={} ", scalar(v)), key),
        }
    }
}

#[cfg(test)]
#[path = "../tests/conformance_plane_sessions_tests.rs"]
mod tests;
