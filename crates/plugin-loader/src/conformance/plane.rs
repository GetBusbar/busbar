// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S SCRIPT. Every plane op of `abi/plane/` through the one dispatcher, in the order
//! the kernel drives a unit: `validate`, `open` (the kernel's `Plugin<Plane>::open`, the first
//! generation's snapshot copied at the crossing), `ready`, `hydrate`, `start`, `arrive` (claimed,
//! unclaimed), the unit's pieces (the ATTEMPT, the caller's body, the far end's answer: whole,
//! through a narrow reply buffer with its `more` re-calls, and once SHORT with its one re-call),
//! an empty caller body, `refusal`, `serve`, `project`, `drive`, `release`, `tick`, `cancel`,
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
//!     "open_claims":    [["<verb>", "<target>"], ...],   // generation 1's snapshot claims
//!     "refresh_claims": [["<verb>", "<target>"], ...],   // generation 2's
//!     "member": "<the pool member an ATTEMPT names>",
//!     "claimed":   { "unit": 7, "method": "POST", "target": "/v1/x" },  // arrive: READY
//!     "unclaimed": { "unit": 8, "method": "GET", "target": "/v1/y", "status": 404 },  // refused
//!     "request":     "<the caller's body>",
//!     "request_out": "<what the plane sends the far end for it>",
//!     "far_end": { "status": 200, "fields": [["<name>", "<value>"], ...],
//!                  "answer": "<the far end's whole answer>",
//!                  "answer_out": "<what the plane relays to the caller>",
//!                  "units": [[<billable class>, <amount>], ...] },   // reported at the last piece
//!     "narrow": { "unit": 9, "reply_cap": 16, "more": 3 },  // the answer `reply_cap` bytes at a time
//!     "short":  { "unit": 11 },              // the answer over a units buffer of capacity 0
//!     "empty":  { "unit": 10, "outcome": "Refused" },        // optional: a caller body that ended empty
//!     "refusal": { "status": 403, "text": "denied", "reply": "<the dialect's error body>" } } }
//! ```
//!
//! THE PINS. Every step is ONE ticket-less crossing (`Plugin::call`), but:
//! * `ready` ([`super::ready_step`]): 0 when the door states none;
//! * `arrive unopened` and `open again`: 0, the host answers REFUSED without a crossing (no
//!   instance yet; one `open` per instance);
//! * `far_end short`: 2, the short answer and its ONE re-call (`Plugin::recall`, the short-buffer
//!   rule on `OutHead`);
//! * `arrive after close`: 0, a closed instance answers FAULT without a crossing.
//!
//! The narrow answer's `more` re-calls are each their own step of one crossing, as many as the
//! inputs pin (`narrow.more`), so a plane that writes fewer bytes per piece than the buffer holds
//! crosses more often than pinned and is refused.

use busbar_contract::abi::hook::SignalEntry;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, OutHead, Span, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, GenIn, RefreshIn};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_GATE,
    UNITS_REPORTED,
};
use serde_json::Value;

use super::{
    called, close, crossings, dispatcher, input, json, load, output, ready_step, release, tick,
    validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::plane::{OwnedSnapshot, Plane};
use crate::dispatch::{Called, Frame, Plugin};

fn text(v: &Value, what: &str) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Null => panic!("conformance.json: plane.{what} is missing"),
        other => other.to_string().into_bytes(),
    }
}

fn num(v: &Value, what: &str) -> u64 {
    v.as_u64()
        .unwrap_or_else(|| panic!("conformance.json: plane.{what} must be a number"))
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

/// A host buffer element, zeroed.
fn z<T: Copy>() -> T {
    // SAFETY: called only for the plane ABI's plain C structs (`UnitCount`, `RecordWrite`,
    // `OutField`, `SignalEntry`): integers, spans and unions of integers, for which all-zero is valid.
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

fn at(buf: &[u8], s: Span) -> String {
    let (from, len) = (s.offset as usize, s.len as usize);
    buf.get(from..from + len).map_or_else(
        || "<OUTSIDE>".into(),
        |b| String::from_utf8_lossy(b).into_owned(),
    )
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
    units: [UnitCount; 2],
    records: [RecordWrite; 2],
    fields: [OutField; 2],
    arena: [u8; 256],
}

/// One piece handed to the plane.
#[derive(Clone, Copy)]
struct Given<'a> {
    unit: u64,
    from: u32,
    flags: u32,
    bytes: &'a [u8],
    attempt_no: u32,
}

impl Piece {
    fn new(reply_cap: usize) -> Box<Self> {
        Box::new(Self {
            reply: vec![0; reply_cap],
            units: [z(); 2],
            records: [z(); 2],
            fields: [z(); 2],
            arena: [0; 256],
        })
    }

    fn frame(
        &mut self,
        g: Given<'_>,
        units_cap: usize,
        member: &[u8],
        head: &[Field],
        status: u32,
    ) -> Frame<OnPieceIn, OnPieceOut> {
        let mut i: OnPieceIn = input();
        (i.unit, i.from, i.flags, i.bytes) = (g.unit, g.from, g.flags, octets(g.bytes));
        (i.attempt_no, i.member) = (g.attempt_no, abi(member));
        if g.flags & PIECE_HAS_STATUS != 0 {
            i.status_code = status;
            (i.head_fields, i.head_fields_len) = (head.as_ptr(), head.len());
        }
        (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
        (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), units_cap);
        (i.records_buf, i.records_cap) = (self.records.as_mut_ptr(), self.records.len());
        (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
        (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
        Frame::new(i, output())
    }

    /// What the plane answered and wrote, as one line.
    fn line(&self, c: &Called, o: &OnPieceOut) -> String {
        let fields: Vec<String> = self.fields[..(o.fields_written as usize).min(2)]
            .iter()
            .map(|f| format!("{}={}", at(&self.arena, f.name), at(&self.arena, f.value)))
            .collect();
        let units: Vec<String> = self.units[..(o.units_written as usize).min(2)]
            .iter()
            .map(|u| format!("{}:{}:{}", u.class, u.amount, u.source == UNITS_REPORTED))
            .collect();
        format!(
            "{} emitted={} more={} to_far_end={} done={} status={} verb={} target={} \
             fields={fields:?} units={units:?}",
            called(c),
            String::from_utf8_lossy(&self.reply[..(o.emitted as usize).min(self.reply.len())]),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
        )
    }
}

/// The script's fixtures, read once from `inputs.plane`.
struct Inputs {
    bad: Vec<Vec<u8>>,
    refresh: Vec<u8>,
    member: Vec<u8>,
    claimed: (u64, Vec<u8>, Vec<u8>),
    unclaimed: (u64, Vec<u8>, Vec<u8>),
    request: Vec<u8>,
    status: u32,
    head: Vec<(String, String)>,
    answer: Vec<u8>,
    narrow: (u64, usize, u64),
    short: u64,
    empty: Option<u64>,
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
        let arrival = |what: &str| {
            let a = &k[what];
            (
                num(&a["unit"], what),
                text(&a["method"], what),
                text(&a["target"], what),
            )
        };
        let f = &k["far_end"];
        Self {
            bad,
            refresh: text(&k["refresh_settings"], "refresh_settings"),
            member: text(&k["member"], "member"),
            claimed: arrival("claimed"),
            unclaimed: arrival("unclaimed"),
            request: text(&k["request"], "request"),
            status: num(&f["status"], "far_end.status") as u32,
            head: pairs(&f["fields"], "far_end.fields"),
            answer: text(&f["answer"], "far_end.answer"),
            narrow: (
                num(&k["narrow"]["unit"], "narrow.unit"),
                num(&k["narrow"]["reply_cap"], "narrow.reply_cap") as usize,
                num(&k["narrow"]["more"], "narrow.more"),
            ),
            short: num(&k["short"]["unit"], "short.unit"),
            empty: k["empty"]
                .is_object()
                .then(|| num(&k["empty"]["unit"], "empty.unit")),
            refusal: (
                num(&k["refusal"]["status"], "refusal.status") as u32,
                text(&k["refusal"]["text"], "refusal.text"),
            ),
        }
    }
}

fn arrive(
    p: &Plugin<Plane>,
    (unit, method, target): &(u64, Vec<u8>, Vec<u8>),
    body: &[u8],
) -> String {
    let mut units = [z::<UnitCount>(); 4];
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(input(), output());
    (a.input.unit, a.input.method, a.input.target) = (*unit, abi(method), abi(target));
    a.input.body = octets(body);
    (a.input.units_buf, a.input.units_cap) = (units.as_mut_ptr(), units.len());
    let c = p.call(slot::ARRIVE, &mut a);
    format!(
        "{} op_class={} principal_required={} dialect={} units={} refusal={} status={}",
        called(&c),
        a.out.op_class,
        a.out.principal_need == PRINCIPAL_REQUIRED,
        a.out.dialect,
        a.out.units_written,
        a.out.refusal,
        a.out.refusal_status
    )
}

/// The ATTEMPT piece of `unit`: from the kernel, no bytes, attempt 1.
fn attempt(unit: u64) -> Given<'static> {
    Given {
        unit,
        from: FROM_KERNEL,
        flags: 0,
        bytes: b"",
        attempt_no: 1,
    }
}

/// A piece of the far end's answer to `unit`.
fn far_end(unit: u64, flags: u32, bytes: &[u8]) -> Given<'_> {
    Given {
        unit,
        from: FROM_FAR_END,
        flags,
        bytes,
        attempt_no: 0,
    }
}

fn generation(p: &Plugin<Plane>, s: u32, generation: u64) -> String {
    let mut g: Frame<GenIn, OutHead> = Frame::new(input(), output());
    g.input.generation = generation;
    called(&p.call(s, &mut g))
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = Inputs::of(s.kind_inputs("plane"));
    let settings = leg.settings(s);
    let head: Vec<Field> = k
        .head
        .iter()
        .map(|(n, v)| Field {
            name: abi(n.as_bytes()),
            value: abi(v.as_bytes()),
        })
        .collect();

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
    let open = |what: &[u8]| {
        let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
        (f.input.open.generation, f.input.open.settings) = (1, json(what));
        let (c, snap) = p.open(&mut f);
        format!("{} {}", called(&c), snapshot(snap.as_ref()))
    };
    r.line("open", 1, || open(&settings));
    ready_step(&mut r, s, &p, &d);
    // One open per instance: the host refuses without a crossing.
    r.line("open again", 0, || open(&settings));
    r.line("hydrate", 1, || generation(&p, slot::HYDRATE, 1));
    r.line("start", 1, || generation(&p, slot::START, 1));
    r.line("arrive claimed", 1, || arrive(&p, &k.claimed, &k.request));
    r.line("arrive unclaimed", 1, || {
        arrive(&p, &k.unclaimed, &k.request)
    });

    let unit = k.claimed.0;
    let whole = PIECE_HAS_STATUS | PIECE_LAST;
    let piece_on = |piece: &mut Piece, g: Given<'_>, units_cap: usize| {
        let mut f = piece.frame(g, units_cap, &k.member, &head, k.status);
        let c = p.call(slot::ON_PIECE, &mut f);
        (c, f)
    };
    // One unit: the ATTEMPT, the caller's body, the far end's whole answer.
    let mut piece = Piece::new(1024);
    for (label, g) in [
        ("attempt", attempt(unit)),
        (
            "body",
            Given {
                unit,
                from: FROM_CALLER,
                flags: PIECE_LAST,
                bytes: &k.request,
                attempt_no: 0,
            },
        ),
        ("far_end", far_end(unit, whole, &k.answer)),
    ] {
        r.line(label, 1, || {
            let (c, f) = piece_on(&mut piece, g, 2);
            piece.line(&c, &f.out)
        });
    }

    // Another, whose answer is written `reply_cap` bytes at a time, then paid out by `more`.
    let (narrow_unit, cap, more) = k.narrow;
    let mut narrow = Piece::new(cap);
    r.line("narrow attempt", 1, || {
        let (c, f) = piece_on(&mut narrow, attempt(narrow_unit), 2);
        narrow.line(&c, &f.out)
    });
    r.line("narrow far_end", 1, || {
        let (c, f) = piece_on(&mut narrow, far_end(narrow_unit, whole, &k.answer), 2);
        narrow.line(&c, &f.out)
    });
    for i in 0..more {
        r.line(&format!("narrow more #{i}"), 1, || {
            let (c, f) = piece_on(&mut narrow, far_end(narrow_unit, 0, b""), 2);
            narrow.line(&c, &f.out)
        });
    }

    // Another, whose answer meets a units buffer of capacity 0: SHORT, then its one re-call.
    let mut short = Piece::new(1024);
    r.line("short attempt", 1, || {
        let (c, f) = piece_on(&mut short, attempt(k.short), 2);
        short.line(&c, &f.out)
    });
    r.line("far_end short", 2, || {
        let (c, mut f) = piece_on(&mut short, far_end(k.short, whole, &k.answer), 0);
        let first = format!(
            "{} units_needed={} recall={}",
            called(&c),
            f.out.units_needed,
            c.recall.is_some()
        );
        let Some(token) = c.recall else {
            return format!("{first} then=no-recall");
        };
        f.input.units_cap = short.units.len();
        let again = p.recall(token, slot::ON_PIECE, &mut f);
        format!("{first} then={}", short.line(&again, &f.out))
    });

    // A caller body that ended empty.
    if let Some(empty) = k.empty {
        r.line("empty", 1, || {
            let g = Given {
                unit: empty,
                from: FROM_CALLER,
                flags: PIECE_LAST,
                bytes: b"",
                attempt_no: 0,
            };
            let (c, f) = piece_on(&mut piece, g, 2);
            piece.line(&c, &f.out)
        });
    }

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
        f.input.target = abi(&k.claimed.2);
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

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: no answer the
/// kind's check refused (FAULT) but after `close`; the settings judged at `validate`; one `open`
/// per instance; each generation's snapshot holds the claims the inputs state; a claimed request
/// arrives READY and an unclaimed one is refused at its status; the ATTEMPT goes to the far end;
/// the caller's body and the far end's answer are relayed as the inputs state, with the far end's
/// count REPORTED at its last piece (whole, paid out through a narrow buffer, and after a short
/// answer's re-call alike); the refusal speaks the dialect; the lifecycle answers READY.
fn contract(fold: &Fold, k: &Value) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
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
    let units: Vec<String> = pairs(&f["units"], "far_end.units")
        .iter()
        .map(|(class, amount)| format!("{class}:{amount}:true"))
        .collect();
    let units = format!("units={units:?}");
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

    // The short answer: FAILED with the units it needs and a re-call token, then the whole answer.
    let short = at("far_end short");
    assert!(
        short.starts_with("Failed ")
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
    if let Some(reply) = k["refusal"]["reply"].as_str() {
        assert!(
            at("refusal").contains(&format!(" reply={reply} ")),
            "refusal: {}",
            at("refusal")
        );
    }
}
