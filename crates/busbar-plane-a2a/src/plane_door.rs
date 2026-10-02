// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface. [`door`] is the LINKED door; the same function is the DROPPED door once a `cdylib`
//! exports it (`busbar_contract::export_door!`), so the two cannot answer differently.
//!
//! The lifecycle is this plane's own:
//!
//! * `validate` reads the settings blob as the `agents:` section ([`door::read_settings`]) and
//!   refuses in the grammar's words;
//! * `open` judges the same section, reads the deployment's public base URL and publishes the
//!   first generation's snapshot ([`door::snapshot_spec`]); `refresh` judges the new section and
//!   publishes the next generation over the base URL `open` was given; `retire` drops a
//!   generation's snapshot. Each generation holds the section it serves beside its snapshot
//!   (`Generations<PlaneSnapshot, AgentsCfg>`), and an arrival keeps the newest one;
//! * `arrive` decides an arrival on the JSON-RPC line ([`crate::arrival::decide`]) and keeps it,
//!   with the generation it arrived under, keyed by its unit (`Keyed`); a refused arrival states
//!   its refusal in its own words, and `refusal` renders those, or the kernel's, in the line's
//!   dialect ([`crate::arrival::render`]);
//! * `on_piece` drives a unit's unary hop ([`crate::relay::Relay`]): the request each ATTEMPT
//!   sends the agent the kernel picked, the caller's body relayed verbatim, and the caller's
//!   answer from the far end's, written into the host's buffers across `more` re-calls;
//! * `on_piece` answers the verbs the plane answers itself over the task store's host records
//!   ([`crate::task_door`]);
//! * `tick` wants no tick, `drive` has no session with unsolicited output, `cancel` finds nothing
//!   in flight, and `release`/`close` hold nothing the SDK does not already drop.

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn,
    PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    ServeIn, ServeOut, UnitCount, CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_ARRIVE,
    UNITS_REPORTED,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{Generations, Keyed};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot, Services};

use std::sync::Arc;

use crate::a2a::config::AgentsCfg;
use crate::arrival::{self, Decision, Dialect};
use crate::door::{self, Line};
use crate::relay::{self, Answer, Relay};

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// THE STATEMENT: the plane's name and version, the settings section it declares
/// ([`door::SECTIONS`]), its one outbound need ([`door::NEEDS`]) and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = Statement {
    kind_tail: (door::TAIL as *const busbar_contract::abi::plane::PlaneTail).cast::<KindTailHead>(),
    sections: door::SECTIONS.as_ptr(),
    sections_len: door::SECTIONS.len(),
    needs: door::NEEDS.as_ptr(),
    needs_len: door::NEEDS.len(),
    ..statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
};

/// The most units the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// One unit the instance keeps, from its arrival: what the arrival was, the agent the caller
/// addressed by name (if it did), the section of the generation it arrived under, and what its
/// pieces carry from one to the next ([`crate::task_door::Pass`]).
#[derive(Debug)]
pub struct Unit {
    /// The arrival, decided.
    pub decision: Decision,
    /// The agent a `/a2a/agents/{agent_id}` target names.
    pub agent: Option<String>,
    /// The section of the newest generation when it arrived.
    pub section: Option<Arc<AgentsCfg>>,
    /// The unit's unary hop and what it still owes the host; `None` for a unit `on_piece` does not
    /// serve yet.
    pub hop: Option<Hop>,
    /// The host services its pieces have made so far, and the piece in flight.
    pub pass: crate::task_door::Pass,
    /// The JSON-RPC envelope an HTTP+JSON arrival's request spells ([`crate::rest::compose`]):
    /// what its unit answers and relays in place of the caller's body, its answers re-framed for
    /// the line ([`crate::rest::reframe`]). `None` on the JSON-RPC line.
    pub envelope: Option<Vec<u8>>,
}

/// One unit's unary hop, and the answer it is part way through writing.
#[derive(Debug)]
pub struct Hop {
    relay: Relay,
    outbox: Outbox,
}

impl Hop {
    /// A hop answering the request `id`, declaring `version`.
    #[must_use]
    pub fn new(id: serde_json::Value, version: &'static str) -> Self {
        Hop {
            relay: Relay::new(id, version),
            outbox: Outbox::default(),
        }
    }
}

/// What a piece's answer still owes the host: its head, once, then its bytes, `reply_cap` at a
/// time. `live` while any of it is unwritten; `recall` after a short answer, whose re-call carries
/// the same piece and must not apply it twice.
#[derive(Debug, Default)]
struct Outbox {
    live: bool,
    recall: bool,
    to_far: bool,
    done: bool,
    head: Option<Head>,
    bytes: Vec<u8>,
    at: usize,
}

/// The head an answer starts with.
#[derive(Debug)]
enum Head {
    /// The request bound for the far end: verb, target, fields.
    Attempt(relay::Attempt),
    /// The caller's reply: its status and media type.
    Reply(u32, &'static str),
}

impl Outbox {
    /// The outbox for `answer`; `None` for a piece the hop refuses.
    fn of(answer: Answer) -> Option<Self> {
        let (to_far, done, head, bytes) = match answer {
            Answer::Nothing => (false, false, None, Vec::new()),
            Answer::Refused => return None,
            Answer::Attempt(a) => (true, false, Some(Head::Attempt(a)), Vec::new()),
            Answer::ToFarEnd(bytes) => (true, false, None, bytes),
            Answer::ToCaller(r) => (
                false,
                true,
                Some(Head::Reply(r.status, r.content_type)),
                r.body,
            ),
        };
        Some(Outbox {
            live: true,
            recall: false,
            to_far,
            done,
            head,
            bytes,
            at: 0,
        })
    }
}

/// One instance: the public base URL `open` was given, the host tables, every live generation's
/// snapshot and section, the units in flight, and the second the task store was last swept.
pub struct A2aDoor {
    public_url: Option<String>,
    pub(crate) host: Option<Host>,
    pub(crate) services: Option<Services>,
    generations: Generations<PlaneSnapshot, AgentsCfg>,
    pub(crate) units: Keyed<u64, Unit>,
    pub(crate) swept: Keyed<(), u64>,
}

/// The settings blob read as the `agents:` section, or the refusal in the grammar's words.
fn section(bytes: &[u8]) -> Result<AgentsCfg, Refusal> {
    door::read_settings(bytes).map_err(Refusal::refused)
}

/// Keep `value` under `key` in `map`, dropping the smallest (oldest) keys first past `cap`.
fn keep<V>(map: &Keyed<u64, V>, cap: usize, key: u64, value: V) {
    map.with_all(|m| {
        while m.len() >= cap && !m.contains_key(&key) {
            if m.pop_first().is_none() {
                break;
            }
        }
        m.insert(key, value);
    });
}

/// The agent a JSON-RPC target names below the catalogue, if it names one.
fn agent_of(target: &str) -> Option<String> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        ["a2a", "agents", id] => Some((*id).to_string()),
        _ => None,
    }
}

/// The public base URL the host lent, when it states one.
fn public_url(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// [`ArriveOut::refusal`]: the arrival is refused in the plane's own words, at its own status
/// (the words ride in the head's error, and `refusal` renders them).
pub const REFUSED_IN_OWN_WORDS: u32 = 1;

/// [`ArriveOut::refusal`]: no line of this door serves the arrival yet (a 404).
pub const UNSERVED: u32 = 2;

/// The status of an arrival no line of this door serves yet.
const STATUS_NOT_FOUND: u32 = 404;

/// REFUSED in the plane's own words, at its own status: `refusal` renders them in the line's
/// dialect.
fn refused(out: &mut Out<'_, ArriveOut>, refusal: &arrival::Refusal) -> Outcome {
    out.set(|o| &o.refusal, REFUSED_IN_OWN_WORDS);
    out.set(|o| &o.refusal_status, refusal.status);
    out.fail(Refusal::refused(refusal.words()))
}

/// REFUSED: no line of this door serves the arrival yet. TRANSITIONAL: the gRPC and open lines
/// are filled when the kernel's plane driver serves the door's request path.
fn unserved(out: &mut Out<'_, ArriveOut>) -> Outcome {
    out.set(|o| &o.refusal, UNSERVED);
    out.set(|o| &o.refusal_status, STATUS_NOT_FOUND);
    out.fail(Refusal::bare())
}

/// One slot body on the SDK's safe surface, over this plane's [`A2aDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = A2aDoor;
            fn call($inst: Instance<'_, A2aDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match section(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(refusal) => out.fail(refusal),
        }
    }
);

slot!(
    /// `open`: the instance over the section and the public base URL, and the first generation's
    /// snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let cfg = match section(input.field(|i| &i.open.settings).bytes()) {
            Ok(cfg) => cfg,
            Err(refusal) => return out.fail(refusal),
        };
        let generation = input.get().open.generation;
        let plane = A2aDoor {
            public_url: public_url(input.field(|i| &i.public_url).bytes()),
            host: input.field(|i| &i.open).host().map(|h| Host::of(h.get())),
            services: input
                .field(|i| &i.open)
                .host()
                .and_then(|h| Services::of(h.get())),
            generations: Generations::new(),
            units: Keyed::new(),
            swept: Keyed::new(),
        };
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, cfg);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot over the same public base
    /// URL.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let cfg = match section(input.field(|i| &i.settings).bytes()) {
            Ok(cfg) => cfg,
            Err(refusal) => return out.fail(refusal),
        };
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        let generation = input.get().generation;
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, cfg);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.get().generation);
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: none wanted.
    Tick, TickIn, TickOut, |_, _, mut out| {
        out.set(|o| &o.next_tick_ns, 0);
        Outcome::Ready
    }
);

slot!(
    /// `drive`: no session has unsolicited output.
    Drive, PlaneDriveIn, PlaneDriveOut, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `cancel`: nothing is in flight, so nothing moved.
    Cancel, CancelIn, CancelOut, |_, _, mut out| {
        out.set(|o| &o.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
);

slot!(
    /// `release`: this plane answers under no lease.
    Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `close`: the SDK drops the instance and every snapshot it still holds.
    Close, InHead, OutHead, |_, _, _| { Outcome::Ready }
);

// ── the request path ──────────────────────────────────────────────────────────────────────────
//
// Nothing routes to these before the flip: the engine still serves every request, and no
// production path loads this door (`tests/door_unrouted.rs` holds that). `arrive`, `on_piece` and
// `refusal` serve the JSON-RPC and HTTP+JSON lines; every other op is REFUSED.

slot!(
    /// `arrive`: an arrival on the JSON-RPC line, or on the HTTP+JSON line as the envelope its
    /// request spells ([`crate::rest::compose`]), decided and kept with the generation it arrived
    /// under, keyed by its unit; a refused one refused in its own words. A message whose method the
    /// vocabulary does not list is classed as the hop the engine relays it on, never refused.
    /// TRANSITIONAL: an arrival on the gRPC line or an open line is filled when the kernel's plane
    /// driver serves the door's request path.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let Some(route) = door::ROUTES.get(given.claim as usize) else {
            return unserved(&mut out);
        };
        let target = input.field(|i| &i.target).as_str().unwrap_or_default();
        let body = input.field(|i| &i.body).bytes();
        let (dialect, envelope) = match door::line_of(route) {
            Line::Document => (door::DIALECT_DOCUMENT, None),
            Line::Target => match crate::rest::compose(route, target, body) {
                Ok(Some(envelope)) => (door::DIALECT_TARGET, Some(envelope)),
                Ok(None) => return unserved(&mut out),
                Err(refusal) => return refused(&mut out, &refusal),
            },
            Line::Framed | Line::Open => return unserved(&mut out),
        };
        let fields = input.fields();
        let decision = arrival::decide(envelope.as_deref().unwrap_or(body), |name| {
            fields
                .iter()
                .find(|f| {
                    f.field(|f| &f.name)
                        .as_str()
                        .is_ok_and(|n| n.eq_ignore_ascii_case(name))
                })
                .and_then(|f| f.field(|f| &f.value).as_str().ok())
        });
        if let Decision::Refused(refusal) = &decision {
            return refused(&mut out, refusal);
        }
        let Some(op) = decision.op_class().and_then(door::op_class_index) else {
            return unserved(&mut out);
        };
        out.set(|o| &o.op_class, op);
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, dialect);
        let agent = agent_of(target);
        let hop = hop_of(&decision, agent.is_some());
        let unit = Unit {
            decision,
            agent,
            section: plane.generations.current(),
            hop,
            pass: crate::task_door::Pass::default(),
            envelope,
        };
        keep(&plane.units, MAX_UNITS, given.unit, unit);
        Outcome::Ready
    }
);

/// The hop a unit's `on_piece` serves: the extended-card read addressed to one agent, which the
/// engine relays task-less (`receive::unary_hop`, its `card_fetch` arm). A task-bearing verb has
/// no hop here: its reply carries busbar's task identity and its rows, which the plane does not
/// keep yet, so its pieces are REFUSED.
fn hop_of(decision: &Decision, addressed: bool) -> Option<Hop> {
    match decision {
        Decision::Request { row, id, version }
            if addressed && row.op == crate::ops::OP_AGENT_CARD =>
        {
            Some(Hop::new(id.clone(), version))
        }
        _ => None,
    }
}

/// The URL the operator wrote for agent `member` in the section the unit arrived under.
fn url_of<'a>(unit: &'a Unit, member: &str) -> Option<&'a str> {
    unit.section
        .as_ref()?
        .agents
        .get(member)
        .map(|a| a.url.as_str())
}

/// One piece of `unit`'s hop: applied (unless it continues or re-calls the answer still owed) and
/// written into the host's buffers. Answers the outcome and whether the unit is done.
fn piece(
    unit: &mut Unit,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    let given = input.get();
    let bytes = input.field(|i| &i.bytes).bytes();
    let member = input.field(|i| &i.member).as_str().unwrap_or_default();
    let url = url_of(unit, member).map(str::to_string);
    let Some(hop) = unit.hop.as_mut() else {
        return (Outcome::Refused, false);
    };
    // A re-call carries the same piece again (after a short answer) or nothing at all (after
    // `more = 1`: no bytes, no flags, no attempt); either way it is served from what is owed.
    let continues = hop.outbox.live
        && (hop.outbox.recall || (bytes.is_empty() && given.flags == 0 && given.attempt_no == 0));
    if !continues {
        let from = match given.from {
            FROM_KERNEL => relay::From::Kernel(url.as_deref()),
            FROM_CALLER => relay::From::Caller,
            FROM_FAR_END => relay::From::FarEnd,
            _ => return (Outcome::Refused, false),
        };
        let answer = hop.relay.on_piece(relay::Piece {
            from,
            bytes,
            status: (given.flags & PIECE_HAS_STATUS != 0).then_some(given.status_code),
            last: given.flags & PIECE_LAST != 0,
        });
        let Some(outbox) = Outbox::of(answer) else {
            return (Outcome::Refused, false);
        };
        hop.outbox = outbox;
    }
    let ob = &mut hop.outbox;
    let (mut reply, mut fields, mut arena, mut units) = (
        input.reply_buf(),
        input.fields_buf(),
        input.arena_buf(),
        input.units_buf(),
    );
    let moved = hop.relay.moved();
    if moved != 0 {
        units.push(UnitCount {
            class: 0,
            source: UNITS_REPORTED,
            amount: moved,
        });
    }
    let mut head_fields = |list: &[(&'static str, String)]| {
        for (name, value) in list {
            fields.push(OutField {
                name: arena.span(name.as_bytes()),
                value: arena.span(value.as_bytes()),
            });
        }
    };
    let (mut verb, mut target, mut status) = (None, None, 0);
    match &ob.head {
        Some(Head::Attempt(a)) => {
            head_fields(&a.fields);
            verb = Some(arena.span(a.verb.as_bytes()));
            target = Some(arena.span(a.target.as_bytes()));
        }
        Some(Head::Reply(s, content_type)) => {
            head_fields(&[(relay::H_CONTENT_TYPE, (*content_type).to_string())]);
            status = *s;
        }
        None => {}
    }
    let short = !(fields.fits() && arena.fits() && units.fits());
    let (fw, fnd) = fields.settle(short);
    let (aw, and) = arena.settle(short);
    let (uw, und) = units.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    if short {
        ob.recall = true;
        return (Outcome::Failed, false);
    }
    let n = reply.stream(&ob.bytes[ob.at..]);
    ob.at += n;
    ob.head = None;
    ob.recall = false;
    let more = ob.at < ob.bytes.len();
    ob.live = more;
    let mut flags = 0;
    if ob.to_far {
        flags |= EMIT_TO_FAR_END;
    }
    let done = ob.done && !more;
    if done {
        flags |= EMIT_DONE;
    }
    if let (Some(v), Some(t)) = (verb, target) {
        out.set(|o| &o.verb, v);
        out.set(|o| &o.target, t);
    }
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.more, u32::from(more));
    out.set(|o| &o.flags, flags);
    out.set(|o| &o.reply_status, status);
    (Outcome::Ready, done)
}

slot!(
    /// `on_piece`: the unit's unary hop, one piece at a time ([`crate::relay`]); otherwise a verb
    /// the plane answers itself, over the task store ([`crate::task_door`]); a unit that is
    /// neither is REFUSED. A finished hop's unit is forgotten.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let unit = input.get().unit;
        let relayed = plane.units.with(&unit, |u| u.is_some_and(|u| u.hop.is_some()));
        if !relayed {
            return crate::task_door::on_piece(plane, &instance, input, out)
                .unwrap_or(Outcome::Refused);
        }
        let (outcome, done) = plane.units.with(&unit, |u| match u {
            Some(u) => piece(u, input, &mut out),
            None => (Outcome::Refused, false),
        });
        if done {
            plane.units.remove(&unit);
        }
        outcome
    }
);

slot!(
    /// `refusal`: a refused arrival rendered in its own words and status, and a kernel or gate
    /// refusal in the engine's admission words at the kernel's status, each in the line's dialect;
    /// on the gRPC line, the envelope at its neutral status, for the grpc transport to map. The
    /// gate-rejected marker is the kernel's: this rendering never sets it.
    RefusalSlot, RefusalIn, RefusalOut, |_, input, mut out| {
        let given = input.get();
        let dialect = match given.dialect {
            door::DIALECT_DOCUMENT => Dialect::JsonRpc,
            door::DIALECT_TARGET => Dialect::RestJson,
            door::DIALECT_FRAMED => Dialect::Framed,
            _ => return Outcome::Refused,
        };
        let text = input.field(|i| &i.text).bytes();
        let rendered = if given.cause == REFUSAL_ARRIVE {
            let Some(refusal) = arrival::Refusal::from_words(text) else {
                return Outcome::Refused;
            };
            arrival::render(dialect, &refusal, true)
        } else {
            let text = std::str::from_utf8(text).unwrap_or_default();
            arrival::render(dialect, &arrival::kernel_refusal(given.status, text), false)
        };
        let (mut reply, mut fields, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&rendered.body);
        fields.push(OutField {
            name: arena.span(b"content-type"),
            value: arena.span(rendered.content_type.as_bytes()),
        });
        let short = !(reply.fits() && fields.fits() && arena.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = fields.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            return Outcome::Failed;
        }
        out.set(|o| &o.status, rendered.status);
        Outcome::Ready
    }
);

slot!(
    /// `serve`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Serve, ServeIn, ServeOut, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `hydrate`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `start`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Start, GenIn, OutHead, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `project`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Project, ProjectIn, ProjectOut, |_, _, _| { Outcome::Refused }
);

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}
