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
    ServeIn, ServeOut, CANCEL_ABORTED, PRINCIPAL_REQUIRED, REFUSAL_ARRIVE,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{Generations, Keyed};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

use std::sync::Arc;

use crate::a2a::config::AgentsCfg;
use crate::arrival::{self, Decision, Dialect};
use crate::door::{self, Line};

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// THE STATEMENT: the plane's name and version, the settings section it declares
/// ([`door::SECTIONS`]), and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = Statement {
    kind_tail: (door::TAIL as *const busbar_contract::abi::plane::PlaneTail).cast::<KindTailHead>(),
    sections: door::SECTIONS.as_ptr(),
    sections_len: door::SECTIONS.len(),
    ..statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
};

/// The most units the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// One unit the instance keeps, from its arrival: what the arrival was, the agent the caller
/// addressed by name (if it did), and the section of the generation it arrived under.
#[derive(Debug)]
pub struct Unit {
    /// The arrival, decided.
    pub decision: Decision,
    /// The agent a `/a2a/agents/{agent_id}` target names.
    pub agent: Option<String>,
    /// The section of the newest generation when it arrived.
    pub section: Option<Arc<AgentsCfg>>,
}

/// One instance: the public base URL `open` was given, every live generation's snapshot and
/// section, and the units in flight.
pub struct A2aDoor {
    public_url: Option<String>,
    generations: Generations<PlaneSnapshot, AgentsCfg>,
    units: Keyed<u64, Unit>,
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
            generations: Generations::new(),
            units: Keyed::new(),
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
// production path loads this door (`tests/door_unrouted.rs` holds that). `arrive` and `refusal`
// serve the JSON-RPC line; every other op is REFUSED.

slot!(
    /// `arrive`: an arrival on the JSON-RPC line decided and kept, with the generation it arrived
    /// under, keyed by its unit; a refused one refused in its own words. A message whose method the
    /// vocabulary does not list is classed as the hop the engine relays it on, never refused.
    /// TRANSITIONAL: an arrival on any other line is filled when the kernel's plane driver serves
    /// the door's request path.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let line = door::ROUTES.get(given.claim as usize).map(door::line_of);
        if line != Some(Line::Document) {
            return out.fail(Refusal::bare());
        }
        let body = input.field(|i| &i.body).bytes();
        let fields = input.fields();
        let decision = arrival::decide(body, |name| {
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
            return out.fail(Refusal::refused(refusal.words()));
        }
        let Some(op) = decision.op_class().and_then(door::op_class_index) else {
            return out.fail(Refusal::bare());
        };
        out.set(|o| &o.op_class, op);
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, door::DIALECT_DOCUMENT);
        let target = input.field(|i| &i.target).as_str().unwrap_or_default();
        let unit = Unit {
            decision,
            agent: agent_of(target),
            section: plane.generations.current(),
        };
        keep(&plane.units, MAX_UNITS, given.unit, unit);
        Outcome::Ready
    }
);

slot!(
    /// `on_piece`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    OnPiece, OnPieceIn, OnPieceOut, |_, _, _| { Outcome::Refused }
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
