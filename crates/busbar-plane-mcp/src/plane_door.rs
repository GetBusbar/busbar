// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface. [`door`] is the LINKED door; the same function is the DROPPED door once a `cdylib`
//! exports it (`busbar_contract::export_door!`), so the two cannot answer differently.
//!
//! The lifecycle is this plane's own:
//!
//! * `validate` reads the settings blob as the `tools:` section ([`door::read_settings`]) and
//!   refuses in the grammar's words;
//! * `open` judges the same section, reads the deployment's public base URL and publishes the
//!   first generation's snapshot ([`door::snapshot_spec`]); `refresh` judges the new section and
//!   publishes the next generation over the base URL `open` was given; `retire` drops a
//!   generation's snapshot, and the catalogue built from its section with it. A request is
//!   answered from the newest live generation's catalogue ([`McpDoor::current`]);
//! * `tick` wants no tick, `drive` has no session with unsolicited output, `cancel` finds nothing
//!   in flight, and `release`/`close` hold nothing the SDK does not already drop.

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn,
    PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    OutField, ServeIn, ServeOut, CANCEL_ABORTED, EMIT_DONE, FROM_CALLER, PIECE_LAST,
    PRINCIPAL_REQUIRED, REFUSAL_ARRIVE,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{Generations, Keyed};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

use std::sync::Arc;

use crate::answer::{Answer, Session};
use crate::arrival::Decision;
use crate::catalogue::Catalogue;
use crate::door;

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// THE STATEMENT: the plane's name and version, and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = Statement {
    kind_tail: (door::TAIL as *const busbar_contract::abi::plane::PlaneTail).cast::<KindTailHead>(),
    ..statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
};

/// One instance: the public base URL `open` was given, and every live generation's snapshot with
/// the catalogue built from that generation's section.
pub struct McpDoor {
    public_url: Option<String>,
    generations: Generations<PlaneSnapshot, Catalogue>,
    units: Keyed<u64, Unit>,
    sessions: Keyed<u64, Session>,
}

impl McpDoor {
    /// The catalogue a request arriving now is answered from: the newest live generation's.
    #[must_use]
    pub fn current(&self) -> Option<Arc<Catalogue>> {
        self.generations.current()
    }
}

/// The settings blob read as the `tools:` section, or the refusal in the grammar's words.
fn section(bytes: &[u8]) -> Result<crate::config::ToolsCfg, Refusal> {
    door::read_settings(bytes).map_err(Refusal::refused)
}

/// The public base URL the host lent, when it states one.
fn public_url(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// One slot body on the SDK's safe surface, over this plane's [`McpDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = McpDoor;
            fn call($inst: Instance<'_, McpDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
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
        let plane = McpDoor {
            public_url: public_url(input.field(|i| &i.public_url).bytes()),
            generations: Generations::new(),
            units: Keyed::new(),
            sessions: Keyed::new(),
        };
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        let catalogue = Catalogue::build(generation, &cfg);
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, catalogue);
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
        let generation = input.get().generation;
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        let catalogue = Catalogue::build(generation, &cfg);
        out.publish_with(|o| &o.snapshot, &plane.generations, generation, &spec, catalogue);
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
    /// `cancel`: the cancelled unit's state is dropped; nothing it holds had moved.
    Cancel, CancelIn, CancelOut, |instance, input, mut out| {
        if let Some(plane) = instance.get() {
            let ticket = input.get().ticket;
            plane.units.with_all(|m| m.retain(|_, u| u.ticket != Some(ticket)));
        }
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
// `arrive` decides what the arrival is ([`crate::arrival::decide`]) and keeps it, with the
// generation it arrived under, keyed by the unit. `on_piece` answers the caller's body from what
// the plane holds ([`crate::answer::answer`]) and ends the unit, streaming what does not fit. A
// refused arrival states its refusal in its own words, which `refusal` renders with its own status.

/// The most units the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// The most sessions the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_SESSIONS: usize = 1024;

/// One unit's state, from its arrival to its end.
struct Unit {
    /// The generation it arrived under.
    catalogue: Option<Arc<Catalogue>>,
    /// What the arrival is.
    decision: Decision,
    /// The request's `params`.
    params: Option<serde_json::Value>,
    /// Its answer while it is still being written: the status, the bytes, and how many went.
    pending: Option<(u32, Vec<u8>, usize)>,
    /// The ticket its pieces cross on, once one has.
    ticket: Option<Ticket>,
}

/// Keep `value` under `key` in `map`, dropping the smallest keys first past `cap`.
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

/// The operation class a decision is counted under: its row's, or the plane's own two.
fn op_class(decision: &Decision) -> u32 {
    match decision {
        Decision::Request { row, .. } => door::op_class_index(row.op),
        Decision::Notice { .. } => door::op_class_index(crate::ops::OP_NOTIFICATION),
        Decision::Session { .. } | Decision::Refused(_) => door::OP_CLASS_SESSION,
    }
}

/// A refusal as the text a refused arrival carries: the plane's own words, read back by
/// [`RefusalSlot`].
fn refusal_text(refusal: &crate::arrival::Refusal) -> String {
    serde_json::json!({
        "status": refusal.status,
        "id": refusal.id,
        "code": refusal.code,
        "message": refusal.message,
        "data": refusal.data,
    })
    .to_string()
}

/// The words of an arrival on a verb the endpoint does not serve.
const NOT_ALLOWED_TEXT: &str = r#"{"allow":"POST"}"#;

/// What a refused arrival said.
enum Words {
    /// A JSON-RPC refusal.
    Rpc(crate::arrival::Refusal),
    /// A verb the endpoint does not serve.
    NotAllowed,
}

/// A refused arrival's words read back.
fn words_of(text: &[u8]) -> Option<Words> {
    if text == NOT_ALLOWED_TEXT.as_bytes() {
        return Some(Words::NotAllowed);
    }
    refusal_of(text).map(Words::Rpc)
}

/// A refused arrival's JSON-RPC refusal read back.
fn refusal_of(text: &[u8]) -> Option<crate::arrival::Refusal> {
    let v: serde_json::Value = serde_json::from_slice(text).ok()?;
    Some(crate::arrival::Refusal {
        status: u32::try_from(v.get("status")?.as_u64()?).ok()?,
        id: v.get("id").filter(|i| !i.is_null()).cloned(),
        code: v.get("code")?.as_i64()?,
        message: v.get("message")?.as_str()?.to_string(),
        data: v.get("data").filter(|d| !d.is_null()).cloned(),
    })
}

slot!(
    /// `arrive`: the arrival decided and kept with its generation; a refused one refused in its own
    /// words.
    Arrive, ArriveIn, ArriveOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let claim = door::ROUTES.get(input.get().claim as usize);
        let stdio = claim.is_some_and(|r| r.carrier == crate::claims::CARRIER_STDIO);
        let body = input.field(|i| &i.body).bytes();
        let fields = input.fields();
        if claim.is_some_and(|r| r.open) {
            // The discovery document is not answered on the request path.
            return out.fail(Refusal::bare());
        }
        if claim.is_some_and(|r| r.verb != "POST") {
            return out.fail(Refusal::refused(NOT_ALLOWED_TEXT));
        }
        let decision = crate::arrival::decide(stdio, body, |name| {
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
            return out.fail(Refusal::refused(refusal_text(refusal)));
        }
        let (correlation, cancels) = match &decision {
            Decision::Request { correlation, .. } | Decision::Session { correlation, .. } => {
                (*correlation, 0)
            }
            Decision::Notice { cancels, .. } => (0, *cancels),
            Decision::Refused(_) => (0, 0),
        };
        out.set(|o| &o.op_class, op_class(&decision));
        out.set(|o| &o.principal_need, PRINCIPAL_REQUIRED);
        out.set(|o| &o.dialect, 0);
        out.set(|o| &o.correlation, correlation);
        out.set(|o| &o.cancels, cancels);
        let params = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("params").cloned());
        let unit = Unit {
            catalogue: plane.current(),
            decision,
            params,
            pending: None,
            ticket: None,
        };
        keep(&plane.units, MAX_UNITS, input.get().unit, unit);
        Outcome::Ready
    }
);

/// Write as much of `bytes[sent..]` as the reply buffer holds; `true` when all of it went.
fn stream(
    out: &mut Out<'_, OnPieceOut>,
    reply: &mut busbar_contract::abi::sdk::HostBuf<'_, u8>,
    bytes: &[u8],
    sent: &mut usize,
) -> bool {
    let n = reply.stream(bytes.get(*sent..).unwrap_or_default());
    *sent += n;
    out.set(|o| &o.emitted, n as u64);
    *sent >= bytes.len()
}

slot!(
    /// `on_piece`: the caller's body answered from what the plane holds, streamed until it is all
    /// written, and the unit ended.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let piece = input.get();
        if piece.from != FROM_CALLER {
            return Outcome::Refused;
        }
        let key = piece.unit;
        let stream_key = piece.stream;
        let mut reply = input.reply_buf();
        let mut first = false;
        let ticket = piece.head.ticket;
        let answered = plane.units.with(&key, |unit| {
            let unit = unit?;
            unit.ticket = Some(ticket);
            if unit.pending.is_none() {
                if piece.flags & PIECE_LAST == 0 {
                    return Some(None);
                }
                let catalogue = unit.catalogue.clone()?;
                let mut session = plane.sessions.get(&stream_key).unwrap_or_default();
                // Nothing is visible until the kernel's entitlement answer is bound here.
                let admit = |_: &str, _: &str| false;
                let answer = crate::answer::answer(
                    &unit.decision,
                    unit.params.as_ref(),
                    &catalogue,
                    &admit,
                    |_| false,
                    &mut session,
                );
                if stream_key != 0 {
                    keep(&plane.sessions, MAX_SESSIONS, stream_key, session);
                }
                match answer {
                    Answer::Here { status, body } => {
                        unit.pending = Some((status, body, 0));
                        first = true;
                    }
                    Answer::Far => return None,
                }
            }
            let (status, body, sent) = unit.pending.as_mut()?;
            let done = stream(&mut out, &mut reply, body, sent);
            Some(Some((*status, done)))
        });
        match answered {
            None => Outcome::Refused,
            Some(None) => Outcome::Ready,
            Some(Some((status, done))) => {
                if first {
                    out.set(|o| &o.reply_status, status);
                }
                if done {
                    plane.units.remove(&key);
                    out.set(|o| &o.flags, EMIT_DONE);
                } else {
                    out.set(|o| &o.more, 1);
                }
                Outcome::Ready
            }
        }
    }
);

slot!(
    /// `refusal`: a refused arrival's own words rendered with its own status; any other refusal
    /// rendered as the one error envelope with no id.
    RefusalSlot, RefusalIn, RefusalOut, |_, input, mut out| {
        let given = input.get();
        let text = input.field(|i| &i.text).bytes();
        let (status, body, fields) = if given.cause == REFUSAL_ARRIVE {
            match words_of(text) {
                Some(Words::Rpc(refusal)) => (refusal.status, refusal.body(), false),
                Some(Words::NotAllowed) => (
                    door::STATUS_METHOD_NOT_ALLOWED,
                    door::method_not_allowed_body(),
                    true,
                ),
                None => return Outcome::Failed,
            }
        } else {
            let message = std::str::from_utf8(text).unwrap_or_default();
            let refusal = crate::arrival::Refusal {
                status: given.status,
                id: None,
                code: crate::codec::CODE_REFUSED,
                message: message.to_string(),
                data: None,
            };
            (0, refusal.body(), false)
        };
        let (mut reply, mut field_buf, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&body);
        if fields {
            field_buf.push(OutField {
                name: arena.span(b"allow"),
                value: arena.span(b"POST"),
            });
        }
        let short = !(reply.fits() && field_buf.fits() && arena.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = field_buf.settle(short);
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
        out.set(|o| &o.status, status);
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
