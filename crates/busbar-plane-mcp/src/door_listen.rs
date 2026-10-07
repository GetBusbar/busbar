// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen` ON THE HTTP CARRIER: A K6 SESSION (ARCHITECT round 4 Q-L3B-SURFACES (a),
//! confirmed round 5 Q-L3B-K6-HTTP (a)). `arrive` states `ROUTE_SESSION` for it, so the driver
//! serves the unit as a duplex session whose caller leg is the long-lived response; every rule of
//! the subscription is [`crate::subscribe`]'s, the same state machine the line carrier drives.
//!
//! - THE CALLER'S PIECE (the request's body, read once) OPENS the subscription ([`Listen::open`]):
//!   a request that can deliver nothing is refused `400` with its JSON-RPC error; one that opens is
//!   answered `200` as an event stream (`content-type: text/event-stream`,
//!   `cache-control: no-cache, no-store`) whose first event is the acknowledgement.
//! - THE TICK ([`tick`]) is the subscription's clock: every [`POLL_NS`] each held subscription is
//!   named on the instance's driver ticket (`drive`, [`drive`]), and the session collects
//!   (`FROM_KERNEL`): one step, its permission re-asked through the kernel's live re-resolution
//!   ([`standing`]), a change frame when the catalogue its caller can see moved, a
//!   keepalive comment (`: keepalive`) when it has been quiet for
//!   [`crate::subscribe::KEEPALIVE_NS`], and its last frame at its bound or on a lapsed permission,
//!   after which the session is done. A new generation (`refresh`) names them at once ([`wake_all`]).
//! - Every frame is one `message` event (`event: message`, `data: <json>`), as predev wrote them.
//! - THE SESSION'S ONE LINE carries the request's fee unit, reported with the acknowledgement.

use super::{ask_entitlements, write, CallUnit, Held, McpDoor, Pending, Written, MAX_UNITS};
use crate::catalogue::Lookup;
use crate::framing::{events, CACHE_CONTROL, CONTENT_TYPE, EVENT_STREAM, NO_STORE};
use crate::subscribe::{Listen, Standing, Step as ListenStep, KEEPALIVE_NS, MAX_LIFETIME_NS};
use crate::tool_arrival::Disposition;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    OnPieceIn, OnPieceOut, PlaneDriveIn, PlaneDriveOut, UnitCount, FROM_CALLER, FROM_KERNEL,
    PIECE_LAST, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::{Lent, Out, Services};
use serde_json::Value;

/// How often the instance's tick steps its held subscriptions (predev re-read the generation and
/// re-asked the permission every 250 ms of a stream's life).
pub(super) const POLL_NS: u64 = 250_000_000;

/// The most subscriptions one caller holds open at once. A caller at it is refused its next one:
/// a quota is a refusal its caller can act on (close one, then open), where an eviction of another
/// caller's stream is not.
pub(super) const MAX_LISTENS_PER_OWNER: usize = 64;

/// What an idle stream writes to say it is alive: an event-stream comment, which every reader
/// drops, so an intermediary does not reclaim a working connection.
const KEEPALIVE: &[u8] = b": keepalive\n\n";

/// The status an invalid `subscriptions/listen` is refused with.
const STATUS_INVALID: u32 = 400;

/// The status a `subscriptions/listen` is refused with when its caller is at its quota.
const STATUS_QUOTA: u32 = 429;

/// One held subscription, by its session's stream.
#[derive(Debug, Clone)]
pub(super) struct Listening {
    /// The caller that opened it, by the reference the kernel lends every piece of its units (the
    /// one the quota counts under).
    owner: String,
    /// The subscription.
    listen: Box<Listen>,
    /// The session's caller-side ticket.
    ticket: Ticket,
    /// The tick clock's reading at its first tick (`0` before one): a subscription its session
    /// never ended (its caller went away while it was idle, which nothing tells the door) is dropped
    /// once it is past its bound.
    first_tick: u64,
    /// The tick asked for a step it has not collected.
    due: bool,
    /// The stream's head is written.
    headed: bool,
}

/// A frame of the stream: its head (status, fields and the request's fee unit) with the first.
fn frame(bytes: Vec<u8>, done: bool, headed: bool) -> Pending {
    let (fields, units) = if headed {
        (Vec::new(), Vec::new())
    } else {
        (
            vec![
                (CONTENT_TYPE.to_string(), EVENT_STREAM.to_string()),
                (CACHE_CONTROL.to_string(), NO_STORE.to_string()),
            ],
            vec![UnitCount {
                class: crate::door::CLASS_FEE_INDEX,
                source: UNITS_REPORTED,
                amount: 1,
            }],
        )
    };
    Pending {
        status: 200,
        fields,
        request: None,
        bytes,
        sent: 0,
        headed,
        done,
        records: Vec::new(),
        audits: Vec::new(),
        lane: None,
        units,
    }
}

/// ONE PIECE OF A LISTEN SESSION (`stream != 0`): the caller's piece opens it, a collection steps
/// it, and the caller's side ending ends it. A re-call after `more = 1` writes what is pending.
pub(super) fn piece(
    plane: &McpDoor,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> Outcome {
    let given = input.get();
    let (key, ticket) = (given.unit, given.head.ticket);
    let caller = input
        .field(|i| &i.caller_ref)
        .as_str()
        .unwrap_or_default()
        .to_string();
    let principal = if caller.is_empty() {
        crate::ask::UNGOVERNED
    } else {
        caller.as_str()
    };
    let step = plane.units.with(&key, |unit| {
        let unit = unit?;
        unit.ticket = Some(ticket);
        if unit.pending.is_some() {
            return Some(true);
        }
        match given.from {
            // The caller went away: the session ends with nothing more to say.
            FROM_CALLER if given.flags & PIECE_LAST != 0 => {
                unit.pending = Some(frame(Vec::new(), true, true));
                Some(true)
            }
            FROM_CALLER => open(plane, ticket, principal, unit),
            FROM_KERNEL if given.attempt_no == 0 => {
                if plane.listens.with(&key, |l| l.is_none()) {
                    return Some(false);
                }
                step(plane, ticket, principal, unit)
            }
            // A listen session dials nothing: an ATTEMPT carries nothing.
            FROM_KERNEL => Some(false),
            _ => None,
        }
    });
    match step {
        None => Outcome::Refused,
        Some(false) => Outcome::Ready,
        Some(true) => {
            let written = plane.units.with(&key, |unit| {
                let pending = unit?.pending.as_mut()?;
                Some(write(&input, out, pending))
            });
            match written {
                None | Some(Err(())) => Outcome::Failed,
                Some(Ok(Written::More)) => Outcome::Ready,
                Some(Ok(Written::Sent)) => {
                    plane.units.with(&key, |unit| {
                        if let Some(unit) = unit {
                            unit.pending = None;
                        }
                    });
                    Outcome::Ready
                }
                Some(Ok(Written::Done)) => {
                    plane.units.remove(&key);
                    plane.listens.remove(&key);
                    Outcome::Ready
                }
            }
        }
    }
}

/// OPEN the subscription the unit's request asks for: refused `400` in its own words, or held and
/// stepped once (the acknowledgement). `None` for a unit that is not a `subscriptions/listen`.
fn open(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) -> Option<bool> {
    let Disposition::Request { row, id } = &unit.disposition else {
        return None;
    };
    if row.op != crate::tool_ops::OP_SUBSCRIPTIONS_LISTEN {
        return None;
    }
    if plane.listens.with(&unit.key, |l| l.is_some()) {
        return Some(false);
    }
    let id = id.clone();
    let held = plane.current().or_else(|| unit.held.clone())?;
    entitled_afresh(plane, ticket, unit, &held);
    let now = mono_ns(plane.services, ticket, unit);
    let opened = {
        let entitled = &unit.entitled;
        let admit = |kind: &str, name: &str| {
            entitled
                .get(&format!("{kind}:{name}"))
                .copied()
                .unwrap_or(false)
        };
        Listen::open(unit.params.as_ref(), id, now, |uri| {
            matches!(held.catalogue.resource_by_uri(&admit, uri), Lookup::One(_))
        })
    };
    match opened {
        Err(refusal) => {
            let body = serde_json::to_vec(&refusal).unwrap_or_default();
            unit.pending = Some(Pending::answer(STATUS_INVALID, body, None, &[]));
            Some(true)
        }
        Ok(listen) => {
            let id = listen.id.clone();
            let listening = Listening {
                owner: principal.to_string(),
                listen: Box::new(listen),
                ticket,
                first_tick: 0,
                due: false,
                headed: false,
            };
            // THE QUOTA REFUSES THE NEW STREAM, never evicts a held one: this caller at its own
            // bound, or the instance at its total, is told so.
            let admitted = plane.listens.with_all(|held| {
                let full = held.len() >= MAX_UNITS
                    || held.values().filter(|l| l.owner == principal).count()
                        >= MAX_LISTENS_PER_OWNER;
                if !full {
                    held.insert(unit.key, listening);
                }
                !full
            });
            if !admitted {
                let refusal = crate::tool_arrival::Refusal {
                    status: STATUS_QUOTA,
                    id: Some(id),
                    code: crate::codec::CODE_REFUSED,
                    message: format!(
                        "this caller holds {MAX_LISTENS_PER_OWNER} open subscriptions, the most one \
                         caller may hold; close one and open again"
                    ),
                    data: Some(serde_json::json!({ "reason": "subscription_quota" })),
                };
                unit.pending = Some(Pending::answer(refusal.status, refusal.body(), None, &[]));
                return Some(true);
            }
            step(plane, ticket, principal, unit)
        }
    }
}

/// ONE STEP of the unit's subscription over the live catalogue, its permission re-asked: what it
/// writes, if anything. `Some(false)` when it has nothing to say.
fn step(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) -> Option<bool> {
    let held = plane.current().or_else(|| unit.held.clone())?;
    entitled_afresh(plane, ticket, unit, &held);
    let now = mono_ns(plane.services, ticket, unit);
    let standing = standing(plane, ticket, principal, unit);
    let entitled = &unit.entitled;
    let admit = |kind: &str, name: &str| {
        entitled
            .get(&format!("{kind}:{name}"))
            .copied()
            .unwrap_or(false)
    };
    let (stepped, headed) = plane.listens.with(&unit.key, |l| {
        let l = l?;
        l.due = false;
        let stepped = l.listen.step(&held.catalogue, &admit, &standing, &[], now);
        Some((stepped, l.headed))
    })?;
    let (bytes, done) = match stepped {
        ListenStep::Frames(frames) => (events(&frames), false),
        ListenStep::Keepalive => (KEEPALIVE.to_vec(), false),
        ListenStep::Quiet => return Some(false),
        ListenStep::End(frames) => (events(&frames), true),
        ListenStep::Closed => (Vec::new(), true),
    };
    // The head goes with the stream's first frame (its acknowledgement, or the last frame of a
    // stream whose permission lapsed before it).
    plane.listens.with(&unit.key, |l| {
        if let Some(l) = l {
            l.headed = true;
        }
    });
    unit.pending = Some(frame(bytes, done, headed));
    Some(true)
}

/// THE TICK: the instance's driver ticket and the tick clock noted, every held subscription asked
/// for a step (a subscription past its bound that never ended is dropped), and the driver ticket
/// woken when any is held. The next tick is [`POLL_NS`] on.
pub(super) fn tick(plane: &McpDoor, driver: Ticket, now_ns: u64) -> u64 {
    plane.driver.insert((), (driver, now_ns));
    let stale = MAX_LIFETIME_NS.saturating_add(KEEPALIVE_NS);
    let (gone, any) = plane.listens.with_all(|m| {
        let mut gone = Vec::new();
        for (key, l) in m.iter_mut() {
            if l.first_tick == 0 {
                l.first_tick = now_ns.max(1);
            }
            if now_ns.saturating_sub(l.first_tick) > stale {
                gone.push(*key);
            }
            l.due = true;
        }
        for key in &gone {
            m.remove(key);
        }
        (gone, !m.is_empty())
    });
    for key in gone {
        plane.units.remove(&key);
    }
    if any {
        wake_driver(plane);
    }
    now_ns.saturating_add(POLL_NS)
}

/// A new generation: every held subscription is asked for a step at once.
pub(super) fn wake_all(plane: &McpDoor) {
    let any = plane.listens.with_all(|m| {
        for l in m.values_mut() {
            l.due = true;
        }
        !m.is_empty()
    });
    if any {
        wake_driver(plane);
    }
}

/// `drive`: the sessions whose step is due, by stream, as many as the host's buffer takes; each one
/// named collects on its caller-side ticket.
pub(super) fn drive(
    plane: &McpDoor,
    input: Lent<'_, PlaneDriveIn>,
    out: &mut Out<'_, PlaneDriveOut>,
) -> Outcome {
    let due: Vec<u64> = plane.listens.with_all(|m| {
        m.iter()
            .filter(|(_, l)| l.due)
            .map(|(stream, _)| *stream)
            .collect()
    });
    let mut buf = input.sessions_buf();
    for stream in &due {
        buf.push(*stream);
    }
    if !buf.fits() {
        out.set(|o| &o.sessions_needed, buf.needed() as u32);
        return Outcome::Failed;
    }
    out.set(|o| &o.sessions_written, buf.written() as u32);
    plane.listens.with_all(|m| {
        for stream in &due {
            if let Some(l) = m.get_mut(stream) {
                l.due = false;
            }
        }
    });
    Outcome::Ready
}

/// The op on `ticket` was cancelled: the subscription it carried is dropped.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    plane
        .listens
        .with_all(|m| m.retain(|_, l| l.ticket != ticket));
}

/// Name the instance's driver ticket (as its last tick handed it): a held subscription owes a step.
fn wake_driver(plane: &McpDoor) {
    let driver = plane.driver.get(&()).map(|(ticket, _)| ticket);
    if let (Some(wake), Some(ticket)) = (plane.wake, driver) {
        if ticket != Ticket::NONE {
            wake.wake(ticket);
        }
    }
}

// ── what a held unit re-asks each frame, and the round busbar's own ask costs ──────────────────

/// Whether a request asks busbar's own round before it is answered: a `prompts/get` of a prompt
/// whose operator asks its caller first, presenting no answers yet (the served engine charged that
/// round on the caller's budget).
pub(super) fn asks_a_round(
    op: busbar_contract::ids::OpClassId,
    held: &Held,
    value: &Value,
) -> bool {
    if op != crate::tool_ops::OP_PROMPT_GET {
        return false;
    }
    let params = value.get("params");
    let retried = params
        .is_some_and(|p| p.get("inputResponses").is_some() || p.get("requestState").is_some());
    let asks = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .and_then(|name| held.catalogue.prompt_for(&|_: &str, _: &str| true, name))
        .is_some_and(|p| !p.ask_caller.is_empty());
    asks && !retried
}

/// The host's monotonic clock on a fresh handle of the unit's ticket; `0` with no clock.
pub(super) fn mono_ns(services: Option<Services>, ticket: Ticket, unit: &mut CallUnit) -> u64 {
    let Some(services) = services else {
        return 0;
    };
    let handle = CompletionHandle {
        ticket,
        seq: unit.issued,
        _reserved: 0,
    };
    unit.issued += 1;
    services.clock_now(handle).map_or(0, |r| r.mono_ns)
}

/// The catalogue's every grant, entitled afresh for this frame: a held unit re-asks what its caller
/// may see each time it looks.
pub(super) fn entitled_afresh(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit, held: &Held) {
    unit.entitled.clear();
    ask_entitlements(plane.services, ticket, unit, &held.catalogue.grants());
}

/// Whether the unit's principal still stands: the kernel's live re-resolution
/// (`entitlement.check` of [`busbar_contract::abi::host::service::ENTITLEMENT_STANDING`]). A host
/// that serves no entitlement stands nothing.
fn stands(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> bool {
    let Some(services) = plane.services else {
        return false;
    };
    let handle = CompletionHandle {
        ticket,
        seq: unit.issued,
        _reserved: 0,
    };
    unit.issued += 1;
    services
        .entitled(
            handle,
            busbar_contract::abi::host::service::ENTITLEMENT_STANDING,
        )
        .unwrap_or(false)
}

/// THE PERMISSION, RE-ASKED THIS FRAME: the kernel re-resolves the unit's principal live
/// ([`stands`]); one that no longer stands is lapsed, in predev's words, and ends the subscription on
/// this frame (on either carrier).
pub(super) fn standing(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
) -> Standing {
    if stands(plane, ticket, unit) {
        Standing::Live
    } else {
        Standing::Lapsed {
            message: format!(
                "`{principal}` is no longer live, so the standing decision it was admitted under \
                 no longer applies"
            ),
            reason: busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE.to_string(),
        }
    }
}
