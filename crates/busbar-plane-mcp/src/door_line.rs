// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINE CARRIER'S UNITS (ARCHITECT Q1a, round 4 Q-L3B-STDIO-SHAPE (B)): the host holds the
//! process's own stdin/stdout open as ONE carrier session and opens a unit per line; what a line
//! MEANS is [`crate::line`]'s, and how a unit answers it is here. What the plane writes unsolicited
//! (busbar's own asks of its caller, a subscription's changes and keepalives) it writes with the
//! host's `session.emit` on the session every line names
//! ([`busbar_contract::abi::host::service::CARRIER_SESSION_FIELD`]).
//!
//! - A REQUEST goes on through the one dispatch under the fields its body implies; its answer is
//!   one line.
//! - An `input_required` answer — busbar's OWN ask, or an UPSTREAM's ask relayed (Law 11) — is
//!   LIVENED ([`liven`]): its first ask is emitted as busbar's own request (`busbar:<n>`), the unit
//!   answers nothing, and the caller's answers are lines of their own: each answer but the round's
//!   last emits the next ask; the last is the RETRY, the request as the caller sent it with the
//!   answers and the sealed state, dispatched as that unit (its own admission). An answer that is an
//!   error hands the caller the `input_required` result itself.
//! - A SUBSCRIPTION (`subscriptions/listen`) is answered with its acknowledgement and kept on the
//!   session ([`listen`]): the tick ([`tick`]) steps it, emitting what changed, a `ping` when it has
//!   been quiet and its last frame at its bound.
//! - The STDIO-ERA VERBS are answered here, and a notification — or a line answering nothing busbar
//!   asked — is answered with nothing at all.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{door_listen, CallUnit, McpDoor, Pending};
use crate::line::{self, Era, LiveAsk, Reply};
use crate::subscribe::{Listen, Standing, Step as ListenStep};
use crate::tool_arrival::Disposition;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};

/// What a line unit is to the carrier.
#[derive(Debug, Clone, Default)]
pub(super) struct LineUnit {
    /// The carrier session it arrived over.
    pub(super) session: u64,
    /// The request this unit dispatches, as JSON: its own line, or the retry it became.
    pub(super) original: Option<Value>,
    /// What it answers without the dispatch: an era verb's answer, a failed ask's fallback, or
    /// nothing at all (an empty answer is written as no line).
    pub(super) preset: Option<Vec<u8>>,
    /// The live round (by its ask number) whose next ask this unit emits.
    pub(super) next_ask: Option<u64>,
    /// The live round this unit's retry is: `0` for a request the caller sent itself.
    pub(super) round: u32,
    /// Its line was raised from the session revision its carrier session negotiated
    /// ([`crate::adapt::raise`]): its answer is lowered back into it.
    pub(super) raised: bool,
}

/// One subscription kept on a carrier session.
#[derive(Debug, Clone)]
pub(super) struct LineListen {
    listen: Box<Listen>,
    /// The entitlement answers it was opened under.
    entitled: BTreeMap<String, bool>,
}

/// One line as `arrive` read it: what the unit is to the carrier, and the bytes the one dispatch
/// decides on (`None` = the unit answers its preset, the dispatch decides nothing).
pub(super) struct Arrival {
    pub(super) unit: LineUnit,
    pub(super) dispatch: Option<Vec<u8>>,
}

/// READ ONE LINE of carrier session `session`: an answer to one of busbar's own asks (its round
/// moved on, or its retry), a cancel, a stdio-era verb, or a request for the one dispatch.
pub(super) fn arrive(plane: &McpDoor, session: u64, body: &[u8]) -> Arrival {
    let mut unit = LineUnit {
        session,
        ..LineUnit::default()
    };
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Arrival {
            unit,
            dispatch: Some(body.to_vec()),
        };
    };
    if let Some(reply) = line::reply(&value) {
        let n = match &reply {
            Reply::Answered(n, _) | Reply::Failed(n) => *n,
        };
        let Some(mut live) = plane.live_asks.remove(&(session, n)) else {
            // An answer to nothing busbar asked on this session: nothing to say.
            unit.preset = Some(Vec::new());
            return Arrival {
                unit,
                dispatch: None,
            };
        };
        match reply {
            Reply::Failed(_) => {
                unit.preset = Some(live.fallback.clone());
            }
            Reply::Answered(_, result) => {
                live.answered(result);
                if live.queued.is_empty() {
                    if let Some(retry) = live.retry() {
                        let dispatch = serde_json::to_vec(&retry).unwrap_or_default();
                        unit.original = Some(retry);
                        unit.round = live.round.saturating_add(1);
                        return Arrival {
                            unit,
                            dispatch: Some(dispatch),
                        };
                    }
                    unit.preset = Some(live.fallback.clone());
                } else {
                    plane.live_asks.insert((session, n), live);
                    unit.next_ask = Some(n);
                    unit.preset = Some(Vec::new());
                }
            }
        }
        return Arrival {
            unit,
            dispatch: None,
        };
    }
    if let Some(id) = line::cancelled(&value) {
        let key = line::id_key(&id);
        plane.live_asks.with_all(|m| {
            m.retain(|(s, _), live| {
                *s != session || live.original.get("id").map(line::id_key) != Some(key.clone())
            });
        });
    }
    match line::era(&value) {
        Era::Dispatch => {}
        Era::Opened(revision, answer) => {
            // THE CARRIER SESSION NOW SPEAKS `revision` (revision by negotiation, THE DESIGN section 2).
            // The table is bounded and evicts nothing (admission bounds live work): a full one
            // answers the stateless revision, which needs no entry.
            let kept = plane.line_revisions.with_all(|m| {
                let full = m.len() >= super::MAX_UNITS && !m.contains_key(&session);
                if !full {
                    m.insert(session, revision);
                }
                !full
            });
            let answer = if kept {
                answer
            } else {
                line::initialize_result(value.get("id").unwrap_or(&Value::Null))
            };
            unit.preset = Some(serde_json::to_vec(&answer).unwrap_or_default());
            return Arrival {
                unit,
                dispatch: None,
            };
        }
        Era::Answer(answer) => {
            unit.preset = Some(serde_json::to_vec(&answer).unwrap_or_default());
            return Arrival {
                unit,
                dispatch: None,
            };
        }
    }
    // A LINE OF A SESSION REVISION carries no stateless `_meta`: it is raised into the one
    // dispatch's shape, and its answer lowered back ([`crate::adapt`]).
    let stateless = value
        .pointer("/params/_meta")
        .and_then(|m| m.get(crate::codec::META_PROTOCOL_VERSION))
        .is_some();
    if !stateless && plane.line_revisions.get(&session).is_some() {
        let mut raised = value.clone();
        if crate::adapt::raise(&mut raised).is_some() {
            unit.raised = true;
            let dispatch = serde_json::to_vec(&raised).unwrap_or_default();
            unit.original = Some(raised);
            return Arrival {
                unit,
                dispatch: Some(dispatch),
            };
        }
    }
    unit.original = Some(value);
    Arrival {
        unit,
        dispatch: Some(body.to_vec()),
    }
}

/// Whether a line that the one dispatch refused is a notification: a notification is never
/// answered, refused or not.
pub(super) fn is_notification(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .is_ok_and(|v| v.get("method").is_some_and(Value::is_string) && v.get("id").is_none())
}

/// The next number busbar spells one of its own requests in.
fn next_ask(plane: &McpDoor) -> u64 {
    plane.ask_seq.with_all(|m| {
        let n = m.entry(()).or_insert(0);
        *n = n.saturating_add(1);
        *n
    })
}

/// `bytes` emitted on carrier session `session`, on a fresh handle of `ticket`: whether it went.
fn emit(plane: &McpDoor, ticket: Ticket, seq: u32, session: u64, bytes: &[u8]) -> bool {
    let Some(services) = plane.services else {
        return false;
    };
    let handle = CompletionHandle {
        ticket,
        seq,
        _reserved: 0,
    };
    services.session_emit(handle, session, bytes).is_ok()
}

/// THE PRESET ANSWER of a line unit, or the next ask of its round emitted (the unit then answers
/// nothing): `None` for a unit the one dispatch answers.
pub(super) fn preset(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<Pending> {
    let line_unit = unit.line.as_mut()?;
    let session = line_unit.session;
    if let Some(n) = line_unit.next_ask.take() {
        let now = door_listen::mono_ns(plane.services, ticket, unit);
        let line_unit = unit.line.as_mut()?;
        if let Some(mut live) = plane.live_asks.remove(&(session, n)) {
            let fresh = next_ask(plane);
            if let Some(ask) = live.issue(fresh) {
                live.arm(now);
                // Kept before it is asked: its answer may arrive before the emit returns.
                let fallback = live.fallback.clone();
                plane.live_asks.insert((session, fresh), live);
                if !emit(plane, ticket, unit.issued, session, &ask) {
                    plane.live_asks.remove(&(session, fresh));
                    line_unit.preset = Some(fallback);
                }
            } else {
                // The next ask cannot be put to the caller: it is handed the result itself.
                line_unit.preset = Some(live.fallback);
            }
            unit.issued += 1;
        }
    }
    let line_unit = unit.line.as_mut()?;
    let bytes = line_unit.preset.take()?;
    Some(Pending::answer(200, bytes, None, &[]))
}

/// LIVEN a line unit's answer: an `input_required` result (busbar's own ask, or an upstream's
/// relayed) is put to the caller as live requests on the session, its first ask emitted now, and
/// the unit answers nothing. Any other answer, or one that cannot be emitted, is left as it is.
pub(super) fn liven(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) {
    let Some(line_unit) = unit.line.as_ref() else {
        return;
    };
    let session = line_unit.session;
    let round = line_unit.round;
    // The round cap: past it the `input_required` result is handed to the caller as it is (its
    // sealed `requestState` makes that a continuation), never put live again.
    if !line::may_liven(round) {
        return;
    }
    let Some(original) = line_unit.original.clone() else {
        return;
    };
    let Some(pending) = unit.pending.as_mut() else {
        return;
    };
    if pending.request.is_some() || pending.status != 200 || pending.bytes.is_empty() {
        return;
    }
    let Ok(answer) = serde_json::from_slice::<Value>(&pending.bytes) else {
        return;
    };
    let Some(result) = answer.get("result") else {
        return;
    };
    if result.get("resultType").and_then(Value::as_str)
        != Some(crate::jsonrpc::RESULT_TYPE_INPUT_REQUIRED)
    {
        return;
    }
    let Some(mut live) = LiveAsk::of(principal, original, pending.bytes.clone(), result, round)
    else {
        return;
    };
    live.session = session;
    live.arm(door_listen::mono_ns(plane.services, ticket, unit));
    let n = next_ask(plane);
    let Some(ask) = live.issue(n) else {
        return;
    };
    let seq = unit.issued;
    unit.issued += 1;
    // KEPT BEFORE IT IS ASKED: the caller's answer is a line of its own, and may arrive before
    // the emit returns.
    plane.live_asks.insert((session, n), live);
    if !emit(plane, ticket, seq, session, &ask) {
        plane.live_asks.remove(&(session, n));
        return;
    }
    if let Some(pending) = unit.pending.as_mut() {
        pending.bytes.clear();
        pending.fields.clear();
    }
}

/// OPEN a subscription on the carrier session: refused in its own words, or answered with its
/// acknowledgement and kept on the session. `None` for a unit that is not a line's
/// `subscriptions/listen`.
pub(super) fn listen(plane: &McpDoor, ticket: Ticket, unit: &mut CallUnit) -> Option<Pending> {
    let session = unit.line.as_ref()?.session;
    let Disposition::Request { row, id } = &unit.disposition else {
        return None;
    };
    if row.op != crate::tool_ops::OP_SUBSCRIPTIONS_LISTEN {
        return None;
    }
    let id = id.clone();
    let held = plane.current().or_else(|| unit.held.clone())?;
    door_listen::entitled_afresh(plane, ticket, unit, &held);
    let now = door_listen::mono_ns(plane.services, ticket, unit);
    let entitled = unit.entitled.clone();
    let admit = |kind: &str, name: &str| {
        entitled
            .get(&format!("{kind}:{name}"))
            .copied()
            .unwrap_or(false)
    };
    let opened = Listen::open(unit.params.as_ref(), id.clone(), now, |uri| {
        matches!(
            held.catalogue.resource_by_uri(&admit, uri),
            crate::catalogue::Lookup::One(_)
        )
    });
    let mut listen = match opened {
        Err(refusal) => {
            let body = serde_json::to_vec(&refusal).unwrap_or_default();
            return Some(Pending::answer(400, body, None, &[]));
        }
        Ok(listen) => listen,
    };
    let frames = match listen.step(&held.catalogue, &admit, &Standing::Live, &[], now) {
        ListenStep::Frames(frames) | ListenStep::End(frames) => frames,
        _ => Vec::new(),
    };
    plane.line_listens.insert(
        (session, line::id_key(&id)),
        LineListen {
            listen: Box::new(listen),
            entitled,
        },
    );
    Some(Pending::answer(200, lines(&frames), None, &[]))
}

/// Frames as lines: one JSON-RPC message per line.
fn lines(frames: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        if !out.is_empty() {
            out.push(b'\n');
        }
        out.extend(serde_json::to_vec(frame).unwrap_or_default());
    }
    out
}

/// THE LAPSE of live asks: a round whose ask in flight went [`line::ASK_TIMEOUT_NS`] unanswered is
/// dropped and the caller is handed the `input_required` result itself, emitted on its session (the
/// unit that put the ask answered nothing, so the fallback is a line of its own).
fn lapse_asks(plane: &McpDoor, ticket: Ticket, now_ns: u64, seq: &mut u32) {
    let lapsed: Vec<(u64, Vec<u8>)> = plane.live_asks.with_all(|m| {
        let keys: Vec<(u64, u64)> = m
            .iter()
            .filter(|(_, live)| live.lapsed(now_ns))
            .map(|(key, _)| *key)
            .collect();
        keys.iter()
            .filter_map(|key| m.remove(key).map(|live| (key.0, live.fallback)))
            .collect()
    });
    for (session, mut fallback) in lapsed {
        fallback.push(b'\n');
        emit(plane, ticket, *seq, session, &fallback);
        *seq = seq.wrapping_add(1);
    }
}

/// THE TICK, for the subscriptions kept on carrier sessions: each stepped over the live catalogue,
/// what it says emitted on its session (a `ping` when it has been quiet), and a subscription whose
/// session can take nothing more, or that ended, dropped.
pub(super) fn tick(plane: &McpDoor, ticket: Ticket, now_ns: u64) {
    let mut seq: u32 = 0;
    lapse_asks(plane, ticket, now_ns, &mut seq);
    let Some(held) = plane.current() else {
        return;
    };
    let gone = plane.line_listens.with_all(|m| {
        let mut gone = Vec::new();
        for ((session, key), kept) in m.iter_mut() {
            let entitled = &kept.entitled;
            let admit = |kind: &str, name: &str| {
                entitled
                    .get(&format!("{kind}:{name}"))
                    .copied()
                    .unwrap_or(false)
            };
            let (bytes, ended) =
                match kept
                    .listen
                    .step(&held.catalogue, &admit, &Standing::Live, &[], now_ns)
                {
                    ListenStep::Frames(frames) => (lines(&frames), false),
                    ListenStep::Keepalive => {
                        let n = next_ask(plane);
                        (
                            serde_json::to_vec(&serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": format!("{}{n}", line::ASK_ID_PREFIX),
                                "method": crate::adapt::METHOD_PING,
                            }))
                            .unwrap_or_default(),
                            false,
                        )
                    }
                    ListenStep::Quiet => (Vec::new(), false),
                    ListenStep::End(frames) => (lines(&frames), true),
                    ListenStep::Closed => (Vec::new(), true),
                };
            let went = bytes.is_empty() || emit(plane, ticket, seq, *session, &bytes);
            seq = seq.wrapping_add(1);
            if ended || !went {
                gone.push((*session, key.clone()));
            }
        }
        for key in &gone {
            m.remove(key);
        }
        gone
    });
    let _ = gone;
}
