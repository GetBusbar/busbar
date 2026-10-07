// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TASK A RELAYED HOP IS FOR (ARCHITECT ruling B1): opened at the unit's first ATTEMPT over the
//! task store's host records, and settled on the far end's answer. Ported from the served engine's
//! unary hop (`busbar-a2a` `receive`: `addressed_task`, `resumable_task`, the mint, the submit and
//! `record_dispatch`, `record_state`, `end_task`), in its order and with its answers.
//!
//! * ADDRESSED: the request's `params` name a task the caller holds ([`identity::named_tasks`]):
//!   the hop reuses its identity and opens nothing.
//! * RESUMED: the caller's message names a `contextId` under which one of its tasks on this agent
//!   is interrupted: the newest moves back to `working` (refused `409` when it cannot).
//! * FRESH: busbar mints the id from eight random bytes ([`identity::mint`]), the `contextId` is the
//!   caller's or the id, and the task is submitted and dispatched to the agent before the hop
//!   (refused `503` when it cannot be recorded).
//!
//! Task ids the caller holds and whose far-end id busbar learnt are sent on as the far end's
//! ([`identity::translate_request`]). On the answer, the reported state is recorded (nothing for
//! `submitted`), and a failed hop ends a task it opened as `failed`.
//!
//! A push callback the request carries INLINE (its `configuration`, in any of the three spellings
//! [`CALLBACK_CONFIG_POINTERS`] names) is judged before anything is opened, by the same floor the
//! push-config verbs use ([`local::judge_callback`]), and a callback or a credential busbar cannot
//! honour refuses the request `400` in the engine's words. One that passes is the task's
//! `push_callback`, on the row it opens, resumes or addresses, and its credential rides back to the
//! door ([`Callback`]), which holds it in plane memory as the engine's delivery does.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::a2a::task::{plan_transition, Direction, Task, TaskState};
use crate::arrival::{Refusal, JSON_MEDIA_TYPE};
use crate::identity::{self, MINT_BYTES};
use crate::local::{self, Reach};
use crate::push::DeliveryAuth;
use crate::relay::{Reply, Settled, TaskHop};
use crate::skill::CALLBACK_CONFIG_POINTERS;
use crate::tasks::{self, Halt, Planned, Records, Step, Write};
use crate::TaskRow;

/// `-32002`: the task cannot be moved.
const CODE_TASK_NOT_CANCELABLE: i64 = -32002;
/// `-32603`: busbar failed.
const CODE_INTERNAL: i64 = -32603;
/// `-32602`: the params are wrong.
const CODE_INVALID_PARAMS: i64 = -32602;
/// The status a callback busbar cannot honour answers with: the caller's fault.
const STATUS_BAD_REQUEST: u32 = 400;
/// The status a task that cannot be recorded answers with.
const STATUS_UNAVAILABLE: u32 = 503;
/// The status an interrupted task that cannot resume answers with.
const STATUS_CONFLICT: u32 = 409;

/// The host's reach opening a task needs beyond the records and the destination judge: the
/// kernel's random bytes.
pub trait Mint: Reach {
    /// `random.fill` into `buf`.
    ///
    /// # Errors
    /// [`Halt`].
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Halt>;
}

/// One relayed request, as its first ATTEMPT sees it.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The caller's JSON-RPC envelope.
    pub envelope: &'a Value,
    /// The envelope a request-stage rewrite left, when one did: the request relayed (its task ids
    /// translated over it). The task is opened from [`Request::envelope`].
    pub relayed: Option<&'a Value>,
    /// The caller's reference: the task store's key prefix.
    pub caller: &'a str,
    /// The agent the kernel picked.
    pub member: &'a str,
    /// Now, in seconds.
    pub now: u64,
}

/// THE PUSH CALLBACK a request carried inline, as it passed the floor: the URL now on the task's
/// row, and the credential the caller asked busbar to present there (none clears one held).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    /// The URL, as registered.
    pub url: String,
    /// The credential, if the config named one.
    pub auth: Option<DeliveryAuth>,
}

/// What opening answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The hop goes ahead for this task, sending `instead` in place of the caller's bytes when a
    /// task id was translated.
    Hop {
        /// The task.
        task: TaskHop,
        /// The translated request, if any id was.
        instead: Option<Vec<u8>>,
        /// The push callback the request carried inline, registered on the task.
        callback: Option<Callback>,
        /// The task as a request addressing it read it, as the record that holds it (none for a
        /// task the opening wrote: its writes hold it).
        read: Option<Write>,
    },
    /// The hop does not go ahead: the caller's whole answer.
    Refused(Reply),
}

/// The answer a refused opening gives, in the engine's `rpcerror::body` words.
fn refused(status: u32, rpc_id: &Value, code: i64, message: &str) -> Opened {
    let refusal = Refusal {
        status,
        id: Some(rpc_id.clone()),
        code,
        message: message.to_string(),
    };
    Opened::Refused(Reply {
        status,
        content_type: JSON_MEDIA_TYPE,
        body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
    })
}

/// A read that failed reads as nothing (the engine's scoped reads collapse an error to absent); a
/// pending one pends.
fn or_absent<T>(read: Result<T, Halt>, absent: T) -> Result<T, Halt> {
    match read {
        Err(Halt::Pending) => Err(Halt::Pending),
        Err(Halt::Failed(_)) => Ok(absent),
        Ok(v) => Ok(v),
    }
}

/// The newest of the caller's tasks under `context_id` on `member` that is interrupted.
fn resumable(rows: Vec<TaskRow>, context_id: &str, member: &str) -> Option<TaskRow> {
    let mut candidates: Vec<TaskRow> = rows
        .into_iter()
        .filter(|r| {
            r.context_id == context_id
                && r.agent_id == member
                && TaskState::parse(&r.state).is_ok_and(TaskState::is_interrupted)
        })
        .collect();
    candidates.sort_by_key(|r| r.updated_at);
    candidates.pop()
}

/// OPEN the task request `req` is for; its record writes go to `out`. `backends` answers the far
/// end's id busbar learnt for one of the caller's task ids.
///
/// # Errors
/// [`Halt::Pending`] when a host call pends: the piece runs again from the top.
pub fn open(
    reach: &mut dyn Mint,
    req: &Request<'_>,
    rpc_id: &Value,
    backends: &dyn Fn(&str) -> Option<String>,
    out: &mut Vec<Write>,
) -> Result<Opened, Halt> {
    let callback = match inline_callback(reach, req.envelope)? {
        Ok(callback) => callback,
        Err(message) => {
            return Ok(refused(
                STATUS_BAD_REQUEST,
                rpc_id,
                CODE_INVALID_PARAMS,
                &message,
            ))
        }
    };
    let url = callback.as_ref().map(|c| c.url.as_str());
    let mut addressed = None;
    let mut read = None;
    for named in identity::named_tasks(req.envelope) {
        if let Some(held) = or_absent(tasks::get(reach, req.caller, named, req.now), None)? {
            read = tasks::as_read(req.caller, &held);
            addressed = Some(held.row);
            break;
        }
    }
    let context = identity::context_of(req.envelope);
    let resumed = match (&addressed, context.is_empty()) {
        (None, false) => resumable(
            or_absent(tasks::list(reach, req.caller, req.now), Vec::new())?,
            context,
            req.member,
        ),
        _ => None,
    };
    let task = match (addressed, resumed) {
        (Some(row), _) => {
            if let Some(url) = url {
                let at = Step {
                    caller: req.caller,
                    request_id: &row.task_id,
                    now: req.now,
                };
                // A callback that cannot be registered leaves the task as it was: the hop goes on.
                if let Err(Halt::Pending) = tasks::set_callback(reach, &at, &row.task_id, url, out)
                {
                    return Err(Halt::Pending);
                }
            }
            TaskHop {
                task_id: row.task_id,
                context_id: row.context_id,
                addressed: true,
                skill: None,
            }
        }
        (None, Some(row)) => {
            let at = Step {
                caller: req.caller,
                request_id: &row.task_id,
                now: req.now,
            };
            let mut plan = |held: &TaskRow| -> Planned {
                plan_transition(TaskState::Working, at.now)(held).map(|(mut next, kind)| {
                    if let Some(url) = url {
                        next.push_callback = url.to_string();
                    }
                    Some((next, kind))
                })
            };
            match tasks::change(reach, &at, &row.task_id, &mut plan, out) {
                Err(Halt::Pending) => return Err(Halt::Pending),
                Err(Halt::Failed(_)) => {
                    return Ok(refused(
                        STATUS_CONFLICT,
                        rpc_id,
                        CODE_TASK_NOT_CANCELABLE,
                        "this task cannot be resumed",
                    ))
                }
                Ok(_) => {}
            }
            TaskHop {
                task_id: row.task_id,
                context_id: row.context_id,
                addressed: false,
                skill: None,
            }
        }
        (None, None) => {
            let mut random = [0u8; MINT_BYTES];
            reach.random(&mut random)?;
            let task_id = identity::mint(req.member, random);
            let context_id = if context.is_empty() {
                task_id.clone()
            } else {
                context.to_string()
            };
            let at = Step {
                caller: req.caller,
                request_id: &task_id,
                now: req.now,
            };
            let opened = Task::submitted(
                task_id.as_str(),
                context_id.as_str(),
                req.caller,
                Direction::Inbound,
                req.now,
            )
            .map_err(|e| Halt::Failed(e.to_string()))
            .and_then(|mut t| {
                t.push_callback = url.map(str::to_string);
                tasks::open(reach, &at, t.to_row(), req.member, out)
            });
            match opened {
                Err(Halt::Pending) => return Err(Halt::Pending),
                Err(Halt::Failed(_)) => {
                    return Ok(refused(
                        STATUS_UNAVAILABLE,
                        rpc_id,
                        CODE_INTERNAL,
                        "the task could not be recorded",
                    ))
                }
                Ok(_) => {}
            }
            TaskHop {
                task_id,
                context_id,
                addressed: false,
                skill: None,
            }
        }
    };
    let instead = translated(reach, req, backends)?;
    Ok(Opened::Hop {
        task,
        instead,
        callback,
        read,
    })
}

/// THE INLINE CONFIG OBJECT whose `url` is the callback: the first of the three spellings that
/// carries a non-empty one, so the credential is read out of the same object as the URL.
fn inline_config(envelope: &Value) -> Option<&Value> {
    CALLBACK_CONFIG_POINTERS.into_iter().find_map(|p| {
        envelope.pointer(p).filter(|cfg| {
            cfg.get("url")
                .and_then(Value::as_str)
                .is_some_and(|u| !u.is_empty())
        })
    })
}

/// THE PUSH CALLBACK `envelope` carries inline, judged: `Ok(None)` for none, the callback as it
/// passed, or the refusal's words (a credential busbar cannot present, or a URL the floor refuses).
///
/// # Errors
/// [`Halt`] from the destination judge.
fn inline_callback(
    reach: &mut dyn Reach,
    envelope: &Value,
) -> Result<Result<Option<Callback>, String>, Halt> {
    let Some(cfg) = inline_config(envelope) else {
        return Ok(Ok(None));
    };
    let auth = match local::delivery_auth(cfg) {
        Ok(auth) => auth,
        Err(message) => return Ok(Err(message)),
    };
    let url = cfg
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(local::judge_callback(reach, &url)?.map(|()| Some(Callback { url, auth })))
}

/// The request with every task id the caller holds, and whose far-end id busbar learnt, sent on as
/// the far end's; `None` when none is.
fn translated(
    reach: &mut dyn Mint,
    req: &Request<'_>,
    backends: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Vec<u8>>, Halt> {
    let mut owned = BTreeMap::new();
    let relayed = req.relayed.unwrap_or(req.envelope);
    for id in identity::translatable(relayed) {
        if owned.contains_key(id) {
            continue;
        }
        let Some(backend) = backends(id).filter(|b| b != id) else {
            continue;
        };
        if or_absent(tasks::get(reach, req.caller, id, req.now), None)?.is_some() {
            owned.insert(id.to_string(), backend);
        }
    }
    if owned.is_empty() {
        return Ok(None);
    }
    Ok(identity::translate_request(relayed, &|id| {
        owned.get(id).cloned()
    }))
}

/// SETTLE `task` on what its answer said; the record writes go to `out`. A write the store refuses
/// is not the caller's failure: the answer stands. A relayed event settles as it passes: the state
/// it reported, then the artifact it carried (the resume cursor, one chunk on), each chained over
/// the writes `out` already holds. Answers the row as it moved (what a push notification about the
/// move carries), or `None` when nothing moved.
///
/// # Errors
/// [`Halt::Pending`] when a records call pends.
pub fn settle(
    rec: &mut dyn Records,
    task: &TaskHop,
    settled: &Settled,
    caller: &str,
    now: u64,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let (to, artifact) = match settled {
        Settled::Reported { state, .. } if *state == TaskState::Submitted => return Ok(None),
        Settled::Reported { state, .. } => (Some(*state), false),
        Settled::Failed => (Some(TaskState::Failed), false),
        Settled::Event {
            state, artifact, ..
        } => (*state, *artifact),
    };
    let at = Step {
        caller,
        request_id: &task.task_id,
        now,
    };
    let mut moved = None;
    if let Some(to) = to {
        let mut step = Vec::new();
        let transitioned = {
            let mut staged = tasks::Staged::new(&mut *rec, out);
            tasks::transition(&mut staged, &at, &task.task_id, to, &mut step)
        };
        match transitioned {
            Err(Halt::Pending) => return Err(Halt::Pending),
            Err(Halt::Failed(_)) => {}
            Ok(row) => {
                out.extend(step);
                moved = row;
            }
        }
    }
    if artifact {
        let mut step = Vec::new();
        let bumped = {
            let mut staged = tasks::Staged::new(&mut *rec, out);
            tasks::bump_cursor(&mut staged, &at, &task.task_id, &mut step)
        };
        match bumped {
            Err(Halt::Pending) => return Err(Halt::Pending),
            Err(Halt::Failed(_)) => {}
            Ok(_) => out.extend(step),
        }
    }
    Ok(moved)
}

/// THE RECORDS A STEP THAT CANNOT REACH THE HOST SEES: nothing but what it is handed, every claim
/// its own. For a task only the step's own unit is changing: the hop that opened or addressed it,
/// refused before it dialled, in the same instant.
struct Unhosted;

impl Records for Unhosted {
    fn get(&mut self, _: &str, _: &str) -> Result<Option<Vec<u8>>, Halt> {
        Ok(None)
    }

    fn list(&mut self, _: &str, _: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        Ok(Vec::new())
    }

    fn claim(&mut self, _: &str, _: &str, _: u64) -> Result<bool, Halt> {
        Ok(true)
    }
}

/// END `task` `failed` WITHOUT THE HOST (the door's `refusal` is ticketless): over `opened`, the
/// records that held the task as its hop's opening left it (the writes the opening made, or the row
/// it read), `caller`'s task moves to `failed` at `now` as [`settle`] moves it on
/// [`Settled::Failed`] (the engine's `end_task` under `fail_task`). The record writes, and the row
/// as it moved (`None`, with no writes, when it could not: a terminal task stays as it is, as the
/// engine's illegal transition left it).
#[must_use]
pub fn fail_unhosted(
    task: &TaskHop,
    opened: &[Write],
    caller: &str,
    now: u64,
) -> (Vec<Write>, Option<TaskRow>) {
    let mut host = Unhosted;
    let mut seen = tasks::Staged::new(&mut host, opened);
    let mut out = Vec::new();
    match settle(&mut seen, task, &Settled::Failed, caller, now, &mut out) {
        Ok(Some(row)) => (out, Some(row)),
        _ => (Vec::new(), None),
    }
}

#[cfg(test)]
#[path = "tests/task_hop_tests.rs"]
mod tests;
