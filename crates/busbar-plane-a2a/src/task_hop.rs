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

use std::collections::BTreeMap;

use serde_json::Value;

use crate::a2a::task::{Direction, Task, TaskState};
use crate::arrival::{Refusal, JSON_MEDIA_TYPE};
use crate::identity::{self, MINT_BYTES};
use crate::relay::{Reply, Settled, TaskHop};
use crate::tasks::{self, Halt, Records, Step, Write};
use crate::TaskRow;

/// `-32002`: the task cannot be moved.
const CODE_TASK_NOT_CANCELABLE: i64 = -32002;
/// `-32603`: busbar failed.
const CODE_INTERNAL: i64 = -32603;
/// The status a task that cannot be recorded answers with.
const STATUS_UNAVAILABLE: u32 = 503;
/// The status an interrupted task that cannot resume answers with.
const STATUS_CONFLICT: u32 = 409;

/// The host's reach opening a task needs beyond the records: the kernel's random bytes.
pub trait Mint: Records {
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
    /// The caller's reference: the task store's key prefix.
    pub caller: &'a str,
    /// The agent the kernel picked.
    pub member: &'a str,
    /// Now, in seconds.
    pub now: u64,
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
    let mut addressed = None;
    for named in identity::named_tasks(req.envelope) {
        if let Some(held) = or_absent(tasks::get(reach, req.caller, named, req.now), None)? {
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
        (Some(row), _) => TaskHop {
            task_id: row.task_id,
            context_id: row.context_id,
            addressed: true,
            skill: None,
        },
        (None, Some(row)) => {
            let at = Step {
                caller: req.caller,
                request_id: &row.task_id,
                now: req.now,
            };
            match tasks::transition(reach, &at, &row.task_id, TaskState::Working, out) {
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
            .and_then(|t| tasks::open(reach, &at, t.to_row(), req.member, out));
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
    Ok(Opened::Hop { task, instead })
}

/// The request with every task id the caller holds, and whose far-end id busbar learnt, sent on as
/// the far end's; `None` when none is.
fn translated(
    reach: &mut dyn Mint,
    req: &Request<'_>,
    backends: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Vec<u8>>, Halt> {
    let mut owned = BTreeMap::new();
    for id in identity::translatable(req.envelope) {
        if owned.contains_key(id) {
            continue;
        }
        let Some(backend) = backends(id) else {
            continue;
        };
        if or_absent(tasks::get(reach, req.caller, id, req.now), None)?.is_some() {
            owned.insert(id.to_string(), backend);
        }
    }
    if owned.is_empty() {
        return Ok(None);
    }
    Ok(identity::translate_request(req.envelope, &|id| {
        owned.get(id).cloned()
    }))
}

/// SETTLE `task` on what its answer said; the record writes go to `out`. A write the store refuses
/// is not the caller's failure: the answer stands.
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
) -> Result<(), Halt> {
    let to = match settled {
        Settled::Reported { state, .. } if *state == TaskState::Submitted => return Ok(()),
        Settled::Reported { state, .. } => *state,
        Settled::Failed => TaskState::Failed,
    };
    let at = Step {
        caller,
        request_id: &task.task_id,
        now,
    };
    match tasks::transition(rec, &at, &task.task_id, to, out) {
        Err(Halt::Pending) => Err(Halt::Pending),
        Err(Halt::Failed(_)) | Ok(_) => Ok(()),
    }
}

#[cfg(test)]
#[path = "tests/task_hop_tests.rs"]
mod tests;
