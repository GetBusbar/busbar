// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TASK STORE, OVER HOST RECORDS (`BUSBAR-1.6.0.md` B.3.1: "the task store is host records";
//! ARCHITECT C2c ruling S2). The plane holds no store: it reads through `records.get` /
//! `records.list`, decides a write with `records.claim`, and says every write as a `RECORD_PUT` in
//! its `on_piece` answer. [`Records`] is that reach; the door serves it through the SDK connector,
//! a test through a map.
//!
//! * KEYS ARE PRINCIPAL-PREFIXED: `<caller>/<task>` for a task, `<caller>/<task>/<seq>` for one of
//!   its events, `<caller>/<task>` again under the push-config kind. `<caller>` is the opaque
//!   per-principal reference the kernel lends on every piece (lower-case hex, so it holds no `/`):
//!   a key under another caller's prefix is one this caller can never name, which is how a foreign
//!   task reads exactly as a missing one.
//! * A CHANGE IS RACE-SAFE: every write of a task consumes the next sequence of its chain, and the
//!   sequence is won with `records.claim` on `<caller>/<task>/<seq>` before anything is written. A
//!   writer that loses re-reads and tries the next one.
//! * THE HASH CHAIN IS COMPUTED HERE, under the injective framing the engine seals new events with
//!   ([`digest`]), and the task record carries the chain's tail so a change never lists its events.
//! * A DELETE IS A TOMBSTONE: a put with an empty value, which the kernel's reads treat as absent.
//! * RETENTION is the engine's `evict_terminal` policy with the same numbers ([`TERMINAL_TTL_SECS`],
//!   [`ABANDON_SECS`], [`MAX_RETAINED`]): a read never answers a terminal task past its window, and
//!   [`sweep`] tombstones it, cancels an abandoned active one, and holds the cap.

use busbar_contract::vocab::{EV_ARTIFACT, EV_DELEGATED, EV_SUBMITTED};
use serde::{Deserialize, Serialize};

use crate::a2a::task::{plan_transition, TaskState};
use crate::record::DIGEST_VERSION_LEN_PREFIXED;
use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT};
use crate::{TaskEventRow, TaskRow};

/// How long a terminal task stays readable after its terminal transition, in seconds.
pub const TERMINAL_TTL_SECS: u64 = 300;
/// The most tasks kept; past it the oldest terminal ones go first, an active one never.
pub const MAX_RETAINED: usize = 4096;
/// How long an active task may sit unchanged before it is canceled as abandoned, in seconds.
pub const ABANDON_SECS: u64 = 86_400;
/// How long a won sequence claim stands. Only writers racing inside one op contend for it; a claim
/// whose writer never wrote frees its sequence again after this, in milliseconds.
pub const CLAIM_TTL_MS: u64 = 60_000;
/// How many times a change re-reads after losing its sequence to another writer.
const TRIES: usize = 3;

/// Why a step on the records did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    /// A records call pends: the op answers PENDING and runs again from the top.
    Pending,
    /// The host failed the call, or the change could not be made; the words say which.
    Failed(String),
}

/// The host records as the store reaches them. Every call is made in the same order on every entry
/// of an op, so a re-run reads the answers the host stored for it (the replay rule).
pub trait Records {
    /// The record of `kind` under `key`; `None` when absent or a tombstone.
    ///
    /// # Errors
    /// [`Halt`].
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt>;
    /// Every live record of `kind` whose key starts with `prefix`, in key order.
    ///
    /// # Errors
    /// [`Halt`].
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt>;
    /// Put `key` of `kind` if absent, for `ttl_ms`: `true` when this call made the claim.
    ///
    /// # Errors
    /// [`Halt`].
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt>;
}

/// One record write the answer carries out: a `RECORD_PUT`; an empty value is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    /// The record kind.
    pub kind: &'static str,
    /// The key.
    pub key: String,
    /// The value; empty = tombstone.
    pub value: Vec<u8>,
}

/// A TASK AS IT IS HELD: the row, and its chain's position (the next sequence and the tail digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    /// The row.
    #[serde(flatten)]
    pub row: TaskRow,
    /// The sequence the next event takes.
    pub next_seq: u64,
    /// The last event's digest.
    pub tail_hash: String,
}

/// The key prefix of everything `caller` holds.
fn scope(caller: &str) -> String {
    format!("{caller}/")
}

/// The key of `caller`'s task `task`.
#[must_use]
pub fn task_key(caller: &str, task: &str) -> String {
    format!("{caller}/{task}")
}

/// The key of event `seq` of `caller`'s task `task`; zero-padded so key order is sequence order.
#[must_use]
pub fn event_key(caller: &str, task: &str, seq: u64) -> String {
    format!("{caller}/{task}/{seq:020}")
}

/// Whether `caller` is a reference a key may start with: non-empty lower-case hex.
#[must_use]
pub fn is_caller(caller: &str) -> bool {
    !caller.is_empty()
        && caller
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `state` is a terminal task-state token.
fn terminal(state: &str) -> bool {
    TaskState::parse(state).is_ok_and(TaskState::is_terminal)
}

/// Whether a held task is past its window at `now`: terminal and unchanged for longer than
/// [`TERMINAL_TTL_SECS`].
#[must_use]
pub fn expired(row: &TaskRow, now: u64) -> bool {
    terminal(&row.state) && now.saturating_sub(row.updated_at) > TERMINAL_TTL_SECS
}

fn decode(bytes: &[u8]) -> Option<Held> {
    serde_json::from_slice(bytes).ok()
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, Halt> {
    serde_json::to_vec(v).map_err(|e| Halt::Failed(e.to_string()))
}

/// ONE EVENT'S DIGEST under the injective length-prefixed framing (v2): a domain tag, then each
/// string field as `<u64-le len><bytes>` and each integer as 8 little-endian bytes, sha256. The
/// field order is the engine's legacy pipe-join's, so the mapping stays legible.
#[must_use]
pub fn digest(ev: &TaskEventRow) -> String {
    let mut buf: Vec<u8> = b"busbar.a2a.taskchain.v2\0".to_vec();
    let text = |buf: &mut Vec<u8>, field: &str| {
        buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
        buf.extend_from_slice(field.as_bytes());
    };
    text(&mut buf, &ev.prev_hash);
    text(&mut buf, &ev.task_id);
    buf.extend_from_slice(&ev.seq.to_le_bytes());
    buf.extend_from_slice(&ev.ts.to_le_bytes());
    text(&mut buf, &ev.kind);
    text(&mut buf, &ev.context_id);
    text(&mut buf, &ev.principal);
    text(&mut buf, &ev.agent_id);
    text(&mut buf, &ev.state);
    busbar_contract::redacted::sha256_hex(&buf)
}

/// Seal event `kind` over `row` at `held`'s chain position, stamped `ts`.
fn seal(held: &Held, row: &TaskRow, kind: &str, request_id: &str, ts: u64) -> TaskEventRow {
    let mut ev = TaskEventRow {
        task_id: row.task_id.clone(),
        seq: held.next_seq,
        ts,
        kind: kind.to_string(),
        context_id: row.context_id.clone(),
        principal: row.principal.clone(),
        agent_id: row.agent_id.clone(),
        state: row.state.clone(),
        request_id: request_id.to_string(),
        prev_hash: held.tail_hash.clone(),
        hash: String::new(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    };
    ev.hash = digest(&ev);
    ev
}

/// `caller`'s task `task` as held, or `None`: absent, another caller's, unreadable, or past its
/// window at `now`. One answer for all of them, so a read is no existence oracle.
///
/// # Errors
/// [`Halt`].
pub fn get(
    rec: &mut dyn Records,
    caller: &str,
    task: &str,
    now: u64,
) -> Result<Option<Held>, Halt> {
    if !is_caller(caller) {
        return Ok(None);
    }
    Ok(rec
        .get(KIND_TASK, &task_key(caller, task))?
        .and_then(|b| decode(&b))
        .filter(|h| !expired(&h.row, now)))
}

/// Every task `caller` holds at `now`, by task id.
///
/// # Errors
/// [`Halt`].
pub fn list(rec: &mut dyn Records, caller: &str, now: u64) -> Result<Vec<TaskRow>, Halt> {
    if !is_caller(caller) {
        return Ok(Vec::new());
    }
    let mut rows: Vec<TaskRow> = rec
        .list(KIND_TASK, &scope(caller))?
        .into_iter()
        .filter_map(|(_, b)| decode(&b))
        .map(|h| h.row)
        .filter(|r| !expired(r, now))
        .collect();
    rows.sort_by(|a, b| a.task_id.cmp(&b.task_id));
    Ok(rows)
}

/// Who writes, for which request, and when: what every change of a task is stamped with.
#[derive(Debug, Clone, Copy)]
pub struct Step<'a> {
    /// The caller's reference: the key prefix.
    pub caller: &'a str,
    /// The request the change belongs to (joins the event to its records; not chained).
    pub request_id: &'a str,
    /// Now, in seconds: the event's stamp.
    pub now: u64,
}

/// Win `held`'s next sequence and write the change: `row` as the task, and the event `kind` sealed
/// over it. `false` when another writer won the sequence first.
fn commit(
    rec: &mut dyn Records,
    at: &Step<'_>,
    held: &Held,
    row: TaskRow,
    kind: &str,
    out: &mut Vec<Write>,
) -> Result<bool, Halt> {
    let key = event_key(at.caller, &row.task_id, held.next_seq);
    if !rec.claim(KIND_TASK_EVENT, &key, CLAIM_TTL_MS)? {
        return Ok(false);
    }
    let ev = seal(held, &row, kind, at.request_id, at.now);
    let next = Held {
        next_seq: held.next_seq.saturating_add(1),
        tail_hash: ev.hash.clone(),
        row,
    };
    out.push(Write {
        kind: KIND_TASK,
        key: task_key(at.caller, &next.row.task_id),
        value: encode(&next)?,
    });
    out.push(Write {
        kind: KIND_TASK_EVENT,
        key,
        value: encode(&ev)?,
    });
    Ok(true)
}

/// SUBMIT `row` for the caller: the task, and its chain's genesis event, stamped with the row's
/// `created_at`. The row is the caller's (its `principal` is the caller's reference).
///
/// # Errors
/// [`Halt`]; `Failed` when there is no caller or the task id is already taken.
pub fn submit(
    rec: &mut dyn Records,
    at: &Step<'_>,
    mut row: TaskRow,
    out: &mut Vec<Write>,
) -> Result<TaskRow, Halt> {
    if !is_caller(at.caller) {
        return Err(Halt::Failed("no caller to hold the task under".into()));
    }
    row.principal = at.caller.to_string();
    let genesis = Held {
        row: row.clone(),
        next_seq: 1,
        tail_hash: String::new(),
    };
    let at = Step {
        now: row.created_at,
        ..*at
    };
    if commit(rec, &at, &genesis, row.clone(), EV_SUBMITTED, out)? {
        Ok(row)
    } else {
        Err(Halt::Failed(format!(
            "task `{}` already exists",
            row.task_id
        )))
    }
}

/// What a change does to one held row: the new row and its event, `None` for nothing to do, or the
/// refusal's words.
pub type Planned = Result<Option<(TaskRow, &'static str)>, String>;

/// A change's plan over the held row.
pub type Plan<'p> = dyn FnMut(&TaskRow) -> Planned + 'p;

/// CHANGE task `task` by `plan`, race-safe: read, plan, win the sequence, write; a lost sequence
/// re-reads and plans again. `None` when the plan had nothing to do.
///
/// # Errors
/// [`Halt`]; `Failed` for no such task, a refused plan, or a sequence lost [`TRIES`] times.
pub fn change(
    rec: &mut dyn Records,
    at: &Step<'_>,
    task: &str,
    plan: &mut Plan<'_>,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    for _ in 0..TRIES {
        let Some(held) = get(rec, at.caller, task, at.now)? else {
            return Err(Halt::Failed(format!("no such task `{task}`")));
        };
        let Some((row, kind)) = plan(&held.row).map_err(Halt::Failed)? else {
            return Ok(None);
        };
        if commit(rec, at, &held, row.clone(), kind, out)? {
            return Ok(Some(row));
        }
    }
    Err(Halt::Failed(format!(
        "task `{task}` kept changing under this write"
    )))
}

/// TRANSITION task `task` to `to`, with the event the move names.
///
/// # Errors
/// As [`change`]; an illegal move is `Failed` in the state machine's words.
pub fn transition(
    rec: &mut dyn Records,
    at: &Step<'_>,
    task: &str,
    to: TaskState,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned { plan_transition(to, at.now)(row).map(Some) };
    change(rec, at, task, &mut plan, out)
}

/// DISPATCH: record the agent the task went to, with a `task.delegated` event.
///
/// # Errors
/// As [`change`].
pub fn dispatch(
    rec: &mut dyn Records,
    at: &Step<'_>,
    task: &str,
    agent_id: &str,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned {
        let mut next = row.clone();
        next.agent_id = agent_id.to_string();
        next.updated_at = at.now;
        Ok(Some((next, EV_DELEGATED)))
    };
    change(rec, at, task, &mut plan, out)
}

/// ADVANCE the artifact cursor to `cursor`, monotonic, with a `task.artifact` event; nothing when it
/// would not move forward.
///
/// # Errors
/// As [`change`].
pub fn advance_cursor(
    rec: &mut dyn Records,
    at: &Step<'_>,
    task: &str,
    cursor: u64,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned {
        if cursor <= row.artifact_cursor {
            return Ok(None);
        }
        let mut next = row.clone();
        next.artifact_cursor = cursor;
        next.updated_at = at.now;
        Ok(Some((next, EV_ARTIFACT)))
    };
    change(rec, at, task, &mut plan, out)
}

/// RECORD one push delivery outcome `kind` on the task's chain; the row itself is unchanged.
///
/// # Errors
/// As [`change`].
pub fn record_push_delivery(
    rec: &mut dyn Records,
    at: &Step<'_>,
    task: &str,
    kind: &'static str,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    let mut plan = |row: &TaskRow| -> Planned { Ok(Some((row.clone(), kind))) };
    change(rec, at, task, &mut plan, out).map(|_| ())
}

/// THE RETENTION SWEEP at `now`, over every task this instance holds: an active task unchanged for
/// longer than [`ABANDON_SECS`] is canceled through its chain; a terminal one past its window is
/// tombstoned with its events and its push config; while [`MAX_RETAINED`] or more are held, the
/// oldest terminal ones go too. At most `budget` tasks are touched; the rest wait for the next sweep.
///
/// # Errors
/// [`Halt`].
pub fn sweep(
    rec: &mut dyn Records,
    now: u64,
    budget: usize,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    let mut held: Vec<(String, TaskRow)> = rec
        .list(KIND_TASK, "")?
        .into_iter()
        .filter_map(|(k, b)| Some((k.split_once('/')?.0.to_string(), decode(&b)?.row)))
        .collect();
    held.sort_by(|a, b| (a.1.updated_at, &a.1.task_id).cmp(&(b.1.updated_at, &b.1.task_id)));
    let mut touched = 0usize;
    for (caller, row) in &held {
        if touched < budget
            && !terminal(&row.state)
            && now.saturating_sub(row.updated_at) > ABANDON_SECS
        {
            let at = Step {
                caller,
                request_id: "",
                now,
            };
            // An abandon that cannot be made leaves the task active for the next sweep.
            if let Err(Halt::Pending) = transition(rec, &at, &row.task_id, TaskState::Canceled, out)
            {
                return Err(Halt::Pending);
            }
            touched += 1;
        }
    }
    let mut kept = held.len();
    for (caller, row) in &held {
        if touched < budget && terminal(&row.state) && (kept >= MAX_RETAINED || expired(row, now)) {
            forget(rec, caller, &row.task_id, out)?;
            kept -= 1;
            touched += 1;
        }
    }
    Ok(())
}

/// Tombstone `caller`'s task `task`, its events and its push config.
fn forget(
    rec: &mut dyn Records,
    caller: &str,
    task: &str,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    let events = format!("{}/", task_key(caller, task));
    for (key, _) in rec.list(KIND_TASK_EVENT, &events)? {
        // Only this task's own events: what follows the prefix is a sequence, all digits.
        if key
            .strip_prefix(&events)
            .is_some_and(|seq| seq.bytes().all(|b| b.is_ascii_digit()))
        {
            out.push(Write {
                kind: KIND_TASK_EVENT,
                key,
                value: Vec::new(),
            });
        }
    }
    for kind in [KIND_TASK, KIND_PUSH_CONFIG] {
        out.push(Write {
            kind,
            key: task_key(caller, task),
            value: Vec::new(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/tasks.rs"]
pub(crate) mod tests;
