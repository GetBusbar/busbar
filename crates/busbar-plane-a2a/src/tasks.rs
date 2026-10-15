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
//! * THE HASH CHAIN IS THE HOST'S (ARCHITECT ruling B1, 2026-10-07; `BUSBAR-1.6.0.md` Part 3, the chain section):
//!   the task-event kind is declared chained, length-prefixed with its scope digested
//!   (`crate::door_statement`'s `RECORD_CHAINS`; B1 ruling 1, coordinator 2026-10-07). An event is an APPEND
//!   to the chain keyed `<caller>/<task>` (`<caller>` the kernel's opaque caller reference, never
//!   the principal) carrying only its own fields ([`suffix`]); the host frames `prev, scope, seq`
//!   ahead of them,
//!   seals, keeps and verifies the chain. The task record carries the chain's next sequence, which
//!   a change claims to stay race-safe.
//! * RESTORE ([`restore`]) is the engine's boot rehydrate over the records: the tasks counted
//!   active, terminal or unreadable, and every active task's chain read back verified by the host,
//!   a break named so the door reports it.
//! * A DELETE IS A TOMBSTONE: a put with an empty value, which the kernel's reads treat as absent;
//!   on the chained kind it drops the whole chain.
//! * RETENTION bounds only SETTLED handles ([`TERMINAL_TTL_SECS`], [`MAX_RETAINED`]; spec
//!   docs/design/BUSBAR-1.6.0.md :198-203, Q128 K2-H5, coordinator 2026-10-07): a read never answers
//!   a terminal task past its window, and [`retention_sweep`] tombstones it and holds the cap over terminal
//!   tasks. An active task is never evicted however long it sits idle; live tasks are bounded at
//!   admission by the kernel's `work.max_live`.

use busbar_contract::vocab::{EV_ARTIFACT, EV_DELEGATED, EV_SUBMITTED};
use serde::{Deserialize, Serialize};

use crate::a2a::task::{plan_transition, readable_row, TaskState};
use crate::record::DIGEST_VERSION_LEN_PREFIXED;
use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT};
use crate::{TaskEventRow, TaskRow};

/// How long a terminal task stays readable after its terminal transition, in seconds.
pub const TERMINAL_TTL_SECS: u64 = 300;
/// The most terminal tasks kept; past it the oldest go first. An active task is never counted
/// against it and never evicted.
pub const MAX_RETAINED: usize = 4096;
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

/// THE RECORDS AS ONE PIECE SEES THEM ONCE IT HAS WRITTEN: a read of a record the piece already
/// wrote answers that write, so several changes of one chain in one answer chain over each other
/// (each claims the sequence the one before it left) rather than over the store's older value. Any
/// other read and every claim go to the host.
pub struct Staged<'r> {
    rec: &'r mut dyn Records,
    written: &'r [Write],
}

impl<'r> Staged<'r> {
    /// `rec`, seen through the `written` writes of the piece so far.
    pub fn new(rec: &'r mut dyn Records, written: &'r [Write]) -> Self {
        Self { rec, written }
    }
}

/// Whether `kind` is the chained kind: its writes are appends the host seals once the store took
/// them, so a read never answers them from the piece's writes.
fn chained(kind: &str) -> bool {
    kind == KIND_TASK_EVENT
}

impl Records for Staged<'_> {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        match self
            .written
            .iter()
            .rev()
            .find(|w| !chained(w.kind) && w.kind == kind && w.key == key)
        {
            Some(w) if w.value.is_empty() => Ok(None),
            Some(w) => Ok(Some(w.value.clone())),
            None => self.rec.get(kind, key),
        }
    }

    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        let mut listed: std::collections::BTreeMap<String, Vec<u8>> =
            self.rec.list(kind, prefix)?.into_iter().collect();
        for w in self
            .written
            .iter()
            .filter(|w| !chained(w.kind) && w.kind == kind && w.key.starts_with(prefix))
        {
            if w.value.is_empty() {
                listed.remove(&w.key);
            } else {
                listed.insert(w.key.clone(), w.value.clone());
            }
        }
        Ok(listed.into_iter().collect())
    }

    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.rec.claim(kind, key, ttl_ms)
    }
}

/// One record write the answer carries out: a `RECORD_PUT`; an empty value is a tombstone. On the
/// chained kind it is an append to the chain `key` names (an empty value drops the chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    /// The record kind.
    pub kind: &'static str,
    /// The key.
    pub key: String,
    /// The value; empty = tombstone.
    pub value: Vec<u8>,
}

/// A TASK AS IT IS HELD: the row, and the sequence its chain's next event takes (the host holds the
/// chain itself; the sequence is what a change claims).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldTask {
    /// The row.
    #[serde(flatten)]
    pub row: TaskRow,
    /// The sequence the next event takes.
    pub next_seq: u64,
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

/// The key of event `seq` of `caller`'s task `task`: the host's listed key of record `seq` of the
/// chain `<caller>/<task>` (`busbar_contract::services::chain_key`), and the key a change claims
/// the sequence under.
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

fn decode(bytes: &[u8]) -> Option<HeldTask> {
    serde_json::from_slice(bytes).ok()
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, Halt> {
    serde_json::to_vec(v).map_err(|e| Halt::Failed(e.to_string()))
}

/// ONE EVENT'S OWN BYTES on its task's chain, in the declared length-prefixed framing (B1 ruling
/// 1, coordinator 2026-10-07): `ts` (its eight big-endian bytes), `kind`, `context_id`,
/// `principal`, `agent_id`, `state`, each after its length as eight big-endian bytes. The host
/// frames `prev_hash`, the chain's scope (`<caller>/<task>`) and `seq` the same way ahead of them,
/// so the digest covers the engine's fields in the engine's order and no byte can cross a field
/// boundary unseen. `request_id` is a join key nothing reads back, and is not kept (B1 ruling 2).
#[must_use]
pub fn suffix(ev: &TaskEventRow) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(&ev.ts.to_be_bytes());
    for text in [
        &ev.kind,
        &ev.context_id,
        &ev.principal,
        &ev.agent_id,
        &ev.state,
    ] {
        field(text.as_bytes());
    }
    out
}

/// Event `kind` over `row` at `held`'s chain position, stamped `ts`; its chain fields are the
/// host's.
fn seal_event(
    held: &HeldTask,
    row: &TaskRow,
    kind: &str,
    request_id: &str,
    ts: u64,
) -> TaskEventRow {
    TaskEventRow {
        task_id: row.task_id.clone(),
        seq: held.next_seq,
        ts,
        kind: kind.to_string(),
        context_id: row.context_id.clone(),
        principal: row.principal.clone(),
        agent_id: row.agent_id.clone(),
        state: row.state.clone(),
        request_id: request_id.to_string(),
        prev_hash: String::new(),
        hash: String::new(),
        digest_version: DIGEST_VERSION_LEN_PREFIXED,
    }
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
) -> Result<Option<HeldTask>, Halt> {
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

/// What a [`restore`] found: the engine's boot rehydrate counts, over the records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
    /// Tasks in flight: their chains were read back verified.
    pub active: usize,
    /// Terminal tasks: counted, deliberately not read further (nothing resumes them, and their
    /// rows stay for the provenance window).
    pub terminal: usize,
    /// Task rows this build cannot read back: counted, never skipped silently.
    pub unreadable: usize,
    /// The in-flight tasks whose chain the host reported broken: the chain's scope
    /// (`<caller>/<task>`) and the break in the host's words. The task is still held: a break is
    /// reported, never a deletion.
    pub chain_breaks: Vec<(String, String)>,
}

/// THE RESTORE (the engine's `restore_from_store`, over host records): every task row read and
/// counted active, terminal or unreadable; then every chain read back through the host, which
/// verifies each, and a break the host announces on an in-flight task's chain is named. Nothing is
/// written.
///
/// # Errors
/// [`Halt`].
pub fn restore(rec: &mut dyn Records) -> Result<Restored, Halt> {
    let mut out = Restored::default();
    let mut active = std::collections::BTreeSet::new();
    for (key, bytes) in rec.list(KIND_TASK, "")? {
        let Some(held) = decode(&bytes).filter(|h| readable_row(&h.row).is_ok()) else {
            out.unreadable += 1;
            continue;
        };
        if terminal(&held.row.state) {
            out.terminal += 1;
        } else {
            out.active += 1;
            active.insert(key);
        }
    }
    for (key, words) in rec.list(KIND_TASK_EVENT, "")? {
        // A record's key ends in its sequence; a span keyed by a bare scope announces that chain's
        // break.
        if busbar_contract::services::chain_key_parts(key.as_bytes()).is_none()
            && active.contains(&key)
        {
            out.chain_breaks
                .push((key, String::from_utf8_lossy(&words).into_owned()));
        }
    }
    Ok(out)
}

/// Who writes, for which request, and when: what every change of a task is stamped with.
#[derive(Debug, Clone, Copy)]
pub struct Stamp<'a> {
    /// The caller's reference: the key prefix.
    pub caller: &'a str,
    /// The request the change belongs to (joins the event to its records; not chained).
    pub request_id: &'a str,
    /// Now, in seconds: the event's stamp.
    pub now: u64,
}

/// Win `held`'s next sequence and write the change: `row` as the task, and the event `kind` sealed
/// over it. The task as now held, or `None` when another writer won the sequence first.
fn commit(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    held: &HeldTask,
    row: TaskRow,
    kind: &str,
    out: &mut Vec<Write>,
) -> Result<Option<HeldTask>, Halt> {
    let key = event_key(at.caller, &row.task_id, held.next_seq);
    if !rec.claim(KIND_TASK_EVENT, &key, CLAIM_TTL_MS)? {
        return Ok(None);
    }
    let ev = seal_event(held, &row, kind, at.request_id, at.now);
    let next = HeldTask {
        next_seq: held.next_seq.saturating_add(1),
        row,
    };
    out.push(Write {
        kind: KIND_TASK,
        key: task_key(at.caller, &next.row.task_id),
        value: encode(&next)?,
    });
    out.push(Write {
        kind: KIND_TASK_EVENT,
        key: task_key(at.caller, &next.row.task_id),
        value: suffix(&ev),
    });
    Ok(Some(next))
}

/// SUBMIT `row` for the caller: the task, and its chain's genesis event, stamped with the row's
/// `created_at`. The row is the caller's (its `principal` is the caller's reference).
///
/// # Errors
/// [`Halt`]; `Failed` when there is no caller or the task id is already taken.
pub fn submit(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    mut row: TaskRow,
    out: &mut Vec<Write>,
) -> Result<TaskRow, Halt> {
    if !is_caller(at.caller) {
        return Err(Halt::Failed("no caller to hold the task under".into()));
    }
    row.principal = at.caller.to_string();
    let genesis = HeldTask {
        row: row.clone(),
        next_seq: 1,
    };
    let at = Stamp {
        now: row.created_at,
        ..*at
    };
    submit_held(rec, &at, &genesis, row, out).map(|held| held.row)
}

/// The genesis commit of [`submit`], answering the task as held.
fn submit_held(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    genesis: &HeldTask,
    row: TaskRow,
    out: &mut Vec<Write>,
) -> Result<HeldTask, Halt> {
    let id = row.task_id.clone();
    commit(rec, at, genesis, row, EV_SUBMITTED, out)?
        .ok_or_else(|| Halt::Failed(format!("task `{id}` already exists")))
}

/// OPEN a relayed task: SUBMIT `row` for the caller, then record its DISPATCH to `agent_id` on the
/// chain the submit just started (the engine's submit then `record_dispatch`, both before the
/// hop). Both events are written in this one answer, so the dispatch is sealed over the genesis
/// held here rather than read back. A dispatch that cannot be recorded leaves the submitted task.
///
/// # Errors
/// As [`submit`].
pub fn open(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    mut row: TaskRow,
    agent_id: &str,
    out: &mut Vec<Write>,
) -> Result<TaskRow, Halt> {
    if !is_caller(at.caller) {
        return Err(Halt::Failed("no caller to hold the task under".into()));
    }
    row.principal = at.caller.to_string();
    let genesis = HeldTask {
        row: row.clone(),
        next_seq: 1,
    };
    let stamped = Stamp {
        now: row.created_at,
        ..*at
    };
    let held = submit_held(rec, &stamped, &genesis, row, out)?;
    let mut next = held.row.clone();
    next.agent_id = agent_id.to_string();
    next.updated_at = at.now;
    match commit(rec, at, &held, next, EV_DELEGATED, out) {
        Ok(Some(dispatched)) => Ok(dispatched.row),
        Ok(None) | Err(Halt::Failed(_)) => Ok(held.row),
        Err(Halt::Pending) => Err(Halt::Pending),
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
    at: &Stamp<'_>,
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
        if commit(rec, at, &held, row.clone(), kind, out)?.is_some() {
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
    at: &Stamp<'_>,
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
    at: &Stamp<'_>,
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

/// REGISTER `callback` as task `task`'s push callback (the engine's `set_push_callback`): the row
/// changes and no event is chained, so the chain's position is kept. `None` when the caller holds
/// no such task.
///
/// # Errors
/// [`Halt`].
pub fn set_callback(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    callback: &str,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let Some(mut held) = get(rec, at.caller, task, at.now)? else {
        return Ok(None);
    };
    held.row.push_callback = callback.to_string();
    held.row.updated_at = at.now;
    out.push(Write {
        kind: KIND_TASK,
        key: task_key(at.caller, task),
        value: encode(&held)?,
    });
    Ok(Some(held.row))
}

/// ADVANCE the artifact cursor to `cursor`, monotonic, with a `task.artifact` event; nothing when it
/// would not move forward.
///
/// # Errors
/// As [`change`].
pub fn advance_cursor(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
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

/// ADVANCE the artifact cursor by one chunk, with a `task.artifact` event: the engine's advance per
/// relayed artifact event, counted on from where the task left off (a resumed stream does not count
/// from zero).
///
/// # Errors
/// As [`change`].
pub fn bump_cursor(
    rec: &mut dyn Records,
    at: &Stamp<'_>,
    task: &str,
    out: &mut Vec<Write>,
) -> Result<Option<TaskRow>, Halt> {
    let mut plan = |row: &TaskRow| -> Planned {
        let mut next = row.clone();
        next.artifact_cursor = row.artifact_cursor.saturating_add(1);
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
    at: &Stamp<'_>,
    task: &str,
    kind: &'static str,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    let mut plan = |row: &TaskRow| -> Planned { Ok(Some((row.clone(), kind))) };
    change(rec, at, task, &mut plan, out).map(|_| ())
}

/// THE RETENTION SWEEP at `now`, over the TERMINAL tasks this instance holds and no others: one
/// past its window is tombstoned with its events and its push config; while [`MAX_RETAINED`] or
/// more terminal ones are held, the oldest go too. An active task is never touched, however long
/// it has been idle (Q128 K2-H5, coordinator 2026-10-07; spec :198-203). At most `budget` tasks are
/// touched; the rest wait for the next sweep.
///
/// # Errors
/// [`Halt`].
pub fn retention_sweep(
    rec: &mut dyn Records,
    now: u64,
    budget: usize,
    out: &mut Vec<Write>,
) -> Result<(), Halt> {
    let mut held: Vec<(String, TaskRow)> = rec
        .list(KIND_TASK, "")?
        .into_iter()
        .filter_map(|(k, b)| Some((k.split_once('/')?.0.to_string(), decode(&b)?.row)))
        .filter(|(_, row)| terminal(&row.state))
        .collect();
    held.sort_by(|a, b| (a.1.updated_at, &a.1.task_id).cmp(&(b.1.updated_at, &b.1.task_id)));
    let mut touched = 0usize;
    let mut kept = held.len();
    for (caller, row) in &held {
        if touched < budget && (kept >= MAX_RETAINED || expired(row, now)) {
            forget(caller, &row.task_id, out);
            kept -= 1;
            touched += 1;
        }
    }
    Ok(())
}

/// Tombstone `caller`'s task `task`, its push config, and its events (the chain dropped whole).
fn forget(caller: &str, task: &str, out: &mut Vec<Write>) {
    for kind in [KIND_TASK_EVENT, KIND_TASK, KIND_PUSH_CONFIG] {
        out.push(Write {
            kind,
            key: task_key(caller, task),
            value: Vec::new(),
        });
    }
}

#[cfg(test)]
#[path = "tests/tasks.rs"]
pub(crate) mod tests;
