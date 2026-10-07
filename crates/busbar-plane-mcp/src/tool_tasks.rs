// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEP-2663 — THE TASKS EXTENSION on the MCP door, pure: the task's state, its two wire shapes, its
//! lifecycle transitions, the retention sweep and the durable rows a task is kept in. The served
//! engine's task registry (`busbar-mcp` `tasks.rs`), ported; the door half that runs a task is
//! `tool_door`'s `door_tasks`.
//!
//! A `tools/call` on a tool whose operator wrote `tools_allow.<tool>.task_support: optional` or
//! `required`, from a caller that declared the extension in
//! `params._meta['io.modelcontextprotocol/clientCapabilities'].extensions`, is answered with a
//! `CreateTaskResult` instead of a result: the caller is handed a `taskId` and polls `tasks/get`
//! until the task reaches a terminal state, at which point the tool result is INLINED on the poll
//! response. `tasks/update` delivers input the task asked for; `tasks/cancel` stops it. There is no
//! `tasks/result` and no `tasks/list` (the v2 wire removed both; `-32601` to them is deliberate).
//!
//! ## WHO RUNS A TASK (ARCHITECT round 5 Q-L3B-TASKS (b) → (A))
//!
//! THE DESIGN: "a work continuation is a NEW unit with its own arrival, admission and window; its
//! principal is the one its work handle recorded", and "a continuation runs as a child unit whose
//! parent has exited, so it files under the late-arm rules". The creating unit opens a durable work
//! handle (`work.open`: the handle's REFERENCE is the `taskId`), nests the continuation on the
//! plane's own task-run claim (`unit.nest`) carrying the reference, and answers. The continuation
//! binds the handle (`work.resume`, principal-checked), takes the run once (`records.claim`), runs
//! the call to its end under its own admission and window, and settles the handle (`work.settle`).
//! `tasks/get` is `work.find` plus what the task holds; `tasks/cancel` is a settle the running
//! continuation observes on its next step.
//!
//! ## WHAT THE STATUSES MEAN, and the one distinction that is easy to get backwards
//!
//! A tool that RAN and reported a failure is `completed` with `result.isError: true`. It is NOT
//! `failed`. `failed` is reserved for a PROTOCOL-level error — the upstream answered a JSON-RPC
//! error, the transport broke, busbar refused to carry the dispatch — and inlines an `error`
//! object with a numeric `code` and a `message`, carrying no `result` at all.
//!
//! ## DURABILITY
//!
//! The served engine's registry was in-process: a restart lost every task. Here THE TASK STORE IS
//! HOST RECORDS (THE DESIGN §2, the mcp bullet): the handle is the kernel's (durable, scoped to the
//! instance and the principal); a live task's state — its status, its `inputRequests`, the answers
//! it holds, the upstream ask it is parked on — is written to the plane's own records in chunks
//! ([`live_parts`]) by every unit that moves it; and a terminal task's result likewise
//! ([`result_chunks`]). So `tasks/get`, `tasks/update` and `tasks/cancel` answer a task from any
//! node and across a restart; what an instance holds of a task is a cache of those rows, plus the
//! halves only its own process has (the run it took, the unit running it).
//!
//! Every live task is indexed under its caller in the plane's records with its run's LEASE
//! ([`Lease`]). A task-creating call settles, `cancelled`, every live task of its caller no process
//! holds whose lease lapsed or that nothing moved past the abandonment ceiling: the handles a
//! process that is gone left behind never exhaust the bound of live work (§1, "Admission bounds
//! live work; nothing evicts it").
//!
//! What IS honoured unconditionally is STRONG CONSISTENCY: the creating unit holds the task before
//! the caller is handed its id, so a `tasks/get` issued with no delay between the two resolves.

use std::collections::BTreeMap;

use busbar_contract::abi::mechanism::ticket::Ticket;
use serde_json::{json, Map, Value};

use crate::ask::CallerAsk;

/// How long a task stays readable through `tasks/get` after it settles (the `ttlMs` every task
/// shape states): the work handles' retention, which the plane's `work: {retain_s}` bounds and
/// whose default is this.
///
/// A POSITIVE value, unlike the catalogue's `ttlMs: 0`, and the difference is not an
/// inconsistency: the catalogue's zero says "this answer may already be stale", a claim about
/// freshness; this one says "the server keeps this row for at least this long", a claim about
/// RETENTION.
pub const TASK_TTL_MS: u64 = 300_000;

/// The poll cadence busbar suggests. Advisory — a client that polls faster is not refused.
pub const TASK_POLL_INTERVAL_MS: u64 = 250;

/// The ceiling on tasks the instance keeps in hand at once: the work handles' live bound, whose
/// default is this. The oldest TERMINAL tasks are dropped first, and a working task is never
/// dropped to make room.
pub const MAX_RETAINED_TASKS: usize = 4096;

/// The ABANDONMENT ceiling on an ACTIVE task: one whose last update is older than this is treated
/// as abandoned by its caller and cancelled (a transition, never a drop), after which the ordinary
/// retention applies. A full day: an `input_required` park waiting on a human legitimately sits
/// for hours, but not for days. Enforced by the create-time sweep (no timer to schedule or leak).
pub const ACTIVE_TASK_ABANDON_MS: u64 = 86_400_000;

/// THE CEILING ON DISTINCT ANSWER KEYS one task retains: `tasks/update` delivers `inputResponses`
/// under keys of the caller's own choosing, so without a ceiling a caller parked in
/// `input_required` could grow one task's map without bound.
pub const MAX_TASK_ANSWERS: usize = 256;

/// The JSON-RPC code a `failed` task inlines: `-32603` (internal error), because what is reported
/// is that busbar could not carry the dispatch to an answer, and the caller has no parameter to
/// correct.
pub const TASK_PROTOCOL_ERROR_CODE: i64 = -32603;

/// How long the continuation's one-time run claim stands: past any live task's abandonment and its
/// retention after, so a task cannot be run twice while its handle can still be found.
pub const RUN_CLAIM_TTL_MS: u64 = ACTIVE_TASK_ABANDON_MS + TASK_TTL_MS;

/// How long the state a task's relayed ask is answered under stands, in seconds: as long as the task
/// may stay parked on its caller ([`ACTIVE_TASK_ABANDON_MS`]), a human's answer included.
pub const TASK_RELAY_TTL_SECS: u64 = ACTIVE_TASK_ABANDON_MS / 1000;

/// The bytes of one result chunk: a plane record holds at most
/// [`busbar_contract::bounded::MAX_RECORD_BYTES`].
pub const RESULT_CHUNK_BYTES: usize = 480;

/// The most chunks one task's result is written in; a longer result is answered while the task is
/// in hand and is not written.
pub const MAX_RESULT_CHUNKS: usize = 256;

/// THE RUN'S LEASE beyond its server's own `timeout:`: how long a task's run may go unheard from
/// before another process takes its handle as left behind (the process running it gone) and settles
/// it `cancelled`. Taken when the continuation is nested and renewed as each call goes out.
pub const RUN_LEASE_MS: u64 = 300_000;

/// The live-state chunks a settle strikes at the least: what a process that did not write a task's
/// live state strikes of it.
pub const LIVE_STRIKES: u32 = 4;

/// A task's lifecycle state, as the wire spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Running.
    Working,
    /// Parked on input busbar asked its caller for. `tasks/update` is what un-parks it.
    InputRequired,
    /// The tool RAN. Whether it reported success or an error of its own is in `result.isError`.
    Completed,
    /// A PROTOCOL-level failure. Carries `error`, never `result`.
    Failed,
    /// Cancelled by `tasks/cancel` (or abandoned, or the continuation stopped with it running).
    Cancelled,
}

impl Status {
    /// The wire token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Status::Working => "working",
            Status::InputRequired => "input_required",
            Status::Completed => "completed",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
        }
    }

    /// The status a token names.
    #[must_use]
    pub fn of_token(token: &str) -> Option<Self> {
        [
            Status::Working,
            Status::InputRequired,
            Status::Completed,
            Status::Failed,
            Status::Cancelled,
        ]
        .into_iter()
        .find(|s| s.token() == token)
    }

    /// Terminal states are the three a task never leaves. `tasks/cancel` on one of them is an
    /// idempotent no-op rather than an error.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Status::Completed | Status::Failed | Status::Cancelled)
    }
}

/// ONE MCP task, as the instance holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Task {
    /// The `taskId`: the work handle's reference.
    pub id: String,
    /// The principal it was created for. A caller may only ever address its own tasks, and an id
    /// belonging to somebody else is answered as UNKNOWN rather than as forbidden.
    principal: String,
    /// The work handle (process-local) the reference was opened or found as.
    pub handle: u64,
    /// The digest of the call it runs ([`run_digest`]), as its durable row states it.
    digest: String,
    status: Status,
    /// Unix milliseconds, from the kernel's one clock. Rendered ISO-8601 on the wire.
    created_ms: u64,
    updated_ms: u64,
    /// The inlined tool result, present only on `completed`.
    result: Option<Value>,
    /// The inlined protocol error, present only on `failed`.
    error: Option<Value>,
    /// The still-unanswered asks of the current round, in the operator's own order. Answering a key
    /// REMOVES it, which is what makes partial fulfilment observable.
    input_requests: Vec<(String, Value)>,
    /// Everything the caller has answered so far, keyed as the operator keyed the ask.
    answers: Map<String, Value>,
    /// The continuation took the run: the local half of its one-time start.
    pub started: bool,
    /// The continuation's unit and the ticket it is woken on, while it runs.
    pub runner: Option<(u64, Ticket)>,
    /// The terminal state was reached in hand and the durable handle not yet settled with it.
    pub unsettled: bool,
    /// How many result chunks were written for it.
    pub chunks: u32,
    /// THE UPSTREAM'S ASK IT IS PARKED ON, relayed (Law 11): answered through `tasks/update` and
    /// carried back to the member that asked, never merged into the tool's arguments.
    relay: Option<RelayPark>,
    /// THE ROUND OF ITS OWN ASKS IT IS PARKED ON, and the call its run resumes with: the
    /// continuation ended with the handle live, and the `tasks/update` that answers the round
    /// nests the resume.
    pub asked: Option<(usize, Value)>,
    /// How many live-state chunks this instance wrote for it.
    pub live_chunks: u32,
}

/// A TASK PARKED ON ITS UPSTREAM'S ASK: busbar's sealed state (bound to the principal, the tool and
/// the member, nesting the upstream's own), the call the retry runs, the upstream's keys and the
/// caller's answers to them so far.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayPark {
    /// Busbar's sealed state the retry presents.
    pub state: String,
    /// The call the continuation runs (its digest is the task's).
    pub params: Value,
    /// The upstream's `inputRequests` keys, in its order.
    keys: Vec<String>,
    /// The caller's answers, by the upstream's keys.
    pub responses: Map<String, Value>,
}

impl Task {
    /// A working task `id` for `principal`, on work handle `handle`, running the call `digest`
    /// names, created at `now_ms`.
    #[must_use]
    pub fn new(id: &str, principal: &str, handle: u64, digest: &str, now_ms: u64) -> Self {
        Task {
            id: id.to_string(),
            principal: principal.to_string(),
            handle,
            digest: digest.to_string(),
            status: Status::Working,
            created_ms: now_ms,
            updated_ms: now_ms,
            result: None,
            error: None,
            input_requests: Vec::new(),
            answers: Map::new(),
            started: false,
            runner: None,
            unsettled: false,
            chunks: 0,
            relay: None,
            asked: None,
            live_chunks: 0,
        }
    }

    /// A task read back from its durable row (`row`) and, for a terminal one, its result
    /// (`terminal`: `{"result": …}` or `{"error": …}`).
    #[must_use]
    pub fn from_row(
        id: &str,
        principal: &str,
        handle: u64,
        row: &WorkRow,
        terminal: Option<&Value>,
    ) -> Self {
        let mut task = Task::new(id, principal, handle, &row.digest, row.created_ms);
        task.status = row.status;
        task.updated_ms = row.updated_ms;
        task.started = true;
        if let Some(t) = terminal {
            task.result = t.get("result").cloned();
            task.error = t.get("error").cloned();
        }
        task
    }

    /// Whether `principal` may address this task.
    #[must_use]
    pub fn owned_by(&self, principal: &str) -> bool {
        self.principal == principal
    }

    /// The key of its index row ([`Lease`]) in the plane's records.
    #[must_use]
    pub fn index_key(&self) -> Vec<u8> {
        index_key(&self.principal, &self.id)
    }

    /// Whether it is parked on its upstream's ask.
    #[must_use]
    pub fn relayed(&self) -> bool {
        self.relay.is_some()
    }

    /// THE LIVE STATE its records keep ([`live_parts`]): its status and last update, its
    /// `inputRequests` in order, the answers it holds, the upstream ask and the round of its own
    /// asks it is parked on.
    #[must_use]
    pub fn live(&self) -> Value {
        let requests: Vec<Value> = self
            .input_requests
            .iter()
            .map(|(k, v)| json!([k, v]))
            .collect();
        json!({
            "status": self.status.token(),
            "updated": self.updated_ms,
            "requests": requests,
            "answers": self.answers,
            "relay": self.relay.as_ref().map(|p| json!({
                "state": p.state,
                "params": p.params,
                "keys": p.keys,
                "responses": p.responses,
            })),
            "asked": self.asked.as_ref().map(|(round, params)| json!([round, params])),
        })
    }

    /// The live state its records hold ([`Task::live`]'s document), laid over a task read from its
    /// row; a document that is not one leaves it as it is.
    pub fn take_live(&mut self, live: &Value) {
        let (Some(status), Some(updated)) = (
            live.get("status")
                .and_then(Value::as_str)
                .and_then(Status::of_token),
            live.get("updated").and_then(Value::as_u64),
        ) else {
            return;
        };
        self.status = status;
        self.updated_ms = updated;
        self.input_requests = live
            .get("requests")
            .and_then(Value::as_array)
            .map(|pairs| {
                pairs
                    .iter()
                    .filter_map(|p| {
                        let pair = p.as_array()?;
                        Some((pair.first()?.as_str()?.to_string(), pair.get(1)?.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.answers = live
            .get("answers")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        self.relay = live.get("relay").and_then(|r| {
            Some(RelayPark {
                state: r.get("state")?.as_str()?.to_string(),
                params: r.get("params")?.clone(),
                keys: r
                    .get("keys")?
                    .as_array()?
                    .iter()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect(),
                responses: r.get("responses")?.as_object()?.clone(),
            })
        });
        self.asked = live.get("asked").and_then(|a| {
            let pair = a.as_array()?;
            Some((
                usize::try_from(pair.first()?.as_u64()?).ok()?,
                pair.get(1)?.clone(),
            ))
        });
    }

    /// THE HOST'S WORD over what the instance holds of this task: `host` (read from its rows and
    /// records) replaces it, the instance keeping only its own halves — the run taken here, the unit
    /// running it, a settle still owed, the chunks it wrote.
    pub fn hosted(&mut self, host: Task) {
        let kept = (
            self.started,
            self.runner,
            self.unsettled,
            self.chunks,
            self.live_chunks,
        );
        *self = host;
        (
            self.started,
            self.runner,
            self.unsettled,
            self.chunks,
            self.live_chunks,
        ) = kept;
    }

    /// Its status.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }

    /// When it was created and last updated (Unix ms).
    #[must_use]
    pub fn stamps(&self) -> (u64, u64) {
        (self.created_ms, self.updated_ms)
    }

    /// The `DetailedTask` a `tasks/get` answers with, minus the `resultType` the response builder
    /// stamps. `requestState` is ABSENT and its absence is load-bearing: SEP-2663 removed it from
    /// the v2 wire.
    #[must_use]
    pub fn detailed(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("taskId".into(), self.id.clone().into());
        obj.insert("status".into(), self.status.token().into());
        obj.insert("createdAt".into(), iso8601_ms(self.created_ms).into());
        obj.insert("lastUpdatedAt".into(), iso8601_ms(self.updated_ms).into());
        obj.insert("ttlMs".into(), TASK_TTL_MS.into());
        obj.insert("pollIntervalMs".into(), TASK_POLL_INTERVAL_MS.into());
        if let Some(result) = &self.result {
            obj.insert("result".into(), result.clone());
        }
        if let Some(error) = &self.error {
            obj.insert("error".into(), error.clone());
        }
        if !self.input_requests.is_empty() {
            let map: Map<String, Value> = self.input_requests.iter().cloned().collect();
            obj.insert("inputRequests".into(), Value::Object(map));
        }
        Value::Object(obj)
    }

    /// The `CreateTaskResult` a `tools/call` answers with — a FLAT `Result & Task` intersection,
    /// carrying none of `result`, `error` or `inputRequests` (those are `tasks/get`'s), and an
    /// EMPTY `content`: the base revision's `CallToolResult` makes `content` required.
    #[must_use]
    pub fn created(&self) -> Value {
        json!({
            "taskId": self.id,
            "status": self.status.token(),
            "createdAt": iso8601_ms(self.created_ms),
            "lastUpdatedAt": iso8601_ms(self.updated_ms),
            "ttlMs": TASK_TTL_MS,
            "pollIntervalMs": TASK_POLL_INTERVAL_MS,
            "content": [],
        })
    }

    /// PARK on a round of asks. Any ask already answered by an earlier `tasks/update` is not
    /// re-asked; a round with nothing left to ask leaves the status alone.
    pub fn park(&mut self, asks: Vec<CallerAsk>, now_ms: u64) {
        if self.status.is_terminal() {
            return;
        }
        self.input_requests = asks
            .into_iter()
            .filter(|a| !self.answers.contains_key(a.key()))
            .map(|a| {
                (
                    a.key().to_string(),
                    json!({ "method": a.method(), "params": a.params() }),
                )
            })
            .collect();
        if !self.input_requests.is_empty() {
            self.status = Status::InputRequired;
            self.updated_ms = now_ms;
        }
    }

    /// PARK ON THE UPSTREAM'S ASK, relayed to the caller (Law 11): `input_required`, its
    /// `inputRequests` the upstream's own, verbatim and in its order, under busbar's sealed `state`;
    /// the retry runs `params`. A terminal task does not park.
    pub fn park_relay(
        &mut self,
        requests: &Map<String, Value>,
        state: String,
        params: Value,
        now_ms: u64,
    ) {
        if self.status.is_terminal() {
            return;
        }
        self.input_requests = requests
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.relay = Some(RelayPark {
            state,
            params,
            keys: requests.keys().cloned().collect(),
            responses: Map::new(),
        });
        self.status = Status::InputRequired;
        self.updated_ms = now_ms;
    }

    /// THE RELAYED ASK, ANSWERED: taken once every key the upstream asked is answered (the retry
    /// goes to the member with the caller's answers), `None` before, and `None` to any later caller.
    pub fn take_relay(&mut self) -> Option<RelayPark> {
        let park = self.relay.as_ref()?;
        if park.keys.iter().any(|k| !park.responses.contains_key(k)) {
            return None;
        }
        self.relay.take()
    }

    /// Deliver `inputResponses`. Keys the task is not waiting on are IGNORED rather than refused.
    /// On a task parked on its upstream's ask the answers are the upstream's: kept for the retry,
    /// never merged into the tool's arguments.
    ///
    /// Returns `false`, applying NOTHING, when this batch would grow the task's answer map past
    /// [`MAX_TASK_ANSWERS`] DISTINCT keys — refused whole, never truncated. A key already held is a
    /// REPEAT, not new, so re-answering one never counts against the ceiling.
    ///
    /// A TERMINAL task takes no input: the update is acknowledged and changes nothing.
    pub fn deliver(&mut self, responses: &Map<String, Value>, now_ms: u64) -> bool {
        if self.status.is_terminal() {
            return true;
        }
        if let Some(park) = self.relay.as_mut() {
            for (key, value) in responses {
                if park.keys.contains(key) {
                    park.responses.insert(key.clone(), value.clone());
                }
            }
            self.input_requests
                .retain(|(k, _)| !responses.contains_key(k));
            self.updated_ms = now_ms;
            if self.input_requests.is_empty() && self.status == Status::InputRequired {
                self.status = Status::Working;
            }
            return true;
        }
        let new_keys = responses
            .keys()
            .filter(|k| !self.answers.contains_key(k.as_str()))
            .count();
        if self.answers.len() + new_keys > MAX_TASK_ANSWERS {
            return false;
        }
        for (key, value) in responses {
            self.answers.insert(key.clone(), value.clone());
        }
        self.input_requests
            .retain(|(k, _)| !responses.contains_key(k));
        self.updated_ms = now_ms;
        if self.input_requests.is_empty() && self.status == Status::InputRequired {
            self.status = Status::Working;
        }
        true
    }

    /// Whether every ask of the current round is answered (or the task left `input_required` some
    /// other way).
    #[must_use]
    pub fn answered(&self) -> bool {
        self.input_requests.is_empty() || self.status.is_terminal()
    }

    /// The answers gathered so far, to merge into the tool arguments.
    #[must_use]
    pub fn answers(&self) -> &Map<String, Value> {
        &self.answers
    }

    /// Back to `working` (the asks are answered), unless terminal.
    pub fn set_working(&mut self, now_ms: u64) {
        if !self.status.is_terminal() {
            self.status = Status::Working;
            self.updated_ms = now_ms;
        }
    }

    /// The tool RAN. `result` is its own answer, `isError` and all. Whether this call made the
    /// transition.
    pub fn complete(&mut self, result: Value, now_ms: u64) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        self.status = Status::Completed;
        self.result = Some(result);
        self.input_requests.clear();
        self.relay = None;
        self.updated_ms = now_ms;
        true
    }

    /// A PROTOCOL-level failure: `error` only, never a `result` beside it. Whether this call made
    /// the transition.
    pub fn fail(&mut self, code: i64, message: String, now_ms: u64) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        self.status = Status::Failed;
        self.error = Some(json!({ "code": code, "message": message }));
        self.result = None;
        self.input_requests.clear();
        self.relay = None;
        self.updated_ms = now_ms;
        true
    }

    /// CANCEL. Idempotent on a terminal task, which is the whole of the `tasks/cancel` contract.
    /// Whether THIS call performed the terminal transition.
    pub fn cancel(&mut self, now_ms: u64) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        self.status = Status::Cancelled;
        self.input_requests.clear();
        self.relay = None;
        self.updated_ms = now_ms;
        true
    }

    /// A terminal task past its retention.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.status.is_terminal() && now_ms.saturating_sub(self.updated_ms) > TASK_TTL_MS
    }

    /// An ACTIVE task nothing has touched for longer than [`ACTIVE_TASK_ABANDON_MS`].
    #[must_use]
    pub fn is_abandoned(&self, now_ms: u64) -> bool {
        !self.status.is_terminal()
            && now_ms.saturating_sub(self.updated_ms) > ACTIVE_TASK_ABANDON_MS
    }

    /// The task's durable row as it now stands.
    #[must_use]
    pub fn row(&self) -> Vec<u8> {
        WorkRow {
            status: self.status,
            created_ms: self.created_ms,
            updated_ms: self.updated_ms,
            digest: self.digest.clone(),
        }
        .bytes()
    }

    /// The terminal value its result chunks carry: `{"result": …}` or `{"error": …}`; `None` for a
    /// task with neither (working, input-required, cancelled).
    #[must_use]
    pub fn terminal(&self) -> Option<Value> {
        match (&self.result, &self.error) {
            (Some(r), _) => Some(json!({ "result": r })),
            (None, Some(e)) => Some(json!({ "error": e })),
            (None, None) => None,
        }
    }
}

/// What one sweep did: the continuations to wake (each saw its task cancelled), the tasks whose
/// handles must be settled with the state they hold, and the result chunks to strike.
#[derive(Debug, Default, PartialEq)]
pub struct Swept {
    /// The tickets of continuations whose task the sweep cancelled.
    pub wake: Vec<Ticket>,
    /// `(handle, task)` of every task that reached its terminal state in hand and is not settled.
    pub settle: Vec<(u64, Task)>,
    /// `(taskId, chunks)` of every dropped task that wrote a result.
    pub strike: Vec<(String, u32)>,
}

/// THE SWEEP, run when a task is created: an ACTIVE task past the abandonment ceiling is first
/// CANCELLED (a transition, never a drop); expired terminal tasks are dropped; and only if that was
/// not enough, the oldest terminal tasks. Never a working one.
pub fn sweep(tasks: &mut BTreeMap<String, Task>, now_ms: u64) -> Swept {
    let mut swept = Swept::default();
    for task in tasks.values_mut() {
        if task.is_abandoned(now_ms) && task.cancel(now_ms) {
            task.unsettled = true;
            if let Some((_, ticket)) = task.runner {
                swept.wake.push(ticket);
            }
        }
        if task.unsettled {
            task.unsettled = false;
            swept.settle.push((task.handle, task.clone()));
        }
    }
    let gone = |t: &Task, swept: &mut Swept| {
        if t.chunks > 0 {
            swept.strike.push((t.id.clone(), t.chunks));
        }
    };
    tasks.retain(|_, t| {
        let keep = !t.is_expired(now_ms);
        if !keep {
            gone(t, &mut swept);
        }
        keep
    });
    if tasks.len() < MAX_RETAINED_TASKS {
        return swept;
    }
    let mut terminal: Vec<(u64, String)> = tasks
        .iter()
        .filter(|(_, t)| t.status.is_terminal())
        .map(|(id, t)| (t.updated_ms, id.clone()))
        .collect();
    terminal.sort_unstable();
    for (_, id) in terminal
        .into_iter()
        .take(tasks.len().saturating_sub(MAX_RETAINED_TASKS) + 1)
    {
        if let Some(t) = tasks.remove(&id) {
            gone(&t, &mut swept);
        }
    }
    swept
}

/// A task's DURABLE ROW, the work handle's record (at most `MAX_WORK_RECORD` bytes): its status,
/// its two stamps, and the digest of the call it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkRow {
    /// Its status.
    pub status: Status,
    /// When it was created (Unix ms).
    pub created_ms: u64,
    /// When it was last updated (Unix ms).
    pub updated_ms: u64,
    /// The digest of the continuation's call ([`run_digest`]).
    pub digest: String,
}

/// The row's version word.
const ROW_V1: &str = "t1";

impl WorkRow {
    /// The row's bytes: `t1|<status>|<created>|<updated>|<digest>`.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "{ROW_V1}|{}|{}|{}|{}",
            self.status.token(),
            self.created_ms,
            self.updated_ms,
            self.digest
        )
        .into_bytes()
    }

    /// A row read back; `None` for bytes that are not one.
    #[must_use]
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut parts = text.split('|');
        if parts.next()? != ROW_V1 {
            return None;
        }
        let status = Status::of_token(parts.next()?)?;
        let created_ms = parts.next()?.parse().ok()?;
        let updated_ms = parts.next()?.parse().ok()?;
        let digest = parts.next()?.to_string();
        if parts.next().is_some() {
            return None;
        }
        Some(WorkRow {
            status,
            created_ms,
            updated_ms,
            digest,
        })
    }
}

/// THE DIGEST of the call a continuation runs (the published name, the arguments as admitted and the
/// caller's `_meta`): written in the handle's row by the creating unit, compared by the
/// continuation against the call its arrival carries, so the run is the call that was admitted.
#[must_use]
pub fn run_digest(params: &Value) -> String {
    busbar_contract::redacted::sha256_hex(&serde_json::to_vec(params).unwrap_or_default())
}

/// The key of chunk `n` of task `id`'s result: ordered, so a listing reads them back in order.
#[must_use]
pub fn chunk_key(id: &str, n: u32) -> Vec<u8> {
    format!("{id}/{n:04}").into_bytes()
}

/// The prefix every chunk of task `id`'s result is keyed under.
#[must_use]
pub fn chunk_prefix(id: &str) -> Vec<u8> {
    format!("{id}/").into_bytes()
}

/// THE RESULT, IN CHUNKS: the terminal value's bytes cut into plane records of at most
/// [`RESULT_CHUNK_BYTES`]; none when it would take more than [`MAX_RESULT_CHUNKS`].
#[must_use]
pub fn result_chunks(id: &str, terminal: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    chunked(|n| chunk_key(id, n), terminal)
}

/// `value`'s bytes cut into plane records of at most [`RESULT_CHUNK_BYTES`], keyed `key(n)`; none
/// when it would take more than [`MAX_RESULT_CHUNKS`].
fn chunked(key: impl Fn(u32) -> Vec<u8>, value: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let chunks: Vec<&[u8]> = bytes.chunks(RESULT_CHUNK_BYTES).collect();
    if chunks.len() > MAX_RESULT_CHUNKS {
        return Vec::new();
    }
    (0u32..)
        .zip(chunks)
        .map(|(n, c)| (key(n), c.to_vec()))
        .collect()
}

/// The key of chunk `n` of task `id`'s live state: ordered, apart from its result's.
#[must_use]
pub fn live_key(id: &str, n: u32) -> Vec<u8> {
    format!("{id}~/{n:04}").into_bytes()
}

/// The prefix every chunk of task `id`'s live state is keyed under.
#[must_use]
pub fn live_prefix(id: &str) -> Vec<u8> {
    format!("{id}~/").into_bytes()
}

/// THE LIVE STATE, IN CHUNKS ([`Task::live`]), as [`result_chunks`] cuts a result.
#[must_use]
pub fn live_parts(id: &str, live: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    chunked(|n| live_key(id, n), live)
}

/// The live state read back from its chunks' bytes, in key order: the first document they hold (an
/// earlier, longer state's chunks past it are not read); `None` when they hold none.
#[must_use]
pub fn read_live(bytes: &[u8]) -> Option<Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .next()?
        .ok()
}

/// The prefix `principal`'s index rows are keyed under: a digest of the principal, never the
/// principal itself.
#[must_use]
pub fn index_prefix(principal: &str) -> Vec<u8> {
    let owner = busbar_contract::redacted::sha256_hex(principal.as_bytes());
    format!("o/{}/", &owner[..32]).into_bytes()
}

/// The key of task `id`'s index row under `principal`.
#[must_use]
pub fn index_key(principal: &str, id: &str) -> Vec<u8> {
    let mut key = index_prefix(principal);
    key.extend_from_slice(id.as_bytes());
    key
}

/// A LIVE TASK'S INDEX ROW: until when a run holds it, and when it last moved. What a create reads
/// to find the tasks of its caller a process that is gone left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    /// Until when its run holds it (Unix ms); `0`: no run does (it is parked on its caller).
    pub until_ms: u64,
    /// When it last moved (Unix ms).
    pub updated_ms: u64,
}

/// The index row's version word.
const LEASE_V1: &str = "l1";

impl Lease {
    /// The row's bytes: `l1|<until>|<updated>`.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        format!("{LEASE_V1}|{}|{}", self.until_ms, self.updated_ms).into_bytes()
    }

    /// A row read back; `None` for bytes that are not one.
    #[must_use]
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut parts = text.split('|');
        if parts.next()? != LEASE_V1 {
            return None;
        }
        let until_ms = parts.next()?.parse().ok()?;
        let updated_ms = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Lease {
            until_ms,
            updated_ms,
        })
    }

    /// Whether the task it indexes is LEFT BEHIND at `now_ms`: its run's lease lapsed (the process
    /// running it is gone), or nothing moved it past [`ACTIVE_TASK_ABANDON_MS`].
    #[must_use]
    pub fn left_behind(&self, now_ms: u64) -> bool {
        (self.until_ms != 0 && now_ms > self.until_ms)
            || now_ms.saturating_sub(self.updated_ms) > ACTIVE_TASK_ABANDON_MS
    }
}

/// The terminal value read back from its chunks (in key order); `None` when they do not make one.
#[must_use]
pub fn read_chunks<'a>(chunks: impl Iterator<Item = &'a [u8]>) -> Option<Value> {
    let bytes: Vec<u8> = chunks.flatten().copied().collect();
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// The arguments a continuation calls with: the admitted arguments, with the caller's gathered ask
/// answers merged in under the operator's own keys. A clone, never a mutation.
#[must_use]
pub fn merge_answers(arguments: &Value, answers: &Map<String, Value>) -> Value {
    if answers.is_empty() {
        return arguments.clone();
    }
    let mut merged = arguments.as_object().cloned().unwrap_or_default();
    for (key, value) in answers {
        merged.insert(key.clone(), value.clone());
    }
    Value::Object(merged)
}

/// The task-scoped ask rounds for a tool, filtered to what this caller declared it can answer. A
/// round left EMPTY by the filter is dropped rather than parked on.
#[must_use]
pub fn task_ask_rounds(
    rounds: &[crate::tools_config::AskRoundCfg],
    capabilities: &Value,
) -> Vec<Vec<CallerAsk>> {
    rounds
        .iter()
        .map(|round| crate::ask::asks_for_round(round, capabilities))
        .filter(|round| !round.is_empty())
        .collect()
}

/// The `CreateTaskResult` envelope: the flat task shape with `resultType: task`, under the caller's
/// id.
#[must_use]
pub fn task_result(id: &Value, created: Value) -> Vec<u8> {
    let mut value = created;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("resultType".into(), RESULT_TYPE_TASK.into());
    }
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".into(), "2.0".into());
    envelope.insert("id".into(), id.clone());
    envelope.insert("result".into(), value);
    serde_json::to_vec(&Value::Object(envelope)).unwrap_or_default()
}

/// SEP-2663's discriminator, returned ONLY on a task busbar itself just created.
pub const RESULT_TYPE_TASK: &str = "task";

/// Unix milliseconds as an ISO-8601 UTC instant, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn iso8601_ms(ms: u64) -> String {
    let ms = i64::try_from(ms).unwrap_or(i64::MAX);
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = busbar_contract::civil::civil_from_days(days);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

#[cfg(test)]
#[path = "tests/tasks.rs"]
mod tests;
