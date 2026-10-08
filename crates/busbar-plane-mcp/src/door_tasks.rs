// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TASKS EXTENSION ON THE DOOR (ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): who creates a task,
//! who runs it, and how the three `tasks/*` verbs read and move it. The task itself — its state, its
//! shapes, its sweep and its durable rows — is [`crate::tool_tasks`].
//!
//! * THE CREATING UNIT (a `tools/call` admitted on a tool that creates a task for this caller) opens
//!   a durable work handle (`work.open`; its reference is the `taskId`), holds the task, nests the
//!   CONTINUATION on the plane's own task-run claim ([`crate::tool_claims::TASK_RUN_MOUNT`],
//!   `unit.nest`) carrying the reference and the call it runs, and answers `CreateTaskResult`.
//!   The continuation runs without any poll, as the served engine's runner did.
//! * THE CONTINUATION is a NEW unit with its own arrival, admission and window (THE DESIGN), under
//!   the principal its handle recorded: it finds the handle (`work.find`, scoped to the instance and
//!   the principal) and checks the call it carries is the one that was admitted (the digest in the
//!   handle's row), takes the run ONCE (the instance's own ledger, then the host's one-time
//!   `records.claim`), binds the handle (`work.resume`, principal-checked), asks its caller the
//!   task's own rounds (`task_ask_caller`, answered through `tasks/update`), sends the call to the
//!   member its walk picked, and settles the handle with the task's terminal state (`work.settle`).
//!   A settle the handle refuses means `tasks/cancel` got there first. PARKED ON ITS CALLER (its
//!   own round unanswered), it ends with the handle live; the `tasks/update` that answers the round,
//!   on whichever node, nests the resume ([`Retry::Asked`]).
//! * AN UPSTREAM'S ASK, RELAYED (Law 11: busbar answers nothing on the caller's behalf; ARCHITECT
//!   Q6): when the member answers the continuation's call with an `input_required` result, the task
//!   parks `input_required` with the upstream's `inputRequests` verbatim, under busbar's sealed
//!   state (bound to the principal, the tool and the member, nesting the upstream's own), and the
//!   continuation ends with the handle live. The caller answers through `tasks/update`; once every
//!   key is answered the update nests a NEW continuation ([`continuation_asked`], the retry): it
//!   presents the state, which is opened, matched and spent once, binds the handle and sends the
//!   call back to the SAME member with the caller's answers and the upstream's own state.
//! * THE TASK STORE IS HOST RECORDS (THE DESIGN, the mcp bullet): `tasks/get` is `work.find` plus
//!   the task's live state, or its result, in the plane's records — the same answer on every
//!   node and across a restart; `tasks/update` delivers input, writes the state it leaves, and nests
//!   the run that continues; `tasks/cancel` settles the handle `cancelled`, which a running
//!   continuation observes when it settles.
//! * A SETTLE THAT DOES NOT LAND is owed: its task is held unsettled and the next create's sweep
//!   settles it again, until it lands. The same sweep settles the live tasks of its caller a process
//!   that is gone left behind ([`tasks::Lease`]), so they never exhaust the bound
//!   of live work (THE DESIGN: admission bounds live work; nothing evicts it).

use std::task::Poll;

use busbar_contract::abi::host::service::{ItemSpan, WORK_LIVE, WORK_SETTLED};
use busbar_contract::abi::mechanism::call::Outcome as AbiOutcome;
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use serde_json::{json, Map, Value};

use super::{
    clock_s, twin_of, CallUnit, CompletionHandle, DoorSeal, Held, McpDoor, Pending, Relay,
    Services, Step, Ticket, Twin,
};
use crate::call::{AdmittedCall, Leg, RelayedRetry};
use crate::door::RECORD_TASK;
use crate::tool_arrival::Refusal;
use crate::tool_tasks::{
    self as tasks, run_digest, Status, Task, WorkRow, RUN_CLAIM_TTL_MS, TASK_PROTOCOL_ERROR_CODE,
};

/// What a unit is to the tasks extension.
pub(super) enum TaskUnit {
    /// The unit that creates a task, part way through.
    Create(Create),
    /// A task's continuation.
    Run(Box<Run>),
    /// A `tasks/*` verb, part way through.
    Verb(Verb),
}

/// What a continuation that is not the task's first run carries.
#[derive(Clone)]
pub(super) enum Retry {
    /// The caller's answer to a relayed ask: busbar's sealed state and the caller's
    /// `inputResponses`.
    Relayed {
        /// Busbar's sealed state.
        state: String,
        /// The caller's answers.
        responses: Value,
    },
    /// The round of the task's own asks it was parked on, answered: the run resumes there.
    Asked(usize),
}

impl TaskUnit {
    /// A continuation of task `reference`, running `params`; `retry` = the caller's answer to the
    /// upstream's ask it carries back (the retry of a relayed ask).
    pub(super) fn run(reference: String, params: Value, retry: Option<Retry>) -> Self {
        let digest = run_digest(&params);
        TaskUnit::Run(Box::new(Run {
            reference,
            params,
            digest,
            retry,
            leg: None,
            begun: false,
            phase: Phase::Bind,
            find: None,
            claim: None,
            resume: None,
            settle: None,
            local: false,
            handle: 0,
            round: 0,
            end: None,
            at: None,
            answered: false,
            far_bytes: 0,
        }))
    }
}

/// The creating unit's progress: the handle numbers its host calls were issued under (a call that
/// pends is re-issued under its first number), the handle it opened, and whether the continuation
/// was nested; this caller's index rows read, the tasks left behind it settles, and the records the
/// settles leave to strike.
#[derive(Default)]
pub(super) struct Create {
    open: Option<u32>,
    nest: Option<u32>,
    opened: Option<(u64, String)>,
    nested: bool,
    swept: bool,
    at: Option<u64>,
    index: Listing,
    indexed: bool,
    left: Vec<Left>,
    struck: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A task left behind, being settled: its reference, the handle number its find was issued under,
/// and whether it is done.
pub(super) struct Left {
    reference: String,
    find: Option<u32>,
    done: bool,
}

/// A verb's progress.
#[derive(Default)]
pub(super) struct Verb {
    find: Option<u32>,
    settle: Option<u32>,
    result: Listing,
    live: Listing,
    at: Option<u64>,
}

/// A listing of the task kind's records under a prefix, page by page: the handle number the page in
/// flight was issued under, where the next page starts, the records read, and whether it is done.
#[derive(Default)]
pub(super) struct Listing {
    page: Option<u32>,
    after: Option<Vec<u8>>,
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    done: bool,
}

/// A continuation.
pub(super) struct Run {
    reference: String,
    /// The call it runs: the published name, the arguments as admitted, the caller's `_meta`.
    params: Value,
    digest: String,
    /// The retry of a relayed ask: the state and the caller's answers it carries.
    retry: Option<Retry>,
    /// The upstream leg the retry's state opened to: the member it goes back to and its own state.
    leg: Option<crate::ask::UpstreamLeg>,
    /// Its caller's body has arrived: its phases run.
    begun: bool,
    phase: Phase,
    find: Option<u32>,
    claim: Option<u32>,
    resume: Option<u32>,
    settle: Option<u32>,
    /// It holds the instance's own half of the one-time run.
    local: bool,
    handle: u64,
    /// The task ask round it is on.
    round: usize,
    /// The terminal state it settles, and when it reached it.
    end: Option<End>,
    at: Option<u64>,
    /// A far end answered one of its rounds: the tool call it reports.
    answered: bool,
    /// The bytes of the documents its far ends answered with: the byte count it reports.
    far_bytes: usize,
}

/// Where a continuation is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Finding, claiming and binding its handle.
    Bind,
    /// Asking its caller the task's own rounds: parked, it ends.
    Ask,
    /// Sending the call.
    Call,
    /// The call is with the far end.
    Far,
    /// Settling its handle.
    Settle,
    /// Its reply is written.
    Done,
}

/// The terminal state a continuation reached.
#[derive(Clone)]
enum End {
    /// The tool ran: its result, as it came.
    Completed(Value),
    /// A protocol-level failure, in words.
    Failed(String),
}

/// The words of a task this caller has no task under: the one answer for an id that does not
/// exist and one that is another caller's (anti-enumeration).
const UNKNOWN_TASK: &str = "No task with that `taskId` exists for this caller.";

/// The words of a verb with no `taskId`.
const NO_TASK_ID: &str = "`params.taskId` is required and must be a string.";

/// The status of a `400` answer.
const STATUS_BAD_REQUEST: u32 = 400;

/// The status a task that could not be started is refused with.
const STATUS_UNAVAILABLE: u32 = 503;

/// The call-log reason of a call whose task could not be started.
const REASON_TASK_UNAVAILABLE: &str = "task_unavailable";

/// The bytes a work handle's answer is read into: its state byte and its record.
const WORK_BYTES: usize = 512;

/// The most result chunks one page of a listing reads.
const PAGE: u32 = 64;

/// The most stale result chunks one creating unit strikes as it writes.
const MAX_STRIKES: usize = 64;

/// One span, blank.
pub(super) fn blank() -> ItemSpan {
    let absent = Span {
        offset: SPAN_ABSENT,
        len: 0,
    };
    ItemSpan {
        key: absent,
        value: absent,
    }
}

/// The handle numbered `slot` on `ticket`: the number it was first issued under, or the unit's next.
pub(super) fn handle(ticket: Ticket, issued: &mut u32, slot: &mut Option<u32>) -> CompletionHandle {
    let seq = *slot.get_or_insert_with(|| {
        let seq = *issued;
        *issued += 1;
        seq
    });
    CompletionHandle {
        ticket,
        seq,
        _reserved: 0,
    }
}

/// The kernel's wall clock in Unix milliseconds, on a fresh handle of `ticket`.
fn task_clock_ms(services: Services, ticket: Ticket, issued: &mut u32) -> u64 {
    let mut fresh = None;
    let h = handle(ticket, issued, &mut fresh);
    services.clock_now(h).map_or(0, |r| r.wall_ns / 1_000_000)
}

/// The caller's declared capabilities in `params`.
fn capabilities(params: Option<&Value>) -> Value {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(crate::codec::META_CLIENT_CAPABILITIES))
        .cloned()
        .unwrap_or(Value::Null)
}

/// Whether `entry` answers this caller's call (`params`) with a task: the operator's declaration
/// crossed with the caller's.
pub(super) fn creates(entry: &crate::catalogue::ToolEntry, params: Option<&Value>) -> bool {
    entry
        .task_support
        .creates_task(crate::call::client_declares_tasks(&capabilities(params)))
}

/// Whether `unit`'s arrival is a `tools/call` that creates a task (its refusal by the caller's
/// budget is said as the served engine's task path said it).
pub(super) fn creates_task(unit: &CallUnit) -> bool {
    let (Some(held), crate::tool_arrival::Disposition::Request { row, .. }) =
        (unit.held.as_ref(), &unit.disposition)
    else {
        return false;
    };
    row.op == crate::tool_ops::OP_TOOL_CALL
        && unit.task.is_none()
        && unit
            .params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .and_then(|name| held.catalogue.tool(name))
            .is_some_and(|entry| creates(entry, unit.params.as_ref()))
}

/// The refusal of a task-creating call by the caller's budget, in the served engine's words.
pub(super) fn budget_refused(id: Option<Value>, message: &str) -> Refusal {
    Refusal {
        status: crate::tool_arrival::STATUS_NOT_FOUND,
        id,
        code: crate::codec::CODE_REFUSED,
        message: format!("this task was refused by your budget: {message}"),
        data: Some(json!({ "reason": busbar_contract::vocab::REASON_NOT_GRANTED })),
    }
}

/// What a continuation's arrival carries: its reference, the call it runs, that call as the
/// `tools/call` body the one dispatch decides, and the caller's answer to a relayed ask it carries
/// back (`None` for the task's first run).
pub(super) type RunArrival = (String, Value, Vec<u8>, Option<Retry>);

/// THE CONTINUATION'S ARRIVAL on the task-run claim: its reference, the call it runs, and that call
/// as the `tools/call` body the one dispatch decides (its head fields mirrored from it), and — the
/// retry of a relayed ask — `relay: {requestState, inputResponses}`, or — the resume of an answered
/// round of the task's own asks — `resume: <round>`. `None` for a body that is not one.
pub(super) fn run_arrival(body: &[u8]) -> Option<RunArrival> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let reference = value.get("taskId")?.as_str()?.to_string();
    let params = value.get("params")?.clone();
    params.get("name")?.as_str()?;
    let retry = match (value.get("relay"), value.get("resume")) {
        (None, None) => None,
        (Some(relay), _) => Some(Retry::Relayed {
            state: relay.get("requestState")?.as_str()?.to_string(),
            responses: relay.get("inputResponses")?.clone(),
        }),
        (None, Some(round)) => Some(Retry::Asked(usize::try_from(round.as_u64()?).ok()?)),
    };
    let call = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": crate::codec::METHOD_TOOLS_CALL,
        "params": params,
    });
    Some((reference, params, serde_json::to_vec(&call).ok()?, retry))
}

/// The refused arrival of a continuation whose body names no task.
pub(super) fn unknown_arrival() -> Refusal {
    Refusal {
        status: STATUS_BAD_REQUEST,
        id: None,
        code: crate::codec::CODE_INVALID_PARAMS,
        message: UNKNOWN_TASK.to_string(),
        data: None,
    }
}

/// The call a continuation runs: the published name, the arguments as admitted (the answers to
/// busbar's own asks merged in), and the caller's `_meta` (its capabilities), its progress token cut
/// (nobody is listening for the continuation's progress).
fn run_params(admitted: &AdmittedCall, params: Option<&Value>) -> Value {
    let mut out = Map::new();
    out.insert("name".into(), admitted.entry.namespaced.clone().into());
    out.insert("arguments".into(), admitted.arguments.clone());
    if let Some(mut meta) = params.and_then(|p| p.get("_meta")).cloned() {
        if let Some(m) = meta.as_object_mut() {
            m.remove("progressToken");
        }
        out.insert("_meta".into(), meta);
    }
    Value::Object(out)
}

/// `unit`'s answer `status` `body`, framed as its arrival asked, its reply done.
fn answer(unit: &mut CallUnit, status: u32, body: Vec<u8>) -> Step {
    unit.pending = Some(Pending::answer(status, body, unit.framing.as_ref(), &[]));
    Step::Write
}

/// `unit`'s refusal.
fn refuse(unit: &mut CallUnit, refusal: &Refusal) -> Step {
    answer(unit, refusal.status, refusal.body())
}

/// A JSON-RPC `-32602` answer in `message`.
fn invalid(id: &Value, message: &str) -> Refusal {
    Refusal {
        status: STATUS_BAD_REQUEST,
        id: Some(id.clone()),
        code: crate::codec::CODE_INVALID_PARAMS,
        message: message.to_string(),
        data: None,
    }
}

/// SETTLE handle `work` with `row`, on a fresh handle of `ticket`: whether it LANDED (settled now, or
/// settled first by another unit). One that pends or fails is owed ([`owe`]): its task is held
/// unsettled and the next create's sweep settles it again, until it lands.
fn settled(services: Services, ticket: Ticket, issued: &mut u32, work: u64, row: &[u8]) -> bool {
    use busbar_contract::abi::sdk::services::ServiceError;
    let mut fresh = None;
    let h = handle(ticket, issued, &mut fresh);
    matches!(
        services.work_settle(h, work, row),
        Poll::Ready(Ok(()) | Err(ServiceError::Declined(AbiOutcome::Refused)))
    )
}

/// A settle of `task` that did not land, OWED: the instance holds the task unsettled, for the next
/// create's sweep.
fn owe(plane: &McpDoor, task: &Task) {
    plane.tasks.with_all(|m| {
        m.entry(task.id.clone())
            .or_insert_with(|| task.clone())
            .unsettled = true;
    });
}

/// THE TASK'S LIVE STATE AS ITS RECORDS (THE DESIGN, the mcp bullet: the task store is
/// host records): its live chunks, any this instance wrote past them struck, and — `until` given — its caller's index row,
/// its run's lease `until` (`0`: no run holds it).
fn live_records(plane: &McpDoor, task: &Task, until: Option<u64>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = tasks::live_parts(&task.id, &task.live());
    let wrote = u32::try_from(out.len()).unwrap_or(u32::MAX);
    let before = plane.tasks.with(&task.id, |t| {
        t.map_or(0, |t| std::mem::replace(&mut t.live_chunks, wrote))
    });
    out.extend((wrote..before).map(|n| (tasks::live_key(&task.id, n), Vec::new())));
    if let Some(until) = until {
        let lease = tasks::Lease {
            until_ms: until,
            updated_ms: task.stamps().1,
        };
        out.push((task.index_key(), lease.bytes()));
    }
    out
}

/// THE RECORDS A SETTLED TASK LEAVES, struck: its live chunks and its caller's index row.
fn struck_records(task: &Task) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = (0..task.live_chunks.max(tasks::LIVE_STRIKES))
        .map(|n| (tasks::live_key(&task.id, n), Vec::new()))
        .collect();
    out.push((task.index_key(), Vec::new()));
    out
}

/// `records` of the task kind ride the unit's pending write.
fn ride(unit: &mut CallUnit, records: Vec<(Vec<u8>, Vec<u8>)>) {
    if let Some(p) = unit.pending.as_mut() {
        p.records
            .extend(records.into_iter().map(|(k, v)| (RECORD_TASK, k, v)));
    }
}

/// THE TASK KIND'S RECORDS under `prefix`, read page by page into `l.rows` in key order (one page
/// only when `once`). `Ready(false)`: the host could not list them.
fn list(
    services: Services,
    ticket: Ticket,
    issued: &mut u32,
    prefix: &[u8],
    once: bool,
    l: &mut Listing,
) -> Poll<bool> {
    use busbar_contract::abi::sdk::services::ServiceError;
    while !l.done {
        let h = handle(ticket, issued, &mut l.page);
        let mut sizes = (64 * 1024, PAGE as usize);
        let mut page: Option<(usize, Option<Vec<u8>>)> = None;
        for _ in 0..2 {
            let mut buf = vec![0u8; sizes.0];
            let mut spans = vec![blank(); sizes.1];
            match services.records_list(
                h,
                crate::door::KIND_TASK,
                prefix,
                l.after.as_deref(),
                PAGE,
                (&mut buf, &mut spans),
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(records)) => {
                    let mut n = 0;
                    for (key, value) in records.records() {
                        l.rows.push((key.to_vec(), value.to_vec()));
                        n += 1;
                    }
                    page = Some((n, records.last_key().map(<[u8]>::to_vec)));
                    break;
                }
                Poll::Ready(Err(ServiceError::Short { bytes, items })) => {
                    sizes = (
                        usize::try_from(bytes).unwrap_or(usize::MAX).max(sizes.0),
                        usize::try_from(items).unwrap_or(usize::MAX).max(sizes.1),
                    );
                }
                Poll::Ready(Err(_)) => return Poll::Ready(false),
            }
        }
        let Some((n, last)) = page else {
            return Poll::Ready(false);
        };
        l.page = None;
        if once || n < PAGE as usize || last.is_none() {
            l.done = true;
        } else {
            l.after = last;
        }
    }
    Poll::Ready(true)
}

/// A TASK LEFT BEHIND, settled `cancelled`: found (scoped to this caller), its own row cancelled and
/// settled. The records its settle leaves to strike; none while it is owed.
fn settle_left(
    plane: &McpDoor,
    services: Services,
    ticket: Ticket,
    issued: &mut u32,
    principal: &str,
    left: &mut Left,
    now: u64,
) -> Poll<Vec<(Vec<u8>, Vec<u8>)>> {
    if left.done {
        return Poll::Ready(Vec::new());
    }
    let h = handle(ticket, issued, &mut left.find);
    let (mut buf, mut spans) = ([0u8; WORK_BYTES], [blank(); 1]);
    let found = match services.work_find(h, &left.reference, &mut buf, &mut spans) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(found) => found,
    };
    left.done = true;
    let mut task = match found {
        Ok(Some(f)) if f.state == WORK_LIVE => match WorkRow::read(f.record) {
            Some(row) => Task::from_row(&left.reference, principal, f.handle, &row, None),
            None => return Poll::Ready(Vec::new()),
        },
        // Settled, or past its retention: only its records are left.
        Ok(_) => {
            let gone = Task::new(&left.reference, principal, 0, "", now);
            return Poll::Ready(struck_records(&gone));
        }
        // The host could not say: the next create reads it again.
        Err(_) => return Poll::Ready(Vec::new()),
    };
    task.cancel(now);
    if settled(services, ticket, issued, task.handle, &task.row()) {
        Poll::Ready(struck_records(&task))
    } else {
        owe(plane, &task);
        Poll::Ready(Vec::new())
    }
}

// ── the creating unit ─────────────────────────────────────────────────────────────────────────

/// THE CREATING UNIT: the sweep, the handle opened, the task held, the continuation nested, and the
/// `CreateTaskResult` written (with the call-log line `refused`/`task_created`, as the served engine
/// recorded it: at the moment the caller is answered nothing has gone out).
pub(super) fn create(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    admitted: &AdmittedCall,
    params: Option<&Value>,
) -> Step {
    let mut st = match unit.task.take() {
        Some(TaskUnit::Create(st)) => st,
        _ => Create::default(),
    };
    let step = creating(plane, ticket, principal, unit, admitted, params, &mut st);
    if unit.task.is_none() {
        unit.task = Some(TaskUnit::Create(st));
    }
    step
}

fn creating(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    admitted: &AdmittedCall,
    params: Option<&Value>,
    st: &mut Create,
) -> Step {
    let generation = unit.held.as_ref().map_or(0, |h| h.catalogue.generation());
    let unavailable = |unit: &mut CallUnit, why: &str| {
        let refusal = Refusal {
            status: STATUS_UNAVAILABLE,
            id: Some(admitted.id.clone()),
            code: crate::codec::CODE_REFUSED,
            message: format!("this task could not be started: {why}"),
            data: Some(json!({ "reason": REASON_TASK_UNAVAILABLE })),
        };
        let ts = clock_s(plane.services, ticket, unit);
        unit.pending = Some(
            Pending::answer(refusal.status, refusal.body(), unit.framing.as_ref(), &[]).logged(
                Some(&crate::call::task_line(
                    &admitted.entry,
                    REASON_TASK_UNAVAILABLE,
                )),
                principal,
                generation,
                ts,
            ),
        );
        Step::Write
    };
    let Some(services) = plane.services else {
        return unavailable(unit, "the host keeps no work handles");
    };
    let run = run_params(admitted, params);
    let digest = run_digest(&run);
    let now = match st.at {
        Some(at) => at,
        None => {
            let at = task_clock_ms(services, ticket, &mut unit.issued);
            st.at = Some(at);
            at
        }
    };
    // THE SWEEP, as the served engine ran it, on a create: abandoned tasks cancelled (their
    // continuations woken to see it), expired ones dropped. A task that reached its terminal state
    // in hand with its handle unsettled is settled now; one whose settle does not land is owed
    // again, until it lands.
    if !st.swept {
        st.swept = true;
        let swept = plane.tasks.with_all(|m| tasks::sweep(m, now));
        if let Some(wake) = plane.wake {
            swept.wake.iter().for_each(|t| wake.wake(*t));
        }
        for (work, task) in &swept.settle {
            if settled(services, ticket, &mut unit.issued, *work, &task.row()) {
                st.struck.extend(struck_records(task));
            } else {
                owe(plane, task);
            }
        }
        plane.strikes.with_all(|m| {
            for (id, chunks) in swept.strike {
                m.insert(id, chunks);
            }
        });
    }
    // THE TASKS LEFT BEHIND (THE DESIGN: admission bounds live work; nothing evicts it): this
    // caller's live tasks no unit here runs whose run's lease lapsed — the process running it is gone — or
    // that nothing moved past the abandonment ceiling, read from the plane's records and settled
    // `cancelled` before the handle is opened, so the handles an earlier process left never exhaust
    // `work.open`. From a submit, never a read or a timer.
    if !st.indexed {
        let prefix = tasks::index_prefix(principal);
        if list(
            services,
            ticket,
            &mut unit.issued,
            &prefix,
            true,
            &mut st.index,
        )
        .is_pending()
        {
            return Step::Pending;
        }
        st.indexed = true;
        for (key, value) in std::mem::take(&mut st.index.rows) {
            let Some(id) = key
                .strip_prefix(prefix.as_slice())
                .and_then(|k| std::str::from_utf8(k).ok())
            else {
                continue;
            };
            let left = tasks::Lease::read(&value).is_some_and(|l| l.left_behind(now));
            let running = plane
                .tasks
                .get(&id.to_string())
                .is_some_and(|t| t.runner.is_some() || t.unsettled);
            if left && !running {
                st.left.push(Left {
                    reference: id.to_string(),
                    find: None,
                    done: false,
                });
            }
        }
    }
    for left in &mut st.left {
        match settle_left(
            plane,
            services,
            ticket,
            &mut unit.issued,
            principal,
            left,
            now,
        ) {
            Poll::Pending => return Step::Pending,
            Poll::Ready(struck) => st.struck.extend(struck),
        }
    }
    if st.opened.is_none() {
        let row = WorkRow {
            status: Status::Working,
            created_ms: now,
            updated_ms: now,
            digest: digest.clone(),
        };
        let h = handle(ticket, &mut unit.issued, &mut st.open);
        let mut buf = [0u8; 64];
        let mut spans = [blank(); 2];
        match services.work_open(
            h,
            crate::door::KIND_TASK,
            &row.bytes(),
            &mut buf,
            &mut spans,
        ) {
            Poll::Pending => return Step::Pending,
            Poll::Ready(Ok(opened)) => {
                let reference = opened.reference.to_string();
                plane.tasks.insert(
                    reference.clone(),
                    Task::new(&reference, principal, opened.handle, &digest, now),
                );
                st.opened = Some((opened.handle, reference));
            }
            Poll::Ready(Err(_)) => {
                let step = unavailable(
                    unit,
                    "the deployment holds as many live tasks as it keeps, or keeps no store for them",
                );
                ride(unit, std::mem::take(&mut st.struck));
                return step;
            }
        }
    }
    let Some((work, reference)) = st.opened.clone() else {
        return Step::Declined;
    };
    if !st.nested {
        let body =
            serde_json::to_vec(&json!({ "taskId": reference, "params": run })).unwrap_or_default();
        let h = handle(ticket, &mut unit.issued, &mut st.nest);
        let mut buf = vec![0u8; 1024];
        let mut spans = vec![blank(); 8];
        match services.unit_nest(
            h,
            "POST",
            crate::tool_claims::TASK_RUN_MOUNT,
            &body,
            &mut buf,
            &mut spans,
        ) {
            // The continuation runs: its answer is its own, and nobody waits for it here.
            Poll::Pending
            | Poll::Ready(Ok(_))
            | Poll::Ready(Err(busbar_contract::abi::sdk::services::ServiceError::Short {
                ..
            })) => st.nested = true,
            // The host runs no continuation for it (no nesting, too deep, too many at once): the
            // task is settled failed — owed until the settle lands — and the call refused.
            Poll::Ready(Err(_)) => {
                if let Some(mut task) = plane.tasks.remove(&reference) {
                    task.fail(
                        TASK_PROTOCOL_ERROR_CODE,
                        "the host ran no continuation for this task".to_string(),
                        now,
                    );
                    if !settled(services, ticket, &mut unit.issued, work, &task.row()) {
                        owe(plane, &task);
                    }
                }
                let step = unavailable(unit, "the host runs no continuation for it");
                ride(unit, std::mem::take(&mut st.struck));
                return step;
            }
        }
    }
    let Some(created) = plane.tasks.get(&reference).map(|t| t.created()) else {
        return Step::Declined;
    };
    // STALE RESULT CHUNKS, struck as this unit writes (a bounded few each time): the highest
    // first, so what is left of a task's chunks is still keyed `0..left`.
    let strikes: Vec<(u32, Vec<u8>, Vec<u8>)> = plane.strikes.with_all(|m| {
        let mut out = Vec::new();
        while out.len() < MAX_STRIKES {
            let Some((id, chunks)) = m.pop_first() else {
                break;
            };
            let room = u32::try_from(MAX_STRIKES - out.len()).unwrap_or(0);
            let take = chunks.min(room);
            for n in (chunks - take)..chunks {
                out.push((RECORD_TASK, tasks::chunk_key(&id, n), Vec::new()));
            }
            if take < chunks {
                m.insert(id, chunks - take);
            }
        }
        out
    });
    let ts = clock_s(plane.services, ticket, unit);
    let mut pending = Pending::answer(
        200,
        tasks::task_result(&admitted.id, created),
        unit.framing.as_ref(),
        &[],
    )
    .logged(
        Some(&crate::call::task_line(
            &admitted.entry,
            busbar_contract::vocab::REASON_TASK_CREATED,
        )),
        principal,
        generation,
        ts,
    );
    pending.records.extend(strikes);
    // ITS INDEX ROW, the run's lease taken: the continuation is nested at once.
    let lease = tasks::Lease {
        until_ms: now.saturating_add(tasks::RUN_LEASE_MS),
        updated_ms: now,
    };
    pending.records.push((
        RECORD_TASK,
        tasks::index_key(principal, &reference),
        lease.bytes(),
    ));
    unit.pending = Some(pending);
    ride(unit, std::mem::take(&mut st.struck));
    Step::Write
}

// ── the continuation ──────────────────────────────────────────────────────────────────────────

/// Whether `unit` is a continuation.
pub(super) fn is_run(unit: &CallUnit) -> bool {
    matches!(unit.task, Some(TaskUnit::Run(_)))
}

/// THE CONTINUATION'S CALLER BODY has arrived (or arrived again, for another member of its walk):
/// its phases run from where they are.
pub(super) fn begin(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) -> Step {
    if let Some(TaskUnit::Run(run)) = unit.task.as_mut() {
        run.begun = true;
        // Another member of the walk: the call is sent again, to it.
        if run.phase == Phase::Far {
            run.phase = Phase::Call;
        }
    }
    advance(plane, ticket, principal, unit)
}

/// A continuation called again part way through a phase that waits on the host (a pend's wake): the
/// phase goes on. `None` for any other unit.
pub(super) fn resume(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    match unit.task.as_ref() {
        Some(TaskUnit::Run(run))
            if run.begun && matches!(run.phase, Phase::Bind | Phase::Settle) => {}
        _ => return None,
    }
    Some(advance(plane, ticket, principal, unit))
}

/// THE FAR END ANSWERED THE CONTINUATION'S CALL (its rounds settled): the terminal state the served
/// engine's runner settled — the tool's result as it came (`completed`, `isError` and all); an
/// upstream failure or a refusal of an upstream's ask, `failed` — then the handle settled.
/// `answered` is the length of the document a far end answered with (`None`: no far end answered),
/// the tool call and the byte count the run reports.
/// THE FAR END ASKED THE CONTINUATION'S CALLER (Law 11, ARCHITECT Q6), the ask granted
/// ([`crate::call::settle_call`]): the task parks `input_required` with the upstream's `result`'s
/// `inputRequests` verbatim under busbar's sealed state, bound to the principal, the tool (`digest`:
/// the arguments as sent) and the member that asked, nesting the upstream's own state; the
/// continuation ends with the handle live, and `tasks/update` answers it. A deployment that cannot
/// seal the state fails the task in the refusal's words. `server` is the asking registration's,
/// `answered` the length of the document it answered with.
#[allow(clippy::too_many_arguments)]
pub(super) fn continuation_asked(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    result: &Value,
    round: u32,
    child: Option<crate::ask::ChildLeg>,
    asked: (&str, &str, Option<usize>),
) -> Step {
    let Some(TaskUnit::Run(mut run)) = unit.task.take() else {
        return Step::Declined;
    };
    let step = asking(
        plane, ticket, principal, unit, &mut run, result, round, child, asked,
    );
    unit.task = Some(TaskUnit::Run(run));
    step
}

#[allow(clippy::too_many_arguments)]
fn asking(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    run: &mut Run,
    result: &Value,
    round: u32,
    child: Option<crate::ask::ChildLeg>,
    (server, digest, answered): (&str, &str, Option<usize>),
) -> Step {
    if let Some(far) = answered {
        run.answered = true;
        run.far_bytes = run.far_bytes.saturating_add(far);
    }
    let Some(services) = plane.services else {
        return not_run(unit, run);
    };
    let leg = crate::ask::UpstreamLeg {
        member: unit.member.clone().unwrap_or_default(),
        state: result.get("requestState").cloned(),
        round: round.saturating_add(1),
        child,
    };
    let name = run
        .params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let sealed = {
        let mut seal = DoorSeal {
            services,
            ticket,
            issued: &mut unit.issued,
            claim: &mut unit.claim,
            spent: &plane.spent,
            pending: false,
        };
        let bind = |now| relay_bind(principal, &name, now);
        crate::tool_door::seal_relayed(
            &mut seal,
            server,
            bind,
            digest,
            leg,
            tasks::TASK_RELAY_TTL_SECS,
        )
    };
    let state = match sealed {
        Ok(state) => state,
        Err(refusal) => {
            run.end = Some(End::Failed(refusal.to_string()));
            run.phase = Phase::Settle;
            return running(plane, ticket, principal, unit, run);
        }
    };
    let requests = result
        .get("inputRequests")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let now = task_clock_ms(services, ticket, &mut unit.issued);
    let params = run.params.clone();
    let parked = plane.tasks.with(&run.reference, |t| match t {
        Some(t) if !t.status().is_terminal() => {
            t.park_relay(&requests, state, params, now);
            t.runner = None;
            Ok(t.clone())
        }
        Some(t) => Err(t.status()),
        None => Err(Status::Cancelled),
    });
    // THE CONTINUATION ENDS with the handle live, its live state in the plane's records: the
    // caller's answer, on whichever node, runs the next one.
    match parked {
        Ok(task) => {
            let records = live_records(plane, &task, Some(0));
            reply(unit, run, Status::InputRequired, records)
        }
        Err(status) => reply(unit, run, status, Vec::new()),
    }
}

/// What a task's relayed-ask state is bound to: the principal, the tool (`name`, as published) and,
/// in the state's leg, the member; not the catalogue generation, because a task parked on a human
/// outlives a configuration move.
fn relay_bind<'a>(principal: &'a str, name: &'a str, now: u64) -> crate::ask::Bind<'a> {
    crate::ask::Bind {
        principal,
        method: crate::codec::METHOD_TOOLS_CALL,
        capability: name,
        generation: 0,
        now,
        roots_epoch: 0,
    }
}

pub(super) fn continuation_answered(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    leg: Leg,
    answered: Option<usize>,
    body: &[u8],
) -> Step {
    if let Some(TaskUnit::Run(run)) = unit.task.as_mut() {
        if let Some(far) = answered {
            run.answered = true;
            run.far_bytes = run.far_bytes.saturating_add(far);
        }
        run.end = Some(match leg {
            Leg::Done(value) => End::Completed(value),
            Leg::Failed(reason) => End::Failed(format!("the MCP upstream call failed: {reason}")),
            Leg::Asked => End::Failed(
                serde_json::from_slice::<Value>(body)
                    .ok()
                    .and_then(|v| {
                        v.pointer("/error/message")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_default(),
            ),
        });
        run.phase = Phase::Settle;
    }
    advance(plane, ticket, principal, unit)
}

fn advance(plane: &McpDoor, ticket: Ticket, principal: &str, unit: &mut CallUnit) -> Step {
    let Some(TaskUnit::Run(mut run)) = unit.task.take() else {
        return Step::Declined;
    };
    let step = running(plane, ticket, principal, unit, &mut run);
    unit.task = Some(TaskUnit::Run(run));
    step
}

/// The continuation's reply: `{taskId, status}`, the tool call it made reported (never a fee: the
/// unit that drew the fee is the one that created the task), and the result's chunks.
fn reply(
    unit: &mut CallUnit,
    run: &mut Run,
    status: Status,
    chunks: Vec<(Vec<u8>, Vec<u8>)>,
) -> Step {
    run.phase = Phase::Done;
    let body = serde_json::to_vec(&json!({ "taskId": run.reference, "status": status.token() }))
        .unwrap_or_default();
    let mut pending = Pending::answer(200, body, None, &[]);
    pending.units.clear();
    if run.answered {
        pending = pending.counted(run.far_bytes);
    }
    pending.records = chunks
        .into_iter()
        .map(|(k, v)| (RECORD_TASK, k, v))
        .collect();
    unit.pending = Some(pending);
    Step::Write
}

/// A continuation that may not run (no such task for its principal, not the admitted call, or run
/// already): the unknown-task answer, nothing moved.
fn not_run(unit: &mut CallUnit, run: &mut Run) -> Step {
    run.phase = Phase::Done;
    let refusal = unknown_arrival();
    let mut pending = Pending::answer(refusal.status, refusal.body(), None, &[]);
    pending.units.clear();
    unit.pending = Some(pending);
    Step::Write
}

/// THE RETRY'S STATE, opened ([`crate::ask::open_relayed`]): busbar's own, sealed for this
/// principal and this task's tool over the arguments it sends (the admitted ones with busbar's own
/// answers merged), nesting an upstream leg, and spent once. `None` for a state that is forged,
/// spent, another caller's or another call's, or for a task that is not this principal's or has
/// ended.
fn relayed_leg(
    plane: &McpDoor,
    services: Services,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    run: &Run,
    state: &str,
) -> Poll<Option<crate::ask::UpstreamLeg>> {
    let held = plane.tasks.get(&run.reference);
    let Some(task) = held.filter(|t| t.owned_by(principal) && !t.status().is_terminal()) else {
        return Poll::Ready(None);
    };
    let arguments = tasks::merge_answers(
        &run.params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({})),
        task.answers(),
    );
    let digest = crate::ask::digest_arguments(&arguments);
    let name = run.params.get("name").and_then(Value::as_str).unwrap_or("");
    let mut seal = DoorSeal {
        services,
        ticket,
        issued: &mut unit.issued,
        claim: &mut unit.claim,
        spent: &plane.spent,
        pending: false,
    };
    // A clock that cannot be read opens nothing: the state's window is not judged at the epoch.
    let opened = seal.now().map(|now| {
        crate::ask::open_relayed(state, relay_bind(principal, name, now), &digest, &mut seal)
    });
    if seal.pending {
        return Poll::Pending;
    }
    Poll::Ready(opened.and_then(Result::ok))
}

#[allow(clippy::too_many_lines)]
fn running(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    run: &mut Run,
) -> Step {
    use busbar_contract::abi::sdk::services::ServiceError;
    let Some(services) = plane.services else {
        return not_run(unit, run);
    };
    let Some(held) = unit.held.clone() else {
        return not_run(unit, run);
    };
    loop {
        match run.phase {
            Phase::Done | Phase::Far => return Step::Taken,
            Phase::Bind => {
                if run.handle == 0 {
                    let h = handle(ticket, &mut unit.issued, &mut run.find);
                    let (mut buf, mut spans) = ([0u8; WORK_BYTES], [blank(); 1]);
                    let found = match services.work_find(h, &run.reference, &mut buf, &mut spans) {
                        Poll::Pending => return Step::Pending,
                        Poll::Ready(Ok(Some(found))) => found,
                        Poll::Ready(_) => return not_run(unit, run),
                    };
                    let Some(row) = WorkRow::read(found.record) else {
                        return not_run(unit, run);
                    };
                    // THE CALL IT CARRIES IS THE CALL THAT WAS ADMITTED.
                    if row.digest != run.digest {
                        return not_run(unit, run);
                    }
                    if found.state == WORK_SETTLED {
                        // Cancelled before it started: nothing to run.
                        return reply(unit, run, row.status, Vec::new());
                    }
                    run.handle = found.handle;
                    let (reference, work) = (run.reference.clone(), found.handle);
                    plane.tasks.with_all(|m| {
                        m.entry(reference.clone()).or_insert_with(|| {
                            let mut t = Task::from_row(&reference, principal, work, &row, None);
                            t.started = false;
                            t
                        });
                    });
                }
                // THE RUN, TAKEN ONCE: the instance's own half, then the host's one-time claim. The
                // retry of a relayed ask is taken by its state instead, spent once.
                if !run.local {
                    match run.retry.clone() {
                        Some(Retry::Relayed { state, .. }) => {
                            match relayed_leg(plane, services, ticket, principal, unit, run, &state)
                            {
                                Poll::Pending => return Step::Pending,
                                Poll::Ready(Some(leg)) => run.leg = Some(leg),
                                Poll::Ready(None) => return not_run(unit, run),
                            }
                        }
                        // THE RESUME of an answered round of the task's own asks: the update that
                        // answered it nested it once, and the host's one-time claim of that round
                        // takes it; it asks from that round on.
                        Some(Retry::Asked(round)) => {
                            let working = plane.tasks.get(&run.reference).is_some_and(|t| {
                                t.owned_by(principal) && t.status() == Status::Working
                            });
                            if !working {
                                return not_run(unit, run);
                            }
                            run.round = round;
                        }
                        None => {
                            let took = plane.tasks.with(&run.reference, |t| match t {
                                Some(t) if !t.started && t.owned_by(principal) => {
                                    t.started = true;
                                    true
                                }
                                _ => false,
                            });
                            if !took {
                                return not_run(unit, run);
                            }
                        }
                    }
                    run.local = true;
                }
                if run.leg.is_none() {
                    let h = handle(ticket, &mut unit.issued, &mut run.claim);
                    let key = match run.retry {
                        Some(Retry::Asked(round)) => format!("task-run:{}/{round}", run.reference),
                        _ => format!("task-run:{}", run.reference),
                    };
                    match services.records_claim(
                        h,
                        crate::door::KIND_APPROVAL,
                        key.as_bytes(),
                        RUN_CLAIM_TTL_MS,
                    ) {
                        Poll::Pending => return Step::Pending,
                        // The host's ledger said this unit takes the run; or no store is bound, and
                        // the instance's own half was the whole gate.
                        Poll::Ready(
                            Ok(true)
                            | Err(
                                ServiceError::Declined(AbiOutcome::Refused)
                                | ServiceError::Unserved,
                            ),
                        ) => {}
                        Poll::Ready(_) => return not_run(unit, run),
                    }
                }
                // THE HANDLE, BOUND to this unit (principal-checked).
                let h = handle(ticket, &mut unit.issued, &mut run.resume);
                let (mut buf, mut spans) = ([0u8; WORK_BYTES], [blank(); 1]);
                match services.work_resume(h, run.handle, &mut buf, &mut spans) {
                    Poll::Pending => return Step::Pending,
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(_)) => return not_run(unit, run),
                }
                let runner = (unit.key, ticket);
                plane.tasks.with(&run.reference, |t| {
                    if let Some(t) = t {
                        t.runner = Some(runner);
                    }
                });
                // The retry's caller already answered busbar's own rounds before the first call.
                run.phase = if run.leg.is_some() {
                    Phase::Call
                } else {
                    Phase::Ask
                };
            }
            Phase::Ask => {
                let name = run.params.get("name").and_then(Value::as_str).unwrap_or("");
                let rounds = held.catalogue.tool(name).map_or_else(Vec::new, |entry| {
                    tasks::task_ask_rounds(&entry.task_ask_caller, &capabilities(Some(&run.params)))
                });
                let now = task_clock_ms(services, ticket, &mut unit.issued);
                while let Some(asks) = rounds.get(run.round) {
                    enum Then {
                        Next,
                        Park(Box<Task>),
                        Gone(Status),
                    }
                    let asked = (run.round, run.params.clone());
                    let then = plane.tasks.with(&run.reference, |t| {
                        let Some(t) = t else {
                            return Then::Gone(Status::Cancelled);
                        };
                        if t.status().is_terminal() {
                            return Then::Gone(t.status());
                        }
                        t.park(asks.clone(), now);
                        if t.answered() {
                            return Then::Next;
                        }
                        t.asked = Some(asked);
                        t.runner = None;
                        Then::Park(Box::new(t.clone()))
                    });
                    match then {
                        Then::Gone(status) => return reply(unit, run, status, Vec::new()),
                        // PARKED ON ITS CALLER: the continuation ends with the handle live and the
                        // task's live state in the plane's records; the `tasks/update` that answers
                        // the round, on whichever node, nests the resume.
                        Then::Park(task) => {
                            let records = live_records(plane, &task, Some(0));
                            return reply(unit, run, Status::InputRequired, records);
                        }
                        Then::Next => run.round += 1,
                    }
                }
                plane.tasks.with(&run.reference, |t| {
                    if let Some(t) = t {
                        t.set_working(now);
                    }
                });
                run.phase = Phase::Call;
            }
            Phase::Call => {
                // A cancel that landed while it waited: observed here, before anything goes out.
                if let Some(status) = plane
                    .tasks
                    .get(&run.reference)
                    .map(|t| t.status())
                    .filter(|s| s.is_terminal())
                {
                    return reply(unit, run, status, Vec::new());
                }
                let answers = plane
                    .tasks
                    .get(&run.reference)
                    .map(|t| t.answers().clone())
                    .unwrap_or_default();
                match call(services, ticket, &held, unit, run, &answers) {
                    // THE RUN'S LEASE, renewed as its call goes out: the task's live state and its
                    // index row ride the request.
                    Ok(Step::Write) => {
                        if let Some(task) = plane.tasks.get(&run.reference) {
                            let timeout = unit
                                .member
                                .as_ref()
                                .and_then(|m| held.section.servers.get(m))
                                .map_or(0, crate::tools_config::McpServerDefCfg::timeout_ms);
                            let now = task_clock_ms(services, ticket, &mut unit.issued);
                            let until = now
                                .saturating_add(timeout)
                                .saturating_add(tasks::RUN_LEASE_MS);
                            let records = live_records(plane, &task, Some(until));
                            ride(unit, records);
                        }
                        return Step::Write;
                    }
                    Ok(step) => return step,
                    Err(end) => {
                        run.end = Some(end);
                        run.phase = Phase::Settle;
                    }
                }
            }
            Phase::Settle => {
                let Some(end) = run.end.clone() else {
                    return not_run(unit, run);
                };
                let at = match run.at {
                    Some(at) => at,
                    None => {
                        let at = task_clock_ms(services, ticket, &mut unit.issued);
                        run.at = Some(at);
                        at
                    }
                };
                let apply = |t: &mut Task| match &end {
                    End::Completed(value) => t.complete(value.clone(), at),
                    End::Failed(message) => t.fail(TASK_PROTOCOL_ERROR_CODE, message.clone(), at),
                };
                let principal_task = plane.tasks.get(&run.reference).unwrap_or_else(|| {
                    Task::new(&run.reference, principal, run.handle, &run.digest, at)
                });
                let mut settled = principal_task.clone();
                apply(&mut settled);
                let h = handle(ticket, &mut unit.issued, &mut run.settle);
                let won = match services.work_settle(h, run.handle, &settled.row()) {
                    Poll::Pending => return Step::Pending,
                    Poll::Ready(Ok(())) => Some(true),
                    // The handle was settled first: `tasks/cancel` won.
                    Poll::Ready(Err(ServiceError::Declined(AbiOutcome::Refused))) => Some(false),
                    // The host could not say: the instance's word stands, and the settle is owed to
                    // the next create's sweep.
                    Poll::Ready(Err(_)) => None,
                };
                let reference = run.reference.clone();
                let (status, chunks) = plane.tasks.with_all(|m| {
                    let t = m.entry(reference.clone()).or_insert(principal_task);
                    t.runner = None;
                    match won {
                        Some(false) => {
                            t.cancel(at);
                            (t.status(), Vec::new())
                        }
                        won => {
                            apply(t);
                            t.unsettled = won.is_none();
                            let chunks = match (won, t.terminal()) {
                                (Some(true), Some(terminal)) => {
                                    tasks::result_chunks(&reference, &terminal)
                                }
                                _ => Vec::new(),
                            };
                            t.chunks = u32::try_from(chunks.len()).unwrap_or(0);
                            (t.status(), chunks)
                        }
                    }
                });
                // A settle that landed leaves the task's live state and index row to strike.
                let mut records = chunks;
                if won.is_some() {
                    if let Some(task) = plane.tasks.get(&reference) {
                        records.extend(struck_records(&task));
                    }
                }
                return reply(unit, run, status, records);
            }
        }
    }
}

/// THE CALL, sent to the member the continuation's walk picked: the arguments as admitted with the
/// task's answers merged in (`answers`), judged again by the argument guard on what is actually
/// about to be dispatched (the answers were never screened), a pool's twin taken as the synchronous
/// path takes it. Every host the arguments name is asked of `dest.judge` on `ticket`. `Err` = the
/// task ends here, in the engine's words.
fn call(
    services: Services,
    ticket: Ticket,
    held: &Held,
    unit: &mut CallUnit,
    run: &mut Run,
    answers: &Map<String, Value>,
) -> Result<Step, End> {
    let name = run.params.get("name").and_then(Value::as_str).unwrap_or("");
    let Some(entry) = held.catalogue.tool(name).cloned() else {
        return Err(End::Failed(format!(
            "`{name}` is not a tool this server exposes"
        )));
    };
    let arguments = tasks::merge_answers(
        &run.params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({})),
        answers,
    );
    let schema = entry
        .input_schema
        .clone()
        .unwrap_or_else(|| json!({ "type": "object" }));
    let judged = crate::argguard::guard(&schema, &arguments, |dest| {
        let h = handle(ticket, &mut unit.issued, &mut None);
        super::dest_verdict(services, h, held, &entry, dest)
    });
    if let Err(refused) = judged {
        return Err(End::Failed(refused.to_string()));
    }
    let Some(member) = unit.member.clone() else {
        // No member to send it to: the walk's terminal is the kernel's to render.
        return Ok(Step::Taken);
    };
    // A RELAYED ASK'S RETRY goes back to the member that asked, and no other.
    if run.leg.as_ref().is_some_and(|leg| leg.member != member) {
        return Ok(Step::Decline);
    }
    let entry = match twin_of(held, Some(&run.params), &member) {
        Twin::Same => entry,
        Twin::Declined => return Ok(Step::Decline),
        Twin::Call(published) => match held.catalogue.tool(&published) {
            Some(twin) => twin.clone(),
            None => return Ok(Step::Decline),
        },
    };
    let Some(def) = held.section.servers.get(&member) else {
        return Ok(Step::Decline);
    };
    // THE RETRY: the caller's answers and the upstream's own state, verbatim, on the next round.
    let relay = run.leg.as_ref().map(|leg| {
        let mut continuation = Map::new();
        if let Some(Retry::Relayed { responses, .. }) = &run.retry {
            continuation.insert("inputResponses".into(), responses.clone());
        }
        if let Some(state) = &leg.state {
            continuation.insert("requestState".into(), state.clone());
        }
        Box::new(RelayedRetry {
            member: leg.member.clone(),
            round: leg.round,
            continuation: Value::Object(continuation),
            child: leg.child.clone(),
        })
    });
    let round = relay.as_ref().map_or(0, |r| r.round);
    let admitted = AdmittedCall {
        sent_digest: crate::ask::digest_arguments(&arguments),
        entry,
        arguments,
        id: json!(0),
        progress_token: None,
        // The caller's declared capabilities: what an upstream's ask may be relayed to it for.
        capabilities: capabilities(Some(&run.params)),
        relay,
    };
    let continuation = admitted.relay.as_ref().map(|r| r.continuation.clone());
    let Some(outbound) =
        crate::call::outbound(&admitted, &member, def, round, continuation.as_ref())
    else {
        return Err(End::Failed(format!(
            "server `{member}` registers no `url:` this door can reach it at"
        )));
    };
    unit.pending = Some(Pending::far(outbound).laned(&admitted.entry.namespaced));
    let mut relay = Relay::of(admitted);
    relay.round = round;
    unit.relay = Some(relay);
    run.phase = Phase::Far;
    Ok(Step::Write)
}

// ── the verbs ─────────────────────────────────────────────────────────────────────────────────

/// THE RUN THAT CONTINUES A TASK, nested by the `tasks/update` that answered it (under the updating
/// caller's principal, the task's own) on the task-run claim: `body` names the task, its call and
/// what continues it. The records the update leaves: the task's live state, its run's lease taken;
/// a host that runs no continuation for it fails the task, its settle owed until it lands.
fn nest_run(
    plane: &McpDoor,
    services: Services,
    ticket: Ticket,
    unit: &mut CallUnit,
    task: &Task,
    body: &Value,
    at: u64,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let body = serde_json::to_vec(body).unwrap_or_default();
    let mut fresh = None;
    let h = handle(ticket, &mut unit.issued, &mut fresh);
    let mut buf = vec![0u8; 1024];
    let mut spans = vec![blank(); 8];
    match services.unit_nest(
        h,
        "POST",
        crate::tool_claims::TASK_RUN_MOUNT,
        &body,
        &mut buf,
        &mut spans,
    ) {
        // The run continues: its answer is its own, and nobody waits for it here.
        Poll::Pending
        | Poll::Ready(Ok(_))
        | Poll::Ready(Err(busbar_contract::abi::sdk::services::ServiceError::Short { .. })) => {
            live_records(plane, task, Some(at.saturating_add(tasks::RUN_LEASE_MS)))
        }
        Poll::Ready(Err(_)) => {
            let failed = plane.tasks.with(&task.id, |t| {
                t.and_then(|t| {
                    t.fail(
                        TASK_PROTOCOL_ERROR_CODE,
                        "the host ran no continuation for the caller's answer".to_string(),
                        at,
                    )
                    .then(|| t.clone())
                })
            });
            match failed {
                Some(t) if settled(services, ticket, &mut unit.issued, t.handle, &t.row()) => {
                    struck_records(&t)
                }
                Some(t) => {
                    owe(plane, &t);
                    Vec::new()
                }
                None => Vec::new(),
            }
        }
    }
}

/// What resolving a verb's `taskId` came to.
enum Resolved {
    /// A host call pended.
    Pending,
    /// No task of this caller's.
    Unknown,
    /// The task.
    Task(Box<Task>),
}

/// A `tasks/*` VERB (`op`) under the caller's request id `id`: behind the `-32021` gate, then
/// `params.taskId`, then the task — `tasks/get` the detailed task with its result INLINED when
/// terminal, `tasks/update` the input delivered (an empty ack), `tasks/cancel` the handle settled
/// `cancelled` (an empty ack, idempotent on a settled task).
pub(super) fn verb(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    op: busbar_contract::ids::OpClassId,
    id: &Value,
) -> Step {
    let params = unit.params.clone();
    if !crate::call::client_declares_tasks(&capabilities(params.as_ref())) {
        return refuse(unit, &crate::call::missing_tasks_capability(id));
    }
    let Some(task_id) = params
        .as_ref()
        .and_then(|p| p.get("taskId"))
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return refuse(unit, &invalid(id, NO_TASK_ID));
    };
    let Some(services) = plane.services else {
        return refuse(unit, &invalid(id, UNKNOWN_TASK));
    };
    let mut st = match unit.task.take() {
        Some(TaskUnit::Verb(st)) => st,
        _ => Verb::default(),
    };
    let step = verbing(
        plane,
        services,
        ticket,
        principal,
        unit,
        op,
        id,
        &task_id,
        params.as_ref(),
        &mut st,
    );
    if unit.task.is_none() {
        unit.task = Some(TaskUnit::Verb(st));
    }
    step
}

#[allow(clippy::too_many_arguments)]
fn verbing(
    plane: &McpDoor,
    services: Services,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    op: busbar_contract::ids::OpClassId,
    id: &Value,
    task_id: &str,
    params: Option<&Value>,
    st: &mut Verb,
) -> Step {
    use busbar_contract::abi::sdk::services::ServiceError;
    let task = match resolve(plane, services, ticket, principal, unit, task_id, st) {
        Resolved::Pending => return Step::Pending,
        Resolved::Unknown => return refuse(unit, &invalid(id, UNKNOWN_TASK)),
        Resolved::Task(task) => *task,
    };
    let at = match st.at {
        Some(at) => at,
        None => {
            let at = task_clock_ms(services, ticket, &mut unit.issued);
            st.at = Some(at);
            at
        }
    };
    let ack = |unit: &mut CallUnit| answer(unit, 200, crate::call::result(id, json!({})));
    if op == crate::tool_ops::OP_TASK_GET {
        return answer(unit, 200, crate::call::result(id, task.detailed()));
    }
    if op == crate::tool_ops::OP_TASK_UPDATE {
        // ABSENT is treated as empty rather than refused.
        let responses = params
            .and_then(|p| p.get("inputResponses"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let delivered = plane.tasks.with(&task.id, |t| {
            t.map(|t| {
                let was = t.status();
                let took = t.deliver(&responses, at);
                let park = t.take_relay();
                let resume = if took
                    && park.is_none()
                    && was == Status::InputRequired
                    && t.status() == Status::Working
                {
                    t.asked.take()
                } else {
                    None
                };
                (took, park, resume, t.clone())
            })
        });
        let (park, resume, t) = match delivered {
            Some((false, ..)) => {
                return refuse(
                    unit,
                    &invalid(
                        id,
                        &format!(
                            "this task already holds {} answer keys, the most one task retains. \
                             `inputResponses` may still update any of its existing keys, but \
                             adding a new one past that ceiling is refused.",
                            tasks::MAX_TASK_ANSWERS
                        ),
                    ),
                )
            }
            Some((true, park, resume, t)) => (park, resume, t),
            None => return ack(unit),
        };
        let records = if t.status().is_terminal() {
            // A terminal task takes no input: nothing moved.
            Vec::new()
        } else if let Some(park) = park {
            // THE CALLER'S ANSWER TO THE UPSTREAM'S ASK continues the task as a NEW unit: the
            // retry, back to the member that asked.
            let body = json!({
                "taskId": t.id,
                "params": park.params,
                "relay": {
                    "requestState": park.state,
                    "inputResponses": Value::Object(park.responses),
                },
            });
            nest_run(plane, services, ticket, unit, &t, &body, at)
        } else if let Some((round, call)) = resume {
            // THE ROUND OF ITS OWN ASKS, ANSWERED: the run resumes there, as a NEW unit.
            let body = json!({ "taskId": t.id, "params": call, "resume": round });
            nest_run(plane, services, ticket, unit, &t, &body, at)
        } else if t.status() == Status::InputRequired {
            live_records(plane, &t, Some(0))
        } else {
            // A run holds it: its state is written, its lease left as the run took it.
            live_records(plane, &t, None)
        };
        let step = ack(unit);
        ride(unit, records);
        return step;
    }
    // `tasks/cancel`: idempotent on a settled task, and audited either way (the served engine's
    // `mcp_task.cancel` row on every cancel of a task the caller holds).
    let cancel_ack = |unit: &mut CallUnit| {
        let step = ack(unit);
        if let Some(p) = unit.pending.take() {
            unit.pending = Some(p.audited(crate::call::AuditRow::task_cancel(&task.id)));
        }
        step
    };
    if task.status().is_terminal() {
        return cancel_ack(unit);
    }
    let mut cancelled = task.clone();
    cancelled.cancel(at);
    let h = handle(ticket, &mut unit.issued, &mut st.settle);
    let landed = match services.work_settle(h, task.handle, &cancelled.row()) {
        Poll::Pending => return Step::Pending,
        Poll::Ready(Ok(())) => Some(true),
        // The continuation settled it first: its terminal state stands.
        Poll::Ready(Err(ServiceError::Declined(AbiOutcome::Refused))) => Some(false),
        // Owed to the next create's sweep, until it lands.
        Poll::Ready(Err(_)) => None,
    };
    if landed != Some(false) {
        plane.tasks.with(&task.id, |t| {
            if let Some(t) = t {
                if t.cancel(at) {
                    t.unsettled = landed.is_none();
                }
            }
        });
    }
    let step = cancel_ack(unit);
    if landed == Some(true) {
        ride(unit, struck_records(&cancelled));
    }
    step
}

/// The task `task_id` names FOR THIS CALLER, from the host's rows (THE DESIGN, the mcp bullet: the
/// task store is host records): `work.find` (scoped to the instance and the principal; every denial alike); a
/// live handle's live state in the plane's records; a settled one's row and the result written
/// there (or the result this instance holds, when it holds one the records could not). The
/// instance's own halves of the task are kept beside what the host says.
fn resolve(
    plane: &McpDoor,
    services: Services,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    task_id: &str,
    st: &mut Verb,
) -> Resolved {
    let h = handle(ticket, &mut unit.issued, &mut st.find);
    let (mut buf, mut spans) = ([0u8; WORK_BYTES], [blank(); 1]);
    let (state, work, row) = match services.work_find(h, task_id, &mut buf, &mut spans) {
        Poll::Pending => return Resolved::Pending,
        Poll::Ready(Ok(Some(found))) => (found.state, found.handle, WorkRow::read(found.record)),
        Poll::Ready(_) => return Resolved::Unknown,
    };
    let held = plane.tasks.get(&task_id.to_string());
    if held.as_ref().is_some_and(|t| !t.owned_by(principal)) {
        return Resolved::Unknown;
    }
    if state != WORK_LIVE {
        if let Some(task) = held.as_ref().filter(|t| t.status().is_terminal()) {
            return Resolved::Task(Box::new(task.clone()));
        }
    }
    // A host that lists none of the plane's records: what the instance holds answers.
    let unlisted =
        |held: Option<Task>| held.map_or(Resolved::Unknown, |t| Resolved::Task(Box::new(t)));
    let Some(row) = row else {
        return Resolved::Unknown;
    };
    let mut task = if state == WORK_LIVE {
        // ITS LIVE STATE, read back from its chunks.
        let prefix = tasks::live_prefix(task_id);
        match list(
            services,
            ticket,
            &mut unit.issued,
            &prefix,
            false,
            &mut st.live,
        ) {
            Poll::Pending => return Resolved::Pending,
            Poll::Ready(false) => return unlisted(held),
            Poll::Ready(true) => {}
        }
        let mut task = Task::from_row(task_id, principal, work, &row, None);
        let bytes: Vec<u8> = st.live.rows.iter().flat_map(|(_, v)| v.clone()).collect();
        if let Some(live) = tasks::read_live(&bytes) {
            task.take_live(&live);
        }
        task
    } else {
        let terminal = match row.status {
            Status::Completed | Status::Failed => {
                // THE RESULT, read back from its chunks.
                let prefix = tasks::chunk_prefix(task_id);
                match list(
                    services,
                    ticket,
                    &mut unit.issued,
                    &prefix,
                    false,
                    &mut st.result,
                ) {
                    Poll::Pending => return Resolved::Pending,
                    Poll::Ready(false) => return unlisted(held),
                    Poll::Ready(true) => {}
                }
                match tasks::read_chunks(st.result.rows.iter().map(|(_, v)| v.as_slice())) {
                    Some(terminal) => Some(terminal),
                    None => return Resolved::Unknown,
                }
            }
            _ => None,
        };
        Task::from_row(task_id, principal, work, &row, terminal.as_ref())
    };
    let host = task.clone();
    plane.tasks.with_all(|m| match m.get_mut(task_id) {
        Some(t) => {
            t.hosted(host);
            task = t.clone();
        }
        None => {
            m.insert(task_id.to_string(), host);
        }
    });
    Resolved::Task(Box::new(task))
}

// ── the kernel's own ends of a continuation ───────────────────────────────────────────────────

/// The kernel cancelled the unit on `ticket` (its caller went, its deadline passed, the node
/// drains): a continuation running on it leaves its task `cancelled` — the transition a caller's
/// `tasks/cancel` makes, as the served engine's runner settled a task its shutdown stopped. The
/// handle is settled by the next create's sweep.
///
/// Answers the ids of the tasks it moved to `cancelled`: each is audited as the served engine's
/// runner audited a task its shutdown stopped (`mcp_task.cancel`).
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) -> Vec<String> {
    let now = clock_now(plane);
    let mut moved = Vec::new();
    plane.tasks.with_all(|m| {
        for (id, t) in m.iter_mut() {
            if t.runner.is_some_and(|(_, tk)| tk == ticket) {
                let at = now.unwrap_or(t.stamps().1);
                if t.cancel(at) {
                    t.unsettled = true;
                    moved.push(id.clone());
                }
                t.runner = None;
            }
        }
    });
    moved
}

/// The kernel refused the continuation `unit` (`text`: its walk was exhausted, its budget said no)
/// before it settled its task: the task fails, as the served engine's runner failed a call that
/// could not be carried. A task another continuation took is not touched.
pub(super) fn continuation_refused(plane: &McpDoor, unit: u64, reference: &str, text: &str) {
    let now = clock_now(plane);
    plane.tasks.with(&reference.to_string(), |t| {
        let Some(t) = t else {
            return;
        };
        let ran_here = t.runner.is_some_and(|(u, _)| u == unit);
        if !ran_here && t.started {
            return;
        }
        let at = now.unwrap_or(t.stamps().1);
        if t.fail(
            TASK_PROTOCOL_ERROR_CODE,
            format!("the MCP upstream call failed: {text}"),
            at,
        ) {
            t.unsettled = true;
        }
        t.started = true;
        t.runner = None;
    });
}

/// The reference of the continuation `unit`, when it is one.
pub(super) fn run_reference(unit: &CallUnit) -> Option<String> {
    match unit.task.as_ref() {
        Some(TaskUnit::Run(run)) if run.phase != Phase::Done => Some(run.reference.clone()),
        _ => None,
    }
}

/// The kernel's clock read off-unit (a call that may not pend), in Unix milliseconds.
fn clock_now(plane: &McpDoor) -> Option<u64> {
    let services = plane.services?;
    let h = CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    };
    services.clock_now(h).ok().map(|r| r.wall_ns / 1_000_000)
}
