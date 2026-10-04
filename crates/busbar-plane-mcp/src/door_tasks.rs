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
//!   A settle the handle refuses means `tasks/cancel` got there first.
//! * `tasks/get` is `work.find` plus what the instance holds of the task (or, when it holds none,
//!   the result written in the plane's records); `tasks/update` delivers input and wakes the
//!   continuation; `tasks/cancel` settles the handle `cancelled`, which the continuation observes
//!   on its next step.

use std::task::Poll;

use busbar_contract::abi::host::service::{ItemSpan, WORK_LIVE, WORK_SETTLED};
use busbar_contract::abi::mechanism::call::Outcome as AbiOutcome;
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use serde_json::{json, Map, Value};

use super::{
    clock_s, twin_of, CallUnit, CompletionHandle, Held, McpDoor, Pending, Relay, Services, Step,
    Ticket, Twin,
};
use crate::call::{AdmittedCall, Leg};
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

impl TaskUnit {
    /// A continuation of task `reference`, running `params`.
    pub(super) fn run(reference: String, params: Value) -> Self {
        let digest = run_digest(&params);
        TaskUnit::Run(Box::new(Run {
            reference,
            params,
            digest,
            begun: false,
            phase: Phase::Bind,
            find: None,
            claim: None,
            resume: None,
            settle: None,
            local: false,
            handle: 0,
            round: 0,
            parked: None,
            end: None,
            at: None,
            answered: false,
        }))
    }
}

/// The creating unit's progress: the handle numbers its host calls were issued under (a call that
/// pends is re-issued under its first number), the handle it opened, and whether the continuation
/// was nested.
#[derive(Default)]
pub(super) struct Create {
    open: Option<u32>,
    nest: Option<u32>,
    opened: Option<(u64, String)>,
    nested: bool,
    swept: bool,
    at: Option<u64>,
}

/// A verb's progress.
#[derive(Default)]
pub(super) struct Verb {
    find: Option<u32>,
    settle: Option<u32>,
    list: Option<u32>,
    after: Option<Vec<u8>>,
    read: Vec<u8>,
    listed: bool,
    at: Option<u64>,
}

/// A continuation.
pub(super) struct Run {
    reference: String,
    /// The call it runs: the published name, the arguments as admitted, the caller's `_meta`.
    params: Value,
    digest: String,
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
    /// The task ask round it is on, and the round it parked the task on.
    round: usize,
    parked: Option<usize>,
    /// The terminal state it settles, and when it reached it.
    end: Option<End>,
    at: Option<u64>,
    /// A far end answered one of its rounds: the tool call it reports.
    answered: bool,
}

/// Where a continuation is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Finding, claiming and binding its handle.
    Bind,
    /// Asking its caller the task's own rounds.
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
fn blank() -> ItemSpan {
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
fn handle(ticket: Ticket, issued: &mut u32, slot: &mut Option<u32>) -> CompletionHandle {
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

/// THE CONTINUATION'S ARRIVAL on the task-run claim: its reference, the call it runs, and that call
/// as the `tools/call` body the one dispatch decides (its head fields mirrored from it). `None` for
/// a body that is not one.
pub(super) fn run_arrival(body: &[u8]) -> Option<(String, Value, Vec<u8>)> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let reference = value.get("taskId")?.as_str()?.to_string();
    let params = value.get("params")?.clone();
    params.get("name")?.as_str()?;
    let call = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": crate::codec::METHOD_TOOLS_CALL,
        "params": params,
    });
    Some((reference, params, serde_json::to_vec(&call).ok()?))
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

/// Wake the continuation `task` runs on, where one waits.
fn wake(plane: &McpDoor, task: &Task) {
    if let (Some(wake), Some((_, ticket))) = (plane.wake, task.runner) {
        wake.wake(ticket);
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
    // in hand with its handle unsettled is settled now; its answer is not waited on.
    if !st.swept {
        st.swept = true;
        let swept = plane.tasks.with_all(|m| tasks::sweep(m, now));
        if let Some(wake) = plane.wake {
            swept.wake.iter().for_each(|t| wake.wake(*t));
        }
        for (work, task) in &swept.settle {
            let mut fresh = None;
            let h = handle(ticket, &mut unit.issued, &mut fresh);
            let _unheard = services.work_settle(h, *work, &task.row());
        }
        plane.strikes.with_all(|m| {
            for (id, chunks) in swept.strike {
                m.insert(id, chunks);
            }
        });
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
            Poll::Ready(Err(_)) => return unavailable(
                unit,
                "the deployment holds as many live tasks as it keeps, or keeps no store for them",
            ),
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
            // task is settled failed, not waited on, and the call refused.
            Poll::Ready(Err(_)) => {
                if let Some(mut task) = plane.tasks.remove(&reference) {
                    task.fail(
                        TASK_PROTOCOL_ERROR_CODE,
                        "the host ran no continuation for this task".to_string(),
                        now,
                    );
                    let mut fresh = None;
                    let h = handle(ticket, &mut unit.issued, &mut fresh);
                    let _unheard = services.work_settle(h, work, &task.row());
                }
                return unavailable(unit, "the host runs no continuation for it");
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
    unit.pending = Some(pending);
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

/// A continuation called again part way through a phase that waits on the host or its caller (a
/// pend's wake, a delivered answer, a cancel): the phase goes on. `None` for any other unit.
pub(super) fn resume(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    match unit.task.as_ref() {
        Some(TaskUnit::Run(run))
            if run.begun && matches!(run.phase, Phase::Bind | Phase::Ask | Phase::Settle) => {}
        _ => return None,
    }
    Some(advance(plane, ticket, principal, unit))
}

/// THE FAR END ANSWERED THE CONTINUATION'S CALL (its rounds settled): the terminal state the served
/// engine's runner settled — the tool's result as it came (`completed`, `isError` and all); an
/// upstream failure or a refusal of an upstream's ask, `failed` — then the handle settled.
pub(super) fn continuation_answered(
    plane: &McpDoor,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    leg: Leg,
    answered: bool,
    body: &[u8],
) -> Step {
    if let Some(TaskUnit::Run(run)) = unit.task.as_mut() {
        run.answered |= answered;
        run.end = Some(match leg {
            Leg::Done(value) => End::Completed(crate::sanitize::normalise_json(&value)),
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
        pending = pending.counted();
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
                // THE RUN, TAKEN ONCE: the instance's own half, then the host's one-time claim.
                if !run.local {
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
                    run.local = true;
                }
                let h = handle(ticket, &mut unit.issued, &mut run.claim);
                let key = format!("task-run:{}", run.reference);
                match services.records_claim(
                    h,
                    crate::door::KIND_APPROVAL,
                    key.as_bytes(),
                    RUN_CLAIM_TTL_MS,
                ) {
                    Poll::Pending => return Step::Pending,
                    // The host's ledger said this unit takes the run; or no store is bound, and the
                    // instance's own half was the whole gate.
                    Poll::Ready(
                        Ok(true)
                        | Err(ServiceError::Declined(AbiOutcome::Refused) | ServiceError::Unserved),
                    ) => {}
                    Poll::Ready(_) => return not_run(unit, run),
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
                run.phase = Phase::Ask;
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
                        Wait,
                        Gone(Status),
                    }
                    let parked = run.parked == Some(run.round);
                    let runner = (unit.key, ticket);
                    let then = plane.tasks.with(&run.reference, |t| {
                        let Some(t) = t else {
                            return Then::Gone(Status::Cancelled);
                        };
                        if t.status().is_terminal() {
                            return Then::Gone(t.status());
                        }
                        if !parked {
                            t.park(asks.clone(), now);
                        }
                        if t.answered() {
                            Then::Next
                        } else {
                            t.runner = Some(runner);
                            Then::Wait
                        }
                    });
                    match then {
                        Then::Gone(status) => return reply(unit, run, status, Vec::new()),
                        Then::Wait => {
                            run.parked = Some(run.round);
                            return Step::Wait(0);
                        }
                        Then::Next => {
                            run.round += 1;
                            run.parked = None;
                        }
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
                match call(&held, unit, run, &answers) {
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
                    // The host could not say: the instance's word stands, and the handle is settled
                    // by the next create's sweep.
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
                return reply(unit, run, status, chunks);
            }
        }
    }
}

/// THE CALL, sent to the member the continuation's walk picked: the arguments as admitted with the
/// task's answers merged in (`answers`), judged again by the argument guard on what is actually
/// about to be dispatched (the answers were never screened), a pool's twin taken as the synchronous
/// path takes it. `Err` = the task ends here, in the engine's words.
fn call(
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
    let policy = crate::argguard::SsrfPolicy {
        allow_private: held
            .section
            .servers
            .get(&entry.server)
            .is_some_and(|d| d.allow_private),
    };
    if let Err(refused) = crate::argguard::guard(&schema, &arguments, policy) {
        return Err(End::Failed(refused.to_string()));
    }
    let Some(member) = unit.member.clone() else {
        // No member to send it to: the walk's terminal is the kernel's to render.
        return Ok(Step::Taken);
    };
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
    let admitted = AdmittedCall {
        entry,
        arguments,
        id: json!(0),
        progress_token: None,
    };
    let Some(outbound) = crate::call::outbound(&admitted, &member, def, 0, None) else {
        return Err(End::Failed(format!(
            "server `{member}` registers no `url:` this door can reach it at"
        )));
    };
    unit.pending = Some(Pending::far(outbound));
    unit.relay = Some(Relay::of(admitted));
    run.phase = Phase::Far;
    Ok(Step::Write)
}

// ── the verbs ─────────────────────────────────────────────────────────────────────────────────

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
            t.map(|t| (t.deliver(&responses, at), t.clone()))
        });
        return match delivered {
            Some((false, _)) => refuse(
                unit,
                &invalid(
                    id,
                    &format!(
                        "this task already holds {} answer keys, the most one task retains. \
                         `inputResponses` may still update any of its existing keys, but adding a \
                         new one past that ceiling is refused.",
                        tasks::MAX_TASK_ANSWERS
                    ),
                ),
            ),
            Some((true, t)) => {
                wake(plane, &t);
                ack(unit)
            }
            None => ack(unit),
        };
    }
    // `tasks/cancel`: idempotent on a settled task.
    if task.status().is_terminal() {
        return ack(unit);
    }
    let mut cancelled = task.clone();
    cancelled.cancel(at);
    let h = handle(ticket, &mut unit.issued, &mut st.settle);
    let settled = match services.work_settle(h, task.handle, &cancelled.row()) {
        Poll::Pending => return Step::Pending,
        Poll::Ready(Ok(())) => Some(true),
        // The continuation settled it first: its terminal state stands.
        Poll::Ready(Err(ServiceError::Declined(AbiOutcome::Refused))) => Some(false),
        Poll::Ready(Err(_)) => None,
    };
    if settled != Some(false) {
        let moved = plane.tasks.with(&task.id, |t| {
            t.and_then(|t| {
                t.cancel(at).then(|| {
                    t.unsettled = settled.is_none();
                    t.clone()
                })
            })
        });
        if let Some(t) = moved {
            wake(plane, &t);
        }
    }
    ack(unit)
}

/// The task `task_id` names FOR THIS CALLER: `work.find` (scoped to the instance and the principal;
/// every denial alike), then what the instance holds of it, else — for a settled handle — its row
/// and the result written in the plane's records. A live handle the instance holds nothing of has
/// no continuation in this process: unknown, as the served engine answered every task after a
/// restart.
fn resolve(
    plane: &McpDoor,
    services: Services,
    ticket: Ticket,
    principal: &str,
    unit: &mut CallUnit,
    task_id: &str,
    st: &mut Verb,
) -> Resolved {
    use busbar_contract::abi::sdk::services::ServiceError;
    let h = handle(ticket, &mut unit.issued, &mut st.find);
    let (mut buf, mut spans) = ([0u8; WORK_BYTES], [blank(); 1]);
    let found = match services.work_find(h, task_id, &mut buf, &mut spans) {
        Poll::Pending => return Resolved::Pending,
        Poll::Ready(Ok(Some(found))) => found,
        Poll::Ready(_) => return Resolved::Unknown,
    };
    if let Some(task) = plane.tasks.get(&task_id.to_string()) {
        return if task.owned_by(principal) {
            Resolved::Task(Box::new(task))
        } else {
            Resolved::Unknown
        };
    }
    if found.state == WORK_LIVE {
        return Resolved::Unknown;
    }
    let Some(row) = WorkRow::read(found.record) else {
        return Resolved::Unknown;
    };
    let terminal = match row.status {
        Status::Completed | Status::Failed => {
            // THE RESULT, read back from its chunks, page by page.
            while !st.listed {
                let prefix = tasks::chunk_prefix(task_id);
                let h = handle(ticket, &mut unit.issued, &mut st.list);
                let mut sizes = (64 * 1024, PAGE as usize);
                let mut page: Option<(usize, Option<Vec<u8>>)> = None;
                for _ in 0..2 {
                    let mut buf = vec![0u8; sizes.0];
                    let mut spans = vec![blank(); sizes.1];
                    match services.records_list(
                        h,
                        crate::door::KIND_TASK,
                        &prefix,
                        st.after.as_deref(),
                        PAGE,
                        (&mut buf, &mut spans),
                    ) {
                        Poll::Pending => return Resolved::Pending,
                        Poll::Ready(Ok(records)) => {
                            let mut n = 0;
                            for (_, value) in records.records() {
                                st.read.extend_from_slice(value);
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
                        Poll::Ready(Err(_)) => return Resolved::Unknown,
                    }
                }
                let Some((n, last)) = page else {
                    return Resolved::Unknown;
                };
                st.list = None;
                if n < PAGE as usize || last.is_none() {
                    st.listed = true;
                } else {
                    st.after = last;
                }
            }
            match tasks::read_chunks(std::iter::once(st.read.as_slice())) {
                Some(terminal) => Some(terminal),
                None => return Resolved::Unknown,
            }
        }
        _ => None,
    };
    let task = Task::from_row(task_id, principal, found.handle, &row, terminal.as_ref());
    plane.tasks.insert(task_id.to_string(), task.clone());
    Resolved::Task(Box::new(task))
}

// ── the kernel's own ends of a continuation ───────────────────────────────────────────────────

/// The kernel cancelled the unit on `ticket` (its caller went, its deadline passed, the node
/// drains): a continuation running on it leaves its task `cancelled` — the transition a caller's
/// `tasks/cancel` makes, as the served engine's runner settled a task its shutdown stopped. The
/// handle is settled by the next create's sweep.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    let now = clock_now(plane);
    plane.tasks.with_all(|m| {
        for t in m.values_mut() {
            if t.runner.is_some_and(|(_, tk)| tk == ticket) {
                let at = now.unwrap_or(t.stamps().1);
                if t.cancel(at) {
                    t.unsettled = true;
                }
                t.runner = None;
            }
        }
    });
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
