// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEP-2663 — THE TASKS EXTENSION on the MCP server plane.
//!
//! A `tools/call` that would take longer than a request may reasonably be held open for is answered
//! with a `CreateTaskResult` instead of a result: the caller is handed a `taskId` and polls
//! `tasks/get` until the task reaches a terminal state, at which point the original tool result is
//! INLINED on the poll response. `tasks/update` delivers input the task asked for; `tasks/cancel`
//! stops it. There is no `tasks/result` and no `tasks/list` — both were removed in the v2 wire, and
//! busbar answering `-32601` to them is deliberate rather than missing.
//!
//! ## WHAT DECIDES WHETHER A TASK IS CREATED, and why it is a registration-time declaration
//!
//! `tools.<server>.tools_allow.<tool>.task_support` — `none`, `optional` or `required`, written by
//! the OPERATOR. Not a runtime property of the call, not a hint the client sends, and not something
//! busbar infers from how long a previous call took.
//!
//! It has to be registration-time because of the gate it feeds. A `required` tool cannot be answered
//! synchronously at all, so a client that did not declare the extension must be refused with
//! `-32021` BEFORE the handler runs — and the only thing that can decide that before the handler
//! runs is what the operator wrote. Inferring it from behaviour would mean discovering the client
//! cannot receive the answer only after having produced it.
//!
//! The client's half of the negotiation is read from the ONE place `2026-07-28` puts it:
//! `params._meta['io.modelcontextprotocol/clientCapabilities'].extensions`. That is the same field
//! for a session-level declaration and for SEP-2575's per-request override, so the two cannot
//! disagree and there is no second code path for the per-request opt-in — see
//! [`client_declares_tasks`].
//!
//! ## WHAT THE STATUSES MEAN, and the one distinction that is easy to get backwards
//!
//! A tool that RAN and reported a failure is `completed` with `result.isError: true`. It is NOT
//! `failed`. `failed` is reserved for a PROTOCOL-level error — the upstream answered a JSON-RPC
//! error, the transport broke, busbar refused to carry the dispatch — and inlines an `error`
//! object with a numeric `code` and a `message`, carrying no `result` at all.
//!
//! The distinction is the same one `isError` already draws on the synchronous path, and it exists
//! for the same reason: a model that is told "the call failed" cannot self-correct, whereas a model
//! that is told "the tool ran and said the file was not found" can.
//!
//! ## DURABILITY IS NOT CLAIMED HERE
//!
//! This registry is IN-PROCESS. A restart loses every in-flight task, and nothing in this module
//! says otherwise. The shared durable task substrate (`store::put_task` / `get_task`) carries no
//! slot for an MCP tool result, and the plugin path that every production store backend runs
//! through does not reach the task methods at all — so writing here would produce a row that
//! reports success while discarding the write, which is worse than not writing. The seam is
//! [`Registry`]: everything above it addresses tasks by id through this type, so a durable
//! implementation replaces this one without touching the method surface.
//!
//! What IS honoured unconditionally is STRONG CONSISTENCY, which is a different property and the
//! one the wire actually requires: [`Registry::create`] inserts the task before the caller is
//! handed its id, so a `tasks/get` issued with no delay between the two always resolves.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use super::callerask::CallerAsk;
use super::catalogue::ToolEntry;
use super::config::AskRoundCfg;

/// The extension identifier, spelled once. It appears in three places that must agree — the
/// server's `capabilities.extensions` advertisement, the client-capability probe, and the
/// `requiredCapabilities` payload on the `-32021` refusal — and three literals would be three
/// chances for one of them to drift.
pub(crate) const TASKS_EXTENSION_ID: &str = "io.modelcontextprotocol/tasks";

/// How long a task stays readable through `tasks/get` after it is created.
///
/// A POSITIVE value here, unlike the catalogue's `ttlMs: 0`, and the difference is not an
/// inconsistency: the catalogue's zero says "this answer may already be stale", which is a claim
/// about freshness; this one says "the server will keep this row for at least this long", which is
/// a claim about RETENTION. Five minutes is comfortably longer than any polling client needs and
/// short enough that an abandoned task is not a permanent allocation.
const TASK_TTL_MS: u64 = 300_000;

/// The poll cadence busbar suggests. Advisory — a client that polls faster is not refused — and
/// deliberately short, because the alternative to a suggestion is every client inventing its own.
const TASK_POLL_INTERVAL_MS: u64 = 250;

/// The hard ceiling on tasks retained in memory at once. Reached only by a deployment creating
/// tasks faster than they expire; the oldest TERMINAL tasks are dropped first, and a working task
/// is never dropped to make room — losing the row of a task that is still running would make its
/// eventual answer unreachable, which is worse than refusing to remember an old completed one.
const MAX_RETAINED_TASKS: usize = 4096;

/// Has this caller declared the tasks extension?
///
/// Reads `capabilities.extensions[TASKS_EXTENSION_ID]`, and PRESENCE is the declaration: the value
/// is a per-extension settings object and `{}` is a complete statement of support. `null` is
/// deliberately not a declaration, matching `callerask::declared` — it is what a client sends when
/// it means "no".
///
/// There is exactly one caller-capability source in this revision, so this function is also the
/// whole of SEP-2575's per-request opt-in: a `tools/call` whose own `_meta` carries the extension
/// arrives here indistinguishable from a session that declared it, because on a protocol with no
/// handshake those are the same statement.
pub(crate) fn client_declares_tasks(capabilities: &serde_json::Value) -> bool {
    capabilities
        .get("extensions")
        .and_then(|e| e.get(TASKS_EXTENSION_ID))
        .is_some_and(|v| !v.is_null())
}

/// The `data.requiredCapabilities` payload on a `-32021` refusal — the shape
/// `MissingRequiredClientCapabilityError` fixes for it, so a client can validate the error against
/// the schema and read what to add without out-of-band documentation.
pub(crate) fn required_tasks_capability() -> serde_json::Value {
    serde_json::json!({ "extensions": { TASKS_EXTENSION_ID: {} } })
}

/// A task's lifecycle state, as the wire spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// Running.
    Working,
    /// Parked on input busbar asked its caller for. `tasks/update` is what un-parks it.
    InputRequired,
    /// The tool RAN. Whether it reported success or an error of its own is in `result.isError` —
    /// see the module header for why a tool error is not `failed`.
    Completed,
    /// A PROTOCOL-level failure. Carries `error`, never `result`.
    Failed,
    /// Cancelled by `tasks/cancel`.
    Cancelled,
}

impl Status {
    fn token(self) -> &'static str {
        match self {
            Status::Working => "working",
            Status::InputRequired => "input_required",
            Status::Completed => "completed",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
        }
    }

    /// Terminal states are the three a task never leaves. `tasks/cancel` on one of them is an
    /// idempotent no-op rather than an error — the spec reserves `-32602` for unknown ids, and a
    /// client racing a completion must not have to distinguish the two.
    fn is_terminal(self) -> bool {
        matches!(self, Status::Completed | Status::Failed | Status::Cancelled)
    }
}

/// The mutable half of a task. Behind its own lock so a poll never waits on the runner.
struct State {
    status: Status,
    /// Unix milliseconds, from the engine's one millisecond clock ([`crate::store::now_ms`]).
    /// Rendered ISO-8601 on the wire; kept numeric here so the retention sweep does not parse
    /// strings back.
    created_ms: u64,
    updated_ms: u64,
    /// The inlined tool result, present only on `completed`.
    result: Option<serde_json::Value>,
    /// The inlined protocol error, present only on `failed`.
    error: Option<serde_json::Value>,
    /// The still-unanswered asks of the current round, in the operator's own order. Answering a key
    /// REMOVES it, which is what makes partial fulfilment observable.
    input_requests: Vec<(String, serde_json::Value)>,
    /// Everything the caller has answered so far, keyed as the operator keyed the ask. Merged into
    /// the tool arguments when the task resumes.
    answers: serde_json::Map<String, serde_json::Value>,
    /// The handle that stops the runner. `None` before the runner is attached and after it has
    /// finished.
    abort: Option<tokio::task::AbortHandle>,
}

/// ONE MCP task.
///
/// `McpTask`, NOT `Task`, and the distinction is deliberate rather than a lint being appeased.
/// `a2a::task::Task` is the A2A plane's task and the two shapes genuinely differ: A2A carries
/// `context_id`, `artifact_cursor` and `push_callback`, and this one carries an inlined tool result
/// and an `inputRequests` map. One name over two shapes would let a reader — or a future refactor —
/// believe a value of one is a value of the other. What the two planes DO share is the concern and
/// the substrate: one clock (`store::now_ms`), and, once the plugin ABI reaches the task methods
/// (A3.1), one durable row. Sharing those is the "one core, three planes" claim being paid; sharing
/// the NAME while the fields differ would only be it being restated.
pub(crate) struct McpTask {
    pub(crate) id: String,
    /// The busbar key id this task belongs to. A caller may only ever address its own tasks, and an
    /// id belonging to somebody else is answered as UNKNOWN rather than as forbidden — the
    /// difference between the two answers is a probe for which ids exist.
    principal: String,
    state: Mutex<State>,
    /// Woken whenever `input_requests` shrinks or the task is cancelled. The runner waits on this
    /// rather than polling, so an answered ask resumes immediately.
    resumed: tokio::sync::Notify,
}

impl McpTask {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Poison-recovering, for the reason `a2a::taskstore` gives for the same pattern: the data
        // behind this lock is a plain struct that is always consistent after a panic, and
        // cascading a poison would make every later task unreadable because one of them tripped.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn touch(state: &mut State) {
        state.updated_ms = crate::store::now_ms();
    }

    /// The `DetailedTask` a `tasks/get` answers with, minus the `resultType` the response builder
    /// stamps.
    ///
    /// `requestState` is ABSENT and its absence is load-bearing: SEP-2663 removed the field from the
    /// v2 wire, and it lives on SEP-2322's `InputRequiredResult` — a lexically adjacent slot in a
    /// document read alongside this one. Putting it here would make a client deduplicate state
    /// across two flows that do not share one.
    pub(crate) fn detailed(&self) -> serde_json::Value {
        let state = self.lock();
        let mut obj = serde_json::Map::new();
        obj.insert("taskId".into(), self.id.clone().into());
        obj.insert("status".into(), state.status.token().into());
        obj.insert("createdAt".into(), iso8601_ms(state.created_ms).into());
        obj.insert("lastUpdatedAt".into(), iso8601_ms(state.updated_ms).into());
        obj.insert("ttlMs".into(), TASK_TTL_MS.into());
        obj.insert("pollIntervalMs".into(), TASK_POLL_INTERVAL_MS.into());
        if let Some(result) = &state.result {
            obj.insert("result".into(), result.clone());
        }
        if let Some(error) = &state.error {
            obj.insert("error".into(), error.clone());
        }
        if !state.input_requests.is_empty() {
            let map: serde_json::Map<String, serde_json::Value> =
                state.input_requests.iter().cloned().collect();
            obj.insert("inputRequests".into(), serde_json::Value::Object(map));
        }
        serde_json::Value::Object(obj)
    }

    /// The `CreateTaskResult` a `tools/call` answers with — a FLAT `Result & Task` intersection, so
    /// `taskId`/`status`/`createdAt`/`lastUpdatedAt`/`ttlMs` sit at the top level and there is no
    /// nested `task` wrapper.
    ///
    /// It carries none of `result`, `error` or `inputRequests`: those are `tasks/get`'s, and a
    /// creation response that carried them would be answering a question the caller has not asked
    /// yet.
    ///
    /// ## Why `content: []` is here
    ///
    /// `2026-07-28`'s own `CallToolResult` makes `content` a required member, and the tasks
    /// extension is not part of that schema — so a `tools/call` response with no `content` is
    /// invalid against the base revision busbar implements, whatever the extension says about it.
    /// An EMPTY array is the honest reconciliation: there is no content yet, the field is present
    /// so a client validating against the base schema is not handed something it must reject, and
    /// the extension forbids nothing here. A client that reads `resultType` sees `task` and never
    /// looks at it.
    pub(crate) fn created(&self) -> serde_json::Value {
        let state = self.lock();
        serde_json::json!({
            "taskId": self.id,
            "status": state.status.token(),
            "createdAt": iso8601_ms(state.created_ms),
            "lastUpdatedAt": iso8601_ms(state.updated_ms),
            "ttlMs": TASK_TTL_MS,
            "pollIntervalMs": TASK_POLL_INTERVAL_MS,
            "content": [],
        })
    }

    /// PARK on a round of asks. Any ask already answered by an earlier `tasks/update` is not
    /// re-asked.
    fn park(&self, asks: Vec<CallerAsk>) {
        let mut state = self.lock();
        state.input_requests = asks
            .into_iter()
            .filter(|a| !state.answers.contains_key(a.key()))
            .map(|a| {
                (
                    a.key().to_string(),
                    serde_json::json!({ "method": a.method(), "params": a.params() }),
                )
            })
            .collect();
        if !state.input_requests.is_empty() {
            state.status = Status::InputRequired;
            Self::touch(&mut state);
        }
    }

    /// Deliver `inputResponses`. Keys the task is not waiting on are IGNORED rather than refused:
    /// a client answering a key that was already satisfied, or one it invented, has not made the
    /// request malformed, and the ack is the same either way.
    ///
    /// Returns nothing — the resulting task state is observed on the next `tasks/get`, which is
    /// what makes the ack an empty `{resultType:"complete"}` rather than a task envelope.
    fn deliver(&self, responses: &serde_json::Map<String, serde_json::Value>) {
        let mut state = self.lock();
        for (key, value) in responses {
            state.answers.insert(key.clone(), value.clone());
        }
        state
            .input_requests
            .retain(|(k, _)| !responses.contains_key(k));
        Self::touch(&mut state);
        if state.input_requests.is_empty() && state.status == Status::InputRequired {
            state.status = Status::Working;
        }
        drop(state);
        self.resumed.notify_waiters();
    }

    /// Wait until every ask of the current round has been answered, or the task leaves
    /// `input_required` some other way (it was cancelled).
    async fn await_answers(&self) {
        loop {
            // The waiter is registered BEFORE the state is re-read. Reading first would leave a
            // window in which `deliver` notifies between the read and the wait, and the runner
            // would sleep on an answer that had already arrived.
            let waiter = self.resumed.notified();
            {
                let state = self.lock();
                if state.input_requests.is_empty() || state.status.is_terminal() {
                    return;
                }
            }
            waiter.await;
        }
    }

    /// The answers gathered so far, as a map to merge into the tool arguments.
    fn answers(&self) -> serde_json::Map<String, serde_json::Value> {
        self.lock().answers.clone()
    }

    fn set_working(&self) {
        let mut state = self.lock();
        if !state.status.is_terminal() {
            state.status = Status::Working;
            Self::touch(&mut state);
        }
    }

    /// The tool RAN. `result` is its own answer, `isError` and all — see the module header.
    fn complete(&self, result: serde_json::Value) {
        let mut state = self.lock();
        if state.status.is_terminal() {
            return;
        }
        state.status = Status::Completed;
        state.result = Some(result);
        state.input_requests.clear();
        state.abort = None;
        Self::touch(&mut state);
    }

    /// A PROTOCOL-level failure. `error` only, never a `result` beside it.
    fn fail(&self, code: i64, message: String) {
        let mut state = self.lock();
        if state.status.is_terminal() {
            return;
        }
        state.status = Status::Failed;
        state.error = Some(serde_json::json!({ "code": code, "message": message }));
        state.result = None;
        state.input_requests.clear();
        state.abort = None;
        Self::touch(&mut state);
    }

    /// CANCEL. Idempotent on a terminal task, which is the whole of the `tasks/cancel` contract:
    /// the ack is the same either way and the settled status is read on the next `tasks/get`.
    ///
    /// The runner is aborted rather than asked to stop, because the thing it is usually blocked on
    /// is an upstream HTTP round trip with a 30-second budget and a cooperative check would not be
    /// reached until it returned. Aborting drops the request future, which closes the connection.
    fn cancel(&self) {
        let mut state = self.lock();
        if state.status.is_terminal() {
            return;
        }
        state.status = Status::Cancelled;
        state.input_requests.clear();
        Self::touch(&mut state);
        if let Some(abort) = state.abort.take() {
            abort.abort();
        }
        drop(state);
        self.resumed.notify_waiters();
    }

    fn attach(&self, abort: tokio::task::AbortHandle) {
        let mut state = self.lock();
        // A task cancelled between creation and the runner being attached must not then start
        // running. Losing that race would make cancellation depend on scheduling.
        if state.status.is_terminal() {
            abort.abort();
        } else {
            state.abort = Some(abort);
        }
    }

    fn is_expired(&self, now: u64) -> bool {
        let state = self.lock();
        state.status.is_terminal() && now.saturating_sub(state.updated_ms) > TASK_TTL_MS
    }
}

/// THE TASK REGISTRY — the seam the whole method surface addresses tasks through.
///
/// PROCESS-GLOBAL rather than a field of `App`, and that is a decision about lifetime rather than
/// convenience: `App` is rebuilt on every config apply, so a task created before an apply would
/// vanish at the moment its `tasks/get` was most likely to arrive. A task outlives the
/// configuration that started it, so it cannot live inside a snapshot of that configuration.
pub(crate) struct Registry {
    tasks: Mutex<HashMap<String, Arc<McpTask>>>,
}

/// The one registry. See [`Registry`] for why it is not on `App`.
pub(crate) static TASKS: LazyLock<Registry> = LazyLock::new(|| Registry {
    tasks: Mutex::new(HashMap::new()),
});

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<McpTask>>> {
        self.tasks.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// CREATE a task and make it readable BEFORE returning it.
    ///
    /// The ordering is the whole of `sep-2663-durable-create-strong-consistency`: the caller must
    /// never hold a `taskId` that a `tasks/get` issued in the next breath would not resolve. The
    /// insert therefore happens here, under the lock, and the runner is attached afterwards — so
    /// even a runner that has not been scheduled yet cannot make the id unresolvable.
    pub(crate) fn create(&self, principal: &str) -> Arc<McpTask> {
        let now = crate::store::now_ms();
        let task = Arc::new(McpTask {
            id: new_task_id(),
            principal: principal.to_string(),
            state: Mutex::new(State {
                status: Status::Working,
                created_ms: now,
                updated_ms: now,
                result: None,
                error: None,
                input_requests: Vec::new(),
                answers: serde_json::Map::new(),
                abort: None,
            }),
            resumed: tokio::sync::Notify::new(),
        });
        let mut tasks = self.lock();
        Self::sweep(&mut tasks, now);
        tasks.insert(task.id.clone(), Arc::clone(&task));
        task
    }

    /// Resolve a task id FOR THIS CALLER. A task belonging to another principal is `None`, exactly
    /// as an id that never existed is — see [`McpTask::principal`].
    pub(crate) fn get(&self, id: &str, principal: &str) -> Option<Arc<McpTask>> {
        self.lock()
            .get(id)
            .filter(|t| t.principal == principal)
            .map(Arc::clone)
    }

    /// Drop expired terminal rows, and — only if that was not enough — the oldest terminal rows.
    /// Never a working one: see [`MAX_RETAINED_TASKS`].
    fn sweep(tasks: &mut HashMap<String, Arc<McpTask>>, now: u64) {
        tasks.retain(|_, t| !t.is_expired(now));
        if tasks.len() < MAX_RETAINED_TASKS {
            return;
        }
        let mut terminal: Vec<(u64, String)> = tasks
            .iter()
            .filter_map(|(id, t)| {
                let state = t.lock();
                state
                    .status
                    .is_terminal()
                    .then(|| (state.updated_ms, id.clone()))
            })
            .collect();
        terminal.sort_unstable();
        for (_, id) in terminal
            .into_iter()
            .take(tasks.len().saturating_sub(MAX_RETAINED_TASKS) + 1)
        {
            tasks.remove(&id);
        }
    }

    /// Deliver `inputResponses` to a task this caller owns.
    pub(crate) fn update(
        &self,
        id: &str,
        principal: &str,
        responses: &serde_json::Map<String, serde_json::Value>,
    ) -> Option<()> {
        let task = self.get(id, principal)?;
        task.deliver(responses);
        Some(())
    }

    /// Cancel a task this caller owns. Idempotent — see [`McpTask::cancel`].
    pub(crate) fn cancel(&self, id: &str, principal: &str) -> Option<()> {
        let task = self.get(id, principal)?;
        task.cancel();
        Some(())
    }
}

/// Everything the background runner needs, gathered once. Owned rather than borrowed: the runner
/// outlives the request that started it, so it cannot hold a reference into that request's frame.
pub(crate) struct Runner {
    pub(crate) pool: Arc<super::client::pool::McpConnectionPool>,
    pub(crate) handle: Arc<crate::state::AppHandle>,
    /// The plane breaker cells `upstream::call` records this task's legs into — the same handle
    /// `create_task` consulted for admission, carried so the runner cannot record into a different
    /// generation's cells than it was admitted against.
    pub(crate) breakers: Arc<crate::store::PlaneBreakers>,
    /// The single-flight probe hold admission handed `create_task`. Releases owner-checked ON DROP
    /// — which covers the runner being ABORTED by `tasks/cancel` as well as its normal end, the
    /// case an explicit release call cannot reach. A recorded outcome makes the drop a no-op.
    /// Never read: the field EXISTS to be dropped with the runner, which is what the allow says.
    #[allow(dead_code)]
    pub(crate) admission: crate::store::PlaneAdmission,
    /// The breaker cell the admitted member records into — `("tool:<pool>", lane)` for a pooled
    /// member, the degenerate `("tool:<server>", 0)` otherwise. Carried from `create_task`'s walk
    /// so the runner's legs record against exactly the cell the admission consulted.
    pub(crate) cell: super::upstream::BreakerCell,
    /// THE CALLER'S PRINCIPAL IS FROZEN IN HERE, AND THAT IS BOUNDED RATHER THAN CLOSED. SAY SO.
    ///
    /// `Authorised::caller` is a `VirtualKey` resolved at ingress. `upstream::call` re-plans the
    /// outbound credential from it on every round — so a NARROWED grant is re-read per round — but
    /// it is re-read from THIS COPY, so the key being deleted, disabled or re-scoped underneath a
    /// running task is not seen at all. The sibling surface with the same shape,
    /// `subscriptions/listen`, does not have this hole: it holds a
    /// [`crate::trust::validate::Standing`] and re-resolves the principal from the live registry on
    /// every poll.
    ///
    /// WHY THIS ONE IS BOUNDED INSTEAD, stated rather than left to be discovered: the task path's
    /// budget is charged ONCE at creation (see the runner's own note below), so re-resolving the
    /// principal here would re-derive a grant against a charge that has already been settled and
    /// against a caller that has already been answered. Making that coherent is a change to when a
    /// task path charges, not a change to how it resolves a key, and it belongs with that decision.
    ///
    /// WHAT MAKES IT SURVIVABLE, and it is a real property rather than an accident: [`TASK_TTL_MS`]
    /// is 300 000. Nothing on this path can outlive a revocation by more than five minutes, and that
    /// bound is enforced by the registry's own sweep rather than by anything a runner remembers.
    /// The bound is what this field is trading on, so removing or raising `TASK_TTL_MS` is a
    /// decision about THIS field as much as about retention.
    pub(crate) authorised: super::upstream::Authorised,
    pub(crate) arguments: serde_json::Value,
    pub(crate) server_id: String,
    pub(crate) max_rounds: u32,
    /// The rounds of input busbar asks its caller for from inside the task, already filtered to
    /// what this caller declared it can answer.
    pub(crate) task_asks: Vec<Vec<CallerAsk>>,
}

/// SPAWN the runner for a freshly created task and attach its abort handle.
///
/// Attaching AFTER spawning is safe because [`McpTask::attach`] re-checks the status under the lock: a
/// `tasks/cancel` that lands in between finds no handle, sets the terminal status, and `attach`
/// then aborts the runner it was handed. Neither ordering leaks a runner.
pub(crate) fn spawn(task: Arc<McpTask>, runner: Runner) {
    let handle = tokio::spawn({
        let task = Arc::clone(&task);
        async move { run(task, runner).await }
    });
    task.attach(handle.abort_handle());
}

/// THE RUNNER. Ask, then dispatch, then settle — and every exit writes a terminal status, because
/// a task that stops without one is a caller polling for ever.
async fn run(task: Arc<McpTask>, runner: Runner) {
    // (1) THE IN-TASK ASK ROUNDS. Ordered, and each one waits for every key it asked.
    for round in &runner.task_asks {
        task.park(round.clone());
        task.await_answers().await;
        if task.lock().status.is_terminal() {
            return;
        }
    }
    task.set_working();

    // (2) THE ANSWERS BECOME ARGUMENTS. An `ask_caller`/`task_ask_caller` entry keyed `user_name`
    // supplies the tool argument `user_name` — which is what an operator writing a confirmation
    // gate means by it, and what makes the gathered answer observable in the task's own result
    // rather than discarded at busbar.
    let arguments = merge_answers(&runner.arguments, &task.answers());

    // (3) THE UPSTREAM LEG, through the SAME bounded, per-round-gated loop the synchronous path
    // uses. Not a second dispatcher: an upstream's own `input_required` must terminate at busbar on
    // this path exactly as it does on that one, and the only way to be sure of that is to run the
    // same loop.
    let server_id = runner.server_id.clone();
    let handle = Arc::clone(&runner.handle);
    let outcome = super::inputreq::drive(
        &runner.server_id,
        runner.max_rounds,
        |round, satisfaction| {
            let leg = super::upstream::call(
                &runner.pool,
                &runner.breakers,
                &runner.cell,
                &runner.authorised,
                &arguments,
                u64::from(round),
                satisfaction,
            );
            // A task never reroutes mid-flight (the member was fixed at creation), so the leg's
            // stage is not consulted here: only the message survives into the loop's refusal.
            async move { leg.await.map_err(|f| f.message) }
        },
        {
            let handle = Arc::clone(&handle);
            let server_id = server_id.clone();
            move || {
                handle
                    .load()
                    .mcp_catalogue
                    .server(&server_id)
                    .map(|s| s.grants)
                    .unwrap_or_default()
            }
        },
        // The SAME satisfier as the synchronous path, for the same reason both run one loop: an
        // upstream's roots or sampling ask from inside a task is the identical decision, judged
        // from the identical live snapshot. The governance context is rebuilt from the principal
        // this task was AUTHORISED as — the runner is detached from the inbound request, and the
        // caller bound at creation is the only principal a completion made on its behalf may be
        // admitted and charged under (bounded by `TASK_TTL_MS`, like everything else the runner
        // carries). See `super::roots::satisfy_upstream_ask` / `super::sampling`.
        |ask| {
            let live = handle.load();
            let entry = live.mcp_catalogue.server(&server_id);
            let roots = entry.map(|s| s.roots.clone()).unwrap_or_default();
            let sampling = entry.and_then(|s| s.sampling.clone());
            let gov = crate::governance::GovCtx {
                key: Some(Arc::new(runner.authorised.caller.clone())),
            };
            let server = server_id.clone();
            async move {
                if ask.kind == "sampling" {
                    super::sampling::satisfy_upstream_ask(
                        &live,
                        &gov,
                        &ask,
                        &server,
                        sampling.as_ref(),
                    )
                    .await
                } else {
                    super::roots::satisfy_upstream_ask(&ask, &server, &roots)
                }
            }
        },
        // NOT CHARGED PER ROUND, and this is the one place the task path deliberately differs from
        // the synchronous one. The caller's budget was charged ONCE, synchronously, at task
        // creation — before the `CreateTaskResult` was returned — because that is the moment the
        // caller can still be told it has been refused. Charging again from a detached runner would
        // bill a request that has already been answered, against a budget window the caller cannot
        // see, with no way to report the refusal except by failing the task.
        |_| Ok(()),
    )
    .await;
    // `runner.admission` (the probe hold) drops with the runner — on this function's normal end
    // AND on an abort — releasing owner-checked; a recorded leg outcome makes that a no-op.

    // (4) SETTLE. A tool that ran is `completed` whatever it said about itself; a refusal is a
    // PROTOCOL error and is `failed`.
    //
    // AN UPSTREAM FAILURE SETTLES `failed` TOO, AND THAT IS NOT THE SAME DECISION THE SYNCHRONOUS
    // PATH MAKES. `mcp::method` renders an upstream failure as a tool execution error — an
    // `isError` RESULT — because a synchronous caller has no other channel on which to be told the
    // tool did not work, and a JSON-RPC error hides the message from the model. A task HAS that
    // other channel: `status: "failed"` with an inlined `error` is the extension's own way of
    // saying "this work did not produce a result", and it is what SEP-2663 requires of the
    // `protocol_error_job` fixture. So the two paths agree about the FACT and differ about the
    // SHAPE, because the shapes are what the two surfaces provide.
    match outcome {
        Ok_(value) => task.complete(super::sanitize::normalise_json(&value)),
        Err_(refusal) => task.fail(TASK_PROTOCOL_ERROR_CODE, refusal.to_string()),
        // The message keeps its exact former wording, because the split is about ATTRIBUTION and a
        // task's inlined error text is already on the wire for a scenario that reads it.
        Upstream_(reason) => task.fail(
            TASK_PROTOCOL_ERROR_CODE,
            format!("the MCP upstream call failed: {reason}"),
        ),
    }
}

/// The JSON-RPC code a `failed` task inlines. `-32603` (internal error) rather than `-32000`: what
/// is being reported is that busbar could not carry the dispatch to an answer, which is the
/// server's own failure, and the caller has no parameter to correct.
const TASK_PROTOCOL_ERROR_CODE: i64 = -32603;

// Three aliases so the `match` above reads as the three outcomes rather than as the enum's spelling.
use super::inputreq::Outcome::Completed as Ok_;
use super::inputreq::Outcome::Refused as Err_;
use super::inputreq::Outcome::UpstreamFailed as Upstream_;

/// Merge the caller's gathered ask answers into the tool arguments, under the operator's own keys.
///
/// A CLONE rather than a mutation of the request's arguments, because the arguments were already
/// digested into the request-state seal before this ran: mutating them would make a retry's digest
/// disagree with the one the seal was minted over.
fn merge_answers(
    arguments: &serde_json::Value,
    answers: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    if answers.is_empty() {
        return arguments.clone();
    }
    let mut merged = arguments
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    for (key, value) in answers {
        merged.insert(key.clone(), value.clone());
    }
    serde_json::Value::Object(merged)
}

/// The task-scoped ask rounds for a tool, filtered to what this caller declared it can answer.
///
/// A round left EMPTY by the filter is dropped rather than parked on: parking on nothing would hang
/// the task for ever waiting for an answer nobody was asked for.
pub(crate) fn task_ask_rounds(
    entry: &ToolEntry,
    capabilities: &serde_json::Value,
) -> Vec<Vec<CallerAsk>> {
    entry
        .task_ask_caller
        .iter()
        .map(|round: &AskRoundCfg| super::callerask::asks_for_round(round, capabilities))
        .filter(|round| !round.is_empty())
        .collect()
}

/// A task id. UNPREDICTABLE rather than sequential: a sequential id is a running count of how much
/// work this deployment has done, and it would let any caller holding one of its own guess its
/// neighbours'.
///
/// The CSPRNG carries the unpredictability, and a process-lifetime counter carries the UNIQUENESS
/// independently of it. That is not belt-and-braces: `getrandom` failing is near-impossible but its
/// failure mode is a zeroed buffer, and a zeroed buffer would mint the same id twice — one caller
/// reading another's result. With the counter mixed in, a CSPRNG failure costs predictability and
/// nothing else.
fn new_task_id() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut out = String::with_capacity(2 + bytes.len() * 2 + 17);
    out.push_str("t_");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out.push('_');
    out.push_str(&format!("{seq:x}"));
    out
}

/// Unix milliseconds as an ISO-8601 UTC instant, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Written out rather than pulled from a date crate because this is the only place in the engine
/// that needs a civil date, and Howard Hinnant's `civil_from_days` is twelve lines that are exactly
/// correct for every proleptic-Gregorian day — including the leap-year and century rules a
/// hand-rolled approximation gets wrong once every four years and once every hundred.
fn iso8601_ms(ms: u64) -> String {
    // Signed ARITHMETIC over an unsigned clock, cast at this one boundary. `div_euclid` is what
    // makes the day/second split correct without a special case, and it needs a signed remainder;
    // the clock itself is unsigned because a duration since the epoch cannot be negative. The cast
    // is lossless for every instant this process can observe — `i64` milliseconds reach the year
    // 292278994.
    let ms = ms as i64;
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Days since the Unix epoch → (year, month, day). Hinnant's algorithm, shifted to an era beginning
/// on 0000-03-01 so the leap day lands at the end of the era's year and needs no special case.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[path = "tests/tasks_tests.rs"]
mod tasks_tests;
