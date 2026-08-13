// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE TASK STORE: the registry of in-flight tasks, its write-through to the configured
//! governance store, and the rehydrate that makes a restart a pause rather than a loss.
//!
//! ## The property this file exists to hold
//!
//! A2A is asynchronous by design. A task can be interrupted waiting on a human and resume hours
//! later. If the task table lives only in RAM, a deploy silently destroys every in-flight task and
//! every interrupt, and `suspend`/resume is a word rather than a behaviour. So: every state change
//! is written through to the store as it happens, and boot reads them back.
//!
//! ## The shape is the audit log's, deliberately
//!
//! [`crate::admin::audit::AuditLog`] already solved this exact problem for admin mutations: an
//! in-memory working set, an optional durable SINK attached at boot, write-through on every append,
//! and a `restore_from_store` that reconstitutes the state and VERIFIES the hash chain before
//! trusting it. Inventing a second shape for the same problem would mean two restore paths with two
//! sets of edge cases. This is that shape, with a per-task chain instead of one global one.
//!
//! ## The RAM default really is ephemeral, and that is a product contract, not an oversight
//!
//! `store: memory` implements none of the task methods, so their `Store` defaults apply and nothing
//! persists. That is documented behaviour for every other stateful thing busbar keeps, and the
//! engine must never paper over it: durability is a property of the CONFIGURED BACKEND, and the only
//! honest way to know whether a deployment has it is to READ A TASK BACK. `restore_from_store`
//! returning zero on the RAM default is the truth being reported, not a bug.
//!
//! ## Reads are scoped, and a foreign id is indistinguishable from a missing one
//!
//! A caller may enumerate and inspect ONLY its own tasks. [`TaskRegistry::get_scoped`] returns the
//! same `Denied` for "no such task" and "that task is not yours", because a distinguishable
//! not-found is an enumeration oracle: a caller that can tell the two apart can probe the id space
//! and learn which task ids exist in other tenants.

// PARTLY UNMOUNTED. `set_sink`, `restore_from_store`, `submit`, `record_dispatch`, `transition`,
// `advance_cursor` and `set_push_callback` are all driven — boot rehydrates, the ingress opens a
// task per call, the relay moves its state, and a state change is now also what DELIVERS the
// caller's push notification. The scoped reads and `compact` await the task-read surface.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::audit::ChainBreak;

use super::provenance::{self, EventInput, TaskChain};
use super::task::{Task, TaskError, TaskState};
use busbar_api::{Store, StoreError, StoreResult};

/// One task plus its provenance chain position. The events themselves are NOT held in RAM — the
/// store owns them, and holding every event of every long-running task would defeat the point of
/// having a durable store at all.
#[derive(Debug, Clone)]
struct Entry {
    task: Task,
    chain: TaskChain,
}

/// Why a scoped read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denied {
    /// The task does not exist, OR it exists and belongs to somebody else. ONE variant, on purpose:
    /// see the module doc. The caller renders 403 either way, before any task data is assembled.
    NotYours,
}

/// What a boot rehydrate actually found. Every number is reported rather than summed into one
/// "restored" count, because they mean different things to an operator and a single number hides the
/// two that are bad news.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Rehydrated {
    /// Active or interrupted tasks brought back and resumable.
    pub(crate) active: usize,
    /// Terminal tasks seen and deliberately not loaded into the working set. They stay in the store
    /// for the provenance window; they are not in-flight and nothing resumes them.
    pub(crate) terminal: usize,
    /// Rows that would not parse (an unknown state or direction, a missing identity). NOT silently
    /// dropped: a skipped row is an in-flight task that ceased to exist across a deploy, which is
    /// the exact failure this store exists to prevent, so it is counted and logged.
    pub(crate) unreadable: usize,
    /// Tasks whose persisted provenance chain FAILED to verify. Tamper evidence. The task is still
    /// restored — refusing to restore it would let anyone who can write to the store delete a task
    /// by corrupting one of its events — but the break is reported and the chain continues from the
    /// broken tail rather than being silently re-based onto it.
    pub(crate) chain_breaks: Vec<ChainBreak>,
}

/// The in-flight task registry. No `Debug`: `dyn Store` is not `Debug` (a store backend must not be
/// obliged to render itself, and one that did would be a place a credential could surface in a log).
#[derive(Default)]
pub(crate) struct TaskRegistry {
    tasks: Mutex<HashMap<String, Entry>>,
    sink: Mutex<Option<Arc<dyn Store>>>,
}

/// THE PROCESS-WIDE REGISTRY. Process state, not config-derived state, so it lives as a global
/// rather than on the swappable `App` snapshot — exactly like [`crate::admin::audit::AUDIT`], and for
/// the same reason: a config apply must not destroy in-flight tasks. An operator editing a pool
/// weight and applying it would otherwise take every running task with it, which is a far larger
/// blast radius than the change they made.
pub(crate) static TASKS: std::sync::LazyLock<TaskRegistry> =
    std::sync::LazyLock::new(TaskRegistry::new);

/// What went wrong servicing a task mutation.
#[derive(Debug)]
pub(crate) enum TaskStoreError {
    /// The task id is not in the working set.
    NoSuchTask(String),
    /// The canonical type refused the move (see [`TaskError`]).
    Task(TaskError),
    /// The durable write failed. Surfaced rather than swallowed: a transition that is not durable is
    /// a transition that a restart will lose, and the caller has to be able to decide.
    Store(StoreError),
}

impl std::fmt::Display for TaskStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStoreError::NoSuchTask(id) => write!(f, "no such task `{id}`"),
            TaskStoreError::Task(e) => write!(f, "{e}"),
            TaskStoreError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl From<TaskError> for TaskStoreError {
    fn from(e: TaskError) -> Self {
        TaskStoreError::Task(e)
    }
}

impl TaskRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Poison-recovering lock. The data behind it is always still consistent after a panic (the
    /// critical sections only mutate a map), and cascading a poison would make every subsequent task
    /// operation panic too — a task plane that wedges permanently because one request panicked.
    fn tasks(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.tasks.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sink(&self) -> Option<Arc<dyn Store>> {
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
    }

    /// Attach the configured governance store as the DURABLE SINK. Called once at boot. With no
    /// sink attached (or with a backend that implements none of the task methods) the registry is a
    /// RAM cache and nothing survives a restart, which is the documented `store: memory` behaviour.
    pub(crate) fn set_sink(&self, store: Arc<dyn Store>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// BOOT REHYDRATE. Reads every persisted task, loads the ACTIVE ones into the working set, and
    /// resumes each one's provenance chain from its persisted events.
    ///
    /// Terminal tasks are counted and left in the store: they are not in flight, and loading them
    /// would grow the working set without bound over a deployment's life for no resume value.
    pub(crate) fn restore_from_store(&self, store: &dyn Store) -> StoreResult<Rehydrated> {
        let rows = store.list_tasks()?;
        let mut out = Rehydrated::default();
        let mut tasks = self.tasks();
        for row in &rows {
            let task = match Task::from_row(row) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(
                        task_id = %row.task_id,
                        error = %e,
                        "a persisted A2A task row could not be read back; it is NOT resumable and \
                         is being reported rather than skipped silently"
                    );
                    out.unreadable += 1;
                    continue;
                }
            };
            if task.state.is_terminal() {
                out.terminal += 1;
                continue;
            }
            // The chain is resumed from what is persisted, and VERIFIED first. A break is reported
            // and the chain continues from the broken tail: refusing to continue would mean anybody
            // who can corrupt one event can silently stop all further provenance for that task.
            let events = store.list_task_events(&task.task_id)?;
            let chain = match TaskChain::from_persisted(&events) {
                Ok(c) => c,
                Err(brk) => {
                    tracing::error!(
                        task_id = %task.task_id,
                        break_detail = %brk,
                        "A2A per-task provenance CHAIN VERIFICATION FAILED on restore — the \
                         persisted events do not verify against their own hash chain"
                    );
                    out.chain_breaks.push(brk);
                    TaskChain::from_persisted_unverified(&events)
                }
            };
            tasks.insert(task.task_id.clone(), Entry { task, chain });
            out.active += 1;
        }
        Ok(out)
    }

    /// SUBMIT a new task: record it, write it through, and open its provenance chain.
    ///
    /// The durable write happens BEFORE the task is announced as accepted. A task acknowledged to a
    /// caller but not yet persisted is precisely the task a crash loses while the caller believes it
    /// is running.
    pub(crate) fn submit(&self, task: &Task, request_id: &str) -> Result<Task, TaskStoreError> {
        let mut chain = TaskChain::new();
        let ev = chain.append(
            &task.task_id,
            EventInput {
                kind: provenance::EV_SUBMITTED,
                context_id: task.context_id.clone(),
                principal: task.principal.clone(),
                agent_id: task.agent_id.clone(),
                state: task.state.as_str().to_string(),
                request_id: request_id.to_string(),
                ts: task.created_at,
            },
        );
        if let Some(store) = self.sink() {
            store
                .put_task(&task.to_row())
                .map_err(TaskStoreError::Store)?;
            store
                .append_task_event(&ev)
                .map_err(TaskStoreError::Store)?;
        }
        self.tasks().insert(
            task.task_id.clone(),
            Entry {
                task: task.clone(),
                chain,
            },
        );
        Ok(task.clone())
    }

    /// TRANSITION a task, emitting the matching chained provenance event and writing both through.
    ///
    /// The in-memory entry is updated only after the durable write succeeds, so a failed write
    /// leaves the working set agreeing with the store rather than ahead of it. Being ahead is the
    /// worse of the two: it makes the process believe a transition happened that a restart will
    /// then un-happen.
    pub(crate) fn transition(
        &self,
        task_id: &str,
        to: TaskState,
        now: u64,
        request_id: &str,
    ) -> Result<Task, TaskStoreError> {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;

        let mut candidate = entry.task.clone();
        candidate.transition_to(to, now)?;

        let kind = match to {
            TaskState::Working if entry.task.state.is_interrupted() => provenance::EV_RESUMED,
            TaskState::Working => provenance::EV_WORKING,
            s if s.is_interrupted() => provenance::EV_INTERRUPTED,
            s if s.is_terminal() => provenance::EV_TERMINAL,
            _ => provenance::EV_WORKING,
        };
        let mut chain = entry.chain.clone();
        let ev = chain.append(
            task_id,
            EventInput {
                kind,
                context_id: candidate.context_id.clone(),
                principal: candidate.principal.clone(),
                agent_id: candidate.agent_id.clone(),
                state: candidate.state.as_str().to_string(),
                request_id: request_id.to_string(),
                ts: now,
            },
        );
        if let Some(store) = self.sink() {
            store
                .put_task(&candidate.to_row())
                .map_err(TaskStoreError::Store)?;
            store
                .append_task_event(&ev)
                .map_err(TaskStoreError::Store)?;
        }
        entry.task = candidate.clone();
        entry.chain = chain;
        Ok(candidate)
    }

    /// DISPATCH: record which agent this task was routed to, and chain a `task.delegated` event.
    /// Separate from [`TaskRegistry::transition`] because choosing a target is not a state change —
    /// the task is `working` before and after — but it IS the single most important fact the
    /// delegating side's provenance has to carry: who delegated, to which registered agent.
    pub(crate) fn record_dispatch(
        &self,
        task_id: &str,
        agent_id: &str,
        now: u64,
        request_id: &str,
    ) -> Result<Task, TaskStoreError> {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        let mut candidate = entry.task.clone();
        candidate.agent_id = agent_id.to_string();
        candidate.updated_at = now;
        let mut chain = entry.chain.clone();
        let ev = chain.append(
            task_id,
            EventInput {
                kind: provenance::EV_DELEGATED,
                context_id: candidate.context_id.clone(),
                principal: candidate.principal.clone(),
                agent_id: candidate.agent_id.clone(),
                state: candidate.state.as_str().to_string(),
                request_id: request_id.to_string(),
                ts: now,
            },
        );
        if let Some(store) = self.sink() {
            store
                .put_task(&candidate.to_row())
                .map_err(TaskStoreError::Store)?;
            store
                .append_task_event(&ev)
                .map_err(TaskStoreError::Store)?;
        }
        entry.task = candidate.clone();
        entry.chain = chain;
        Ok(candidate)
    }

    /// ADVANCE THE ARTIFACT CURSOR — how many artifact chunks have been durably relayed.
    ///
    /// MONOTONIC, and a request to move it backwards is refused rather than applied. The cursor is
    /// the resubscribe resume point; rewinding it re-delivers artifact chunks the caller already
    /// has, and on a chunked assembly that is corruption rather than duplication.
    pub(crate) fn advance_cursor(
        &self,
        task_id: &str,
        cursor: u64,
        now: u64,
        request_id: &str,
    ) -> Result<Task, TaskStoreError> {
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        if cursor <= entry.task.artifact_cursor {
            return Ok(entry.task.clone());
        }
        let mut candidate = entry.task.clone();
        candidate.artifact_cursor = cursor;
        candidate.updated_at = now;
        let mut chain = entry.chain.clone();
        let ev = chain.append(
            task_id,
            EventInput {
                kind: provenance::EV_ARTIFACT,
                context_id: candidate.context_id.clone(),
                principal: candidate.principal.clone(),
                agent_id: candidate.agent_id.clone(),
                state: candidate.state.as_str().to_string(),
                request_id: request_id.to_string(),
                ts: now,
            },
        );
        if let Some(store) = self.sink() {
            store
                .put_task(&candidate.to_row())
                .map_err(TaskStoreError::Store)?;
            store
                .append_task_event(&ev)
                .map_err(TaskStoreError::Store)?;
        }
        entry.task = candidate.clone();
        entry.chain = chain;
        Ok(candidate)
    }

    /// Register (or clear) this task's push-notification callback.
    ///
    /// THE FULL SSRF DECISION IS STILL MADE ELSEWHERE — twice, and both are load-bearing:
    /// `ingress::rpc` runs [`super::pushnotify::validate`] against a live resolution before the
    /// caller's registration is accepted at all, and [`super::pushdeliver`] runs it AGAIN against a
    /// fresh resolution before every single delivery, because a durable row outlives the DNS answer
    /// that was checked when it was written.
    ///
    /// What this method adds is the part neither of those can provide: a floor. It used to take a
    /// bare `Option<String>` and persist whatever it was handed, with a doc comment asserting the
    /// caller had validated. That made the tree safe by COINCIDENCE OF CALL ORDER — true of the one
    /// caller that existed, and silently untrue for the next one, or for a row somebody wrote into
    /// the governance store directly. So the resolver-free half of the guard runs here too, and a
    /// URL it refuses is DROPPED rather than stored.
    ///
    /// Dropped rather than returned as an error, deliberately. This is a floor under a check that
    /// has already happened at the surface where the caller is present to be told; by the time a
    /// refusable URL reaches this method something upstream has already failed to do its job, and
    /// the useful response is to make the callback not exist and say so loudly in the log, not to
    /// fail a task the caller is owed. The registration path still answers `400` at the ingress.
    pub(crate) fn set_push_callback(
        &self,
        task_id: &str,
        callback: Option<String>,
        now: u64,
    ) -> Result<Task, TaskStoreError> {
        let callback = match callback {
            Some(url) => match super::pushnotify::structural_refusal(&url) {
                Some(refusal) => {
                    tracing::error!(
                        task = %task_id,
                        error = %refusal,
                        "a2a: a push callback the SSRF guard refuses reached the task store and was \
                         DROPPED; the caller that stored it did not validate first"
                    );
                    None
                }
                None => Some(url),
            },
            None => None,
        };
        let mut tasks = self.tasks();
        let entry = tasks
            .get_mut(task_id)
            .ok_or_else(|| TaskStoreError::NoSuchTask(task_id.to_string()))?;
        let mut candidate = entry.task.clone();
        candidate.push_callback = callback;
        candidate.updated_at = now;
        if let Some(store) = self.sink() {
            store
                .put_task(&candidate.to_row())
                .map_err(TaskStoreError::Store)?;
        }
        entry.task = candidate.clone();
        Ok(candidate)
    }

    /// SCOPED READ. The authorization gate for `GetTask`: a caller sees its own tasks and nothing
    /// else, and cannot tell a foreign id from a nonexistent one.
    pub(crate) fn get_scoped(&self, principal: &str, task_id: &str) -> Result<Task, Denied> {
        // An EMPTY principal never matches, even against a row that somehow carried one. `Task`
        // refuses to construct with an empty principal, so this is belt-and-braces against a future
        // caller that reaches here with an unauthenticated identity: an empty-equals-empty match
        // would turn "not authenticated" into "owns every unattributed task".
        if principal.is_empty() {
            return Err(Denied::NotYours);
        }
        match self.tasks().get(task_id) {
            Some(e) if e.task.principal == principal => Ok(e.task.clone()),
            _ => Err(Denied::NotYours),
        }
    }

    /// SCOPED LIST. The authorization gate for `ListTasks`, sorted by task id so the result is
    /// deterministic (a listing whose order varies makes a diff between two calls unreadable).
    pub(crate) fn list_scoped(&self, principal: &str) -> Vec<Task> {
        if principal.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<Task> = self
            .tasks()
            .values()
            .filter(|e| e.task.principal == principal)
            .map(|e| e.task.clone())
            .collect();
        out.sort_by(|a, b| a.task_id.cmp(&b.task_id));
        out
    }

    /// UNSCOPED read — for the retention sweep and the operator surface, never for a caller.
    /// Named so that a call site using it for a caller read is visible in review.
    pub(crate) fn get_unscoped(&self, task_id: &str) -> Option<Task> {
        self.tasks().get(task_id).map(|e| e.task.clone())
    }

    /// How many tasks are in the working set. Active + interrupted only — terminal tasks are not
    /// loaded (see [`TaskRegistry::restore_from_store`]).
    pub(crate) fn len(&self) -> usize {
        self.tasks().len()
    }

    /// Drop a task from the WORKING SET once it is terminal, leaving its durable rows and its
    /// provenance chain in the store for the retention window.
    ///
    /// Refusing to evict an ACTIVE task is the guard that matters: evicting one loses its chain
    /// position, and the next event for it would open a SECOND chain at seq 1 under the same task
    /// id — two chains that each verify and together describe nothing.
    pub(crate) fn evict_terminal(&self, task_id: &str) -> bool {
        let mut tasks = self.tasks();
        match tasks.get(task_id) {
            Some(e) if e.task.state.is_terminal() => {
                tasks.remove(task_id);
                true
            }
            _ => false,
        }
    }

    /// RETENTION: ask the store to drop terminal task rows older than `before`, and drop any
    /// matching working-set entries. Returns how many durable rows went.
    ///
    /// The policy lives at the call site, not here: retention is a setting on the store, not a
    /// subsystem of its own, so this file owns the mechanism and nothing about the window.
    pub(crate) fn compact(&self, before: u64) -> StoreResult<u64> {
        let removed = match self.sink() {
            Some(store) => store.purge_tasks_before(before)?,
            None => 0,
        };
        let mut tasks = self.tasks();
        tasks.retain(|_, e| !(e.task.state.is_terminal() && e.task.updated_at < before));
        Ok(removed)
    }

    /// VERIFY one task's persisted provenance chain, end to end, against the store.
    ///
    /// This is the operator-facing half of the hash chain, and its existence is the difference
    /// between provenance and decoration: a chain nothing ever recomputes proves nothing, because
    /// nobody ever finds out that it does not.
    pub(crate) fn verify_task_chain(
        &self,
        store: &dyn Store,
        task_id: &str,
    ) -> StoreResult<Result<usize, ChainBreak>> {
        let events = store.list_task_events(task_id)?;
        match crate::audit::verify_chain(&events) {
            Ok(()) => Ok(Ok(events.len())),
            Err(brk) => Ok(Err(brk)),
        }
    }
}

#[cfg(test)]
#[path = "tests/taskstore_tests.rs"]
mod taskstore_tests;
