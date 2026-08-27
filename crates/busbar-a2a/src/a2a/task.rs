// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CANONICAL TASK: busbar's own struct for the unit of work A2A calls a Task, and the state
//! machine that says which moves are legal.
//!
//! ## Why the type is ours
//!
//! Same ruling the rest of this plane obeys: protocol in, canonical type, protocol out. A2A is
//! versioned and moving, and a task row is the LONGEST-LIVED thing this plane writes — it outlives
//! the process, and after a durable store is configured it outlives the release. A generated wire
//! type in that row would mean a specification revision rewriting rows an operator has on disk.
//!
//! ## The state machine is not decoration, it is the thing that makes a resume safe
//!
//! A task moves `submitted` → `working`, may be INTERRUPTED to `input-required` or `auth-required`,
//! and ends in exactly one of `completed`, `failed`, `canceled`, `rejected`. Two properties are
//! enforced here rather than left to each call site:
//!
//! - **Terminal is terminal.** Nothing leaves a terminal state. A late artifact arriving after a
//!   `completed`, or a cancel racing a completion, must be REFUSED rather than silently resurrect a
//!   finished task — a resurrected task re-bills a caller and re-emits provenance for work that was
//!   already accounted for.
//! - **An interrupt is a pause, not an ending.** `input-required` and `auth-required` are the states
//!   a task legitimately sits in for hours waiting on a human, which is precisely why the row has to
//!   be durable and why the retention sweep must not treat "old" as "collectable".
//!
//! The transition table is a FUNCTION rather than a set of `if`s scattered across the relay, because
//! the interesting failure is the transition nobody wrote a branch for.

// PARTLY UNMOUNTED. `Task::submitted` and the store projection are driven by every inbound call.
// The transition verbs beyond the opening one belong to the relay that watches a task to
// completion, which this branch does not mount; the table they enforce is settled first on
// purpose, because a state machine that changes after tasks exist invalidates the rows.
#![cfg_attr(not(test), allow(dead_code))]

use serde::{Deserialize, Serialize};

/// Which side of the hop this task is. Persisted, because the two directions RESUME differently
/// after a restart: an inbound task re-establishes the relay to the caller that submitted it, an
/// outbound one re-subscribes to the remote agent it was delegated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Direction {
    /// busbar is the server: an external caller delegated work to a busbar-fronted agent.
    Inbound,
    /// busbar is the client: a fronted agent delegated work to a registered remote agent.
    Outbound,
}

impl Direction {
    /// The stable wire/store token. Config, admin responses, audit rows and store rows all spell it
    /// this way, so an operator comparing two of them is comparing the same string.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }

    /// Parse a stored token. An UNKNOWN token is an error rather than a default, because defaulting
    /// picks a direction for a row that will then be resumed the wrong way — re-subscribing to a
    /// remote agent for a task that never had one, or relaying to a caller that never asked.
    pub(crate) fn parse(s: &str) -> Result<Self, TaskError> {
        match s {
            "inbound" => Ok(Direction::Inbound),
            "outbound" => Ok(Direction::Outbound),
            other => Err(TaskError::UnknownDirection(other.to_string())),
        }
    }
}

/// The A2A task lifecycle states busbar runs, spelled exactly as the protocol spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TaskState {
    /// Accepted, not yet started.
    Submitted,
    /// Running.
    Working,
    /// PAUSED awaiting caller input. Not an ending.
    InputRequired,
    /// PAUSED awaiting caller authentication/authorization. Not an ending.
    AuthRequired,
    /// Terminal: finished successfully.
    Completed,
    /// Terminal: finished unsuccessfully.
    Failed,
    /// Terminal: stopped on request.
    Canceled,
    /// Terminal: refused before doing the work.
    Rejected,
}

impl TaskState {
    /// The stable wire/store token.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            TaskState::Submitted => "submitted",
            TaskState::Working => "working",
            TaskState::InputRequired => "input-required",
            TaskState::AuthRequired => "auth-required",
            TaskState::Completed => "completed",
            TaskState::Failed => "failed",
            TaskState::Canceled => "canceled",
            TaskState::Rejected => "rejected",
        }
    }

    /// Parse a stored token, refusing an unknown one.
    ///
    /// FAILING CLOSED HERE IS THE POINT. A row written by a NEWER engine carrying a state this
    /// binary does not know is a row this binary cannot reason about: it cannot tell whether it is
    /// terminal (safe to compact) or interrupted (must be preserved and resumed). Defaulting such a
    /// row to anything is guessing, and the cheap guess — "unknown means terminal" — is the one that
    /// deletes a live task on a downgrade.
    pub(crate) fn parse(s: &str) -> Result<Self, TaskError> {
        match s {
            "submitted" => Ok(TaskState::Submitted),
            "working" => Ok(TaskState::Working),
            "input-required" => Ok(TaskState::InputRequired),
            "auth-required" => Ok(TaskState::AuthRequired),
            "completed" => Ok(TaskState::Completed),
            "failed" => Ok(TaskState::Failed),
            "canceled" => Ok(TaskState::Canceled),
            "rejected" => Ok(TaskState::Rejected),
            other => Err(TaskError::UnknownState(other.to_string())),
        }
    }

    /// A state nothing leaves.
    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Failed | TaskState::Canceled | TaskState::Rejected
        )
    }

    /// PAUSED awaiting the caller. Distinct from terminal AND from active: an interrupted task
    /// consumes no compute and may sit for a long time, and is the exact row the durable store
    /// exists for.
    pub(crate) fn is_interrupted(self) -> bool {
        matches!(self, TaskState::InputRequired | TaskState::AuthRequired)
    }

    /// Live in any sense — running or paused. The rehydrate-on-restart set, and the set the
    /// retention sweep must never touch.
    pub(crate) fn is_active(self) -> bool {
        !self.is_terminal()
    }

    /// Is `to` a legal move from `self`?
    ///
    /// Written as a total function over the pair rather than as guards at the call sites, so the
    /// combination nobody thought about is refused by default instead of falling through.
    pub(crate) fn can_transition_to(self, to: TaskState) -> bool {
        use TaskState::*;
        match self {
            // A submitted task may start, be interrupted before starting (an auth challenge can
            // land immediately), or end without ever running.
            Submitted => matches!(
                to,
                Working | InputRequired | AuthRequired | Completed | Failed | Canceled | Rejected
            ),
            // Working may be interrupted or may end. It may NOT go back to submitted: `submitted`
            // means "not yet started", and a task that has started can never truthfully claim that
            // again — a resumed task returns to `working`, which is what resume actually means.
            Working => matches!(
                to,
                InputRequired | AuthRequired | Completed | Failed | Canceled | Rejected
            ),
            // An interrupt resolves by RESUMING (back to working) or by ending. Crucially it may
            // also move to the OTHER interrupt: a caller who supplies the requested input can then
            // be challenged for auth, and forcing that through `working` would emit a provenance
            // event claiming work happened when none did.
            InputRequired => matches!(
                to,
                Working | AuthRequired | Completed | Failed | Canceled | Rejected
            ),
            AuthRequired => matches!(
                to,
                Working | InputRequired | Completed | Failed | Canceled | Rejected
            ),
            // TERMINAL IS TERMINAL, including to ITSELF. A repeated `completed` is not harmless: it
            // is the shape a duplicate delivery takes, and accepting it appends a second provenance
            // event and a second billing attribution for one piece of work.
            Completed | Failed | Canceled | Rejected => false,
        }
    }
}

/// What went wrong reading or moving a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskError {
    /// A stored state token this binary does not know (see [`TaskState::parse`]).
    UnknownState(String),
    /// A stored direction token this binary does not know.
    UnknownDirection(String),
    /// The move is not in the transition table.
    IllegalTransition {
        from: &'static str,
        to: &'static str,
    },
    /// A row with no `task_id`, `context_id` or `principal`. Refused on the way IN rather than
    /// discovered on the way out: an empty `principal` is a task nobody can be shown and nobody can
    /// be billed for, and an empty `task_id` collides with the next one.
    MissingIdentity(&'static str),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::UnknownState(s) => write!(
                f,
                "unknown task state `{s}`: this row was written by a different engine version and \
                 cannot be classified as terminal or interrupted, so it is refused rather than \
                 guessed at"
            ),
            TaskError::UnknownDirection(s) => write!(f, "unknown task direction `{s}`"),
            TaskError::IllegalTransition { from, to } => {
                write!(f, "illegal task transition `{from}` -> `{to}`")
            }
            TaskError::MissingIdentity(which) => {
                write!(f, "task is missing its `{which}`")
            }
        }
    }
}

/// THE CANONICAL TASK ROW. Exactly the fields that decide how an in-flight task RESUMES after a
/// restart — who it belongs to, what state it is in, which agent it went to, and how far its
/// artifact stream got — plus the two timestamps the retention policy reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Task {
    pub(crate) task_id: String,
    pub(crate) context_id: String,
    pub(crate) principal: String,
    pub(crate) direction: Direction,
    pub(crate) state: TaskState,
    /// The chosen (outbound) or fronted (inbound) agent id; empty before dispatch.
    pub(crate) agent_id: String,
    /// How many artifact chunks have been durably relayed — the resubscribe resume point.
    pub(crate) artifact_cursor: u64,
    /// The registered push-notification callback for this task, or `None`. Already SSRF-validated
    /// when it was registered (see [`super::pushnotify`]); it is re-validated before delivery,
    /// because the row can outlive the DNS answer that was checked when it was written.
    pub(crate) push_callback: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

impl Task {
    /// A freshly SUBMITTED task. The only constructor that invents a state, so every other path has
    /// to go through [`Task::transition_to`] and be checked.
    pub(crate) fn submitted(
        task_id: impl Into<String>,
        context_id: impl Into<String>,
        principal: impl Into<String>,
        direction: Direction,
        now: u64,
    ) -> Result<Self, TaskError> {
        let task = Task {
            task_id: task_id.into(),
            context_id: context_id.into(),
            principal: principal.into(),
            direction,
            state: TaskState::Submitted,
            agent_id: String::new(),
            artifact_cursor: 0,
            push_callback: None,
            created_at: now,
            updated_at: now,
        };
        task.check_identity()?;
        Ok(task)
    }

    fn check_identity(&self) -> Result<(), TaskError> {
        if self.task_id.is_empty() {
            return Err(TaskError::MissingIdentity("task_id"));
        }
        if self.context_id.is_empty() {
            return Err(TaskError::MissingIdentity("context_id"));
        }
        if self.principal.is_empty() {
            return Err(TaskError::MissingIdentity("principal"));
        }
        Ok(())
    }

    /// Move to `to`, or refuse. `updated_at` moves only on a move that was ACCEPTED, so the
    /// retention sweep's age key never advances because of a rejected transition.
    pub(crate) fn transition_to(&mut self, to: TaskState, now: u64) -> Result<(), TaskError> {
        if !self.state.can_transition_to(to) {
            return Err(TaskError::IllegalTransition {
                from: self.state.as_str(),
                to: to.as_str(),
            });
        }
        self.state = to;
        self.updated_at = now;
        Ok(())
    }

    /// Project onto the store seam.
    pub(crate) fn to_row(&self) -> busbar_api::TaskRow {
        busbar_api::TaskRow {
            task_id: self.task_id.clone(),
            context_id: self.context_id.clone(),
            principal: self.principal.clone(),
            direction: self.direction.as_str().to_string(),
            state: self.state.as_str().to_string(),
            agent_id: self.agent_id.clone(),
            artifact_cursor: self.artifact_cursor,
            push_callback: self.push_callback.clone().unwrap_or_default(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Read back from the store seam, validating every field that has a closed domain. A row that
    /// does not parse is REFUSED and reported; the rehydrate path counts refusals rather than
    /// dropping them, because a silently skipped row is an in-flight task that quietly ceased to
    /// exist across a deploy — the exact failure the durable store was built to prevent.
    pub(crate) fn from_row(row: &busbar_api::TaskRow) -> Result<Self, TaskError> {
        let task = Task {
            task_id: row.task_id.clone(),
            context_id: row.context_id.clone(),
            principal: row.principal.clone(),
            direction: Direction::parse(&row.direction)?,
            state: TaskState::parse(&row.state)?,
            agent_id: row.agent_id.clone(),
            artifact_cursor: row.artifact_cursor,
            push_callback: if row.push_callback.is_empty() {
                None
            } else {
                Some(row.push_callback.clone())
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        };
        task.check_identity()?;
        Ok(task)
    }
}

/// MAP AN A2A STATE TRANSITION TO ITS PROVENANCE EVENT KIND. A2A DOMAIN LOGIC that moved to the a2a
/// side at the D4 codec inversion: the neutral core engine only hash-chains and persists whatever
/// `kind` it is handed, so the classification — which needs the [`TaskState`] enum — lives here and
/// the resulting `&'static str` is passed INTO the engine's record path. The kind CONSTANTS are still
/// core's (`busbar_core::provenance::EV_*`), so the emitted strings are unchanged; only the mapping
/// moved.
///
/// `from` is the state BEFORE the move and it is load-bearing: an `interrupted → working` move is a
/// RESUME, a distinct event from a fresh `working`, and the two are only separable by looking at the
/// prior state. The fallthrough is `working`, matching the pre-cleave inline mapping byte-for-byte.
pub(crate) fn event_kind_for_transition(from: TaskState, to: TaskState) -> &'static str {
    use busbar_substrate::audit::vocab::{EV_INTERRUPTED, EV_RESUMED, EV_TERMINAL, EV_WORKING};
    match to {
        TaskState::Working if from.is_interrupted() => EV_RESUMED,
        TaskState::Working => EV_WORKING,
        s if s.is_interrupted() => EV_INTERRUPTED,
        s if s.is_terminal() => EV_TERMINAL,
        _ => EV_WORKING,
    }
}

/// THE TRANSITION PLAN the neutral engine applies under its working-set lock. Given the CURRENT
/// persisted [`TaskRow`], reconstruct the canonical [`Task`], VALIDATE the move against the state
/// machine, choose the provenance event `kind`, and project the new row back — all A2A domain logic
/// the engine must not name. Returns the new row + kind on success, or the codec's rendered message
/// on refusal (an illegal move, an unreadable current row), which the engine wraps into its neutral
/// `Domain` error byte-identically to the pre-cleave `TaskStoreError::Task(TaskError)`. The new row's
/// `updated_at` is `now` (the move's timestamp), which the engine also uses as the event `ts` — the
/// same value the pre-cleave `transition(.., now, ..)` argument carried.
pub(crate) fn plan_transition(
    to: TaskState,
    now: u64,
) -> impl FnOnce(&busbar_api::TaskRow) -> Result<(busbar_api::TaskRow, &'static str), String> {
    move |row| {
        let mut task = Task::from_row(row).map_err(|e| e.to_string())?;
        // Kind is chosen off the FROM-state (before the move), exactly as the pre-cleave engine did.
        let kind = event_kind_for_transition(task.state, to);
        task.transition_to(to, now).map_err(|e| e.to_string())?;
        Ok((task.to_row(), kind))
    }
}

/// THE RESTORE-ROW READABILITY PREDICATE the neutral engine's rehydrate consults. Answers `Ok(())`
/// when the row parses as a canonical [`Task`] (a known state + direction token and a present
/// identity) and `Err(rendered message)` otherwise — the exact classification the pre-cleave
/// `restore_from_store` made inline with `Task::from_row`, moved to the a2a side so core names no
/// codec. The terminal/active split is core's ([`busbar_core::plane::taskstore`]'s neutral token check),
/// applied only after this predicate confirms the token is one this binary knows.
pub(crate) fn readable_row(row: &busbar_api::TaskRow) -> Result<(), String> {
    Task::from_row(row).map(|_| ()).map_err(|e| e.to_string())
}

/// THE A2A TASK CODEC the core TASKS engine reaches through the neutral
/// [`busbar_substrate::plane_host::TaskCodec`] seam. A ZST (so `&A2aTaskCodec` promotes to `'static`),
/// installed once by the composition root (`main`) under `plane-a2a`. Each method forwards to the
/// A2A-side codec fragment the engine must not name — so core's `task_journal_write`, boot restore and
/// `task_set_push_callback` name no `crate::a2a` type. Byte-identical to the former in-core reaches.
pub struct A2aTaskCodec;

impl busbar_substrate::plane_host::TaskCodec for A2aTaskCodec {
    fn plan_transition(
        &self,
        to_state: &str,
        now: u64,
    ) -> Result<
        Box<
            dyn FnOnce(&busbar_api::TaskRow) -> Result<(busbar_api::TaskRow, &'static str), String>,
        >,
        String,
    > {
        let to = TaskState::parse(to_state).map_err(|e| e.to_string())?;
        Ok(Box::new(plan_transition(to, now)))
    }

    fn floor_callback(&self, task_id: &str, callback: Option<String>) -> Option<String> {
        super::pushnotify::floor_callback(task_id, callback)
    }

    fn readable_row(&self, row: &busbar_api::TaskRow) -> Result<(), String> {
        readable_row(row)
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/task_tests.rs"]
mod task_tests;
