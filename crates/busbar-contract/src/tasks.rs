// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TASK-STORE VOCABULARY: what a caller-visible long-running task IS, read through one face by
//! every plane that owns a tasks extension.
//!
//! A plane whose `tools/call` (or equivalent) may run longer than a request may reasonably be held
//! open for hands the caller a task id instead of an answer, and the caller polls for it. Two planes
//! — mcp's SEP-2663 extension and a2a's native `Task` object — each keep their OWN store, in their
//! own process-local shape, because the two wire objects genuinely differ (a2a's carries a context id
//! and an artifact cursor; mcp's inlines a tool result). What is IDENTICAL between them is the read a
//! poll performs: resolve an id for the caller that holds it, and hand back what is settled so far.
//! That read is [`TaskStore::get`], and it is the whole of this module.
//!
//! ## Facts are carried, not interpreted
//!
//! [`TaskRecord::status`] is the plane's own wire word, unread by this face — mcp closes its status
//! vocabulary as `working`/`input_required`/`completed`/`failed`/`cancelled`; a2a's differs. Minting
//! one closed enum here would mean this face taking a position on which of the two vocabularies (or
//! a third) is correct, and it does not need to: the fold that would care is on the plane's own side
//! of this seam, where the wire is named.
//!
//! [`TaskRecord::result`], [`TaskRecord::error`] and the entries of
//! [`TaskRecord::input_requests`] are OPAQUE bytes — each plane's own codec's encoding of whatever it
//! settled — for the same reason [`busbar_contract::wire`](crate::wire) carries bytes rather than a
//! parsed document everywhere else it crosses this boundary: a value already framed in one plane's
//! dialect is not translated a second time by a face that does not speak it.
//!
//! ## The one privacy rule
//!
//! A task belongs to the principal that created it. [`TaskStore::get`] answers `None` for a task
//! that exists but belongs to someone else, EXACTLY as it answers `None` for an id that never
//! existed — the two cases are indistinguishable on purpose, because a distinguishable answer would
//! let a caller learn which ids exist without holding them.

/// One stored task, read back through [`TaskStore::get`].
///
/// Every timestamp is carried PRE-FORMATTED (the plane's own wire spelling, e.g. RFC 3339) rather
/// than as a raw clock reading: formatting a clock reading is a decision about a calendar, and nothing
/// this face does needs to make it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskRecord {
    /// The task id, as the plane's own wire spells it.
    pub id: String,
    /// The lifecycle status, as the plane's own wire spells it. Not interpreted here — see the
    /// module header.
    pub status: String,
    /// When the task was created, pre-formatted.
    pub created_at: String,
    /// When the task's state last changed, pre-formatted.
    pub updated_at: String,
    /// How long, in milliseconds, the store commits to retaining this row after it settles.
    pub ttl_ms: u64,
    /// The poll cadence this store suggests, in milliseconds.
    pub poll_interval_ms: u64,
    /// The settled answer, in the plane's own codec's bytes. `None` before the task is terminal, or
    /// on a task that terminates by [`error`](Self::error) instead.
    pub result: Option<Vec<u8>>,
    /// The protocol-level failure, in the plane's own codec's bytes. `None` unless the task failed.
    pub error: Option<Vec<u8>>,
    /// The still-unanswered asks of the current round: a key and its value's bytes, in the store's
    /// own order. Empty when nothing is outstanding.
    pub input_requests: Vec<(String, Vec<u8>)>,
}

/// The seam every plane's task methods read and move a stored task through.
///
/// One face for every plane that has a task extension, so a kind-neutral step (or, short of one, a
/// second plane reading the same shape) never has to know which store answered it.
///
/// ## The clock is HANDED IN, never read here
///
/// Both writes take `now_ms` rather than reading a clock behind the face. A store that read its own
/// clock would be a second reading of the time on a request that already took one, and the two can
/// disagree — a plane's own rule is that it reads no clock but the one its context hands it, and a
/// face that broke that rule for the store's convenience would move the violation rather than
/// remove it. The millisecond scale is the one every timestamp on [`TaskRecord`] was formatted from.
///
/// ## An absent task and a foreign one are ONE answer, on the writes too
///
/// [`TaskStore::update`] and [`TaskStore::cancel`] answer `None` on a task that belongs to somebody
/// else, exactly as [`TaskStore::get`] does and for exactly the same reason. It matters MORE here,
/// not less: a write that refused a foreign task by name would let a caller enumerate live ids
/// without ever being able to read one, which is the probe the read arm was closed against.
pub trait TaskStore {
    /// Resolve `id` FOR `principal`. `None` when there is no such task, OR it belongs to a
    /// different principal — see the module header for why the two are the same answer.
    fn get(&self, id: &str, principal: &str) -> Option<TaskRecord>;

    /// DELIVER the caller's answers to a task's outstanding asks.
    ///
    /// `answers` is keyed the way [`TaskRecord::input_requests`] is, and each value is the plane's
    /// own codec's bytes for the same reason the asks are: a value already framed in one plane's
    /// dialect is not translated a second time by a face that does not speak it. An answer to a key
    /// the task never asked for is the STORE's business, not this face's — the store knows what it
    /// parked on and this face does not.
    ///
    /// `Some(())` when the task was this caller's; `None` otherwise. Delivering an EMPTY answer set
    /// is well-formed and not an error: a caller that has nothing yet has said so.
    fn update(
        &self,
        id: &str,
        principal: &str,
        answers: &[(String, Vec<u8>)],
        now_ms: u64,
    ) -> Option<()>;

    /// CANCEL a task, IDEMPOTENTLY.
    ///
    /// A task that has already settled is not an error and is not rewritten: a task can terminate
    /// between the poll that observed it running and the cancel that followed, and making every
    /// caller handle a race it cannot avoid is not a contract worth having. `Some(())` when the task
    /// was this caller's — settled or not — and `None` otherwise.
    fn cancel(&self, id: &str, principal: &str, now_ms: u64) -> Option<()>;
}
