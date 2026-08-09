// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-TASK HASH CHAIN: the provenance substrate both directions share, and the verifier that
//! makes it more than decoration.
//!
//! ## What this is, stated honestly
//!
//! This is TAMPER-EVIDENCE, not tamper-prevention, and the distinction is the whole product claim.
//! A chain detects an altered, reordered, inserted or deleted event AFTER the fact. It does not stop
//! one. A host that is compromised at the moment of writing can rewrite the whole chain consistently
//! and this will verify; prevention means shipping the events off-box to something the compromised
//! host cannot rewrite. Anything stronger said about it is oversold.
//!
//! ## Per TASK, not one global chain
//!
//! Tasks are concurrent, long-lived, and belong to different callers. One global chain would:
//!
//! - serialise every transition of every task behind a single append lock, on a plane whose whole
//!   premise is many simultaneous long-running tasks;
//! - make one task's provenance unverifiable without possessing every other caller's events, which
//!   collides head-on with the rule that a caller may never see another tenant's task; and
//! - make an unrelated task's loss break the chain of a task that was fine.
//!
//! So the chain's scope is the `task_id` and the sequence is 1-based within it.
//!
//! ## The verifier reports WHERE and WHY, and that is deliberate
//!
//! A verifier that returns `bool` tells an operator that something is wrong and nothing else, which
//! in practice means the check gets run once and then ignored. [`verify_chain`] names the sequence
//! number and distinguishes the three failures that mean different things:
//!
//! - a DIGEST mismatch: this event's own fields were edited;
//! - a LINK mismatch: this event does not follow the one before it (an insertion, a deletion, or a
//!   reorder);
//! - a SEQUENCE break: a gap or a duplicate, which a link check alone would miss when a whole
//!   contiguous run was removed from the tail.
//!
//! The three are distinguishable because the operator's next action differs.

// PARTLY UNMOUNTED. The chain is appended on every inbound task the ingress opens, so `append`,
// `EV_SUBMITTED` and `EV_DELEGATED` are live. The event kinds for transitions the ingress does not
// yet drive — artifact relay, interrupt, resume, terminal — are declared here because the DIGEST
// covers the kind: adding one later would be adding a field to a chained record, which is not a
// change a deployment with existing chains can absorb.
#![cfg_attr(not(test), allow(dead_code))]

use busbar_api::TaskEventRow;

/// Event kinds. Small, stable, greppable — tooling branches on these strings, so they are constants
/// rather than formatted at each call site.
pub(crate) const EV_SUBMITTED: &str = "task.submitted";
pub(crate) const EV_WORKING: &str = "task.working";
pub(crate) const EV_INTERRUPTED: &str = "task.interrupted";
pub(crate) const EV_RESUMED: &str = "task.resumed";
pub(crate) const EV_DELEGATED: &str = "task.delegated";
pub(crate) const EV_ARTIFACT: &str = "task.artifact";
pub(crate) const EV_TERMINAL: &str = "task.terminal";
pub(crate) const EV_REHYDRATED: &str = "task.rehydrated";

/// The fields a caller supplies for one event. `seq`, `prev_hash` and `hash` are NOT here: they are
/// the chain's own business and are computed by [`TaskChain::append`], so no call site can supply a
/// sequence number or a link of its own choosing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventInput {
    pub(crate) kind: &'static str,
    pub(crate) context_id: String,
    pub(crate) principal: String,
    pub(crate) agent_id: String,
    pub(crate) state: String,
    pub(crate) request_id: String,
    pub(crate) ts: u64,
}

/// The digest over an event's CHAINED fields.
///
/// `request_id` is deliberately EXCLUDED. It is a join key handed in by the request spine, it is
/// absent on the paths that have no inbound request (the boot rehydrate, the retention sweep), and
/// a field that is sometimes absent must not be able to make an otherwise-intact chain unverifiable.
/// Everything that carries meaning about WHAT HAPPENED is inside.
///
/// The separator is `|` and every field is length-unambiguous in practice because `task_id`,
/// `context_id`, `principal` and `agent_id` are busbar-issued ids and the kinds and states are from
/// closed sets, none of which may contain `|`. [`EventInput`] fields that could, cannot reach here:
/// the constructor is crate-internal and every caller passes ids.
fn compute_hash(row: &TaskEventRow) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.prev_hash,
        row.task_id,
        row.seq,
        row.ts,
        row.kind,
        row.context_id,
        row.principal,
        row.agent_id,
        row.state
    );
    busbar_api::sha256_hex(canonical.as_bytes())
}

/// ONE TASK'S CHAIN, in memory: the tail link and the next sequence number. Small on purpose — the
/// events themselves live in the store, and holding every event of every task in RAM is the thing
/// the durable store exists to avoid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TaskChain {
    /// The `hash` of the most recent event, or empty when the chain is empty.
    tail_hash: String,
    /// The sequence the NEXT appended event gets.
    next_seq: u64,
}

impl TaskChain {
    /// A chain with nothing in it. The first event gets `seq` 1 and an empty `prev_hash`.
    pub(crate) fn new() -> Self {
        TaskChain {
            tail_hash: String::new(),
            next_seq: 1,
        }
    }

    /// Continue a chain from what is already PERSISTED, so a restart continues the same chain rather
    /// than starting a second one under the same task id.
    ///
    /// The events are VERIFIED before they are trusted to position the chain. Resuming from an
    /// unverified tail would append a valid-looking link onto a forged one and launder the forgery:
    /// every subsequent verification would pass, and the break would sit permanently behind the
    /// point anybody looks. On a broken chain this returns the error and the caller decides — the
    /// engine's answer is to report it loudly and continue from the broken tail, because refusing to
    /// record anything further would mean a detected tamper silently stops all provenance.
    pub(crate) fn from_persisted(events: &[TaskEventRow]) -> Result<Self, ChainBreak> {
        verify_chain(events)?;
        Ok(Self::from_persisted_unverified(events))
    }

    /// Position a chain on the tail of `events` WITHOUT verifying them. Only for the
    /// tamper-detected path, where the break has already been reported and the alternative is to
    /// stop recording provenance entirely.
    pub(crate) fn from_persisted_unverified(events: &[TaskEventRow]) -> Self {
        match events.last() {
            None => TaskChain::new(),
            Some(last) => TaskChain {
                tail_hash: last.hash.clone(),
                next_seq: last.seq.saturating_add(1),
            },
        }
    }

    /// The sequence the next appended event will carry.
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Append one event, linking it to the tail and advancing the chain.
    pub(crate) fn append(&mut self, task_id: &str, input: EventInput) -> TaskEventRow {
        let mut row = TaskEventRow {
            task_id: task_id.to_string(),
            seq: self.next_seq,
            ts: input.ts,
            kind: input.kind.to_string(),
            context_id: input.context_id,
            principal: input.principal,
            agent_id: input.agent_id,
            state: input.state,
            request_id: input.request_id,
            prev_hash: self.tail_hash.clone(),
            hash: String::new(),
        };
        row.hash = compute_hash(&row);
        self.tail_hash = row.hash.clone();
        self.next_seq = self.next_seq.saturating_add(1);
        row
    }
}

/// WHY a chain failed to verify, and WHERE. Three distinguishable causes, because the operator's
/// response to each is different.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainBreakKind {
    /// This event's stored `hash` is not the digest of its own fields: a field was edited in place.
    DigestMismatch { stored: String, recomputed: String },
    /// This event's `prev_hash` is not the previous event's `hash`: something was inserted,
    /// removed, or reordered around here.
    LinkMismatch { expected: String, found: String },
    /// The sequence is not `1, 2, 3, …`: a gap (events removed) or a duplicate/regression.
    SequenceBreak { expected: u64, found: u64 },
    /// A different task's event is present in this chain. A chain is scoped to ONE task; mixing
    /// them in would let one caller's provenance depend on another caller's rows.
    ForeignTask { expected: String, found: String },
}

/// A verification failure: the position and the cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainBreak {
    /// The 1-based index INTO THE SLICE at which the break was found. Distinct from `seq`, which is
    /// itself untrustworthy on a `SequenceBreak` — reporting only `seq` would report the tampered
    /// value.
    pub(crate) at_index: usize,
    /// The event's claimed sequence number.
    pub(crate) seq: u64,
    /// The task the chain is scoped to.
    pub(crate) task_id: String,
    pub(crate) kind: ChainBreakKind,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "task `{}` provenance chain BROKEN at index {} (seq {}): ",
            self.task_id, self.at_index, self.seq
        )?;
        match &self.kind {
            ChainBreakKind::DigestMismatch { stored, recomputed } => write!(
                f,
                "the event's own fields do not hash to its stored digest (stored {stored}, \
                 recomputed {recomputed}) — this event was EDITED"
            ),
            ChainBreakKind::LinkMismatch { expected, found } => write!(
                f,
                "prev_hash does not match the preceding event's hash (expected {expected}, found \
                 {found}) — an event was INSERTED, REMOVED or REORDERED here"
            ),
            ChainBreakKind::SequenceBreak { expected, found } => write!(
                f,
                "sequence is not contiguous (expected {expected}, found {found}) — events were \
                 REMOVED or DUPLICATED"
            ),
            ChainBreakKind::ForeignTask { expected, found } => write!(
                f,
                "an event belonging to task `{found}` appears in task `{expected}`'s chain"
            ),
        }
    }
}

/// VERIFY one task's chain. `events` must be the store's oldest-first list for a single task.
///
/// An EMPTY list verifies. That is not a loophole being waved through: "this task has no events" is
/// indistinguishable from "every event was deleted" using the events alone, and pretending otherwise
/// would make the verifier claim a guarantee it cannot provide. The guarantee that DOES close it is
/// held elsewhere — the task row records that the task exists, so a task row with an empty chain is
/// detectable by the caller that holds both, which is exactly what [`super::taskstore`]'s audit
/// sweep does.
pub(crate) fn verify_chain(events: &[TaskEventRow]) -> Result<(), ChainBreak> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    let task_id = first.task_id.clone();
    let mut expected_prev = String::new();
    let mut expected_seq = 1u64;

    for (i, ev) in events.iter().enumerate() {
        let at_index = i + 1;
        let brk = |kind| ChainBreak {
            at_index,
            seq: ev.seq,
            task_id: task_id.clone(),
            kind,
        };
        if ev.task_id != task_id {
            return Err(brk(ChainBreakKind::ForeignTask {
                expected: task_id.clone(),
                found: ev.task_id.clone(),
            }));
        }
        if ev.seq != expected_seq {
            return Err(brk(ChainBreakKind::SequenceBreak {
                expected: expected_seq,
                found: ev.seq,
            }));
        }
        // The LINK is checked before the DIGEST. Both are wrong when an event is spliced out, and
        // the link is the one that names the real defect ("something is missing here") while the
        // digest would report the innocent successor as edited.
        if ev.prev_hash != expected_prev {
            return Err(brk(ChainBreakKind::LinkMismatch {
                expected: expected_prev.clone(),
                found: ev.prev_hash.clone(),
            }));
        }
        let recomputed = compute_hash(ev);
        if recomputed != ev.hash {
            return Err(brk(ChainBreakKind::DigestMismatch {
                stored: ev.hash.clone(),
                recomputed,
            }));
        }
        expected_prev = ev.hash.clone();
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/provenance_tests.rs"]
mod provenance_tests;
