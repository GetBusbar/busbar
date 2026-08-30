// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-TASK PROVENANCE RECORD — the A2A plane's contribution to the ONE hash chain, which is
//! [`crate::audit`]'s and not this file's.
//!
//! ## What this file is now, and what it deliberately is not
//!
//! It used to carry its own `compute_hash`, its own `TaskChain`, its own `ChainBreak`/`ChainBreakKind`
//! and its own `verify_chain` — a second copy of the machinery `admin/audit.rs` already had and a
//! third of what `mcp/calllog.rs` had. Owner's ruling, 2026-08-13: *"auditing is core. nothing
//! auditing wise should be mcp a2a or llm specific. thats how audits break."* Three chains give
//! three answers to "what happened", and an auditor reads whichever was wired last.
//!
//! So the mechanism moved to [`crate::audit`] and what stays here is the RECORD SHAPE: the event
//! kinds and the transition→kind mapping. The durable write path itself flows through the neutral
//! journal seam (`crate::plane_host::journal`): a task event crosses the store boundary as a
//! `PlaneJournalRecord` whose `content` is the pre-framed digest suffix built plane-side in
//! [`crate::plane::taskstore`], so core's seq-authority never carries a scrap of A2A vocabulary.
//! A2A supplies a record shape; it does not supply a second chain — the same shape as `a2a/pin.rs`,
//! which supplies an artifact and not a second trust state machine.
//!
//! ## Per TASK, not one global chain — and that is still true
//!
//! The chain's SCOPE is `task_id` and the sequence is 1-based within it. Tasks are concurrent,
//! long-lived, and belong to different callers. One global chain would serialise every transition of
//! every task behind a single append lock, make one task's provenance unverifiable without
//! possessing every other caller's events, and let an unrelated task's loss break the chain of a
//! task that was fine. Unifying the MECHANISM does not merge the STREAMS: [`crate::audit`] keys a
//! chain by scope and its verifier refuses a foreign scope outright.
//!
//! ## What the claim is
//!
//! TAMPER-EVIDENCE, not tamper-prevention: a chain detects an altered, reordered, inserted or
//! deleted event AFTER the fact. It does not stop one, and a host compromised at the moment of
//! writing can rewrite a whole chain consistently and this will verify. Stated in full in
//! [`crate::audit`], where the mechanism it describes now lives.

// PARTLY UNMOUNTED, and the allow stays scoped to that fact. The chain is appended on every inbound
// task the ingress opens, so the mechanism and most kinds are live. The event kinds for transitions
// the ingress does not yet drive are declared anyway because the DIGEST covers the kind: adding one
// later would be adding a field to a chained record, which is not a change a deployment with
// existing chains can absorb.
#![cfg_attr(not(test), allow(dead_code))]

// The transition→event-kind MAPPING moved to the a2a side (`event_kind_for_transition`, in a2a::task)
// at the D4 codec inversion: it is A2A lifecycle semantics (resumed/working/interrupted) that needs the
// `TaskState` enum, and the neutral engine only hash-chains and persists whatever `kind` the caller
// hands it. What stays here is the RECORD SHAPE — the event-kind CONSTANTS below, greppable and stable —
// which name no a2a type; the a2a-side mapping references these constants, so the emitted strings are
// still defined in core and remain byte-identical.

// Event kinds. The `kind` token each per-task provenance event carries. Now OWNED by the neutral
// audit vocabulary ([`busbar_substrate::audit::vocab`]) so the A2A plane that appends these events and
// this engine that hash-chains them name ONE spelling of each across the core/substrate seam — the
// digest covers the kind's VALUE, so a single spelling is what keeps existing chains verifying.
// Re-exported here for core's own call sites. `EV_WORKING`/`EV_INTERRUPTED`/`EV_RESUMED` are named
// by the a2a-side event-kind mapping directly off the vocabulary and are not re-exported here;
// `EV_TERMINAL` IS re-exported because the taskstore's abandonment sweep appends it (the same kind
// the a2a mapping chooses for every transition into a terminal state); `EV_REHYDRATED` is declared
// in the vocabulary to reserve its digest value and has no live appender yet. Gated with its users
// (the TASKS engine + host journal, all `plane-a2a`): with the plane off they are compiled out and
// this re-export would otherwise read unused.
#[cfg(feature = "plane-a2a")]
pub use busbar_substrate::audit::vocab::{
    EV_ARTIFACT, EV_DELEGATED, EV_PUSH_DELIVERED, EV_PUSH_FAILED, EV_PUSH_REFUSED, EV_SUBMITTED,
    EV_TERMINAL,
};

/// The fields a caller supplies for one event. `seq`, `prev_hash` and `hash` are NOT here: they are
/// the chain's own business and are supplied by [`crate::audit::Chain::append`], so no call site can
/// supply a sequence number or a link of its own choosing.
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
