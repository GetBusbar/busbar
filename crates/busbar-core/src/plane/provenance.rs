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

// The transition→event-kind mapping below is the ONLY A2A-type-dependent thing in this record-shape
// module; the rest (the record shape) stays in core ungated. So the `TaskState` import — and the
// mapping that needs it — are gated to `plane-a2a`, matching `plane::taskstore` (its only caller).
#[cfg(feature = "plane-a2a")]
use crate::a2a::task::TaskState;

/// Event kinds. Small, stable, greppable — tooling branches on these strings, so they are constants
/// rather than formatted at each call site.
pub(crate) const EV_SUBMITTED: &str = "task.submitted";
pub(crate) const EV_WORKING: &str = "task.working";
pub(crate) const EV_INTERRUPTED: &str = "task.interrupted";
pub(crate) const EV_RESUMED: &str = "task.resumed";
pub(crate) const EV_DELEGATED: &str = "task.delegated";
pub(crate) const EV_ARTIFACT: &str = "task.artifact";
pub(crate) const EV_TERMINAL: &str = "task.terminal";
// A DECLARED-BUT-UNMOUNTED kind: the boot rehydrate does not yet append its own event, but the kind
// is declared because the digest covers the kind's value — adding one later is a chained-record field
// change no deployment with existing chains can absorb. The `not(test)` blanket above allows the other
// unmounted kinds; this one carries its own allow because it has no reference in a test build either.
#[allow(dead_code)]
pub(crate) const EV_REHYDRATED: &str = "task.rehydrated";

// ── THE PUSH-NOTIFICATION DELIVERY EVENTS ───────────────────────────────────────────────────────
//
// WHAT WAS MISSING: `crate::a2a::pushdeliver` connected to a caller's webhook, ran the full SSRF guard
// against a FRESH resolution before every delivery, and then disposed of the outcome with a
// `tracing::warn!` at each of its three call sites. So **a delivery refused by the SSRF guard left
// no record at all** — a security control that fires silently is one nobody can audit after the
// fact, and "the guard refused a delivery to 169.254.169.254 for this task" is precisely the line an
// incident review needs. The task chain is where it belongs: the delivery is an event in that task's
// life, it is scoped to that task, and the owner's ruling is that no plane supplies a second chain.
//
// THREE KINDS, NOT ONE, and the split is the `outcome`/`reason` split this vocabulary is built on:
// `refused` means the request did not go out and `delivered`/`failed` mean it did. An operator
// reading `push_refused` looks at busbar's guard and the callback's DNS; one reading `push_failed`
// looks at the caller's own receiver. Collapsing them would send half of each population to the
// wrong place. A NEW KIND IS SAFE TO ADD (unlike a new FIELD): the digest covers the kind's VALUE,
// so events already on disk keep verifying against the same formula.

/// The receiver ANSWERED 2xx. The notification is delivered and the caller has it.
pub(crate) const EV_PUSH_DELIVERED: &str = "task.push_delivered";

/// BUSBAR DECLINED TO CONNECT: the delivery-time SSRF guard refused the fresh resolution (a callback
/// whose name now answers a private or metadata address, a wholesale move away from the pinned set),
/// the host would not resolve at all, or the stored URL is not one. Nothing left the process.
///
/// This is the one the absence of a record was worst for. An attacker's nameserver waits out the gap
/// between registration and delivery precisely because the row is durable and the DNS answer is not;
/// the refusal firing is the control WORKING, and it left no evidence that it had.
pub(crate) const EV_PUSH_REFUSED: &str = "task.push_refused";

/// THE DELIVERY WENT OUT AND THE RECEIVER FAILED IT: the socket errored, or the webhook answered
/// non-2xx. A statement about the CALLER's infrastructure, not about busbar's guard — which is why
/// it is not [`EV_PUSH_REFUSED`], for the same reason `audit::vocab::REASON_UPSTREAM_FAILED` rides
/// `dispatched` rather than `refused`.
pub(crate) const EV_PUSH_FAILED: &str = "task.push_failed";

/// MAP AN A2A STATE TRANSITION TO ITS PROVENANCE EVENT KIND. This is A2A DOMAIN LOGIC — the
/// record-shape half of the chain — deliberately kept OUT of the durable write path so a mutator
/// chooses the kind HERE and hands the journal a ready `EventInput`, never a match on task state
/// fused into the store append. Factoring it out is what lets the write path delegate to the generic
/// `audit::Journal` without carrying a scrap of A2A vocabulary into core's seq authority.
///
/// `from` is the state BEFORE the move and it is load-bearing: an `interrupted → working` move is a
/// RESUME, a distinct event from a fresh `working`, and the two are only separable by looking at the
/// prior state. The fallthrough is `working`, matching the pre-cleave inline mapping byte-for-byte.
#[cfg(feature = "plane-a2a")]
pub(crate) fn event_kind_for_transition(from: TaskState, to: TaskState) -> &'static str {
    match to {
        TaskState::Working if from.is_interrupted() => EV_RESUMED,
        TaskState::Working => EV_WORKING,
        s if s.is_interrupted() => EV_INTERRUPTED,
        s if s.is_terminal() => EV_TERMINAL,
        _ => EV_WORKING,
    }
}

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
