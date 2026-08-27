// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT VOCABULARY — the stable tokens every chained record's `outcome` and `reason` fields may
//! carry, owned by core rather than by whichever plane wrote them down first.
//!
//! ## Why the MCP words won, rather than the oldest ones
//!
//! Three streams recorded outcomes and they were not equally good at it. The admin audit log has one
//! word for a failure — `rejected` — while the MCP call log deliberately distinguishes
//! [`REASON_NOT_GRANTED`] (the caller was never entitled to this), [`REASON_EGRESS_DENIED`] (it was
//! entitled, and the credential gate refused) and [`REASON_UPSTREAM_FAILED`] (it went out and the
//! far end broke). Those are three different incidents with three different owners, and a log that
//! calls all of them "refused" makes an operator open a shell to find out which one happened.
//!
//! So unification promotes the RICHER vocabulary instead of flattening to the weakest of the three.
//! A `reason` sits BESIDE the `outcome`, so nothing that reads `outcome` alone changed, and a reader
//! that branches on the tokens it knows and ignores the rest keeps working as the set grows.
//!
//! ## The outcome/reason split is load-bearing, not decoration
//!
//! [`OUTCOME_DISPATCHED`] means THE CALL WENT OUT and [`OUTCOME_REFUSED`] means it did not — that is
//! the whole content of the field, and it is why [`REASON_UPSTREAM_FAILED`] rides `dispatched`: an
//! upstream outage recorded as a refusal says the opposite of what happened, and an operator reading
//! it would chase an authorization problem that does not exist.
//!
//! ## These are WIRE WORDS
//!
//! Tooling greps them and store rows already hold them. A token may be ADDED; one that exists may
//! not be spelled differently, because renaming it silently breaks every query written against it.

// ── OUTCOMES: what happened, in one word per stream's terms ─────────────────────────────────────

/// Admin stream: the mutation COMMITTED.
pub const OUTCOME_APPLIED: &str = "applied";
/// Admin stream: validation or conflict, and NOTHING changed.
pub const OUTCOME_REJECTED: &str = "rejected";
/// Cross-protocol egress: the request STILL FORWARDED, but a caller control with no native target
/// representation was dropped (audit-and-allow). Recorded as a first-class event, not just a log warn.
pub const OUTCOME_DEGRADED: &str = "degraded";
/// Call stream: THE CALL WENT OUT. It may still carry a `reason` — see [`REASON_UPSTREAM_FAILED`].
pub const OUTCOME_DISPATCHED: &str = "dispatched";
/// Call stream: the call did NOT go out.
pub const OUTCOME_REFUSED: &str = "refused";

// ── REASONS: which of the distinguishable refusals it was ───────────────────────────────────────

/// The caller holds no grant for this capability. Lands at ADMISSION, before any upstream is
/// contacted — so a `not_granted` record is proof the upstream never saw the request.
pub const REASON_NOT_GRANTED: &str = "not_granted";

/// The caller was entitled and the EGRESS CREDENTIAL gate refused: no registration, no lease, or a
/// credential a caller may not borrow. A different incident from [`REASON_NOT_GRANTED`] with a
/// different owner, which is exactly why it is a different word.
pub const REASON_EGRESS_DENIED: &str = "egress_denied";

/// The call WENT OUT and the upstream then failed. It rides [`OUTCOME_DISPATCHED`], not
/// [`OUTCOME_REFUSED`], and the distinction is the point: `refused` means the call did not go out,
/// and this one did. The word itself is unchanged from when it rode `refused` so that tooling
/// already grepping for it keeps finding the same event.
pub const REASON_UPSTREAM_FAILED: &str = "upstream_failed";

/// The request was answered with an unsatisfied caller-ask round. `refused`, not a third outcome:
/// `dispatched` means the call went out and this one did not. The caller's retry is a fresh inbound
/// request and gets its own record, so the exchange is reconstructable from the chain without a
/// token that means "neither".
pub const REASON_CALLER_ASK_PENDING: &str = "caller_ask_pending";

/// The request was answered with a TASK rather than a result. Also `refused`, for the same reason:
/// at the moment the request is answered nothing has gone out. What happens next belongs to the
/// task's own provenance chain, and this record's job is to say that the request existed, who made
/// it, what it named, and that it became task work.
pub const REASON_TASK_CREATED: &str = "task_created";

/// A GOVERNANCE BUCKET REFUSED THE REQUEST: a rate, concurrency or budget limit the presenting key
/// is bound to was already at its ceiling, so nothing was dispatched.
///
/// Its own word rather than [`REASON_NOT_GRANTED`], because the two send an operator to different
/// places and the remedies are different objects: `not_granted` means this caller may never reach
/// this thing and the remedy is a scope, while this means the caller is entitled and has spent its
/// allowance — the remedy is a quota, or waiting for the window to roll. Flattening them would make
/// an operator audit the grant matrix for a decision the grant matrix did not take, which is the
/// exact failure this vocabulary exists to prevent.
pub const REASON_LIMIT_EXCEEDED: &str = "limit_exceeded";

/// The reason token for a call an operator's HOOK GATE refused (`tools.hooks:` /
/// `tools.<server>.hooks:`).
///
/// `refused`, and a token of its OWN rather than folding into [`REASON_NOT_GRANTED`]: those two send
/// an operator to different places. `not_granted` means the caller's key does not reach this tool and
/// the remedy is a scope; this means the tool was reachable and a policy the operator attached said
/// no, and the remedy is that policy. A single word for both would make an operator debug the
/// grant matrix for a decision the grant matrix did not take.
pub const REASON_HOOK_REJECTED: &str = "hook_rejected";

/// The request's parameters were missing or malformed. RECORDED rather than dropped: the caller is
/// already AUTHENTICATED at this point, and a chain that silently omits every malformed request from
/// a principal is a chain with a hole an attacker can choose.
pub const REASON_MALFORMED: &str = "malformed_params";

// ── THE FAILOVER SEAM'S REASONS ─────────────────────────────────────────────────────────────────
//
// `crate::failover` asks one question before every hop on every plane — is there anywhere left, are
// these two the same deployment, and may this call be made twice. Its refusals are recorded, so its
// words are audit words and they live here with the rest rather than in the module that decides.
//
// THEY STAY PLURAL, for the reason the whole file states: each one sends an operator somewhere
// different. One is an outage, one is a configuration that does not hold up against the digests
// busbar computed, and one is busbar declining to repeat something with effects.

/// There is nowhere left to send this request: the pool names no candidate, or every candidate in it
/// refused admission. ONE word for both, because they are one incident with one operator question
/// ("what is up with that pool?") — the refusal itself carries the per-candidate reasons in the
/// shared `Unavailable` taxonomy, so nothing is lost by not spelling them apart here.
// Named by `crate::failover` (see its header for why that module is not on a dispatch path yet);
// the word is defined HERE regardless, because the audit vocabulary is core's and a plane arriving
// later must find it rather than spell a fourth synonym.
#[cfg_attr(not(test), allow(dead_code))]
pub const REASON_NO_UPSTREAM_LEFT: &str = "no_upstream_left";

/// A FAILOVER HOP WAS REFUSED BECAUSE THE PINS DISAGREE. The operator declared two registrations to
/// be the same deployment, busbar compared the fingerprints it already had, and they are not equal —
/// so the request was not moved.
///
/// Its own word because it indicts neither the caller nor the upstream: it is the one refusal that
/// says the CONFIGURATION claimed something checkable and the check failed. Distinct from
/// [`REASON_ARTIFACT_DRIFTED`], which is one upstream changing under an approval; this is two
/// upstreams that were never the same thing.
// Named by `crate::failover` (see its header for why that module is not on a dispatch path yet);
// the word is defined HERE regardless, because the audit vocabulary is core's and a plane arriving
// later must find it rather than spell a fourth synonym.
#[cfg_attr(not(test), allow(dead_code))]
pub const REASON_NOT_INTERCHANGEABLE: &str = "not_interchangeable";

/// THE SAFETY RULE FIRED. The call already went out, it is not declared repeatable, and busbar
/// therefore did NOT send it to a second member of the pool.
///
/// Recorded rather than folded into a generic failure because it is the one outcome an operator may
/// actually want to change, and the change is a deliberate one: declare the operation safe to repeat.
/// A log that called this "upstream failed" would hide the fact that busbar had somewhere else to go
/// and chose not to use it.
// Named by `crate::failover` (see its header for why that module is not on a dispatch path yet);
// the word is defined HERE regardless, because the audit vocabulary is core's and a plane arriving
// later must find it rather than spell a fourth synonym.
#[cfg_attr(not(test), allow(dead_code))]
pub const REASON_NOT_REPEATABLE: &str = "not_repeatable";

// ── THE ORDERED REQUEST VALIDATOR'S REASONS ─────────────────────────────────────────────────────
//
// `crate::trust::validate` asks one ordered question before every dispatch on every plane —
// identity, then grant, then whether the artifact still matches what was approved, then whether the
// snapshot it was admitted under is still live. Its refusals are recorded, so its words are audit
// words and they live here with the rest.
//
// THEY STAY PLURAL FOR THE SAME REASON THE THREE ABOVE DO. Each one sends an operator somewhere
// different: re-issue a credential, grant a scope, edit the target's egress list, work a changes
// queue, retry. A gate that answered "refused" to all five would be the admin log's single word
// re-invented one layer down.

/// The PRINCIPAL is no longer live: deleted, disabled, or past its expiry. Distinct from
/// [`REASON_NOT_GRANTED`] because the remedies are different objects — a key that is gone is
/// re-issued, a key that is merely unscoped is granted — and distinct from an authentication
/// failure at the edge because this principal DID authenticate and then went stale underneath a
/// request that was already in flight.
pub const REASON_IDENTITY_NOT_LIVE: &str = "identity_not_live";

/// The REGISTRATION serves nothing: pending, quarantined, suspended or in error. A statement about
/// the upstream rather than about the caller, which is why it is not a grant word — the caller may
/// be perfectly entitled and there is simply nothing here that may be dispatched to.
///
/// A plane may render this more finely (`not_pinned`, `not_approved`, `quarantined` are three
/// operator actions behind this one decision) and doing so is the opposite of flattening: the gate
/// decides, and the plane says which of its shapes the decision took.
pub const REASON_NOT_SERVING: &str = "not_serving";

/// THE RUG-PULL. The registration serves, and the capability being asked for is offered at a
/// fingerprint nobody approved — a tool's schema changed under the cache, a card was re-signed.
/// Its own word because it is the one refusal that indicts the UPSTREAM rather than the operator's
/// configuration or the caller's grant.
pub const REASON_ARTIFACT_DRIFTED: &str = "artifact_drifted";

/// THE LIFECYCLE RACE. The registry moved between admission and dispatch, so the request is refused
/// rather than sent against a snapshot the operator has already replaced.
///
/// The least specific of the refusals and deliberately the LAST one asked, because "something
/// moved, retry" is a worse message than any of the others and an operator handed it goes looking
/// for an apply they may not have made. Nothing is admitted by asking it last: a request that would
/// fail an earlier step fails that step instead.
pub const REASON_GENERATION_MOVED: &str = "generation_moved";

// ── TASK PROVENANCE EVENT KINDS ─────────────────────────────────────────────────────────────────
//
// The `kind` token every per-task provenance event carries. Owned here in the neutral vocabulary,
// not by the A2A plane that appends them, for the reason the whole module states: the digest covers
// the kind's VALUE, so events already on disk keep verifying against the same formula only if there
// is ONE spelling of each kind. The core TASKS engine hash-chains and persists them and the A2A plane
// (and its a2a-side event-kind mapping) supplies them; both name these constants, so core re-exports
// them at `crate::plane::provenance::EV_*` and its own call sites are unchanged.

/// Accepted, not yet started.
pub const EV_SUBMITTED: &str = "task.submitted";
/// Running (a fresh start, not a resume).
pub const EV_WORKING: &str = "task.working";
/// Paused awaiting the caller (input- or auth-required).
pub const EV_INTERRUPTED: &str = "task.interrupted";
/// An interrupted task resumed to working — distinct from a fresh `working`.
pub const EV_RESUMED: &str = "task.resumed";
/// Dispatched to the chosen/fronted agent.
pub const EV_DELEGATED: &str = "task.delegated";
/// An artifact chunk was durably relayed (the resume cursor advanced).
pub const EV_ARTIFACT: &str = "task.artifact";
/// Reached a terminal state (completed/failed/canceled/rejected).
pub const EV_TERMINAL: &str = "task.terminal";
/// A declared-but-unmounted kind: boot rehydrate does not append its own event yet, but the kind is
/// declared because the digest covers its value — adding one later is a chained-record field change
/// no deployment with existing chains can absorb.
pub const EV_REHYDRATED: &str = "task.rehydrated";
/// The push receiver answered 2xx: the notification is delivered.
pub const EV_PUSH_DELIVERED: &str = "task.push_delivered";
/// busbar declined to connect: the delivery-time SSRF guard refused the fresh resolution. Nothing
/// left the process — a security control firing, recorded so it leaves evidence.
pub const EV_PUSH_REFUSED: &str = "task.push_refused";
/// The delivery went out and the receiver failed it (socket error or non-2xx) — a statement about
/// the caller's infrastructure, not busbar's guard.
pub const EV_PUSH_FAILED: &str = "task.push_failed";
