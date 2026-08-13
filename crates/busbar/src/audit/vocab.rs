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
pub(crate) const OUTCOME_APPLIED: &str = "applied";
/// Admin stream: validation or conflict, and NOTHING changed.
pub(crate) const OUTCOME_REJECTED: &str = "rejected";
/// Call stream: THE CALL WENT OUT. It may still carry a `reason` — see [`REASON_UPSTREAM_FAILED`].
pub(crate) const OUTCOME_DISPATCHED: &str = "dispatched";
/// Call stream: the call did NOT go out.
pub(crate) const OUTCOME_REFUSED: &str = "refused";

// ── REASONS: which of the distinguishable refusals it was ───────────────────────────────────────

/// The caller holds no grant for this capability. Lands at ADMISSION, before any upstream is
/// contacted — so a `not_granted` record is proof the upstream never saw the request.
pub(crate) const REASON_NOT_GRANTED: &str = "not_granted";

/// The caller was entitled and the EGRESS CREDENTIAL gate refused: no registration, no lease, or a
/// credential a caller may not borrow. A different incident from [`REASON_NOT_GRANTED`] with a
/// different owner, which is exactly why it is a different word.
pub(crate) const REASON_EGRESS_DENIED: &str = "egress_denied";

/// The call WENT OUT and the upstream then failed. It rides [`OUTCOME_DISPATCHED`], not
/// [`OUTCOME_REFUSED`], and the distinction is the point: `refused` means the call did not go out,
/// and this one did. The word itself is unchanged from when it rode `refused` so that tooling
/// already grepping for it keeps finding the same event.
pub(crate) const REASON_UPSTREAM_FAILED: &str = "upstream_failed";

/// The request was answered with an unsatisfied caller-ask round. `refused`, not a third outcome:
/// `dispatched` means the call went out and this one did not. The caller's retry is a fresh inbound
/// request and gets its own record, so the exchange is reconstructable from the chain without a
/// token that means "neither".
pub(crate) const REASON_CALLER_ASK_PENDING: &str = "caller_ask_pending";

/// The request was answered with a TASK rather than a result. Also `refused`, for the same reason:
/// at the moment the request is answered nothing has gone out. What happens next belongs to the
/// task's own provenance chain, and this record's job is to say that the request existed, who made
/// it, what it named, and that it became task work.
pub(crate) const REASON_TASK_CREATED: &str = "task_created";

/// The request's parameters were missing or malformed. RECORDED rather than dropped: the caller is
/// already AUTHENTICATED at this point, and a chain that silently omits every malformed request from
/// a principal is a chain with a hole an attacker can choose.
pub(crate) const REASON_MALFORMED: &str = "malformed_params";
