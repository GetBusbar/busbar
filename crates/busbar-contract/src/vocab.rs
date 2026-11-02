// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT VOCABULARY — the stable tokens every chained record's `outcome` and `reason` fields may

/// Admin stream: the mutation COMMITTED.
pub const OUTCOME_APPLIED: &str = "applied";
/// Admin stream: validation or conflict, and NOTHING changed.
pub const OUTCOME_REJECTED: &str = "rejected";
/// Cross-protocol egress: the request STILL FORWARDED, but a caller control with no native target
pub const OUTCOME_DEGRADED: &str = "degraded";
/// Call stream: THE CALL WENT OUT. It may still carry a `reason` — see [`REASON_UPSTREAM_FAILED`].
pub const OUTCOME_DISPATCHED: &str = "dispatched";
/// Call stream: the call did NOT go out.
pub const OUTCOME_REFUSED: &str = "refused";
/// Usage residual: the provider reported a count no billing class records, and it was NOT billed
pub const OUTCOME_UNBILLED: &str = "unbilled";

/// The caller holds no grant for this capability. Lands at ADMISSION, before any upstream is
pub const REASON_NOT_GRANTED: &str = "not_granted";

/// The caller was entitled and the EGRESS CREDENTIAL gate refused: no registration, no lease, or a
pub const REASON_EGRESS_DENIED: &str = "egress_denied";

/// The call WENT OUT and the upstream then failed. It rides [`OUTCOME_DISPATCHED`], not
pub const REASON_UPSTREAM_FAILED: &str = "upstream_failed";

/// The request was answered with an unsatisfied caller-ask round. `refused`, not a third outcome:
pub const REASON_CALLER_ASK_PENDING: &str = "caller_ask_pending";

/// The request was answered with a TASK rather than a result. Also `refused`, for the same reason:
pub const REASON_TASK_CREATED: &str = "task_created";

/// The reason token for a call an operator's HOOK GATE refused (`tools.hooks:` /
pub const REASON_HOOK_REJECTED: &str = "hook_rejected";

/// The request's parameters were missing or malformed. RECORDED rather than dropped: the caller is
pub const REASON_MALFORMED: &str = "malformed_params";

/// The PRINCIPAL is no longer live: deleted, disabled, or past its expiry. Distinct from
pub const REASON_IDENTITY_NOT_LIVE: &str = "identity_not_live";

/// The REGISTRATION serves nothing: pending, quarantined, suspended or in error. A statement about
pub const REASON_NOT_SERVING: &str = "not_serving";

/// THE RUG-PULL. The registration serves, and the capability being asked for is offered at a
pub const REASON_ARTIFACT_DRIFTED: &str = "artifact_drifted";

/// THE LIFECYCLE RACE. The registry moved between admission and dispatch, so the request is refused
pub const REASON_GENERATION_MOVED: &str = "generation_moved";

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
/// The push receiver answered 2xx: the notification is delivered.
pub const EV_PUSH_DELIVERED: &str = "task.push_delivered";
/// busbar declined to connect: the delivery-time SSRF guard refused the fresh resolution. Nothing
pub const EV_PUSH_REFUSED: &str = "task.push_refused";
/// The delivery went out and the receiver failed it (socket error or non-2xx) — a statement about
pub const EV_PUSH_FAILED: &str = "task.push_failed";
