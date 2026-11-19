// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT VOCABULARY — the stable tokens every chained record's `outcome` and `reason` fields may

/// Admin stream: the mutation COMMITTED.
pub const OUTCOME_APPLIED: &str = "applied";
/// Admin stream: validation or conflict, and NOTHING changed.
pub const OUTCOME_REJECTED: &str = "rejected";
/// Cross-protocol egress: the request STILL FORWARDED, but a caller control with no native target
pub const OUTCOME_DEGRADED: &str = "degraded";
/// Call stream: the call did NOT go out.
pub const OUTCOME_REFUSED: &str = "refused";

/// The caller holds no grant for this capability. Lands at ADMISSION, before any upstream is
pub const REASON_NOT_GRANTED: &str = "not_granted";

/// The caller was entitled and the EGRESS CREDENTIAL gate refused: no registration, no lease, or a
pub const REASON_EGRESS_DENIED: &str = "egress_denied";

/// The call WENT OUT and the upstream then failed. It rides [`OUTCOME_DISPATCHED`], not
pub const REASON_UPSTREAM_FAILED: &str = "upstream_failed";

/// The PRINCIPAL is no longer live: deleted, disabled, or past its expiry. Distinct from
pub const REASON_IDENTITY_NOT_LIVE: &str = "identity_not_live";

/// The REGISTRATION serves nothing: pending, quarantined, suspended or in error. A statement about
pub const REASON_NOT_SERVING: &str = "not_serving";

/// THE RUG-PULL. The registration serves, and the capability being asked for is offered at a
pub const REASON_ARTIFACT_DRIFTED: &str = "artifact_drifted";

/// THE LIFECYCLE RACE. The registry moved between admission and dispatch, so the request is refused
pub const REASON_GENERATION_MOVED: &str = "generation_moved";
