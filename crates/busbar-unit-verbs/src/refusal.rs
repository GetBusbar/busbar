// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reasons a verb call can be refused, named the way the architecture document names them
//! (`Refused(Approve, InsufficientApprovers)`, `Refused(Approve, SelfApproval)`, and so on) so a
//! caller can render or audit the exact reason without re-deriving it from a status code.

/// A refused verb call. `step` mirrors the ten-step names `busbar-caps` seals (this crate only ever
/// refuses at `Approve` or `Admit` — the other eight belong to units this crate is not); `reason` is
/// the stable machine-readable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// The step the refusal happened at.
    pub step: RefusalStep,
    /// The stable reason code.
    pub reason: ReasonCode,
}

impl Refusal {
    /// Build a refusal.
    pub const fn new(step: RefusalStep, reason: ReasonCode) -> Self {
        Refusal { step, reason }
    }
}

/// The step a refusal is attributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalStep {
    /// The maker-checker approval step.
    Approve,
    /// The admission step (scope, posture, rate limit, replay).
    Admit,
    /// The verb executed but its own domain rule (a missing group, a bad state) refused it.
    Verify,
}

/// The stable reason codes this crate returns. Additive-only, matching the architecture document's
/// own vocabulary rather than inventing a parallel one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// `set_dual_control(required)` needs at least two distinct admin principals.
    InsufficientApprovers,
    /// An `approve` whose approver is the same principal as the maker.
    SelfApproval,
    /// A payload hash on `approve` that does not equal the pending mutation's.
    PayloadMismatch,
    /// An irreducible verb other than `set_operator_key`/`export_keyset`, called while
    /// `operator: unset`.
    OperatorUnset,
    /// A mutating verb called under `required` posture with no matching `approve` yet.
    ApprovalPending,
    /// The caller's scope does not satisfy the verb's required scope.
    Unauthorized,
    /// An `Idempotency-Key` header names an in-flight reservation (same actor, same key).
    IdempotencyInFlight,
    /// The per-principal mutation rate budget for this verb's class is exhausted for the window.
    RateLimited,
    /// The named resource does not exist.
    NotFound,
    /// The request conflicts with existing state (a re-home, a duplicate, a state mismatch).
    Conflict,
    /// The request body/arguments failed validation.
    Validation,
    /// A store/governance call returned an error the caller must fail closed on.
    StoreError,
    /// Anything else — logged, never detailed to the caller (secrets may be in scope for a verb
    /// call, so an internal error never echoes its cause).
    Internal,
}
