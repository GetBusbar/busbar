// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The refusal codes and the facts the teller's steps seal.

use crate::bounded::{BoundedVec, MAX_USAGE_LINES};
use crate::ids::OpClassId;

/// The closed reason codes a refusal may carry.
///
/// These are opaque to a client: the wire rendering is the dialect's, and the code is what the
/// journal and the exceptions report read. Adding one is a kernel change, because every code has
/// to have a settlement row.
///
/// This is the contract-side spelling of the kernel's own reason vocabulary (`busbar-caps`'s
/// `ReasonCode`), and there is exactly one bridge between them: `impl From<ReasonCode> for
/// RefusalReason`, which is exhaustive on the kernel side. Every reason the kernel can stop a unit
/// for therefore has a spelling here, and no two of them share one — a reason with no spelling
/// would reach a client as some other refusal, which is worse than reaching it as an unfamiliar
/// one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RefusalReason {
    /// The in-flight table is full.
    InFlightCap,
    /// The per-connection read cursor ceiling was reached.
    CursorBudget,
    /// The per-connection credential slab was too small for the located span.
    CredentialBudget,
    /// The node-global session budget was reached.
    SessionBudget,
    /// The request body was larger than configuration allows.
    BodyTooLarge,
    /// A second open unit was offered on a direction that already has one.
    OpenSlotBusy,
    /// The plane narrowed to a scheme its claim does not declare.
    SchemeNotDeclared,
    /// The credential did not verify.
    CredentialRejected,
    /// The session is not bound, so a session-carried credential cannot be used.
    SessionUnbound,
    /// The principal's authority was withdrawn.
    Revoked,
    /// The principal lacks the scope this operation requires.
    ScopeMissing,
    /// A gate hook vetoed the unit.
    Vetoed,
    /// The verified set is empty.
    NoDestination,
    /// The principal is over a money cap.
    OverBudget,
    /// The principal's group is frozen.
    GroupFrozen,
    /// A meter class this unit would consume has no price and none is allowed.
    Unpriced,
    /// The overdraft ceiling was reached.
    OverdraftCeiling,
    /// The node's slice of a bucket window is out of date.
    StaleSlice,
    /// The journal cannot be written, so nothing may be admitted.
    DurabilityUnavailable,
    /// The chain's buckets disagree on the tier multiplier.
    TierMismatch,
    /// The node-global body-spill budget was reached.
    SpillBudget,
    /// The per-call scratch pad hit its abuse ceiling.
    ScratchExhausted,
    /// The source is over its arrival rate.
    RateLimited,
    /// The plane could not make sense of the bytes.
    DecodeFailed,
    /// A challenge-response exchange ran past its round or byte bound.
    ChallengeExhausted,
    /// The principal may not reach the pool it named at all. Answered before pricing, and distinct
    /// from a plain scope denial, so the two do not become one refusal in the record.
    PoolNotPermitted,
    /// The name the caller supplied has no configured rate: nothing is wrong with the caller's
    /// budget, the name simply cannot be billed.
    NoRate,
    /// The idempotency key was already used; the earlier answer is replayed.
    Replayed,
    /// The idempotency key belongs to a unit still in flight.
    InFlight,
    /// The destination spent its lifetime request budget.
    DestinationBudgetExhausted,
    /// The circuit breaker for the destination is open.
    BreakerOpen,
    /// The destination could not be reached.
    DestinationUnreachable,
    /// Two evidence sources for the same unit disagree about what it consumed.
    MeterDisputed,
    /// Two legs of a handoff did not agree on what they were doing.
    HandoffMismatch,
    /// A plane call panicked.
    PlanePanic,
    /// The task running the unit disappeared without an end.
    TaskLost,
    /// The unit made no progress within its deadline.
    Stalled,
    /// A minted secret's placeholder did not appear exactly once at its declared location.
    SecretPlaceholder,
    /// The node is draining.
    Drain,
    /// A later unit superseded this one.
    Superseded,
    /// The client went away.
    ClientGone,
    /// The unit ran past its maximum duration.
    DeadlineExceeded,
    /// The counterparty or capability the unit rests on is not trusted (the kernel's Approve).
    Untrusted,
    /// The member's own credential, re-resolved for this request, is unavailable.
    CredentialUnavailable,
    /// The request's method is one no route at its path takes.
    MethodNotAllowed,
    /// The node failed in a way it names to no caller.
    Internal,
}

/// How a plane says a response ended.
///
/// This is the second source for the fee decision. Where it and the transport's status class
/// disagree, the ledger posts the lower evidence and flags the dispute; it never silently prefers
/// the house's reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum FinishClass {
    /// The whole answer arrived.
    Complete,
    /// One turn of a duplex exchange ended; the session continues.
    TurnComplete,
    /// The answer was cut short.
    Partial,
    /// The upstream reported an error.
    Error,
}

/// What the audit step seals about a unit.
///
/// The operation class here is checked against the one the draft declared, because the draft's is
/// the one that priced the unit; a difference is a dispute, not a re-price.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AuditFacts {
    /// The operation class the plane says this unit was.
    pub op_class: OpClassId,
    /// How the plane says it ended.
    pub finish: FinishClass,
}

/// One resource a principal must hold scope over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ResourceLocator {
    /// The kind of resource, in the plane's own vocabulary.
    pub kind: &'static str,
    /// Which one.
    pub name: &'static str,
}

/// What a plane offers the approve step: resource locators, and nothing else.
///
/// Not a decision, not a scope, not an amount. The scope unit reads the required scope out of
/// policy and compares it against the principal; the plane only says what is being asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeFacts {
    /// The resources this unit touches.
    pub resources: BoundedVec<ResourceLocator, MAX_USAGE_LINES>,
}
