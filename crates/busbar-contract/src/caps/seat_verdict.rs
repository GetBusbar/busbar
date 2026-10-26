// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A step's answer, and the closed vocabulary of reasons a unit can be stopped for.
//!
//! # What a unit cannot do with the token it was lent
//!
//! It cannot answer a step it was not asked. The token names the step; so does the answer:
//!
//! ```compile_fail,E0308
//! use busbar_contract::caps::{Admit, Admission, SeatVerdict, Meter, Pass};
//!
//! fn forge(token: &Pass<Meter>) -> SeatVerdict<Admit> {
//!     // The token is for the meter step; the decision it builds is a meter decision.
//!     SeatVerdict::proceed(token, Admission::ZeroHold)
//! }
//! ```
//!
//! The same call with the meter's own answer type compiles, so the fixture above fails for the one
//! reason it is meant to and not because something was misspelled:
//!
#![cfg_attr(feature = "test-seal", doc = "```")]
#![cfg_attr(not(feature = "test-seal"), doc = "```ignore")]
//! use busbar_contract::caps::{Consumption, SeatVerdict, Grant, KernelSeal, Meter, Pass, Usage};
//! let seal = KernelSeal::acquire_for_kernel();
//! let token: Pass<Meter> = Pass::mint(&seal);
//! let usage = Usage::report(&Grant::<Consumption>::mint(&seal), Vec::new()).unwrap();
//! let decision: SeatVerdict<Meter> = SeatVerdict::proceed(&token, usage);
//! assert_eq!(decision.into_result(&seal).unwrap().total(), 0);
//! ```
//!
//! The reason vocabulary is closed, and closed means a crate that renders reasons can decide
//! something for every one of them without a fallback arm — so a reason added later is a compile
//! error at every renderer rather than whatever the wildcard happened to say:
//!
//! ```
//! use busbar_contract::caps::ReasonCode::{self, *};
//! fn is_the_callers_money(code: ReasonCode) -> bool {
//!     match code {
//!         OverBudget | OverdraftCeiling | Unpriced | NoRate => true,
//!         InFlightCap | CursorBudget | CredentialBudget | SessionBudget | SpillBudget
//!         | ScratchExhausted | RateLimited | BodyTooLarge | OpenSlotBusy | DecodeFailed
//!         | SchemeNotDeclared | SessionUnbound | Unauthenticated | ChallengeExhausted | Revoked
//!         | ScopeDenied | PoolNotPermitted | HookVeto | NoDestination | GroupFrozen
//!         | StaleSlice | DurabilityUnavailable | TierMismatch | Replayed | InFlight
//!         | DestinationBudgetExhausted | BreakerOpen | DestinationUnreachable | MeterDisputed
//!         | HandoffMismatch | PlanePanic | TaskLost | Stalled | SecretPlaceholder | Drain
//!         | Superseded | ClientGone | DeadlineExceeded | Untrusted
//!         | CredentialUnavailable | MethodNotAllowed | Internal => false,
//!     }
//! }
//! assert!(is_the_callers_money(ReasonCode::OverBudget));
//! assert!(!is_the_callers_money(ReasonCode::Drain));
//! ```
//!
//! It cannot open its own answer, because reading a decision needs the kernel's seal:
//!
//! ```compile_fail,E0061
//! use busbar_contract::caps::{SeatVerdict, Verify};
//!
//! fn peek(d: SeatVerdict<Verify>) {
//!     let _ = d.into_result();
//! }
//! ```

use crate::caps::step::{Step, StepName};
use crate::caps::token::{KernelSeal, Pass};

macro_rules! reasons {
    ($($(#[$doc:meta])* $name:ident => $wire:literal, $refusal:ident, $class:ident,)*) => {
        /// Why a unit was stopped. A closed vocabulary: the wire may render whatever a dialect
        /// renders, but the reason a unit ended is one of these and nothing else, so the journal,
        /// the refusal and the disputes report all name the same thing.
        ///
        /// Closed in the language as well as in the prose: no `#[non_exhaustive]`, because a
        /// renderer outside this crate has to be able to answer for every reason without a
        /// fallback arm. Adding a reason is meant to break every renderer at compile time — that
        /// is the whole value of writing the vocabulary down once.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ReasonCode {
            $($(#[$doc])* $name,)*
        }

        impl ReasonCode {
            /// Every reason, so a test can check no two of them render the same word.
            pub const ALL: &'static [ReasonCode] = &[$(ReasonCode::$name,)*];

            /// The reason as the journal and the refusal both spell it.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(ReasonCode::$name => $wire,)*
                }
            }

            /// THE class of this reason: the table's fourth column, the one reason-to-class
            /// grouping in the tree (`abi::plane::RefusalClass`).
            pub(crate) const fn class(self) -> crate::abi::plane::RefusalClass {
                match self {
                    $(ReasonCode::$name => crate::abi::plane::RefusalClass::$class,)*
                }
            }

            /// This reason's wire code: the wire table names each reason by the reason's own name.
            pub(crate) const fn wire(self) -> crate::abi::plane::RefusalCode {
                match self {
                    $(ReasonCode::$name => crate::abi::plane::RefusalCode::$name,)*
                }
            }

            /// The reason a wire code names; `None` for the walk's `Unsent*` codes alone, which
            /// are no reason of this vocabulary.
            pub(crate) const fn of_wire(code: crate::abi::plane::RefusalCode) -> Option<ReasonCode> {
                use crate::abi::plane::RefusalCode as W;
                match code {
                    $(W::$name => Some(ReasonCode::$name),)*
                    W::UnsentNoAttempt
                    | W::UnsentNoRoute
                    | W::UnsentNeedUnbound
                    | W::UnsentTargetNotPath
                    | W::UnsentFieldName
                    | W::UnsentUnrecorded
                    | W::UnsentAuthFailed
                    | W::UnsentOpenRefused => None,
                }
            }
        }

        // The one bridge from the kernel's reason vocabulary to the contract's spelling of it.
        //
        // The kernel decides in `ReasonCode` and the plane is handed a `RefusalReason` to render,
        // so without a written-down join the two sides drift: a reason with no spelling on the far
        // side reaches a client as whatever the nearest arm said, and the same reason spelled two
        // ways on the two sides is the same defect wearing a different name. The join is the third
        // column of the table above, so a reason added to the vocabulary does not compile until a
        // client can be told about it, and this crate's own tests walk `ReasonCode::ALL` to check
        // the mapping is injective -- two reasons that render as one spelling are two refusals
        // nothing can tell apart.
        impl From<ReasonCode> for crate::unit::RefusalReason {
            fn from(code: ReasonCode) -> Self {
                match code {
                    $(ReasonCode::$name => crate::unit::RefusalReason::$refusal,)*
                }
            }
        }

        // The same join read the other way, so a plane handed a `RefusalReason` can reach the one
        // classification (`abi::plane::RefusalCode::class`) without a reason match of its own.
        impl From<crate::unit::RefusalReason> for ReasonCode {
            fn from(reason: crate::unit::RefusalReason) -> Self {
                match reason {
                    $(crate::unit::RefusalReason::$refusal => ReasonCode::$name,)*
                }
            }
        }
    };
}

// ONE ROW PER REASON: its name, its journal word, its `unit::RefusalReason` spelling, and its
// `abi::plane::RefusalClass`. Its wire code is the `abi::plane::RefusalCode` of the same name.
reasons! {
    /// The in-flight table is full.
    InFlightCap => "in_flight_cap", InFlightCap, Busy,
    /// The node-global connection-cursor budget is exhausted.
    CursorBudget => "cursor_budget", CursorBudget, TooLarge,
    /// The per-connection credential slab could not hold the credential span.
    CredentialBudget => "credential_budget", CredentialBudget, TooLarge,
    /// The node-global session budget is exhausted.
    SessionBudget => "session_budget", SessionBudget, Unavailable,
    /// The node-global body-spill budget is exhausted.
    SpillBudget => "spill_budget", SpillBudget, Unavailable,
    /// The per-call scratch pad hit its abuse ceiling.
    ScratchExhausted => "scratch_exhausted", ScratchExhausted, Unavailable,
    /// The source is over its arrival rate.
    RateLimited => "rate_limited", RateLimited, Throttled,
    /// The request body is larger than the configured maximum.
    BodyTooLarge => "body_too_large", BodyTooLarge, TooLarge,
    /// The direction already has an open unit.
    OpenSlotBusy => "open_slot_busy", OpenSlotBusy, Unavailable,
    /// The plane could not make sense of the bytes.
    DecodeFailed => "decode_failed", DecodeFailed, Unreadable,
    /// The plane narrowed to an auth scheme its claim never declared.
    SchemeNotDeclared => "scheme_not_declared", SchemeNotDeclared, Unauthenticated,
    /// The session is unbound, so a credential cannot be taken from it.
    SessionUnbound => "session_unbound", SessionUnbound, Unauthenticated,
    /// No credential resolved to a principal.
    Unauthenticated => "unauthenticated", CredentialRejected, Unauthenticated,
    /// The challenge exchange ran past its round or byte bound.
    ChallengeExhausted => "challenge_exhausted", ChallengeExhausted, Unauthenticated,
    /// The credential was revoked.
    Revoked => "revoked", Revoked, Unauthenticated,
    /// The principal lacks the scope the operation requires.
    ScopeDenied => "scope_denied", ScopeMissing, Forbidden,
    /// The principal is not permitted to reach the bucket it named. Distinct from a plain scope
    /// denial: the ladder answers this one before it asks about pricing at all, and the two carry
    /// different statuses on the wire, so collapsing them would make two refusals indistinguishable
    /// to anything reading the record.
    PoolNotPermitted => "pool_not_permitted", PoolNotPermitted, Forbidden,
    /// The name the caller supplied has no configured rate. A bad request rather than an exhausted
    /// one: nothing is wrong with the caller's budget, the name simply cannot be billed. Modelled
    /// as its own reason rather than as the absence of a gate, so the record can say which of the
    /// two a refusal was.
    NoRate => "no_rate", NoRate, Rejected,
    /// A hook vetoed the unit.
    HookVeto => "hook_veto", Vetoed, Forbidden,
    /// No destination survived verification.
    NoDestination => "no_destination", NoDestination, NotFound,
    /// A budget in the principal's chain has no headroom.
    OverBudget => "over_budget", OverBudget, QuotaExhausted,
    /// The principal's group is frozen.
    GroupFrozen => "group_frozen", GroupFrozen, Forbidden,
    /// A meter class the present rate card does not price.
    Unpriced => "unpriced", Unpriced, Rejected,
    /// The overdraft ceiling on a capped bucket is reached.
    OverdraftCeiling => "overdraft_ceiling", OverdraftCeiling, Unavailable,
    /// The node's slice of the bucket window is behind the current epoch.
    StaleSlice => "stale_slice", StaleSlice, Unavailable,
    /// The journal cannot be written durably.
    DurabilityUnavailable => "durability_unavailable", DurabilityUnavailable, Unavailable,
    /// Two buckets in one chain disagree about the tier multiplier.
    TierMismatch => "tier_mismatch", TierMismatch, Unavailable,
    /// The idempotency key was already used; the earlier answer is replayed.
    Replayed => "replayed", Replayed, Rejected,
    /// The idempotency key belongs to a unit still in flight.
    InFlight => "in_flight", InFlight, Busy,
    /// The destination spent its lifetime request budget.
    DestinationBudgetExhausted => "destination_budget_exhausted", DestinationBudgetExhausted, Unreachable,
    /// The circuit breaker for the destination is open.
    BreakerOpen => "breaker_open", BreakerOpen, Unreachable,
    /// The destination could not be reached.
    DestinationUnreachable => "destination_unreachable", DestinationUnreachable, Unreachable,
    /// Two evidence sources for the same unit disagree.
    MeterDisputed => "meter_disputed", MeterDisputed, NodeFault,
    /// A layer offered a handoff the layer adopting it does not compose over, or handed up a body
    /// it cannot adopt. Its own reason rather than a framing failure: nothing was wrong with the
    /// bytes, the two legs simply did not agree on what they were doing.
    HandoffMismatch => "handoff_mismatch", HandoffMismatch, NodeFault,
    /// A plane call panicked.
    PlanePanic => "plane_panic", PlanePanic, PlaneFault,
    /// The task running the unit disappeared without an end.
    TaskLost => "task_lost", TaskLost, NodeFault,
    /// The unit made no progress within its deadline.
    Stalled => "stalled", Stalled, Timeout,
    /// A minted secret placeholder did not appear exactly once at its declared location.
    SecretPlaceholder => "secret_placeholder", SecretPlaceholder, NodeFault,
    /// The node is draining.
    Drain => "drain", Drain, Unavailable,
    /// A later unit superseded this one.
    Superseded => "superseded", Superseded, Rejected,
    /// The client went away.
    ClientGone => "client_gone", ClientGone, Unavailable,
    /// The unit ran past its maximum duration.
    DeadlineExceeded => "deadline_exceeded", DeadlineExceeded, Timeout,
    /// The kernel's Approve step judged the trust facts the plane stated and does not trust the
    /// counterparty or capability the unit rests on (trust is the kernel's
    /// Approve step; a plane only states facts).
    Untrusted => "untrusted", Untrusted, Forbidden,
    /// The member's own credential, re-resolved for this request, is unavailable (it no longer
    /// resolves, or its new value would not bind): nothing was dialled.
    CredentialUnavailable => "credential_unavailable", CredentialUnavailable, Unreachable,
    /// The request's method is one no route at its path takes: the kernel's own refusal, decided
    /// before any unit.
    MethodNotAllowed => "method_not_allowed", MethodNotAllowed, Rejected,
    /// The node failed in a way it names to no caller (a request handler panicked): the kernel's
    /// own refusal, decided before any unit.
    Internal => "internal", Internal, NodeFault,
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A unit's "stop here": the reason, and the step it was raised at.
///
/// The step is stamped by the decision, not by the caller, so a unit cannot claim it stopped
/// somewhere it never reached. Until a decision stamps it there is no step, and the refusal says
/// so: an unstamped refusal that named the first step of the loop would be a claim about where the
/// unit got to, and the step is precisely what says whether money was committed before it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    at: Option<StepName>,
    reason: ReasonCode,
    retry_after: Option<u32>,
}

impl Refusal {
    /// Raise a refusal for `reason`. The step is filled in when the refusal becomes a decision.
    pub fn new(reason: ReasonCode) -> Self {
        Refusal {
            at: None,
            reason,
            retry_after: None,
        }
    }

    /// Ask the client to come back after this many seconds.
    pub fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after = Some(seconds);
        self
    }

    /// Stamp the step. Crate-internal: only a decision does this.
    pub(crate) fn at(mut self, at: StepName) -> Self {
        self.at = Some(at);
        self
    }

    /// The step the unit stopped at, once a decision has stamped one.
    pub fn step(&self) -> Option<StepName> {
        self.at
    }

    /// Why it stopped.
    pub fn reason(&self) -> ReasonCode {
        self.reason
    }

    /// The retry hint, if the refusal carries one.
    pub fn retry_after_secs(&self) -> Option<u32> {
        self.retry_after
    }

    /// Whether the refusal was raised while a hold was open. False until a step is stamped: an
    /// unstamped refusal has not reached any step, so it cannot have reached one past the door.
    pub fn under_hold(&self) -> bool {
        self.at.is_some_and(StepName::under_hold)
    }
}

/// A step's answer: proceed with the facts the next step reads, or refuse.
///
/// Built only with the token for the same step; read only by the kernel. Neither `Clone` nor
/// `Copy`, so one token yields one answer, and `#[must_use]`, so an answer cannot be quietly
/// dropped on the way back to the loop.
#[must_use = "a decision that is not returned to the loop silently skips the step"]
pub struct SeatVerdict<S: Step>(Inner<S>);

enum Inner<S: Step> {
    Proceed(S::Facts),
    Refuse(Refusal),
}

impl<S: Step> SeatVerdict<S> {
    /// Proceed past step `S`, carrying `facts` to the next step.
    pub fn proceed(_token: &Pass<S>, facts: S::Facts) -> Self {
        SeatVerdict(Inner::Proceed(facts))
    }

    /// Stop the unit at step `S`. The refusal is stamped with `S`, so the record says where.
    pub fn refuse(_token: &Pass<S>, refusal: Refusal) -> Self {
        SeatVerdict(Inner::Refuse(refusal.at(S::NAME)))
    }

    /// Open the answer. Only the kernel reads decisions.
    pub fn into_result(self, _seal: &KernelSeal) -> Result<S::Facts, Refusal> {
        match self.0 {
            Inner::Proceed(facts) => Ok(facts),
            Inner::Refuse(refusal) => Err(refusal),
        }
    }
}

impl<S: Step> std::fmt::Debug for SeatVerdict<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::Proceed(_) => write!(f, "SeatVerdict<{}>::Proceed", S::NAME),
            Inner::Refuse(r) => write!(f, "SeatVerdict<{}>::Refuse({})", S::NAME, r.reason),
        }
    }
}
