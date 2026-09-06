// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A step's answer, and the closed vocabulary of reasons a unit can be stopped for.
//!
//! # What a unit cannot do with the token it was lent
//!
//! It cannot answer a step it was not asked. The token names the step; so does the answer:
//!
//! ```compile_fail,E0308
//! use busbar_caps::{Admit, Admission, Decision, Meter, UnitToken};
//!
//! fn forge(token: &UnitToken<Meter>) -> Decision<Admit> {
//!     // The token is for the meter step; the decision it builds is a meter decision.
//!     Decision::proceed(token, Admission::ZeroHold)
//! }
//! ```
//!
//! The same call with the meter's own answer type compiles, so the fixture above fails for the one
//! reason it is meant to and not because something was misspelled:
//!
//! ```
//! use busbar_caps::{Decision, KernelSeal, Meter, Usage, UnitToken, UsageToken};
//! let seal = KernelSeal::acquire_for_kernel();
//! let token: UnitToken<Meter> = UnitToken::mint(&seal);
//! let usage = Usage::report(&UsageToken::mint(&seal), Vec::new()).unwrap();
//! let decision: Decision<Meter> = Decision::proceed(&token, usage);
//! assert_eq!(decision.into_result(&seal).unwrap().total(), 0);
//! ```
//!
//! The reason vocabulary is closed, and closed means a crate that renders reasons can decide
//! something for every one of them without a fallback arm — so a reason added later is a compile
//! error at every renderer rather than whatever the wildcard happened to say:
//!
//! ```
//! use busbar_caps::ReasonCode::{self, *};
//! fn is_the_callers_money(code: ReasonCode) -> bool {
//!     match code {
//!         OverBudget | OverdraftCeiling | Unpriced | NoRate => true,
//!         InFlightCap | CursorBudget | CredentialBudget | SessionBudget | SpillBudget
//!         | ArenaBudget | RateLimited | BodyTooLarge | OpenSlotBusy | DecodeFailed
//!         | SchemeNotDeclared | SessionUnbound | Unauthenticated | ChallengeExhausted | Revoked
//!         | ScopeDenied | PoolNotPermitted | HookVeto | NoDestination | GroupFrozen
//!         | StaleSlice | DurabilityUnavailable | TierMismatch | Replayed | InFlight
//!         | DestinationBudgetExhausted | BreakerOpen | DestinationUnreachable | MeterDisputed
//!         | HandoffMismatch | PlanePanic | TaskLost | Stalled | SecretPlaceholder | Drain
//!         | Superseded | ClientGone | DeadlineExceeded => false,
//!     }
//! }
//! assert!(is_the_callers_money(ReasonCode::OverBudget));
//! assert!(!is_the_callers_money(ReasonCode::Drain));
//! ```
//!
//! It cannot open its own answer, because reading a decision needs the kernel's seal:
//!
//! ```compile_fail,E0061
//! use busbar_caps::{Decision, Verify};
//!
//! fn peek(d: Decision<Verify>) {
//!     let _ = d.into_result();
//! }
//! ```

use crate::step::{Step, StepName};
use crate::token::{KernelSeal, UnitToken};

macro_rules! reasons {
    ($($(#[$doc:meta])* $name:ident => $wire:literal,)*) => {
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
        }
    };
}

reasons! {
    /// The in-flight table is full.
    InFlightCap => "in_flight_cap",
    /// The node-global connection-cursor budget is exhausted.
    CursorBudget => "cursor_budget",
    /// The per-connection credential slab could not hold the credential span.
    CredentialBudget => "credential_budget",
    /// The node-global session budget is exhausted.
    SessionBudget => "session_budget",
    /// The node-global body-spill budget is exhausted.
    SpillBudget => "spill_budget",
    /// The per-unit arena is exhausted.
    ArenaBudget => "arena_budget",
    /// The source is over its arrival rate.
    RateLimited => "rate_limited",
    /// The request body is larger than the configured maximum.
    BodyTooLarge => "body_too_large",
    /// The direction already has an open unit.
    OpenSlotBusy => "open_slot_busy",
    /// The plane could not make sense of the bytes.
    DecodeFailed => "decode_failed",
    /// The plane narrowed to an auth scheme its claim never declared.
    SchemeNotDeclared => "scheme_not_declared",
    /// The session is unbound, so a credential cannot be taken from it.
    SessionUnbound => "session_unbound",
    /// No credential resolved to a principal.
    Unauthenticated => "unauthenticated",
    /// The challenge exchange ran past its round or byte bound.
    ChallengeExhausted => "challenge_exhausted",
    /// The credential was revoked.
    Revoked => "revoked",
    /// The principal lacks the scope the operation requires.
    ScopeDenied => "scope_denied",
    /// The principal is not permitted to reach the pool it named. Distinct from a plain scope
    /// denial: the ladder answers this one before it asks about pricing at all, and the two carry
    /// different statuses on the wire, so collapsing them would make two refusals indistinguishable
    /// to anything reading the record.
    PoolNotPermitted => "pool_not_permitted",
    /// The name the caller supplied has no configured rate. A bad request rather than an exhausted
    /// one: nothing is wrong with the caller's budget, the name simply cannot be billed. Modelled
    /// as its own reason rather than as the absence of a gate, so the record can say which of the
    /// two a refusal was.
    NoRate => "no_rate",
    /// A hook vetoed the unit.
    HookVeto => "hook_veto",
    /// No destination survived verification.
    NoDestination => "no_destination",
    /// A budget in the principal's chain has no headroom.
    OverBudget => "over_budget",
    /// The principal's group is frozen.
    GroupFrozen => "group_frozen",
    /// A meter class the present rate card does not price.
    Unpriced => "unpriced",
    /// The overdraft ceiling on a capped bucket is reached.
    OverdraftCeiling => "overdraft_ceiling",
    /// The node's slice of the bucket window is behind the current epoch.
    StaleSlice => "stale_slice",
    /// The journal cannot be written durably.
    DurabilityUnavailable => "durability_unavailable",
    /// Two buckets in one chain disagree about the tier multiplier.
    TierMismatch => "tier_mismatch",
    /// The idempotency key was already used; the earlier answer is replayed.
    Replayed => "replayed",
    /// The idempotency key belongs to a unit still in flight.
    InFlight => "in_flight",
    /// The destination spent its lifetime request budget.
    DestinationBudgetExhausted => "destination_budget_exhausted",
    /// The circuit breaker for the destination is open.
    BreakerOpen => "breaker_open",
    /// The destination could not be reached.
    DestinationUnreachable => "destination_unreachable",
    /// Two evidence sources for the same unit disagree.
    MeterDisputed => "meter_disputed",
    /// A layer offered a handoff the layer adopting it does not compose over, or handed up a stream
    /// it cannot adopt. Its own reason rather than a framing failure: nothing was wrong with the
    /// bytes, the two legs simply did not agree on what they were doing.
    HandoffMismatch => "handoff_mismatch",
    /// A plane call panicked.
    PlanePanic => "plane_panic",
    /// The task running the unit disappeared without an end.
    TaskLost => "task_lost",
    /// The unit made no progress within its deadline.
    Stalled => "stalled",
    /// A minted secret placeholder did not appear exactly once at its declared location.
    SecretPlaceholder => "secret_placeholder",
    /// The node is draining.
    Drain => "drain",
    /// A later unit superseded this one.
    Superseded => "superseded",
    /// The client went away.
    ClientGone => "client_gone",
    /// The unit ran past its maximum duration.
    DeadlineExceeded => "deadline_exceeded",
}

/// The one bridge from the kernel's reason vocabulary to the contract's spelling of it.
///
/// The kernel decides in `ReasonCode` and the plane is handed a `RefusalReason` to render, so
/// without a written-down join the two sets drift: a reason with no spelling on the far side
/// reaches a client as whatever the nearest arm said, and the same reason spelled two ways on the
/// two sides is the same defect wearing a different name. The match is exhaustive and has no
/// fallback arm, so a reason added to the vocabulary above does not compile until a client can be
/// told about it, and `busbar-caps`'s own tests walk `ReasonCode::ALL` to check the mapping is
/// injective — two reasons that render as one spelling are two refusals nothing can tell apart.
impl From<ReasonCode> for busbar_contract::unit::RefusalReason {
    fn from(code: ReasonCode) -> Self {
        use busbar_contract::unit::RefusalReason as R;
        match code {
            // The reasons both sides already named, keeping each side's existing spelling: these
            // are what a client sees today, and the wording is not this bridge's to change.
            ReasonCode::InFlightCap => R::InFlightCap,
            ReasonCode::CursorBudget => R::CursorBudget,
            ReasonCode::CredentialBudget => R::CredentialBudget,
            ReasonCode::SessionBudget => R::SessionBudget,
            ReasonCode::BodyTooLarge => R::BodyTooLarge,
            ReasonCode::OpenSlotBusy => R::OpenSlotBusy,
            ReasonCode::SchemeNotDeclared => R::SchemeNotDeclared,
            ReasonCode::SessionUnbound => R::SessionUnbound,
            ReasonCode::Revoked => R::Revoked,
            ReasonCode::NoDestination => R::NoDestination,
            ReasonCode::OverBudget => R::OverBudget,
            ReasonCode::GroupFrozen => R::GroupFrozen,
            ReasonCode::Unpriced => R::Unpriced,
            ReasonCode::OverdraftCeiling => R::OverdraftCeiling,
            ReasonCode::StaleSlice => R::StaleSlice,
            ReasonCode::DurabilityUnavailable => R::DurabilityUnavailable,
            ReasonCode::TierMismatch => R::TierMismatch,
            // The three the two sides named differently. One thing, two spellings, and this is
            // where they are joined rather than in each renderer's head.
            ReasonCode::Unauthenticated => R::CredentialRejected,
            ReasonCode::ScopeDenied => R::ScopeMissing,
            ReasonCode::HookVeto => R::Vetoed,
            // The reasons that had no spelling a client could be shown at all.
            ReasonCode::SpillBudget => R::SpillBudget,
            ReasonCode::ArenaBudget => R::ArenaBudget,
            ReasonCode::RateLimited => R::RateLimited,
            ReasonCode::DecodeFailed => R::DecodeFailed,
            ReasonCode::ChallengeExhausted => R::ChallengeExhausted,
            ReasonCode::PoolNotPermitted => R::PoolNotPermitted,
            ReasonCode::NoRate => R::NoRate,
            ReasonCode::Replayed => R::Replayed,
            ReasonCode::InFlight => R::InFlight,
            ReasonCode::DestinationBudgetExhausted => R::DestinationBudgetExhausted,
            ReasonCode::BreakerOpen => R::BreakerOpen,
            ReasonCode::DestinationUnreachable => R::DestinationUnreachable,
            ReasonCode::MeterDisputed => R::MeterDisputed,
            ReasonCode::HandoffMismatch => R::HandoffMismatch,
            ReasonCode::PlanePanic => R::PlanePanic,
            ReasonCode::TaskLost => R::TaskLost,
            ReasonCode::Stalled => R::Stalled,
            ReasonCode::SecretPlaceholder => R::SecretPlaceholder,
            ReasonCode::Drain => R::Drain,
            ReasonCode::Superseded => R::Superseded,
            ReasonCode::ClientGone => R::ClientGone,
            ReasonCode::DeadlineExceeded => R::DeadlineExceeded,
        }
    }
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
pub struct Decision<S: Step>(Inner<S>);

enum Inner<S: Step> {
    Proceed(S::Facts),
    Refuse(Refusal),
}

impl<S: Step> Decision<S> {
    /// Proceed past step `S`, carrying `facts` to the next step.
    pub fn proceed(_token: &UnitToken<S>, facts: S::Facts) -> Self {
        Decision(Inner::Proceed(facts))
    }

    /// Stop the unit at step `S`. The refusal is stamped with `S`, so the record says where.
    pub fn refuse(_token: &UnitToken<S>, refusal: Refusal) -> Self {
        Decision(Inner::Refuse(refusal.at(S::NAME)))
    }

    /// Open the answer. Only the kernel reads decisions.
    pub fn into_result(self, _seal: &KernelSeal) -> Result<S::Facts, Refusal> {
        match self.0 {
            Inner::Proceed(facts) => Ok(facts),
            Inner::Refuse(refusal) => Err(refusal),
        }
    }
}

impl<S: Step> std::fmt::Debug for Decision<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::Proceed(_) => write!(f, "Decision<{}>::Proceed", S::NAME),
            Inner::Refuse(r) => write!(f, "Decision<{}>::Refuse({})", S::NAME, r.reason),
        }
    }
}
