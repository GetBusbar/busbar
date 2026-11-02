// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ten steps of the loop, as type-level markers, and the facts each step hands the next.

use crate::caps::{Admission, Usage, VerifiedDestination};

/// The seal on [`Step`]. Only the ten markers declared in this module implement it, so nothing
mod sealed {
    /// The private supertrait no downstream type can name, and therefore cannot implement.
    pub trait Sealed {}
}

/// One step of the loop, as a zero-sized type-level marker.
pub trait Step: sealed::Sealed + Send + Sync + 'static {
    /// What a "proceed" answer for this step carries forward.
    type Facts: Send + 'static;
    /// The step as a runtime name.
    const NAME: StepName;
    /// Whether the kernel keeps this step's token to itself (arrival, decode and encode).
    const KERNEL_OWNED: bool;
}

/// The ten steps as plain runtime names, in loop order.
///
/// Ordered so that "did this happen while a hold was open" is a comparison rather than a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepName {
    /// The kernel's gate: size, rate, source and the budgets, before any plane is known.
    Arrival,
    /// The kernel asks the plane to recognise the shape of what arrived.
    Decode,
    /// The auth unit resolves who is calling.
    Authenticate,
    /// The trust unit judges where the unit may go.
    Verify,
    /// The scope unit judges whether the caller may do it.
    Approve,
    /// The door. A pass opens the unit's hold.
    Admit,
    /// Runs under the hold: the egress unit dials and relays.
    Route,
    /// Runs under the hold: the usage unit reads what the unit actually cost.
    Meter,
    /// Runs under the hold: the audit unit seals how the unit ended.
    Audit,
    /// The kernel's last word: the bytes the client sees.
    Encode,
}

impl StepName {
    /// Every step, in the order the loop runs them.
    pub const ALL: [StepName; 10] = [
        StepName::Arrival,
        StepName::Decode,
        StepName::Authenticate,
        StepName::Verify,
        StepName::Approve,
        StepName::Admit,
        StepName::Route,
        StepName::Meter,
        StepName::Audit,
        StepName::Encode,
    ];

    /// Whether a hold is open at this step — strictly after the door.
    pub fn under_hold(self) -> bool {
        self > StepName::Admit
    }

    /// The step as it appears in refusals and audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            StepName::Arrival => "arrival",
            StepName::Decode => "decode",
            StepName::Authenticate => "authenticate",
            StepName::Verify => "verify",
            StepName::Approve => "approve",
            StepName::Admit => "admit",
            StepName::Route => "route",
            StepName::Meter => "meter",
            StepName::Audit => "audit",
            StepName::Encode => "encode",
        }
    }
}

impl std::fmt::Display for StepName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

macro_rules! step_markers {
    ($($(#[$doc:meta])* $name:ident => $facts:ty, $kernel:expr;)*) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $name;

            impl sealed::Sealed for $name {}

            impl Step for $name {
                type Facts = $facts;
                const NAME: StepName = StepName::$name;
                const KERNEL_OWNED: bool = $kernel;
            }
        )*
    };
}

step_markers! {
    /// Step 0 — the transport-level facts of a connection, read before any plane is known.
    Arrival => ArrivalRecord, true;
    /// Step 0b — the plane says what shape arrived: a draft unit, a frame, a close, a discard.
    Decode => OpClassId, true;
    /// Step 1 — who is calling, or one more round before that can be said.
    Authenticate => Authenticated, false;
    /// Step 2 — where the unit may go: the sealed set of destinations, before anything is charged.
    Verify => Vec<VerifiedDestination>, false;
    /// Step 3 — whether the caller may do this at all.
    Approve => ScopeFacts, false;
    /// Step 4 — the door. A pass yields either the unit's own hold or an accrual into a parent's.
    Admit => Admission, false;
    /// Step 5 — dial, send, relay, all under the hold.
    Route => RoutePlan, false;
    /// Step 6 — what the unit actually cost, folded from what the legs reported.
    Meter => Usage, false;
    /// Step 7 — how the unit ended, sealed for the record.
    Audit => AuditFacts, false;
    /// Step 8 — the bytes that leave. The kernel's own step; no unit is asked.
    Encode => Frame, true;
}

pub use crate::{
    ArrivalRecord, AuditFacts, Challenge, Frame, LaneId, MeterClassId, OpClassId, PrincipalId,
    RoutePlan, ScopeFacts, UnitKey,
};

/// What passing the authenticate step carries forward.
///
/// Two arms, because a challenge is not a decision about this unit — it is a request for one more
/// round before a decision can be made. The design says the step's answer may yield a challenge,
/// and this is where it does: the decision stays two-armed (proceed or refuse) and it is the FACTS
/// that are either an identity or another round, so no other step gains an arm it has no use for.
///
/// The kernel delivers a challenge as the handshake unit's delivery leg and asks the unit again
/// when the proof arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authenticated {
    /// Established: this is who is calling.
    Principal(PrincipalId),
    /// Not yet: deliver this and ask again.
    Challenge(Challenge),
}

impl Authenticated {
    /// The principal, where the step settled on one.
    #[must_use]
    pub fn principal(&self) -> Option<&PrincipalId> {
        match self {
            Self::Principal(p) => Some(p),
            Self::Challenge(_) => None,
        }
    }
}
