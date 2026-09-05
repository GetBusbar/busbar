// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ten steps of the loop, as type-level markers, and the facts each step hands the next.
//!
//! The design names ten steps and fixes their order: arrival, decode, authenticate, verify,
//! approve, admit, route, meter, audit, encode. Three of them — arrival, decode and encode — are
//! the kernel's own work and their tokens are never lent to a unit; the other seven each belong to
//! exactly one unit.
//!
//! The marker types exist so the ORDER is carried by types instead of by discipline. A unit asked
//! to answer one step is handed the token for that step and can only build the answer for that
//! step, so it can neither reply to a question it was not asked nor skip ahead to a later one.

use crate::{Admission, Usage, VerifiedDestination};

/// The seal on [`Step`]. Only the ten markers declared in this module implement it, so nothing
/// outside can invent an eleventh step or a private marker that would mint tokens of its own.
mod sealed {
    /// The private supertrait no downstream type can name, and therefore cannot implement.
    pub trait Sealed {}
}

/// One step of the loop, as a zero-sized type-level marker.
///
/// `Facts` is what a successful pass through this step hands to the next one; `NAME` is the same
/// step as a plain runtime value, for refusals and audit rows; `KERNEL_OWNED` says whether the
/// token for this step is ever lent out at all.
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
    ///
    /// A refusal here is audited WITH the hold: the admission stands and the caller was charged.
    /// A refusal at or before the door is audited without one, because nothing was charged.
    pub fn under_hold(self) -> bool {
        self > StepName::Admit
    }

    /// Whether the kernel keeps this step's token to itself.
    pub fn kernel_owned(self) -> bool {
        matches!(
            self,
            StepName::Arrival | StepName::Decode | StepName::Encode
        )
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

macro_rules! step_marker {
    ($(#[$doc:meta])* $name:ident, $facts:ty, $kernel:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Step for $name {
            type Facts = $facts;
            const NAME: StepName = StepName::$name;
            const KERNEL_OWNED: bool = $kernel;
        }
    };
}

step_marker!(
    /// Step 0 — the transport-level facts of a connection, read before any plane is known.
    Arrival,
    ArrivalFacts,
    true
);
step_marker!(
    /// Step 0b — the plane says what shape arrived: a draft unit, a frame, a close, a discard.
    Decode,
    DecodeFacts,
    true
);
step_marker!(
    /// Step 1 — who is calling.
    Authenticate,
    Principal,
    false
);
step_marker!(
    /// Step 2 — where the unit may go: the sealed set of destinations, before anything is charged.
    Verify,
    Vec<VerifiedDestination>,
    false
);
step_marker!(
    /// Step 3 — whether the caller may do this at all.
    Approve,
    ScopeFacts,
    false
);
step_marker!(
    /// Step 4 — the door. A pass yields either the unit's own hold or an accrual into a parent's.
    Admit,
    Admission,
    false
);
step_marker!(
    /// Step 5 — dial, send, relay, all under the hold.
    Route,
    RouteFacts,
    false
);
step_marker!(
    /// Step 6 — what the unit actually cost, folded from what the legs reported.
    Meter,
    Usage,
    false
);
step_marker!(
    /// Step 7 — how the unit ended, sealed for the record.
    Audit,
    AuditFacts,
    false
);
step_marker!(
    /// Step 8 — the bytes that leave. The kernel's own step; no unit is asked.
    Encode,
    EncodeFacts,
    true
);

// contract: every placeholder below stands in for a type the contract crate owns. They are declared
// here only so the step markers have a `Facts` type to name while the two crates land side by side;
// the integrator replaces each one with the contract's own and deletes it from this module.

/// Placeholder for the arrival record — source, port, ALPN, SNI, peer certificate, transport chain.
// contract: ArrivalRecord
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArrivalFacts;

/// Placeholder for what decode produced — the draft unit, or the frame/close/discard verdict.
// contract: Ingress / Progress / UnitDraft
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeFacts;

/// Placeholder for the scope facts approve reads — the resource locators the plane pointed at.
// contract: ScopeFacts
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeFacts;

/// Placeholder for what route produced — the legs walked and what came back from each.
// contract: RoutePlan / leg results
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteFacts;

/// Placeholder for the audit facts the plane supplies — its operation class and its finish class.
// contract: AuditFacts
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditFacts;

/// Placeholder for what encode produced — the framed bytes handed back to the transport.
// contract: encoded frame
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodeFacts;

/// The caller, as authenticate resolved them.
///
/// Only the identity is modelled here, because that is the one thing a capability type needs: an
/// accrual into a parent unit's hold is refused unless the two principals are the same.
// contract: Principal (the full credential facts live in the contract crate)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal(String);

impl Principal {
    /// Name a principal.
    pub fn new(id: impl Into<String>) -> Self {
        Principal(id.into())
    }

    /// The principal's identity as the journal spells it.
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// Placeholder for the priced axis a destination sits on.
// contract: LaneId
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaneId(String);

impl LaneId {
    /// Name a lane.
    pub fn new(id: impl Into<String>) -> Self {
        LaneId(id.into())
    }

    /// The lane's configured name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Placeholder for a declared meter class — the open key a usage line is reported against.
// contract: MeterClassId
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeterClassId(String);

impl MeterClassId {
    /// Name a meter class.
    pub fn new(id: impl Into<String>) -> Self {
        MeterClassId(id.into())
    }

    /// The class's declared name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Placeholder for the kernel's per-unit key.
// contract: the unit key on `Unit`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnitKey(u64);

impl UnitKey {
    /// Name a unit.
    pub fn new(key: u64) -> Self {
        UnitKey(key)
    }

    /// The key as the journal writes it.
    pub fn get(self) -> u64 {
        self.0
    }
}
