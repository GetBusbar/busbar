// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-caps — the capability types, and the tokens that seal them

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(missing_debug_implementations)]

pub mod capability;
pub mod egress;
pub mod hold;
pub mod seat_verdict;
pub mod step;
pub mod token;
pub mod unit_end;
pub mod usage;

pub use capability::{
    AdminVerb, Admittance, Capability, Consumption, Dial, DurableWrite, Exit, KeyHandle, Sign,
    WriteMoney,
};
pub use egress::{TransportKeyHandle, VerifiedDestination};
pub use hold::{
    AccrualPrepareError, AccrualRefused, Admission, AdmitRejected, CellError, DurabilityLost, Hold,
    HoldAccrual, HoldCell, HoldCellState, Posted, PostingFlags,
};
pub use seat_verdict::{ReasonCode, Refusal, SeatVerdict};
pub use step::{
    Admit, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate, Authenticated,
    Challenge, Decode, Encode, Frame, LaneId, Meter, MeterClassId, OpClassId, PrincipalId, Route,
    RoutePlan, ScopeFacts, Step, StepName, UnitKey, Verify,
};
pub use token::{CallId, Grant, KernelSeal, Pass};
pub use unit_end::{Abort, IdempotencyKey, Origin, OriginKind, Outcome, SessionId, UnitEnd};
pub use usage::{LocatorPtr, QuantitySource, Usage, UsageError, UsageLine, MAX_USAGE_LINES};

#[cfg(test)]
mod tests;
