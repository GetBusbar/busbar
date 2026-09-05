// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-caps — the capability types, and the tokens that seal them
//!
//! Everything here is one idea: a value whose existence IS a permission. A hold exists only
//! because the door said yes; a posting only because the ledger settled a hold; none can be built
//! by saying "make me one" — each constructor demands a token, handed out by the loop to one unit
//! for the length of one step call. That is "sealed by token, not by visibility": a `pub(crate)`
//! constructor only keeps out other crates, a token keeps out everyone who is not, at this
//! instant, the unit entitled to act. See `docs/design/contract-notes.md` for the longer version.
//!
//! ## What is in here
//!
//! - The [ten steps](step) as type-level markers, sealed so no eleventh can be invented.
//! - The [tokens](token): one per unit, plus the kernel's own.
//! - [`Decision<S>`] — a step's answer, buildable only with the token for that same step.
//! - [`Hold`], [`HoldCell`], [`HoldAccrual`] — the reservation, the slot it lives in, and a child's
//!   spend against a parent's.
//! - [`Posted`], [`DurabilityLost`], [`Usage`] — what closes a hold, and what it is closed against.
//! - [`VerifiedDestination`], [`AuthDecoration`], [`SecretSlot`], [`TransportKeyHandle`],
//!   [`SecretOnce`] — the capabilities on the way out.
//! - [`Origin`], [`SessionId`], [`IdempotencyKey`], [`UnitEnd`] — the kernel's own.
//! - The [canary] the kernel balances.
//!
//! The rules Rust cannot carry are written down as data in `fixtures/lint_rules.rs`, next to the
//! crate rather than inside it, because nothing that uses this crate ever names them.
//!
//! ## What Rust actually enforces here, honestly
//!
//! Three columns, because conflating them is how a system ends up believing in a guarantee nobody
//! implemented.
//!
//! | Property | How | When |
//! |---|---|---|
//! | A unit cannot answer a step it was not asked | the token names the step and so does the answer | compile-time |
//! | A unit cannot skip a step | a step's facts are the next step's input, and only a decision produces them | compile-time |
//! | A unit cannot read back its own answer | opening a decision needs the kernel's seal | compile-time |
//! | No one but the admission unit opens a hold | `Hold::open` demands an `AdmitToken` | compile-time |
//! | No one but the ledger settles one | `Posted::settle` demands a `LedgerToken` and takes the hold by value | compile-time |
//! | A hold is settled at most once | settling consumes the hold; there is no second one to settle | compile-time |
//! | A hold cannot cross a `catch_unwind` | a hold is deliberately not unwind-safe | compile-time |
//! | A hold cannot be duplicated | no `Clone`, no `Copy` | compile-time |
//! | A token cannot be kept or copied | no `Clone`, no `Copy`, lent by reference | compile-time |
//! | Only ten steps exist | the `Step` trait is sealed on a private supertrait | compile-time |
//! | A hold is taken from its cell exactly once | the cell is a state machine, transitions under a lock | runtime |
//! | Two holds never enter one cell | the second offer is refused and handed back | runtime |
//! | A child's accrual belongs to its parent | the cell checks state and principal | runtime |
//! | A hold accidentally dropped is caught | `#[must_use]`, denied as a lint in the kernel | compile-time (lint) |
//! | A hold DELIBERATELY forgotten, leaked or `ManuallyDrop`ped is caught | source scan over the hold-escape list in `fixtures/lint_rules.rs` | CI |
//! | Only the kernel mints tokens | one audited symbol, [`KernelSeal::acquire_for_kernel`] | CI |
//! | The recovery token stays in the recovery module | source scan over the seal-site list, same file | CI |
//! | There are exactly two take sites | source scan, plus a fixture | CI |
//! | Every unit that was admitted actually settled | the two-sided [`canary::Canary`] | runtime + CI |
//!
//! The row that matters most is the one that is NOT compile-time: Rust has no linear types, so
//! "this value must be consumed by exactly this function" cannot be said. `#[must_use]` catches the
//! accident, the cell catches the double, the canary catches the omission, and the scan catches the
//! deliberate. Four partial mechanisms, stated as four, rather than one guarantee that is not real.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod canary;
pub mod decision;
pub mod egress;
pub mod hold;
pub mod step;
pub mod token;
pub mod unit_end;
pub mod usage;

pub use canary::{Canary, CanaryBreak};
pub use decision::{Decision, ReasonCode, Refusal};
pub use egress::{AuthDecoration, SecretOnce, SecretSlot, TransportKeyHandle, VerifiedDestination};
pub use hold::{
    Accrual, AccrualRefused, Admission, AdmitRejected, CellError, DurabilityLost, Hold,
    HoldAccrual, HoldCell, HoldCellState, Posted, PostingFlags,
};
pub use step::{
    Admit, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate, Authenticated,
    Challenge, Decode, Encode, Frame, LaneId, Meter, MeterClassId, OpClassId, PrincipalId, Route,
    RoutePlan, ScopeFacts, Step, StepName, UnitKey, Verify,
};
pub use token::{
    AdminToken, AdmitToken, DurabilityToken, EgressAuthToken, ExitToken, KernelSeal, LedgerToken,
    RecoveryToken, TransportKeyToken, TrustToken, UnitToken, UsageToken,
};
pub use unit_end::{Abort, IdempotencyKey, Origin, OriginKind, Outcome, SessionId, UnitEnd};
pub use usage::{LocatorPtr, QuantitySource, Usage, UsageError, UsageLine, MAX_USAGE_LINES};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
