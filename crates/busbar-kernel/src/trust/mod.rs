// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TRUST: the trust keys a plane declares ([`section`]), the per-instance trust state
//! the `trust.*` host services answer from ([`book`]), its re-verification cadence ([`reverify`]),
//! detached-signature judgement against a declared root ([`signed`]), and the identity-and-grant
//! judgement with the standing-permission primitive ([`validate`]).
//!
//! The lifecycle is the kernel's (THE DESIGN §11.12): a plane reports sightings and states the facts
//! a unit rests on, and the kernel decides. No plane, protocol or pin mechanism is named here.

/// THE IDENTITY-AND-GRANT JUDGEMENT, the generation source and the standing-permission primitive.
pub mod validate;

/// THE RE-VERIFICATION CADENCE: when a counterparty is due to be looked at again.
pub mod reverify;

/// The operator-facing trust state word, written once for every caller that renders one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustState {
    /// Nothing approved, so nothing is served.
    Pending,
    /// Approved, and the last sighting agrees. Serves, subject to scope.
    Approved,
    /// Approved, but the last sighting disagrees with what was approved. Refused until the operator
    /// works the drift.
    Quarantined,
    /// Suspended by an operator or by an anomaly control. Outranks every other state.
    Suspended,
    /// The last contact failed. Never serves.
    Error,
}

impl TrustState {
    /// THE WIRE WORD, named once: the string a UI branches on.
    pub fn word(self) -> &'static str {
        match self {
            TrustState::Pending => "pending",
            TrustState::Approved => "approved",
            TrustState::Quarantined => "quarantined",
            TrustState::Suspended => "suspended",
            TrustState::Error => "error",
        }
    }
}

/// THE TRUST KEYS A PLANE DECLARES, parsed and judged by the kernel for every plane alike.
pub mod section;

/// THE KERNEL'S TRUST STATE per instance and counterparty, behind `trust.sight` and `trust.due`.
pub mod book;

/// THE DURABLE DEMOTION RECORD: a live observation that disagreed with the approval, kept across a
/// restart, and the one settle rule. The root attaches it to the kernel's host services.
pub(crate) mod demotion;
pub use demotion::DemotionRecord;

/// A DOCUMENT'S DETACHED SIGNATURES judged against a declared root key, behind `trust.verify`.
pub mod signed;
