// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod validate;

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

pub mod section;

pub mod book;

pub(crate) mod demotion;
pub use demotion::DemotionRecord;

pub mod signed;
