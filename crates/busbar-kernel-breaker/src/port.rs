// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The disposition-plus-outcome answer the egress unit's `Breaker::classify` port needs, and the

use crate::classify::{self, Disposition, Reading, WireFault};
use crate::Outcome;

/// One upstream answer, as this unit classifies it: the [`Reading`] and the wait the upstream asked
/// for on the answer, in whole seconds, where it asked for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// What the breaker knows about the answer.
    pub reading: Reading,
    /// The upstream's requested wait, in whole seconds, where it asked for one.
    pub retry_after: Option<u64>,
}

/// What the classifier made of one upstream answer: where the caller sends the request next, what
/// this unit's own state machine should be told, and the metric label for the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    /// Where the caller sends the request next.
    pub disposition: Disposition,
    /// What [`crate::Breaker::observe`] should be told.
    pub outcome: Outcome,
    /// The metric label for this failure.
    pub label: &'static str,
}

/// The metric label literals, read off the contract's disposition table — the same rows the egress

pub mod label {
    use busbar_contract::upstream::Disposition;
    /// A transient upstream failure.
    pub const TRANSIENT_UPSTREAM: &str = Disposition::TransientUpstream.label();
    /// A definitive signal about the shared destination.
    pub const HARD_DOWN: &str = Disposition::HardDown.label();
    /// The request was too large for this destination's window.
    pub const CONTEXT_LENGTH: &str = Disposition::ContextLength.label();
    /// The caller's own fault. Never read as a telemetry label by the reference caller (a

    pub const CLIENT_FAULT: &str = Disposition::ClientFault.label();
    /// A healthy destination's answer, recorded as a success. Never a failure's label: a

    pub const HEALTHY: &str = "healthy";
}

/// Fold a classified [`Disposition`] into the [`Outcome`] this unit's state machine acts on and the

#[must_use]
pub fn outcome_and_label(
    disposition: Disposition,
    retry_after: Option<u64>,
) -> (Outcome, &'static str) {
    match disposition {
        Disposition::ClientFault => (Outcome::RecordNothing, label::CLIENT_FAULT),

        Disposition::TransientUpstream => (
            Outcome::Transient { retry_after },
            label::TRANSIENT_UPSTREAM,
        ),

        Disposition::HardDown => (Outcome::HardDown, label::HARD_DOWN),

        Disposition::ContextLength => (Outcome::RecordNothing, label::CONTEXT_LENGTH),
    }
}

/// Classify one upstream answer and fold it straight through to the [`Outcome`] and label a caller

#[must_use]
pub fn classify_upstream(status: UpstreamStatus) -> Classified {
    let disposition = classify::classify(status.reading);

    let (outcome, label) = if status.reading == Reading::Answered(Some(WireFault::Healthy)) {
        (Outcome::Success, label::HEALTHY)
    } else {
        outcome_and_label(disposition, status.retry_after)
    };
    Classified {
        disposition,
        outcome,
        label,
    }
}

#[cfg(test)]
#[path = "tests/port.rs"]
mod tests;
