// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The disposition-plus-outcome answer the egress unit's `Breaker::classify` port needs, and the
//! pure mapping from a reading of an answer onto it.
//!
//! [`classify`] answers ONLY the disposition. The egress port needs one step further: what the
//! answer means to THIS unit's own state machine (an [`Outcome`]) and the metric label a caller's
//! dashboard reads. That fold is [`outcome_and_label`] below, ported as data from 1.5.5's four-way
//! split: `ClientFault` records nothing and relays; `TransientUpstream` carries the upstream's own
//! requested wait through as the cooldown floor; `HardDown` trips every pool cell for the
//! destination; `ContextLength` records nothing and fails over. [`classify_upstream`] composes the
//! two into the one call a caller needs.
//!
//! The input is facts and nothing else: the transport's fault reading of the answer (or the
//! kernel's fact that none came) and the wait the answer's frame stated, already in whole seconds.
//! No number, no namespace, no header and no body crosses into this unit.

use crate::classify::{self, Disposition, Reading};
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
/// unit reads, so the two crates no longer keep four strings in step by hand.
pub mod label {
    use busbar_contract::upstream::Disposition;
    /// A transient upstream failure.
    pub const TRANSIENT_UPSTREAM: &str = Disposition::TransientUpstream.label();
    /// A definitive signal about the shared destination.
    pub const HARD_DOWN: &str = Disposition::HardDown.label();
    /// The request was too large for this destination's window.
    pub const CONTEXT_LENGTH: &str = Disposition::ContextLength.label();
    /// The caller's own fault. Never read as a telemetry label by the reference caller (a
    /// `ClientFault` short-circuits before the label is used) but a real value all the same — never
    /// a placeholder a future caller could mistake for "unset".
    pub const CLIENT_FAULT: &str = Disposition::ClientFault.label();
}

/// Fold a classified [`Disposition`] into the [`Outcome`] this unit's state machine acts on and the
/// metric label a caller records the failure under. A pure function: no destination, no lock, no
/// clock.
#[must_use]
pub fn outcome_and_label(
    disposition: Disposition,
    retry_after: Option<u64>,
) -> (Outcome, &'static str) {
    match disposition {
        // The caller's bad input: the destination is healthy either way, so nothing is recorded —
        // folded together with `ContextLength` below, per `Outcome`'s own doc comment.
        Disposition::ClientFault => (Outcome::RecordNothing, label::CLIENT_FAULT),
        // A transient failure: the upstream's own requested wait (if any) threads through as the
        // cooldown floor `BreakerCell::compute_cooldown_with_retry_after` reads.
        Disposition::TransientUpstream => (
            Outcome::Transient { retry_after },
            label::TRANSIENT_UPSTREAM,
        ),
        // A definitive signal about the shared destination: every pool cell trips, not just this
        // one — see `BreakerUnit::hard_down_all`, which `BreakerUnit::observe` dispatches
        // `Outcome::HardDown` to.
        Disposition::HardDown => (Outcome::HardDown, label::HARD_DOWN),
        // Too big for this destination's window: the destination is healthy, record nothing.
        Disposition::ContextLength => (Outcome::RecordNothing, label::CONTEXT_LENGTH),
    }
}

/// Classify one upstream answer and fold it straight through to the [`Outcome`] and label a caller
/// acts on. A pure function: no lock, no destination, no clock.
#[must_use]
pub fn classify_upstream(status: UpstreamStatus) -> Classified {
    let disposition = classify::classify(status.reading);
    let (outcome, label) = outcome_and_label(disposition, status.retry_after);
    Classified {
        disposition,
        outcome,
        label,
    }
}

#[cfg(test)]
#[path = "tests/port.rs"]
mod tests;
