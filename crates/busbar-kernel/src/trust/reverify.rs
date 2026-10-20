// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RE-VERIFICATION CADENCE: when the kernel's trust book ([`super::book`]) marks a
//! counterparty due to be looked at again, from the operator's declared policy and the kernel's
//! own clock.

#[cfg(test)]
#[path = "tests/reverify_tests.rs"]
mod reverify_tests;

/// The operator's cadence. Config, therefore intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// How long an observation stays fresh before the upstream is re-fetched and re-verified.
    pub ttl_ms: u64,
    /// How long after the most recent DRIFT a clean answer is disbelieved.
    ///
    /// Zero is a legitimate setting and means "believe a recovery immediately", which is the right
    /// choice for an upstream an operator knows to be flaky for boring reasons. It is not the
    /// default, because the boring explanation and the hostile one look identical from here.
    pub recovery_backoff_ms: u64,
}

/// What has been observed so far. Store, therefore accumulation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    /// When the upstream was last contacted, on OUR clock. Never a timestamp the upstream supplied.
    pub last_checked_ms: Option<u64>,
    /// When drift was last OBSERVED, whether or not it was acted on.
    pub last_drift_ms: Option<u64>,
    /// How many times drift has been observed. Counts held observations too: the whole point of
    /// separating detection from demotion is that the operator still gets to see the flapping.
    pub drift_observations: u64,
}

/// Why the upstream is being checked now, or why it is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Due {
    /// Approved from a declarative pin and never actually contacted.
    NeverChecked,
    /// The operator's freshness window has elapsed.
    TtlExpired,
    /// An operator asked, explicitly. Outranks the timer: someone with out-of-band reason to suspect
    /// an upstream, or handling a scheduled vendor key rotation, does not wait for it.
    OperatorSync,
    /// The clock moved BACKWARDS since the last check, so the elapsed time cannot be computed and
    /// the freshness window cannot be trusted. Treated as due rather than as fresh, because the
    /// alternative reads a corrected or tampered clock as permanent freshness and an upstream that
    /// is never checked again is one that can change freely.
    ClockWentBackwards,
    /// Fresh, and nobody asked.
    No,
}

impl Due {
    /// Whether a check should happen.
    pub fn should_check(self) -> bool {
        !matches!(self, Due::No)
    }
}

/// Decide whether to re-fetch, from the operator's policy and OUR clock alone.
///
/// Reaching the TTL is due, not "one tick short of due": the operator wrote the longest staleness
/// they will accept, so treating it as still acceptable makes the setting mean something other than
/// what it says.
pub fn due(ledger: &Ledger, policy: &Policy, now_ms: u64, operator_sync: bool) -> Due {
    if operator_sync {
        return Due::OperatorSync;
    }
    let Some(last) = ledger.last_checked_ms else {
        return Due::NeverChecked;
    };
    if now_ms < last {
        return Due::ClockWentBackwards;
    }
    if now_ms - last >= policy.ttl_ms {
        return Due::TtlExpired;
    }
    Due::No
}
