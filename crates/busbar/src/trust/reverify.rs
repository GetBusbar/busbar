// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RE-VERIFICATION CADENCE: when to look again, and what to believe when the answer keeps changing.
//!
//! An approval is a statement about a document at a moment. Nothing keeps it true. The pin catches a
//! change only when somebody looks, so this module is what decides when somebody looks and what is
//! recorded when they do.
//!
//! ## The upstream never gets a vote on when it is checked
//!
//! The cadence is operator config and the clock, and nothing else. Not a `list_changed` style
//! notification, not a cache header, not a freshness hint in the document. The reason is not
//! subtlety, it is that every one of those is written by the party being checked: an upstream that
//! could say "nothing has changed" could say it forever, and the one moment it most wants to say it
//! is the moment after it changed something. A notification may cause an EXTRA check; it can never
//! postpone one.
//!
//! ## Two hazards, and they pull in opposite directions
//!
//! Never re-checking means a silent rug-pull is never found. Re-checking a FLAPPING upstream and
//! acting on every answer means the operator gets a demotion storm, which is a denial of service
//! against the human rather than against the gateway, and a human buried in alerts turns them off.
//!
//! The resolution is asymmetric, deliberately: **detection is never rate-limited, and the direction
//! that is held is RECOVERY, never demotion.** The first drift demotes immediately, so flapping
//! recently never buys a hostile upstream a free window. Once drifted, a clean answer is not
//! believed for a backoff period, so the alternation collapses into one quarantine that persists
//! rather than a storm of transitions. Every observation is still counted, whether or not it is
//! acted on, because the changes queue an operator works must show what actually happened and not
//! merely what survived the filter.
//!
//! ## Plane-neutral, and deliberately not promoted yet
//!
//! Nothing here names a plane; it is generic over the pinned artifact exactly as the lifecycle is.
//! It lives here rather than in [`crate::trust`] because this is its FIRST use, and the house rule
//! is to extract on the second. That rule was inverted for the lifecycle only because the lifecycle
//! had a known second consumer waiting before a line of it existed. This does not, so it stays where
//! its one caller is, and moves when a second plane wants it.

use super::{Approval, PinnedArtifact, Sighting};

/// The operator's cadence. Config, therefore intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    /// How long an observation stays fresh before the upstream is re-fetched and re-verified.
    pub(crate) ttl_ms: u64,
    /// How long after the most recent DRIFT a clean answer is disbelieved.
    ///
    /// Zero is a legitimate setting and means "believe a recovery immediately", which is the right
    /// choice for an upstream an operator knows to be flaky for boring reasons. It is not the
    /// default, because the boring explanation and the hostile one look identical from here.
    pub(crate) recovery_backoff_ms: u64,
}

/// What has been observed so far. Store, therefore accumulation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ledger {
    /// When the upstream was last contacted, on OUR clock. Never a timestamp the upstream supplied.
    pub(crate) last_checked_ms: Option<u64>,
    /// When drift was last OBSERVED, whether or not it was acted on.
    pub(crate) last_drift_ms: Option<u64>,
    /// How many times drift has been observed. Counts held observations too: the whole point of
    /// separating detection from demotion is that the operator still gets to see the flapping.
    pub(crate) drift_observations: u64,
}

/// Why the upstream is being checked now, or why it is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Due {
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
    pub(crate) fn should_check(self) -> bool {
        !matches!(self, Due::No)
    }
}

/// Decide whether to re-fetch, from the operator's policy and OUR clock alone.
///
/// Reaching the TTL is due, not "one tick short of due": the operator wrote the longest staleness
/// they will accept, so treating it as still acceptable makes the setting mean something other than
/// what it says.
pub(crate) fn due(ledger: &Ledger, policy: &Policy, now_ms: u64, operator_sync: bool) -> Due {
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

/// What settling an observation did, so a caller can log and surface it rather than inferring it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Settled<A: PinnedArtifact> {
    /// The sighting to RECORD. The trust state derives from it, so this is what decides whether the
    /// upstream is quarantined.
    pub(crate) sighting: Sighting<A>,
    /// Drift was observed on this pass. Set whether or not the observation was acted on.
    pub(crate) drift_observed: bool,
    /// A clean answer was DISBELIEVED because the backoff since the last drift has not elapsed.
    /// Surfaced so an operator can tell "still broken" from "claims to be fine, too soon to say".
    pub(crate) recovery_held: bool,
}

/// Fold a fresh observation into what is recorded.
///
/// The ledger is always stamped, and drift is always counted, before any decision about what to
/// believe. Detection and demotion are different acts, and only the second one is ever held back.
pub(crate) fn settle<A: PinnedArtifact>(
    approval: &Approval<A>,
    recorded: &Sighting<A>,
    observed: Sighting<A>,
    ledger: &mut Ledger,
    policy: &Policy,
    now_ms: u64,
) -> Settled<A> {
    ledger.last_checked_ms = Some(now_ms);

    match &observed {
        // A FAILED CONTACT IS NOT A RECOVERY. Recording it derives `Error`, which never serves, and
        // it deliberately does not clear the drift clock: an upstream that could age its own
        // quarantine out by refusing connections would have been handed the cheapest possible escape
        // from being quarantined.
        Sighting::Failed(_) => Settled {
            sighting: observed,
            drift_observed: false,
            recovery_held: false,
        },
        // Nothing observed, nothing to fold. Keeping what is recorded is the only answer that does
        // not invent an observation.
        Sighting::Never => Settled {
            sighting: recorded.clone(),
            drift_observed: false,
            recovery_held: false,
        },
        Sighting::Seen(_) => {
            if !approval.drift(&observed).is_empty() {
                // DEMOTION IS NEVER HELD. Holding it would mean an upstream that flapped recently
                // gets a window in which its next change is not acted on, and choosing when to flap
                // is entirely within its gift.
                ledger.drift_observations += 1;
                ledger.last_drift_ms = Some(now_ms);
                return Settled {
                    sighting: observed,
                    drift_observed: true,
                    recovery_held: false,
                };
            }
            // A clean answer, which is the only case the backoff applies to.
            let held = ledger.last_drift_ms.is_some_and(|drifted| {
                now_ms >= drifted && now_ms - drifted < policy.recovery_backoff_ms
            });
            Settled {
                sighting: if held { recorded.clone() } else { observed },
                drift_observed: false,
                recovery_held: held,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/reverify_tests.rs"]
mod reverify_tests;
