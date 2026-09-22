// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE RE-VERIFICATION CADENCE moved DOWN into `busbar-substrate` in Phase-B B1;
//! this module re-exports it (glob) so every `crate::trust::reverify::…` name resolves unchanged and
//! hosts the core-only re-verification tests, which exercise an in-core plane consumer's
//! registration/pin call site.

#[cfg(test)]
#[path = "tests/reverify_tests.rs"]
mod reverify_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
use super::{Approval, PinnedArtifact, Sighting};

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

    /// Marshal this reason onto the neutral [`VerifyDecision`](busbar_plugin::hot::VerifyDecision) the
    /// host `verify_decide_q` slot returns BY VALUE — the outbound half of the reason mapping the slot
    /// uses so a full `Due` crosses the `#[repr(C)]` seam rather than a lossy `Fresh`/`Stale` bool.
    /// The exact inverse of [`from_verify_decision`](Self::from_verify_decision) for every reason.
    pub fn to_verify_decision(self) -> busbar_plugin::hot::VerifyDecision {
        use busbar_plugin::hot::VerifyDecision as V;
        match self {
            Due::No => V::Fresh,
            Due::NeverChecked => V::NeverChecked,
            Due::TtlExpired => V::TtlExpired,
            Due::OperatorSync => V::OperatorSync,
            Due::ClockWentBackwards => V::ClockWentBackwards,
        }
    }

    /// Reconstruct the reason from the neutral [`VerifyDecision`](busbar_plugin::hot::VerifyDecision)
    /// the host `verify_decide_q` slot answered with — the inbound half of the mapping the a2a
    /// re-verify job uses so `reverify_once` reconstructs the SAME rich `Due` it audits in `Pass{due}`,
    /// byte-identical to the compiled-in veneer for every genuine input. [`Stale`](busbar_plugin::hot::VerifyDecision::Stale)
    /// is the slot's GENERIC fail-closed due (null query / caught panic) — reconstructed as
    /// [`TtlExpired`](Due::TtlExpired), a due reason so `should_check()` holds; the slot never answers
    /// it for a real query, so the audit bytes never depend on this arm.
    #[cfg(feature = "relay")]
    pub fn from_verify_decision(decision: busbar_plugin::hot::VerifyDecision) -> Self {
        use busbar_plugin::hot::VerifyDecision as V;
        match decision {
            V::Fresh => Due::No,
            V::NeverChecked => Due::NeverChecked,
            V::TtlExpired => Due::TtlExpired,
            V::OperatorSync => Due::OperatorSync,
            V::ClockWentBackwards => Due::ClockWentBackwards,
            V::Stale => Due::TtlExpired,
        }
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

/// What settling an observation did, so a caller can log and surface it rather than inferring it.
#[derive(Clone, Debug, PartialEq)]
pub struct Settled<A: PinnedArtifact> {
    /// The sighting to RECORD. The trust state derives from it, so this is what decides whether the
    /// upstream is quarantined.
    pub sighting: Sighting<A>,
    /// Drift was observed on this pass. Set whether or not the observation was acted on.
    pub drift_observed: bool,
    /// A clean answer was DISBELIEVED because the backoff since the last drift has not elapsed.
    /// Surfaced so an operator can tell "still broken" from "claims to be fine, too soon to say".
    pub recovery_held: bool,
}

/// Fold a fresh observation into what is recorded.
///
/// The ledger is always stamped, and drift is always counted, before any decision about what to
/// believe. Detection and demotion are different acts, and only the second one is ever held back.
pub fn settle<A: PinnedArtifact>(
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
        // not invent an observation. `Demoted` is here with `Never` and not with `Failed` for
        // exactly that reason: it is the REPLAY of an observation taken by a previous process, so it
        // can arrive as the RECORDED sighting but is never something a fresh look produces. Folding
        // it in as if it were would let a boot replay stamp the drift clock a second time for a
        // demotion that has already been counted once.
        Sighting::Never | Sighting::Demoted(_) => Settled {
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
            //
            // A clock that has gone backwards since the drift was stamped says nothing about how
            // much of the backoff has elapsed, and the only safe reading of "unknown" is that it
            // has not. `is_due` already fails an unreadable clock CLOSED — treating the same clock
            // as an expired backoff here would fail it OPEN, and would hand any upstream that can
            // nudge our clock backwards a way to have its next clean answer believed at once.
            let held = ledger.last_drift_ms.is_some_and(|drifted| {
                now_ms < drifted || now_ms - drifted < policy.recovery_backoff_ms
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
#[path = "tests/reverify.rs"]
mod tests;
