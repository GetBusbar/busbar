// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST SWEEP JOB, written ONCE and run by every plane.
//!
//! An approval is a statement about an upstream at a moment, and nothing keeps it true. The pin
//! catches a change only when somebody looks, so something has to look on a timer with no operator
//! present. That job is this module, and there is one of it.
//!
//! ## What this owns, and why each piece is here rather than per plane
//!
//! - **The cadence** ([`SWEEP_TICK`]). Two planes running one defence on two heartbeats is a
//!   difference with no reason behind it, and the two constants it replaced were already required —
//!   in prose, in both files — to hold the same value. Prose is not a mechanism.
//! - **The clock.** One reading of one clock ([`crate::store::now_ms`]). A second `now_ms` is how
//!   one plane ends up with different overflow or signedness behaviour from its sibling, which is a
//!   difference no reviewer sees.
//! - **The outcome shape** ([`SweepOutcome`]). Every plane answers "which registration, was it due,
//!   and what came back".
//! - **The reporting vocabulary** ([`SweepEvent`]) and the ONE renderer ([`report`]). This is the
//!   half that matters operationally: an operator watching a fleet reads one set of lines with a
//!   `plane` label on them, rather than learning two dialects for one event.
//! - **The loop** ([`spawn`]): the tick, the shutdown broadcast, and the panic containment that
//!   keeps one bad upstream from turning into a deployment that never sweeps anything again.
//!
//! ## What the plane supplies, and why THAT is the honest seam
//!
//! Exactly one thing: [`Sweeper::sweep`] — look at every registration once and say what was seen.
//!
//! That is the fetch, and the fetch genuinely differs. An A2A card is one signed document read over
//! a blocking socket behind an SSRF guard, under a registry write lock held for the whole pass so a
//! config apply cannot land half-way through it. An MCP refresh is an async JSON-RPC round trip
//! through a connection pool that may first perform an RFC 8693 token exchange, over entries cloned
//! out of a catalogue that is rebuilt on every apply. Forcing one function over both would be a
//! shared shape hiding two behaviours — which is the failure this file exists to prevent, inverted.
//!
//! So the difference lives in the ONE method a plane implements, and nowhere else. Above it there is
//! no plane-specific code at all: [`Plane`] travels through this module as a LABEL, never as a
//! branch. There is no `match` on it here, and adding one would mean the parameterisation failed.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::reverify::Due;
use super::Drift;
use crate::plane::Plane;

/// HOW OFTEN EVERY PLANE'S SWEEP LOOKS FOR WORK. A constant, for every plane, and deliberately not
/// config.
///
/// A configurable sweep interval is a configurable detection delay wearing a scheduling costume. The
/// cadence an operator controls is the per-registration TTL, which [`super::reverify::due`] owns;
/// this only decides how finely the job notices that a TTL elapsed, and coarsening it can only make
/// detection later.
pub(crate) const SWEEP_TICK: Duration = Duration::from_secs(30);

/// WHAT A SWEEP SAW, in the vocabulary every plane shares.
///
/// The plane's own pass produces its own rich type; this is what that type LOWERS to for reporting.
/// The lowering is where a plane's vocabulary stops: below it an MCP tool list and an A2A skill set
/// are different things, and above it they are both "the capability set moved".
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SweepEvent {
    /// The check could not be ATTEMPTED, so nothing was contacted and no trust state changed.
    /// Distinct from a check that WAS attempted and failed: this one is the operator's own
    /// configuration, the other is a network.
    NotAttempted { reason: String },
    /// The upstream was contacted and could not be reached or authenticated. Recorded as a failed
    /// contact, which never serves and never clears the drift clock.
    ContactFailed { reason: String },
    /// The observation DISAGREES with the approval. The registration is demoted, on the timer, with
    /// no operator present — and demotion is never held.
    Drifted {
        /// The derived trust state word, from [`super::TrustState::word`].
        state: &'static str,
        /// What the operator has to work. Itemised so the first notice an operator gets names the
        /// capabilities that moved rather than only the fact that something did.
        drift: Drift,
    },
    /// A clean observation was made and is NOT yet believed, because the recovery backoff since the
    /// last drift has not elapsed. Only recovery is ever held.
    RecoveryHeld,
    /// An anomaly breaker suspended the registration on this pass.
    Suspended { reason: String },
}

/// THE LOWERING: a plane's own pass type, expressed in the shared event vocabulary.
///
/// Implemented on the plane's rich outcome rather than replacing it, so the plane's own tests keep
/// asserting against the type their subject actually produces while the operator-facing rendering
/// stays single.
pub(crate) trait SweepDetail {
    /// What this pass is worth reporting. Empty means "nothing an operator needs to read".
    fn events(&self) -> Vec<SweepEvent>;
}

/// WHAT ONE SWEEP DID TO ONE REGISTRATION, so the outcome can be logged and surfaced rather than
/// re-derived by a reader who would have to guess.
#[derive(Debug)]
pub(crate) struct SweepOutcome<D> {
    /// The registration this is about, in the plane's own naming — a server id, an agent id.
    pub(crate) subject: String,
    /// Why it was checked, or why it was not.
    pub(crate) due: Due,
    /// The plane's own pass. Rich, and never flattened away: [`SweepDetail`] projects it for the
    /// log, and the plane's tests read it directly.
    pub(crate) detail: D,
}

/// Log what a sweep did. ONE renderer, for every plane.
///
/// Separated from the sweep itself so the decision is testable without a subscriber and the
/// reporting is not something a test has to tolerate.
///
/// A registration that was not due is silent. The `plane` label is the ONLY thing that differs
/// between two planes' lines, which is the entire point: an operator learns these five lines once.
pub(crate) fn report<D: SweepDetail>(plane: Plane, outcomes: &[SweepOutcome<D>]) {
    for outcome in outcomes {
        if !outcome.due.should_check() {
            continue;
        }
        let subject = outcome.subject.as_str();
        for event in outcome.detail.events() {
            match event {
                SweepEvent::NotAttempted { reason } => tracing::warn!(
                    plane = plane.key(),
                    subject = %subject,
                    error = %reason,
                    "a scheduled trust sweep could not be ATTEMPTED; the registration was NOT \
                     contacted and its trust state is unchanged"
                ),
                SweepEvent::ContactFailed { reason } => tracing::warn!(
                    plane = plane.key(),
                    subject = %subject,
                    due = ?outcome.due,
                    error = %reason,
                    "a scheduled trust sweep could not authenticate the upstream; recorded as a \
                     failed contact"
                ),
                // THE LINE THIS WHOLE MODULE EXISTS TO EMIT. Nobody asked for it, and it is the
                // operator's first notice that an upstream changed something underneath an approval.
                SweepEvent::Drifted { state, drift } => tracing::warn!(
                    plane = plane.key(),
                    subject = %subject,
                    due = ?outcome.due,
                    state = state,
                    pin_changed = drift.pin_changed,
                    changed = ?drift.changed,
                    added = ?drift.added,
                    removed = ?drift.removed,
                    "the upstream DRIFTED from the approved pin; the registration is demoted and \
                     stops serving until an operator re-approves"
                ),
                SweepEvent::RecoveryHeld => tracing::info!(
                    plane = plane.key(),
                    subject = %subject,
                    "a clean observation was made but is not yet believed; the recovery backoff \
                     since the last drift has not elapsed"
                ),
                SweepEvent::Suspended { reason } => tracing::warn!(
                    plane = plane.key(),
                    subject = %subject,
                    reason = %reason,
                    "the anomaly breaker suspended a registration"
                ),
            }
        }
    }
}

/// ONE PLANE'S HALF OF THE JOB: look at every registration once, and say what was seen.
///
/// The whole of the plane-specific surface, deliberately. A plane that needed a second method here
/// would be telling us the job is not actually one job.
pub(crate) trait Sweeper: Send + Sync + 'static {
    /// The plane's own pass type for one registration.
    type Detail: SweepDetail + Send;

    /// Which plane this job runs on. A LABEL for the operator's log lines; nothing in this module
    /// branches on it.
    fn plane(&self) -> Plane;

    /// ONE SWEEP over every registration on the plane, at the clock reading it is handed.
    ///
    /// Takes the clock as an argument and holds no timer of its own, which is what makes the
    /// behaviour testable on both planes: a test drives the same code the job drives, at times it
    /// chooses, with no sleeping and nothing for a scheduler to race.
    ///
    /// `operator_sync` is never passed here and there is no argument through which a due check could
    /// be suppressed: THE TIMER IS NOT AN OPERATOR, and the admin verb outranks it by calling the
    /// pass outright.
    fn sweep(&self, now_ms: u64) -> impl Future<Output = Vec<SweepOutcome<Self::Detail>>> + Send;
}

/// SPAWN THE SWEEP JOB for the process lifetime.
///
/// A `select!` between the tick and the shutdown broadcast, which is the crate's settled spawned-job
/// shape — a second shape is a second set of shutdown bugs.
///
/// **There is no final sweep at shutdown.** No observation is buffered here: the ledger is the
/// durable record of what was seen, and a registration that was not swept before the process stopped
/// is `NeverChecked` or `TtlExpired` at the next boot, which is to say due immediately. Doing fetches
/// against every registered upstream while the process is trying to exit would trade a guarantee we
/// already have for a slower shutdown.
///
/// **A panicked sweep is reported and the job CONTINUES.** Exiting the loop would turn one bad
/// upstream into a deployment that never sweeps anything again, silently — which is the exact
/// failure this job exists to prevent.
///
/// Returns the `JoinHandle` even though production drops it, so a test can shut the job down and
/// JOIN it rather than guess a wall-clock duration.
pub(crate) fn spawn<S: Sweeper>(
    sweeper: S,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let plane = sweeper.plane();
    let sweeper = Arc::new(sweeper);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(SWEEP_TICK) => {
                    let held = Arc::clone(&sweeper);
                    // ONE READING OF ONE CLOCK, taken here so both planes are swept against the
                    // same notion of now and neither can grow its own arithmetic.
                    let now = crate::store::now_ms();
                    let swept = std::panic::AssertUnwindSafe(async move { held.sweep(now).await });
                    match futures::FutureExt::catch_unwind(swept).await {
                        Ok(outcomes) => report(plane, &outcomes),
                        Err(_) => tracing::error!(
                            plane = plane.key(),
                            "a scheduled trust sweep panicked; the job continues"
                        ),
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    })
}

#[cfg(test)]
#[path = "tests/sweep_tests.rs"]
mod sweep_tests;
