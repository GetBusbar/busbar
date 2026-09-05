// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The clock's work: what a node does when nothing arrived.
//!
//! Three jobs, all of them the same idea — a thing that is not happening still has to be accounted
//! for.
//!
//! **The session tick** checkpoints what a live session has accrued, and where session time is
//! priced it opens a small unit that holds and settles one interval of it. It also closes a session
//! that has gone quiet, and one whose budget has run dry — priced seconds are never accrued
//! unmetered.
//!
//! **The node tick** sweeps. A task can disappear: a runtime shuts down, a thread is cancelled, a
//! future is dropped. The unit it was running still has a hold in its cell, and the sweep is the
//! SECOND holder of a key to that cell. It takes the hold and settles it, so a lost task costs
//! exactly one tick of delay and never a lost posting. A unit that is merely SLOW is a different
//! thing and gets a different answer: an alarm, and a drain, and — where the protocol is one whose
//! long silences are normal — no ending at all.
//!
//! **Drain** is how a node stops without cutting anyone off mid-sentence, and the fleet rule is how
//! a node decides whether stopping is even the right thing to do when it cannot reach the store.

use busbar_caps::{
    Abort, Canary, ExitToken, HoldCell, LedgerToken, MeterClassId, Outcome, Posted, PostingFlags,
    QuantitySource, ReasonCode, StepName, UnitEnd, Usage, UsageLine, UsageToken,
};

use crate::inflight::UnitSlot;
use crate::slice::{ConcurrencyGauge, LeaseSet};
use crate::teller::{settle_amount, Evidence, Kernel};
use crate::Millis;

/// How long a session may go without a non-tick unit before it is closed.
pub const SESSION_IDLE_MAX_MS: Millis = 300_000;

/// What a session tick decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTick {
    /// Nothing to do.
    Idle,
    /// Checkpoint the accrued figure, because it changed since the last tick.
    Checkpoint {
        /// What has accrued so far.
        accrued: u64,
    },
    /// Open a priced accrual unit for this many milliseconds of session time.
    Accrue {
        /// How much time to price. Normally one interval; after a tick that could not run, the
        /// elapsed time since the last SETTLED tick, so priced time is never simply dropped.
        elapsed: Millis,
        /// Whether the catch-up spans more than one interval, which marks the posting late.
        late: bool,
        /// Whether the catch-up was clipped at the idle bound, which marks it estimated and closes
        /// the session.
        clipped: bool,
    },
    /// Close the session.
    Close {
        /// Why.
        reason: ReasonCode,
    },
}

/// What one session tick should do.
///
/// `since_settled` is the time since the last accrual tick that actually settled, which is what
/// makes a tick refused at the in-flight cap cost nothing: the next one prices the whole gap.
pub fn session_tick(
    interval: Millis,
    since_settled: Millis,
    idle_for: Millis,
    accrued_changed: Option<u64>,
    priced_seconds: bool,
    budget_dry: bool,
    revoked: bool,
) -> SessionTick {
    if revoked {
        SessionTick::Close {
            reason: ReasonCode::Revoked,
        }
    } else if budget_dry {
        SessionTick::Close {
            reason: ReasonCode::OverBudget,
        }
    } else if idle_for >= SESSION_IDLE_MAX_MS {
        SessionTick::Close {
            reason: ReasonCode::DeadlineExceeded,
        }
    } else if priced_seconds {
        let clipped = since_settled > SESSION_IDLE_MAX_MS;
        SessionTick::Accrue {
            elapsed: since_settled.min(SESSION_IDLE_MAX_MS),
            late: since_settled > interval,
            clipped,
        }
    } else {
        match accrued_changed {
            Some(accrued) => SessionTick::Checkpoint { accrued },
            None => SessionTick::Idle,
        }
    }
}

/// What the sweep decided about one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sweep {
    /// It is running normally.
    Running,
    /// Its task is gone. Take the hold and settle: `Failed(step, TaskLost)`.
    TaskLost {
        /// Where it was when the task disappeared.
        at: StepName,
    },
    /// It has made no progress for too long, and the protocol it is on is one where that means
    /// something is wrong. Alarm, drain, and end it.
    Stalled {
        /// Where it stopped.
        at: StepName,
    },
    /// It has made no progress for too long, but its protocol has no idle bound, so the sweep only
    /// alarms and the unit runs to whatever end it reaches on its own.
    AlarmOnly,
}

/// Sweep one unit.
///
/// The two things the sweep reads are whether the drop guard MARKED the slot — a guard only ever
/// marks; it never ends a unit, because it runs during an unwind — and how long it has been since
/// the unit last advanced a step or relayed a frame.
pub fn sweep(
    slot: &UnitSlot,
    at: StepName,
    now: Millis,
    max_unit_duration: Millis,
    idle_bound_applies: bool,
) -> Sweep {
    if slot.is_marked() {
        Sweep::TaskLost { at }
    } else if slot.idle_for(now) >= max_unit_duration {
        if idle_bound_applies {
            Sweep::Stalled { at }
        } else {
            Sweep::AlarmOnly
        }
    } else {
        Sweep::Running
    }
}

/// The outcome a swept unit is settled under.
pub fn sweep_outcome(verdict: Sweep) -> Option<Outcome> {
    match verdict {
        Sweep::TaskLost { at } => Some(Outcome::Failed(at, ReasonCode::TaskLost)),
        Sweep::Stalled { at } => Some(Outcome::Failed(at, ReasonCode::Stalled)),
        Sweep::Running | Sweep::AlarmOnly => None,
    }
}

/// What drain does to one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainVerdict {
    /// Let it finish. Some protocols have no idle bound and were never cut before; draining is not
    /// the moment to start.
    RunToEnd,
    /// Pump it for up to the maximum unit duration, then end it.
    PumpThenAbort {
        /// How long it may keep going.
        grace: Millis,
    },
    /// End it now.
    Abort,
}

/// Decide what drain does to a unit.
pub fn drain_verdict(has_idle_bound: bool, max_unit_duration: Millis) -> DrainVerdict {
    if has_idle_bound {
        DrainVerdict::PumpThenAbort {
            grace: max_unit_duration,
        }
    } else {
        DrainVerdict::RunToEnd
    }
}

/// The end a drained unit gets.
pub fn drain_outcome() -> Outcome {
    Outcome::Aborted(Abort::Drain)
}

/// How this node is behaving, as its peers see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Everything is reachable.
    Serving,
    /// A staleness bound has been crossed. Broadcast the moment it happens, BEFORE acting on it,
    /// so peers can count it.
    Stale,
    /// On the way out.
    Draining,
}

/// What a node decides to do when it cannot reach the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetAction {
    /// Carry on as normal.
    Serve,
    /// Keep serving on slices already drawn, taking no new ones, until the bound. Postings are
    /// marked as having been made under stale policy, and the outage is journaled every tick.
    ServeStale {
        /// How long this may go on.
        until: Millis,
    },
    /// Stop taking work and drain.
    Drain,
}

/// The fleet rule.
///
/// Three branches, and the first one matters more than the other two put together: a node with NO
/// configured peers never drains for a store it cannot reach. That is every single-node deployment
/// there has ever been, and for it "the store is slow" has never meant "stop serving". It keeps
/// admitting against what it last knew, journals locally, and reconciles when the store returns.
///
/// With peers, the question is whether this node is the odd one out. If enough peers are also stale
/// or draining, the partition is the fleet's, not this node's, and the availability answer is to
/// keep serving on slices already drawn until a bound that is long enough for every admitted unit
/// to settle before the store would release its slice — so no slice is ever spent on two sides of a
/// partition. If the quorum is not met, this node is probably the broken one, and it serves only
/// for a short grace and then drains.
pub fn fleet_action(
    peers_configured: usize,
    stale_or_draining_peers: usize,
    drain_quorum: usize,
    stale_for: Millis,
    outage_grace: Millis,
    stale_serve_max: Millis,
) -> FleetAction {
    if peers_configured == 0 {
        FleetAction::Serve
    } else if peers_configured >= 2 && stale_or_draining_peers >= drain_quorum {
        if stale_for < stale_serve_max {
            FleetAction::ServeStale {
                until: stale_serve_max,
            }
        } else {
            FleetAction::Drain
        }
    } else if stale_for < outage_grace {
        FleetAction::ServeStale {
            until: outage_grace,
        }
    } else {
        FleetAction::Drain
    }
}

/// Settle a unit the sweep found abandoned.
///
/// This is the SECOND holder of a key to a hold cell, and there is no third. The exit path and this
/// function both take by compare-and-set, so whichever arrives second is told the unit is already
/// settled and does nothing — which is why a lost task costs one tick of delay and never a lost
/// posting, and why a unit that ends normally a moment later is not settled twice.
pub fn sweep_settle(
    kernel: &Kernel,
    cell: &HoldCell,
    verdict: Sweep,
    evidence: &Evidence,
    canary: &Canary,
    leases: &mut LeaseSet,
    gauge: &ConcurrencyGauge,
) -> Option<UnitEnd> {
    match sweep_outcome(verdict) {
        None => None,
        Some(outcome) => {
            let taken = cell.take(&ExitToken::mint(kernel.seal()));
            // A lost task holds its concurrency leases until somebody gives them back, and the
            // exit path it would have used is never going to run. The rule is that leases go back
            // on every end; this is one of the two ends, so they go back here, in the same breath
            // as the take — including when the take loses, because the unit ended either way.
            leases.release_all(gauge);
            match taken {
                None => None,
                Some(hold) => {
                    let (amount, flags) = settle_amount(&outcome, evidence);
                    let lines = vec![UsageLine {
                        class: MeterClassId::new("nano_units"),
                        quantity: amount,
                        source: QuantitySource::Count,
                        estimated: flags.contains(PostingFlags::ESTIMATED),
                    }];
                    let token = UsageToken::mint(kernel.seal());
                    // Estimated or reported is the settlement table's answer, not the sweep's: a
                    // unit whose locator DID arrive before its task disappeared is settled at the
                    // figure the destination reported, unflagged, exactly as the table says.
                    let usage = if flags.contains(PostingFlags::ESTIMATED) {
                        Usage::estimate(&token, lines)
                    } else {
                        Usage::report(&token, lines)
                    }
                    .expect("one usage line is always within the record's bound");
                    let posted = Posted::settle(hold, &usage, &LedgerToken::mint(kernel.seal()))
                        .flagged(flags);
                    canary.settled();
                    Some(UnitEnd::seal(
                        &ExitToken::mint(kernel.seal()),
                        outcome,
                        Ok(posted),
                    ))
                }
            }
        }
    }
}
