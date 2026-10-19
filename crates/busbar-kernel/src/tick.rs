// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The clock's work: what a node does when nothing arrived.
//!
//! A thing that is not happening still has to be accounted for.
//!
//! **The node tick** sweeps. A task can disappear: a runtime shuts down, a thread is cancelled, a
//! future is dropped. The unit it was running still has a hold in its cell, and the sweep is the
//! SECOND holder of a key to that cell. It takes the hold and settles it, so a lost task costs
//! exactly one tick of delay and never a lost posting. A unit that is merely SLOW is a different
//! thing and gets a different answer: an alarm, and — where the protocol is one whose long silences
//! are normal — no ending at all.

use busbar_contract::caps::{
    Canary, Consumption, Exit, Grant, Outcome, Posted, PostingFlags, QuantitySource, ReasonCode,
    StepName, UnitEnd, Usage, UsageLine, WriteMoney,
};

use crate::inflight::UnitSlot;
use crate::slice::ConcurrencyGauge;
use crate::teller::{settle_written, Evidence, Kernel, Written, KERNEL_ACCRUAL_CLASS};
use crate::Millis;

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
    } else if slot.idle_for(now) < max_unit_duration {
        Sweep::Running
    } else if idle_bound_applies {
        Sweep::Stalled { at }
    } else {
        Sweep::AlarmOnly
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

/// Settle a unit the sweep found abandoned.
///
/// This is the SECOND holder of a key to a hold cell, and there is no third. The exit path and this
/// function both take by compare-and-set, so whichever arrives second is told the unit is already
/// settled and does nothing — which is why a lost task costs one tick of delay and never a lost
/// posting, and why a unit that ends normally a moment later is not settled twice.
///
/// The whole SLOT is what the sweep is given, because the slot is what the unit owns: its hold and
/// its leases, reclaimed together or not at all. A verdict that says the unit is still running
/// reclaims nothing of either, and an abandoned slot gives back both at its deadline.
pub fn sweep_settle(
    kernel: &Kernel,
    slot: &UnitSlot,
    verdict: Sweep,
    evidence: &Evidence,
    canary: &Canary,
    gauge: &ConcurrencyGauge,
) -> Option<UnitEnd> {
    match sweep_outcome(verdict) {
        None => None,
        Some(outcome) => {
            // The take is spelled the way the exit path spells it — the grant minted IN the
            // argument — and that is load-bearing rather than style (item 130). The construction
            // gate's `seal-sites` row confines and COUNTS that literal spelling: there are exactly
            // three take sites, and a take through a named grant (`let exit = ...; take(&exit)`,
            // which is how this line used to read) is a take the gate cannot see, so the sweep was
            // the one site the "no fourth" guarantee was blind to.
            let taken = slot.cell().take(&Grant::<Exit>::mint(kernel.seal()));
            // A lost task holds its concurrency leases until somebody gives them back, and the
            // exit path it would have used is never going to run. The rule is that leases go back
            // on every end; this is one of the two ends, so they go back here, in the same breath
            // as the take — including when the take loses, because the unit ended either way. They
            // are the unit's OWN leases: the slot owns them, so the sweep no longer has to be
            // handed a set that a gone task took with it.
            slot.leases().release_all(gauge);
            taken.map(|hold| {
                let Written { amount, flags, .. } = settle_written(&outcome, evidence);
                // Estimated or reported is the settlement writer's answer, not the sweep's: a unit
                // whose plane DID report before its task disappeared is settled at the figure it
                // reported, unflagged, exactly as the writer says.
                let estimated = flags.contains(PostingFlags::ESTIMATED);
                let lines = vec![UsageLine {
                    class: KERNEL_ACCRUAL_CLASS,
                    quantity: amount,
                    source: QuantitySource::Count,
                    estimated,
                }];
                let token = Grant::<Consumption>::mint(kernel.seal());
                let usage = if estimated {
                    Usage::estimate(&token, lines)
                } else {
                    Usage::report(&token, lines)
                }
                .expect("one usage line is always within the record's bound");
                // As every other settling site: the writer's `amount` is the money, and the one
                // line is the evidence it was derived from.
                let ledger = Grant::<WriteMoney>::mint(kernel.seal());
                let posted =
                    Posted::settle(hold, u128::from(amount), &usage, &ledger).flagged(flags);
                canary.settled();
                UnitEnd::seal(&Grant::<Exit>::mint(kernel.seal()), outcome, Ok(posted))
            })
        }
    }
}
