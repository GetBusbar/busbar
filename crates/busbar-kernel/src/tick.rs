// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::canary::Canary;
use busbar_contract::caps::{
    Audit, Consumption, Exit, Grant, Outcome, Pass, Posted, PostingFlags, QuantitySource,
    ReasonCode, StepName, UnitEnd, Usage, UsageLine, WriteMoney,
};

use crate::inflight::UnitSlot;
use crate::slice::ConcurrencyGauge;
use crate::teller::{audit_pass, settle_written, Evidence, Kernel, Written, KERNEL_ACCRUAL_CLASS};
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

pub fn sweep_outcome(verdict: Sweep) -> Option<Outcome> {
    match verdict {
        Sweep::TaskLost { at } => Some(Outcome::Failed(at, ReasonCode::TaskLost)),
        Sweep::Stalled { at } => Some(Outcome::Failed(at, ReasonCode::Stalled)),
        Sweep::Running | Sweep::AlarmOnly => None,
    }
}

/// What the sweep settled for one unit: its sealed end, the one line it was posted from, and the
/// unit's audit pass.
///
/// THE DESIGN §1 (`BUSBAR-1.6.0.md` l.190-197): "The audit step writes one fixed record, for every
/// plane ... never optional"; §7 U14 (l.1061-1065): one audit record per unit, sealed at its one line.
/// A unit the sweep settles never reached its own audit step, so the sweep hands its caller the pass
/// that step would have been lent, beside the exact line the posting settled, and the caller seals
/// the unit's one record from both where it writes the line. A settled unit and its pass come back
/// together or not at all, so no swept unit settles without the means to seal its record.
#[derive(Debug)]
pub struct Swept {
    /// The unit's sealed end: `Failed(at, TaskLost | Stalled)`, with its posting.
    pub end: UnitEnd,
    /// The one usage line the posting was settled from, as posted: the record's amount.
    pub line: UsageLine,
    /// The unit's audit pass, bound to the call its hold was opened under.
    pub audit: Pass<Audit>,
}

pub fn sweep_settle(
    kernel: &Kernel,
    slot: &UnitSlot,
    verdict: Sweep,
    evidence: &Evidence,
    canary: &Canary,
    gauge: &ConcurrencyGauge,
) -> Option<Swept> {
    match sweep_outcome(verdict) {
        None => None,
        Some(outcome) => {
            let taken = slot.cell().take(&Grant::<Exit>::mint(kernel.seal()));

            slot.leases().release_all(gauge);
            taken.map(|hold| {
                let audit = audit_pass(kernel.seal(), hold.call());
                let Written { amount, flags, .. } = settle_written(&outcome, evidence);

                let estimated = flags.contains(PostingFlags::ESTIMATED);

                let line = UsageLine {
                    class: evidence.class.unwrap_or(KERNEL_ACCRUAL_CLASS),
                    quantity: amount,
                    source: QuantitySource::Count,
                    estimated,
                };
                let token = Grant::<Consumption>::mint(kernel.seal());
                let lines = vec![line.clone()];
                let usage = if estimated {
                    Usage::estimate(&token, lines)
                } else {
                    Usage::report(&token, lines)
                }
                .expect("one usage line is always within the record's bound");

                let ledger = Grant::<WriteMoney>::mint(kernel.seal());
                let posted = Posted::settle(hold, amount, &usage, &ledger).flagged(flags);
                canary.settled();
                Swept {
                    end: UnitEnd::seal(&Grant::<Exit>::mint(kernel.seal()), outcome, Ok(posted)),
                    line,
                    audit,
                }
            })
        }
    }
}

pub type ClockJob = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

pub trait ClockWork: Send + Sync {
    fn beat(&self, now: std::time::SystemTime) -> Option<ClockJob>;
}

pub fn on_clock(work: std::sync::Weak<dyn ClockWork>) {
    crate::oauth_as::seam::hold_clock_work(work);
}

pub fn beat(now: std::time::SystemTime) -> Vec<ClockJob> {
    let live = crate::oauth_as::seam::clock_work();
    live.iter().filter_map(|w| w.beat(now)).collect()
}

#[cfg(test)]
#[path = "tests/clock_tests.rs"]
mod clock_tests;
