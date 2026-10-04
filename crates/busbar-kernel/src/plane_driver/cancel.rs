// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CANCEL, AND THE SEAM THE MONEY STEPS PLUG INTO (`BUSBAR-1.6.0.md` Part 3, §12 "Cancel";
//! `BUSBAR-1.6.0.md` THE DESIGN, §7).
//!
//! The driver keeps its own facts about a unit: whether the far end answered, whether the reply
//! streamed to the caller, and the last cumulative units the plane reported. A cancelled unit's
//! bill is computed from those facts and the plane's `cancel` disposition by the four 1.5.5 rules
//! ([`cancel_bills_reported_units`]); a FAULT or absent disposition bills as [`CANCEL_FAILED`].
//! The driver computes the bill and hands it to the [`MoneySeam`]; it posts nothing itself. The
//! budget hold is released on the money steps' own path, never folded into the bill.
//!
//! A unit whose caller went away is BURIED, because nothing may cross the dispatcher inside a
//! `Drop`: an op still in flight goes to the dispatcher's client-drop path (a message, which makes
//! the cancel crossing on the op's worker) and waits here until it settles; a unit with no op in
//! flight waits here for its ticketless `cancel`. The host buffers are not kept here: the op lent
//! them, so the dispatcher holds them until the crossing returns. [`super::PlaneDriver::sweep`]
//! finishes both, outside any `Drop`.

use busbar_contract::abi::mechanism::call::Outcome as AbiOutcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    cancel_bills_reported_units, UnitCount, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL,
};
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane_calls::PieceInFlight;

use super::PlaneDriver;
use crate::teller::{Ended, UnitCtx};

/// What the money steps answer to a running unit's cumulative units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpoint {
    /// The unit runs on.
    Continue,
    /// The budget is dry under `cut-stream`: the driver cancels the unit and the plane renders the
    /// in-stream error frame through `refusal`.
    Cut,
}

/// THE MONEY SEAM: where the kernel's money steps (the hold at admit, checkpoints, the cut, the
/// cancel bill and the separate refund) plug into the driver. The driver moves no money: it reports
/// units, cancel bills and abandoned ends here, and nothing else.
pub trait MoneySeam: Send + Sync {
    /// Every READY answer's cumulative units, as the plane reported them (estimated and reported
    /// alike; only a source [`units_bill`](busbar_contract::abi::plane::units_bill) passes ever
    /// bills). Feeds the budget check and the checkpoint cadence.
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint;

    /// A cancelled unit's bill, by the four 1.5.5 cancel rules.
    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill);

    /// The unit's route step ended without a cancel (complete, failed or exhausted): no cancel bill
    /// will follow for it, so its last reported counts are its bill.
    fn finished(&self, ctx: &UnitCtx) {
        let _ = ctx;
    }

    /// The member whose attempt answered the unit, once it commits (failover happens only before
    /// the first byte, so this is final): its CONFIG model name and its provider. The money steps
    /// ledger and meter the unit under it, as 1.5.5's `ledger_and_meter` did under the serving
    /// lane. The driver calls it once per unit, before any piece of that answer is relayed.
    fn served(&self, ctx: &UnitCtx, model: &str, provider: &str) {
        let _ = (ctx, model, provider);
    }

    /// The end of a unit whose caller went away, as the loop's guard reached it: posted by the
    /// money steps exactly as a returned end is. Runs inside a `Drop`: it must not panic, await or
    /// cross a plugin.
    fn abandoned(&self, ctx: &UnitCtx, ended: Ended);

    /// A duplex session opens under its unit's one admission (THE DESIGN §7: the kernel's session
    /// account, one sealed line at the end). REFUSES by default: session money is K6-4's, and until
    /// a money seam states it no session runs unbilled.
    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        let _ = ctx;
        Err(ReasonCode::Unpriced)
    }

    /// The session's one cleanup ran: it is over. Runs inside a `Drop`: it must not panic, await
    /// or cross a plugin.
    fn session_ended(&self, ctx: &UnitCtx) {
        let _ = ctx;
    }
}

/// The driver's own facts about a unit (never the plane's word alone).
#[derive(Debug, Clone, Default)]
pub(crate) struct Facts {
    /// A far-end piece reached the plane.
    pub(crate) far_end_answered: bool,
    /// A byte of the reply reached the caller.
    pub(crate) streamed: bool,
    /// The reply's head was stated to the caller (once: a head with no body may precede the
    /// answer's first byte).
    pub(crate) headed: bool,
    /// The live attempt's answer is relayed as the unit's: a terminal's dispatch (a spill, the
    /// least-bad bypass, a queued slot), which 1.5.5 never failed over, so a retry verdict on it
    /// renders the answer instead.
    pub(crate) relayed: bool,
    /// The last cumulative units the plane reported.
    pub(crate) units: Vec<UnitCount>,
}

/// A cancelled unit's bill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelBill {
    /// Why the unit was cancelled, the reason its end records: [`ReasonCode::DeadlineExceeded`]
    /// (past its deadline), [`ReasonCode::OverBudget`] (a checkpoint dried the budget under
    /// `cut-stream`), [`ReasonCode::Drain`] (the plane's generation is being replaced) or
    /// [`ReasonCode::ClientGone`] (the caller went away).
    pub cause: ReasonCode,
    /// The plane's disposition; a FAULT, an absent or an unknown disposition is [`CANCEL_FAILED`].
    pub disposition: u32,
    /// The far end answered before the cancel (the driver's fact).
    pub far_end_answered: bool,
    /// The reply streamed to the caller (the driver's fact).
    pub streamed: bool,
    /// The far-end-reported cumulative units that bill; empty when nothing bills.
    pub billed: Vec<(u32, u64)>,
}

impl CancelBill {
    pub(crate) fn new(cause: ReasonCode, disposition: Option<u32>, facts: &Facts) -> Self {
        let disposition = match disposition {
            Some(d @ (CANCEL_OK_PARTIAL | CANCEL_FAILED | CANCEL_ABORTED)) => d,
            _ => CANCEL_FAILED,
        };
        // Rules 1-3: a translate-abort and a failure bill nothing, a partial bills only when it
        // streamed, and the plane's partial counts only if the far end did answer.
        let bills =
            facts.far_end_answered && cancel_bills_reported_units(disposition, facts.streamed);
        let billed = super::money::reported(if bills { &facts.units[..] } else { &[] });
        CancelBill {
            cause,
            disposition,
            far_end_answered: facts.far_end_answered,
            streamed: facts.streamed,
            billed,
        }
    }
}

/// A unit whose caller went away, waiting for its cancel to finish.
pub(crate) struct Buried {
    pub(crate) ctx: UnitCtx,
    pub(crate) ticket: Ticket,
    pub(crate) facts: Facts,
    /// The op that was in flight.
    pub(crate) flight: Option<Box<dyn PieceInFlight>>,
}

impl PlaneDriver {
    /// Finish every buried unit that can be finished: an in-flight op that has settled, and a unit
    /// with no op in flight, which gets its ticketless `cancel` here. Each is billed through the
    /// money seam and its ticket recycled. Called at the start of every unit and by the kernel's
    /// tick; never inside a `Drop`, and never under a lock (the plane is called with none held).
    pub fn sweep(&self) {
        let buried = std::mem::take(&mut *self.lock_buried());
        let mut unsettled = Vec::new();
        for mut unit in buried {
            let disposition = match unit.flight.take() {
                Some(mut flight) => match flight.settled() {
                    None => {
                        unit.flight = Some(flight);
                        unsettled.push(unit);
                        continue;
                    }
                    // The client-drop path cancelled the op on its worker; an op that ended on its
                    // own before the cancel reached it leaves the plane owing one.
                    Some(done) => match (done.disposition, done.outcome) {
                        (Some(d), _) => Some(d),
                        (None, AbiOutcome::Fault) => None,
                        (None, _) => self.cancel_now(unit.ticket),
                    },
                },
                None => self.cancel_now(unit.ticket),
            };
            let bill = CancelBill::new(ReasonCode::ClientGone, disposition, &unit.facts);
            self.money.cancelled(&unit.ctx, &bill);
            self.calls.recycle(unit.ticket);
        }
        self.lock_buried().extend(unsettled);
    }

    /// How many buried units are still waiting (a witness for the tests and the tick).
    pub fn buried(&self) -> usize {
        self.lock_buried().len()
    }

    pub(crate) fn bury(&self, unit: Buried) {
        self.lock_buried().push(unit);
    }

    fn lock_buried(&self) -> std::sync::MutexGuard<'_, Vec<Buried>> {
        self.buried
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
