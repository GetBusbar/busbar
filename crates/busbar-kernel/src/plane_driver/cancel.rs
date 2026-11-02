// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub trait MoneySeam: Send + Sync {
    fn checkpoint(&self, ctx: &UnitCtx, units: &[UnitCount]) -> Checkpoint;

    fn cancelled(&self, ctx: &UnitCtx, bill: &CancelBill);

    fn finished(&self, ctx: &UnitCtx) {
        let _ = ctx;
    }

    fn served(&self, ctx: &UnitCtx, member: &str, provider: &str) {
        let _ = (ctx, member, provider);
    }

    fn laned(&self, ctx: &UnitCtx, lane: &str) {
        let _ = (ctx, lane);
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended);

    fn session_opened(&self, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        let _ = ctx;
        Err(ReasonCode::Unpriced)
    }

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
    /// A byte of the reply reached the caller from a piece that carried the far end's bytes (or a
    /// piece of the kernel's, for an answer the plane makes itself): the answer's CONTENT began.
    /// A byte the plane writes on a far-end piece that carried none (its own closing frame for an
    /// answer cut before its first byte) is not content, so that unit ended before its first byte.
    pub(crate) content: bool,
    /// The far end CUT the answer after its head (its connection failed, or the send's deadline
    /// passed): the plane was handed its last piece with `PIECE_CUT`.
    pub(crate) cut: bool,
    /// The reply's head was stated to the caller (once: a head with no body may precede the
    /// answer's first byte).
    pub(crate) headed: bool,
    /// The status that head stated (`0`: the plane stated none).
    pub(crate) status: u32,
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

pub(crate) type CancelFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Option<busbar_contract::plane_calls::Cancelled>> + Send>,
>;

pub(crate) fn poll_cancel(
    future: &mut CancelFuture,
    cx: &mut std::task::Context<'_>,
) -> std::task::Poll<Option<busbar_contract::plane_calls::Cancelled>> {
    future.as_mut().poll(cx)
}

pub(crate) struct Buried {
    pub(crate) ctx: UnitCtx,
    pub(crate) ticket: Ticket,
    pub(crate) facts: Facts,

    pub(crate) flight: Option<Box<dyn PieceInFlight>>,
    pub(crate) closing: Option<CancelFuture>,
    pub(crate) billed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) started: std::sync::Arc<std::sync::atomic::AtomicBool>,

    pub(crate) principal: Option<busbar_contract::caps::PrincipalId>,

    pub(crate) closed: bool,

    pub(crate) piece_flags: u32,

    pub(crate) final_answer: bool,
}

impl PlaneDriver {
    pub fn sweep(&self) {
        self.sweep_with_context(&mut std::task::Context::from_waker(std::task::Waker::noop()));
    }

    pub(crate) fn sweep_with_context(&self, cx: &mut std::task::Context<'_>) -> bool {
        let _sweep = match self.cleanup_sweep.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        let buried = std::mem::take(&mut *self.lock_buried());
        let mut unsettled = Vec::new();
        for mut unit in buried {
            let key = unit.ctx.key.get();
            let mut bill_ready = false;
            let cancelled = match unit.flight.take() {
                Some(mut flight) => match flight.settled() {
                    None => {
                        unit.flight = Some(flight);
                        unsettled.push(unit);
                        continue;
                    }
                    Some(done) => match (done.disposition, done.outcome) {
                        (Some(d), _) => {
                            bill_ready = true;
                            Some((d, flight.cancel_writes()))
                        }
                        (None, AbiOutcome::Fault) => {
                            bill_ready = true;
                            None
                        }
                        (None, _)
                            if super::route::answered_done(
                                &done,
                                &*flight,
                                unit.piece_flags,
                                unit.final_answer,
                            ) =>
                        {
                            bill_ready = true;
                            None
                        }
                        (None, _) if unit.closed => None,
                        (None, _) => {
                            unit.closed = true;
                            unit.started
                                .store(true, std::sync::atomic::Ordering::Release);
                            unit.closing = Some(self.cancel_unit(unit.ticket, key));
                            unsettled.push(unit);
                            continue;
                        }
                    },
                },
                None => {
                    if unit.closing.is_none() && !unit.closed {
                        unit.closed = true;
                        unit.started
                            .store(true, std::sync::atomic::Ordering::Release);
                        unit.closing = Some(self.cancel_unit(unit.ticket, key));
                    }
                    match unit.closing.as_mut().map(|future| poll_cancel(future, cx)) {
                        Some(std::task::Poll::Pending) => {
                            unsettled.push(unit);
                            continue;
                        }
                        Some(std::task::Poll::Ready(cancelled)) => {
                            bill_ready = true;
                            cancelled.map(|c| (c.disposition, c.writes))
                        }
                        None => {
                            bill_ready = !unit.started.load(std::sync::atomic::Ordering::Acquire);
                            None
                        }
                    }
                }
            };

            if let Some((_, writes)) = &cancelled {
                self.fold_writes(writes, unit.principal.as_ref());
            }
            let disposition = cancelled.map(|(d, _)| d);
            let bill = CancelBill::new(ReasonCode::ClientGone, disposition, &unit.facts);
            if bill_ready && !unit.billed.swap(true, std::sync::atomic::Ordering::AcqRel) {
                self.money.cancelled(&unit.ctx, &bill);
            }
            self.calls.recycle(unit.ticket);
        }
        self.lock_buried().extend(unsettled);

        self.close_owed(cx);
        self.buried() == 0 && self.owed_closes() == 0
    }

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
