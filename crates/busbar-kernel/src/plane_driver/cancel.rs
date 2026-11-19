// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::Outcome as AbiOutcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane::codes::{
    cancel_bills_reported_units, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL,
};
use busbar_contract::plane_calls::PieceInFlight;

use super::PlaneDriver;
use crate::teller::{Ended, UnitCtx};

/// What the money steps answer to a running unit's cumulative units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpoint {
    /// The unit runs on.
    Continue,
    /// The reported quantity cannot be accepted exactly; retain the previous valid report.
    Unpriced,
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

    /// SHUTDOWN-HANG F4 "Running requests at exit": every unit still open in this seam's
    /// tables, pushed into `out`. Read once, at exit, off the request path; a seam with no
    /// open-unit table has nothing to list.
    fn open_units(&self, out: &mut Vec<OpenUnitEvidence>) {
        let _ = out;
    }
}

/// One unit still open at exit (SHUTDOWN-HANG F4 `open_at_exit`): its identity, its last reported
/// counts and, for a governed unit, a clone of the grant that holds its gate count. The clone
/// keeps the grant alive while the exit walk counts distinct grants, so no address is reused.
#[derive(Clone)]
pub struct OpenUnitEvidence {
    pub unit: busbar_contract::UnitKey,
    pub checkpoint: [u8; 16],
    /// The unit's principal, group, lane and arrival, shared with the open unit.
    pub money: std::sync::Arc<super::UnitMoney>,
    /// The last cumulative counts the plane reported.
    pub reported: Vec<UnitCount>,
    pub ledgered: bool,
    pub finished: bool,
    pub grant: Option<std::sync::Arc<crate::governance::AdmitGrant>>,
}

impl std::fmt::Debug for OpenUnitEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenUnitEvidence")
            .field("unit", &self.unit)
            .field("principal", &self.money.key.id)
            .field("lane", &self.money.lane)
            .field("arrived", &self.money.arrived)
            .field("ledgered", &self.ledgered)
            .field("finished", &self.finished)
            .field("governed", &self.grant.is_some())
            .finish_non_exhaustive()
    }
}

impl PlaneDriver {
    /// This driver's open units, through its money seam (SHUTDOWN-HANG F4, at exit).
    pub(crate) fn open_unit_evidence(&self, out: &mut Vec<OpenUnitEvidence>) {
        self.money.open_units(out);
    }

    /// Whether two drivers share one money seam, so the exit walk lists its units once.
    pub(crate) fn shares_money_with(&self, other: &PlaneDriver) -> bool {
        std::sync::Arc::ptr_eq(&self.money, &other.money)
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
    /// The unit closed on the plane's own done: a READY `on_piece` answer that said the reply is
    /// complete (`closes_unit`), never a kernel cancel. Its stated units are final, so a cancel
    /// that follows bills them, whatever its cause.
    pub(crate) plane_done: bool,
    /// Why the provider's final stated usage was not billed, when it was not: the reason that
    /// ended the unit before its final report was accepted (`BUSBAR-5046`).
    pub(crate) unread: Option<ReasonCode>,
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
    pub billed: Vec<(u32, busbar_contract::Count)>,
    /// The provider answered, but its final stated usage was not billed: the reason that ended
    /// the unit before that report was accepted. Ledgered on the unit's record and audited
    /// (`BUSBAR-5046 plane-usage-unread`); `None` when nothing went unread.
    pub unread: Option<ReasonCode>,
}

impl CancelBill {
    pub(crate) fn new(cause: ReasonCode, disposition: Option<u32>, facts: &Facts) -> Self {
        let disposition = match disposition {
            Some(d @ (CANCEL_OK_PARTIAL | CANCEL_FAILED | CANCEL_ABORTED)) => d,
            _ => CANCEL_FAILED,
        };

        // A unit that closed on the plane's own done has stated its final usage: the cancel that
        // follows (any cause) bills it. The disposition stays what the plane gave, never a
        // plane-acknowledged partial that did not happen.
        let bills = facts.far_end_answered
            && (facts.plane_done || cancel_bills_reported_units(disposition, facts.streamed));
        let billed = super::money::reported(if bills { &facts.units[..] } else { &[] });
        CancelBill {
            cause,
            disposition,
            far_end_answered: facts.far_end_answered,
            streamed: facts.streamed,
            billed,
            unread: facts.unread,
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

    /// The leg the in-flight piece was pushed toward, for the same pre-fold and attribution
    /// checks the walk makes.
    pub(crate) leg: super::route::Leg,

    /// The unit's buffers (moved here by `Pumping::drop`): the settled piece's lane and reply
    /// bytes, and the attempt's member and provider.
    pub(crate) keep: super::route::Keep,

    /// `Pumping::drop` already settled a done flight it found settled (attributed, or refused).
    pub(crate) done_settled: bool,
}

impl PlaneDriver {
    pub fn sweep(&self) {
        self.sweep_with_context(&mut std::task::Context::from_waker(std::task::Waker::noop()));
    }

    pub(crate) fn sweep_with_context(&self, cx: &mut std::task::Context<'_>) -> bool {
        // The sweep's guard holds its reused buffer of the units still unsettled.
        let mut unsettled = match self.cleanup_sweep.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return false,
        };
        unsettled.clear();
        let mut buried = std::mem::take(&mut *self.lock_buried());
        for mut unit in buried.drain(..) {
            let key = unit.ctx.key.get();
            let mut bill_ready = false;
            let cancelled = match unit.flight.take() {
                Some(mut flight) => match flight.settled() {
                    None => {
                        unit.flight = Some(flight);
                        unsettled.push(unit);
                        continue;
                    }
                    Some(_) if flight.retirement().is_some() => {
                        // The sibling owns no settlement, writes, bill or cancellation.
                        self.calls.recycle(unit.ticket);
                        continue;
                    }
                    Some(done) => match (done.disposition, done.outcome) {
                        (Some(d), _) => {
                            bill_ready = true;
                            Some((d, flight.cancel_writes()))
                        }
                        // A plane fault is explicit: never a plane-done bill.
                        (None, AbiOutcome::Fault) => {
                            bill_ready = true;
                            Some((CANCEL_FAILED, Vec::new()))
                        }
                        (None, _)
                            if super::route::answered_done(
                                &done,
                                &*flight,
                                unit.piece_flags,
                                unit.final_answer,
                            ) =>
                        {
                            // The done piece settled after the bury: it is attributed (or
                            // refused) here, exactly as the walk would have, before the bill.
                            if !unit.done_settled {
                                if let Some(out) = flight.out() {
                                    let keep = unit
                                        .keep
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    if let Some(bufs) = keep.as_deref() {
                                        super::route::bury_done(
                                            &*self.money,
                                            &unit.ctx,
                                            &out,
                                            bufs,
                                            unit.leg,
                                            unit.piece_flags,
                                            &mut unit.facts,
                                        );
                                    }
                                }
                            }
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
                self.usage_unread(&unit.ctx, &bill, unit.principal.as_ref());
            }
            self.calls.recycle(unit.ticket);
        }
        {
            // Units buried during the sweep first, then the still-unsettled ones, as before; the
            // drained list keeps its capacity and becomes the live one.
            let mut live = self.lock_buried();
            buried.append(&mut live);
            buried.append(&mut unsettled);
            std::mem::swap(&mut *live, &mut buried);
        }
        drop(unsettled);

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
