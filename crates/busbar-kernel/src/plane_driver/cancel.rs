// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::plane::UnitCount;
use busbar_contract::caps::ReasonCode;
use busbar_contract::plane::codes::{
    cancel_bills_reported_units, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL,
};

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

    /// The unit's far end is being dialled: the unit has run, so its end never releases the
    /// request count admission took, whatever its owner says it ran.
    fn dialled(&self, ctx: &UnitCtx) {
        let _ = ctx;
    }

    /// The provider's final stated usage for the unit was not accepted (`BUSBAR-5046`): the unit
    /// keeps `reason` for its terminal record and bills only the usage accepted before it. `true`
    /// the first time for the unit (its `plane-usage-unread` row is then written), `false` after.
    fn unread(&self, ctx: &UnitCtx, reason: ReasonCode) -> bool {
        let _ = (ctx, reason);
        true
    }

    /// The lane the unit is served under, when the seam knows it (the unread row names it).
    fn lane(&self, ctx: &UnitCtx) -> Option<String> {
        let _ = ctx;
        None
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
