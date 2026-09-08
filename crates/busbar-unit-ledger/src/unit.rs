// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for Ledger`, in the exemplar's file position.

use busbar_caps::step::Audit;
use busbar_caps::{Hold, LedgerToken, Unit, UnitToken, Usage};

use crate::settle::{Ledger, Settlement};
use crate::totals::{TotalsKey, WindowStart};

/// Everything the loop hands this unit at the audit step.
///
/// The hold is taken BY VALUE, which is the whole discipline: settling consumes it, so there is no
/// second one to settle.
pub struct SettleInput<'a> {
    /// Which book the settlement moves.
    pub key: &'a TotalsKey,
    /// Which window it lands in.
    pub window: WindowStart,
    /// The reservation the door opened. Consumed here.
    pub hold: Hold,
    /// What the unit is priced at.
    pub priced_nanos: u128,
    /// What the unit used.
    pub usage: &'a Usage,
    /// The token that settles a hold. Only the ledger is lent it.
    pub ledger: &'a LedgerToken,
}

/// The ledger unit SERVES the audit step: it settles, and its answer is the settlement.
///
/// `OWNS_ITS_STEP` is `false` because the root's own table says the audit row is "the audit unit,
/// then the ledger unit" — the audit unit seals the record and the ledger moves the books under it.
/// The settlement is not a `Decision`: it is `Posted` plus the residual it released and the
/// overdraft it noted, and it leaves the loop as `Result<Settled, DurabilityLost>` on the exit path
/// rather than as a step's answer. Money is byte-identical through this seam: it is one delegation
/// to [`Ledger::settle_recording`], the same function the root already called.
impl Unit for Ledger {
    type Step = Audit;
    type Input<'a> = SettleInput<'a>;
    type Answer<'a> = Settlement;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Audit>,
        input: SettleInput<'a>,
    ) -> Settlement {
        self.settle_recording(
            input.key,
            input.window,
            input.hold,
            input.priced_nanos,
            input.usage,
            input.ledger,
        )
    }
}
