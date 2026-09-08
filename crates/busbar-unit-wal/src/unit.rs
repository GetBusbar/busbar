// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for Journal`, in the exemplar's file position.

use busbar_caps::step::Audit;
use busbar_caps::{DurabilityLost, DurabilityToken, StepName, Unit, UnitToken};

use crate::journal::{Entry, Journal, JournalAck};

/// Everything the loop hands this unit when it commits a batch.
pub struct AppendInput<'a> {
    /// The token that commits a batch. Only the durability path is lent it.
    pub durability: &'a DurabilityToken,
    /// Which step the batch is being written at — recorded, not decided on.
    pub at: StepName,
    /// The entries, committed together or not at all.
    pub entries: &'a [Entry],
}

/// The WAL unit SERVES the audit step: it commits the batch and acks, and decides nothing.
///
/// `OWNS_ITS_STEP` is `false` because the root's own table says so — `crates/busbar/src/root/
/// kernel.rs`: "the WAL unit sits under the ledger on the durability path". Its answer is an ack or
/// a `DurabilityLost`, which leaves the loop on the exit path rather than as a step's answer. The
/// `at: StepName` field is a RECORD of which step the batch belongs to; it is deliberately not
/// `Self::Step`, because a WAL that inferred the step from its own placement would write the wrong
/// one for every batch the ledger flushes late.
impl Unit for Journal {
    type Step = Audit;
    type Input<'a> = AppendInput<'a>;
    type Answer<'a> = Result<JournalAck, DurabilityLost>;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Audit>,
        input: AppendInput<'a>,
    ) -> Result<JournalAck, DurabilityLost> {
        self.append(input.durability, input.at, input.entries)
    }
}
