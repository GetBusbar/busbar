// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money gate. Red: the native path opens billable units without asking the journal.

use super::Node;
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;
use busbar_kernel::refusal::ClientRefusal;

#[cfg(test)]
#[path = "money_gate_tests.rs"]
mod tests;

impl Node {
    pub(crate) fn money_gate(&self) -> Result<(), ClientRefusal> {
        Ok(())
    }

    pub(crate) fn close_money_episode(&self, _journal: &RuntimeJournal) {
        tracing::trace!(refused = self.money_refusals(), "red: no money episode");
    }

    #[must_use]
    pub(crate) fn money_refusals(&self) -> u64 {
        0
    }
}
