// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money gate: no billable unit opens on a node whose journal cannot record money (journal
//! failed, staging closed, a conditional publication pending, the custody buffer full, the store's
//! in-flight queue exhausted). Otherwise the engine would serve a request whose cost can never be
//! recorded. Every native open of a billable unit calls [`Node::money_gate`] once, before money is
//! admitted and before any upstream call: the native data commit, a port_mount unit, a nested child.
//! Every cause of a refusal lives in the journal (`State::refusal`), read here through its one
//! lock-free flag.

use super::Node;
use busbar_contract::caps::ReasonCode;
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;
use busbar_kernel::refusal::ClientRefusal;
use std::sync::atomic::Ordering;

#[cfg(test)]
#[path = "money_gate_tests.rs"]
mod tests;

impl Node {
    /// `Ok` when a billable unit may open now; otherwise the client's refusal: 503,
    /// `durability_unavailable`, with the journal's own reason as its text (the text the old
    /// request path rendered for this refusal). The healthy check is the journal's lock-free flag
    /// ([`RuntimeJournal::admits_money`]); only a refusal does more. A node with no journal bound
    /// admits, as the old path did.
    #[inline]
    pub(crate) fn money_gate(&self) -> Result<(), ClientRefusal> {
        match self.lane.get() {
            Some(journal) if !journal.admits_money() => Err(self.refuse_money(journal)),
            _ => Ok(()),
        }
    }

    /// Count the refusal and log the first of an episode; [`Self::close_money_episode`] logs its end.
    #[cold]
    fn refuse_money(&self, journal: &RuntimeJournal) -> ClientRefusal {
        // `None` only when the journal recovered since the flag was read: this one request is
        // still refused, and the next one is admitted.
        let why = journal
            .refuses_money()
            .unwrap_or_else(|| "native journal cannot record money".into());
        let refused = self.money_refusals.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.money_refusing.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                reason = %why,
                refused,
                "billable requests are refused with 503 durability_unavailable: the journal cannot record money"
            );
        }
        let status = busbar_kernel::plane_driver::refusal_status(ReasonCode::DurabilityUnavailable);
        crate::root::native_refusals::client(
            ReasonCode::DurabilityUnavailable,
            u16::try_from(status).unwrap_or(503),
            why,
        )
    }

    /// From the node's settle tick: once the journal admits again, end the refusal episode with
    /// one log line. Admission itself never waits for this: the next request reads the flag.
    pub(crate) fn close_money_episode(&self, journal: &RuntimeJournal) {
        if journal.admits_money() && self.money_refusing.swap(false, Ordering::Relaxed) {
            tracing::info!(
                refused = self.money_refusals(),
                "billable requests are admitted again: the journal records money"
            );
        }
    }

    /// Billable opens this node has refused because its journal could not record money.
    #[must_use]
    pub(crate) fn money_refusals(&self) -> u64 {
        self.money_refusals.load(Ordering::Relaxed)
    }
}
