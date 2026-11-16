// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only journal views outside the custody owner (SHUTDOWN-HANG F1, R15). The proof-dependent
//! journal primitives are private to this module tree; code outside it reads another node's
//! journal through [`ForeignJournal`] and this node's own journal, cold, through [`OwnHistory`].
//! Both come only from this node's [`RuntimeJournal`], and neither has a CAS or a custody check.

use super::*;

/// Read-only view of ANOTHER node's journal: its complete historical proof, records within that
/// proof, and the selected-head predicates a later check re-reads. Obtained only from
/// [`RuntimeJournal::foreign`], which refuses this node. Unchanged in strength and cost from the
/// read-only `StoreJournal` calls it wraps.
pub(crate) struct ForeignJournal<'a> {
    journal: StoreJournal<'a>,
}
impl<'a> ForeignJournal<'a> {
    pub(super) fn new(store: &'a CoreStore, node: u64) -> Result<Self> {
        Ok(Self {
            journal: StoreJournal::new(store, node)?,
        })
    }
    /// A recovery history with no custody owner at all (tests only): every node is read as
    /// another node's journal.
    #[cfg(test)]
    pub(crate) fn unowned(store: &'a CoreStore, node: u64) -> Result<Self> {
        Self::new(store, node)
    }
    /// The historical verifier over the whole journal; only `finish` grants the proof.
    pub(crate) async fn proof(&self) -> Result<Replay<'_, 'a>> {
        self.journal.historical_replay().await
    }
    /// The original at `sequence` within `proof`.
    pub(crate) async fn record(&self, proof: &VerifiedHead, sequence: u64) -> Result<Record> {
        self.journal.read_verified_record(proof, sequence).await
    }
    /// Recheck the exact original a completed replay retained at `ordinal`.
    pub(crate) async fn confirm_original(
        &self,
        proof: &VerifiedHead,
        ordinal: u64,
        original: &Record,
    ) -> Result<()> {
        self.journal
            .confirm_original_record(proof, ordinal, original)
            .await
    }
    /// The selected head and owner rows `proof` names, for a later check of the same read.
    pub(crate) fn predicates(&self, proof: &VerifiedHead) -> Result<Vec<Predicate>> {
        self.journal.selected_predicates(proof)
    }
}

/// This node's own journal, read cold: boot scans and hops this process carries no evidence for.
/// Obtained only from [`RuntimeJournal::history`]. Replays and record reads only; every custody
/// confirmation and every CAS stays with the owner.
pub(crate) struct OwnHistory<'a> {
    journal: StoreJournal<'a>,
}
impl<'a> OwnHistory<'a> {
    pub(super) fn new(store: &'a CoreStore, node: u64) -> Result<Self> {
        Ok(Self {
            journal: StoreJournal::new(store, node)?,
        })
    }
    /// The historical verifier over the whole journal.
    pub(crate) async fn replay(&self) -> Result<Replay<'_, 'a>> {
        self.journal.historical_replay().await
    }
    /// The historical verifier continued from `base`, a completed proof of this node.
    pub(crate) async fn replay_after(&self, base: &VerifiedHead) -> Result<Replay<'_, 'a>> {
        self.journal.historical_replay_after(base).await
    }
    /// The original at `sequence` within `proof`.
    pub(crate) async fn record(&self, proof: &VerifiedHead, sequence: u64) -> Result<Record> {
        self.journal.read_verified_record(proof, sequence).await
    }
    /// The original at a runtime-located `ordinal`, checked against `sequence` and `proof`.
    pub(crate) async fn record_at(
        &self,
        proof: &VerifiedHead,
        sequence: u64,
        ordinal: u64,
    ) -> Result<Record> {
        self.journal
            .read_verified_record_at(proof, sequence, ordinal)
            .await
    }
    /// Recheck the exact original a completed replay retained at `ordinal`.
    pub(crate) async fn confirm_original(
        &self,
        proof: &VerifiedHead,
        ordinal: u64,
        original: &Record,
    ) -> Result<()> {
        self.journal
            .confirm_original_record(proof, ordinal, original)
            .await
    }
}
