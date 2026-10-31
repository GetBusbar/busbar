// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO DISASTER-RECOVERY VERBS, ON THE NODE'S JOURNAL AND THE CONFIGURED STORE (status row
//! 187, audit PL2#4).
//!
//! - **`chain_break`** seals a `ChainBreak` record whose body opens with [`OPERATOR_BREAK_TAG`] on
//!   the node's journal — the same record class the journal seals for a quarantined segment or an
//!   overflow, told apart by its first body field — and the journal ships it through `record_put`
//!   like every other record. The break is a fact in the chain itself: the chain still verifies,
//!   and the boot walk reads it back as a deliberate operator break ([`Durability::operator_breaks`]).
//! - **`store_restore`** is refused. The configured store has no restore operation and no backup
//!   exists anywhere in the tree, so a restore happens off-node, with the store's own tooling.
//!
//! Nothing here is held in this node's memory.

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{AdminVerb, DurableWrite, Grant, StepName};
use busbar_kernel_seams::verb_store::StoreError as VerbStoreError;
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, RecordClass};

use super::store_chain::ACK_DEADLINE;
use super::Durability;

/// The first body field of the `ChainBreak` record an operator's `chain_break` seals, which tells it
/// apart from the break a quarantine (`busbar_kernel_wal::QUARANTINE_BODY_TAG`) or an overflow seals.
pub const OPERATOR_BREAK_TAG: &str = "operator-chain-break";

/// One deliberate operator break the chain carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorBreak {
    /// Where on this node's chain the break was sealed.
    pub node_seq: u64,
    /// When, in seconds since the Unix epoch.
    pub at: u64,
}

/// The operator break `record` is, or `None` for any other record.
fn operator_break_of(record: &JournalRecord) -> Option<OperatorBreak> {
    if record.class != RecordClass::ChainBreak {
        return None;
    }
    let mut body = BodyReader::new(&record.body);
    if body.text()? != OPERATOR_BREAK_TAG {
        return None;
    }
    Some(OperatorBreak {
        node_seq: record.node_seq,
        at: body.num()?,
    })
}

impl Durability {
    /// THE DELIBERATE OPERATOR BREAKS THE CHAIN CARRIES, oldest first: the boot walk's reading of
    /// every `ChainBreak` record whose body opens with [`OPERATOR_BREAK_TAG`]. The chain is verified
    /// first, so a break here is one the chain vouches for, never a corruption read as one.
    ///
    /// # Errors
    ///
    /// The chain could not be read (outer), or it did not verify (inner).
    pub fn operator_breaks(
        &self,
    ) -> std::io::Result<Result<Vec<OperatorBreak>, busbar_kernel_wal::JournalBreak>> {
        Ok(self
            .chain()?
            .map(|records| records.iter().filter_map(operator_break_of).collect()))
    }
}

/// THE BOOT'S READING OF WHAT THE DISASTER-RECOVERY VERBS LEFT: the operator breaks on the chain
/// `book` resumed, read as what they are — deliberate, and on a chain that verifies — and named in
/// the log. They never stop a boot.
pub fn report_operator_breaks(book: &Durability) {
    match book.operator_breaks() {
        Ok(Ok(breaks)) => {
            if let Some(latest) = breaks.last() {
                tracing::warn!(
                    breaks = breaks.len(),
                    latest_node_seq = latest.node_seq,
                    latest_at = latest.at,
                    "this node's chain carries deliberate operator breaks (chain_break); the chain \
                     verifies across them"
                );
            }
        }
        Ok(Err(why)) => {
            tracing::warn!(reason = %why, "the chain did not verify for its operator breaks")
        }
        Err(why) => {
            tracing::warn!(reason = %why, "the chain could not be read for its operator breaks")
        }
    }
}

/// The wall clock, in seconds since the Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// THE VERB STORE THE ADMIN UNIT'S DISASTER-RECOVERY VERBS REACH: the node's journal for the chain
/// break, and the configured store's name for the refused restore. Holds no state of its own.
struct NodeRecovery {
    /// The node's one book: the chain an operator break is sealed onto.
    book: Arc<Mutex<Durability>>,
    /// What seals onto it.
    token: Grant<DurableWrite>,
    /// The configured store's name.
    store: String,
}

/// A disaster-recovery verb that did not happen: one error line naming the verb and why, and the
/// store failure the admin unit answers `503 unavailable` for. Never acknowledged.
fn refused(verb: &'static str, why: &str) -> VerbStoreError {
    tracing::error!(verb, reason = why, "a disaster-recovery verb was refused");
    VerbStoreError::Failed
}

impl busbar_kernel_seams::verb_store::Store for NodeRecovery {
    /// Seal an operator break on the node's journal, and answer once the store has kept it: the
    /// same acknowledgement every durable admin verb waits for (ARCHITECT 2026-10-07 H3 ruling (d)).
    fn chain_break(&self, _admin: &Grant<AdminVerb>) -> Result<(), VerbStoreError> {
        let wall = now_secs();
        let mut body = BodyWriter::new();
        body.text(OPERATOR_BREAK_TAG).num(wall);
        let entry = Entry::new(RecordClass::ChainBreak, body.finish()).at(wall, 0);
        let (lane, node, node_seq) = {
            let mut durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
            // Where the store is the journal's durability, the verb answers once the store kept the
            // record; a journal on a disk took it when it sealed it.
            let lane = if durability.durable_in_store() {
                durability.lane().cloned()
            } else {
                None
            };
            if let Some(lane) = &lane {
                lane.healthy().map_err(|why| refused("chain_break", &why))?;
            }
            let ack = durability
                .journal
                .append(&self.token, StepName::Route, &[entry])
                .map_err(|e| refused("chain_break", &format!("{e:?}")))?;
            let sealed = ack
                .sealed
                .last()
                .ok_or_else(|| refused("chain_break", "the journal sealed nothing"))?;
            (lane, durability.journal.node(), sealed.node_seq)
        };
        if let Some(lane) = lane {
            lane.wait_acked(node, node_seq, ACK_DEADLINE)
                .map_err(|why| refused("chain_break", &why))?;
        }
        tracing::warn!(
            node_seq,
            "the journal chain was deliberately broken by an operator (chain_break)"
        );
        Ok(())
    }

    /// Refused: the configured store has no restore operation, so nothing is restored, nothing is
    /// recorded and nothing on this node changes. A restore happens off-node, with the store's own
    /// tooling.
    fn store_restore(
        &self,
        _admin: &Grant<AdminVerb>,
        _backup_ref: &str,
    ) -> Result<(), VerbStoreError> {
        Err(refused(
            "store_restore",
            &format!(
                "the configured store `{}` has no restore operation, so nothing was restored; \
                 restores happen off-node, with the store's own tooling",
                self.store
            ),
        ))
    }
}

/// THE VERB STORE THE ADMIN UNIT'S DISASTER-RECOVERY VERBS REACH, over the node's journal (`book`,
/// sealed under `token`) and the configured store named `store`.
#[must_use]
pub fn node_verb_store(
    book: Arc<Mutex<Durability>>,
    token: Grant<DurableWrite>,
    store: &str,
) -> crate::root::kernel::VerbStoreHandle {
    Some(Arc::new(NodeRecovery {
        book,
        token,
        store: store.to_string(),
    }))
}

#[cfg(test)]
#[path = "../tests/durability_recovery.rs"]
mod tests;
