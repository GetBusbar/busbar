// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{AdminVerb, DurableWrite, Grant, StepName};
use busbar_kernel_seams::verb_store::StoreError as VerbStoreError;
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, RecordClass};

use super::store_chain::ACK_DEADLINE;
use super::Durability;

pub const OPERATOR_BREAK_TAG: &str = "operator-chain-break";

/// One deliberate operator break the chain carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorBreak {
    /// Where on this node's chain the break was sealed.
    pub node_seq: u64,
    /// When, in seconds since the Unix epoch.
    pub at: u64,
}

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
    pub fn operator_breaks(
        &self,
    ) -> std::io::Result<Result<Vec<OperatorBreak>, busbar_kernel_wal::JournalBreak>> {
        Ok(self
            .chain()?
            .map(|records| records.iter().filter_map(operator_break_of).collect()))
    }
}

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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct NodeRecovery {
    book: Arc<Mutex<Durability>>,

    token: Grant<DurableWrite>,

    store: String,
}

fn refused(verb: &'static str, why: &str) -> VerbStoreError {
    tracing::error!(verb, reason = why, "a disaster-recovery verb was refused");
    VerbStoreError::Failed
}

impl busbar_kernel_seams::verb_store::Store for NodeRecovery {
    fn chain_break(&self, _admin: &Grant<AdminVerb>) -> Result<(), VerbStoreError> {
        let wall = now_secs();
        let mut body = BodyWriter::new();
        body.text(OPERATOR_BREAK_TAG).num(wall);
        let entry = Entry::new(RecordClass::ChainBreak, body.finish()).at(wall, 0);
        let (lane, node, node_seq) = {
            let mut durability = self.book.lock().unwrap_or_else(|p| p.into_inner());

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
