// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{AdminVerb, DurableWrite, Grant};
use busbar_kernel::persistence::recovery_api::StoreError as VerbStoreError;
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, RecordClass};

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
    pub async fn operator_breaks(
        &self,
    ) -> std::io::Result<Result<Vec<OperatorBreak>, busbar_kernel_wal::JournalBreak>> {
        Ok(self
            .chain()
            .await?
            .map(|records| records.iter().filter_map(operator_break_of).collect()))
    }
}

pub async fn report_operator_breaks(book: &Durability) {
    match book.operator_breaks().await {
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

    pending: Mutex<Option<Arc<busbar_kernel::persistence::journal::runtime::StagedRun>>>,

    store: String,
}

fn refused(verb: &'static str, why: &str) -> VerbStoreError {
    tracing::error!(verb, reason = why, "a disaster-recovery verb was refused");
    VerbStoreError::Failed
}

impl busbar_kernel::persistence::recovery_api::Store for NodeRecovery {
    fn chain_break<'a>(
        &'a self,
        _admin: &'a Grant<AdminVerb>,
    ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
        Box::pin(async move {
            let wall = now_secs();
            let mut body = BodyWriter::new();
            body.text(OPERATOR_BREAK_TAG).num(wall);
            let entry = Entry::new(RecordClass::ChainBreak, body.finish()).at(wall, 0);
            let journal = self
                .book
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .journal
                .clone();
            let run = {
                let mut pending = self
                    .pending
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                match pending.as_ref() {
                    Some(run) => run.clone(),
                    None => {
                        let run = journal
                            .stage_run(&[entry])
                            .map_err(|error| refused("chain_break", &format!("{error:?}")))?;
                        *pending = Some(run.clone());
                        run
                    }
                }
            };
            journal
                .confirm(&run)
                .await
                .map_err(|error| refused("chain_break", &format!("{error:?}")))?;
            self.pending
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take();
            let node_seq = run
                .records()
                .last()
                .ok_or_else(|| refused("chain_break", "journal sealed no original"))?
                .node_seq;
            tracing::warn!(node_seq, "journal carries an explicit operator chain break");
            Ok(())
        })
    }
    fn store_restore<'a>(
        &'a self,
        _admin: &'a Grant<AdminVerb>,
        _backup_ref: &'a str,
    ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
        Box::pin(async move {
            Err(refused(
                "store_restore",
                &format!(
                    "the configured store `{}` has no restore operation; restore through its own off-node tooling",
                    self.store
                ),
            ))
        })
    }
}

#[must_use]
pub fn node_verb_store(
    book: Arc<Mutex<Durability>>,
    _token: Grant<DurableWrite>,
    store: &str,
) -> crate::root::kernel::VerbStoreHandle {
    Some(Arc::new(NodeRecovery {
        book,
        pending: Mutex::new(None),
        store: store.to_string(),
    }))
}

#[cfg(test)]
#[path = "../tests/durability_recovery.rs"]
mod tests;
