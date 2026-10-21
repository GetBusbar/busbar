// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE THREE DISASTER-RECOVERY VERBS, ON THE NODE'S JOURNAL AND THE CONFIGURED STORE (status row
//! 187, audit PL2#4; OWNER 2026-10-20: the DR verbs stay in 1.6.0 and must be real).
//!
//! Each verb is built from the store v3 operations the node already uses, and no new store slot:
//!
//! - **`chain_break`** seals a `ChainBreak` record whose body opens with [`OPERATOR_BREAK_TAG`] on
//!   the node's journal — the same record class the journal seals for a quarantined segment or an
//!   overflow, told apart by its first body field — and the journal ships it through `record_put`
//!   like every other record. The break is a fact in the chain itself: the chain still verifies,
//!   and the boot walk reads it back as a deliberate operator break ([`Durability::operator_breaks`]).
//! - **`store_restore`** is refused. The configured store has no restore operation and no backup
//!   exists anywhere in the tree, so a restore happens off-node, with the store's own tooling.
//! - **`reseal_epoch_floor`** puts the floor under [`EPOCH_FLOOR_SCHEMA`], keyed per store, and every
//!   reader takes it back through `record_get` ([`epoch_floor`]): the boot, and the verb itself.
//!
//! Nothing here is held in this node's memory.

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{AdminVerb, DurableWrite, Grant, StepName};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use busbar_contract::verb_store::StoreError as VerbStoreError;
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, RecordClass};

use super::store_chain::{off_runtime, wait_for, ACK_DEADLINE};
use super::Durability;
use crate::root::loader::store_adapter::StoreAdapter;

/// The first body field of the `ChainBreak` record an operator's `chain_break` seals, which tells it
/// apart from the break a quarantine (`busbar_kernel_wal::QUARANTINE_BODY_TAG`) or an overflow seals.
pub const OPERATOR_BREAK_TAG: &str = "operator-chain-break";

/// The reserved host record schema the epoch floor is kept under in the configured store, one record
/// per store.
pub const EPOCH_FLOOR_SCHEMA: &str = "busbar.epoch_floor.v1";

/// One deliberate operator break the chain carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorBreak {
    /// Where on this node's chain the break was sealed.
    pub node_seq: u64,
    /// When, in seconds since the Unix epoch.
    pub at: u64,
}

/// The epoch floor a store was resealed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochFloor {
    /// The slice epoch no node on this store may serve below.
    pub floor: u64,
    /// When it was resealed, in seconds since the Unix epoch.
    pub resealed_at: u64,
}

/// The bytes of a floor record: the floor, then the reseal instant, each big-endian.
const FLOOR_BYTES: usize = 16;

/// The key a store's floor is kept under.
fn floor_key(store: &str) -> Vec<u8> {
    let mut key = b"store:".to_vec();
    key.extend_from_slice(store.as_bytes());
    key
}

/// A floor record's bytes.
fn encode_floor(floor: EpochFloor) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FLOOR_BYTES);
    bytes.extend_from_slice(&floor.floor.to_be_bytes());
    bytes.extend_from_slice(&floor.resealed_at.to_be_bytes());
    bytes
}

/// A floor record's bytes back as the floor, or `None` for bytes this build did not write.
fn decode_floor(bytes: &[u8]) -> Option<EpochFloor> {
    if bytes.len() != FLOOR_BYTES {
        return None;
    }
    Some(EpochFloor {
        floor: u64::from_be_bytes(bytes[..8].try_into().ok()?),
        resealed_at: u64::from_be_bytes(bytes[8..].try_into().ok()?),
    })
}

/// THE EPOCH FLOOR THE STORE HOLDS for `store`, read through `record_get`: `None` when it was never
/// resealed.
///
/// # Errors
///
/// The store would not answer, or the record it holds is not one this build wrote.
pub fn epoch_floor(calls: &dyn StoreCalls, store: &str) -> Result<Option<EpochFloor>, String> {
    let key = floor_key(store);
    let held = off_runtime(|| wait_for(calls.record_get(EPOCH_FLOOR_SCHEMA, &key)))
        .map_err(|e| format!("the epoch floor in the store `{store}`: {e}"))?;
    held.map(|value| {
        decode_floor(value.as_slice()).ok_or_else(|| {
            format!("the epoch floor record in the store `{store}` is not one this build wrote")
        })
    })
    .transpose()
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

/// THE BOOT'S READING OF WHAT THE DISASTER-RECOVERY VERBS LEFT: the epoch floor the store holds,
/// through `record_get`, and the operator breaks on the chain `book` resumed.
///
/// A node whose slice `epoch` is below the store's floor does not boot: the floor exists to fence
/// out exactly such a node. Operator breaks are read as what they are — deliberate, and on a chain
/// that verifies — and named in the log; they never stop a boot.
///
/// # Errors
///
/// The store would not answer for its floor, holds a floor this build did not write, or holds one
/// above `epoch`.
pub fn boot_recovery(
    book: &Durability,
    calls: &dyn StoreCalls,
    store: &str,
    epoch: u64,
) -> Result<Option<EpochFloor>, String> {
    let floor = epoch_floor(calls, store)?;
    if let Some(floor) = floor {
        if epoch < floor.floor {
            return Err(format!(
                "this node's slice epoch {epoch} is below the epoch floor {} the store `{store}` \
                 was resealed to at {}; a node below the floor may not serve",
                floor.floor, floor.resealed_at
            ));
        }
        tracing::debug!(
            store,
            floor = floor.floor,
            resealed_at = floor.resealed_at,
            "the store's epoch floor admits this node"
        );
    }
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
    Ok(floor)
}

/// The wall clock, in seconds since the Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// THE VERB STORE THE ADMIN UNIT'S DISASTER-RECOVERY VERBS REACH: the node's journal for the chain
/// break, the configured store for the epoch floor, and the loader adapter over that same store for
/// the sealed new-verb replay cache. Holds no state of its own.
struct NodeRecovery {
    /// The node's one book: the chain an operator break is sealed onto.
    book: Arc<Mutex<Durability>>,
    /// What seals onto it.
    token: Grant<DurableWrite>,
    /// The configured store's v3 slots.
    calls: Arc<dyn StoreCalls>,
    /// The configured store's name, which the floor is keyed by.
    store: String,
    /// The loader adapter over the same store: the slice epoch and the sealed replay cache.
    adapter: StoreAdapter,
}

/// A disaster-recovery verb that did not happen: one error line naming the verb and why, and the
/// store failure the admin unit answers `503 unavailable` for. Never acknowledged.
fn refused(verb: &'static str, why: &str) -> VerbStoreError {
    tracing::error!(verb, reason = why, "a disaster-recovery verb was refused");
    VerbStoreError::Failed
}

impl busbar_contract::verb_store::Store for NodeRecovery {
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

    /// Put the floor — this node's slice epoch — in the store, and answer once the store reads it
    /// back.
    fn reseal_epoch_floor(&self, _admin: &Grant<AdminVerb>) -> Result<(), VerbStoreError> {
        let floor = EpochFloor {
            floor: self.adapter.recovery_epoch(),
            resealed_at: now_secs(),
        };
        let value = RecordBytes::new(encode_floor(floor))
            .map_err(|n| refused("reseal_epoch_floor", &format!("a {n}-byte floor record")))?;
        let key = floor_key(&self.store);
        off_runtime(|| wait_for(self.calls.record_put(EPOCH_FLOOR_SCHEMA, &key, &value)))
            .map_err(|e| refused("reseal_epoch_floor", &e.to_string()))?;
        match epoch_floor(self.calls.as_ref(), &self.store) {
            Ok(Some(held)) if held == floor => Ok(()),
            Ok(held) => Err(refused(
                "reseal_epoch_floor",
                &format!("the store reads back {held:?}, not the floor it was handed"),
            )),
            Err(why) => Err(refused("reseal_epoch_floor", &why)),
        }
    }

    fn replay_new_verb(&self, key: &(String, String)) -> Result<Option<Vec<u8>>, VerbStoreError> {
        self.adapter.replay_new_verb(key)
    }

    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), VerbStoreError> {
        self.adapter.commit_new_verb_replay(key, response)
    }
}

/// THE VERB STORE THE ADMIN UNIT'S DISASTER-RECOVERY VERBS REACH, over the node's journal (`book`,
/// sealed under `token`) and the configured store (`calls`, named `store`), with `adapter` the
/// loader's adapter over the same store.
#[must_use]
pub fn node_verb_store(
    book: Arc<Mutex<Durability>>,
    token: Grant<DurableWrite>,
    calls: Arc<dyn StoreCalls>,
    store: &str,
    adapter: &StoreAdapter,
) -> crate::root::kernel::VerbStoreHandle {
    Some(Arc::new(NodeRecovery {
        book,
        token,
        calls,
        store: store.to_string(),
        adapter: adapter.clone(),
    }))
}

#[cfg(test)]
#[path = "../tests/durability_recovery.rs"]
mod tests;
