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

// RED COMMIT ONLY: the readers have no production caller until the fix binds them.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{DurableWrite, Grant};
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel_wal::{BodyReader, JournalRecord, RecordClass};

use super::store_chain::{off_runtime, wait_for};
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
    let _ = (book, token, calls, store);
    Some(adapter.verb_store())
}

#[cfg(test)]
#[path = "../tests/durability_recovery.rs"]
mod tests;
