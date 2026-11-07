// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A bounded verification of original historical frames. This proves their
//! contents and links, never custody of their node or permission to import them.

use super::{Error, Result};
use busbar_kernel_wal::{JournalRecord, Record};

/// Explicit host resource policy, independent of backend page dimensions.
#[derive(Clone, Copy)]
pub(crate) struct SnapshotBudget {
    pub(crate) records: usize,
    pub(crate) bytes: usize,
}

/// Immutable original frames whose entire selected history has been checked.
/// A retained prefix may start at a nonzero previous hash, just as the original
/// WAL verifier permits; this is a historical boundary, never a synthetic link.
pub(crate) struct HistoricalSnapshot {
    node: u64,
    records: Vec<Record>,
    first_previous: [u8; 32],
    tail_sequence: u64,
    tail_hash: [u8; 32],
}

impl HistoricalSnapshot {
    pub(crate) fn verify(node: u64, records: Vec<Record>, budget: SnapshotBudget) -> Result<Self> {
        if node == 0 || records.is_empty() {
            return Err(Error::Invalid);
        }
        if records.len() > budget.records {
            return Err(Error::Budget);
        }
        // Check all allocation dimensions before decoding and copying bodies.
        let mut bytes = 0usize;
        for record in &records {
            bytes = bytes
                .checked_add(record.body.len())
                .ok_or(Error::Overflow)?;
            if bytes > budget.bytes {
                return Err(Error::Budget);
            }
        }
        let mut decoded = Vec::new();
        decoded
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Budget)?;
        let mut previous = None;
        for record in &records {
            let frame = JournalRecord::decode(&record.body).map_err(Error::Verification)?;
            if frame.node != node
                || frame.node_seq == 0
                || frame.identity() != record.identity()
                || frame.encode() != record.body
                || previous.is_some_and(|sequence| sequence >= frame.node_seq)
            {
                return Err(Error::Corrupt);
            }
            previous = Some(frame.node_seq);
            decoded.push(frame);
        }
        // The original verifier checks every digest and consults only the
        // QuarantineNote bridges carried by original ChainBreak bodies.
        busbar_kernel_wal::verify_journal(&decoded).map_err(Error::Verification)?;
        let first_previous = decoded[0].prev_hash;
        let tail = decoded.last().ok_or(Error::Invalid)?;
        Ok(Self {
            node,
            first_previous,
            tail_sequence: tail.node_seq,
            tail_hash: tail.hash,
            records,
        })
    }

    pub(crate) fn node(&self) -> u64 {
        self.node
    }
    pub(crate) fn records(&self) -> &[Record] {
        &self.records
    }
    pub(crate) fn first_previous(&self) -> [u8; 32] {
        self.first_previous
    }
    pub(crate) fn tail(&self) -> (u64, [u8; 32]) {
        (self.tail_sequence, self.tail_hash)
    }
}
