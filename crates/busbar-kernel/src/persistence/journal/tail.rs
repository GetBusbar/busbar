// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A READ-ONLY TAIL VIEW OF ANOTHER NODE'S JOURNAL (SEALING-FIX r20 §3.6.2 steps 1-2): the head and
//! owner rows `replay` reads first, and its original frames by ordinal, newest first, so the
//! predecessor sealer walks a dead node's tail back to its last stamp without reading its whole
//! history and without claiming its writer.

use busbar_kernel_wal::JournalRecord;

use super::{decode_record, valid_owner, Error, Head, Result, StoreJournal};

/// The selected head and owner of a node's journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailView {
    /// How many original frames the journal holds (ordinals `1..=count`).
    pub count: u64,
    /// The newest frame's WAL `node_seq`.
    pub sequence: u64,
    /// The newest frame's chain hash.
    pub hash: [u8; 32],
    /// The owner row's `(writer_epoch, writer)`.
    pub owner: (u64, [u8; 16]),
}

impl StoreJournal<'_> {
    /// The head and owner rows, or `None` when the node never wrote a journal record.
    pub(crate) async fn tail_view(&self) -> Result<Option<TailView>> {
        let mut rows = self
            .read(vec![self.address(b'H', 0), self.address(b'O', 0)])
            .await?;
        let owner = rows.pop().ok_or(Error::Corrupt)?;
        let head = rows.pop().ok_or(Error::Corrupt)?;
        let (head, owner) = match (head, owner) {
            (None, None) => return Ok(None),
            (Some(head), Some(owner)) => (head, owner),
            _ => return Err(Error::Corrupt),
        };
        if !valid_owner(&owner) {
            return Err(Error::Corrupt);
        }
        let head = Head::decode(&head)?;
        let bytes = owner.expose(&crate::seal::lend());
        let epoch = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| Error::Corrupt)?);
        let writer: [u8; 16] = bytes[16..32].try_into().map_err(|_| Error::Corrupt)?;
        Ok(Some(TailView {
            count: head.count,
            sequence: head.sequence,
            hash: head.hash,
            owner: (epoch, writer),
        }))
    }

    /// Original frames `from..=to` (ordinals), oldest first, each verified as a WAL frame of this
    /// node, and each linked to the next by its chain hash. The caller links the newest to the
    /// head (or to the batch above it).
    pub(crate) async fn read_back(&self, from: u64, to: u64) -> Result<Vec<JournalRecord>> {
        if from == 0 || from > to {
            return Err(Error::Invalid);
        }
        let addresses = (from..=to).map(|at| self.address(b'R', at)).collect();
        let rows = self.read(addresses).await?;
        let mut out: Vec<JournalRecord> = Vec::with_capacity(rows.len());
        for row in rows {
            let row = row.ok_or(Error::Corrupt)?;
            let bytes = row.expose(&crate::seal::lend());
            if bytes.len() > self.store.limits().scan_bytes {
                return Err(Error::Budget);
            }
            let record = decode_record(self.node, bytes)?;
            if let Some(previous) = out.last() {
                if record.prev_hash != previous.hash
                    || previous.node_seq.checked_add(1) != Some(record.node_seq)
                {
                    return Err(Error::UnsupportedHistory);
                }
            }
            out.push(record);
        }
        Ok(out)
    }
}
