// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 part B §B3.1, §B10.3: the exported audit tail a declaration carries, one chain per node.
//!
//! Canonical encoding: `"BSRT1\0\0\0" ‖ u32 BE node_count ‖` per node in strictly ascending `node`:
//! `node u64 BE ‖ u32 BE record_count ‖` per record in strictly ascending `node_seq`:
//! `u32 BE length ‖` the record's exact journal bytes. Any other order, a duplicate, an empty chain, a
//! record of another node, non-canonical record bytes or trailing bytes is `tail_encoding_invalid`.
//! The digest is `sha256("busbar.restore.tail.v1\0" ‖ canonical bytes)`, so it does not depend on how
//! an upload was chunked.

use busbar_kernel_wal::journal::JournalRecord;

/// The encoding's magic.
pub const MAGIC: &[u8; 8] = b"BSRT1\0\0\0";
/// The largest tail one declaration takes (§B10.3); beyond it `restore_tail_too_large` (413).
pub const MAX_RESTORE_TAIL_BYTES: usize = 256 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"busbar.restore.tail.v1\0";

/// One node's exported chain, oldest record first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeChain {
    /// The journal `NODE` every record carries.
    pub node: u64,
    /// The records, in strictly ascending `node_seq`.
    pub records: Vec<JournalRecord>,
}

/// The tail: one chain per node, in strictly ascending `node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tail {
    /// The per-node chains.
    pub chains: Vec<NodeChain>,
}

/// Why a tail does not decode (the `reason` of the refusal, §B10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailError {
    /// Over [`MAX_RESTORE_TAIL_BYTES`]: 413 `restore_tail_too_large`.
    TooLarge,
    /// Not the canonical encoding: 422 `tail_encoding_invalid`.
    Encoding,
}

impl TailError {
    /// The refusal's reason.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "restore_tail_too_large",
            Self::Encoding => "tail_encoding_invalid",
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TailError> {
        let (head, rest) = self.bytes.split_at_checked(n).ok_or(TailError::Encoding)?;
        self.bytes = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, TailError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| TailError::Encoding)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, TailError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| TailError::Encoding)?,
        ))
    }
}

/// Decode a canonical tail.
pub fn decode(bytes: &[u8]) -> Result<Tail, TailError> {
    if bytes.len() > MAX_RESTORE_TAIL_BYTES {
        return Err(TailError::TooLarge);
    }
    let mut reader = Reader { bytes };
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(TailError::Encoding);
    }
    let node_count = reader.u32()?;
    let mut chains: Vec<NodeChain> = Vec::new();
    for _ in 0..node_count {
        let node = reader.u64()?;
        if chains.last().is_some_and(|last| last.node >= node) {
            return Err(TailError::Encoding);
        }
        let record_count = reader.u32()?;
        if record_count == 0 {
            return Err(TailError::Encoding);
        }
        let mut records: Vec<JournalRecord> = Vec::new();
        for _ in 0..record_count {
            let length = usize::try_from(reader.u32()?).map_err(|_| TailError::Encoding)?;
            let raw = reader.take(length)?;
            let record = JournalRecord::decode(raw).map_err(|_| TailError::Encoding)?;
            if record.node != node
                || record.encode() != raw
                || records
                    .last()
                    .is_some_and(|last| last.node_seq >= record.node_seq)
            {
                return Err(TailError::Encoding);
            }
            records.push(record);
        }
        chains.push(NodeChain { node, records });
    }
    if !reader.bytes.is_empty() {
        return Err(TailError::Encoding);
    }
    Ok(Tail { chains })
}

/// The canonical encoding of `tail`.
#[must_use]
pub fn encode(tail: &Tail) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(tail.chains.len() as u32).to_be_bytes());
    for chain in &tail.chains {
        out.extend_from_slice(&chain.node.to_be_bytes());
        out.extend_from_slice(&(chain.records.len() as u32).to_be_bytes());
        for record in &chain.records {
            let raw = record.encode();
            out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            out.extend_from_slice(&raw);
        }
    }
    out
}

/// The tail digest over its canonical bytes.
#[must_use]
pub fn digest(canonical: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(DIGEST_DOMAIN.len() + canonical.len());
    data.extend_from_slice(DIGEST_DOMAIN);
    data.extend_from_slice(canonical);
    busbar_contract::abi::sdk::digest::sha256(&data)
}

/// Why a decoded tail does not verify (§B3.1, §B10.2): each a 422 reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// `tail_chain_broken`: the node's chain does not continue from its restored head (or, for a node born
    /// after the backup, from genesis), or does not link record to record.
    ChainBroken {
        /// The node whose chain breaks.
        node: u64,
    },
}

impl VerifyError {
    /// The refusal's reason.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::ChainBroken { .. } => "tail_chain_broken",
        }
    }
}

/// Continuity (§B3.1): every chain continues from `heads[node]`, the node's head in the restored Store
/// as `(node_seq, hash)`, or from genesis (`node_seq` 1, a zero predecessor) for a node with no head
/// there (born after the backup), and links record to record by the journal's own rules (a
/// quarantine `ChainBreak`'s named hole included).
pub fn verify_continuity(
    tail: &Tail,
    heads: &std::collections::BTreeMap<u64, (u64, [u8; 32])>,
) -> Result<(), VerifyError> {
    for chain in &tail.chains {
        let broken = VerifyError::ChainBroken { node: chain.node };
        let first = chain.records.first().ok_or(broken)?;
        let (sequence, hash) = heads.get(&chain.node).copied().unwrap_or((0, [0u8; 32]));
        if sequence.checked_add(1) != Some(first.node_seq) || first.prev_hash != hash {
            return Err(broken);
        }
        busbar_kernel_wal::journal::verify(&chain.records).map_err(|_| broken)?;
    }
    Ok(())
}

/// The restored Store's head of each node in `nodes` (absent for a node with no records there), read
/// from each node's journal head row.
pub async fn restored_heads(
    core: &super::facade::CoreStore,
    nodes: impl IntoIterator<Item = u64>,
) -> Result<std::collections::BTreeMap<u64, (u64, [u8; 32])>, String> {
    let mut heads = std::collections::BTreeMap::new();
    for node in nodes {
        let journal = super::journal::StoreJournal::new(core, node)
            .map_err(|error| format!("node {node}: {error:?}"))?;
        if let Some(head) = journal
            .selected_head()
            .await
            .map_err(|error| format!("node {node}: {error:?}"))?
        {
            heads.insert(node, head);
        }
    }
    Ok(heads)
}

#[cfg(test)]
#[path = "tests/restore_tail_tests.rs"]
mod tests;
