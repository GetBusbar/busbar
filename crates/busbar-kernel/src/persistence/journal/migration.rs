// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure historical journal verification/encoding for inactive migration targets.
//! These codecs never emit an owner or grant append or business replay rights.

use super::*;
use busbar_kernel_wal::{QuarantineNote, RecordClass};

/// A stable, indexed original node run from the verified frozen source. Each
/// callback reassembles one complete canonical BJRN frame, not all payloads.
pub(crate) trait IndexedFrames {
    fn count(&self) -> u64;
    fn frame(&mut self, ordinal: u64) -> Result<Vec<u8>>;
}

pub(crate) struct SourceBudget {
    pub(crate) max_frame_bytes: usize,
    pub(crate) max_reads: u64,
}

/// Verification facts about one complete original indexed run. The checksum
/// binds every original byte, including records across an authorized hole;
/// it is inventory evidence and never replaces an original journal chain hash.
pub(crate) struct VerifiedNode {
    node: u64,
    head: Head,
    original_digest: [u8; 32],
}
impl VerifiedNode {
    pub(crate) fn node(&self) -> u64 {
        self.node
    }
    pub(crate) fn count(&self) -> u64 {
        self.head.count
    }
    pub(crate) fn tail(&self) -> (u64, [u8; 32]) {
        (self.head.sequence, self.head.hash)
    }
    pub(crate) fn original_digest(&self) -> [u8; 32] {
        self.original_digest
    }
}

struct Reader<'a, S> {
    source: &'a mut S,
    node: u64,
    count: u64,
    budget: SourceBudget,
}
impl<S: IndexedFrames> Reader<'_, S> {
    fn read(&mut self, ordinal: u64) -> Result<(JournalRecord, Vec<u8>)> {
        self.budget.max_reads = self.budget.max_reads.checked_sub(1).ok_or(Error::Budget)?;
        let bytes = self.source.frame(ordinal)?;
        if bytes.len() > self.budget.max_frame_bytes {
            return Err(Error::Budget);
        }
        Ok((decode_record(self.node, &bytes)?, bytes))
    }

    fn bridge_covers(&mut self, previous: Head, current: &JournalRecord) -> Result<bool> {
        if current.node_seq <= previous.sequence {
            return Ok(false);
        }
        for ordinal in 1..=self.count {
            let (note, _) = self.read(ordinal)?;
            if note.class != RecordClass::ChainBreak {
                continue;
            }
            let Some(bridge) = QuarantineNote::read(&note.body).and_then(|note| note.bridge) else {
                continue;
            };
            if bridge.before.0 != self.node || current.node_seq <= bridge.before.1 {
                continue;
            }
            let named = bridge.after == Some(current.identity());
            if named && bridge.before == (self.node, previous.sequence) {
                return Ok(true);
            }
            if !(named || bridge.after.is_none()) || bridge.before.1 > previous.sequence {
                continue;
            }
            for anchor_ordinal in 1..=previous.count {
                let (anchor, _) = self.read(anchor_ordinal)?;
                if anchor.identity() == bridge.before && anchor.hash == current.prev_hash {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

pub(crate) fn verify_source<S: IndexedFrames>(
    node: u64,
    source: &mut S,
    budget: SourceBudget,
) -> Result<VerifiedNode> {
    let count = source.count();
    if node == 0 || count == 0 {
        return Err(Error::Invalid);
    }
    if count > budget.max_reads || budget.max_frame_bytes == 0 {
        return Err(Error::Budget);
    }
    let mut reader = Reader {
        source,
        node,
        count,
        budget,
    };
    let mut observed = Head::default();
    let mut digest = Sha256::new();
    digest.update(b"busbar.journal.original-run/1\0");
    digest.update(node.to_be_bytes());
    digest.update(count.to_be_bytes());
    for ordinal in 1..=count {
        let (record, bytes) = reader.read(ordinal)?;
        if observed.count != 0 {
            if record.node_seq <= observed.sequence {
                return Err(Error::Corrupt);
            }
            let follows = record.prev_hash == observed.hash
                && observed.sequence.checked_add(1) == Some(record.node_seq);
            if !follows && !reader.bridge_covers(observed, &record)? {
                return Err(Error::UnsupportedHistory);
            }
        }
        digest.update(ordinal.to_be_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
        observed = advance(observed, &record)?;
    }
    Ok(VerifiedNode {
        node,
        head: observed,
        original_digest: digest.finalize().into(),
    })
}

fn address(node: u64, tag: u8, ordinal: u64) -> Address {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(&JOURNAL.0);
    key.extend_from_slice(&node.to_be_bytes());
    key.push(tag);
    key.extend_from_slice(&ordinal.to_be_bytes());
    Address {
        namespace: partition::namespace(JOURNAL, &[&node.to_be_bytes()]).0,
        key,
    }
}

/// Address-class validation for compiled inactive-target transforms. It accepts
/// immutable originals and their selection only; ownership is never authorized.
pub(crate) fn authorizes(candidate: &Address) -> bool {
    let key = &candidate.key;
    if key.len() != 33 || key[..16] != JOURNAL.0 {
        return false;
    }
    let Ok(node_bytes) = <[u8; 8]>::try_from(&key[16..24]) else {
        return false;
    };
    let Ok(ordinal_bytes) = <[u8; 8]>::try_from(&key[25..33]) else {
        return false;
    };
    let node = u64::from_be_bytes(node_bytes);
    let ordinal = u64::from_be_bytes(ordinal_bytes);
    node != 0
        && matches!((key[24], ordinal), (b'R', 1..) | (b'H', 0))
        && candidate.namespace == partition::namespace(JOURNAL, &[&node.to_be_bytes()]).0
}

/// Encode one original immutable row, without asserting whole-run completeness
/// or custody. The caller must verify the frozen run and copied target inventory.
pub(crate) fn record(
    node: u64,
    ordinal: u64,
    original: &Record,
) -> Result<(Address, Secret<Vec<u8>>)> {
    if node == 0 || ordinal == 0 {
        return Err(Error::Invalid);
    }
    let decoded = decode_record(node, &original.body)?;
    if decoded.identity() != original.identity() {
        return Err(Error::Corrupt);
    }
    Ok((
        address(node, b'R', ordinal),
        Secret::new(original.body.clone()),
    ))
}

/// Finalize the inactive target's completely verified original selection.
/// There is deliberately no owner encoder: only verified migration activation
/// plus explicit cold custody authorization can publish append ownership.
pub(crate) fn head(node: &VerifiedNode) -> (Address, Secret<Vec<u8>>) {
    (address(node.node, b'H', 0), node.head.encode())
}
