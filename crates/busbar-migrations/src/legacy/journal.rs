// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Frozen-source original-journal bridge. Only bounded metadata is retained;
//! payloads are reread one complete original frame at a time. The output is R/H
//! for an inactive target, never O custody or a business recovery verdict.

use super::{
    CanonicalRows,
    archive::Provenance,
    journal_binding::{JournalMigration, Part},
    transform::ARCHIVAL,
};
use crate::{Bounds, Error, archive_source::ArchiveSource};
use busbar_contract::Secret;
use busbar_kernel::persistence::import_target::{
    journal::{self as codec, Error as JournalError},
    records::keys,
};
use busbar_kernel_wal::{JournalRecord, Record as Original};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek},
    sync::Arc,
};

/// Explicit bounds for metadata retention and original-frame verification.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Maximum retained node and frame inventory bytes.
    pub metadata_bytes: usize,
    /// Maximum reassembled original frame bytes.
    pub max_frame_bytes: usize,
    /// Maximum frame reads, including bridge lookahead.
    pub max_frame_reads: u64,
}

struct FrameFact {
    node: u64,
    sequence: u64,
    hash: Option<[u8; 32]>,
}
struct NodeFact {
    first: usize,
    end: usize,
    verified: codec::VerifiedNode,
}

/// Fully verified frozen journal inventory; emits immutable originals and heads.
/// It grants neither live journal custody nor business replay authority.
pub struct JournalPlan<R> {
    source: Arc<ArchiveSource<R>>,
    bounds: Bounds,
    facts: Vec<FrameFact>,
    nodes: Vec<NodeFact>,
    provenance: Provenance,
    descriptor: [u8; 32],
}
impl<R> std::fmt::Debug for JournalPlan<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalPlan")
            .field("nodes", &self.nodes.len())
            .field("frames", &self.facts.len())
            .finish_non_exhaustive()
    }
}

fn group_identity(key: &Secret<Vec<u8>>) -> Result<Option<(u64, u64)>, Error> {
    let parts =
        keys::components(key.expose(&crate::seal::lend()), b'G').map_err(|_| Error::Corrupt)?;
    if parts.first().copied() != Some(b"J".as_slice()) {
        return Ok(None);
    }
    if parts.len() != 3 {
        return Err(Error::Corrupt);
    }
    let node = u64::from_be_bytes(parts[1].try_into().map_err(|_| Error::Corrupt)?);
    let sequence = u64::from_be_bytes(parts[2].try_into().map_err(|_| Error::Corrupt)?);
    if node == 0 || sequence == 0 {
        return Err(Error::Corrupt);
    }
    Ok(Some((node, sequence)))
}
fn journal_error(error: JournalError) -> Error {
    match error {
        JournalError::Budget | JournalError::Overflow => Error::Bounds,
        _ => Error::Corrupt,
    }
}
fn framed_identity(key: &[u8]) -> Result<(u64, u64, u16), Error> {
    if key.len() != 18 {
        return Err(Error::Corrupt);
    }
    let node = u64::from_be_bytes(key[..8].try_into().map_err(|_| Error::Corrupt)?);
    let sequence = u64::from_be_bytes(key[8..16].try_into().map_err(|_| Error::Corrupt)?);
    let part = u16::from_be_bytes(key[16..].try_into().map_err(|_| Error::Corrupt)?);
    if node == 0 || sequence == 0 {
        return Err(Error::Corrupt);
    }
    Ok((node, sequence, part))
}

/// Reassemble only original count-framed parts. Repeated observations are
/// accepted solely when their complete part bytes agree; no missing part,
/// inconsistent count or logical sealed/stored identity is repaired.
fn assemble(parts: &[Part<'_>], budget: usize) -> Result<Original, Error> {
    let first = parts.first().ok_or(Error::Corrupt)?;
    let (node, sequence, _) = framed_identity(first.key)?;
    let mut slots = std::collections::BTreeMap::new();
    let mut expected = None;
    let mut bytes = 0usize;
    for part in parts {
        let (found_node, found_sequence, ordinal) = framed_identity(part.key)?;
        if found_node != node
            || found_sequence != sequence
            || part.value.len() < 2
            || part.value.len() > busbar_contract::MAX_RECORD_BYTES
        {
            return Err(Error::Corrupt);
        }
        let count = u16::from_be_bytes(part.value[..2].try_into().map_err(|_| Error::Corrupt)?);
        if count == 0 || ordinal >= count || expected.is_some_and(|old| old != count) {
            return Err(Error::Corrupt);
        }
        expected = Some(count);
        if let Some(previous) = slots.get(&ordinal) {
            if *previous != part.value {
                return Err(Error::Corrupt);
            }
        } else {
            bytes = bytes
                .checked_add(part.value.len() - 2)
                .ok_or(Error::Bounds)?;
            if bytes > budget {
                return Err(Error::Bounds);
            }
            slots.insert(ordinal, part.value);
        }
    }
    if slots.len() != usize::from(expected.ok_or(Error::Corrupt)?) {
        return Err(Error::Corrupt);
    }
    let mut original = Vec::new();
    original
        .try_reserve_exact(bytes)
        .map_err(|_| Error::Bounds)?;
    for (expected, (ordinal, value)) in slots.into_iter().enumerate() {
        if usize::from(ordinal) != expected {
            return Err(Error::Corrupt);
        }
        original.extend_from_slice(&value[2..]);
    }
    let decoded = JournalRecord::decode(&original).map_err(|_| Error::Corrupt)?;
    busbar_kernel_wal::verify_journal(std::slice::from_ref(&decoded))
        .map_err(|_| Error::Corrupt)?;
    if decoded.identity() != (node, sequence) || decoded.encode() != original {
        return Err(Error::Corrupt);
    }
    Ok(Original::new(node, sequence, original))
}

fn original_group<R: Read + Seek + Send>(
    source: &ArchiveSource<R>,
    bounds: Bounds,
    node: u64,
    sequence: u64,
    max_frame: usize,
) -> Result<Original, Error> {
    let mut raw_key = [0u8; 18];
    raw_key[..8].copy_from_slice(&node.to_be_bytes());
    raw_key[8..16].copy_from_slice(&sequence.to_be_bytes());
    let key = super::group::journal_group_key(&raw_key).map_err(|_| Error::Corrupt)?;
    let mut chunks = std::collections::BTreeMap::<[u8; 18], Secret<Vec<u8>>>::new();
    let mut payload_bytes = 0usize;
    let mut retain = |raw_key: &[u8], value: &[u8]| -> Result<(), Error> {
        let (found_node, found_sequence, _) = framed_identity(raw_key)?;
        if (found_node, found_sequence) != (node, sequence)
            || value.len() < 2
            || value.len() > busbar_contract::MAX_RECORD_BYTES
        {
            return Err(Error::Corrupt);
        }
        let key: [u8; 18] = raw_key.try_into().map_err(|_| Error::Corrupt)?;
        if let Some(previous) = chunks.get(&key) {
            if previous.expose(&crate::seal::lend()) != value {
                return Err(Error::Corrupt);
            }
        } else {
            payload_bytes = payload_bytes
                .checked_add(value.len() - 2)
                .ok_or(Error::Bounds)?;
            if payload_bytes > max_frame {
                return Err(Error::Bounds);
            }
            // Protocol identities bound the number of slots to u16::MAX;
            // immutable payload retention is additionally capped by max_frame.
            chunks.insert(key, Secret::new(value.to_vec()));
        }
        Ok(())
    };
    source.visit_group_rows(ARCHIVAL, &key, bounds.bytes as usize, &mut |record| {
        let seal = crate::seal::lend();
        let view = source.interpretation().ok_or(Error::MissingCapability)?;
        let fact = view.decode(record.value.expose(&seal), bounds.bytes as usize)?;
        let busbar_contract::persistence::lifecycle::source::HistoricalFact::Record {
            schema,
            key,
            value,
        } = fact.fact()
        else {
            return Err(Error::Corrupt);
        };
        if schema != "busbar.journal.v1" {
            return Err(Error::Corrupt);
        }
        retain(key.expose(&seal), value.expose(&seal))
    })?;
    let seal = crate::seal::lend();
    let parts: Vec<_> = chunks
        .iter()
        .map(|(key, value)| Part {
            key,
            value: value.expose(&seal),
        })
        .collect();
    let original = assemble(&parts, max_frame)?;
    if original.identity() != (node, sequence) {
        return Err(Error::Corrupt);
    }
    Ok(original)
}

struct NodeSource<'a, R> {
    source: &'a ArchiveSource<R>,
    bounds: Bounds,
    facts: &'a mut [FrameFact],
    remaining_reads: &'a mut u64,
    max_frame: usize,
}
impl<R: Read + Seek + Send> codec::IndexedFrames for NodeSource<'_, R> {
    fn count(&self) -> u64 {
        self.facts.len() as u64
    }
    fn frame(&mut self, ordinal: u64) -> std::result::Result<Vec<u8>, JournalError> {
        *self.remaining_reads = self
            .remaining_reads
            .checked_sub(1)
            .ok_or(JournalError::Budget)?;
        let index = usize::try_from(ordinal.checked_sub(1).ok_or(JournalError::Invalid)?)
            .map_err(|_| JournalError::Budget)?;
        let fact = self.facts.get(index).ok_or(JournalError::Corrupt)?;
        let original = original_group(
            self.source,
            self.bounds,
            fact.node,
            fact.sequence,
            self.max_frame,
        )
        .map_err(|error| match error {
            Error::Bounds => JournalError::Budget,
            _ => JournalError::Corrupt,
        })?;
        let hash = JournalRecord::decode(&original.body)
            .map_err(|_| JournalError::Corrupt)?
            .hash;
        let fact = self.facts.get_mut(index).ok_or(JournalError::Corrupt)?;
        if fact.hash.is_some_and(|previous| previous != hash) {
            return Err(JournalError::Corrupt);
        }
        fact.hash = Some(hash);
        Ok(original.body)
    }
}

impl<R: Read + Seek + Send> JournalPlan<R> {
    /// Verify every source node run within the explicit metadata and I/O bounds.
    pub fn verify(
        source: Arc<ArchiveSource<R>>,
        bounds: Bounds,
        budget: Budget,
    ) -> Result<Self, Error> {
        bounds.validate()?;
        if source.interpretation().is_none() {
            return Err(Error::MissingCapability);
        }
        let mut count = 0usize;
        source.visit_group_keys(ARCHIVAL, &mut |key| {
            if group_identity(key)?.is_some() {
                count = count.checked_add(1).ok_or(Error::Bounds)?;
            }
            Ok(())
        })?;
        let metadata = count
            .checked_mul(std::mem::size_of::<FrameFact>())
            .ok_or(Error::Bounds)?;
        if metadata > budget.metadata_bytes {
            return Err(Error::Bounds);
        }
        let mut facts = Vec::new();
        facts.try_reserve_exact(count).map_err(|_| Error::Bounds)?;
        source.visit_group_keys(ARCHIVAL, &mut |key| {
            if let Some((node, sequence)) = group_identity(key)? {
                facts.push(FrameFact {
                    node,
                    sequence,
                    hash: None,
                });
            }
            Ok(())
        })?;
        facts.sort_unstable_by_key(|fact| (fact.node, fact.sequence));
        if facts
            .windows(2)
            .any(|pair| (pair[0].node, pair[0].sequence) == (pair[1].node, pair[1].sequence))
        {
            return Err(Error::Corrupt);
        }
        let node_count = facts
            .iter()
            .enumerate()
            .filter(|(index, fact)| *index == 0 || facts[*index - 1].node != fact.node)
            .count();
        let metadata = node_count
            .checked_mul(std::mem::size_of::<NodeFact>())
            .and_then(|nodes| metadata.checked_add(nodes))
            .ok_or(Error::Bounds)?;
        if metadata > budget.metadata_bytes {
            return Err(Error::Bounds);
        }
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(node_count)
            .map_err(|_| Error::Bounds)?;
        let mut remaining_reads = budget.max_frame_reads;
        let mut first = 0;
        while first < facts.len() {
            let node = facts[first].node;
            let mut end = first + 1;
            while end < facts.len() && facts[end].node == node {
                end += 1;
            }
            let reads = remaining_reads;
            let mut original = NodeSource {
                source: &source,
                bounds,
                facts: &mut facts[first..end],
                remaining_reads: &mut remaining_reads,
                max_frame: budget.max_frame_bytes,
            };
            let verified = codec::verify_source(
                node,
                &mut original,
                codec::SourceBudget {
                    max_frame_bytes: budget.max_frame_bytes,
                    max_reads: reads,
                },
            )
            .map_err(journal_error)?;
            nodes.push(NodeFact {
                first,
                end,
                verified,
            });
            first = end;
        }
        let provenance = Provenance {
            dataset: source.identity().dataset,
            catalogue: source.header().catalogue_digest,
        };
        let mut hash = Sha256::new();
        hash.update(b"busbar.migration.original-journal/1\0");
        hash.update(provenance.dataset);
        hash.update(provenance.catalogue);
        hash.update(source.identity().artifact_digest);
        for node in &nodes {
            hash.update(node.verified.node().to_be_bytes());
            hash.update(node.verified.count().to_be_bytes());
            hash.update(node.verified.original_digest());
        }
        for fact in &facts {
            hash.update(fact.node.to_be_bytes());
            hash.update(fact.sequence.to_be_bytes());
            hash.update(fact.hash.ok_or(Error::Corrupt)?);
        }
        Ok(Self {
            source,
            bounds,
            facts,
            nodes,
            provenance,
            descriptor: hash.finalize().into(),
        })
    }
    /// Enumerate verified original node identities in ascending order.
    pub fn nodes(&self) -> impl Iterator<Item = u64> + '_ {
        self.nodes.iter().map(|node| node.verified.node())
    }
    fn canonical_rows(&self, original: Original) -> Result<CanonicalRows, Error> {
        let index = self
            .facts
            .binary_search_by_key(&original.identity(), |fact| (fact.node, fact.sequence))
            .map_err(|_| Error::Corrupt)?;
        let decoded = JournalRecord::decode(&original.body).map_err(|_| Error::Corrupt)?;
        if self.facts[index].hash != Some(decoded.hash) {
            return Err(Error::Corrupt);
        }
        let node = self
            .nodes
            .iter()
            .find(|node| index >= node.first && index < node.end)
            .ok_or(Error::Corrupt)?;
        let ordinal = u64::try_from(index - node.first + 1).map_err(|_| Error::Bounds)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(3).map_err(|_| Error::Bounds)?;
        rows.push(codec::record(original.node, ordinal, &original).map_err(journal_error)?);
        if index + 1 == node.end {
            rows.push(codec::head(&node.verified));
            rows.push(codec::inventory_row(&node.verified).map_err(journal_error)?);
        }
        Ok(rows)
    }
    pub(crate) fn verified_node(&self, node: u64) -> Option<&codec::VerifiedNode> {
        self.nodes
            .binary_search_by_key(&node, |fact| fact.verified.node())
            .ok()
            .map(|index| &self.nodes[index].verified)
    }
    /// Reread an original frame and check its verified inventory identity.
    pub fn source_frame(
        &self,
        node: u64,
        sequence: u64,
        max_frame_bytes: usize,
    ) -> Result<Original, Error> {
        self.verified_node(node).ok_or(Error::Corrupt)?;
        let index = self
            .facts
            .binary_search_by_key(&(node, sequence), |fact| (fact.node, fact.sequence))
            .map_err(|_| Error::Corrupt)?;
        let original = original_group(&self.source, self.bounds, node, sequence, max_frame_bytes)?;
        if JournalRecord::decode(&original.body)
            .map_err(|_| Error::Corrupt)?
            .hash
            != self.facts[index].hash.ok_or(Error::Corrupt)?
        {
            return Err(Error::Corrupt);
        }
        Ok(original)
    }
}
impl<R: Read + Seek + Send> JournalMigration for JournalPlan<R> {
    fn provenance(&self) -> Provenance {
        self.provenance
    }
    fn descriptor_digest(&self) -> [u8; 32] {
        self.descriptor
    }
    fn inventory_authorizes(&self, address: &busbar_contract::persistence::Address) -> bool {
        if !codec::inventory_address_class(address) {
            return false;
        }
        // The owner class check establishes the canonical logical key ending in
        // its big-endian node. The ID selects a proof, never grants authority.
        let Some(tail) = address.key.get(address.key.len().saturating_sub(8)..) else {
            return false;
        };
        let Ok(raw) = <[u8; 8]>::try_from(tail) else {
            return false;
        };
        let Some(proof) = self.verified_node(u64::from_be_bytes(raw)) else {
            return false;
        };
        codec::inventory_row(proof)
            .is_ok_and(|(_, value)| codec::inventory_matches(proof, address, &value))
    }
    fn visit_verified_nodes(
        &self,
        visitor: &mut dyn FnMut(&codec::VerifiedNode) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for node in &self.nodes {
            visitor(&node.verified)?;
        }
        Ok(())
    }
    fn copy_source_group(
        &self,
        node: u64,
        sequence: u64,
        max_frame_bytes: usize,
    ) -> Result<CanonicalRows, Error> {
        self.canonical_rows(self.source_frame(node, sequence, max_frame_bytes)?)
    }
    fn copy_group(
        &self,
        parts: &[Part<'_>],
        max_frame_bytes: usize,
    ) -> Result<CanonicalRows, Error> {
        let original = assemble(parts, max_frame_bytes)?;
        self.canonical_rows(original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Vec<u8> {
        let body = vec![37; 600];
        let mut frame = JournalRecord {
            class: busbar_kernel_wal::RecordClass::Reconciliation,
            node: 7,
            node_seq: 9,
            lease_epoch: 3,
            policy_epoch: 2,
            wall: 13,
            mono: 17,
            body_hash: busbar_kernel_wal::journal::body_digest(&body),
            body,
            prev_hash: [19; 32],
            hash: [0; 32],
        };
        frame.hash = frame.digest_of_chain();
        frame.encode()
    }

    #[test]
    fn complete_journal_projection_streams_beyond_group_page_item_cap() {
        use busbar_contract::persistence::lifecycle::source::HistoricalFact;
        let original = original();
        let chunks: Vec<_> = original.chunks(510).collect();
        let mut facts = Vec::new();
        for (ordinal, chunk) in chunks.iter().enumerate() {
            let mut key = 7u64.to_be_bytes().to_vec();
            key.extend_from_slice(&9u64.to_be_bytes());
            key.extend_from_slice(&(ordinal as u16).to_be_bytes());
            let mut value = (chunks.len() as u16).to_be_bytes().to_vec();
            value.extend_from_slice(chunk);
            facts.push(HistoricalFact::Record {
                schema: "busbar.journal.v1".into(),
                key: Secret::new(key),
                value: Secret::new(value),
            });
        }
        let source = crate::source_facts::test_archive(facts, 65536);
        let bounds = Bounds {
            items: 1,
            bytes: 4096,
        };
        let mut key = 7u64.to_be_bytes().to_vec();
        key.extend_from_slice(&9u64.to_be_bytes());
        key.extend_from_slice(&0u16.to_be_bytes());
        let group = super::super::group::journal_group_key(&key).unwrap();
        assert!(matches!(
            source.read_group_sync(ARCHIVAL, &group, bounds),
            Err(Error::Bounds)
        ));
        let plan = JournalPlan::verify(
            source,
            bounds,
            Budget {
                metadata_bytes: 4096,
                max_frame_bytes: 4096,
                max_frame_reads: 4,
            },
        )
        .unwrap();
        assert_eq!(plan.source_frame(7, 9, 4096).unwrap().body, original);
        let rows = plan.copy_source_group(7, 9, 4096).unwrap();
        assert_eq!(rows.len(), 3);
        let proof = plan.verified_node(7).unwrap();
        assert!(
            rows.iter()
                .all(|(address, value)| codec::authorizes(address)
                    || codec::inventory_matches(proof, address, value))
        );
        assert_eq!(rows[0].1.expose(&crate::seal::lend()), &original);
    }

    #[test]
    fn original_parts_preserve_frame_and_reject_incomplete_or_changed_evidence() {
        let original = original();
        let chunks: Vec<_> = original.chunks(510).collect();
        let keys: Vec<_> = (0..chunks.len())
            .map(|ordinal| {
                let mut key = Vec::new();
                key.extend_from_slice(&7u64.to_be_bytes());
                key.extend_from_slice(&9u64.to_be_bytes());
                key.extend_from_slice(&(ordinal as u16).to_be_bytes());
                key
            })
            .collect();
        let mut values: Vec<_> = chunks
            .iter()
            .map(|chunk| {
                let mut value = (chunks.len() as u16).to_be_bytes().to_vec();
                value.extend_from_slice(chunk);
                value
            })
            .collect();
        fn parts<'a>(keys: &'a [Vec<u8>], values: &'a [Vec<u8>]) -> Vec<Part<'a>> {
            keys.iter()
                .zip(values)
                .map(|(key, value)| Part { key, value })
                .collect::<Vec<_>>()
        }
        // Retained prefixes may have a nonzero original predecessor; never
        // normalize it while reconstructing the immutable original frame.
        assert_eq!(
            assemble(&parts(&keys, &values), original.len())
                .unwrap()
                .body,
            original
        );
        assert!(matches!(
            assemble(&parts(&keys, &values)[1..], original.len()),
            Err(Error::Corrupt)
        ));
        assert!(matches!(
            assemble(&parts(&keys, &values), original.len() - 1),
            Err(Error::Bounds)
        ));
        values[0][100] ^= 1;
        assert!(matches!(
            assemble(&parts(&keys, &values), original.len()),
            Err(Error::Corrupt)
        ));
    }
}
