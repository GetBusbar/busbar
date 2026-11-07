// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store-owned journal custody; WAL framing and signed body recipes stay unchanged.
//!
//! Writes remain contiguous under their existing owner. Explicit bounded
//! historical snapshots verify retained prefixes and original quarantine bridges
//! with the WAL verifier. Explicit cold transfer requires a native irreversible
//! dataset-epoch fence and records custody metadata atomically. This grants only
//! journal appends; no business replay or adoption decision is manufactured here.

use std::sync::Arc;

use busbar_contract::{
    persistence::{
        Address, Candidate, DatasetId, ExpectedValue, Failure, Mutation, NamespaceId, Predicate,
        PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
    },
    Secret,
};
use busbar_kernel_wal::{JournalBreak, JournalRecord, Record};
use sha2::{Digest, Sha256};

use super::{
    facade::{AccessError, CoreStore, LogicalClaim, LogicalId, Submission, WriterAuthority},
    partition,
};

const JOURNAL: NamespaceId = NamespaceId(*b"busbar.journal4\0");
const HEAD_MAGIC: &[u8; 8] = b"BBJHEAD1";
const OWNER_MAGIC: &[u8; 8] = b"BBJOWN01";

pub(crate) mod historical;
pub(crate) mod migration;
mod transfer;
#[cfg(test)]
pub(crate) use transfer::Handover;
mod recovery_hooks;
pub(crate) use recovery_hooks::Selection;
pub mod runtime;
pub use runtime::{BufferBudget, RuntimeError, RuntimeJournal, StagedRun};

#[derive(Debug)]
pub(crate) enum Error {
    Access(AccessError),
    Backend(Failure),
    Invalid,
    Corrupt,
    Budget,
    Overflow,
    Authority,
    /// Needs explicit historical verification rather than contiguous replay.
    UnsupportedHistory,
    Verification(JournalBreak),
    IncompleteReplay,
}
type Result<T> = std::result::Result<T, Error>;
impl From<AccessError> for Error {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Head {
    count: u64,
    sequence: u64,
    hash: [u8; 32],
}
impl Head {
    fn encode(self) -> Secret<Vec<u8>> {
        let mut bytes = Vec::with_capacity(56);
        bytes.extend_from_slice(HEAD_MAGIC);
        bytes.extend_from_slice(&self.count.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.hash);
        Secret::new(bytes)
    }
    fn decode(bytes: &Secret<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.expose(&crate::seal::lend());
        if bytes.len() != 56 || &bytes[..8] != HEAD_MAGIC {
            return Err(Error::Corrupt);
        }
        let result = Self {
            count: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| Error::Corrupt)?),
            sequence: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| Error::Corrupt)?),
            hash: bytes[24..].try_into().map_err(|_| Error::Corrupt)?,
        };
        if result.count == 0 || result.sequence == 0 {
            return Err(Error::Corrupt);
        }
        Ok(result)
    }
}

fn owner_bytes(authority: WriterAuthority) -> Secret<Vec<u8>> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(OWNER_MAGIC);
    bytes.extend_from_slice(&authority.writer_epoch.to_le_bytes());
    bytes.extend_from_slice(&authority.writer);
    Secret::new(bytes)
}
fn valid_owner(value: &Secret<Vec<u8>>) -> bool {
    let bytes = value.expose(&crate::seal::lend());
    bytes.len() == 32
        && &bytes[..8] == OWNER_MAGIC
        && bytes[8..16] != [0; 8]
        && bytes[16..32] != [0; 16]
}

/// Proof obtained by consuming every original frame up to a selected head, or
/// extending that complete prefix with exact verified originals whose guarded
/// native append received Applied.
/// Its head predicate remains necessary: verification is not a lock on writers.
pub(crate) struct VerifiedHead {
    dataset: DatasetId,
    node: u64,
    head: Head,
    selected: Option<Secret<Vec<u8>>>,
    owner: Option<Secret<Vec<u8>>>,
    // Exact original-byte ancestry, including frames covered by quarantine
    // bridges. This constant-size process-local proof is never a new format.
    records_seal: [u8; 32],
}
fn extend_records_seal(previous: [u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"busbar.journal.original-proof/1\0");
    hash.update(previous);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
impl VerifiedHead {
    pub(crate) fn owner_identity(&self) -> Option<(u64, [u8; 16])> {
        let owner = self.owner.as_ref()?;
        if !valid_owner(owner) {
            return None;
        }
        let bytes = owner.expose(&crate::seal::lend());
        Some((
            u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            bytes[16..32].try_into().ok()?,
        ))
    }
    pub(crate) fn sequence(&self) -> u64 {
        self.head.sequence
    }
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.head.hash
    }
}

/// A completely verified, bounded historical view of one selected immutable
/// prefix. The private head binds it to the selected dataset/node and custody.
pub(crate) struct VerifiedSnapshot {
    head: VerifiedHead,
    history: historical::HistoricalSnapshot,
}
impl VerifiedSnapshot {
    pub(crate) fn head(&self) -> &VerifiedHead {
        &self.head
    }
    pub(crate) fn records(&self) -> &[Record] {
        self.history.records()
    }
}

pub(crate) enum WriteResult {
    Submitted(Submission),
    Busy,
}

/// One node's original journal. Opening for inspection never claims its writer.
pub(crate) struct StoreJournal<'a> {
    store: &'a CoreStore,
    node: u64,
    namespace: NamespaceId,
}
impl<'a> StoreJournal<'a> {
    pub(crate) fn new(store: &'a CoreStore, node: u64) -> Result<Self> {
        if node == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            node,
            namespace: partition::namespace(JOURNAL, &[&node.to_be_bytes()]),
        })
    }
    fn address(&self, tag: u8, ordinal: u64) -> Address {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(&JOURNAL.0);
        key.extend_from_slice(&self.node.to_be_bytes());
        key.push(tag);
        key.extend_from_slice(&ordinal.to_be_bytes());
        Address {
            namespace: self.namespace.0,
            key,
        }
    }
    async fn read(&self, addresses: Vec<Address>) -> Result<Vec<Option<Secret<Vec<u8>>>>> {
        let count = addresses.len();
        let result = self
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.store.info().dataset,
                addresses,
                time: None,
            }))
            .await
            .map_err(Error::Backend)?;
        let ReadResult::Values {
            observed_at,
            values,
        } = result
        else {
            return Err(Error::Corrupt);
        };
        if values.len() != count || observed_at.authority != self.store.info().clock_authority {
            return Err(Error::Corrupt);
        }
        Ok(values)
    }

    /// Select one head and then walk immutable records with constant retained
    /// state. Concurrent appends cannot change this cursor's selected prefix.
    pub(crate) async fn replay(&self) -> Result<Replay<'_, 'a>> {
        let mut rows = self
            .read(vec![self.address(b'H', 0), self.address(b'O', 0)])
            .await?;
        let owner = rows.pop().ok_or(Error::Corrupt)?;
        let selected = rows.pop().ok_or(Error::Corrupt)?;
        if owner.is_some() != selected.is_some() || owner.as_ref().is_some_and(|v| !valid_owner(v))
        {
            return Err(Error::Corrupt);
        }
        let head = selected
            .as_ref()
            .map(Head::decode)
            .transpose()?
            .unwrap_or_default();
        Ok(Replay {
            journal: self,
            target: VerifiedHead {
                dataset: self.store.info().dataset,
                node: self.node,
                head,
                selected,
                owner,
                records_seal: [0; 32],
            },
            observed: Head::default(),
            failed: false,
            historical: false,
            records_seal: [0; 32],
        })
    }

    /// Verify every original frame in the selected prefix using the historical
    /// WAL rules, including retained prefixes and carried quarantine bridges.
    /// The explicit snapshot budget is a host memory admission policy; it does
    /// not change backend page limits or the maximum journal length. Empty
    /// journals use the streaming replay proof instead.
    pub(crate) async fn snapshot(
        &self,
        budget: historical::SnapshotBudget,
    ) -> Result<VerifiedSnapshot> {
        let mut target = self.replay().await?.target;
        let count = usize::try_from(target.head.count).map_err(|_| Error::Budget)?;
        if count == 0 {
            return Err(Error::Invalid);
        }
        if count > budget.records {
            return Err(Error::Budget);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| Error::Budget)?;
        let mut total = 0usize;
        for ordinal in 1..=target.head.count {
            let bytes = self
                .read(vec![self.address(b'R', ordinal)])
                .await?
                .pop()
                .flatten()
                .ok_or(Error::Corrupt)?;
            let bytes = bytes.expose(&crate::seal::lend());
            total = total.checked_add(bytes.len()).ok_or(Error::Overflow)?;
            if total > budget.bytes {
                return Err(Error::Budget);
            }
            let decoded = JournalRecord::decode(bytes).map_err(Error::Verification)?;
            records.push(Record::new(decoded.node, decoded.node_seq, bytes.clone()));
        }
        let history = historical::HistoricalSnapshot::verify(self.node, records, budget)?;
        if history.tail() != (target.head.sequence, target.head.hash) {
            return Err(Error::Corrupt);
        }
        for record in history.records() {
            target.records_seal = extend_records_seal(target.records_seal, &record.body);
        }
        Ok(VerifiedSnapshot {
            head: target,
            history,
        })
    }

    /// Guard a domain-owned recovery candidate against changes to the completely
    /// verified selected prefix. This is evidence custody, not an adoption or
    /// accounting verdict; the recovery owner supplies those effects separately.
    pub(crate) fn selected_head_predicate(&self, proof: &VerifiedHead) -> Result<Predicate> {
        if proof.dataset != self.store.info().dataset || proof.node != self.node {
            return Err(Error::Authority);
        }
        Ok(Predicate {
            address: self.address(b'H', 0),
            expected: proof
                .selected
                .as_ref()
                .map_or(ExpectedValue::Absent, |value| {
                    ExpectedValue::Exact(value.clone())
                }),
        })
    }

    /// Append original frames and select their head in ONE native candidate.
    /// The first append binds this node to its dataset writer epoch and identity.
    /// Native attempt admission fences execution epochs, permitting a live writer
    /// to roll its execution epoch without changing its journal identity. A later
    /// process uses a fresh node unless the host explicitly completes a native
    /// cold-epoch custody transfer of the completely verified old journal.
    ///
    /// Repeating this call with the same proof and records after cancellation or
    /// Unknown resumes the retained exact candidate. Changed input conflicts.
    pub(crate) async fn append(
        &self,
        previous: &VerifiedHead,
        records: &[Record],
    ) -> Result<WriteResult> {
        if previous.dataset != self.store.info().dataset || previous.node != self.node {
            return Err(Error::Authority);
        }
        let owner = owner_bytes(self.store.authority()?);
        if previous.owner.as_ref().is_some_and(|old| old != &owner) {
            return Err(Error::Authority);
        }
        let limits = self.store.limits();
        if records.is_empty() || records.len() > limits.scan_items {
            return Err(Error::Budget);
        }
        let mut bytes = 0usize;
        let mut digest = Sha256::new();
        digest.update(b"busbar.journal.append/1\0");
        digest.update(previous.head.encode().expose(&crate::seal::lend()));
        digest.update(owner.expose(&crate::seal::lend()));
        for record in records {
            bytes = bytes
                .checked_add(record.body.len())
                .ok_or(Error::Overflow)?;
            if bytes > limits.scan_bytes {
                return Err(Error::Budget);
            }
            digest.update(record.node.to_le_bytes());
            digest.update(record.node_seq.to_le_bytes());
            digest.update((record.body.len() as u64).to_le_bytes());
            digest.update(&record.body);
        }
        let mut operation = [0; 16];
        operation[..8].copy_from_slice(&self.node.to_be_bytes());
        let permit = match self.store.claim_logical(
            LogicalId {
                namespace: self.namespace.0,
                operation,
            },
            digest.finalize().into(),
        )? {
            LogicalClaim::Prepare(permit) => permit,
            LogicalClaim::Retained(id) => {
                return Ok(WriteResult::Submitted(self.store.retry(id).await?));
            }
            LogicalClaim::Busy => return Ok(WriteResult::Busy),
        };
        let expected = |value: &Option<Secret<Vec<u8>>>| {
            value
                .as_ref()
                .map_or(ExpectedValue::Absent, |v| ExpectedValue::Exact(v.clone()))
        };
        let mut predicates = vec![
            Predicate {
                address: self.address(b'H', 0),
                expected: expected(&previous.selected),
            },
            Predicate {
                address: self.address(b'O', 0),
                expected: expected(&previous.owner),
            },
        ];
        let mut mutations = Vec::new();
        predicates
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Budget)?;
        mutations
            .try_reserve_exact(records.len() + 2)
            .map_err(|_| Error::Budget)?;
        let mut head = previous.head;
        for record in records {
            let decoded = checked_record(self.node, &record.body, head)?;
            if decoded.identity() != record.identity() {
                return Err(Error::Corrupt);
            }
            head = advance(head, &decoded)?;
            let address = self.address(b'R', head.count);
            predicates.push(Predicate {
                address: address.clone(),
                expected: ExpectedValue::Absent,
            });
            mutations.push(Mutation::Put {
                address,
                value: Secret::new(record.body.clone()),
            });
        }
        if previous.owner.is_none() {
            mutations.push(Mutation::Put {
                address: self.address(b'O', 0),
                value: owner,
            });
        }
        mutations.push(Mutation::Put {
            address: self.address(b'H', 0),
            value: head.encode(),
        });
        let candidate = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)?;
        Ok(WriteResult::Submitted(permit.submit(candidate).await?))
    }
}

fn checked_record(node: u64, bytes: &[u8], previous: Head) -> Result<JournalRecord> {
    let decoded = decode_record(node, bytes)?;
    if decoded.prev_hash != previous.hash
        || (previous.count != 0 && previous.sequence.checked_add(1) != Some(decoded.node_seq))
    {
        return Err(Error::UnsupportedHistory);
    }
    Ok(decoded)
}
fn decode_record(node: u64, bytes: &[u8]) -> Result<JournalRecord> {
    let decoded = JournalRecord::decode(bytes).map_err(Error::Verification)?;
    // Reuse the original verifier and digest recipe, including reserved bytes.
    busbar_kernel_wal::journal::verify(std::slice::from_ref(&decoded))
        .map_err(Error::Verification)?;
    if decoded.node != node || decoded.node_seq == 0 || decoded.encode() != bytes {
        return Err(Error::Corrupt);
    }
    Ok(decoded)
}
fn advance(previous: Head, record: &JournalRecord) -> Result<Head> {
    Ok(Head {
        count: previous.count.checked_add(1).ok_or(Error::Overflow)?,
        sequence: record.node_seq,
        hash: record.hash,
    })
}

/// Returns one verified original frame at a time. A domain must finish the
/// cursor before treating a replay as complete or publishing reconstructed state.
pub(crate) struct Replay<'j, 's> {
    journal: &'j StoreJournal<'s>,
    target: VerifiedHead,
    observed: Head,
    failed: bool,
    historical: bool,
    records_seal: [u8; 32],
}
impl Replay<'_, '_> {
    pub(crate) async fn next(&mut self) -> Result<Option<Record>> {
        if self.failed {
            return Err(Error::IncompleteReplay);
        }
        // Cancellation cannot advance or bless a partially observed prefix.
        let result = self.read_next().await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    async fn read_next(&mut self) -> Result<Option<Record>> {
        if self.observed.count == self.target.head.count {
            if self.observed != self.target.head {
                return Err(Error::Corrupt);
            }
            return Ok(None);
        }
        let ordinal = self.observed.count.checked_add(1).ok_or(Error::Overflow)?;
        let mut rows = self
            .journal
            .read(vec![self.journal.address(b'R', ordinal)])
            .await?;
        let bytes = rows.pop().flatten().ok_or(Error::Corrupt)?;
        let bytes = bytes.expose(&crate::seal::lend());
        if bytes.len() > self.journal.store.limits().scan_bytes {
            return Err(Error::Budget);
        }
        let decoded = if self.historical {
            let decoded = decode_record(self.journal.node, bytes)?;
            if self.observed.count != 0
                && (decoded.prev_hash != self.observed.hash
                    || self.observed.sequence.checked_add(1) != Some(decoded.node_seq))
                && !self
                    .journal
                    .bridge_covers(&self.target, self.observed, &decoded)
                    .await?
            {
                return Err(Error::UnsupportedHistory);
            }
            decoded
        } else {
            checked_record(self.journal.node, bytes, self.observed)?
        };
        let next = advance(self.observed, &decoded)?;
        if next.count == self.target.head.count && next != self.target.head {
            return Err(Error::Corrupt);
        }
        let record = Record::new(decoded.node, decoded.node_seq, bytes.clone());
        self.records_seal = extend_records_seal(self.records_seal, bytes);
        self.observed = next;
        Ok(Some(record))
    }
    pub(crate) fn finish(mut self) -> Result<VerifiedHead> {
        if self.failed || self.observed != self.target.head {
            return Err(Error::IncompleteReplay);
        }
        self.target.records_seal = self.records_seal;
        Ok(self.target)
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
