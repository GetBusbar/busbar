// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Recovery selection and custody over the scoped native journal owner. Original
//! candidate frames, predecessor pointers and attested handovers remain unchanged.

use crate::{
    governance::recovery::{
        RecoveryError, RecoveryEvent, RecoveryInspection, RecoveryLink, RecoveryResolution,
        RecoverySelection, RecoverySink, RecoveryState, RecoveryVerdict,
    },
    persistence::{
        commit::SubmitResult,
        facade::CoreStore,
        journal::{
            runtime::{LiveChange, RuntimeJournal, StagedRun},
            Selection, StoreJournal, VerifiedHead, WriteResult,
        },
        partition,
    },
};
use busbar_contract::{
    caps::{DurableWrite, Grant},
    persistence::{
        Address, Decision, ExpectedValue, NamespaceId, Predicate, Read, ReadResult, Scan,
    },
    Secret,
};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, Record, RecordClass};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

#[path = "recovery_import.rs"]
pub(crate) mod imported;

const RECOVERY: NamespaceId = NamespaceId(*b"busbar.recover1\0");
const TAG: &str = "usage.recovery.v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    node: u64,
    sequence: u64,
    revision: u64,
    event_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    event: RecoveryEvent,
    previous_head: Option<Head>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adoption: Option<AdoptionProof>,
}

/// Operator attestations are audited facts, never inferred from a node lease. The selected
/// verdict digest makes an intermediate unknown checkpoint inert until that verdict is selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionProof {
    version: u8,
    operation_id: [u8; 16],
    body_fingerprint: [u8; 32],
    foreign_head: Head,
    final_event_digest: [u8; 32],
    landed: bool,
    sender_quiesced: bool,
    backend_quiesced: bool,
    actor: String,
    reason: String,
}

#[derive(Clone, Copy)]
struct DecisionTag {
    node: u64,
    revision: u64,
    state: RecoveryState,
    digest: [u8; 32],
}

struct CompactCandidate {
    head: Head,
    link: RecoveryLink,
    payload_hash: [u8; 32],
    adoption: Option<AdoptionProof>,
    newer: Option<DecisionTag>,
}

impl CompactCandidate {
    fn of(head: &Head, candidate: &Candidate, newer: Option<DecisionTag>) -> Self {
        Self {
            head: head.clone(),
            link: RecoveryLink::from_event(&candidate.event),
            payload_hash: busbar_kernel_wal::body_digest(&candidate.event.payload),
            adoption: candidate.adoption.clone(),
            newer,
        }
    }

    fn tag(&self) -> DecisionTag {
        DecisionTag {
            node: self.head.node,
            revision: self.head.revision,
            state: self.link.state,
            digest: self.head.event_digest,
        }
    }
}

impl AdoptionProof {
    fn validate_compact(
        &self,
        parent_head: &Head,
        parent: &RecoveryEvent,
        child: &CompactCandidate,
    ) -> Result<(), RecoveryError> {
        if self.version != 1
            || self.operation_id != child.link.operation_id
            || self.body_fingerprint != child.link.body_fingerprint
            || self.foreign_head != *parent_head
            || parent_head.node == child.head.node
            || !self.sender_quiesced
            || !self.backend_quiesced
            || self.actor.trim().is_empty()
            || self.actor.len() > 256
            || self.reason.trim().is_empty()
            || self.reason.len() > 4096
        {
            return Err(invalid("invalid attested recovery handover proof"));
        }
        let verdict = if self.landed {
            RecoveryState::VerdictLanded
        } else {
            RecoveryState::VerdictNotLanded
        };
        let same_payload = child.payload_hash == busbar_kernel_wal::body_digest(&parent.payload);
        let decision = match parent.state {
            RecoveryState::LandedUnknown if child.link.state == verdict => child.tag(),
            RecoveryState::Intent if child.link.state == RecoveryState::LandedUnknown => {
                let newer = child
                    .newer
                    .ok_or_else(|| invalid("handover verdict is not selected"))?;
                if child.head.revision.checked_add(1) != Some(newer.revision) {
                    return Err(invalid("handover verdict skips the unknown checkpoint"));
                }
                newer
            }
            state if state == verdict && child.link.state == state && same_payload => child.tag(),
            RecoveryState::Applied
                if self.landed && child.link.state == RecoveryState::Applied && same_payload =>
            {
                child.tag()
            }
            RecoveryState::ConditionConflict
                if !self.landed
                    && child.link.state == RecoveryState::ConditionConflict
                    && same_payload =>
            {
                child.tag()
            }
            _ => return Err(invalid("handover changes a foreign recovery decision")),
        };
        let expected = match parent.state {
            RecoveryState::Applied => RecoveryState::Applied,
            RecoveryState::ConditionConflict => RecoveryState::ConditionConflict,
            _ => verdict,
        };
        if decision.node != child.head.node
            || decision.state != expected
            || decision.digest != self.final_event_digest
        {
            return Err(invalid(
                "attested handover decision differs from selected ancestry",
            ));
        }
        Ok(())
    }

    fn matches(&self, resolution: &RecoveryResolution) -> bool {
        self.operation_id == resolution.operation_id
            && self.body_fingerprint == resolution.body_fingerprint
            && self.foreign_head.revision == resolution.expected_revision
            && self.landed == (resolution.verdict == RecoveryVerdict::Landed)
            && self.sender_quiesced == resolution.sender_quiesced
            && self.backend_quiesced == resolution.backend_quiesced
            && self.actor == resolution.actor
            && self.reason == resolution.reason
    }
}

fn unavailable(why: impl std::fmt::Debug) -> RecoveryError {
    let why = format!("{why:?}");
    RecoveryError::Unavailable(why)
}

fn invalid(why: &str) -> RecoveryError {
    let why = why.to_owned();
    RecoveryError::Invalid(why)
}

fn invalid_from(error: &dyn std::fmt::Display) -> RecoveryError {
    let why = error.to_string();
    RecoveryError::Invalid(why)
}

fn body(candidate: &Candidate) -> Result<Vec<u8>, RecoveryError> {
    let mut writer = BodyWriter::new();
    writer.text(TAG);
    let mut body = writer.finish();
    // The candidate is the body's second field, framed exactly as `BodyWriter::bytes` frames
    // one (u64 LE length, then the bytes), but serialized straight into the body rather than
    // through a separate encoding that is then copied in.
    let at = body.len();
    body.extend_from_slice(&0u64.to_le_bytes());
    serde_json::to_writer(&mut body, candidate).map_err(|e| invalid_from(&e))?;
    let len = (body.len() - at - 8) as u64;
    body[at..at + 8].copy_from_slice(&len.to_le_bytes());
    Ok(body)
}

fn candidate(record: &JournalRecord) -> Result<Option<Candidate>, RecoveryError> {
    if record.class != RecordClass::Reconciliation {
        return Ok(None);
    }
    let mut reader = BodyReader::new(&record.body);
    if reader.text() != Some(TAG) {
        return Ok(None);
    }
    let encoded = reader
        .bytes()
        .ok_or_else(|| invalid("truncated recovery candidate"))?;
    if !reader.is_done() {
        return Err(invalid("trailing recovery candidate bytes"));
    }
    serde_json::from_slice(encoded)
        .map(Some)
        .map_err(|e| invalid_from(&e))
}

/// Historical schema_records used the original full operation16 directly as
/// record_key. Validate its exact frozen Head shape, preserving value bytes.
pub(crate) fn legacy_head_address(
    operation: &[u8],
    value: &[u8],
) -> Result<Address, RecoveryError> {
    let operation: &[u8; 16] = operation
        .try_into()
        .map_err(|_| invalid("invalid historical recovery operation identity"))?;
    let head: Head =
        serde_json::from_slice(value).map_err(|_| invalid("invalid historical recovery head"))?;
    if head.version != 1 || head.node == 0 || head.sequence == 0 {
        return Err(invalid("invalid historical recovery head"));
    }
    Ok(address(operation))
}

fn address(operation: &[u8; 16]) -> Address {
    // One allocation at the final size: the namespace tag, then the operation id.
    let mut key = vec![0u8; RECOVERY.0.len() + operation.len()];
    let (tag, id) = key.split_at_mut(RECOVERY.0.len());
    tag.copy_from_slice(&RECOVERY.0);
    id.copy_from_slice(operation);
    Address {
        namespace: partition::namespace(RECOVERY, &[&operation[..1]]).0,
        key,
    }
}
async fn read(
    store: &CoreStore,
    addresses: Vec<Address>,
) -> Result<Vec<Option<Secret<Vec<u8>>>>, RecoveryError> {
    let count = addresses.len();
    let result = store
        .backend()
        .read(Arc::new(Read {
            dataset: store.info().dataset,
            addresses,
            time: None,
        }))
        .await
        .map_err(unavailable)?;
    let ReadResult::Values {
        observed_at,
        values,
    } = result
    else {
        return Err(invalid("unexpected temporal recovery read"));
    };
    if values.len() != count || observed_at.authority != store.info().clock_authority {
        return Err(invalid("invalid native recovery observation"));
    }
    Ok(values)
}
async fn check(store: &CoreStore, predicates: Vec<Predicate>) -> Result<(), RecoveryError> {
    // Move each address into the read instead of cloning it; only the expectations stay behind.
    let (addresses, expected): (Vec<_>, Vec<_>) = predicates
        .into_iter()
        .map(|p| (p.address, p.expected))
        .unzip();
    let values = read(store, addresses).await?;
    for (expected, value) in expected.into_iter().zip(values) {
        let matches = match (expected, value) {
            (ExpectedValue::Absent, None) => true,
            (ExpectedValue::Exact(expected), Some(actual)) => expected == actual,
            _ => false,
        };
        if !matches {
            return Err(RecoveryError::Conflict(
                "recovery evidence changed during verification".into(),
            ));
        }
    }
    Ok(())
}
async fn head(
    store: &CoreStore,
    operation: &[u8; 16],
) -> Result<Option<(Head, Secret<Vec<u8>>)>, RecoveryError> {
    let Some(raw) = read(store, vec![address(operation)]).await?.pop().flatten() else {
        return Ok(None);
    };
    let decoded: Head =
        serde_json::from_slice(raw.expose(&crate::seal::lend())).map_err(|e| invalid_from(&e))?;
    if decoded.version != 1 || decoded.node == 0 || decoded.sequence == 0 {
        return Err(invalid("invalid recovery selection head"));
    }
    Ok(Some((decoded, raw)))
}
async fn heads(store: &CoreStore) -> Result<Vec<([u8; 16], Head)>, RecoveryError> {
    // Generations and pagination are scoped to each independent namespace. Bound
    // backend pressure while avoiding 256 serial round trips on an empty store.
    let mut buckets = stream::iter(0..=u8::MAX)
        .map(|bucket| bucket_heads(store, bucket))
        .buffer_unordered(4);
    let mut result = Vec::new();
    while let Some(bucket) = buckets.next().await {
        result.extend(bucket?);
    }
    result.sort_by_key(|(operation, _)| *operation);
    Ok(result)
}

async fn bucket_heads(
    store: &CoreStore,
    bucket: u8,
) -> Result<Vec<([u8; 16], Head)>, RecoveryError> {
    let mut result = Vec::new();
    let namespace = partition::namespace(RECOVERY, &[&[bucket]]);
    let mut after = None;
    let mut generation = None;
    loop {
        let page = store
            .backend()
            .scan(Arc::new(Scan {
                dataset: store.info().dataset,
                namespace,
                prefix: RECOVERY.0.to_vec(),
                after: after.clone(),
                generation,
                allow_change: false,
                max_items: store.limits().scan_items,
                max_bytes: store.limits().scan_bytes,
            }))
            .await
            .map_err(unavailable)?;
        if generation.is_some_and(|g| g != page.generation) {
            return Err(invalid("recovery scan generation changed"));
        }
        generation = Some(page.generation);
        for (at, value) in page.rows {
            if at.namespace != namespace.0
                || at.key.len() != 32
                || at.key[..16] != RECOVERY.0
                || at.key[16] != bucket
            {
                return Err(invalid("invalid recovery head identity"));
            }
            let operation = at.key[16..].try_into().map_err(|e| invalid_from(&e))?;
            let tip: Head = serde_json::from_slice(value.expose(&crate::seal::lend()))
                .map_err(|e| invalid_from(&e))?;
            if tip.version != 1 || tip.node == 0 || tip.sequence == 0 {
                return Err(invalid("invalid recovery head"));
            }
            result.push((operation, tip));
        }
        match page.next {
            Some(next) if after.as_ref().is_none_or(|old| old < &next) => after = Some(next),
            Some(_) => return Err(invalid("nonprogressing recovery scan")),
            None => break,
        }
    }
    Ok(result)
}

/// Immutable original frames retained only within one verification attempt.
/// Both body allocation and entry metadata are bounded by the native page limits.
/// Frames are shared, so carrying the cache to the next verification copies no
/// body.
#[derive(Clone, Default)]
struct HistoryRecords {
    records: BTreeMap<(u64, u64), (u64, Arc<Record>)>,
    bytes: usize,
}
impl HistoryRecords {
    fn insert(&mut self, ordinal: u64, record: Record, max_entries: usize, max_bytes: usize) {
        let bytes = record.body.capacity();
        if max_entries == 0 || bytes > max_bytes {
            return;
        }
        while self.records.len() >= max_entries || self.bytes > max_bytes - bytes {
            let Some((_, (_, removed))) = self.records.pop_first() else {
                break;
            };
            self.bytes -= removed.body.capacity();
        }
        let identity = record.identity();
        if let Some((_, previous)) = self.records.insert(identity, (ordinal, Arc::new(record))) {
            self.bytes -= previous.body.capacity();
        }
        self.bytes += bytes;
    }
    /// The frames of `node` only: the cache a later verification of this
    /// node's live journal starts from.
    fn of_node(&self, node: u64) -> Self {
        let mut kept = Self::default();
        for (identity, entry) in self.records.range((node, 0)..=(node, u64::MAX)) {
            kept.bytes += entry.1.body.capacity();
            kept.records.insert(*identity, entry.clone());
        }
        kept
    }
}

/// Only a recovery candidate frame is ever looked up by `History::candidate`.
fn is_candidate_frame(record: &Record) -> bool {
    JournalRecord::decode(&record.body)
        .is_ok_and(|frame| frame.class == RecordClass::Reconciliation)
}

/// The last proof of this node's own journal that was completed by reading its
/// originals from the Store, with the bounded cache of this node's recovery
/// frames that reading kept. The next verification beside the live owner
/// continues from it and reads only the originals appended since.
#[derive(Clone)]
struct VerifiedJournal {
    proof: Arc<VerifiedHead>,
    records: HistoryRecords,
}

#[cfg(test)]
#[test]
fn history_records_bound_allocations_and_leave_misses_for_verified_fallback() {
    let mut cache = HistoryRecords::default();
    cache.insert(1, Record::new(1, 1, vec![1; 4]), 2, 8);
    cache.insert(1, Record::new(1, 2, vec![2; 4]), 2, 8);
    cache.insert(1, Record::new(2, 1, vec![3; 4]), 2, 8);
    assert_eq!(cache.records.len(), 2);
    assert_eq!(cache.bytes, 8);
    assert!(!cache.records.contains_key(&(1, 1)));
    // Charge allocated capacity even when the body length is small. A frame
    // that cannot fit is a normal cache miss, never a verification refusal.
    let mut oversized = Vec::with_capacity(9);
    oversized.push(4);
    cache.insert(1, Record::new(2, 2, oversized), 2, 8);
    assert!(!cache.records.contains_key(&(2, 2)));
    assert_eq!(cache.bytes, 8);
    cache.insert(1, Record::new(3, 1, vec![5]), 1, 8);
    assert_eq!(cache.records.len(), 1);
    assert_eq!(cache.bytes, 1);
}

/// One verification attempt streams and proves the complete immutable prefix.
/// Its bounded frame cache avoids replaying that prefix for each ancestry link;
/// cache misses still use the original verified reader.
struct History<'a> {
    store: &'a CoreStore,
    proofs: BTreeMap<u64, Arc<VerifiedHead>>,
    records: HistoryRecords,
    /// Set for any verification made beside this node's live journal owner:
    /// a read-only observation, or this owner's own recovery write. That owner
    /// keeps appending (audit, usage, checkpoints), so this node's proof is
    /// confirmed as a prefix of the owner's current admitted head instead of
    /// being pinned. The proof is a verified reading of every original, made
    /// whole here or continued from `base`.
    live: Option<&'a RuntimeJournal>,
    /// Beside the live owner only: this node's last proof completed from Store
    /// originals. This node's proof continues from it, reading only the
    /// originals appended after it; each must link to the one before.
    base: Option<Arc<VerifiedHead>>,
}
impl<'a> History<'a> {
    fn new(store: &'a CoreStore) -> Self {
        Self {
            store,
            proofs: BTreeMap::new(),
            records: HistoryRecords::default(),
            live: None,
            base: None,
        }
    }
    fn observing(store: &'a CoreStore, journal: &'a RuntimeJournal) -> Self {
        Self {
            live: Some(journal),
            ..Self::new(store)
        }
    }
    /// Beside the live owner, continuing from this node's last verified proof
    /// and its cached recovery frames. Without one it is a plain observation.
    fn continuing(
        store: &'a CoreStore,
        journal: &'a RuntimeJournal,
        verified: Option<VerifiedJournal>,
    ) -> Self {
        let mut history = Self::observing(store, journal);
        if let Some(verified) = verified {
            history.base = Some(verified.proof);
            history.records = verified.records;
        }
        history
    }
    /// This node's proof and recovery frames, for the next verification beside
    /// the live owner to continue from.
    fn verified(&self) -> Option<VerifiedJournal> {
        let node = self.live?.node();
        Some(VerifiedJournal {
            proof: self.proofs.get(&node)?.clone(),
            records: self.records.of_node(node),
        })
    }
    async fn proof(&mut self, node: u64) -> Result<Arc<VerifiedHead>, RecoveryError> {
        if let Some(proof) = self.proofs.get(&node) {
            return Ok(proof.clone());
        }
        let journal = StoreJournal::new(self.store, node).map_err(unavailable)?;
        let local = self.live.is_some_and(|live| live.node() == node);
        let mut cursor = match self.base.as_deref().filter(|_| local) {
            Some(base) => journal.historical_replay_after(base).await,
            None => journal.historical_replay().await,
        }
        .map_err(unavailable)?;
        // Keep staging private until the entire prefix and its seal are valid.
        // Taking the old cache also bounds the total retained allocation while
        // proving another node; a failed proof simply discards cached frames.
        let mut staged = std::mem::take(&mut self.records);
        let limits = self.store.limits();
        let mut ordinal = cursor.position();
        while let Some(record) = cursor.next().await.map_err(unavailable)? {
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| invalid("journal ordinal overflow"))?;
            // The live journal also carries audit, usage and checkpoint frames;
            // only its recovery frames are ever looked up, so only they are
            // kept, and the bounded cache holds the newest of them.
            if !local || is_candidate_frame(&record) {
                staged.insert(ordinal, record, limits.scan_items, limits.scan_bytes);
            }
        }
        let proof = Arc::new(cursor.finish().map_err(unavailable)?);
        self.records = staged;
        self.proofs.insert(node, proof.clone());
        Ok(proof)
    }
    async fn candidate(&mut self, at: &Head) -> Result<Candidate, RecoveryError> {
        let proof = self.proof(at.node).await?;
        let journal = StoreJournal::new(self.store, at.node).map_err(unavailable)?;
        if let Some((ordinal, record)) = self.records.records.get(&(at.node, at.sequence)) {
            journal
                .confirm_original_record(&proof, *ordinal, record)
                .await
                .map_err(unavailable)?;
            return Self::decode_candidate(record);
        }
        let record = journal
            .read_verified_record(&proof, at.sequence)
            .await
            .map_err(unavailable)?;
        Self::decode_candidate(&record)
    }
    fn decode_candidate(record: &Record) -> Result<Candidate, RecoveryError> {
        let decoded = JournalRecord::decode(&record.body).map_err(|e| invalid_from(&e))?;
        if decoded.identity() != record.identity() {
            return Err(invalid("recovery key and sealed identity differ"));
        }
        candidate(&decoded)?.ok_or_else(|| invalid("selected frame is not a recovery candidate"))
    }
    async fn finish(&self) -> Result<(), RecoveryError> {
        let live = self
            .live
            .filter(|journal| self.proofs.contains_key(&journal.node()));
        let mut predicates = Vec::new();
        for (node, proof) in &self.proofs {
            if live.is_some_and(|journal| journal.node() == *node) {
                continue;
            }
            predicates.extend(
                StoreJournal::new(self.store, *node)
                    .map_err(unavailable)?
                    .selected_predicates(proof)
                    .map_err(unavailable)?,
            );
        }
        check(self.store, predicates).await?;
        if let Some(journal) = live {
            match self.proofs.get(&journal.node()) {
                Some(proof) => confirm_this_node(self.store, journal, proof).await?,
                None => journal
                    .confirm_live_owned(None)
                    .await
                    .map_err(unavailable)?,
            }
        }
        Ok(())
    }
    async fn selection(
        &mut self,
        operation: &[u8; 16],
        tip: &Head,
        mut visit: impl FnMut(&Head, &Candidate) -> Result<(), RecoveryError> + Send,
    ) -> Result<RecoverySelection, RecoveryError> {
        let mut next = tip.clone();
        let mut selected = None;
        let mut child: Option<CompactCandidate> = None;
        loop {
            let at = next;
            if at.version != 1 || at.node == 0 || at.sequence == 0 {
                return Err(invalid("invalid recovery predecessor pointer"));
            }
            let candidate = self.candidate(&at).await?;
            if candidate.event.operation_id != *operation
                || candidate.event.revision != at.revision
                || candidate.event.fingerprint()? != at.event_digest
            {
                return Err(invalid("selected recovery identity differs"));
            }
            if selected.is_none() {
                selected = Some(candidate.event.clone());
            }
            if let Some(child) = &child {
                child.link.follows(Some(&candidate.event))?;
                if child.head.node == at.node {
                    if child.adoption.is_some() || at.sequence >= child.head.sequence {
                        return Err(invalid(
                            "recovery predecessor is not an earlier owned record",
                        ));
                    }
                } else {
                    child
                        .adoption
                        .as_ref()
                        .ok_or_else(|| invalid("recovery ownership changed without attestation"))?
                        .validate_compact(&at, &candidate.event, child)?;
                }
            }
            visit(&at, &candidate)?;
            match &candidate.previous_head {
                Some(previous)
                    if previous.revision.checked_add(1) == Some(at.revision)
                        && candidate.event.previous_event == Some(previous.event_digest) =>
                {
                    next = previous.clone()
                }
                None if at.revision == 0
                    && candidate.event.previous_event.is_none()
                    && candidate.adoption.is_none() =>
                {
                    candidate.event.follows(None)?;
                    return Ok(RecoverySelection {
                        initial: candidate.event,
                        selected: selected.expect("selected endpoint"),
                    });
                }
                _ => return Err(invalid("invalid selected recovery predecessor")),
            }
            let newer = child.as_ref().map(CompactCandidate::tag);
            child = Some(CompactCandidate::of(&at, &candidate, newer));
        }
    }
}

/// How a verification treats this node's own selected journal head.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pin {
    /// Prove and confirm this node's ownership. Every write path and owned
    /// check uses it. A pinned History requires the exact head; a History
    /// beside the live owner requires a prefix of its admitted head.
    Strict,
    /// A read-only observation beside the live journal owner, which keeps
    /// appending. Its admission is confirmed once by the caller instead.
    Live,
}

#[derive(Clone)]
struct Pending {
    event: RecoveryEvent,
    record: Record,
    head: Head,
    predecessor: Option<Secret<Vec<u8>>>,
    run: Arc<StagedRun>,
    selection_proof: Option<Arc<VerifiedHead>>,
    /// A re-driven uncertain attempt met a definite no-effect: its first crossing may still
    /// land, so it is never resubmitted and only reconciliation resolves it.
    reconciling: bool,
}
#[derive(Clone)]
struct PendingAdoption {
    proof: AdoptionProof,
    guards_digest: [u8; 32],
    guards: Arc<[Predicate]>,
    transitions: Vec<RecoveryEvent>,
    records: Vec<Record>,
    target: Head,
    predecessor: Secret<Vec<u8>>,
    runs: Vec<Arc<StagedRun>>,
    selection_proof: Option<Arc<VerifiedHead>>,
}
#[derive(Default)]
struct DriverState {
    pending: BTreeMap<[u8; 16], Pending>,
    adoptions: BTreeMap<[u8; 16], PendingAdoption>,
    driving: BTreeSet<[u8; 16]>,
}

/// Scoped recovery domain owner. Its only backend is the opened CoreStore and
/// its original native journal; no caller can supply a raw candidate or address.
pub struct StoreRecovery {
    journal: Arc<RuntimeJournal>,
    store: Arc<CoreStore>,
    node: u64,
    _token: Grant<DurableWrite>,
    state: Mutex<DriverState>,
    /// This node's last journal proof completed from Store originals, which
    /// the next persist beside the live owner continues from.
    verified: Mutex<Option<VerifiedJournal>>,
    retirements: crate::persistence::boot_identity::WriterRetirements,
}
struct Driving<'a> {
    sink: &'a StoreRecovery,
    operation: [u8; 16],
}
impl Drop for Driving<'_> {
    fn drop(&mut self) {
        self.sink
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .driving
            .remove(&self.operation);
    }
}
impl StoreRecovery {
    pub fn new(
        journal: Arc<RuntimeJournal>,
        token: Grant<DurableWrite>,
    ) -> Result<Self, RecoveryError> {
        let node = journal.node();
        let store = journal.store().clone();
        if node == 0 {
            return Err(invalid("recovery node must be nonzero"));
        }
        Ok(Self {
            journal,
            store,
            node,
            _token: token,
            state: Mutex::new(DriverState::default()),
            verified: Mutex::new(None),
            retirements: Default::default(),
        })
    }
    /// Test probe: the evidence carried for this node's own original `seq` (stub: none yet).
    #[cfg(test)]
    pub(crate) fn carried(
        &self,
        _seq: u64,
    ) -> Option<crate::persistence::journal::runtime::Carried> {
        None
    }
    fn drive(&self, operation: [u8; 16]) -> Result<Driving<'_>, RecoveryError> {
        if !self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .driving
            .insert(operation)
        {
            return Err(unavailable("recovery operation has an active driver"));
        }
        Ok(Driving {
            sink: self,
            operation,
        })
    }
    /// Save the proof `change_live` will CAS against into the retained entry,
    /// synchronously under its driver and before any native claim. A resolved
    /// (missing) entry stays absent.
    fn retain_pending(&self, operation: [u8; 16], proof: &Arc<VerifiedHead>) {
        if let Some(pending) = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
            .get_mut(&operation)
        {
            pending.selection_proof = Some(proof.clone());
        }
    }
    fn retain_adoption(&self, operation: [u8; 16], proof: &Arc<VerifiedHead>) {
        if let Some(pending) = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .adoptions
            .get_mut(&operation)
        {
            pending.selection_proof = Some(proof.clone());
        }
    }
    /// A History beside this node's live owner that continues from its last
    /// verified journal proof, so a persist reads only the originals appended
    /// since instead of replaying the whole journal.
    fn continuing(&self) -> History<'_> {
        let verified = self
            .verified
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        History::continuing(&self.store, &self.journal, verified)
    }
    /// Keep `history`'s proof of this node once its whole verification has
    /// succeeded. A later proof never yields to an earlier one.
    fn keep_verified(&self, history: &History<'_>) {
        let Some(verified) = history.verified() else {
            return;
        };
        let mut kept = self.verified.lock().unwrap_or_else(|p| p.into_inner());
        if kept
            .as_ref()
            .is_none_or(|kept| kept.proof.sequence() <= verified.proof.sequence())
        {
            *kept = Some(verified);
        }
    }
    async fn owned(&self) -> Result<Arc<VerifiedHead>, RecoveryError> {
        let mut history = History::observing(&self.store, &self.journal);
        self.owned_with_history(&mut history).await
    }
    async fn owned_with_history(
        &self,
        history: &mut History<'_>,
    ) -> Result<Arc<VerifiedHead>, RecoveryError> {
        let proof = history.proof(self.node).await?;
        self.confirm_local(history, &proof).await?;
        Ok(proof)
    }
    /// Confirm this node's `proof` is owned and admitted. A pinned History
    /// requires the exact head. A History beside this node's live owner
    /// requires the owner's admitted head to extend `proof`: that owner keeps
    /// appending on the request path, so the originals after `proof` are read
    /// and must link to it and reproduce the live head and its original-byte
    /// seal exactly, then that head's H and O rows and admission are checked.
    /// A forked, rewritten or damaged tail, or a fence, epoch or owner change,
    /// refuses. Selection itself is guarded separately, under the publication
    /// driver against the live head.
    async fn confirm_local(
        &self,
        history: &History<'_>,
        proof: &VerifiedHead,
    ) -> Result<(), RecoveryError> {
        if let Some(journal) = history.live.filter(|journal| journal.node() == self.node) {
            return confirm_this_node(&self.store, journal, proof).await;
        }
        StoreJournal::new(&self.store, self.node)
            .map_err(unavailable)?
            .confirm_owned(proof)
            .await
            .map_err(unavailable)
    }
    /// Verify a checkpoint this owner just wrote (or found already written):
    /// complete ancestry and ownership, beside its own live journal.
    async fn verify_written_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let mut history = self.continuing();
        self.verify_checkpoint_with_history(event, true, Pin::Strict, &mut history)
            .await?;
        self.keep_verified(&history);
        Ok(())
    }
    async fn verify_origin_at(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let mut history = History::observing(&self.store, &self.journal);
        self.verify_origin_with_history(event, Pin::Strict, &mut history)
            .await
    }
    async fn verify_origin_with_history(
        &self,
        event: &RecoveryEvent,
        pin: Pin,
        history: &mut History<'_>,
    ) -> Result<(), RecoveryError> {
        let local = match pin {
            Pin::Strict => Some(self.owned_with_history(history).await?),
            Pin::Live => None,
        };
        let current = head(&self.store, &event.operation_id).await?;
        let initial = match &current {
            Some((tip, _)) => {
                history
                    .selection(&event.operation_id, tip, |_, _| Ok(()))
                    .await?
                    .initial
            }
            None => {
                event.follows(None)?;
                event.clone()
            }
        };
        if event.kind != initial.kind
            || event.body_fingerprint != initial.body_fingerprint
            || event.first_sent_at_ms != initial.first_sent_at_ms
            || (event.revision == 0 && event != &initial)
            || event.origin_reference()? != initial.origin_reference()?
        {
            return Err(invalid("recovery child genesis identity changed"));
        }
        let mut predicates = vec![Predicate {
            address: address(&event.operation_id),
            expected: current.as_ref().map_or(ExpectedValue::Absent, |(_, raw)| {
                ExpectedValue::Exact(raw.clone())
            }),
        }];
        if let Some(origin) = initial.origin_reference()? {
            let (tip, raw) = head(&self.store, &origin.operation_id)
                .await?
                .ok_or_else(|| invalid("recovery origin has no selected parent"))?;
            let mut parent = None;
            history
                .selection(&origin.operation_id, &tip, |at, candidate| {
                    if at.event_digest == origin.event_fingerprint {
                        parent = Some(candidate.event.clone())
                    }
                    Ok(())
                })
                .await?;
            parent
                .ok_or_else(|| invalid("recovery origin is outside selected parent ancestry"))?
                .authorizes_child(&initial)?;
            predicates.push(Predicate {
                address: address(&origin.operation_id),
                expected: ExpectedValue::Exact(raw),
            });
        }
        history.finish().await?;
        check(&self.store, predicates).await?;
        let Some(local) = local else {
            return Ok(());
        };
        self.confirm_local(history, &local).await
    }
    async fn verify_checkpoint_at(
        &self,
        event: &RecoveryEvent,
        owned: bool,
    ) -> Result<(), RecoveryError> {
        let mut history = History::observing(&self.store, &self.journal);
        self.verify_checkpoint_with_history(event, owned, Pin::Strict, &mut history)
            .await
    }
    async fn verify_checkpoint_with_history(
        &self,
        event: &RecoveryEvent,
        owned: bool,
        pin: Pin,
        history: &mut History<'_>,
    ) -> Result<(), RecoveryError> {
        let (tip, raw) = head(&self.store, &event.operation_id)
            .await?
            .ok_or_else(|| invalid("checkpoint has no selected operation"))?;
        if owned && tip.node != self.node {
            return Err(RecoveryError::Conflict(
                "checkpoint belongs to another node".into(),
            ));
        }
        let mut found = None;
        let digest = event.fingerprint()?;
        history
            .selection(&event.operation_id, &tip, |at, candidate| {
                if at.event_digest == digest {
                    found = Some(candidate.event.clone())
                }
                Ok(())
            })
            .await?;
        if found.as_ref() != Some(event) {
            return Err(RecoveryError::Conflict(
                "checkpoint is outside current selected ancestry".into(),
            ));
        }
        self.verify_origin_with_history(event, pin, history).await?;
        history.finish().await?;
        if pin == Pin::Strict {
            // Beside the live owner, `owned_with_history` already proved this
            // proof extends to the owner's live head, original by original,
            // and checked that exact live head's H and O rows and admission in
            // one read: the exact-head check of the head that now exists. The
            // owned predicates of this earlier proof would refuse every
            // request-path append made since. Only a pinned History rechecks
            // its own exact head here.
            let proof = self.owned_with_history(history).await?;
            if !history
                .live
                .is_some_and(|journal| journal.node() == self.node)
            {
                check(
                    &self.store,
                    StoreJournal::new(&self.store, self.node)
                        .map_err(unavailable)?
                        .owned_predicates(&proof)
                        .map_err(unavailable)?,
                )
                .await?;
            }
        }
        check(
            &self.store,
            vec![Predicate {
                address: address(&event.operation_id),
                expected: ExpectedValue::Exact(raw),
            }],
        )
        .await
    }
    async fn selection(
        &self,
        operation: &[u8; 16],
        tip: &Head,
    ) -> Result<RecoverySelection, RecoveryError> {
        let mut history = History::observing(&self.store, &self.journal);
        let selection = history.selection(operation, tip, |_, _| Ok(())).await?;
        history.finish().await?;
        Ok(selection)
    }
    async fn adopted_selection(
        &self,
        tip: &Head,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        let mut history = History::observing(&self.store, &self.journal);
        let mut attested = false;
        let result = history
            .selection(&resolution.operation_id, tip, |_, candidate| {
                attested |= candidate.adoption.as_ref().is_some_and(|proof| {
                    proof.final_event_digest == tip.event_digest && proof.matches(resolution)
                });
                Ok(())
            })
            .await?;
        history.finish().await?;
        if transitions.last() != Some(&result.selected) || !attested {
            return Err(RecoveryError::Conflict(
                "selected handover differs from attested decision".into(),
            ));
        }
        Ok(result)
    }
}

/// Confirm this node's `proof` is owned and admitted: either the store still
/// holds exactly that head (one read), or this node's one writer vouches that
/// its live head extends the proof (only the tail after it is read, outside
/// the writer's driver). The writer keeps appending on the request path, so an
/// exact match alone would lose to every append made since the proof.
async fn confirm_this_node(
    store: &CoreStore,
    journal: &RuntimeJournal,
    proof: &VerifiedHead,
) -> Result<(), RecoveryError> {
    let exact = StoreJournal::new(store, journal.node())
        .map_err(unavailable)?
        .confirm_owned(proof)
        .await;
    if exact.is_ok() {
        return Ok(());
    }
    journal
        .confirm_live_owned(Some(proof))
        .await
        .map_err(unavailable)
}
fn applied(result: WriteResult) -> Result<bool, RecoveryError> {
    match result {
        WriteResult::Submitted(submission) => match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(true),
                Decision::ConditionConflict => Ok(false),
                _ => Err(unavailable("recovery candidate requires reconciliation")),
            },
            _ => Err(unavailable(
                "recovery candidate remains retained and unconfirmed",
            )),
        },
        WriteResult::Busy => Err(unavailable(
            "recovery candidate has an active native submission",
        )),
    }
}
impl StoreRecovery {
    async fn persist_at(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let _driving = self.drive(event.operation_id)?;
        let saved = {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .get(&event.operation_id)
                .cloned()
        };
        let pending = if let Some(saved) = saved {
            if saved.event != *event {
                return Err(RecoveryError::Conflict(
                    "another immutable recovery candidate is pending".into(),
                ));
            }
            saved
        } else {
            // One preflight attempt shares immutable evidence only until the
            // staging boundary; every use still confirms live native guards.
            // This node's own journal keeps taking request-path appends while
            // the proof is verified, so it is confirmed beside the live owner,
            // continuing from the last verified proof of this node.
            let mut history = self.continuing();
            let current = head(&self.store, &event.operation_id).await?;
            let selected = if let Some((tip, _)) = &current {
                if tip.node != self.node {
                    return Err(RecoveryError::Conflict(
                        "recovery operation belongs to another node".into(),
                    ));
                }
                let selected = history
                    .selection(&event.operation_id, tip, |_, _| Ok(()))
                    .await?;
                history.finish().await?;
                Some(selected)
            } else {
                None
            };
            if selected.as_ref().is_some_and(|s| s.selected == *event) {
                self.verify_checkpoint_with_history(event, true, Pin::Strict, &mut history)
                    .await?;
                self.keep_verified(&history);
                return Ok(());
            }
            event.follows(selected.as_ref().map(|s| &s.selected))?;
            self.verify_origin_with_history(event, Pin::Strict, &mut history)
                .await?;
            self.owned_with_history(&mut history).await?;
            self.keep_verified(&history);
            drop(history);
            let body = body(&Candidate {
                event: event.clone(),
                previous_head: current.as_ref().map(|(tip, _)| tip.clone()),
                adoption: None,
            })?;
            let run = self
                .journal
                .stage_run(&[Entry::new(RecordClass::Reconciliation, body)
                    .at(crate::store::now_ms() / 1000, 0)])
                .map_err(unavailable)?;
            let record = run.records()[0].clone();
            let pending = Pending {
                event: event.clone(),
                head: Head {
                    version: 1,
                    node: self.node,
                    sequence: record.node_seq,
                    revision: event.revision,
                    event_digest: event.fingerprint()?,
                },
                record,
                predecessor: current.map(|(_, raw)| raw),
                run,
                selection_proof: None,
                reconciling: false,
            };
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .insert(event.operation_id, pending.clone());
            pending
        };
        if pending.reconciling {
            return Err(unavailable(
                "recovery candidate remains retained and unconfirmed",
            ));
        }
        // A retained proof means an earlier crossing of this exact attempt has an
        // unknown outcome (cancelled or reply lost).
        let redrive = pending.selection_proof.is_some();
        if !redrive {
            self.journal
                .confirm(&pending.run)
                .await
                .map_err(unavailable)?;
        }
        let selection = Selection {
            operation_id: event.operation_id,
            address: address(&event.operation_id),
            expected: pending
                .predecessor
                .clone()
                .map_or(ExpectedValue::Absent, ExpectedValue::Exact),
            value: Secret::new(serde_json::to_vec(&pending.head).map_err(|e| invalid_from(&e))?),
        };
        // Built and submitted under the journal's publication driver against its
        // live head (or the exact retained proof). The proof is saved into this
        // pending entry under the driver, before any native claim.
        let operation = event.operation_id;
        let (_, result) = self
            .journal
            .change_live(
                std::slice::from_ref(&pending.record),
                LiveChange::Select {
                    selection,
                    guards: &[],
                },
                pending.selection_proof.clone(),
                &|proof: &Arc<VerifiedHead>| self.retain_pending(operation, proof),
            )
            .await
            .map_err(unavailable)?;
        let selected = applied(result)?;
        if !selected && redrive {
            // The re-drive's no-effect does not resolve the earlier crossing, which
            // may still land: keep the exact attempt and never resubmit it.
            if let Some(saved) = self
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .get_mut(&event.operation_id)
            {
                saved.reconciling = true;
            }
            return Err(unavailable(
                "recovery candidate remains retained and unconfirmed",
            ));
        }
        if !selected {
            // (SHUTDOWN-HANG F2.1) Classify the definitive no-effect by one read of the selection
            // row. Unchanged: the CAS ran under the driver against the live head, so it failed on
            // our custody (fenced, epoch moved) or on one of our originals; neither is another
            // selector, and the entry is kept.
            let current = head(&self.store, &event.operation_id).await?;
            let unchanged = match (current.as_ref(), pending.predecessor.as_ref()) {
                (None, None) => true,
                (Some((_, row)), Some(previous)) => {
                    row.expose(&crate::seal::lend()) == previous.expose(&crate::seal::lend())
                }
                _ => false,
            };
            if unchanged {
                if let Some(saved) = self
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pending
                    .get_mut(&event.operation_id)
                {
                    saved.selection_proof = None;
                }
                return Err(match self.journal.confirm_with(&[]).await {
                    Err(lost) => unavailable(lost),
                    Ok(()) => invalid("journal original differs at computed ordinal (Corrupt)"),
                });
            }
            // A definitive no-effect may coincide with another exact selector.
            // Its complete current ancestry remains the only acceptable proof.
            // This node's ownership is re-proved first, then the selection.
            // Only a genuine selection conflict discards the pending work; a
            // transient refusal keeps it and the next attempt re-proves (PERFPASS-F2 T2c).
            let verified = async {
                let mut history = self.continuing();
                self.owned_with_history(&mut history).await?;
                drop(history);
                self.verify_written_checkpoint(event).await
            };
            match verified.await {
                Ok(()) => {}
                Err(RecoveryError::Conflict(_)) => {
                    self.state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pending
                        .remove(&event.operation_id);
                    return Err(RecoveryError::Conflict(
                        "another recovery candidate won selection".into(),
                    ));
                }
                Err(error) => {
                    if let Some(saved) = self
                        .state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pending
                        .get_mut(&event.operation_id)
                    {
                        // The definite no-effect resolved that attempt: the next
                        // one proves against the live head again.
                        saved.selection_proof = None;
                    }
                    return Err(error);
                }
            }
        } else {
            self.verify_written_checkpoint(event).await?;
        }
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
            .remove(&event.operation_id);
        Ok(())
    }
    async fn adopt_at(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        self.adopt_at_with(resolution, transitions, &[]).await
    }
    async fn adopt_at_with(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
        guards: &[Predicate],
    ) -> Result<RecoverySelection, RecoveryError> {
        let guards_digest = imported::guards_digest(guards);
        if !resolution.sender_quiesced
            || !resolution.backend_quiesced
            || resolution.actor.trim().is_empty()
            || resolution.actor.len() > 256
            || resolution.reason.trim().is_empty()
            || resolution.reason.len() > 4096
            || !(1..=2).contains(&transitions.len())
        {
            return Err(invalid(
                "handover requires explicit quiescence, actor, reason and legal verdict chain",
            ));
        }
        if transitions.iter().any(|e| {
            e.operation_id != resolution.operation_id
                || e.body_fingerprint != resolution.body_fingerprint
        }) {
            return Err(invalid("handover operation identity differs"));
        }
        let _driving = self.drive(resolution.operation_id)?;
        let saved = {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .adoptions
                .get(&resolution.operation_id)
                .cloned()
        };
        let pending = if let Some(saved) = saved {
            if !saved.proof.matches(resolution)
                || saved.transitions != transitions
                || saved.guards_digest != guards_digest
            {
                return Err(RecoveryError::Conflict(
                    "another immutable handover is pending".into(),
                ));
            }
            saved
        } else {
            let (current, raw) = head(&self.store, &resolution.operation_id)
                .await?
                .ok_or_else(|| invalid("foreign recovery operation does not exist"))?;
            if current.node == self.node {
                let result = self
                    .adopted_selection(&current, resolution, transitions)
                    .await?;
                self.verify_checkpoint_at(&result.selected, true).await?;
                return Ok(result);
            }
            let selected = self.selection(&resolution.operation_id, &current).await?;
            let foreign = &selected.selected;
            if foreign.revision != resolution.expected_revision
                || foreign.body_fingerprint != resolution.body_fingerprint
            {
                return Err(RecoveryError::Conflict(
                    "foreign recovery identity or revision differs".into(),
                ));
            }
            let verdict = if resolution.verdict == RecoveryVerdict::Landed {
                RecoveryState::VerdictLanded
            } else {
                RecoveryState::VerdictNotLanded
            };
            let last = transitions.last().expect("nonempty transitions");
            let legal = match foreign.state {
                RecoveryState::Intent => {
                    transitions.len() == 2
                        && transitions[0].state == RecoveryState::LandedUnknown
                        && last.state == verdict
                }
                RecoveryState::LandedUnknown => transitions.len() == 1 && last.state == verdict,
                state if state == verdict => {
                    transitions.len() == 1 && last.state == state && last.payload == foreign.payload
                }
                RecoveryState::Applied => {
                    resolution.verdict == RecoveryVerdict::Landed
                        && transitions.len() == 1
                        && last.state == RecoveryState::Applied
                        && last.payload == foreign.payload
                }
                RecoveryState::ConditionConflict => {
                    resolution.verdict == RecoveryVerdict::NotLanded
                        && transitions.len() == 1
                        && last.state == RecoveryState::ConditionConflict
                        && last.payload == foreign.payload
                }
                _ => false,
            };
            if !legal {
                return Err(RecoveryError::Conflict(
                    "foreign decision cannot be changed by handover".into(),
                ));
            }
            let mut previous = foreign;
            for event in transitions {
                event.follows(Some(previous))?;
                self.verify_origin_at(event).await?;
                previous = event;
            }
            let proof = AdoptionProof {
                version: 1,
                operation_id: resolution.operation_id,
                body_fingerprint: resolution.body_fingerprint,
                foreign_head: current.clone(),
                final_event_digest: last.fingerprint()?,
                landed: resolution.verdict == RecoveryVerdict::Landed,
                sender_quiesced: resolution.sender_quiesced,
                backend_quiesced: resolution.backend_quiesced,
                actor: resolution.actor.clone(),
                reason: resolution.reason.clone(),
            };
            self.owned().await?;
            let mut runs = Vec::new();
            let mut records = Vec::new();
            let mut previous_head = current;
            let staged_at = crate::store::now_ms() / 1000;
            for (index, event) in transitions.iter().enumerate() {
                let encoded = body(&Candidate {
                    event: event.clone(),
                    previous_head: Some(previous_head),
                    adoption: (index == 0).then(|| proof.clone()),
                })?;
                let run = self
                    .journal
                    .stage_run(&[Entry::new(RecordClass::Reconciliation, encoded).at(staged_at, 0)])
                    .map_err(unavailable)?;
                let record = run.records()[0].clone();
                previous_head = Head {
                    version: 1,
                    node: self.node,
                    sequence: record.node_seq,
                    revision: event.revision,
                    event_digest: event.fingerprint()?,
                };
                records.push(record);
                runs.push(run);
            }
            let pending = PendingAdoption {
                proof,
                guards_digest,
                guards: imported::copy_guards(guards),
                transitions: transitions.to_vec(),
                records,
                target: previous_head,
                predecessor: raw,
                runs,
                selection_proof: None,
            };
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .adoptions
                .insert(resolution.operation_id, pending.clone());
            pending
        };
        if pending.selection_proof.is_none() {
            for run in &pending.runs {
                self.journal.confirm(run).await.map_err(unavailable)?;
            }
        }
        let selection = Selection {
            operation_id: resolution.operation_id,
            address: address(&resolution.operation_id),
            expected: ExpectedValue::Exact(pending.predecessor.clone()),
            value: Secret::new(serde_json::to_vec(&pending.target).map_err(|e| invalid_from(&e))?),
        };
        // As for `persist_at`: under the publication driver, proof retained in
        // this adoption entry before any native claim.
        let operation = resolution.operation_id;
        let (_, result) = self
            .journal
            .change_live(
                &pending.records,
                LiveChange::Select {
                    selection,
                    guards: &pending.guards,
                },
                pending.selection_proof.clone(),
                &|proof: &Arc<VerifiedHead>| self.retain_adoption(operation, proof),
            )
            .await
            .map_err(unavailable)?;
        let committed = applied(result)?;
        let current = head(&self.store, &resolution.operation_id)
            .await?
            .ok_or_else(|| invalid("selected handover disappeared"))?;
        let verified = self
            .adopted_selection(&current.0, resolution, transitions)
            .await;
        if !committed && verified.is_err() {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .adoptions
                .remove(&resolution.operation_id);
            return Err(RecoveryError::Conflict(
                "another recovery decision won handover".into(),
            ));
        }
        let result = verified?;
        self.verify_checkpoint_at(&result.selected, true).await?;
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .adoptions
            .remove(&resolution.operation_id);
        Ok(result)
    }
}
#[async_trait::async_trait]
impl RecoverySink for StoreRecovery {
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.persist_at(event).await
    }
    async fn replay_selections(&self) -> Result<Vec<RecoverySelection>, RecoveryError> {
        self.adopt_pending().await?;
        let local = self.owned().await?;
        let mut result = Vec::new();
        for (operation, tip) in heads(&self.store).await? {
            if tip.node == self.node {
                let selected = self.selection(&operation, &tip).await?;
                self.verify_checkpoint_at(&selected.selected, true).await?;
                result.push(selected);
            }
        }
        confirm_this_node(&self.store, &self.journal, &local).await?;
        Ok(result)
    }
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        self.adopt_pending().await?;
        let local = self.owned().await?;
        let mut events = Vec::new();
        for (operation, tip) in heads(&self.store).await? {
            if tip.node == self.node {
                let mut history = History::observing(&self.store, &self.journal);
                let mut chain = Vec::new();
                history
                    .selection(&operation, &tip, |_, candidate| {
                        chain.push(candidate.event.clone());
                        Ok(())
                    })
                    .await?;
                history.finish().await?;
                chain.reverse();
                self.verify_checkpoint_at(chain.last().expect("selected chain"), true)
                    .await?;
                events.extend(chain);
            }
        }
        confirm_this_node(&self.store, &self.journal, &local).await?;
        Ok(events)
    }
    async fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.verify_checkpoint_at(event, false).await
    }
    async fn confirm_owned_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.verify_checkpoint_at(event, true).await
    }
    async fn verify_origin(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.verify_origin_at(event).await
    }
    /// Read-only listing beside this node's live journal owner, which keeps
    /// appending. Foreign evidence stays exactly pinned; this node is proved by
    /// live admission, never by pinning a head its own writer is free to move.
    async fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        let mut result = Vec::new();
        for (operation, tip) in heads(&self.store).await? {
            if tip.node != self.node {
                let mut history = History::observing(&self.store, &self.journal);
                let selection = history.selection(&operation, &tip, |_, _| Ok(())).await?;
                history.finish().await?;
                self.verify_checkpoint_with_history(
                    &selection.selected,
                    false,
                    Pin::Live,
                    &mut history,
                )
                .await?;
                result.push(RecoveryInspection {
                    owner_node: tip.node,
                    event: selection.selected,
                });
            }
        }
        // An empty listing still proves this node is admitted.
        self.journal
            .confirm_live_owned(None)
            .await
            .map_err(unavailable)?;
        Ok(result)
    }
    async fn adopt_verdict_selection(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        self.adopt_at(resolution, transitions).await
    }
    async fn adopt_verdict(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        let selection = self.adopt_at(resolution, transitions).await?;
        let tip = head(&self.store, &resolution.operation_id)
            .await?
            .ok_or_else(|| invalid("selected handover disappeared"))?
            .0;
        let mut history = History::observing(&self.store, &self.journal);
        let mut events = Vec::new();
        history
            .selection(&resolution.operation_id, &tip, |_, candidate| {
                events.push(candidate.event.clone());
                Ok(())
            })
            .await?;
        history.finish().await?;
        events.reverse();
        if events.last() != Some(&selection.selected) {
            return Err(RecoveryError::Conflict(
                "handover advanced during replay".into(),
            ));
        }
        Ok(events)
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
