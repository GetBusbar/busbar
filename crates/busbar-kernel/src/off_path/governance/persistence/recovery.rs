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
            runtime::{Carried, LiveChange, RuntimeError, RuntimeJournal, StagedRun},
            Error as JournalError, ForeignJournal, OwnHistory, Pin, Replay, RowChange, Selection,
            VerifiedHead, WriteResult,
        },
        partition,
    },
};
use busbar_contract::{
    caps::{DurableWrite, Grant},
    json,
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
    json::to_writer(&mut body, candidate).map_err(|e| invalid_from(&e))?;
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
    json::parse(encoded).map(Some).map_err(|e| invalid_from(&e))
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
    let head: Head = json::parse(value).map_err(|_| invalid("invalid historical recovery head"))?;
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
        json::parse(raw.expose(&crate::seal::lend())).map_err(|e| invalid_from(&e))?;
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
            let tip: Head =
                json::parse(value.expose(&crate::seal::lend())).map_err(|e| invalid_from(&e))?;
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

/// One node's journal as a History reads it (SHUTDOWN-HANG R15): this node's own, cold, from its
/// custody owner, or another node's, read-only. Neither has a CAS or a custody check.
enum NodeJournal<'a> {
    Own(OwnHistory<'a>),
    Foreign(ForeignJournal<'a>),
}
impl<'a> NodeJournal<'a> {
    /// The historical verifier; this node's own continues from `base` when given.
    async fn replay(&self, base: Option<&VerifiedHead>) -> Result<Replay<'_, 'a>, JournalError> {
        match (self, base) {
            (Self::Own(own), Some(base)) => own.replay_after(base).await,
            (Self::Own(own), None) => own.replay().await,
            (Self::Foreign(foreign), _) => foreign.proof().await,
        }
    }
    async fn record(&self, proof: &VerifiedHead, sequence: u64) -> Result<Record, RecoveryError> {
        match self {
            Self::Own(own) => own.record(proof, sequence).await,
            Self::Foreign(foreign) => foreign.record(proof, sequence).await,
        }
        .map_err(unavailable)
    }
    async fn confirm_original(
        &self,
        proof: &VerifiedHead,
        ordinal: u64,
        original: &Record,
    ) -> Result<(), RecoveryError> {
        match self {
            Self::Own(own) => own.confirm_original(proof, ordinal, original).await,
            Self::Foreign(foreign) => foreign.confirm_original(proof, ordinal, original).await,
        }
        .map_err(unavailable)
    }
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
    /// Beside the live owner only: the evidence this process carries for its own originals
    /// (SHUTDOWN-HANG F1). An own hop it names is read once by its computed ordinal and checked
    /// against the carried hash, with no proof of this node built at all.
    carried: Option<&'a Mutex<DriverState>>,
    /// An own original was read by carried evidence, so `finish` confirms this node's custody
    /// even when no proof of it was built.
    own_read: bool,
    /// This node's head as the live owner vouched for it in `owned_with_history`, when no proof
    /// of this node was built: confirming it needs one custody read, never the driver.
    own_verified: Option<Arc<VerifiedHead>>,
    /// Own originals read through a proof (not carried), as `(sequence, chain hash)`: the boot
    /// replay carries them for operations still unsettled.
    own_seen: Vec<Carried>,
}
impl<'a> History<'a> {
    fn new(store: &'a CoreStore) -> Self {
        Self {
            store,
            proofs: BTreeMap::new(),
            records: HistoryRecords::default(),
            live: None,
            base: None,
            carried: None,
            own_read: false,
            own_verified: None,
            own_seen: Vec::new(),
        }
    }
    /// The evidence carried for this node's own original `sequence`, if any.
    fn carried_hash(&self, node: u64, sequence: u64) -> Option<Carried> {
        self.live.filter(|journal| journal.node() == node)?;
        let state = self.carried?.lock().unwrap_or_else(|p| p.into_inner());
        state.carried.get(&sequence).map(|(hash, _owners)| Carried {
            seq: sequence,
            hash: *hash,
        })
    }
    fn observing(store: &'a CoreStore, journal: &'a RuntimeJournal) -> Self {
        Self {
            live: Some(journal),
            ..Self::new(store)
        }
    }
    /// The same History, reading own hops by the evidence `state` carries (SHUTDOWN-HANG F1).
    fn carrying(mut self, state: &'a Mutex<DriverState>) -> Self {
        self.carried = Some(state);
        self
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
    /// `node`'s journal as this History may read it (R15): this node's own through the live
    /// owner, any other node read-only through it. A History with no owner reads nothing outside
    /// tests.
    fn journal_of(&self, node: u64) -> Result<NodeJournal<'a>, RecoveryError> {
        match self.live {
            Some(live) if live.node() == node => {
                live.history().map(NodeJournal::Own).map_err(unavailable)
            }
            Some(live) => live
                .foreign(node)
                .map(NodeJournal::Foreign)
                .map_err(unavailable),
            None => Self::unowned(self.store, node),
        }
    }
    #[cfg(test)]
    fn unowned(store: &'a CoreStore, node: u64) -> Result<NodeJournal<'a>, RecoveryError> {
        ForeignJournal::unowned(store, node)
            .map(NodeJournal::Foreign)
            .map_err(unavailable)
    }
    #[cfg(not(test))]
    fn unowned(_: &'a CoreStore, _: u64) -> Result<NodeJournal<'a>, RecoveryError> {
        Err(invalid(
            "a recovery history without its journal owner reads no journal",
        ))
    }
    async fn proof(&mut self, node: u64) -> Result<Arc<VerifiedHead>, RecoveryError> {
        if let Some(proof) = self.proofs.get(&node) {
            return Ok(proof.clone());
        }
        let journal = self.journal_of(node)?;
        let local = matches!(journal, NodeJournal::Own(_));
        // Keep staging private until the entire prefix and its seal are valid.
        // Taking the old cache also bounds the total retained allocation while
        // proving another node; a failed proof simply discards cached frames.
        let mut staged = std::mem::take(&mut self.records);
        let mut base = self.base.clone().filter(|_| local);
        let mut restarts = 0;
        let proof = loop {
            match self
                .walk_from(&journal, base.as_deref(), local, &mut staged)
                .await
            {
                Err(JournalError::Rebased) if restarts < 3 => {
                    restarts += 1;
                    staged = HistoryRecords::default();
                    base = None;
                }
                Err(JournalError::Rebased) => return Err(unavailable(JournalError::Busy)),
                done => break Arc::new(done.map_err(unavailable)?),
            }
        };
        self.records = staged;
        self.proofs.insert(node, proof.clone());
        Ok(proof)
    }

    async fn walk_from(
        &self,
        journal: &NodeJournal<'_>,
        base: Option<&VerifiedHead>,
        local: bool,
        staged: &mut HistoryRecords,
    ) -> Result<VerifiedHead, JournalError> {
        let mut cursor = journal.replay(base).await?;
        let limits = self.store.limits();
        let mut ordinal = cursor.position();
        while let Some(record) = cursor.next().await? {
            ordinal = ordinal.checked_add(1).ok_or(JournalError::Overflow)?;
            // The live journal also carries audit, usage and checkpoint frames;
            // only its recovery frames are ever looked up, so only they are
            // kept, and the bounded cache holds the newest of them.
            if !local || is_candidate_frame(&record) {
                staged.insert(ordinal, record, limits.scan_items, limits.scan_bytes);
            }
        }
        cursor.finish()
    }
    async fn candidate(&mut self, at: &Head) -> Result<Candidate, RecoveryError> {
        // (SHUTDOWN-HANG F1) An own original this process appended (or the boot replay verified)
        // is read lane-free at its computed ordinal and must be the bytes it carried: no replay.
        if let (Some(live), Some(carried)) = (self.live, self.carried_hash(at.node, at.sequence)) {
            let record = live.record(carried).await.map_err(carried_error)?;
            self.own_read = true;
            return Self::decode_candidate(&record).map(|(candidate, _)| candidate);
        }
        let proof = self.proof(at.node).await?;
        let journal = self.journal_of(at.node)?;
        let local = matches!(journal, NodeJournal::Own(_));
        let record = match self.records.records.get(&(at.node, at.sequence)) {
            Some((ordinal, record)) => {
                journal.confirm_original(&proof, *ordinal, record).await?;
                record.clone()
            }
            None => journal.record(&proof, at.sequence).await?,
        };
        let (candidate, hash) = Self::decode_candidate(&record)?;
        if local {
            self.own_seen.push(Carried {
                seq: at.sequence,
                hash,
            });
        }
        Ok(candidate)
    }
    /// The candidate a recovery original carries, and the original's chain hash.
    fn decode_candidate(record: &Record) -> Result<(Candidate, [u8; 32]), RecoveryError> {
        let decoded = JournalRecord::decode(&record.body).map_err(|e| invalid_from(&e))?;
        if decoded.identity() != record.identity() {
            return Err(invalid("recovery key and sealed identity differ"));
        }
        let candidate = candidate(&decoded)?
            .ok_or_else(|| invalid("selected frame is not a recovery candidate"))?;
        Ok((candidate, decoded.hash))
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
            match self.journal_of(*node)? {
                NodeJournal::Foreign(foreign) => {
                    predicates.extend(foreign.predicates(proof).map_err(unavailable)?)
                }
                NodeJournal::Own(_) => continue,
            }
        }
        check(self.store, predicates).await?;
        if let Some(journal) = live {
            match self.proofs.get(&journal.node()) {
                Some(proof) => confirm_this_node(journal, proof).await?,
                None => journal
                    .confirm_live_owned(None)
                    .await
                    .map_err(unavailable)?,
            }
        } else if let Some(journal) = self.live.filter(|_| self.own_read) {
            // Own originals read by carried evidence, with no proof of this node: one lane-free
            // read of H, O and admission (SHUTDOWN-HANG F1 `confirm_with`).
            journal.confirm_with(&[]).await.map_err(unavailable)?;
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
    /// The last crossing definitely applied nothing and our authority was lost or could not be
    /// read: every later drive repeats only the authority read until it passes, so nothing is
    /// resubmitted under lost authority (owner ruling 2026-11-16).
    authority_first: bool,
    /// Who may drive this staged original (SHUTDOWN-HANG F3.2).
    owner: Owner,
}
/// A member of the unresolved batch is driven only by that batch, with exactly its membership;
/// any other entry is driven by whichever driver comes next, reusing its staged original, so one
/// Reconciliation original exists per (operation, revision).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Single,
    Batch(u64),
}
/// The one recovery batch attempt that may still apply (SHUTDOWN-HANG F3.2): one CAS selecting
/// every member's staged original under one operation id.
#[derive(Clone)]
struct BatchAttempt {
    id: u64,
    operation: [u8; 16],
    members: Vec<[u8; 16]>,
    /// The proof the attempt CASes against, retained under the publication driver before any
    /// native claim; `None` until its first crossing and after a definite no-effect re-arm.
    proof: Option<Arc<VerifiedHead>>,
    /// As `Pending::authority_first`, for the whole batch.
    authority_first: bool,
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
    /// At most one batch attempt may still apply (F3.2).
    batch: Option<BatchAttempt>,
    next_batch: u64,
    /// The chain hash of each own Reconciliation original this process holds evidence for, by
    /// sequence (SHUTDOWN-HANG F1): inserted when its append is confirmed, or by the boot replay's
    /// verified walk; about 56 B each, RAM only.
    carried: BTreeMap<u64, ([u8; 32], usize)>,
    /// The carried sequences of each operation, dropped by `release(op)`.
    carried_by_op: BTreeMap<[u8; 16], Vec<u64>>,
    /// A row stays pinned until its last unsettled operation releases its carried evidence.
    pins: BTreeMap<u64, Pin>,
}
impl DriverState {
    fn carry(&mut self, operation: [u8; 16], carried: Carried) {
        let seqs = self.carried_by_op.entry(operation).or_default();
        if !seqs.contains(&carried.seq) {
            seqs.push(carried.seq);
            let (_, owners) = self.carried.entry(carried.seq).or_insert((carried.hash, 0));
            *owners += 1;
        }
    }
    /// Whether `operation`'s staged original belongs to the batch attempt that may still apply.
    fn batch_owned(&self, operation: &[u8; 16]) -> bool {
        match self.pending.get(operation).map(|pending| pending.owner) {
            Some(Owner::Batch(id)) => self.batch.as_ref().is_some_and(|batch| batch.id == id),
            _ => false,
        }
    }
}

/// The evidence `run` carries for its original at `seq`.
fn carried_of(run: &StagedRun, seq: u64) -> Option<Carried> {
    run.carried().find(|carried| carried.seq == seq)
}

fn carried_error(error: RuntimeError) -> RecoveryError {
    match error {
        RuntimeError::Corrupt => {
            invalid("recovery original differs from carried evidence (Corrupt)")
        }
        other => unavailable(other),
    }
}

/// An operation's current selection: its head and the raw row (`None` before its first).
type Current = Option<(Head, Secret<Vec<u8>>)>;

/// Candidates whose pre-checks run at once in one batch (each is a few store reads).
const PRECHECKS: usize = 16;

/// What one batch crossing decided.
enum Crossed {
    /// Every member is selected; their events, for the post-write verification.
    Applied(Vec<RecoveryEvent>),
    /// A definite no-effect on the attempt's first crossing: `conflict` for a failed condition,
    /// otherwise a refusal of the whole candidate.
    Definite {
        attempt: BatchAttempt,
        conflict: bool,
        why: RecoveryError,
    },
    /// A re-driven in-doubt attempt met a definite no-effect with our authority intact (owner
    /// ruling 2026-11-16): the same members, re-armed under a new operation id, to re-select
    /// whole against the live head.
    Reselect(BatchAttempt),
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
    /// Serialises batch drivers: one batch attempt at a time (F3.2).
    batching: tokio::sync::Mutex<()>,
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
            batching: tokio::sync::Mutex::new(()),
        })
    }
    /// Test probe: the evidence carried for this node's own original `seq`.
    #[cfg(test)]
    pub(crate) fn carried(&self, seq: u64) -> Option<Carried> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .carried
            .get(&seq)
            .map(|(hash, _owners)| Carried { seq, hash: *hash })
    }
    fn carry(&self, operation: [u8; 16], carried: Option<Carried>) {
        if let Some(carried) = carried {
            let pin = self.journal.pin(carried.seq);
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(pin) = pin {
                state.pins.entry(carried.seq).or_insert(pin);
            }
            state.carry(operation, carried);
        }
    }
    /// Drop every sequence carried for `operation` (F1 `RecoverySink::release`).
    fn release_carried(&self, operation: [u8; 16]) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(seqs) = state.carried_by_op.remove(&operation) {
            for seq in seqs {
                if let Some((_, owners)) = state.carried.get_mut(&seq) {
                    *owners -= 1;
                    if *owners == 0 {
                        state.carried.remove(&seq);
                        state.pins.remove(&seq);
                    }
                }
            }
        }
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
        History::continuing(&self.store, &self.journal, verified).carrying(&self.state)
    }
    /// A History beside this node's live owner that reads own hops by carried evidence.
    fn history(&self) -> History<'_> {
        History::observing(&self.store, &self.journal).carrying(&self.state)
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
        // (SHUTDOWN-HANG F1) Beside the live owner with carried evidence, and no proof of this
        // node built yet: the owner's own verified head, confirmed in one lane-free read of H, O
        // and admission. No original is replayed; own hops are read by their carried hashes.
        if history.carried.is_some() && !history.proofs.contains_key(&self.node) {
            if let Some(journal) = history.live.filter(|journal| journal.node() == self.node) {
                journal.confirm_with(&[]).await.map_err(unavailable)?;
                let verified = journal.verified().map_err(unavailable)?;
                history.own_verified = Some(verified.clone());
                return Ok(verified);
            }
        }
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
            if history
                .own_verified
                .as_deref()
                .is_some_and(|own| std::ptr::eq(own, proof))
            {
                // The owner's own head (F1): one lane-free custody read, never the driver.
                return journal.confirm_with(&[]).await.map_err(unavailable);
            }
            return confirm_this_node(journal, proof).await;
        }
        self.journal.confirm_exact(proof).await.map_err(unavailable)
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
        let mut history = self.history();
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
        let mut history = self.history();
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
                    self.journal.owned_predicates(&proof).map_err(unavailable)?,
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
        let mut history = self.history();
        let selection = history.selection(operation, tip, |_, _| Ok(())).await?;
        history.finish().await?;
        Ok(selection)
    }
    /// `selection`, carrying the verified own hops of an operation still unsettled (SHUTDOWN-HANG
    /// F1, the boot replay): its next persist reads them by their hashes, with no replay.
    async fn selection_carried(
        &self,
        operation: &[u8; 16],
        tip: &Head,
    ) -> Result<RecoverySelection, RecoveryError> {
        let mut history = self.history();
        let selection = history.selection(operation, tip, |_, _| Ok(())).await?;
        history.finish().await?;
        if selection.selected.state != RecoveryState::Settled {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            for carried in history.own_seen.drain(..) {
                if let Some(pin) = self.journal.pin(carried.seq) {
                    state.pins.entry(carried.seq).or_insert(pin);
                }
                state.carry(*operation, carried);
            }
        }
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
    journal: &RuntimeJournal,
    proof: &VerifiedHead,
) -> Result<(), RecoveryError> {
    let exact = journal.confirm_exact(proof).await;
    if exact.is_ok() {
        return Ok(());
    }
    journal
        .confirm_live_owned(Some(proof))
        .await
        .map_err(unavailable)
}
/// A crossing whose outcome our authority decides (SHUTDOWN-HANG F2.1(1)): an in-doubt send the
/// store answered fenced or stale (`Reconcile`), or a fenced or stale decision. Never re-selected.
fn fenced_shape(result: &WriteResult) -> bool {
    match result {
        WriteResult::Submitted(submission) => match &submission.result {
            SubmitResult::Reconcile => true,
            SubmitResult::Decided(decision) => {
                matches!(decision.as_ref(), Decision::Fenced | Decision::Stale)
            }
            _ => false,
        },
        WriteResult::Busy => false,
    }
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
/// What one single-operation selection crossing decided.
enum Selected {
    Applied,
    /// A definite condition conflict: nothing applied.
    Conflict,
    /// A definite no-effect refusal of the whole candidate (a fence answers like a size refusal).
    Refused(RecoveryError),
}
fn selection_outcome(result: WriteResult) -> Result<Selected, RecoveryError> {
    match result {
        WriteResult::Submitted(submission) => match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(Selected::Applied),
                Decision::ConditionConflict => Ok(Selected::Conflict),
                Decision::TimeGuardFailed { .. } => Ok(Selected::Refused(unavailable(
                    "recovery temporal guard refused",
                ))),
                _ => Err(unavailable("recovery candidate requires reconciliation")),
            },
            SubmitResult::NoEffect(failure) => Ok(Selected::Refused(unavailable(failure))),
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
    /// The entry's last crossing resolved with no effect: nothing is retained, and the next
    /// crossing re-selects the same staged original against the live head.
    fn clear_retained(&self, operation: [u8; 16]) {
        if let Some(pending) = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
            .get_mut(&operation)
        {
            pending.selection_proof = None;
            pending.authority_first = false;
        }
    }
    /// Our authority is lost or unread after a crossing that applied nothing: the staged original
    /// is kept for the successor, nothing is retained, and every later drive repeats only the
    /// authority read (owner ruling 2026-11-16: never resubmitted).
    fn hold_for_authority(&self, operation: [u8; 16]) {
        if let Some(pending) = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
            .get_mut(&operation)
        {
            pending.selection_proof = None;
            pending.authority_first = true;
        }
    }
    async fn persist_at(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let _driving = self.drive(event.operation_id)?;
        let saved = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.batch_owned(&event.operation_id) {
                // (SHUTDOWN-HANG F3.2) The batch that staged this original may still apply: it is
                // resolved with exactly its membership first, and nothing is staged twice.
                return Err(unavailable(
                    "recovery candidate is owned by an unresolved batch",
                ));
            }
            state.pending.get(&event.operation_id).cloned()
        };
        let pending = if let Some(saved) = saved {
            if saved.event != *event {
                return Err(RecoveryError::Conflict(
                    "another immutable recovery candidate is pending".into(),
                ));
            }
            saved
        } else {
            let Some(current) = self.prepare(event).await? else {
                return Ok(());
            };
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
                authority_first: false,
                owner: Owner::Single,
            };
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .insert(event.operation_id, pending.clone());
            pending
        };
        let operation = event.operation_id;
        if pending.authority_first {
            // (owner ruling 2026-11-16) Our authority was lost or unread after a crossing that
            // applied nothing: only the authority read repeats until it passes.
            self.authority().await?;
            self.clear_retained(operation);
        }
        // A retained proof means an earlier crossing of this exact attempt has an
        // unknown outcome (cancelled or reply lost).
        let mut retained = pending.selection_proof.clone();
        if retained.is_none() {
            self.journal
                .confirm(&pending.run)
                .await
                .map_err(unavailable)?;
            // (F1) The original is in the prefix at its sequence: evidence from here on, before
            // the select and every post-write verification.
            self.carry(
                event.operation_id,
                carried_of(&pending.run, pending.record.node_seq),
            );
        }
        let value = json::to_vec(&pending.head).map_err(|e| invalid_from(&e))?;
        // At most two crossings: a re-drive of the retained attempt, then (after a definite
        // no-effect and our authority read) one re-select of the same staged original.
        let selected = loop {
            let redrive = retained.is_some();
            let selection = Selection {
                operation_id: operation,
                address: address(&operation),
                expected: pending
                    .predecessor
                    .clone()
                    .map_or(ExpectedValue::Absent, ExpectedValue::Exact),
                value: Secret::new(value.clone()),
            };
            // Built and submitted under the journal's publication driver against its
            // live head (or the exact retained proof). The proof is saved into this
            // pending entry under the driver, before any native claim.
            let (_, result) = self
                .journal
                .change_live(
                    std::slice::from_ref(&pending.record),
                    LiveChange::Select {
                        selection,
                        guards: &[],
                    },
                    retained.take(),
                    &|proof: &Arc<VerifiedHead>| self.retain_pending(operation, proof),
                )
                .await
                .map_err(unavailable)?;
            if fenced_shape(&result) {
                // (F2.1(1)) A fenced in-doubt send, or a fenced or stale decision, is never
                // re-selected. Our authority decides it: lost, it is `Authority` and the attempt
                // is never resubmitted; otherwise it stays retained for reconciliation.
                if let Err(lost) = self.authority().await {
                    self.hold_for_authority(operation);
                    return Err(lost);
                }
            }
            match selection_outcome(result)? {
                Selected::Applied => break true,
                Selected::Conflict if !redrive => break false,
                Selected::Conflict => {
                    // (F2.1(1), owner ruling 2026-11-16 "Re-select, after authority check") The
                    // re-drive resubmitted the retained attempt under its own commit key, and the
                    // store answers an attempt that already applied as Applied: this condition
                    // conflict is a definitive no-effect. Our authority first: lost, it is
                    // `Authority` and nothing is resubmitted; otherwise the same staged original
                    // is re-selected once under current custody.
                    if let Err(lost) = self.authority().await {
                        self.hold_for_authority(operation);
                        return Err(lost);
                    }
                    self.clear_retained(operation);
                }
                Selected::Refused(why) => {
                    // A definite no-effect that is not a condition (a refusal of the whole
                    // candidate): a fence answers like a size refusal, so our authority first
                    // (F3.2 step 4 for a batch of one). Lost, nothing is resubmitted; otherwise
                    // the next drive re-selects the same staged original.
                    if let Err(lost) = self.authority().await {
                        self.hold_for_authority(operation);
                        return Err(lost);
                    }
                    self.clear_retained(operation);
                    return Err(why);
                }
            }
        };
        if !selected {
            self.no_effect(event, &pending.head, pending.predecessor.as_ref())
                .await?;
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

    /// One candidate's pre-checks before staging (shared by `persist_at` and the batch). `None`
    /// when its exact event is already selected (verified in place); otherwise the current
    /// selection it must follow (`None` when the operation has none yet).
    async fn prepare(&self, event: &RecoveryEvent) -> Result<Option<Current>, RecoveryError> {
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
            return Ok(None);
        }
        event.follows(selected.as_ref().map(|s| &s.selected))?;
        self.verify_origin_with_history(event, Pin::Strict, &mut history)
            .await?;
        self.owned_with_history(&mut history).await?;
        self.keep_verified(&history);
        Ok(Some(current))
    }

    /// (SHUTDOWN-HANG F2.1, F3.2 step 4) Our authority, in one read of the dataset root, our
    /// writer's control row, H and O: a fenced writer, a moved root epoch or an execution epoch no
    /// longer admitted is `Authority`, and nothing is re-selected.
    async fn authority(&self) -> Result<(), RecoveryError> {
        self.journal.confirm_with(&[]).await.map_err(unavailable)
    }

    /// A definitive no-effect on a candidate's first crossing (SHUTDOWN-HANG F2.1(2)), classified
    /// by one read of its selection row:
    /// - our head: another driver applied this exact candidate; Ok after the post-write
    ///   verification;
    /// - our predecessor: the CAS ran under the driver against the live head, so it failed on our
    ///   custody or on one of our originals. Our authority decides: lost, `Authority` (never
    ///   resubmitted); intact, a changed original (`Corrupt`). The entry is kept;
    /// - anything else: another candidate won the row, and this entry can never apply: discarded.
    async fn no_effect(
        &self,
        event: &RecoveryEvent,
        ours: &Head,
        predecessor: Option<&Secret<Vec<u8>>>,
    ) -> Result<(), RecoveryError> {
        let operation = event.operation_id;
        let current = head(&self.store, &operation).await?;
        let unchanged = match (current.as_ref(), predecessor) {
            (None, None) => true,
            (Some((_, row)), Some(previous)) => {
                row.expose(&crate::seal::lend()) == previous.expose(&crate::seal::lend())
            }
            _ => false,
        };
        if unchanged {
            return Err(match self.journal.confirm_with(&[]).await {
                Err(lost) => {
                    self.hold_for_authority(operation);
                    unavailable(lost)
                }
                Ok(()) => {
                    self.clear_retained(operation);
                    invalid("journal original differs at computed ordinal (Corrupt)")
                }
            });
        }
        if current.as_ref().is_none_or(|(tip, _)| tip != ours) {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .remove(&operation);
            return Err(RecoveryError::Conflict(
                "another recovery candidate won selection".into(),
            ));
        }
        // Another driver selected this exact candidate. Its complete current ancestry remains the
        // only acceptable proof: this node's ownership is re-proved first, then the selection.
        // Only a genuine selection conflict discards the pending work; a transient refusal keeps
        // it and the next attempt re-proves (PERFPASS-F2 T2c).
        let verified = async {
            let mut history = self.continuing();
            self.owned_with_history(&mut history).await?;
            drop(history);
            self.verify_written_checkpoint(event).await
        };
        match verified.await {
            Ok(()) => Ok(()),
            Err(RecoveryError::Conflict(_)) => {
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pending
                    .remove(&operation);
                Err(RecoveryError::Conflict(
                    "another recovery candidate won selection".into(),
                ))
            }
            Err(error) => {
                // The definite no-effect resolved that attempt: the next one proves against the
                // live head again.
                self.clear_retained(operation);
                Err(error)
            }
        }
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
            value: Secret::new(json::to_vec(&pending.target).map_err(|e| invalid_from(&e))?),
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
/// How a batch crossing failed.
enum BatchFailed {
    /// A definite no-effect: `conflict` for a failed condition, otherwise a refusal.
    Definite { conflict: bool, why: RecoveryError },
    /// The attempt may still apply, or needs reconciliation: it stays the unresolved batch.
    Unresolved(RecoveryError),
}

fn batch_outcome(result: WriteResult) -> Result<(), BatchFailed> {
    match result {
        WriteResult::Submitted(submission) => match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(()),
                Decision::ConditionConflict => Err(BatchFailed::Definite {
                    conflict: true,
                    why: RecoveryError::Conflict(
                        "recovery selection head or node fence changed".into(),
                    ),
                }),
                Decision::TimeGuardFailed { .. } => Err(BatchFailed::Definite {
                    conflict: false,
                    why: unavailable("recovery temporal guard refused"),
                }),
                _ => Err(BatchFailed::Unresolved(unavailable(
                    "recovery candidate requires reconciliation",
                ))),
            },
            SubmitResult::NoEffect(failure) => Err(BatchFailed::Definite {
                conflict: false,
                why: unavailable(failure),
            }),
            _ => Err(BatchFailed::Unresolved(unavailable(
                "recovery candidate remains retained and unconfirmed",
            ))),
        },
        WriteResult::Busy => Err(BatchFailed::Unresolved(unavailable(
            "recovery candidate has an active native submission",
        ))),
    }
}

impl StoreRecovery {
    /// One keep phase over several operations (SHUTDOWN-HANG F3.2): every new original staged as
    /// one run and appended once, and every member selected in one CAS. A batch of one is
    /// `persist_at`; a batch over the store's per-call limit runs in parts of that limit.
    async fn persist_rows(&self, events: &[RecoveryEvent]) -> Vec<Result<(), RecoveryError>> {
        let limit = self.store.limits().scan_items.max(2);
        let mut out = Vec::with_capacity(events.len());
        for part in events.chunks(limit) {
            if let [event] = part {
                out.push(self.persist_at(event).await);
            } else {
                out.extend(self.persist_part(part).await);
            }
        }
        out
    }

    async fn persist_part(&self, events: &[RecoveryEvent]) -> Vec<Result<(), RecoveryError>> {
        let _batching = self.batching.lock().await;
        let missing = || unavailable("recovery batch result missing");
        let mut out: Vec<Option<Result<(), RecoveryError>>> = Vec::with_capacity(events.len());
        out.resize_with(events.len(), || None);
        // 1. The unresolved batch is driven first, with exactly its membership. While it stays in
        //    doubt nothing new is staged.
        if let Err(why) = self.resolve_batch().await {
            return events.iter().map(|_| Err(why.clone())).collect();
        }
        // 2. Each operation's driver, then the pre-checks of every new candidate, run together.
        //    A busy or conflicting operation fails alone.
        let mut guards = Vec::with_capacity(events.len());
        let mut fresh = Vec::with_capacity(events.len());
        let mut deferred = Vec::new();
        for (at, event) in events.iter().enumerate() {
            if events[..at]
                .iter()
                .any(|earlier| earlier.operation_id == event.operation_id)
            {
                out[at] = Some(Err(RecoveryError::Conflict(
                    "a recovery operation repeats in one batch".into(),
                )));
                continue;
            }
            let guard = match self.drive(event.operation_id) {
                Ok(guard) => guard,
                Err(why) => {
                    out[at] = Some(Err(why));
                    continue;
                }
            };
            let saved = self
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .get(&event.operation_id)
                .map(|pending| pending.event == *event);
            match saved {
                Some(false) => {
                    out[at] = Some(Err(RecoveryError::Conflict(
                        "another immutable recovery candidate is pending".into(),
                    )))
                }
                // An original staged by an earlier attempt: driven alone after the batch, which
                // reuses it, so no second original is ever staged.
                Some(true) => deferred.push(at),
                None => {
                    guards.push(guard);
                    fresh.push(at);
                }
            }
        }
        let prepared: Vec<_> = stream::iter(fresh)
            .map(|at| async move { (at, self.prepare(&events[at]).await) })
            .buffered(PRECHECKS)
            .collect()
            .await;
        // 3. One run for every new original.
        let now = crate::store::now_ms() / 1000;
        let mut staged = Vec::with_capacity(prepared.len());
        let mut entries = Vec::with_capacity(prepared.len());
        for (at, prepared) in prepared {
            match prepared {
                Ok(None) => out[at] = Some(Ok(())),
                Ok(Some(current)) => match body(&Candidate {
                    event: events[at].clone(),
                    previous_head: current.as_ref().map(|(tip, _)| tip.clone()),
                    adoption: None,
                }) {
                    Ok(body) => {
                        entries.push(Entry::new(RecordClass::Reconciliation, body).at(now, 0));
                        staged.push((at, current));
                    }
                    Err(why) => out[at] = Some(Err(why)),
                },
                Err(why) => out[at] = Some(Err(why)),
            }
        }
        if !staged.is_empty() {
            match self.stage_batch(events, staged, &entries) {
                Ok(attempt) => {
                    // 4. One select for every member, bisected on a conflict.
                    for (operation, answer) in self.drive_batch(attempt).await {
                        if let Some(at) = events.iter().position(|e| e.operation_id == operation) {
                            out[at].get_or_insert(answer);
                        }
                    }
                }
                Err((failed, why)) => {
                    for at in failed {
                        out[at] = Some(Err(why.clone()));
                    }
                }
            }
        }
        // 5. The drivers are released when the call returns; the entries are not.
        drop(guards);
        for at in deferred {
            out[at] = Some(self.persist_at(&events[at]).await);
        }
        out.into_iter()
            .map(|answer| answer.unwrap_or_else(|| Err(missing())))
            .collect()
    }

    /// (F3.2 step 3) One `stage_run` for every new original; each member's entry is inserted
    /// owned by the new batch, which becomes the one unresolved attempt.
    fn stage_batch(
        &self,
        events: &[RecoveryEvent],
        staged: Vec<(usize, Current)>,
        entries: &[Entry],
    ) -> Result<BatchAttempt, (Vec<usize>, RecoveryError)> {
        let at: Vec<usize> = staged.iter().map(|(at, _)| *at).collect();
        let run = match self.journal.stage_run(entries) {
            Ok(run) => run,
            Err(why) => return Err((at, unavailable(why))),
        };
        let mut pendings = Vec::with_capacity(staged.len());
        for (index, (position, current)) in staged.into_iter().enumerate() {
            let event = &events[position];
            let (Some(record), Ok(event_digest)) =
                (run.records().get(index).cloned(), event.fingerprint())
            else {
                return Err((at, invalid("recovery batch staging is incomplete")));
            };
            pendings.push(Pending {
                event: event.clone(),
                head: Head {
                    version: 1,
                    node: self.node,
                    sequence: record.node_seq,
                    revision: event.revision,
                    event_digest,
                },
                record,
                predecessor: current.map(|(_, raw)| raw),
                run: run.clone(),
                selection_proof: None,
                authority_first: false,
                owner: Owner::Single,
            });
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.next_batch = state.next_batch.wrapping_add(1);
        let id = state.next_batch;
        let mut members = Vec::with_capacity(pendings.len());
        for mut pending in pendings {
            pending.owner = Owner::Batch(id);
            members.push(pending.event.operation_id);
            state.pending.insert(pending.event.operation_id, pending);
        }
        let attempt = BatchAttempt {
            id,
            operation: crate::door::op_id().0,
            members,
            proof: None,
            authority_first: false,
        };
        state.batch = Some(attempt.clone());
        Ok(attempt)
    }

    /// (F3.2 step 1) The unresolved batch, driven with exactly its membership. `Err` while it
    /// stays unresolved; members it selected are verified, the rest are free for any driver.
    async fn resolve_batch(&self) -> Result<(), RecoveryError> {
        let attempt = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .batch
            .clone();
        let Some(attempt) = attempt else {
            return Ok(());
        };
        let answers = self.drive_batch(attempt).await;
        if self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .batch
            .is_none()
        {
            return Ok(());
        }
        let why = answers
            .into_iter()
            .find_map(|(_, answer)| answer.err())
            .map_or_else(String::new, |why| why.to_string());
        Err(RecoveryError::Unavailable(format!(
            "a recovery batch is unresolved: {why}"
        )))
    }

    /// Drives `first` to an answer per member (SHUTDOWN-HANG F3.2 step 4).
    /// - Applied: every member is selected, then verified by its post-write verification.
    /// - In doubt: the attempt stays the unresolved batch with the same membership; its members
    ///   and every member not yet tried answer unresolved.
    /// - A definite condition conflict bisects: each half under a new operation id (safe after a
    ///   definite no-effect), down to single members, each classified alone (F2.1).
    /// - A definite refusal of the whole attempt is checked against our authority first (one
    ///   read): fenced, nothing is split, re-selected or halved. Otherwise the batch limit halves
    ///   for the rest of the pass and `UNIT_FLUSH_BATCH_REDUCED` is raised once.
    ///
    /// For one bad member of B, at most 2·log2 B extra crossings.
    async fn drive_batch(&self, first: BatchAttempt) -> Vec<([u8; 16], Result<(), RecoveryError>)> {
        let mut out = Vec::with_capacity(first.members.len());
        let mut limit = first.members.len().max(1);
        let mut reduced = false;
        let mut blocked: Option<RecoveryError> = None;
        let mut work = vec![first];
        while let Some(next) = work.pop() {
            if let Some(why) = &blocked {
                // Never crossed under its own id (a part of a definite no-effect): free for any
                // driver, which reuses its staged original.
                self.free(&next.members);
                out.extend(
                    next.members
                        .iter()
                        .map(|member| (*member, Err(why.clone()))),
                );
                continue;
            }
            if next.members.len() > limit {
                let (head, rest) = self.split(next, limit);
                work.push(rest);
                work.push(head);
                continue;
            }
            let members = next.members.clone();
            match self.cross(next).await {
                Ok(Crossed::Applied(events)) => {
                    let verified: Vec<_> = stream::iter(events)
                        .map(|event| async move {
                            let answer = self.verify_written_checkpoint(&event).await;
                            (event.operation_id, answer)
                        })
                        .buffered(PRECHECKS)
                        .collect()
                        .await;
                    out.extend(verified);
                }
                Ok(Crossed::Reselect(attempt)) => work.push(attempt),
                Err(why) => {
                    out.extend(members.iter().map(|member| (*member, Err(why.clone()))));
                    blocked = Some(why);
                }
                Ok(Crossed::Definite {
                    attempt,
                    conflict,
                    why,
                }) => {
                    let width = attempt.members.len();
                    if width == 1 {
                        let answer = self.alone(attempt, conflict, why).await;
                        out.push((members[0], answer));
                    } else if conflict {
                        self.clear_batch();
                        let (head, rest) = self.split(attempt, width / 2);
                        work.push(rest);
                        work.push(head);
                    } else if let Err(lost) = self.authority().await {
                        // Fenced, or not read: re-armed whole, still the unresolved batch; the
                        // next pass repeats only this check, and nothing crosses until it passes.
                        self.rearm(attempt, true);
                        out.extend(members.iter().map(|member| (*member, Err(lost.clone()))));
                        blocked = Some(lost);
                    } else {
                        self.clear_batch();
                        limit = limit.min(width / 2).max(1);
                        reduced = true;
                        let (head, rest) = self.split(attempt, width / 2);
                        work.push(rest);
                        work.push(head);
                    }
                }
            }
        }
        if reduced {
            crate::diag_warn!(
                crate::diagnostics::UNIT_FLUSH_BATCH_REDUCED,
                b = limit,
                "the store refused a whole recovery batch; the rest of this pass used smaller ones"
            );
        }
        out
    }

    /// One crossing of `attempt`, which becomes the unresolved batch before anything crosses: the
    /// append of its members' originals if not yet confirmed (lane hold 1), then one CAS of every
    /// member built under the publication driver against its live head or the exact retained
    /// proof (lane hold 2). `Err` while it stays unresolved.
    async fn cross(&self, mut attempt: BatchAttempt) -> Result<Crossed, RecoveryError> {
        let rows: Vec<Pending> = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let mut rows = Vec::with_capacity(attempt.members.len());
            for member in &attempt.members {
                if let Some(pending) = state.pending.get_mut(member) {
                    pending.owner = Owner::Batch(attempt.id);
                    rows.push(pending.clone());
                }
            }
            if rows.len() != attempt.members.len() {
                state.batch = None;
                return Err(invalid("a recovery batch member lost its staged original"));
            }
            state.batch = Some(attempt.clone());
            rows
        };
        if attempt.authority_first {
            // (owner ruling 2026-11-16) Our authority was lost or unread after a crossing that
            // applied nothing: only the authority read repeats, and nothing crosses until it
            // passes. The batch stays unresolved meanwhile.
            self.authority().await?;
            attempt.authority_first = false;
            if let Some(batch) = self
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .batch
                .as_mut()
                .filter(|batch| batch.id == attempt.id)
            {
                batch.authority_first = false;
            }
        }
        let redrive = attempt.proof.is_some();
        if !redrive {
            let mut confirmed: Vec<&Arc<StagedRun>> = Vec::new();
            for row in &rows {
                if confirmed.iter().any(|run| Arc::ptr_eq(run, &row.run)) {
                    continue;
                }
                self.journal.confirm(&row.run).await.map_err(unavailable)?;
                confirmed.push(&row.run);
            }
            // (F1) Every member's original is evidence from here on, before the select.
            for row in &rows {
                self.carry(
                    row.event.operation_id,
                    carried_of(&row.run, row.record.node_seq),
                );
            }
        }
        let mut changes = Vec::with_capacity(rows.len());
        for row in &rows {
            changes.push(RowChange {
                records: std::slice::from_ref(&row.record),
                address: address(&row.event.operation_id),
                expected: row
                    .predecessor
                    .clone()
                    .map_or(ExpectedValue::Absent, ExpectedValue::Exact),
                value: Some(Secret::new(
                    json::to_vec(&row.head).map_err(|e| invalid_from(&e))?,
                )),
            });
        }
        let operation = attempt.operation;
        let (used, result) = self
            .journal
            .change_rows_live(
                operation,
                &changes,
                attempt.proof.clone(),
                &|proof: &Arc<VerifiedHead>| self.retain_batch(operation, proof),
            )
            .await
            .map_err(unavailable)?;
        drop(changes);
        let fenced = fenced_shape(&result);
        match batch_outcome(result) {
            Ok(()) => {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                state.batch = None;
                let mut events = Vec::with_capacity(rows.len());
                for row in rows {
                    state.pending.remove(&row.event.operation_id);
                    events.push(row.event);
                }
                Ok(Crossed::Applied(events))
            }
            Err(BatchFailed::Unresolved(why)) => {
                if fenced {
                    // (F2.1(1)) Never re-selected; lost authority names itself, and the attempt
                    // is never resubmitted.
                    if let Err(lost) = self.authority().await {
                        self.rearm(attempt, true);
                        return Err(lost);
                    }
                }
                Err(why)
            }
            Err(BatchFailed::Definite { .. }) if redrive => {
                // (F2.1(1), owner ruling 2026-11-16 "Re-select, after authority check") The
                // re-drive resubmitted the retained attempt under its own commit key, and the
                // store answers an attempt that already applied as Applied: this no-effect is
                // definitive. Our authority first: lost, `Authority`, and nothing crosses again
                // until it passes; otherwise every member's staged original is re-selected once,
                // whole, under a new operation id against the live head.
                if let Err(lost) = self.authority().await {
                    self.rearm(attempt, true);
                    return Err(lost);
                }
                Ok(Crossed::Reselect(self.rearm(attempt, false)))
            }
            Err(BatchFailed::Definite { conflict, why }) => {
                attempt.proof = Some(used);
                Ok(Crossed::Definite {
                    attempt,
                    conflict,
                    why,
                })
            }
        }
    }

    /// A definite no-effect for a single member on its first crossing (SHUTDOWN-HANG F2.1). Its
    /// entry is kept and freed for any driver, unless another candidate won its row.
    async fn alone(
        &self,
        attempt: BatchAttempt,
        conflict: bool,
        why: RecoveryError,
    ) -> Result<(), RecoveryError> {
        let operation = attempt.members.first().copied();
        let freed = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.batch = None;
            operation.and_then(|operation| {
                state.pending.get_mut(&operation).map(|pending| {
                    pending.owner = Owner::Single;
                    pending.selection_proof = None;
                    (
                        operation,
                        pending.event.clone(),
                        pending.head.clone(),
                        pending.predecessor.clone(),
                    )
                })
            })
        };
        let Some((operation, event, ours, predecessor)) = freed else {
            return Err(why);
        };
        if !conflict {
            // A refusal of this one candidate: our authority first, never retried as benign; lost,
            // nothing crosses again until it passes.
            if let Err(lost) = self.authority().await {
                self.hold_for_authority(operation);
                return Err(lost);
            }
            return Err(why);
        }
        self.no_effect(&event, &ours, predecessor.as_ref()).await?;
        // Another driver selected this exact candidate.
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending
            .remove(&operation);
        Ok(())
    }

    /// The first `at` members and the rest, each a fresh attempt under its own id and operation
    /// id. Only an attempt that has definitely not applied, or never crossed, is split.
    fn split(&self, attempt: BatchAttempt, at: usize) -> (BatchAttempt, BatchAttempt) {
        let (first, rest) = attempt.members.split_at(at.min(attempt.members.len()));
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut half = |members: &[[u8; 16]]| {
            state.next_batch = state.next_batch.wrapping_add(1);
            BatchAttempt {
                id: state.next_batch,
                operation: crate::door::op_id().0,
                members: members.to_vec(),
                proof: None,
                authority_first: false,
            }
        };
        let head = half(first);
        let rest = half(rest);
        (head, rest)
    }

    /// The same members under a new operation id, against the live head on the next crossing;
    /// still the unresolved batch, which is returned. With `authority_first` the next crossing
    /// first repeats the authority read, and nothing crosses until it passes.
    fn rearm(&self, attempt: BatchAttempt, authority_first: bool) -> BatchAttempt {
        let rearmed = BatchAttempt {
            operation: crate::door::op_id().0,
            proof: None,
            authority_first,
            ..attempt
        };
        self.state.lock().unwrap_or_else(|p| p.into_inner()).batch = Some(rearmed.clone());
        rearmed
    }

    fn clear_batch(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).batch = None;
    }

    /// Members no batch attempt in flight owns: any driver may reuse their staged originals.
    fn free(&self, members: &[[u8; 16]]) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let current = state.batch.as_ref().map(|batch| batch.id);
        for member in members {
            if let Some(pending) = state.pending.get_mut(member) {
                if !matches!((pending.owner, current), (Owner::Batch(id), Some(now)) if id == now) {
                    pending.owner = Owner::Single;
                }
            }
        }
    }

    /// Save the proof `change_rows_live` will CAS against into the unresolved batch,
    /// synchronously under its driver and before any native claim. Only the attempt with this
    /// exact operation id is touched.
    fn retain_batch(&self, operation: [u8; 16], proof: &Arc<VerifiedHead>) {
        if let Some(batch) = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .batch
            .as_mut()
            .filter(|batch| batch.operation == operation)
        {
            batch.proof = Some(proof.clone());
        }
    }
}
#[async_trait::async_trait]
impl RecoverySink for StoreRecovery {
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.persist_at(event).await
    }
    /// One staged run, one append and one selection CAS for the whole batch (SHUTDOWN-HANG F3.2).
    async fn persist_batch(&self, events: &[RecoveryEvent]) -> Vec<Result<(), RecoveryError>> {
        self.persist_rows(events).await
    }
    fn release(&self, operation_id: [u8; 16]) {
        self.release_carried(operation_id);
    }
    async fn replay_selections(&self) -> Result<Vec<RecoverySelection>, RecoveryError> {
        self.adopt_pending().await?;
        let local = self.owned().await?;
        let mut result = Vec::new();
        for (operation, tip) in heads(&self.store).await? {
            if tip.node == self.node {
                let selected = self.selection_carried(&operation, &tip).await?;
                self.verify_checkpoint_at(&selected.selected, true).await?;
                result.push(selected);
            }
        }
        confirm_this_node(&self.journal, &local).await?;
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
        confirm_this_node(&self.journal, &local).await?;
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
