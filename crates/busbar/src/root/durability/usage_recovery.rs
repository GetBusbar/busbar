// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::store::conditional::{Expected, Mutation, Predicate};
use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_contract::store_calls::StoreCalls;
use busbar_kernel::governance::recovery::{
    RecoveryError, RecoveryEvent, RecoveryInspection, RecoveryLink, RecoveryResolution,
    RecoverySelection, RecoverySink, RecoveryState, RecoveryVerdict,
};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, Record, RecordClass};
use serde::{Deserialize, Serialize};

use super::store_chain::{
    confirm_record_bytes, off_runtime, read_chain, read_record_exact, verify_stored_chain,
    wait_for, ACK_DEADLINE,
};
use super::{Durability, JournalLane};

pub(crate) const HEAD_SCHEMA: &str = "busbar.usage-recovery-head.v1";
const TAG: &str = "usage.recovery.v1";
const PAGE: u32 = 256;

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

    fn validate(
        &self,
        previous: &(Head, Candidate),
        current: &(Head, Candidate),
        descendants: &[(Head, Candidate)],
    ) -> Result<(), RecoveryError> {
        if self.version != 1
            || self.operation_id != current.1.event.operation_id
            || self.body_fingerprint != current.1.event.body_fingerprint
            || self.foreign_head != previous.0
            || previous.0.node == current.0.node
            || !self.sender_quiesced
            || !self.backend_quiesced
            || self.actor.trim().is_empty()
            || self.actor.len() > 256
            || self.reason.trim().is_empty()
            || self.reason.len() > 4096
        {
            return Err(invalid("invalid attested recovery handover proof"));
        }
        let verdict_state = if self.landed {
            RecoveryState::VerdictLanded
        } else {
            RecoveryState::VerdictNotLanded
        };
        let decision = match previous.1.event.state {
            RecoveryState::LandedUnknown if current.1.event.state == verdict_state => current,
            state
                if state == verdict_state
                    && current.1.event.state == state
                    && current.1.event.payload == previous.1.event.payload =>
            {
                current
            }
            RecoveryState::Applied
                if self.landed
                    && current.1.event.state == RecoveryState::Applied
                    && current.1.event.payload == previous.1.event.payload =>
            {
                current
            }
            RecoveryState::ConditionConflict
                if !self.landed
                    && current.1.event.state == RecoveryState::ConditionConflict
                    && current.1.event.payload == previous.1.event.payload =>
            {
                current
            }
            RecoveryState::Intent if current.1.event.state == RecoveryState::LandedUnknown => {
                descendants
                    .first()
                    .ok_or_else(|| invalid("handover verdict is not selected"))?
            }
            _ => {
                return Err(invalid(
                    "handover does not end an unresolved foreign operation",
                ))
            }
        };
        let expected = match previous.1.event.state {
            RecoveryState::Applied => RecoveryState::Applied,
            RecoveryState::ConditionConflict => RecoveryState::ConditionConflict,
            _ => verdict_state,
        };
        if decision.0.node != current.0.node
            || decision.1.event.state != expected
            || decision.1.event.fingerprint()? != self.final_event_digest
        {
            return Err(invalid(
                "attested handover verdict differs from selected ancestry",
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

fn unavailable(why: impl ToString) -> RecoveryError {
    RecoveryError::Unavailable(why.to_string())
}

fn invalid(why: impl ToString) -> RecoveryError {
    RecoveryError::Invalid(why.to_string())
}

fn body(candidate: &Candidate) -> Result<Vec<u8>, RecoveryError> {
    let encoded = serde_json::to_vec(candidate).map_err(invalid)?;
    let mut writer = BodyWriter::new();
    writer.text(TAG).bytes(&encoded);
    Ok(writer.finish())
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
    serde_json::from_slice(encoded).map(Some).map_err(invalid)
}

pub(super) fn is_recovery_record(record: &Record) -> bool {
    JournalRecord::decode(&record.body).is_ok_and(|record| {
        record.class == RecordClass::Reconciliation
            && BodyReader::new(&record.body).text() == Some(TAG)
    })
}

fn head(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
) -> Result<Option<(Head, Vec<u8>)>, RecoveryError> {
    let Some(raw) = wait_for(calls.record_get(HEAD_SCHEMA, operation)).map_err(unavailable)? else {
        return Ok(None);
    };
    let decoded: Head = serde_json::from_slice(raw.as_slice()).map_err(invalid)?;
    if decoded.version != 1 || decoded.node == 0 || decoded.sequence == 0 {
        return Err(invalid("invalid recovery selection head"));
    }
    Ok(Some((decoded, raw.as_slice().to_vec())))
}

type Chains = BTreeMap<u64, Vec<JournalRecord>>;

fn stream_selection(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
    tip: &Head,
    owner: u64,
    mut visit: impl FnMut(&Head, &Candidate) -> Result<(), RecoveryError>,
) -> Result<RecoverySelection, RecoveryError> {
    if tip.node != owner {
        return Err(invalid("recovery selection is not owned by this node"));
    }
    let mut next = tip.clone();
    let mut selected = None;
    let mut child: Option<CompactCandidate> = None;
    let mut verified_owner = None;
    loop {
        let at = next;
        if at.version != 1 || at.node == 0 || at.sequence == 0 {
            return Err(invalid("invalid recovery predecessor pointer"));
        }
        // A node segment is checked once, in pages, with no retained journal payload index.
        // Revisiting a former owner after another handover performs a new cold verification.
        if verified_owner != Some(at.node) {
            verify_stored_chain(calls, at.node).map_err(invalid)?;
            verified_owner = Some(at.node);
        }
        let record = read_record_exact(calls, at.node, at.sequence).map_err(invalid)?;
        let candidate = candidate(&record)?
            .ok_or_else(|| invalid("selected record is not a recovery candidate"))?;
        drop(record);
        if candidate.event.operation_id != *operation
            || candidate.event.revision != at.revision
            || candidate.event.fingerprint()? != at.event_digest
        {
            return Err(invalid("selected recovery record identity differs"));
        }
        if selected.is_none() {
            selected = Some(candidate.event.clone());
        }
        if let Some(child) = &child {
            child.link.follows(Some(&candidate.event))?;
            if child.head.node == at.node {
                if child.adoption.is_some() || at.sequence >= child.head.sequence {
                    return Err(invalid(
                        "recovery predecessor is not an earlier owned journal record",
                    ));
                }
            } else {
                child
                    .adoption
                    .as_ref()
                    .ok_or_else(|| {
                        invalid("recovery ownership changed without an attested decision")
                    })?
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
                    selected: selected.unwrap(),
                });
            }
            _ => return Err(invalid("invalid selected recovery predecessor")),
        }
        let newer = child.as_ref().map(CompactCandidate::tag);
        child = Some(CompactCandidate::of(&at, &candidate, newer));
    }
}

fn selection(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
    tip: &Head,
    owner: u64,
) -> Result<RecoverySelection, RecoveryError> {
    stream_selection(calls, operation, tip, owner, |_, _| Ok(()))
}

fn selected_checkpoint(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
    tip: &Head,
    digest: [u8; 32],
    missing: &str,
) -> Result<RecoveryEvent, RecoveryError> {
    let mut found = None;
    stream_selection(calls, operation, tip, tip.node, |at, _| {
        if at.event_digest == digest {
            found = Some(at.clone());
        }
        Ok(())
    })?;
    let at = found.ok_or_else(|| invalid(missing))?;
    // Retain only the pointer while the fold continues. Materialize this one payload AFTER the
    // full selected chain has verified, never alongside a retained historical payload list.
    let record = read_record_exact(calls, at.node, at.sequence).map_err(invalid)?;
    let event = candidate(&record)?
        .ok_or_else(|| invalid("selected checkpoint is not a recovery candidate"))?
        .event;
    if event.fingerprint()? != at.event_digest || event.operation_id != *operation {
        return Err(invalid("selected checkpoint changed during readback"));
    }
    Ok(event)
}

fn selected(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
    tip: &Head,
    owner: u64,
    chains: &mut Chains,
) -> Result<Vec<RecoveryEvent>, RecoveryError> {
    Ok(selected_chain(calls, operation, tip, owner, chains)?
        .into_iter()
        .map(|(_, candidate)| candidate.event)
        .collect())
}

fn selected_chain(
    calls: &dyn StoreCalls,
    operation: &[u8; 16],
    tip: &Head,
    owner: u64,
    chains: &mut Chains,
) -> Result<Vec<(Head, Candidate)>, RecoveryError> {
    if tip.node != owner {
        return Err(invalid("recovery selection is not owned by this node"));
    }
    let mut next = Some(tip.clone());
    let mut backwards = Vec::new();
    while let Some(at) = next {
        if at.version != 1 || at.node == 0 || at.sequence == 0 {
            return Err(invalid("invalid recovery predecessor pointer"));
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = chains.entry(at.node) {
            let records = read_chain(calls, at.node).map_err(unavailable)?;
            let decoded = busbar_kernel_wal::decode_run(&records).map_err(invalid)?;
            if records
                .iter()
                .zip(&decoded)
                .any(|(outer, inner)| outer.identity() != inner.identity())
            {
                return Err(invalid(
                    "recovery journal key and sealed record identity differ",
                ));
            }
            busbar_kernel_wal::verify_journal(&decoded).map_err(invalid)?;
            entry.insert(decoded);
        }
        let record = chains[&at.node]
            .iter()
            .find(|record| record.node == at.node && record.node_seq == at.sequence)
            .ok_or_else(|| invalid("selected recovery journal record is missing"))?;
        confirm_record_bytes(
            calls,
            &Record::new(record.node, record.node_seq, record.encode()),
        )
        .map_err(unavailable)?;
        let candidate = candidate(record)?
            .ok_or_else(|| invalid("selected journal record is not a recovery candidate"))?;
        if &candidate.event.operation_id != operation
            || candidate.event.revision != at.revision
            || candidate.event.fingerprint()? != at.event_digest
        {
            return Err(invalid("selected recovery record identity differs"));
        }
        match &candidate.previous_head {
            Some(previous)
                if previous.revision.checked_add(1) == Some(at.revision)
                    && candidate.event.previous_event == Some(previous.event_digest) => {}
            None if at.revision == 0 && candidate.event.previous_event.is_none() => {}
            _ => return Err(invalid("invalid selected recovery predecessor")),
        }
        next = candidate.previous_head.clone();
        backwards.push((at, candidate));
    }
    backwards.reverse();
    for (index, current) in backwards.iter().enumerate() {
        let previous = index.checked_sub(1).map(|previous| &backwards[previous]);
        current
            .1
            .event
            .follows(previous.map(|(_, candidate)| &candidate.event))?;
        match (previous, &current.1.adoption) {
            (Some(previous), Some(proof)) if previous.0.node != current.0.node => {
                proof.validate(previous, current, &backwards[index + 1..])?;
            }
            (Some(previous), None) if previous.0.node == current.0.node => {}
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "recovery ownership changed without an attested verdict",
                ))
            }
        }
    }
    Ok(backwards)
}

fn heads(calls: &dyn StoreCalls) -> Result<Vec<([u8; 16], Head)>, RecoveryError> {
    let mut pending = vec![Vec::new()];
    let mut out = Vec::new();
    while let Some(prefix) = pending.pop() {
        let page = wait_for(calls.record_scan(HEAD_SCHEMA, &prefix, PAGE)).map_err(unavailable)?;
        if page.len() > PAGE as usize
            || page
                .iter()
                .any(|(key, _)| key.len() != 16 || !key.starts_with(&prefix))
            || page.windows(2).any(|rows| rows[0].0 >= rows[1].0)
        {
            return Err(invalid("invalid recovery head scan"));
        }
        if page.len() == PAGE as usize {
            if prefix.len() >= 16 {
                return Err(invalid("oversized recovery head page"));
            }
            for byte in (0..=u8::MAX).rev() {
                let mut child = prefix.clone();
                child.push(byte);
                pending.push(child);
            }
        } else {
            for (key, value) in page {
                let operation = key
                    .try_into()
                    .map_err(|_| invalid("invalid recovery head key"))?;
                let head: Head = serde_json::from_slice(value.as_slice()).map_err(invalid)?;
                out.push((operation, head));
            }
        }
    }
    out.sort_by_key(|(operation, _)| *operation);
    Ok(out)
}

fn adopted_history(
    calls: &dyn StoreCalls,
    node: u64,
    tip: &Head,
    resolution: &RecoveryResolution,
    transitions: &[RecoveryEvent],
) -> Result<Vec<RecoveryEvent>, RecoveryError> {
    let chain = selected_chain(
        calls,
        &resolution.operation_id,
        tip,
        node,
        &mut Chains::new(),
    )?;
    let last = transitions
        .last()
        .ok_or_else(|| invalid("handover has no verdict"))?;
    if chain.last().map(|(_, candidate)| &candidate.event) != Some(last)
        || !chain.iter().any(|(_, candidate)| {
            candidate.adoption.as_ref().is_some_and(|proof| {
                proof.final_event_digest == tip.event_digest && proof.matches(resolution)
            })
        })
    {
        return Err(RecoveryError::Conflict(
            "selected handover differs from this attested decision".into(),
        ));
    }
    Ok(chain
        .into_iter()
        .map(|(_, candidate)| candidate.event)
        .collect())
}

fn adopted_selection(
    calls: &dyn StoreCalls,
    node: u64,
    tip: &Head,
    resolution: &RecoveryResolution,
    transitions: &[RecoveryEvent],
) -> Result<RecoverySelection, RecoveryError> {
    let mut attested = false;
    let result = stream_selection(
        calls,
        &resolution.operation_id,
        tip,
        node,
        |_, candidate| {
            attested |= candidate.adoption.as_ref().is_some_and(|proof| {
                proof.final_event_digest == tip.event_digest && proof.matches(resolution)
            });
            Ok(())
        },
    )?;
    if transitions.last() != Some(&result.selected) || !attested {
        return Err(RecoveryError::Conflict(
            "selected handover differs from this attested decision".into(),
        ));
    }
    Ok(result)
}

#[derive(Clone)]
struct Pending {
    event: RecoveryEvent,
    record: Record,
    head: Head,
    predecessor: Option<Vec<u8>>,
}

struct StoreRecovery {
    book: Arc<Mutex<Durability>>,
    token: Grant<DurableWrite>,
    state: Mutex<DriverState>,
}

#[derive(Default)]
struct DriverState {
    pending: BTreeMap<[u8; 16], Pending>,
    adoptions: BTreeMap<[u8; 16], PendingAdoption>,
    driving: BTreeSet<[u8; 16]>,
}

#[derive(Clone)]
struct PendingAdoption {
    proof: AdoptionProof,
    transitions: Vec<RecoveryEvent>,
    records: Vec<Pending>,
    predecessor: Vec<u8>,
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
    fn drive(&self, operation: [u8; 16]) -> Result<Driving<'_>, RecoveryError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.driving.insert(operation) {
            return Err(unavailable(
                "this recovery operation already has an active driver",
            ));
        }
        Ok(Driving {
            sink: self,
            operation,
        })
    }

    fn append_candidate(
        &self,
        lane: &JournalLane,
        node: u64,
        candidate: Candidate,
    ) -> Result<Pending, RecoveryError> {
        let encoded = body(&candidate)?;
        lane.validate_recovery_frame(node, encoded.len())
            .map_err(invalid)?;
        let sealed = {
            let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
            let ack = book
                .journal
                .append(
                    &self.token,
                    StepName::Meter,
                    &[Entry::new(RecordClass::Reconciliation, encoded)
                        .at(busbar_kernel::store::now_ms() / 1_000, 0)],
                )
                .map_err(|_| {
                    unavailable("recovery candidate remains unconfirmed in the journal")
                })?;
            ack.sealed
                .into_iter()
                .last()
                .ok_or_else(|| invalid("recovery append sealed no record"))?
        };
        Ok(Pending {
            head: Head {
                version: 1,
                node,
                sequence: sealed.node_seq,
                revision: candidate.event.revision,
                event_digest: candidate.event.fingerprint()?,
            },
            event: candidate.event,
            record: Record::new(node, sealed.node_seq, sealed.encode()),
            predecessor: None,
        })
    }

    fn inputs(&self) -> Result<(JournalLane, u64), RecoveryError> {
        let book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        if !book.durable_in_store() {
            return Err(unavailable("recovery requires the opened Store journal"));
        }
        Ok((
            book.lane()
                .cloned()
                .ok_or_else(|| unavailable("no recovery journal lane"))?,
            book.journal.node(),
        ))
    }

    fn inspect_foreign_at(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        let (lane, node) = self.inputs()?;
        let fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let calls = lane.calls();
        let mut tips = Vec::new();
        for (operation, tip) in heads(calls.as_ref())? {
            if tip.node != node {
                let event = selection(calls.as_ref(), &operation, &tip, tip.node)?.selected;
                tips.push(RecoveryInspection {
                    owner_node: tip.node,
                    event,
                });
            }
        }
        if lane.recovery_predicates(node).map_err(unavailable)? != fences {
            return Err(unavailable(
                "the local node fence changed during foreign inspection",
            ));
        }
        Ok(tips)
    }

    fn verify_origin_at(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let (lane, node) = self.inputs()?;
        let fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let calls = lane.calls();
        let initial = match head(calls.as_ref(), &event.operation_id)? {
            Some((tip, _)) => {
                selection(calls.as_ref(), &event.operation_id, &tip, tip.node)?.initial
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
        {
            return Err(invalid(
                "recovery child identity differs from selected genesis",
            ));
        }
        let origin = initial.origin_reference()?;
        if event.origin_reference()? != origin {
            return Err(invalid(
                "recovery checkpoint changed its immutable child origin",
            ));
        }
        if let Some(origin) = origin {
            let (tip, _) = head(calls.as_ref(), &origin.operation_id)?
                .ok_or_else(|| invalid("recovery origin parent has no selected head"))?;
            let parent = selected_checkpoint(
                calls.as_ref(),
                &origin.operation_id,
                &tip,
                origin.event_fingerprint,
                "recovery origin checkpoint is not in the current selected parent chain",
            )?;
            parent.authorizes_child(&initial)?;
        }
        if lane.recovery_predicates(node).map_err(unavailable)? != fences {
            return Err(unavailable(
                "the local node fence changed during child-origin verification",
            ));
        }
        Ok(())
    }

    fn verify_checkpoint_at(
        &self,
        event: &RecoveryEvent,
        require_owned: bool,
    ) -> Result<(), RecoveryError> {
        let (lane, node) = self.inputs()?;
        let fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let calls = lane.calls();
        let (tip, raw) = head(calls.as_ref(), &event.operation_id)?
            .ok_or_else(|| invalid("recovery checkpoint has no selected operation"))?;
        if require_owned && tip.node != node {
            return Err(RecoveryError::Conflict(
                "recovery checkpoint belongs to another node's selected operation".into(),
            ));
        }
        let actual = selected_checkpoint(
            calls.as_ref(),
            &event.operation_id,
            &tip,
            event.fingerprint()?,
            "recovery checkpoint is not in the current selected ancestry",
        )?;
        if &actual != event {
            return Err(invalid(
                "selected checkpoint differs from its exact event identity",
            ));
        }
        self.verify_origin_at(&actual)?;
        if require_owned {
            let current = head(calls.as_ref(), &event.operation_id)?;
            if !current
                .as_ref()
                .is_some_and(|(tip, current_raw)| tip.node == node && current_raw == &raw)
            {
                return Err(RecoveryError::Conflict(
                    "recovery ownership or selection changed during owned checkpoint confirmation"
                        .into(),
                ));
            }
        }
        if lane.recovery_predicates(node).map_err(unavailable)? != fences {
            return Err(unavailable(
                "the local node fence changed during checkpoint verification",
            ));
        }
        Ok(())
    }

    fn replay_selections_at(&self) -> Result<Vec<RecoverySelection>, RecoveryError> {
        let (lane, node) = self.inputs()?;
        let fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let calls = lane.calls();
        let mut summaries = Vec::new();
        for (operation, tip) in heads(calls.as_ref())? {
            if tip.node == node {
                let summary = selection(calls.as_ref(), &operation, &tip, node)?;
                self.verify_origin_at(&summary.selected)?;
                summaries.push(summary);
            }
        }
        if lane.recovery_predicates(node).map_err(unavailable)? != fences {
            return Err(unavailable(
                "the local node fence changed during recovery replay",
            ));
        }
        Ok(summaries)
    }

    fn adopt_verdict_selection_at(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        if !resolution.sender_quiesced
            || !resolution.backend_quiesced
            || resolution.actor.trim().is_empty()
            || resolution.actor.len() > 256
            || resolution.reason.trim().is_empty()
            || resolution.reason.len() > 4096
            || !(1..=2).contains(&transitions.len())
        {
            return Err(invalid("handover requires explicit sender/backend quiescence, actor, reason and a legal verdict chain"));
        }
        let verdict = if resolution.verdict == RecoveryVerdict::Landed {
            RecoveryState::VerdictLanded
        } else {
            RecoveryState::VerdictNotLanded
        };
        let last = transitions.last().unwrap();
        if transitions.iter().any(|event| {
            event.operation_id != resolution.operation_id
                || event.body_fingerprint != resolution.body_fingerprint
        }) {
            return Err(invalid(
                "handover verdict does not match its operation identity",
            ));
        }
        let _driving = self.drive(resolution.operation_id)?;
        let (lane, node) = self.inputs()?;
        let fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let calls = lane.calls();
        let (current, raw) = head(calls.as_ref(), &resolution.operation_id)?
            .ok_or_else(|| invalid("foreign recovery operation does not exist"))?;
        let digest = last.fingerprint()?;
        if current.node == node {
            let run = adopted_selection(calls.as_ref(), node, &current, resolution, transitions)?;
            self.verify_origin_at(last)?;
            if head(calls.as_ref(), &resolution.operation_id)?
                .as_ref()
                .map(|(_, value)| value)
                != Some(&raw)
                || lane.recovery_predicates(node).map_err(unavailable)? != fences
            {
                return Err(unavailable(
                    "handover authority changed during confirmation",
                ));
            }
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .adoptions
                .remove(&resolution.operation_id);
            return Ok(run);
        }
        let run = selection(
            calls.as_ref(),
            &resolution.operation_id,
            &current,
            current.node,
        )?;
        let foreign = &run.selected;
        if foreign.revision != resolution.expected_revision
            || foreign.body_fingerprint != resolution.body_fingerprint
        {
            return Err(RecoveryError::Conflict(
                "foreign recovery head differs from the attested revision".into(),
            ));
        }
        let legal_shape = match foreign.state {
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
        if !legal_shape {
            return Err(RecoveryError::Conflict(
                "foreign recovery decision cannot be changed by handover".into(),
            ));
        }
        let mut previous = foreign;
        for event in transitions {
            event.follows(Some(previous))?;
            self.verify_origin_at(event)?;
            previous = event;
        }
        let proof = AdoptionProof {
            version: 1,
            operation_id: resolution.operation_id,
            body_fingerprint: resolution.body_fingerprint,
            foreign_head: current.clone(),
            final_event_digest: digest,
            landed: resolution.verdict == RecoveryVerdict::Landed,
            sender_quiesced: resolution.sender_quiesced,
            backend_quiesced: resolution.backend_quiesced,
            actor: resolution.actor.clone(),
            reason: resolution.reason.clone(),
        };
        let saved = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .adoptions
            .get(&resolution.operation_id)
            .cloned();
        let pending = if let Some(saved) = saved {
            if saved.proof != proof
                || saved.transitions.as_slice() != transitions
                || saved.predecessor != raw
            {
                return Err(RecoveryError::Conflict(
                    "another immutable attested handover is pending".into(),
                ));
            }
            saved
        } else {
            let mut previous_head = current;
            let mut records = Vec::with_capacity(transitions.len());
            for (index, event) in transitions.iter().enumerate() {
                let candidate = self.append_candidate(
                    &lane,
                    node,
                    Candidate {
                        event: event.clone(),
                        previous_head: Some(previous_head),
                        adoption: (index == 0).then(|| proof.clone()),
                    },
                )?;
                previous_head = candidate.head.clone();
                records.push(candidate);
            }
            let pending = PendingAdoption {
                proof,
                transitions: transitions.to_vec(),
                records,
                predecessor: raw,
            };
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .adoptions
                .insert(resolution.operation_id, pending.clone());
            pending
        };
        let target = &pending.records.last().unwrap().head;
        let _ = lane.wait_acked(node, target.sequence, ACK_DEADLINE);
        for record in &pending.records {
            lane.confirm_recovery_record(&record.record)
                .map_err(unavailable)?;
        }
        let fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let mut predicates = fences.clone();
        predicates.push(Predicate {
            schema: HEAD_SCHEMA.into(),
            key: resolution.operation_id.to_vec(),
            expected: Expected::Bytes(pending.predecessor.clone()),
        });
        let value = serde_json::to_vec(target).map_err(invalid)?;
        let request = super::conditional::candidate(
            predicates,
            vec![Mutation::Put {
                schema: HEAD_SCHEMA.into(),
                key: resolution.operation_id.to_vec(),
                value,
            }],
        );
        drop(request.encode_held().map_err(invalid)?);
        // One head CAS selects the complete verdict chain; an intermediate unknown checkpoint
        // can never transfer custody by itself. Attestations authorize this explicit path only.
        let decision = wait_for(calls.record_transaction(&request));
        let observed = head(calls.as_ref(), &resolution.operation_id)?;
        if let Some((tip, observed_raw)) = &observed {
            if tip.node == node && tip.event_digest == digest {
                let run = adopted_selection(calls.as_ref(), node, tip, resolution, transitions)?;
                self.verify_origin_at(last)?;
                if head(calls.as_ref(), &resolution.operation_id)?
                    .as_ref()
                    .map(|(_, value)| value)
                    != Some(observed_raw)
                    || lane.recovery_predicates(node).map_err(unavailable)? != fences
                {
                    return Err(unavailable(
                        "handover authority changed during confirmation",
                    ));
                }
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .adoptions
                    .remove(&resolution.operation_id);
                return Ok(run);
            }
        }
        if observed.as_ref().map(|(_, value)| value) != Some(&pending.predecessor) {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .adoptions
                .remove(&resolution.operation_id);
            return Err(RecoveryError::Conflict(
                "another recovery decision won the handover CAS".into(),
            ));
        }
        Err(unavailable(format!(
            "attested handover selection is unconfirmed: {decision:?}"
        )))
    }

    fn persist_at(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let _driving = self.drive(event.operation_id)?;
        let (lane, node) = self.inputs()?;
        let calls = lane.calls();
        let initial_fences = lane.recovery_predicates(node).map_err(unavailable)?;
        let current = head(calls.as_ref(), &event.operation_id)?;
        let digest = event.fingerprint()?;
        if current.as_ref().is_some_and(|(head, _)| head.node != node) {
            return Err(RecoveryError::Conflict(
                "this recovery operation belongs to another node".into(),
            ));
        }
        self.verify_origin_at(event)?;
        if let Some((current_head, _)) = &current {
            if current_head.node != node {
                return Err(RecoveryError::Conflict(
                    "this recovery operation belongs to another node".into(),
                ));
            }
            if current_head.event_digest == digest {
                let run = selection(calls.as_ref(), &event.operation_id, current_head, node)?;
                if &run.selected != event {
                    return Err(invalid("recovery event digest collision"));
                }
                if head(calls.as_ref(), &event.operation_id)?
                    .as_ref()
                    .map(|(_, raw)| raw)
                    != current.as_ref().map(|(_, raw)| raw)
                {
                    return Err(RecoveryError::Conflict(
                        "recovery selection advanced during confirmation".into(),
                    ));
                }
                if lane.recovery_predicates(node).map_err(unavailable)? != initial_fences {
                    return Err(unavailable(
                        "the node fence changed during recovery confirmation",
                    ));
                }
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pending
                    .remove(&event.operation_id);
                return Ok(());
            }
        }
        let previous = current.as_ref().map(|(head, _)| head);
        let run = previous
            .map(|head| selection(calls.as_ref(), &event.operation_id, head, node))
            .transpose()?;
        event
            .follows(run.as_ref().map(|summary| &summary.selected))
            .map_err(|_| {
                RecoveryError::Conflict(
                    "recovery selection has advanced or names another predecessor".into(),
                )
            })?;
        let predecessor = current.as_ref().map(|(_, raw)| raw.clone());
        let saved = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state
                .pending
                .get(&event.operation_id)
                .is_some_and(|p| p.predecessor != predecessor)
            {
                state.pending.remove(&event.operation_id);
            }
            state.pending.get(&event.operation_id).cloned()
        };
        if saved.as_ref().is_some_and(|p| p.event != *event) {
            return Err(RecoveryError::Conflict(
                "another immutable candidate owns this recovery revision".into(),
            ));
        }
        let candidate = if let Some(saved) = saved {
            saved
        } else {
            let candidate = Candidate {
                event: event.clone(),
                previous_head: previous.cloned(),
                adoption: None,
            };
            let encoded = body(&candidate)?;
            lane.validate_recovery_frame(node, encoded.len())
                .map_err(invalid)?;
            let sealed = {
                let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
                let wall = busbar_kernel::store::now_ms() / 1_000;
                let ack = book
                    .journal
                    .append(
                        &self.token,
                        StepName::Meter,
                        &[Entry::new(RecordClass::Reconciliation, encoded).at(wall, 0)],
                    )
                    .map_err(|_| {
                        unavailable("recovery candidate remains unconfirmed in the journal")
                    })?;
                ack.sealed
                    .into_iter()
                    .last()
                    .ok_or_else(|| invalid("recovery append sealed no record"))?
            };
            let pending = Pending {
                event: event.clone(),
                head: Head {
                    version: 1,
                    node,
                    sequence: sealed.node_seq,
                    revision: event.revision,
                    event_digest: digest,
                },
                record: Record::new(node, sealed.node_seq, sealed.encode()),
                predecessor: predecessor.clone(),
            };
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .insert(event.operation_id, pending.clone());
            pending
        };
        if candidate.predecessor != predecessor {
            return Err(RecoveryError::Conflict(
                "recovery predecessor changed before selection".into(),
            ));
        }
        // No usage send, dead transfer, verdict effect or forgetting is authorized until the
        // complete candidate is in the Store AND its operation head selects it.
        let _ = lane.wait_acked(node, candidate.record.node_seq, ACK_DEADLINE);
        lane.confirm_recovery_record(&candidate.record)
            .map_err(unavailable)?;
        let mut predicates = lane.recovery_predicates(node).map_err(unavailable)?;
        predicates.push(Predicate {
            schema: HEAD_SCHEMA.into(),
            key: event.operation_id.to_vec(),
            expected: candidate
                .predecessor
                .clone()
                .map_or(Expected::Absent, Expected::Bytes),
        });
        let value = serde_json::to_vec(&candidate.head).map_err(invalid)?;
        let request = super::conditional::candidate(
            predicates.clone(),
            vec![Mutation::Put {
                schema: HEAD_SCHEMA.into(),
                key: event.operation_id.to_vec(),
                value: value.clone(),
            }],
        );
        drop(request.encode_held().map_err(invalid)?);
        // Selection heads only advance and are never deleted or restored. A later attempt may
        // use a fresh conditional id for this exact prior-row -> immutable-candidate CAS: the
        // full prior predicate prevents replaying an effect or replacing a winning branch even
        // after conditional receipt retention expires. This does not renew a usage operation.
        let decision = wait_for(calls.record_transaction(&request));
        let observed = head(calls.as_ref(), &event.operation_id)?;
        if let Some((selected_head, selected_raw)) = &observed {
            if selected_head.node == node && selected_head.event_digest == digest {
                if selected_raw != &value {
                    let run = selection(calls.as_ref(), &event.operation_id, selected_head, node)?;
                    if &run.selected != event {
                        return Err(invalid("recovery event digest collision"));
                    }
                }
                self.verify_origin_at(event)?;
                if head(calls.as_ref(), &event.operation_id)?
                    .as_ref()
                    .map(|(_, raw)| raw)
                    != Some(selected_raw)
                {
                    return Err(RecoveryError::Conflict(
                        "recovery selection advanced during origin confirmation".into(),
                    ));
                }
                if lane
                    .recovery_predicates(node)
                    .map_err(unavailable)?
                    .as_slice()
                    == &predicates[..predicates.len() - 1]
                {
                    self.state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .pending
                        .remove(&event.operation_id);
                    return Ok(());
                }
            }
        }
        if observed.as_ref().map(|(_, raw)| raw) != candidate.predecessor.as_ref() {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .remove(&event.operation_id);
            return Err(RecoveryError::Conflict(
                "another recovery candidate won selection".into(),
            ));
        }
        Err(unavailable(format!(
            "recovery head selection is unconfirmed: {decision:?}"
        )))
    }
}

impl RecoverySink for StoreRecovery {
    fn replay_selections(&self) -> Result<Vec<RecoverySelection>, RecoveryError> {
        off_runtime(|| self.replay_selections_at())
    }

    fn adopt_verdict_selection(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        off_runtime(|| self.adopt_verdict_selection_at(resolution, transitions))
    }

    fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        off_runtime(|| self.verify_checkpoint_at(event, false))
    }

    fn confirm_owned_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        off_runtime(|| self.verify_checkpoint_at(event, true))
    }

    fn verify_origin(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        off_runtime(|| self.verify_origin_at(event))
    }

    fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        off_runtime(|| self.inspect_foreign_at())
    }

    fn adopt_verdict(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        // Compatibility only. Production ownership handover consumes the bounded selection API.
        off_runtime(|| {
            self.adopt_verdict_selection_at(resolution, transitions)?;
            let (lane, node) = self.inputs()?;
            let calls = lane.calls();
            let (tip, _) = head(calls.as_ref(), &resolution.operation_id)?
                .ok_or_else(|| invalid("selected handover disappeared"))?;
            adopted_history(calls.as_ref(), node, &tip, resolution, transitions)
        })
    }

    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        off_runtime(|| self.persist_at(event))
    }

    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        // Compatibility only. Production startup uses replay_selections instead of history Vecs.
        off_runtime(|| {
            let (lane, node) = self.inputs()?;
            let predicates = lane.recovery_predicates(node).map_err(unavailable)?;
            let calls = lane.calls();
            let mut chains = Chains::new();
            let mut events = Vec::new();
            for (operation, tip) in heads(calls.as_ref())? {
                if tip.node == node {
                    let run = selected(calls.as_ref(), &operation, &tip, node, &mut chains)?;
                    if let Some(event) = run.last() {
                        self.verify_origin_at(event)?;
                    }
                    events.extend(run);
                }
            }
            if lane.recovery_predicates(node).map_err(unavailable)? != predicates {
                return Err(unavailable(
                    "the local node fence changed during recovery replay",
                ));
            }
            Ok(events)
        })
    }
}

pub(crate) fn usage_recovery_sink(book: &Arc<Mutex<Durability>>) -> Arc<dyn RecoverySink> {
    Arc::new(StoreRecovery {
        book: Arc::clone(book),
        token: busbar_kernel::teller::Kernel::new().durability_token(),
        state: Mutex::new(DriverState::default()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::store_double::RecordSlots;
    use busbar_kernel::governance::recovery::{RecoveryKind, RecoveryState};

    fn opened(slots: &RecordSlots, host: &str) -> Arc<Mutex<Durability>> {
        let taken = super::super::take_node(slots.calls().as_ref(), host).unwrap();
        let lane = JournalLane::start(slots.calls(), "recovery-test").unwrap();
        if let Some(lease) = taken.lease {
            lane.hold_lease(lease);
        }
        lane.bind_recovery_identity(host, taken.id).unwrap();
        Arc::new(Mutex::new(
            super::super::build_on_store(
                &super::super::DurabilityConfig { data_dir: None },
                taken.id,
                lane,
                None,
            )
            .unwrap(),
        ))
    }

    fn intent() -> RecoveryEvent {
        RecoveryEvent {
            operation_id: [1; 16],
            revision: 0,
            previous_event: None,
            kind: RecoveryKind::Usage,
            body_fingerprint: [2; 32],
            state: RecoveryState::Intent,
            first_sent_at_ms: Some(1_000),
            payload: serde_json::to_vec(&serde_json::json!({"test": vec![3u8; 900]})).unwrap(),
        }
    }

    fn transition(previous: &RecoveryEvent, state: RecoveryState) -> RecoveryEvent {
        RecoveryEvent {
            revision: previous.revision + 1,
            previous_event: Some(previous.fingerprint().unwrap()),
            state,
            ..previous.clone()
        }
    }

    fn attestation(event: &RecoveryEvent, verdict: RecoveryVerdict) -> RecoveryResolution {
        RecoveryResolution {
            operation_id: event.operation_id,
            body_fingerprint: event.body_fingerprint,
            expected_revision: event.revision,
            verdict,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "operator".into(),
            reason: "old per-operation senders retired; outstanding backend mutations settled"
                .into(),
        }
    }

    fn retire(book: &Arc<Mutex<Durability>>) {
        let lane = book.lock().unwrap().lane().unwrap().clone();
        assert!(lane.drain(ACK_DEADLINE));
        lane.release_held_lease();
    }

    fn handover_events(previous: &RecoveryEvent, verdict: RecoveryVerdict) -> Vec<RecoveryEvent> {
        let state = if verdict == RecoveryVerdict::Landed {
            RecoveryState::VerdictLanded
        } else {
            RecoveryState::VerdictNotLanded
        };
        match previous.state {
            RecoveryState::Intent => {
                let unknown = transition(previous, RecoveryState::LandedUnknown);
                vec![unknown.clone(), transition(&unknown, state)]
            }
            RecoveryState::LandedUnknown => vec![transition(previous, state)],
            state => vec![transition(previous, state)],
        }
    }

    fn linked_events() -> (RecoveryEvent, RecoveryEvent, RecoveryEvent) {
        let mut child = intent();
        child.operation_id = [9; 16];
        child.body_fingerprint = [8; 32];
        let template = serde_json::json!({"physical": [1, 2, 3]});
        let template_bytes = serde_json::to_vec(&template).unwrap();
        let mut parent = intent();
        parent.operation_id = [6; 16];
        parent.payload = serde_json::to_vec(&serde_json::json!({"handoffs": []})).unwrap();
        let mut checkpoint = transition(&parent, RecoveryState::Applied);
        checkpoint.payload = serde_json::to_vec(&serde_json::json!({"handoffs": [{
            "operation_id": child.operation_id, "kind": child.kind,
            "body_fingerprint": child.body_fingerprint, "first_sent_at_ms": child.first_sent_at_ms,
            "payload": template_bytes,
        }]}))
        .unwrap();
        let mut physical = template;
        physical["origin"] = serde_json::json!({
            "operation_id": checkpoint.operation_id, "event_fingerprint": checkpoint.fingerprint().unwrap(),
        });
        child.payload = serde_json::to_vec(&physical).unwrap();
        (parent, checkpoint, child)
    }

    #[test]
    fn restart_replays_selected_candidates_with_the_original_send_time() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-restart");
        let sink = usage_recovery_sink(&book);
        let sent = intent();
        let dead = transition(&sent, RecoveryState::LandedUnknown);
        sink.persist(&sent).unwrap();
        sink.persist(&dead).unwrap();
        let lane = book.lock().unwrap().lane().unwrap().clone();
        assert!(lane.drain(ACK_DEADLINE));
        lane.release_held_lease();
        let restarted = opened(&slots, "recovery-restart");
        assert_eq!(
            usage_recovery_sink(&restarted).replay().unwrap(),
            vec![sent, dead]
        );
    }

    #[test]
    fn two_verdict_callers_select_only_one_candidate_and_forks_are_inert() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-verdict-race");
        let first = usage_recovery_sink(&book);
        let second = usage_recovery_sink(&book);
        let sent = intent();
        let dead = transition(&sent, RecoveryState::LandedUnknown);
        first.persist(&sent).unwrap();
        first.persist(&dead).unwrap();
        let landed = transition(&dead, RecoveryState::VerdictLanded);
        let not_landed = transition(&dead, RecoveryState::VerdictNotLanded);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let join = Arc::clone(&barrier);
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address().0 == HEAD_SCHEMA)
            {
                join.wait();
            }
            None
        });
        let one = std::thread::spawn(move || first.persist(&landed));
        let two = std::thread::spawn(move || second.persist(&not_landed));
        let results = [one.join().unwrap(), two.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(RecoveryError::Conflict(_))))
                .count(),
            1
        );
        let run = usage_recovery_sink(&book).replay().unwrap();
        assert_eq!(run.len(), 3);
        assert_eq!(run[0], sent);
        assert_eq!(run[1], dead);
        assert!(matches!(
            run[2].state,
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded
        ));
    }

    #[test]
    fn unknown_head_write_keeps_one_candidate_and_retries_only_its_exact_cas() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-head-unknown");
        let sink = usage_recovery_sink(&book);
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address().0 == HEAD_SCHEMA)
                && seen.fetch_add(1, Ordering::Relaxed) == 0
            {
                return Some(busbar_contract::store_calls::StoreFailure::Failed(
                    "unknown".into(),
                ));
            }
            None
        });
        let sent = intent();
        assert!(matches!(
            sink.persist(&sent),
            Err(RecoveryError::Unavailable(_))
        ));
        let sequence = book.lock().unwrap().journal.next_seq();
        sink.persist(&sent).unwrap();
        assert_eq!(book.lock().unwrap().journal.next_seq(), sequence);
        assert_eq!(sink.replay().unwrap(), vec![sent]);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn fresh_node_mode_is_bound_to_its_minted_registry_row() {
        let slots = RecordSlots::new();
        let first = opened(&slots, "recovery-fresh");
        // Keep the first writer live while take_node watches for an expired host lease.
        super::super::store_identity::set_lease_expiry(
            slots.calls().as_ref(),
            "recovery-fresh",
            u64::MAX,
        );
        let fresh = opened(&slots, "recovery-fresh");
        assert_ne!(
            first.lock().unwrap().journal.node(),
            fresh.lock().unwrap().journal.node()
        );
        let sink = usage_recovery_sink(&fresh);
        sink.persist(&intent()).unwrap();
        assert_eq!(sink.replay().unwrap(), vec![intent()]);
    }

    #[test]
    fn lost_acks_confirm_both_candidates_and_the_selected_head() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-lost-acks");
        let sink = usage_recovery_sink(&book);
        slots.lose_transaction_acks(true);
        sink.persist(&intent()).unwrap();
        assert_eq!(sink.replay().unwrap(), vec![intent()]);
    }

    #[test]
    fn two_live_nodes_cannot_restore_or_resolve_one_anothers_operations() {
        let slots = RecordSlots::new();
        let first = opened(&slots, "recovery-node-one");
        let second = opened(&slots, "recovery-node-two");
        let one = usage_recovery_sink(&first);
        let two = usage_recovery_sink(&second);
        let sent = intent();
        let dead = transition(&sent, RecoveryState::LandedUnknown);
        let verdict = transition(&dead, RecoveryState::VerdictLanded);
        one.persist(&sent).unwrap();
        one.persist(&dead).unwrap();
        let before = second.lock().unwrap().journal.next_seq();
        assert_eq!(two.replay().unwrap(), Vec::<RecoveryEvent>::new());
        assert!(matches!(
            two.persist(&verdict),
            Err(RecoveryError::Conflict(_))
        ));
        assert_eq!(second.lock().unwrap().journal.next_seq(), before);
        one.persist(&verdict).unwrap();
        assert!(matches!(
            one.persist(&dead),
            Err(RecoveryError::Conflict(_))
        ));
        assert_eq!(one.replay().unwrap(), vec![sent, dead, verdict]);
    }

    #[test]
    fn a_pending_head_call_does_not_hold_the_driver_map_or_block_another_operation() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-independent");
        let sink = usage_recovery_sink(&book);
        let (entered, waiting) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let gate = Arc::clone(&release);
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address() == (HEAD_SCHEMA, &[1; 16][..]))
            {
                entered.send(()).unwrap();
                let (lock, ready) = &*gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = ready.wait(open).unwrap();
                }
            }
            None
        });
        let first = Arc::clone(&sink);
        let one = std::thread::spawn(move || first.persist(&intent()));
        waiting
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let (finished, done) = std::sync::mpsc::channel();
        let second = Arc::clone(&sink);
        let two = std::thread::spawn(move || {
            let mut event = intent();
            event.operation_id = [4; 16];
            let result = second.persist(&event);
            finished.send(result).unwrap();
        });
        let independent = done.recv_timeout(std::time::Duration::from_secs(5));
        let (lock, ready) = &*release;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        one.join().unwrap().unwrap();
        two.join().unwrap();
        independent
            .expect("unrelated operation must finish while the first Store call is pending")
            .unwrap();
    }

    #[test]
    fn a_valid_sealed_record_under_another_store_sequence_is_not_replay_evidence() {
        use super::super::store_chain::{part_key, JOURNAL_SCHEMA};
        let slots = RecordSlots::new();
        let book = opened(&slots, "recovery-key-identity");
        let sink = usage_recovery_sink(&book);
        sink.persist(&intent()).unwrap();
        let calls = slots.calls();
        let (tip, raw) = head(calls.as_ref(), &[1; 16]).unwrap().unwrap();
        let prefix = part_key(tip.node, tip.sequence, 0);
        let parts = wait_for(calls.record_scan(JOURNAL_SCHEMA, &prefix[..16], 65_536)).unwrap();
        let mut mutations = vec![Mutation::DeleteRange {
            schema: JOURNAL_SCHEMA.into(),
            prefix: prefix[..16].to_vec(),
            exact_key_length: 18,
        }];
        for (index, (_, value)) in parts.into_iter().enumerate() {
            mutations.push(Mutation::Put {
                schema: JOURNAL_SCHEMA.into(),
                key: part_key(tip.node, tip.sequence + 1, index as u16).to_vec(),
                value: value.as_slice().to_vec(),
            });
        }
        let rewrite = super::super::conditional::candidate(
            vec![Predicate {
                schema: HEAD_SCHEMA.into(),
                key: vec![1; 16],
                expected: Expected::Bytes(raw),
            }],
            mutations,
        );
        wait_for(calls.record_transaction(&rewrite)).unwrap();
        assert!(
            matches!(sink.replay(), Err(RecoveryError::Invalid(reason)) if reason.contains("key and sealed record identity"))
        );
    }

    #[test]
    fn foreign_metadata_does_not_authorize_handover_without_both_attestations() {
        let slots = RecordSlots::new();
        let old = opened(&slots, "handover-alive-old");
        let new = opened(&slots, "handover-alive-new");
        let old_sink = usage_recovery_sink(&old);
        let new_sink = usage_recovery_sink(&new);
        let sent = intent();
        old_sink.persist(&sent).unwrap();
        assert_eq!(
            new_sink.inspect_foreign().unwrap(),
            vec![RecoveryInspection {
                owner_node: old.lock().unwrap().journal.node(),
                event: sent.clone(),
            }]
        );
        assert!(new_sink.replay().unwrap().is_empty());
        let events = handover_events(&sent, RecoveryVerdict::NotLanded);
        let before = new.lock().unwrap().journal.next_seq();
        let original = head(slots.calls().as_ref(), &sent.operation_id).unwrap();
        for (sender_quiesced, backend_quiesced) in [(false, false), (true, false), (false, true)] {
            let request = RecoveryResolution {
                sender_quiesced,
                backend_quiesced,
                ..attestation(&sent, RecoveryVerdict::NotLanded)
            };
            assert!(matches!(
                new_sink.adopt_verdict(&request, &events),
                Err(RecoveryError::Invalid(_))
            ));
        }
        assert_eq!(new.lock().unwrap().journal.next_seq(), before);
        assert_eq!(
            head(slots.calls().as_ref(), &sent.operation_id).unwrap(),
            original
        );
        assert!(matches!(
            new_sink.persist(&events[0]),
            Err(RecoveryError::Conflict(_))
        ));
    }

    #[test]
    fn attested_retired_foreign_states_preserve_decisions_and_replay_across_restart() {
        for (state, choice) in [
            (RecoveryState::Intent, RecoveryVerdict::NotLanded),
            (RecoveryState::LandedUnknown, RecoveryVerdict::Landed),
            (RecoveryState::VerdictLanded, RecoveryVerdict::Landed),
            (RecoveryState::VerdictNotLanded, RecoveryVerdict::NotLanded),
            (RecoveryState::Applied, RecoveryVerdict::Landed),
            (RecoveryState::ConditionConflict, RecoveryVerdict::NotLanded),
        ] {
            let slots = RecordSlots::new();
            let old = opened(&slots, "handover-retired-old");
            let new = opened(&slots, "handover-retired-new");
            let old_sink = usage_recovery_sink(&old);
            let new_sink = usage_recovery_sink(&new);
            let sent = intent();
            old_sink.persist(&sent).unwrap();
            let foreign = match state {
                RecoveryState::Intent => sent,
                RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded => {
                    let unknown = transition(&sent, RecoveryState::LandedUnknown);
                    old_sink.persist(&unknown).unwrap();
                    transition(&unknown, state)
                }
                _ => transition(&sent, state),
            };
            if foreign.revision > 0 {
                old_sink.persist(&foreign).unwrap();
            }
            let (foreign_head, _) = head(slots.calls().as_ref(), &foreign.operation_id)
                .unwrap()
                .unwrap();
            retire(&old);
            let events = handover_events(&foreign, choice);
            let request = attestation(&foreign, choice);
            let selected = new_sink.adopt_verdict(&request, &events).unwrap();
            assert_eq!(selected.last(), events.last(), "state {state:?}");
            assert_eq!(new_sink.replay().unwrap(), selected);
            assert!(new_sink.inspect_foreign().unwrap().is_empty());
            let (tip, _) = head(slots.calls().as_ref(), &foreign.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(tip.node, new.lock().unwrap().journal.node());
            let chain = selected_chain(
                slots.calls().as_ref(),
                &foreign.operation_id,
                &tip,
                tip.node,
                &mut Chains::new(),
            )
            .unwrap();
            let proof = chain
                .iter()
                .find_map(|(_, candidate)| candidate.adoption.as_ref())
                .unwrap();
            assert_eq!(proof.foreign_head, foreign_head);
            assert!(proof.matches(&request));
            let opposite = RecoveryResolution {
                verdict: if choice == RecoveryVerdict::Landed {
                    RecoveryVerdict::NotLanded
                } else {
                    RecoveryVerdict::Landed
                },
                ..request.clone()
            };
            assert!(matches!(
                new_sink.adopt_verdict(&opposite, &events),
                Err(RecoveryError::Conflict(_))
            ));
            retire(&new);
            let restarted = opened(&slots, "handover-retired-new");
            assert_eq!(usage_recovery_sink(&restarted).replay().unwrap(), selected);
        }
    }

    #[test]
    fn competing_attested_verdicts_have_one_foreign_head_cas_winner() {
        let slots = RecordSlots::new();
        let old = opened(&slots, "handover-race-old");
        let one = opened(&slots, "handover-race-one");
        let two = opened(&slots, "handover-race-two");
        let old_sink = usage_recovery_sink(&old);
        let sent = intent();
        let foreign = transition(&sent, RecoveryState::LandedUnknown);
        old_sink.persist(&sent).unwrap();
        old_sink.persist(&foreign).unwrap();
        retire(&old);
        let first = usage_recovery_sink(&one);
        let second = usage_recovery_sink(&two);
        let landed = handover_events(&foreign, RecoveryVerdict::Landed);
        let not_landed = handover_events(&foreign, RecoveryVerdict::NotLanded);
        let yes = attestation(&foreign, RecoveryVerdict::Landed);
        let no = attestation(&foreign, RecoveryVerdict::NotLanded);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address().0 == HEAD_SCHEMA)
            {
                barrier.wait();
            }
            None
        });
        let first = std::thread::spawn(move || first.adopt_verdict(&yes, &landed));
        let second = std::thread::spawn(move || second.adopt_verdict(&no, &not_landed));
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(RecoveryError::Conflict(_))))
                .count(),
            1
        );
        let tip = head(slots.calls().as_ref(), &foreign.operation_id)
            .unwrap()
            .unwrap()
            .0;
        let owner = if results[0].is_ok() { one } else { two };
        assert_eq!(tip.node, owner.lock().unwrap().journal.node());
        assert_eq!(
            usage_recovery_sink(&owner).replay().unwrap(),
            *results
                .iter()
                .find_map(|result| result.as_ref().ok())
                .unwrap()
        );
    }

    #[test]
    fn unknown_adoption_selects_no_intermediate_head_and_retains_exact_candidates() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let slots = RecordSlots::new();
        let old = opened(&slots, "handover-unknown-old");
        let new = opened(&slots, "handover-unknown-new");
        let sent = intent();
        usage_recovery_sink(&old).persist(&sent).unwrap();
        retire(&old);
        let sink = usage_recovery_sink(&new);
        let request = attestation(&sent, RecoveryVerdict::NotLanded);
        let events = handover_events(&sent, RecoveryVerdict::NotLanded);
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&attempts);
        slots.on_transaction(move |request| {
            for mutation in &request.mutations {
                if let Mutation::Put { schema, value, .. } = mutation {
                    if schema == HEAD_SCHEMA {
                        assert_eq!(serde_json::from_slice::<Head>(value).unwrap().revision, 2);
                        if count.fetch_add(1, Ordering::Relaxed) == 0 {
                            return Some(busbar_contract::store_calls::StoreFailure::Failed(
                                "unknown".into(),
                            ));
                        }
                    }
                }
            }
            None
        });
        assert!(matches!(
            sink.adopt_verdict(&request, &events),
            Err(RecoveryError::Unavailable(_))
        ));
        let sequence = new.lock().unwrap().journal.next_seq();
        assert!(sink.replay().unwrap().is_empty());
        assert_eq!(sink.inspect_foreign().unwrap().last().unwrap().event, sent);
        sink.adopt_verdict(&request, &events).unwrap();
        assert_eq!(new.lock().unwrap().journal.next_seq(), sequence);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn committed_handover_retries_after_foreign_inspection_disappears() {
        let slots = RecordSlots::new();
        let old = opened(&slots, "handover-receipt-old");
        let new = opened(&slots, "handover-receipt-new");
        let sent = intent();
        usage_recovery_sink(&old).persist(&sent).unwrap();
        retire(&old);
        let sink = usage_recovery_sink(&new);
        let request = attestation(&sent, RecoveryVerdict::Landed);
        let events = handover_events(&sent, RecoveryVerdict::Landed);
        let fail_readback = slots.clone();
        slots.on_transaction(move |request| {
            if request
                .mutations
                .iter()
                .any(|m| m.address().0 == HEAD_SCHEMA)
            {
                fail_readback.fail_reads(true);
            }
            None
        });
        assert!(matches!(
            sink.adopt_verdict(&request, &events),
            Err(RecoveryError::Unavailable(_))
        ));
        slots.fail_reads(false);
        assert!(sink.inspect_foreign().unwrap().is_empty());
        let sequence = new.lock().unwrap().journal.next_seq();
        let selected = sink.adopt_verdict(&request, &events).unwrap();
        assert_eq!(selected.last(), events.last());
        assert_eq!(new.lock().unwrap().journal.next_seq(), sequence);
    }

    #[test]
    fn retired_fresh_node_orphan_is_visible_and_requires_explicit_attested_handover() {
        let slots = RecordSlots::new();
        let host_owner = opened(&slots, "handover-shared-host");
        super::super::store_identity::set_lease_expiry(
            slots.calls().as_ref(),
            "handover-shared-host",
            u64::MAX,
        );
        let orphan = opened(&slots, "handover-shared-host");
        let recipient = opened(&slots, "handover-orphan-recipient");
        let orphan_node = orphan.lock().unwrap().journal.node();
        assert_ne!(orphan_node, host_owner.lock().unwrap().journal.node());
        let old_sink = usage_recovery_sink(&orphan);
        let sink = usage_recovery_sink(&recipient);
        let sent = intent();
        let unknown = transition(&sent, RecoveryState::LandedUnknown);
        old_sink.persist(&sent).unwrap();
        old_sink.persist(&unknown).unwrap();
        retire(&orphan);
        assert!(sink.replay().unwrap().is_empty());
        assert_eq!(
            sink.inspect_foreign().unwrap(),
            vec![RecoveryInspection {
                owner_node: orphan_node,
                event: unknown.clone(),
            }]
        );
        let request = attestation(&unknown, RecoveryVerdict::NotLanded);
        let events = handover_events(&unknown, RecoveryVerdict::NotLanded);
        let selected = sink.adopt_verdict(&request, &events).unwrap();
        assert_eq!(selected, sink.replay().unwrap());
        assert!(usage_recovery_sink(&host_owner)
            .replay()
            .unwrap()
            .is_empty());
        assert!(sink.inspect_foreign().unwrap().is_empty());
    }

    #[test]
    fn adopted_child_proves_foreign_parent_without_importing_parent_ownership() {
        let slots = RecordSlots::new();
        let old = opened(&slots, "origin-foreign-old");
        let new = opened(&slots, "origin-foreign-new");
        let old_sink = usage_recovery_sink(&old);
        let sink = usage_recovery_sink(&new);
        let (parent, checkpoint, child) = linked_events();
        old_sink.persist(&parent).unwrap();
        old_sink.persist(&checkpoint).unwrap();
        old_sink.persist(&child).unwrap();
        let unknown = transition(&child, RecoveryState::LandedUnknown);
        old_sink.persist(&unknown).unwrap();
        retire(&old);
        let request = attestation(&unknown, RecoveryVerdict::NotLanded);
        let events = handover_events(&unknown, RecoveryVerdict::NotLanded);
        let selected = sink.adopt_verdict(&request, &events).unwrap();
        sink.verify_origin(selected.last().unwrap()).unwrap();
        assert!(sink
            .replay()
            .unwrap()
            .iter()
            .all(|event| event.operation_id == child.operation_id));
        assert_eq!(
            head(slots.calls().as_ref(), &parent.operation_id)
                .unwrap()
                .unwrap()
                .0
                .node,
            old.lock().unwrap().journal.node()
        );
        assert_eq!(
            sink.inspect_foreign().unwrap(),
            vec![RecoveryInspection {
                owner_node: old.lock().unwrap().journal.node(),
                event: checkpoint,
            }]
        );
    }

    #[test]
    fn selected_parent_requires_exact_child_template_and_immutable_latest_origin() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "origin-template");
        let sink = usage_recovery_sink(&book);
        let (parent, checkpoint, child) = linked_events();
        sink.persist(&parent).unwrap();
        sink.persist(&checkpoint).unwrap();
        let mut changed = child.clone();
        let mut body: serde_json::Value = serde_json::from_slice(&changed.payload).unwrap();
        body["physical"] = serde_json::json!([1, 2, 99]);
        changed.payload = serde_json::to_vec(&body).unwrap();
        assert!(matches!(
            sink.verify_origin(&changed),
            Err(RecoveryError::Invalid(_))
        ));
        assert!(matches!(
            sink.persist(&changed),
            Err(RecoveryError::Invalid(_))
        ));
        assert!(head(slots.calls().as_ref(), &child.operation_id)
            .unwrap()
            .is_none());
        sink.persist(&child).unwrap();
        let mut latest = transition(&child, RecoveryState::LandedUnknown);
        let mut body: serde_json::Value = serde_json::from_slice(&latest.payload).unwrap();
        body["origin"] = serde_json::Value::Null;
        latest.payload = serde_json::to_vec(&body).unwrap();
        assert!(matches!(
            sink.verify_origin(&latest),
            Err(RecoveryError::Invalid(_))
        ));
        assert!(matches!(
            sink.persist(&latest),
            Err(RecoveryError::Invalid(_))
        ));
    }

    #[test]
    fn origin_requires_selected_parent_checkpoint_even_when_fork_is_journaled() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "origin-unselected");
        let sink = usage_recovery_sink(&book);
        let (parent, checkpoint, child) = linked_events();
        assert!(matches!(
            sink.verify_origin(&child),
            Err(RecoveryError::Invalid(_))
        ));
        sink.persist(&parent).unwrap();
        let (parent_head, _) = head(slots.calls().as_ref(), &parent.operation_id)
            .unwrap()
            .unwrap();
        let lane = book.lock().unwrap().lane().unwrap().clone();
        let adapter = StoreRecovery {
            book: Arc::clone(&book),
            token: busbar_kernel::teller::Kernel::new().durability_token(),
            state: Mutex::new(DriverState::default()),
        };
        let abandoned = adapter
            .append_candidate(
                &lane,
                parent_head.node,
                Candidate {
                    event: checkpoint.clone(),
                    previous_head: Some(parent_head),
                    adoption: None,
                },
            )
            .unwrap();
        lane.wait_acked(abandoned.head.node, abandoned.head.sequence, ACK_DEADLINE)
            .unwrap();
        lane.confirm_recovery_record(&abandoned.record).unwrap();
        let mut winner = checkpoint;
        winner.payload = serde_json::to_vec(&serde_json::json!({"handoffs": []})).unwrap();
        sink.persist(&winner).unwrap();
        assert!(
            matches!(sink.verify_origin(&child), Err(RecoveryError::Invalid(reason))
            if reason.contains("not in the current selected parent chain"))
        );
        assert!(head(slots.calls().as_ref(), &child.operation_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn streaming_summary_proves_long_history_and_exact_selected_checkpoints() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "stream-summary");
        let sink = usage_recovery_sink(&book);
        let initial = intent();
        sink.persist(&initial).unwrap();
        let mut current = initial.clone();
        let mut middle = None;
        for step in 0..24 {
            let mut next = transition(&current, RecoveryState::LandedUnknown);
            next.payload = serde_json::to_vec(&serde_json::json!({"checkpoint": step})).unwrap();
            sink.persist(&next).unwrap();
            if step == 11 {
                middle = Some(next.clone());
            }
            current = next;
        }
        assert_eq!(
            sink.replay_selections().unwrap(),
            vec![RecoverySelection {
                initial: initial.clone(),
                selected: current.clone(),
            }]
        );
        sink.verify_checkpoint(&initial).unwrap();
        sink.verify_checkpoint(middle.as_ref().unwrap()).unwrap();
        sink.verify_checkpoint(&current).unwrap();
        assert_eq!(sink.replay().unwrap().len(), 25);
    }

    #[test]
    fn streaming_summary_rejects_a_selected_gap_and_a_durable_unselected_fork() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "stream-membership");
        let sink = usage_recovery_sink(&book);
        let initial = intent();
        sink.persist(&initial).unwrap();
        let initial_head = head(slots.calls().as_ref(), &initial.operation_id)
            .unwrap()
            .unwrap()
            .0;
        let selected = transition(&initial, RecoveryState::LandedUnknown);
        sink.persist(&selected).unwrap();
        let lane = book.lock().unwrap().lane().unwrap().clone();
        let adapter = StoreRecovery {
            book: Arc::clone(&book),
            token: busbar_kernel::teller::Kernel::new().durability_token(),
            state: Mutex::new(DriverState::default()),
        };
        let fork = transition(&initial, RecoveryState::Applied);
        let abandoned = adapter
            .append_candidate(
                &lane,
                initial_head.node,
                Candidate {
                    event: fork.clone(),
                    previous_head: Some(initial_head),
                    adoption: None,
                },
            )
            .unwrap();
        lane.wait_acked(abandoned.head.node, abandoned.head.sequence, ACK_DEADLINE)
            .unwrap();
        lane.confirm_recovery_record(&abandoned.record).unwrap();
        assert!(sink.verify_checkpoint(&fork).is_err());
        let (current_head, raw) = head(slots.calls().as_ref(), &selected.operation_id)
            .unwrap()
            .unwrap();
        let mut skipped = transition(&selected, RecoveryState::LandedUnknown);
        skipped.revision += 1;
        let bad = adapter
            .append_candidate(
                &lane,
                current_head.node,
                Candidate {
                    event: skipped,
                    previous_head: Some(current_head),
                    adoption: None,
                },
            )
            .unwrap();
        lane.wait_acked(bad.head.node, bad.head.sequence, ACK_DEADLINE)
            .unwrap();
        let select = super::super::conditional::candidate(
            vec![Predicate {
                schema: HEAD_SCHEMA.into(),
                key: selected.operation_id.to_vec(),
                expected: Expected::Bytes(raw),
            }],
            vec![Mutation::Put {
                schema: HEAD_SCHEMA.into(),
                key: selected.operation_id.to_vec(),
                value: serde_json::to_vec(&bad.head).unwrap(),
            }],
        );
        wait_for(slots.calls().record_transaction(&select)).unwrap();
        assert!(matches!(
            sink.replay_selections(),
            Err(RecoveryError::Invalid(_))
        ));
    }

    #[test]
    fn streaming_handover_summary_retains_verified_foreign_ancestry_authority() {
        let slots = RecordSlots::new();
        let old = opened(&slots, "stream-adopt-old");
        let new = opened(&slots, "stream-adopt-new");
        let old_sink = usage_recovery_sink(&old);
        let sink = usage_recovery_sink(&new);
        let initial = intent();
        let unknown = transition(&initial, RecoveryState::LandedUnknown);
        old_sink.persist(&initial).unwrap();
        old_sink.persist(&unknown).unwrap();
        retire(&old);
        let request = attestation(&unknown, RecoveryVerdict::NotLanded);
        let transitions = handover_events(&unknown, RecoveryVerdict::NotLanded);
        let summary = sink
            .adopt_verdict_selection(&request, &transitions)
            .unwrap();
        assert_eq!(summary.initial, initial);
        assert_eq!(&summary.selected, transitions.last().unwrap());
        sink.verify_checkpoint(&unknown).unwrap();
        assert_eq!(sink.replay_selections().unwrap(), vec![summary]);
    }

    #[test]
    fn owned_confirmation_accepts_an_ancestor_after_the_operation_settles() {
        let slots = RecordSlots::new();
        let book = opened(&slots, "owned-flight-ancestor");
        let sink = usage_recovery_sink(&book);
        let initial = intent();
        let applied = transition(&initial, RecoveryState::Applied);
        let settled = transition(&applied, RecoveryState::Settled);
        sink.persist(&initial).unwrap();
        sink.persist(&applied).unwrap();
        sink.persist(&settled).unwrap();
        assert!(matches!(
            sink.persist(&applied),
            Err(RecoveryError::Conflict(_))
        ));
        sink.confirm_owned_checkpoint(&initial).unwrap();
        sink.confirm_owned_checkpoint(&applied).unwrap();
        sink.confirm_owned_checkpoint(&settled).unwrap();
    }

    #[test]
    fn owned_confirmation_refuses_the_old_node_after_handover_but_readonly_proof_survives() {
        let slots = RecordSlots::new();
        let old = opened(&slots, "owned-flight-old");
        let new = opened(&slots, "owned-flight-new");
        let old_sink = usage_recovery_sink(&old);
        let new_sink = usage_recovery_sink(&new);
        let initial = intent();
        let unknown = transition(&initial, RecoveryState::LandedUnknown);
        old_sink.persist(&initial).unwrap();
        old_sink.persist(&unknown).unwrap();
        old_sink.confirm_owned_checkpoint(&initial).unwrap();
        // This fixture has no per-operation backend sender. Keep the old node alive so a
        // read-only ancestry proof still works after the explicitly attested handover.
        let request = attestation(&unknown, RecoveryVerdict::NotLanded);
        let transitions = handover_events(&unknown, RecoveryVerdict::NotLanded);
        new_sink
            .adopt_verdict_selection(&request, &transitions)
            .unwrap();
        old_sink.verify_checkpoint(&initial).unwrap();
        assert!(matches!(
            old_sink.confirm_owned_checkpoint(&initial),
            Err(RecoveryError::Conflict(_))
        ));
        new_sink.confirm_owned_checkpoint(&initial).unwrap();
        new_sink.confirm_owned_checkpoint(&unknown).unwrap();
    }
}
