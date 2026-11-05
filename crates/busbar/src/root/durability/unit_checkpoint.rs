// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The selected running-money snapshot is a named Store head over immutable journal evidence.
//! Only the owning fenced node can advance or remove it; replay verifies its retained chain.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Predicate};
use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use busbar_kernel::governance::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, Record, RecordClass};
use serde::{Deserialize, Serialize};

use super::store_chain::{
    off_runtime, read_record_exact, verify_stored_chain_with_seals, wait_for, RecordSeal,
};
use super::{Durability, JournalLane};

pub(crate) const SCHEMA: &str = "busbar.unit-checkpoint.v1";
const TAG: &str = "unit.accrued";
const PAGE: u32 = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    node: u64,
    sequence: u64,
    revision: u64,
}

fn error(message: impl ToString) -> RecordStoreError {
    RecordStoreError(message.to_string())
}

fn body(snapshot: &UnitCheckpoint) -> RecordStoreResult<Vec<u8>> {
    let encoded = serde_json::to_vec(snapshot).map_err(error)?;
    let mut writer = BodyWriter::new();
    writer.text(TAG).bytes(&encoded);
    Ok(writer.finish())
}

fn snapshot(
    record: &JournalRecord,
    keys: &busbar_kernel_audit::AuditKeySet,
) -> RecordStoreResult<UnitCheckpoint> {
    let mut reader = BodyReader::new(&record.body);
    if record.class != RecordClass::Checkpoint || reader.text() != Some(TAG) {
        return Err(error(
            "running money head does not name unit.accrued evidence",
        ));
    }
    let encoded = reader
        .bytes()
        .ok_or_else(|| error("truncated unit.accrued evidence"))?;
    let signature = reader
        .bytes()
        .ok_or_else(|| error("unsigned unit.accrued evidence"))?;
    let mut signed = BodyWriter::new();
    signed.text(TAG).bytes(encoded);
    keys.verify_checkpoint_body(&signed.finish(), signature)
        .map_err(error)?;
    let snapshot: UnitCheckpoint = serde_json::from_slice(encoded).map_err(error)?;
    snapshot.validate()?;
    if !reader.is_done() {
        return Err(error("trailing unit.accrued evidence"));
    }
    Ok(snapshot)
}

pub(super) fn is_checkpoint_record(record: &Record) -> bool {
    JournalRecord::decode(&record.body)
        .ok()
        .is_some_and(|record| {
            record.class == RecordClass::Checkpoint
                && BodyReader::new(&record.body).text() == Some(TAG)
        })
}

struct StoreCheckpoints {
    book: Arc<Mutex<Durability>>,
    token: Grant<DurableWrite>,
    driving: Mutex<()>,
}

impl StoreCheckpoints {
    fn inputs(&self) -> RecordStoreResult<(JournalLane, u64)> {
        let book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        if !book.durable_in_store() {
            return Err(error("running money requires the opened Store journal"));
        }
        Ok((
            book.lane()
                .cloned()
                .ok_or_else(|| error("no running money journal lane"))?,
            book.journal.node(),
        ))
    }

    fn selected(
        &self,
        lane: &JournalLane,
        id: &[u8; 16],
        raw: &[u8],
    ) -> RecordStoreResult<(Head, UnitCheckpoint, RecordSeal)> {
        let head: Head = serde_json::from_slice(raw).map_err(error)?;
        if head.version != 1 || head.sequence == 0 {
            return Err(error("invalid running money head"));
        }
        let record =
            read_record_exact(lane.calls().as_ref(), head.node, head.sequence).map_err(error)?;
        let keys = super::keyset_of(&self.book.lock().unwrap_or_else(|p| p.into_inner()).record);
        let checkpoint = snapshot(&record, &keys)?;
        if checkpoint.id != *id || checkpoint.revision != head.revision {
            return Err(error("running money head differs from journal evidence"));
        }
        Ok((head, checkpoint, RecordSeal::of(&record)))
    }

    fn persist_at(&self, checkpoint: &UnitCheckpoint) -> RecordStoreResult<()> {
        checkpoint.validate()?;
        if checkpoint.audit.is_none() {
            return Err(error("unit.accrued lacks captured admission audit facts"));
        }
        let _driving = self.driving.lock().unwrap_or_else(|p| p.into_inner());
        let (lane, node) = self.inputs()?;
        let calls = lane.calls();
        let mut predicates = lane.recovery_predicates(node).map_err(error)?;
        let previous = wait_for(calls.record_get(SCHEMA, &checkpoint.id)).map_err(error)?;
        if let Some(raw) = &previous {
            let (head, selected, _) = self.selected(&lane, &checkpoint.id, raw.as_slice())?;
            if head.node != node {
                return Err(error("running money belongs to another node"));
            }
            if selected == *checkpoint {
                return Ok(());
            }
            if head.revision >= checkpoint.revision || selected.terminal.is_some() {
                return Err(error(
                    "running money checkpoint would overwrite selected custody",
                ));
            }
        }
        let mut encoded = body(checkpoint)?;
        let signature = self
            .book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record
            .sign_checkpoint_body(&encoded)
            .ok_or_else(|| error("unit.accrued requires the deployment signing key"))?;
        let mut signature_field = BodyWriter::new();
        signature_field.bytes(&signature);
        encoded.extend_from_slice(&signature_field.finish());
        lane.validate_recovery_frame(node, encoded.len())
            .map_err(error)?;
        let sealed = {
            let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
            book.journal
                .append(
                    &self.token,
                    StepName::Meter,
                    &[Entry::new(RecordClass::Checkpoint, encoded).at(checkpoint.arrived, 0)],
                )
                .map_err(|_| error("unit.accrued journal append is unconfirmed"))?
                .sealed
                .into_iter()
                .last()
                .ok_or_else(|| error("unit.accrued append sealed no record"))?
        };
        let record = Record::new(node, sealed.node_seq, sealed.encode());
        let _ = lane.wait_acked(node, record.node_seq, super::store_chain::ACK_DEADLINE);
        lane.confirm_recovery_record(&record).map_err(error)?;
        let head = Head {
            version: 1,
            node,
            sequence: sealed.node_seq,
            revision: checkpoint.revision,
        };
        predicates.push(Predicate {
            schema: SCHEMA.into(),
            key: checkpoint.id.to_vec(),
            expected: previous.map_or(Expected::Absent, |raw| {
                Expected::Bytes(raw.as_slice().to_vec())
            }),
        });
        let request = super::conditional::candidate(
            predicates,
            vec![Mutation::Put {
                schema: SCHEMA.into(),
                key: checkpoint.id.to_vec(),
                value: serde_json::to_vec(&head).map_err(error)?,
            }],
        );
        match super::conditional::decide(calls.as_ref(), &request).map_err(error)? {
            Decision::Applied => Ok(()),
            Decision::ConditionConflict => Err(error("running money head or node fence changed")),
        }
    }

    fn remove_at(&self, checkpoint: &UnitCheckpoint) -> RecordStoreResult<()> {
        if checkpoint.terminal.is_none() {
            return Err(error("cannot remove running money before terminal custody"));
        }
        super::unit_checkpoint_audit::confirm(&self.book, checkpoint)?;
        let _driving = self.driving.lock().unwrap_or_else(|p| p.into_inner());
        let (lane, node) = self.inputs()?;
        let calls = lane.calls();
        let mut predicates = lane.recovery_predicates(node).map_err(error)?;
        let Some(raw) = wait_for(calls.record_get(SCHEMA, &checkpoint.id)).map_err(error)? else {
            return Ok(());
        };
        let (head, selected, _) = self.selected(&lane, &checkpoint.id, raw.as_slice())?;
        if head.node != node || selected != *checkpoint {
            return Err(error("terminal running money custody changed"));
        }
        predicates.push(Predicate {
            schema: SCHEMA.into(),
            key: checkpoint.id.to_vec(),
            expected: Expected::Bytes(raw.as_slice().to_vec()),
        });
        let request = super::conditional::candidate(
            predicates,
            vec![Mutation::Delete {
                schema: SCHEMA.into(),
                key: checkpoint.id.to_vec(),
            }],
        );
        match super::conditional::decide(calls.as_ref(), &request).map_err(error)? {
            Decision::Applied => Ok(()),
            Decision::ConditionConflict => {
                Err(error("terminal running money head or node fence changed"))
            }
        }
    }

    fn replay_at(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        let (lane, node) = self.inputs()?;
        let calls = lane.calls();
        let fences = lane.recovery_predicates(node).map_err(error)?;
        let mut seals = Vec::new();
        let mut prefixes = vec![Vec::new()];
        let mut out = Vec::new();
        while let Some(prefix) = prefixes.pop() {
            let page = wait_for(calls.record_scan(SCHEMA, &prefix, PAGE)).map_err(error)?;
            if page.len() > PAGE as usize
                || page
                    .iter()
                    .any(|(key, _)| key.len() != 16 || !key.starts_with(&prefix))
                || page.windows(2).any(|rows| rows[0].0 >= rows[1].0)
            {
                return Err(error("invalid running money checkpoint scan"));
            }
            if page.len() == PAGE as usize {
                if prefix.len() >= 16 {
                    return Err(error("oversized running money checkpoint page"));
                }
                for byte in (0..=u8::MAX).rev() {
                    let mut next = prefix.clone();
                    next.push(byte);
                    prefixes.push(next);
                }
            } else {
                for (key, raw) in page {
                    let head: Head = serde_json::from_slice(raw.as_slice()).map_err(error)?;
                    if head.node != node {
                        continue;
                    }
                    let id: [u8; 16] = key
                        .try_into()
                        .map_err(|_| error("invalid running money key"))?;
                    let (_, checkpoint, seal) = self.selected(&lane, &id, raw.as_slice())?;
                    out.push(checkpoint);
                    seals.push(seal);
                }
            }
        }
        seals.sort_by_key(|seal| seal.sequence);
        verify_stored_chain_with_seals(calls.as_ref(), node, &seals).map_err(error)?;
        if !lane.recovery_fence_matches(node, &fences).map_err(error)? {
            return Err(error("node fence changed during running money replay"));
        }
        Ok(out)
    }
}

impl UnitCheckpointSink for StoreCheckpoints {
    fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        off_runtime(|| self.persist_at(snapshot))
    }
    fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        off_runtime(|| self.remove_at(snapshot))
    }
    fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        off_runtime(|| self.replay_at())
    }
    fn recover_audit(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        off_runtime(|| super::unit_checkpoint_audit::recover(&self.book, snapshot))
    }
}

pub(crate) fn unit_checkpoint_sink(book: &Arc<Mutex<Durability>>) -> Arc<dyn UnitCheckpointSink> {
    Arc::new(StoreCheckpoints {
        book: book.clone(),
        token: busbar_kernel::teller::Kernel::new().durability_token(),
        driving: Mutex::new(()),
    })
}

#[cfg(test)]
#[path = "unit_checkpoint_tests.rs"]
mod tests;
