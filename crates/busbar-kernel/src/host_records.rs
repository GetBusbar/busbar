// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::abi::sdk::store::conditional;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_contract::store_calls::StoreFailure;

pub trait RecordRows: Send + Sync {
    fn supports_record_transaction(&self) -> bool {
        false
    }

    fn record_transaction(
        &self,
        _request: &conditional::Request,
    ) -> Result<conditional::Decision, StoreFailure> {
        Err(StoreFailure::Refused(
            "record transactions are unsupported".into(),
        ))
    }

    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError>;

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError>;

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError>;

    fn claim(&self, kind: &str, token: &str, expires_at: u64, now: u64)
        -> Result<bool, StoreError>;
}

pub const CLAIM_KIND: &str = "busbar.record-claim";

pub struct StoreRows(pub Arc<dyn busbar_contract::store_calls::StoreCalls>);

impl std::fmt::Debug for StoreRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreRows").finish_non_exhaustive()
    }
}

fn awaited<T>(call: busbar_contract::store_calls::StoreCall<'_, T>) -> Result<T, StoreError> {
    futures::executor::block_on(call).map_err(|failure| match failure {
        busbar_contract::store_calls::StoreFailure::Refused(text) => StoreError::Rejected(text),
        _ => StoreError::Unavailable,
    })
}

impl RecordRows for StoreRows {
    fn supports_record_transaction(&self) -> bool {
        self.0.supports_record_transaction()
    }

    fn record_transaction(
        &self,
        request: &conditional::Request,
    ) -> Result<conditional::Decision, StoreFailure> {
        futures::executor::block_on(self.0.record_transaction(request))
    }

    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        awaited(self.0.record_put(schema.as_str(), key, value))
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        awaited(self.0.record_get(schema.as_str(), key))
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        awaited(self.0.record_scan(schema.as_str(), prefix, limit))
    }

    fn claim(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<bool, StoreError> {
        awaited(self.0.redeem_plane_token(kind, token, expires_at, now))
    }
}

#[must_use]
pub fn record_key(instance: &str, key: &[u8]) -> Vec<u8> {
    let label = instance.as_bytes();
    let len = u16::try_from(label.len()).unwrap_or(u16::MAX);
    let mut k = Vec::with_capacity(2 + label.len() + key.len());
    k.extend_from_slice(&len.to_be_bytes());
    k.extend_from_slice(label);
    k.extend_from_slice(key);
    k
}

type Queued = (u64, Vec<u8>);

type Queues = HashMap<Arc<str>, BTreeMap<(String, Vec<u8>), Queued>>;

/// THE OVERLAY of every instance's unacknowledged writes.
#[derive(Debug, Default)]
pub struct PendingRecords {
    inner: Mutex<Queues>,
    seq: AtomicU64,
}

impl PendingRecords {
    fn lock(&self) -> MutexGuard<'_, Queues> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn enqueue(&self, instance: &str, kind: &str, key: &[u8], value: Vec<u8>) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock()
            .entry(Arc::from(instance))
            .or_default()
            .insert((kind.to_string(), key.to_vec()), (seq, value));
        seq
    }

    pub fn acked(&self, instance: &str, kind: &str, key: &[u8], seq: u64) {
        let mut map = self.lock();
        if let Some(q) = map.get_mut(instance) {
            let at = (kind.to_string(), key.to_vec());
            if q.get(&at).is_some_and(|(queued, _)| *queued == seq) {
                q.remove(&at);
            }
            if q.is_empty() {
                map.remove(instance);
            }
        }
    }

    #[must_use]
    pub fn get(&self, instance: &str, kind: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.lock()
            .get(instance)?
            .get(&(kind.to_string(), key.to_vec()))
            .map(|(_, v)| v.clone())
    }

    #[must_use]
    pub fn under(&self, instance: &str, kind: &str, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.lock().get(instance).map_or_else(Vec::new, |q| {
            q.iter()
                .filter(|((k, key), _)| k == kind && key.starts_with(prefix))
                .map(|((_, key), (_, v))| (key.clone(), v.clone()))
                .collect()
        })
    }

    #[must_use]
    pub fn queued(&self) -> usize {
        self.lock().values().map(BTreeMap::len).sum()
    }
}

pub const BATCH_CAP: usize = 256;

pub const QUEUE_CAP: usize = 4096;

pub const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

pub type Acked = Box<dyn FnOnce(Result<(), &'static str>) + Send>;

pub const WRITE_FAILED: &str = "the store did not take the write";

pub const WRITE_DROPPED: &str = "the write was dropped before the store took it";

pub struct Owed(Option<Acked>);

impl Owed {
    #[must_use]
    pub fn new(acked: Acked) -> Self {
        Self(Some(acked))
    }

    fn answer(mut self, result: Result<(), &'static str>) {
        if let Some(acked) = self.0.take() {
            acked(result);
        }
    }
}

impl Drop for Owed {
    fn drop(&mut self) {
        if let Some(acked) = self.0.take() {
            acked(Err(WRITE_DROPPED));
        }
    }
}

impl std::fmt::Debug for Owed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Owed")
    }
}

/// One write on its way to the store.
#[derive(Debug)]
pub struct Write {
    /// The writer's label.
    pub instance: Arc<str>,
    /// The record kind's schema.
    pub schema: RecordSchemaId,
    /// The writer's key, unscoped.
    pub key: Vec<u8>,
    /// The bytes.
    pub value: RecordBytes,
    /// Its sequence in [`PendingRecords`].
    pub seq: u64,
    /// Its writer's answer.
    pub owed: Owed,
    /// The declared framing of a chained kind's write: an APPEND to the chain `key` names (an
    /// empty value drops the chain), sealed by [`crate::host_chains::ChainBook`] and never laid on
    /// the overlay. `None` for a put.
    pub chain: Option<crate::host_chains::ChainFraming>,
}

pub use busbar_contract::abi::sdk::plane::conditional::{
    ChainMutation, ConditionalCandidate, ConditionalFailure, ConditionalResult, RecordMutation,
    RecordPredicate,
};

pub type ConditionalAcked = Box<dyn FnOnce(ConditionalResult) + Send>;

pub type ChainLifeAcked = Box<dyn FnOnce(Result<conditional::Expected, &'static str>) + Send>;

pub(crate) struct ConditionalOwed {
    correlation: u64,
    acked: Option<ConditionalAcked>,
}

impl ConditionalOwed {
    pub(crate) fn new(correlation: u64, acked: ConditionalAcked) -> Self {
        Self {
            correlation,
            acked: Some(acked),
        }
    }

    fn answer(mut self, decision: Result<conditional::Decision, ConditionalFailure>) {
        if let Some(acked) = self.acked.take() {
            acked(ConditionalResult {
                correlation: self.correlation,
                decision,
            });
        }
    }
}

impl std::fmt::Debug for ConditionalOwed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConditionalOwed")
            .field("correlation", &self.correlation)
            .finish()
    }
}

/// Host-owned admission. The exact prepared request survives caller cancellation and reload.
#[derive(Debug)]
pub(crate) struct ConditionalWrite {
    pub instance: Arc<str>,
    pub request: zeroize::Zeroizing<conditional::Request>,
    pub chains: zeroize::Zeroizing<Vec<crate::host_chains::ConditionalChain>>,
    pub owed: ConditionalOwed,
    _unit: Option<Arc<crate::host_units::UnitRecord>>,
    prepared: bool,
    submitted: Option<std::time::Instant>,
    uncertain: bool,
    positions: Vec<crate::host_chains::ConditionalPosition>,
}

impl ConditionalWrite {
    pub(crate) fn new(
        instance: Arc<str>,
        request: zeroize::Zeroizing<conditional::Request>,
        chains: zeroize::Zeroizing<Vec<crate::host_chains::ConditionalChain>>,
        owed: ConditionalOwed,
        unit: Option<Arc<crate::host_units::UnitRecord>>,
    ) -> Self {
        Self {
            instance,
            request,
            chains,
            owed,
            _unit: unit,
            prepared: false,
            submitted: None,
            uncertain: false,
            positions: Vec::new(),
        }
    }

    fn attempt(
        mut self,
        rows: &dyn RecordRows,
        book: &crate::host_chains::ChainBook,
    ) -> Option<Self> {
        if !self.prepared {
            for chain in self.chains.iter() {
                match chain.prepare(rows, &self.instance, &mut self.request, book) {
                    Ok(position) => self.positions.push(position),
                    Err(why) => {
                        self.owed.answer(Err(ConditionalFailure::Refused(why)));
                        return None;
                    }
                }
            }
            if self.request.encode_held().is_err() {
                self.owed.answer(Err(ConditionalFailure::Refused(
                    "invalid record transaction",
                )));
                return None;
            }
            self.prepared = true;
        }
        let first = *self.submitted.get_or_insert_with(std::time::Instant::now);
        if first.elapsed().as_secs() >= busbar_contract::abi::store::OP_ID_RETENTION_SECS {
            if let Some(acked) = self.owed.acked.take() {
                acked(ConditionalResult {
                    correlation: self.owed.correlation,
                    decision: Err(ConditionalFailure::Indeterminate),
                });
            }
            return Some(self);
        }
        match rows.record_transaction(&self.request) {
            Ok(decision) => {
                for position in &self.positions {
                    book.conditional_settled(position, decision);
                }
                self.owed.answer(Ok(decision));
                None
            }
            Err(StoreFailure::Conflict) => {
                self.owed.answer(Err(ConditionalFailure::OpIdConflict));
                None
            }
            Err(StoreFailure::Refused(_)) if self.uncertain => Some(self),
            Err(StoreFailure::Refused(_)) => {
                self.owed
                    .answer(Err(ConditionalFailure::Refused(WRITE_FAILED)));
                None
            }
            Err(StoreFailure::Failed(_) | StoreFailure::Fault(_)) => {
                self.uncertain = true;
                Some(self)
            }
            Err(StoreFailure::Overloaded) => Some(self),
        }
    }
}

#[derive(Debug)]
enum QueuedWrite {
    Ordinary(Write),
    Conditional(ConditionalWrite),
}

#[derive(Debug, Default)]
struct Queue {
    writes: Vec<QueuedWrite>,
    flushing: bool,
    in_flight: usize,
}

/// THE WRITE-BEHIND BATCHER of record writes: at most one flush runs at a time.
#[derive(Debug, Default)]
pub struct WriteBehind {
    queue: Mutex<Queue>,
}

impl WriteBehind {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn push_with(&self, make: impl FnOnce() -> Write) -> Option<bool> {
        let mut q = self.lock();
        if q.writes.len() + q.in_flight >= QUEUE_CAP {
            return None;
        }
        q.writes.push(QueuedWrite::Ordinary(make()));
        Some(!std::mem::replace(&mut q.flushing, true))
    }

    pub(crate) fn push_conditional(&self, write: ConditionalWrite) -> Option<bool> {
        let mut q = self.lock();
        if q.writes.len() + q.in_flight >= QUEUE_CAP {
            return None;
        }

        q.writes.reserve(1);
        q.writes.push(QueuedWrite::Conditional(write));
        Some(!std::mem::replace(&mut q.flushing, true))
    }

    pub fn start(&self) -> bool {
        let mut q = self.lock();
        !q.writes.is_empty() && !std::mem::replace(&mut q.flushing, true)
    }

    #[must_use]
    pub fn idle(&self) -> bool {
        let q = self.lock();
        q.writes.is_empty() && !q.flushing
    }

    pub fn abandon(&self) {
        self.lock().flushing = false;
    }

    pub fn flush(
        &self,
        pending: &PendingRecords,
        rows: &dyn RecordRows,
        chains: &crate::host_chains::ChainBook,
    ) {
        loop {
            let mut unresolved = Vec::new();
            let batch = {
                let mut q = self.lock();
                let n = q.writes.len().min(BATCH_CAP);
                let batch: Vec<QueuedWrite> = q.writes.drain(..n).collect();
                q.in_flight += batch.len();
                if batch.is_empty() {
                    q.flushing = false;
                    return;
                }
                batch
            };
            let batch_len = batch.len();
            for queued in batch {
                let w = match queued {
                    QueuedWrite::Ordinary(w) => w,
                    QueuedWrite::Conditional(w) => {
                        if let Some(write) = w.attempt(rows, chains) {
                            unresolved.push(QueuedWrite::Conditional(write));
                        }
                        continue;
                    }
                };
                if let Some(framing) = w.chain {
                    let scope = String::from_utf8_lossy(&w.key);
                    let took = if w.value.as_slice().is_empty() {
                        chains.drop_chain(rows, &w.instance, w.schema, &scope)
                    } else {
                        chains.append(
                            rows,
                            &w.instance,
                            w.schema,
                            &scope,
                            w.value.as_slice(),
                            framing,
                        )
                    };
                    w.owed.answer(took);
                    continue;
                }
                let key = record_key(&w.instance, &w.key);
                let took = rows.record_put(w.schema, &key, &w.value);
                pending.acked(&w.instance, w.schema.as_str(), &w.key, w.seq);
                w.owed.answer(took.map_err(|_| WRITE_FAILED));
            }
            let mut q = self.lock();
            q.in_flight -= batch_len;
            if !unresolved.is_empty() {
                q.writes.append(&mut unresolved);
                q.flushing = false;
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/host_records_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/host_conditional_records_tests.rs"]
mod conditional_tests;
