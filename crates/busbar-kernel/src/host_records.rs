// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::host_records::conditional;
use busbar_contract::host_records::RecordFailure;
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};

pub trait RecordRows: Send + Sync {
    fn supports_record_transaction(&self) -> bool {
        false
    }

    fn record_transaction(
        &self,
        _request: &conditional::Request,
    ) -> Result<conditional::Decision, RecordFailure> {
        Err(RecordFailure::Refused(
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

/// The length of [`record_key`]'s instance scope: what precedes the writer's own key in it.
#[must_use]
pub fn record_scope_len(instance: &str) -> usize {
    2 + instance.len()
}

/// One unacknowledged write: its sequence and its bytes, the same bytes its [`Write`] carries to
/// the store (shared, never copied).
type Queued = (u64, Arc<RecordBytes>);

/// One instance's unacknowledged writes, by record kind and then key: a lookup borrows both. A
/// kind is named by its schema's own fixed name.
type KindQueues = BTreeMap<&'static str, BTreeMap<Vec<u8>, Queued>>;

type Queues = HashMap<Arc<str>, KindQueues>;

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

    /// Lay one unacknowledged write on the overlay and answer its sequence. `kind` is the record
    /// schema's own name. The instance label and the bytes are the caller's, shared: the overlay
    /// copies neither. The key is the overlay's own, held until the write is acknowledged.
    pub fn enqueue(
        &self,
        instance: &Arc<str>,
        kind: &'static str,
        key: &[u8],
        value: &Arc<RecordBytes>,
    ) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut map = self.lock();
        if !map.contains_key(instance.as_ref()) {
            map.insert(Arc::clone(instance), KindQueues::default());
        }
        let Some(kinds) = map.get_mut(instance.as_ref()) else {
            return seq;
        };
        let keys = kinds.entry(kind).or_default();
        match keys.get_mut(key) {
            Some(queued) => *queued = (seq, Arc::clone(value)),
            None => {
                keys.insert(key.to_vec(), (seq, Arc::clone(value)));
            }
        }
        seq
    }

    pub fn acked(&self, instance: &str, kind: &str, key: &[u8], seq: u64) {
        let mut map = self.lock();
        let Some(keys) = map.get_mut(instance).and_then(|kinds| kinds.get_mut(kind)) else {
            return;
        };
        if keys.get(key).is_some_and(|(queued, _)| *queued == seq) {
            keys.remove(key);
        }
    }

    #[must_use]
    pub fn get(&self, instance: &str, kind: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.lock()
            .get(instance)?
            .get(kind)?
            .get(key)
            .map(|(_, v)| v.as_slice().to_vec())
    }

    #[must_use]
    pub fn under(&self, instance: &str, kind: &str, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        use std::ops::Bound;
        let map = self.lock();
        let Some(keys) = map.get(instance).and_then(|kinds| kinds.get(kind)) else {
            return Vec::new();
        };
        keys.range::<[u8], _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, (_, v))| (key.to_vec(), v.as_slice().to_vec()))
            .collect()
    }

    #[must_use]
    pub fn queued(&self) -> usize {
        self.lock()
            .values()
            .flat_map(BTreeMap::values)
            .map(BTreeMap::len)
            .sum()
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

    pub(crate) fn answer(mut self, result: Result<(), &'static str>) {
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

/// A queued write's bytes. A write laid on the overlay shares them with its overlay row, so
/// they are not copied for it; a write with no overlay row (a chained write, a private work
/// write) holds them alone, exactly as it was handed them.
#[derive(Debug)]
pub enum WriteBytes {
    /// The write's own bytes: nothing else holds them.
    Own(RecordBytes),
    /// The bytes this write's overlay row holds too.
    Shared(Arc<RecordBytes>),
}

impl std::ops::Deref for WriteBytes {
    type Target = RecordBytes;

    fn deref(&self) -> &RecordBytes {
        match self {
            Self::Own(bytes) => bytes,
            Self::Shared(bytes) => bytes,
        }
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
    /// The bytes: shared with this write's overlay row when it has one, its own otherwise.
    pub value: WriteBytes,
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
    pub(crate) correlation: u64,
    pub(crate) acked: Option<ConditionalAcked>,
}

impl ConditionalOwed {
    pub(crate) fn new(correlation: u64, acked: ConditionalAcked) -> Self {
        Self {
            correlation,
            acked: Some(acked),
        }
    }

    pub(crate) fn answer(mut self, decision: Result<conditional::Decision, ConditionalFailure>) {
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
    pub request: conditional::Request,
    /// On CoreStore, the receipt identity `request.op_id` derives from: every retry, before or
    /// after CoreStore's logical entry pops, keeps its generation pinned (DES-264 §4.1).
    pub held: Option<crate::persistence::record_ops::HeldOp>,
    pub chains: Vec<crate::host_chains::ConditionalChain>,
    pub owed: ConditionalOwed,
    _unit: Option<Arc<crate::host_units::UnitRecord>>,
    pub(crate) prepared: bool,
    uncertain: bool,
    pub(crate) positions: Vec<crate::host_chains::ConditionalPosition>,
    pub(crate) native_pending: Option<crate::persistence::facade::PendingId>,
}

impl ConditionalWrite {
    pub(crate) fn new(
        instance: Arc<str>,
        request: conditional::Request,
        held: Option<crate::persistence::record_ops::HeldOp>,
        chains: Vec<crate::host_chains::ConditionalChain>,
        owed: ConditionalOwed,
        unit: Option<Arc<crate::host_units::UnitRecord>>,
    ) -> Self {
        Self {
            instance,
            request,
            held,
            chains,
            owed,
            _unit: unit,
            prepared: false,
            uncertain: false,
            positions: Vec::new(),
            native_pending: None,
        }
    }

    pub(crate) fn attempt(
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
        // An ambiguous write is resent with its exact operation, however old: its slot is held
        // until it settles, so the store replays the recorded verdict (STORE-TRANSACTIONS N8).
        match rows.record_transaction(&self.request) {
            Ok(decision) => {
                for position in &self.positions {
                    book.conditional_settled(position, decision);
                }
                self.owed.answer(Ok(decision));
                None
            }
            Err(RecordFailure::Conflict) => {
                self.owed.answer(Err(ConditionalFailure::OpIdConflict));
                None
            }
            Err(RecordFailure::Refused(_)) if self.uncertain => Some(self),
            Err(RecordFailure::Refused(_)) => {
                self.owed
                    .answer(Err(ConditionalFailure::Refused(WRITE_FAILED)));
                None
            }
            Err(RecordFailure::Failed(_) | RecordFailure::Fault(_)) => {
                self.uncertain = true;
                Some(self)
            }
            Err(RecordFailure::Overloaded) => Some(self),
        }
    }
}

pub(crate) struct NativeWrite {
    pub(crate) write: Write,
    pub(crate) request: Option<crate::persistence::scoped::Request>,
    pub(crate) pending: Option<crate::persistence::facade::PendingId>,
    pub(crate) positions: Vec<crate::host_chains::ConditionalPosition>,
    pub(crate) private: bool,
    pub(crate) conflicts: usize,
}
impl std::fmt::Debug for NativeWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeWrite")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) enum QueuedWrite {
    Ordinary(Write),
    Conditional(ConditionalWrite),
    Native(NativeWrite),
}

#[derive(Debug, Default)]
pub(crate) struct Queue {
    pub(crate) writes: Vec<QueuedWrite>,
    pub(crate) flushing: bool,
    pub(crate) in_flight: usize,
}

/// THE WRITE-BEHIND BATCHER of record writes: at most one flush runs at a time.
#[derive(Debug, Default)]
pub struct WriteBehind {
    queue: Mutex<Queue>,
}

/// A cancelled asynchronous waiter returns its exact prepared writes to the
/// existing queue before releasing the single-flush flag.
pub(crate) struct AsyncBatch {
    pub(crate) owner: Arc<WriteBehind>,
    pub(crate) batch: std::collections::VecDeque<QueuedWrite>,
    pub(crate) unresolved: Vec<QueuedWrite>,
    pub(crate) count: usize,
}
impl Drop for AsyncBatch {
    fn drop(&mut self) {
        if self.count == 0 {
            return;
        }
        let mut queue = self.owner.lock();
        queue.in_flight -= self.count;
        let mut retained = std::mem::take(&mut self.unresolved);
        retained.extend(self.batch.drain(..));
        retained.append(&mut queue.writes);
        queue.writes = retained;
        queue.flushing = false;
    }
}

impl WriteBehind {
    pub(crate) fn lock(&self) -> MutexGuard<'_, Queue> {
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

    pub(crate) fn push_native_with(&self, make: impl FnOnce() -> Write) -> Option<bool> {
        let mut queue = self.lock();
        if queue.writes.len() + queue.in_flight >= QUEUE_CAP {
            return None;
        }
        queue.writes.push(QueuedWrite::Native(NativeWrite {
            write: make(),
            request: None,
            pending: None,
            positions: Vec::new(),
            private: false,
            conflicts: 0,
        }));
        Some(!std::mem::replace(&mut queue.flushing, true))
    }

    pub(crate) fn push_native_private_with(&self, make: impl FnOnce() -> Write) -> Option<bool> {
        let mut queue = self.lock();
        if queue.writes.len() + queue.in_flight >= QUEUE_CAP {
            return None;
        }
        queue.writes.push(QueuedWrite::Native(NativeWrite {
            write: make(),
            request: None,
            pending: None,
            positions: Vec::new(),
            private: true,
            conflicts: 0,
        }));
        Some(!std::mem::replace(&mut queue.flushing, true))
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
}

#[cfg(test)]
#[path = "tests/host_records_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/host_conditional_records_tests.rs"]
mod conditional_tests;
