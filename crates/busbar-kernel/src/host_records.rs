// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};
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
    native_pending: Option<crate::persistence::facade::PendingId>,
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
            native_pending: None,
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

struct NativeWrite {
    write: Write,
    request: Option<crate::persistence::scoped::Request>,
    pending: Option<crate::persistence::facade::PendingId>,
    positions: Vec<crate::host_chains::ConditionalPosition>,
    private: bool,
    conflicts: usize,
}

impl NativeWrite {
    async fn attempt(
        &mut self,
        store: &Arc<crate::persistence::facade::CoreStore>,
        book: &crate::host_chains::ChainBook,
    ) -> Option<Result<(), &'static str>> {
        use crate::persistence::scoped::{Mutation, Outcome, Predicate, Request, ScopedStore};
        let schemas = [
            self.write.schema.as_str().to_string(),
            crate::host_chains::CHAIN_LIFE_SCHEMA.as_str().to_string(),
        ];
        let scoped = match if self.private {
            ScopedStore::host_private(Arc::clone(store), &self.write.instance, schemas.clone())
        } else {
            ScopedStore::authorized(Arc::clone(store), &self.write.instance, schemas.clone())
        } {
            Ok(scoped) => scoped,
            Err(_) => return Some(Err(WRITE_FAILED)),
        };
        if self.request.is_none() {
            let operation = match store.next_id() {
                Ok(id) => id.operation,
                Err(_) => return Some(Err(WRITE_FAILED)),
            };
            if let Some(framing) = self.write.chain {
                let rows = match crate::host_records_async::AsyncRecords::authorized(
                    Arc::clone(store),
                    &self.write.instance,
                    schemas,
                ) {
                    Ok(rows) => rows,
                    Err(_) => return Some(Err(WRITE_FAILED)),
                };
                let scope = match std::str::from_utf8(&self.write.key) {
                    Ok(scope) => scope,
                    Err(_) => return Some(Err(crate::host_chains::CHAIN_SCOPE_UNFIT)),
                };
                let input = crate::host_chains::OrdinaryChain {
                    instance: &self.write.instance,
                    schema: self.write.schema,
                    scope,
                    content: self.write.value.as_slice(),
                    framing,
                };
                let (request, position) =
                    match book.prepare_ordinary_async(&rows, input, operation).await {
                        Ok(prepared) => prepared,
                        Err(why) => return Some(Err(why)),
                    };
                match native_request(&self.write.instance, &request) {
                    Ok(request) => self.request = Some(request),
                    Err(why) => return Some(Err(why)),
                };
                self.positions.push(position);
            } else {
                self.request = Some(Request {
                    op_id: operation,
                    predicates: Vec::<Predicate>::new(),
                    mutations: vec![if self.write.value.as_slice().is_empty() {
                        Mutation::Delete {
                            schema: self.write.schema.as_str().into(),
                            key: self.write.key.clone(),
                        }
                    } else {
                        Mutation::Put {
                            schema: self.write.schema.as_str().into(),
                            key: self.write.key.clone(),
                            value: busbar_contract::Secret::new(
                                self.write.value.as_slice().to_vec(),
                            ),
                        }
                    }],
                });
            }
        }
        let result = match self.pending {
            Some(id) => scoped.retry(id).await,
            None => scoped.conditional_native(self.request.as_ref()?).await,
        };
        match result {
            Ok(Outcome::Applied) => {
                for position in &self.positions {
                    book.conditional_settled(position, conditional::Decision::Applied);
                }
                Some(Ok(()))
            }
            Ok(Outcome::ConditionConflict) if self.write.chain.is_some() => {
                for position in &self.positions {
                    book.conditional_settled(position, conditional::Decision::ConditionConflict);
                }
                self.request = None;
                self.pending = None;
                self.positions.clear();
                self.conflicts += 1;
                if self.conflicts >= crate::host_chains::CLAIM_ATTEMPTS {
                    Some(Err(WRITE_FAILED))
                } else {
                    None
                }
            }
            Ok(Outcome::ConditionConflict | Outcome::OpIdConflict | Outcome::NoEffect(_)) => {
                Some(Err(WRITE_FAILED))
            }
            Ok(Outcome::Pending(id) | Outcome::Reconcile(id) | Outcome::Busy(Some(id))) => {
                self.pending = Some(id);
                None
            }
            Ok(Outcome::Busy(None)) => None,
            Err(_) if self.pending.is_some() => None,
            Err(_) => Some(Err(WRITE_FAILED)),
        }
    }
}

fn native_request(
    instance: &str,
    request: &conditional::Request,
) -> Result<crate::persistence::scoped::Request, &'static str> {
    use crate::persistence::scoped::{Expected, Mutation, Predicate, Request};
    let scope = record_key(instance, &[]);
    let key = |key: &[u8]| {
        key.strip_prefix(scope.as_slice())
            .map(<[u8]>::to_vec)
            .ok_or(WRITE_FAILED)
    };
    Ok(Request {
        op_id: request.op_id.0,
        predicates: request
            .predicates
            .iter()
            .map(|predicate| {
                Ok(Predicate {
                    schema: predicate.schema.clone(),
                    key: key(&predicate.key)?,
                    expected: match &predicate.expected {
                        conditional::Expected::Absent => Expected::Absent,
                        conditional::Expected::Bytes(bytes) => {
                            Expected::Exact(busbar_contract::Secret::new(bytes.clone()))
                        }
                    },
                })
            })
            .collect::<Result<_, &'static str>>()?,
        mutations: request
            .mutations
            .iter()
            .map(|mutation| {
                Ok(match mutation {
                    conditional::Mutation::Put {
                        schema,
                        key: at,
                        value,
                    } => Mutation::Put {
                        schema: schema.clone(),
                        key: key(at)?,
                        value: busbar_contract::Secret::new(value.clone()),
                    },
                    conditional::Mutation::Delete { schema, key: at } => Mutation::Delete {
                        schema: schema.clone(),
                        key: key(at)?,
                    },
                    conditional::Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => Mutation::DeleteRange {
                        schema: schema.clone(),
                        prefix: key(prefix)?,
                        exact_key_length: exact_key_length
                            .checked_sub(scope.len() as u64)
                            .ok_or(WRITE_FAILED)?,
                    },
                })
            })
            .collect::<Result<_, &'static str>>()?,
    })
}

impl ConditionalWrite {
    async fn attempt_native(
        &mut self,
        store: &Arc<crate::persistence::facade::CoreStore>,
        book: &crate::host_chains::ChainBook,
    ) -> Option<Result<conditional::Decision, ConditionalFailure>> {
        use crate::persistence::scoped::Outcome;
        let mut schemas: std::collections::BTreeSet<String> = self
            .request
            .predicates
            .iter()
            .map(|p| p.schema.clone())
            .chain(
                self.request
                    .mutations
                    .iter()
                    .map(|m| m.address().0.to_string()),
            )
            .collect();
        for chain in self.chains.iter() {
            schemas.insert(chain.schema.as_str().to_string());
        }
        schemas.insert(crate::host_chains::CHAIN_LIFE_SCHEMA.as_str().to_string());
        let rows = match crate::host_records_async::AsyncRecords::authorized(
            Arc::clone(store),
            &self.instance,
            schemas,
        ) {
            Ok(rows) => rows,
            Err(_) => return Some(Err(ConditionalFailure::Refused(WRITE_FAILED))),
        };
        if !self.prepared {
            // Discovery may await between chains. Publish the complete plan to
            // retained queue custody only after every chain has been prepared;
            // cancellation cannot append a second copy to a partial request.
            let mut request = zeroize::Zeroizing::new((*self.request).clone());
            let mut positions = Vec::new();
            for chain in self.chains.iter() {
                match chain
                    .prepare_async(&rows, &self.instance, &mut request, book)
                    .await
                {
                    Ok(position) => positions.push(position),
                    Err(why) => return Some(Err(ConditionalFailure::Refused(why))),
                }
            }
            if request.encode_held().is_err() {
                return Some(Err(ConditionalFailure::Refused(
                    "invalid record transaction",
                )));
            }
            self.request = request;
            self.positions = positions;
            self.prepared = true;
        }
        let result = match self.native_pending {
            Some(id) => rows.retry(id).await,
            None => rows.conditional(&self.request).await,
        };
        let decision = match result {
            Ok(Outcome::Applied) => conditional::Decision::Applied,
            Ok(Outcome::ConditionConflict) => conditional::Decision::ConditionConflict,
            Ok(Outcome::OpIdConflict) => return Some(Err(ConditionalFailure::OpIdConflict)),
            Ok(Outcome::Pending(id) | Outcome::Busy(Some(id))) => {
                self.native_pending = Some(id);
                return None;
            }
            Ok(Outcome::Reconcile(id)) => {
                self.native_pending = Some(id);
                if let Some(acked) = self.owed.acked.take() {
                    acked(ConditionalResult {
                        correlation: self.owed.correlation,
                        decision: Err(ConditionalFailure::Indeterminate),
                    })
                };
                return None;
            }
            Ok(Outcome::Busy(None)) => return None,
            Ok(Outcome::NoEffect(_)) => {
                return Some(Err(ConditionalFailure::Refused(WRITE_FAILED)))
            }
            Err(_) if self.native_pending.is_some() => return None,
            Err(_) => return Some(Err(ConditionalFailure::Refused(WRITE_FAILED))),
        };
        for position in &self.positions {
            book.conditional_settled(position, decision);
        }
        Some(Ok(decision))
    }
}

impl std::fmt::Debug for NativeWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeWrite")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum QueuedWrite {
    Ordinary(Write),
    Conditional(ConditionalWrite),
    Native(NativeWrite),
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

/// A cancelled asynchronous waiter returns its exact prepared writes to the
/// existing queue before releasing the single-flush flag.
struct AsyncBatch {
    owner: Arc<WriteBehind>,
    batch: std::collections::VecDeque<QueuedWrite>,
    unresolved: Vec<QueuedWrite>,
    count: usize,
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

    pub(crate) async fn flush_native(
        self: &Arc<Self>,
        pending: &PendingRecords,
        store: &Arc<crate::persistence::facade::CoreStore>,
        chains: &crate::host_chains::ChainBook,
    ) {
        loop {
            let batch = {
                let mut queue = self.lock();
                let count = queue.writes.len().min(BATCH_CAP);
                let batch: std::collections::VecDeque<_> = queue.writes.drain(..count).collect();
                queue.in_flight += count;
                if count == 0 {
                    queue.flushing = false;
                    return;
                }
                batch
            };
            let mut held = AsyncBatch {
                owner: Arc::clone(self),
                count: batch.len(),
                batch,
                unresolved: Vec::new(),
            };
            while !held.batch.is_empty() {
                if matches!(held.batch.front(), Some(QueuedWrite::Ordinary(_))) {
                    if let Some(QueuedWrite::Ordinary(write)) = held.batch.pop_front() {
                        held.batch.push_front(QueuedWrite::Native(NativeWrite {
                            write,
                            request: None,
                            pending: None,
                            positions: Vec::new(),
                            private: false,
                            conflicts: 0,
                        }));
                    }
                }
                match held.batch.front_mut() {
                    Some(QueuedWrite::Native(write)) => {
                        let result = write.attempt(store, chains).await;
                        if let Some(result) = result {
                            if let Some(QueuedWrite::Native(write)) = held.batch.pop_front() {
                                pending.acked(
                                    &write.write.instance,
                                    write.write.schema.as_str(),
                                    &write.write.key,
                                    write.write.seq,
                                );
                                write.write.owed.answer(result);
                            }
                        } else if let Some(write) = held.batch.pop_front() {
                            held.unresolved.push(write);
                            held.unresolved.extend(held.batch.drain(..));
                            break;
                        }
                    }
                    Some(QueuedWrite::Conditional(write)) => {
                        let result = write.attempt_native(store, chains).await;
                        if let Some(result) = result {
                            if let Some(QueuedWrite::Conditional(write)) = held.batch.pop_front() {
                                write.owed.answer(result);
                            }
                        } else if let Some(write) = held.batch.pop_front() {
                            held.unresolved.push(write);
                            held.unresolved.extend(held.batch.drain(..));
                            break;
                        }
                    }
                    _ => unreachable!("ordinary writes converted before crossing"),
                }
            }
            let retry = !held.unresolved.is_empty();
            {
                let mut queue = self.lock();
                queue.in_flight -= held.count;
                if retry {
                    let mut retained = std::mem::take(&mut held.unresolved);
                    retained.append(&mut queue.writes);
                    queue.writes = retained;
                    queue.flushing = false;
                }
            }
            held.count = 0;
            if retry {
                return;
            }
        }
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
                    QueuedWrite::Native(w) => {
                        unresolved.push(QueuedWrite::Native(w));
                        continue;
                    }
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
