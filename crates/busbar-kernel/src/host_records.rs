// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORDS BEHIND `records.get` / `records.list` (`BUSBAR-1.6.0.md` THE DESIGN, host services):
//! the store's typed record surface a caller's records are read through, and the kernel-owned
//! overlay of each instance's queued writes that makes those reads see the instance's own writes.
//!
//! * [`RecordRows`] is the store kind's `record_put` / `record_get` / `record_scan` (store v3 slots
//!   `RECORD_PUT` / `RECORD_GET` / `RECORD_SCAN`), keyed by the caller's declared record kind as the
//!   schema.
//! * [`PendingRecords`] holds what an instance wrote and the store has not yet acknowledged:
//!   `(kind, key)` to the bytes. Each write is enqueued here and drained through
//!   [`PendingRecords::acked`] once the store took it; a read consults it first, so an instance
//!   always reads what it wrote.
//! * [`WriteBehind`] batches the writes to the store: a burst queues behind the one flush that is
//!   running, which writes everything queued, batch after batch, then ends. A write is ANSWERED only
//!   once the store took it ([`Acked`]): a write is durable before its writer hears so, as the
//!   durable handle engine's write-through is. A write the store refuses answers FAILED and leaves
//!   the overlay.
//! * THE BOUNDS (ruling H2 U10): at most [`QUEUE_CAP`] writes wait (a write past it is refused,
//!   and fails the op that carried it), at most [`BATCH_CAP`] cross in one batch, and a flush the
//!   pool refused is restarted within [`FLUSH_INTERVAL`] by the kernel's cadence
//!   (`KernelServices::flushes`), never left to wait on a later write.
//! * THE CRASH WINDOW: what a crash loses is exactly the queued writes (at most [`QUEUE_CAP`]), and
//!   none of them was answered: the op that carried each never completed, so no caller was told it
//!   was kept. Every answered write is in the store. A graceful stop drains the queue
//!   (`KernelServices::drain`, under its own deadline, so a hung store cannot hold the stop).
//! * NEVER BEHIND: `records.claim` (approval redemption, replay refusal, idempotency) is the store's
//!   own one-time put, answered only after the store decided it; it never joins this queue. Money
//!   writes do not reach this path at all.
//! * [`record_key`] scopes every stored key by the instance's LABEL: two instances declaring one
//!   kind (of one plugin or of two) never read or write each other's records.
//! * The list rule, laying the overlay over the store's rows, is the contract's
//!   [`busbar_contract::services::merge_list`].

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};

/// The store kind's typed records.
pub trait RecordRows: Send + Sync {
    /// Write one record.
    ///
    /// # Errors
    ///
    /// The store's.
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError>;

    /// One record, or `None`.
    ///
    /// # Errors
    ///
    /// The store's.
    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError>;

    /// The records under `prefix`, in key order, at most `limit` (`0` = none).
    ///
    /// # Errors
    ///
    /// The store's.
    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError>;
}

/// THE CONFIGURED STORE'S TYPED RECORDS, as [`RecordRows`]: its store v3 record slots
/// ([`busbar_contract::store_calls::StoreCalls`]), each call awaited where it is made. The host
/// services call these only on their blocking pool (never on a runtime worker), so a call waits
/// there for the store's answer. A store that FAILED or REFUSED the call answers its text.
pub struct StoreRows(pub Arc<dyn busbar_contract::store_calls::StoreCalls>);

impl std::fmt::Debug for StoreRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreRows").finish_non_exhaustive()
    }
}

/// The store's answer to one awaited call, as the records' error.
fn awaited<T>(call: busbar_contract::store_calls::StoreCall<'_, T>) -> Result<T, StoreError> {
    futures::executor::block_on(call).map_err(|failure| match failure {
        busbar_contract::store_calls::StoreFailure::Refused(text) => StoreError::Rejected(text),
        _ => StoreError::Unavailable,
    })
}

impl RecordRows for StoreRows {
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
}

/// The store key of `key` for the instance labelled `instance`: the label's length (two bytes, big
/// endian), the label, then the key. The length makes the scope unambiguous whatever the label
/// holds, and a key's scoped form begins with its prefix's scoped form, so a prefix scan stays one.
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

/// One queued write: its sequence, and its bytes or a tombstone.
type Queued = (u64, Vec<u8>);

/// Every instance's queued writes, by `(kind, key)`.
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

    /// Queue `instance`'s write of `value` under `(kind, key)`. Answers the write's sequence, which
    /// the store's acknowledgement names.
    pub fn enqueue(&self, instance: &str, kind: &str, key: &[u8], value: Vec<u8>) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock()
            .entry(Arc::from(instance))
            .or_default()
            .insert((kind.to_string(), key.to_vec()), (seq, value));
        seq
    }

    /// The store took `instance`'s write `seq` of `(kind, key)`: it reads from the store from now
    /// on. A write to the same key queued after it stays queued.
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

    /// `instance`'s queued write of `(kind, key)`, or `None` when nothing is queued.
    #[must_use]
    pub fn get(&self, instance: &str, kind: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.lock()
            .get(instance)?
            .get(&(kind.to_string(), key.to_vec()))
            .map(|(_, v)| v.clone())
    }

    /// `instance`'s queued writes of `kind` under `prefix`, in key order.
    #[must_use]
    pub fn under(&self, instance: &str, kind: &str, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.lock().get(instance).map_or_else(Vec::new, |q| {
            q.iter()
                .filter(|((k, key), _)| k == kind && key.starts_with(prefix))
                .map(|((_, key), (_, v))| (key.clone(), v.clone()))
                .collect()
        })
    }

    /// How many writes are queued, over every instance.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.lock().values().map(BTreeMap::len).sum()
    }
}

/// The most writes one batch carries to the store.
pub const BATCH_CAP: usize = 256;
/// The most writes that wait for the store; a write past it is refused.
pub const QUEUE_CAP: usize = 4096;
/// How often the kernel's flush cadence (`KernelServices::flushes`) restarts a flush that did not
/// run (its pool refused it), so a queued write is never left waiting on the next write.
pub const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Where a record write's answer goes, once: `Ok` when the store took it, or the refusal.
pub type Acked = Box<dyn FnOnce(Result<(), &'static str>) + Send>;

/// The answer of a write the store did not take.
pub const WRITE_FAILED: &str = "the store did not take the write";
/// The answer of a write dropped before any flush reached it.
pub const WRITE_DROPPED: &str = "the write was dropped before the store took it";

/// A write's owed answer. Dropped unanswered it answers [`WRITE_DROPPED`]: a writer never waits on
/// a write nobody will make.
pub struct Owed(Option<Acked>);

impl Owed {
    /// Owe `acked` its answer.
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
}

#[derive(Debug, Default)]
struct Queue {
    writes: Vec<Write>,
    flushing: bool,
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

    /// Queue the write `make` builds, if there is room: `make` runs under the queue's lock, so a
    /// write the queue refuses never reaches the overlay. `Some(true)` when no flush is running
    /// (the caller starts one), `None` when [`QUEUE_CAP`] writes already wait.
    pub fn push_with(&self, make: impl FnOnce() -> Write) -> Option<bool> {
        let mut q = self.lock();
        if q.writes.len() >= QUEUE_CAP {
            return None;
        }
        q.writes.push(make());
        Some(!std::mem::replace(&mut q.flushing, true))
    }

    /// The tick: `true` when writes wait and no flush is running; the caller starts one.
    pub fn start(&self) -> bool {
        let mut q = self.lock();
        !q.writes.is_empty() && !std::mem::replace(&mut q.flushing, true)
    }

    /// Nothing waits and no flush runs.
    #[must_use]
    pub fn idle(&self) -> bool {
        let q = self.lock();
        q.writes.is_empty() && !q.flushing
    }

    /// The flush that was to run will not: the next write starts one.
    pub fn abandon(&self) {
        self.lock().flushing = false;
    }

    /// THE FLUSH: write every queued write to `rows`, in order, at most [`BATCH_CAP`] a batch; answer each once
    /// the store took it and acknowledge it in `pending`; end when nothing is queued. A write the
    /// store refuses answers [`WRITE_FAILED`] and leaves the overlay; the rest go on.
    pub fn flush(&self, pending: &PendingRecords, rows: &dyn RecordRows) {
        loop {
            let batch = {
                let mut q = self.lock();
                let n = q.writes.len().min(BATCH_CAP);
                let batch: Vec<Write> = q.writes.drain(..n).collect();
                if batch.is_empty() {
                    q.flushing = false;
                    return;
                }
                batch
            };
            for w in batch {
                let key = record_key(&w.instance, &w.key);
                let took = rows.record_put(w.schema, &key, &w.value);
                pending.acked(&w.instance, w.schema.as_str(), &w.key, w.seq);
                w.owed.answer(took.map_err(|_| WRITE_FAILED));
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/host_records_tests.rs"]
mod tests;
