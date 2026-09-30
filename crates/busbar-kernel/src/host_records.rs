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
//!   `(kind, key)` to the bytes, or a tombstone. Each write is enqueued here and drained through
//!   [`PendingRecords::acked`] once the store took it; a read consults it first, so an instance
//!   always reads what it wrote.
//! * [`WriteBehind`] batches the writes to the store: a burst queues behind the one flush that is
//!   running, which writes everything queued, batch after batch, then ends; a write the store
//!   refuses stays queued, first in line for the next flush.
//! * [`record_key`] scopes every stored key by the instance's LABEL: two instances declaring one
//!   kind (of one plugin or of two) never read or write each other's records.
//! * The list rule, laying the overlay over the store's rows, is the contract's
//!   [`busbar_contract::services::merge_list`].

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, Store, StoreError};

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

impl<T: Store> RecordRows for T {
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), StoreError> {
        Store::record_put(self, schema, key, value)
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        Store::record_get(self, schema, key)
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        Store::record_scan(self, schema, prefix, limit)
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
type Queued = (u64, Option<Vec<u8>>);

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

    /// Queue `instance`'s write of `(kind, key)`: `Some` bytes, or `None` for a delete. Answers the
    /// write's sequence, which the batch that carries it is acknowledged up to.
    pub fn enqueue(&self, instance: &str, kind: &str, key: &[u8], value: Option<Vec<u8>>) -> u64 {
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

    /// `instance`'s queued write of `(kind, key)`: `Some(Some(bytes))`, `Some(None)` for a queued
    /// delete, or `None` when nothing is queued.
    #[must_use]
    pub fn get(&self, instance: &str, kind: &str, key: &[u8]) -> Option<Option<Vec<u8>>> {
        self.lock()
            .get(instance)?
            .get(&(kind.to_string(), key.to_vec()))
            .map(|(_, v)| v.clone())
    }

    /// `instance`'s queued writes of `kind` under `prefix`, in key order.
    #[must_use]
    pub fn under(
        &self,
        instance: &str,
        kind: &str,
        prefix: &[u8],
    ) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
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

    /// Queue `write`. `true` when no flush is running: the caller starts one.
    pub fn push(&self, write: Write) -> bool {
        let mut q = self.lock();
        q.writes.push(write);
        !std::mem::replace(&mut q.flushing, true)
    }

    /// The flush that was to run will not: the next write starts one.
    pub fn abandon(&self) {
        self.lock().flushing = false;
    }

    /// THE FLUSH: write every queued write to `rows`, batch after batch, and acknowledge each in
    /// `pending`; end when nothing is queued. A write the store refuses ends the flush and stays
    /// queued ahead of the rest, in order, for the next.
    pub fn flush(&self, pending: &PendingRecords, rows: &dyn RecordRows) {
        loop {
            let batch = {
                let mut q = self.lock();
                let batch = std::mem::take(&mut q.writes);
                if batch.is_empty() {
                    q.flushing = false;
                    return;
                }
                batch
            };
            let mut writes = batch.into_iter();
            for w in writes.by_ref() {
                let key = record_key(&w.instance, &w.key);
                if rows.record_put(w.schema, &key, &w.value).is_err() {
                    let mut q = self.lock();
                    let mut kept = vec![w];
                    kept.extend(writes);
                    kept.append(&mut q.writes);
                    q.writes = kept;
                    q.flushing = false;
                    return;
                }
                pending.acked(&w.instance, w.schema.as_str(), &w.key, w.seq);
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/host_records_tests.rs"]
mod tests;
