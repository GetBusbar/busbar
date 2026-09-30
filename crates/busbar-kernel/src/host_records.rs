// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORDS BEHIND `records.get` / `records.list` (`BUSBAR-1.6.0.md` THE DESIGN, host services):
//! the store's typed record surface a caller's records are read through, and the kernel-owned
//! overlay of each instance's queued writes that makes those reads see the instance's own writes.
//!
//! * [`RecordReads`] is the store kind's `record_get` / `record_scan` pair (store v3 slots
//!   `RECORD_GET` / `RECORD_SCAN`), keyed by the caller's declared record kind as the schema.
//! * [`PendingRecords`] holds what an instance wrote and the store has not yet acknowledged:
//!   `(kind, key)` to the bytes, or a tombstone. The plane driver's write-behind batcher enqueues each
//!   write and drains through [`PendingRecords::acked`] when the store acknowledges its batch; a read
//!   consults it first, so an instance always reads what it wrote.
//! * [`merge_list`] is the one list rule: the store's rows under the prefix, the overlay laid over
//!   them (a queued value replaces, a tombstone removes), then the keys after `after`, in key order,
//!   at most `limit`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, Store, StoreError};

/// The store kind's typed record reads.
pub trait RecordReads: Send + Sync {
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

impl<T: Store> RecordReads for T {
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

    /// The store acknowledged `instance`'s writes up to `upto`: they read from the store from now
    /// on. A write to the same key queued after `upto` stays queued.
    pub fn acked(&self, instance: &str, upto: u64) {
        let mut map = self.lock();
        if let Some(q) = map.get_mut(instance) {
            q.retain(|_, (seq, _)| *seq > upto);
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

/// THE LIST RULE: `stored` (the store's rows under the prefix) with `queued` laid over them, the
/// keys after `after`, in key order, at most `limit`.
#[must_use]
pub fn merge_list(
    stored: Vec<(Vec<u8>, Vec<u8>)>,
    queued: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    after: Option<&[u8]>,
    limit: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = stored.into_iter().collect();
    for (k, v) in queued {
        match v {
            Some(v) => {
                rows.insert(k, v);
            }
            None => {
                rows.remove(&k);
            }
        }
    }
    rows.into_iter()
        .filter(|(k, _)| after.is_none_or(|a| k.as_slice() > a))
        .take(limit)
        .collect()
}

#[cfg(test)]
#[path = "tests/host_records_tests.rs"]
mod tests;
