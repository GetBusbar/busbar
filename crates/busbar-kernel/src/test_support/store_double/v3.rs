// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the 1.5.5 op set ([`SyncStore`]): the
//! `op_id`-carrying count batches, plane records and the kernel-held records.
//!
//! DEDUPE (`abi::store` S1-S4): every `op_id` this store APPLIED is remembered, with the op's value
//! fields and its answer, for [`OP_ID_RETENTION_SECS`]. A replay with the same value fields applies
//! nothing and answers the original; different value fields are a conflict. The dedupe log lives
//! under ONE lock, and an op's dedupe check, its effect and its record happen under it, so two
//! racing calls with one `op_id` apply once. This store is EPHEMERAL (its Statement tail says so):
//! the log is lost on restart together with everything it guards, so a replay after a restart
//! re-applies onto an empty store, which is the state the restart left.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{OpRefused, OpResult, Scanned, SyncStore, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    MeteringDelta, PlaneRecordRef, RecordStore, RecordStoreResult, UsageDelta,
};

use super::{now, MemoryStore, NAME};

/// [`super::SECRET_REF_PATHS`], as the door's Statement states them.
const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str(
        super::SECRET_REF_PATHS[0],
    )];

busbar_contract::store_door!(
    MemoryStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    1024,
    secret_refs: SECRET_REFS
);

/// What an applied op answered, replayed verbatim.
#[derive(Debug, Clone)]
enum Answer {
    Done,
}

/// One remembered op: its value fields and its answer.
struct Recorded {
    body: String,
    answer: Answer,
}

#[derive(Default)]
struct Inner {
    ops: HashMap<OpId, Recorded>,
    /// `(recorded_at, op_id)`, oldest first: the retention sweep's order.
    aged: VecDeque<(u64, OpId)>,
}

/// The v3 state [`MemoryStore`] carries.
#[derive(Default)]
pub(crate) struct State {
    inner: Mutex<Inner>,
}

/// Whether an op is new, a replay, or a conflict.
enum Seen {
    New,
    Replay(Answer),
    Conflict,
}

impl Inner {
    fn seen(&self, op: OpId, body: &str) -> Seen {
        match self.ops.get(&op) {
            None => Seen::New,
            Some(r) if r.body == body => Seen::Replay(r.answer.clone()),
            Some(_) => Seen::Conflict,
        }
    }

    /// Remember an APPLIED op, and forget every op past its retention.
    fn record(&mut self, now: u64, op: OpId, body: String, answer: Answer) {
        while let Some(&(at, old)) = self.aged.front() {
            if at.saturating_add(OP_ID_RETENTION_SECS) > now {
                break;
            }
            self.aged.pop_front();
            self.ops.remove(&old);
        }
        self.ops.insert(op, Recorded { body, answer });
        self.aged.push_back((now, op));
    }
}

impl State {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn failed(e: busbar_contract::records::RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

impl MemoryStore {
    /// Run one `op_id`-carrying write under the v3 lock: a replay answers the original, a
    /// conflict applies nothing, and a new op runs `apply` and is remembered only if it applied.
    fn deduped(
        &self,
        op: OpId,
        body: String,
        apply: impl FnOnce(&Self, &mut Inner) -> OpResult<Answer>,
    ) -> OpResult<Answer> {
        let mut inner = self.v3.lock();
        match inner.seen(op, &body) {
            Seen::Replay(a) => Ok(a),
            Seen::Conflict => Err(OpRefused::Conflict),
            Seen::New => {
                let answer = apply(self, &mut inner)?;
                inner.record(now(), op, body, answer.clone());
                Ok(answer)
            }
        }
    }
}

/// The store v3 slots' own bodies: each op's ONE body, which the table's slot answers inline (the
/// memory store never pends).
impl MemoryStore {
    pub(crate) fn v3_append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        let body = format!("append_plane_record:{:?}", record.to_record());
        self.deduped(op, body, |s, _| {
            s.append_plane_record(record).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        // The store keeps the record, so it copies it here (the door lends the host's bytes).
        let value = RecordBytes::new(value.to_vec())
            .map_err(|n| format!("a record of {n} bytes is over the ceiling"))?;
        self.record_put_at(schema, key, &value);
        Ok(())
    }

    pub(crate) fn v3_record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        Ok(self.record_get_at(schema, key))
    }

    pub(crate) fn v3_record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        Ok(self.record_scan_at(schema, prefix, limit))
    }

    pub(crate) fn v3_add_usage_batch(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        self.deduped(op, body, |s, _| {
            // A RAM ledger cannot fail an add, so applying in order is atomic.
            for (bucket, window, delta) in cells {
                s.add_usage(bucket, *window, delta).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.deduped(op, body, |s, _| {
            for d in deltas {
                s.add_metering(d).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }
}

/// Served whole by the SDK ([`SyncStore`]): the 1.5.5 op set is the double's
/// [`RecordStore`](busbar_contract::records::RecordStore) impl, and every slot answers at once.
impl SyncStore for MemoryStore {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: true,
    };

    fn validate(_settings: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn open(settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        let store = Self::new();
        let planted = serde_json::from_slice::<serde_json::Value>(settings)
            .ok()
            .and_then(|v| v.get("panic_on_plane_append")?.as_bool())
            .unwrap_or(false);
        store
            .panic_on_plane_append
            .store(planted, std::sync::atomic::Ordering::Relaxed);
        Ok(store)
    }

    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()> {
        if self
            .panic_on_plane_append
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            panic!("store double: the planted panic on a plane-record append");
        }
        self.v3_append_plane_record_op(op, record)
    }

    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.v3_record_put(schema, key, value)
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        self.v3_record_get(schema, key)
    }

    fn record_scan(&self, schema: &str, prefix: &[u8], limit: u32) -> Result<Scanned, String> {
        self.v3_record_scan(schema, prefix, limit)
    }

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        self.v3_add_usage_batch(op, cells)
    }

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        self.v3_add_metering_batch(op, deltas)
    }

    fn purge_usage_before(&self, before: u64) -> RecordStoreResult<u64> {
        let mut usage = self.usage();
        let was = usage.len();
        usage.retain(|(_, window_start), _| *window_start == 0 || *window_start >= before);
        Ok((was - usage.len()) as u64)
    }
}
