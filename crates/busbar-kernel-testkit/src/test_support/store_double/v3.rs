// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::conditional;
use busbar_contract::abi::sdk::store::{OpRefused, OpResult, Scanned, SyncStore, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::correction;
use busbar_contract::records::{
    MeteringDelta, PlaneRecordRef, RecordStore, RecordStoreResult, UsageDelta,
};

use super::{now, MemoryStore, NAME};

const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str(
        super::SECRET_REF_PATHS[0],
    )];

busbar_contract::statement_extensions!(REWRAP_EXTENSIONS: [
    (busbar_contract::abi::sdk::store::rewrap::INTENT, b"1"),
    (correction::CAPABILITY, busbar_contract::abi::sdk::store::correction::CAPABILITY_VALUE),
    (conditional::CAPABILITY, b"1"),
]);

busbar_contract::store_door!(
    MemoryStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    1024,
    extensions: REWRAP_EXTENSIONS,
    secret_refs: SECRET_REFS
);

/// What an applied op answered, replayed verbatim.
#[derive(Debug, Clone)]
enum Answer {
    Done,
}

struct Recorded {
    body: Body,
    answer: Answer,
}

/// Keep correction identities in the same operation namespace as ordinary writes.
#[derive(PartialEq, Eq)]
enum Body {
    Ordinary(String),
    UsageCorrection([u8; 32]),
    RecordTransaction([u8; 32]),
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

enum Seen {
    New,
    Replay(Answer),
    Conflict,
}

impl Inner {
    fn seen(&self, op: OpId, body: &Body) -> Seen {
        match self.ops.get(&op) {
            None => Seen::New,
            Some(r) if &r.body == body => Seen::Replay(r.answer.clone()),
            Some(_) => Seen::Conflict,
        }
    }

    fn record(&mut self, now: u64, op: OpId, body: Body, answer: Answer) {
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
    fn v3_record_transaction(
        &self,
        request: &conditional::Request,
    ) -> OpResult<conditional::Decision> {
        use conditional::{Decision, Expected, Mutation};
        request
            .validate()
            .map_err(|reason| OpRefused::Refused(reason.into()))?;
        let body = Body::RecordTransaction(request.fingerprint());
        let mut inner = self.v3.lock();
        match inner.seen(request.op_id, &body) {
            Seen::Replay(_) => return Ok(Decision::Applied),
            Seen::Conflict => return Err(OpRefused::Conflict),
            Seen::New => {}
        }
        let mut records = self.records.write().unwrap_or_else(|p| p.into_inner());
        for predicate in &request.predicates {
            let actual = records.get(&(predicate.schema.clone(), predicate.key.clone()));
            let matches = match &predicate.expected {
                Expected::Absent => actual.is_none(),
                Expected::Bytes(bytes) => actual.is_some_and(|value| value.as_slice() == bytes),
            };
            if !matches {
                return Ok(Decision::ConditionConflict);
            }
        }
        for mutation in &request.mutations {
            match mutation {
                Mutation::Put { schema, key, value } => {
                    records.insert(
                        (schema.clone(), key.clone()),
                        RecordBytes::new(value.clone()).expect("validated record bytes"),
                    );
                }
                Mutation::Delete { schema, key } => {
                    records.remove(&(schema.clone(), key.clone()));
                }
                Mutation::DeleteRange {
                    schema,
                    prefix,
                    exact_key_length,
                } => {
                    records.retain(|(s, k), _| {
                        s != schema || k.len() as u64 != *exact_key_length || !k.starts_with(prefix)
                    });
                }
            }
        }
        inner.record(now(), request.op_id, body, Answer::Done);
        Ok(Decision::Applied)
    }

    fn deduped(
        &self,
        op: OpId,
        body: String,
        apply: impl FnOnce(&Self, &mut Inner) -> OpResult<Answer>,
    ) -> OpResult<Answer> {
        let mut inner = self.v3.lock();
        let body = Body::Ordinary(body);
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

impl MemoryStore {
    pub(crate) fn v3_apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> OpResult<correction::Decision> {
        request
            .validate()
            .map_err(|reason| OpRefused::Refused(reason.into()))?;
        let body = Body::UsageCorrection(request.fingerprint());
        let mut inner = self.v3.lock();

        match inner.seen(request.op_id, &body) {
            Seen::Replay(_) => return Ok(correction::Decision::Applied),
            Seen::Conflict => return Err(OpRefused::Conflict),
            Seen::New => {}
        }

        let keys = self.keys_read();
        let mut usage = self.usage();
        let metering = self.metering_read();
        if !keys
            .get(&request.key_id)
            .is_some_and(|key| key.deleted_at.is_none())
        {
            return Ok(correction::Decision::ConditionConflict);
        }
        let mut selected: Vec<_> = metering
            .iter()
            .filter(|((key, day, ..), _)| key == &request.key_id && *day == request.day_start)
            .map(|(_, row)| row.clone())
            .collect();
        correction::canonical_metering(&mut selected);
        if selected != request.metering {
            return Ok(correction::Decision::ConditionConflict);
        }
        for change in &request.usage {
            let address = (&change.address.bucket_id, change.address.window_start);
            let mut actual = usage
                .get(&(address.0.clone(), address.1))
                .cloned()
                .unwrap_or_default();
            correction::canonical_ledger(&mut actual)
                .map_err(|reason| OpRefused::Failed(reason.into()))?;
            if actual != change.expected {
                return Ok(correction::Decision::ConditionConflict);
            }
        }
        for change in &request.usage {
            usage.insert(
                (
                    change.address.bucket_id.clone(),
                    change.address.window_start,
                ),
                change.replacement.clone(),
            );
        }
        inner.record(now(), request.op_id, body, Answer::Done);
        Ok(correction::Decision::Applied)
    }

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
            if cells
                .iter()
                .any(|(bucket, _, _)| correction::reserved_bucket(bucket))
            {
                return Err(OpRefused::Refused(
                    "reserved usage correction bucket".into(),
                ));
            }
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

impl SyncStore for MemoryStore {
    const RECORD_TRANSACTION: bool = true;
    const USAGE_CORRECTION: bool = true;

    fn record_transaction(
        &self,
        request: &conditional::Request,
    ) -> OpResult<conditional::Decision> {
        self.v3_record_transaction(request)
    }

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

    fn apply_usage_correction(
        &self,
        request: &correction::Request,
    ) -> OpResult<correction::Decision> {
        self.v3_apply_usage_correction(request)
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

#[cfg(test)]
mod provided_id_tests {
    use super::*;

    #[test]
    fn direct_batches_and_existing_receipts_share_the_exact_identity() {
        const PROVIDED_ID: OpId = OpId([0x73; 16]);
        const BUCKET: &str = "provided-id-bucket";
        let store = MemoryStore::new();
        let window = now();
        let delta = UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: Vec::new(),
        };
        let cells = [(BUCKET, window, delta)];
        RecordStore::add_usage_batch_deduped(&store, PROVIDED_ID, &cells).unwrap();
        <MemoryStore as SyncStore>::add_usage_batch(&store, PROVIDED_ID, &cells).unwrap();
        assert_eq!(
            RecordStore::get_usage(&store, BUCKET, window)
                .unwrap()
                .requests,
            1
        );
        let changed = [(
            BUCKET,
            window,
            UsageDelta {
                requests: 2,
                ..cells[0].2.clone()
            },
        )];
        let error =
            RecordStore::add_usage_batch_deduped(&store, PROVIDED_ID, &changed).unwrap_err();
        assert_eq!(error.0, busbar_contract::abi::store::DIAG_OPID_CONFLICT);
        assert_eq!(
            RecordStore::get_usage(&store, BUCKET, window)
                .unwrap()
                .requests,
            1
        );
    }
}
