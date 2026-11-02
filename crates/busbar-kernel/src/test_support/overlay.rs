// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! A real record Store for configuration persistence tests, with controlled transport outcomes.
use crate::config::overlay::OverlayStore;
use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Request};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Barrier, Mutex};

#[derive(Default)]
struct Rows {
    records: BTreeMap<(String, Vec<u8>), RecordBytes>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    fail_reads: bool,
    fail_writes: bool,
    fail_transactions: bool,
    lose_reply: bool,
    block_read: Option<Arc<Barrier>>,
    candidates: Vec<Request>,
    write_allowance: Option<usize>,
    after_transaction: Option<Box<dyn FnOnce() + Send>>,
    before_transaction: Option<Box<dyn FnOnce() + Send>>,
    after_read: Option<Box<dyn FnOnce() + Send>>,
    pause_reply: Option<Arc<Mutex<ReplyPause>>>,
}

#[derive(Default)]
struct ReplyPause {
    entered: bool,
    released: bool,
    waker: Option<std::task::Waker>,
}

/// A real Pending Store reply. Dropping the controlling handle releases its waiter as well, so
/// an assertion failure cannot strand a transaction's blocking task or its mutation guard.
pub struct TestOverlayPause(Arc<Mutex<ReplyPause>>);

impl TestOverlayPause {
    pub fn entered(&self) -> bool {
        self.0.lock().unwrap().entered
    }

    pub fn release(&self) {
        let waker = {
            let mut state = self.0.lock().unwrap();
            state.released = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Drop for TestOverlayPause {
    fn drop(&mut self) {
        self.release();
    }
}

struct ReplyWait(Arc<Mutex<ReplyPause>>);

impl std::future::Future for ReplyWait {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        let incoming = cx.waker().clone();
        let (released, outgoing) = {
            let mut state = self.0.lock().unwrap();
            state.entered = true;
            if state.released {
                (true, Some(incoming))
            } else {
                (false, state.waker.replace(incoming))
            }
        };
        drop(outgoing);
        if released {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }
}

#[derive(Default)]
struct Calls(Mutex<Rows>);

/// The backend is attached directly to its Store; no filesystem path identifies it.
#[derive(Clone)]
pub struct TestOverlayStore {
    calls: Arc<Calls>,
    backend: Arc<OverlayStore>,
}
impl Default for TestOverlayStore {
    fn default() -> Self {
        Self::new()
    }
}
impl TestOverlayStore {
    pub fn new() -> Self {
        let calls = Arc::new(Calls::default());
        let backend = OverlayStore::new(calls.clone()).unwrap();
        Self { calls, backend }
    }
    pub fn backend(&self) -> Arc<OverlayStore> {
        self.backend.clone()
    }
    pub fn fail_reads(&self, value: bool) {
        self.calls.0.lock().unwrap().fail_reads = value;
    }
    pub fn fail_writes(&self, value: bool) {
        self.calls.0.lock().unwrap().fail_writes = value;
    }
    pub fn fail_transactions(&self, value: bool) {
        self.calls.0.lock().unwrap().fail_transactions = value;
    }
    pub fn lose_next_commit_reply(&self) {
        self.calls.0.lock().unwrap().lose_reply = true;
    }
    pub fn pause_next_commit_reply(&self) -> TestOverlayPause {
        let pause = Arc::new(Mutex::new(ReplyPause::default()));
        self.calls.0.lock().unwrap().pause_reply = Some(pause.clone());
        TestOverlayPause(pause)
    }
    pub fn block_reads(&self, barrier: Arc<Barrier>) {
        self.calls.0.lock().unwrap().block_read = Some(barrier);
    }
    pub fn read_bytes(&self) -> Option<Vec<u8>> {
        self.backend.read_bytes().unwrap()
    }
    pub fn candidates(&self) -> Vec<Request> {
        self.calls.0.lock().unwrap().candidates.clone()
    }
    pub fn fail_after_chunk_writes(&self, count: usize) {
        self.calls.0.lock().unwrap().write_allowance = Some(count);
    }
    pub fn allow_chunk_writes(&self) {
        self.calls.0.lock().unwrap().write_allowance = None;
    }
    pub fn on_next_transaction_reply(&self, callback: impl FnOnce() + Send + 'static) {
        self.calls.0.lock().unwrap().after_transaction = Some(Box::new(callback));
    }
    pub fn stored_record_count(&self) -> usize {
        self.calls.0.lock().unwrap().records.len()
    }
    pub fn fork_backend(&self) -> Arc<OverlayStore> {
        OverlayStore::new(self.calls.clone()).unwrap()
    }
    pub fn before_next_transaction(&self, callback: impl FnOnce() + Send + 'static) {
        self.calls.0.lock().unwrap().before_transaction = Some(Box::new(callback));
    }
    pub fn on_next_read_reply(&self, callback: impl FnOnce() + Send + 'static) {
        self.calls.0.lock().unwrap().after_read = Some(Box::new(callback));
    }
    /// Seed even corrupt/newer JSON as a complete immutable Store generation.
    pub fn seed_bytes(&self, bytes: &[u8]) {
        let generation = crate::door::op_id().0;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let head = serde_json::to_vec(&serde_json::json!({"version":1,"generation":generation,"length":bytes.len() as u64,"digest":digest})).unwrap();
        let mut rows = self.calls.0.lock().unwrap();
        for (index, chunk) in bytes.chunks(busbar_contract::MAX_RECORD_BYTES).enumerate() {
            let mut key = b"chunk:".to_vec();
            key.extend_from_slice(&generation);
            key.extend_from_slice(&(index as u64).to_be_bytes());
            rows.records.insert(
                ("busbar.config.overlay.v1".into(), key),
                RecordBytes::new(chunk.to_vec()).unwrap(),
            );
        }
        rows.records.insert(
            ("busbar.config.overlay.v1".into(), b"head".to_vec()),
            RecordBytes::new(head).unwrap(),
        );
    }
}
pub fn new_test_overlay() -> Arc<OverlayStore> {
    TestOverlayStore::new().backend()
}
fn ready<'a, T: Send + 'a>(value: Result<T, StoreFailure>) -> StoreCall<'a, T> {
    Box::pin(std::future::ready(value))
}
fn unused<'a, T: Send + 'a>() -> StoreCall<'a, T> {
    ready(Err(StoreFailure::Refused(
        "overlay fixture only serves records".into(),
    )))
}
impl StoreCalls for Calls {
    fn supports_record_transaction(&self) -> bool {
        true
    }
    fn record_transaction<'a>(&'a self, request: &'a Request) -> StoreCall<'a, Decision> {
        let before = { self.0.lock().unwrap().before_transaction.take() };
        if let Some(before) = before {
            before();
        }
        let result = (|| {
            request
                .validate()
                .map_err(|e| StoreFailure::Refused(e.into()))?;
            let mut rows = self.0.lock().unwrap();
            rows.candidates.push(request.clone());
            if rows.fail_writes || rows.fail_transactions {
                return Err(StoreFailure::Refused("planted write refusal".into()));
            }
            let fingerprint = request.fingerprint();
            if let Some(prior) = rows.receipts.get(&request.op_id.0) {
                return if prior == &fingerprint {
                    Ok(Decision::Applied)
                } else {
                    Err(StoreFailure::Conflict)
                };
            }
            for predicate in &request.predicates {
                let value = rows
                    .records
                    .get(&(predicate.schema.clone(), predicate.key.clone()));
                let matches = match &predicate.expected {
                    Expected::Absent => value.is_none(),
                    Expected::Bytes(bytes) => value.is_some_and(|v| v.as_slice() == bytes),
                };
                if !matches {
                    return Ok(Decision::ConditionConflict);
                }
            }
            for mutation in &request.mutations {
                match mutation {
                    Mutation::Put { schema, key, value } => {
                        rows.records.insert(
                            (schema.clone(), key.clone()),
                            RecordBytes::new(value.clone()).unwrap(),
                        );
                    }
                    Mutation::Delete { schema, key } => {
                        rows.records.remove(&(schema.clone(), key.clone()));
                    }
                    Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => {
                        rows.records.retain(|(s, k), _| {
                            s != schema
                                || k.len() as u64 != *exact_key_length
                                || !k.starts_with(prefix)
                        });
                    }
                }
            }
            rows.receipts.insert(request.op_id.0, fingerprint);
            if std::mem::take(&mut rows.lose_reply) {
                Err(StoreFailure::Fault("planted lost commit reply".into()))
            } else {
                Ok(Decision::Applied)
            }
        })();
        let callback = { self.0.lock().unwrap().after_transaction.take() };
        if let Some(callback) = callback {
            callback();
        }
        let pause = { self.0.lock().unwrap().pause_reply.take() };
        Box::pin(async move {
            if let Some(pause) = pause {
                ReplyWait(pause).await;
            }
            result
        })
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        let mut rows = self.0.lock().unwrap();
        if rows.fail_writes {
            return ready(Err(StoreFailure::Refused("planted write refusal".into())));
        }
        if let Some(remaining) = &mut rows.write_allowance {
            if *remaining == 0 {
                return ready(Err(StoreFailure::Failed(
                    "planted partial staging failure".into(),
                )));
            }
            *remaining -= 1;
        }
        if value.as_slice().is_empty() {
            rows.records.remove(&(schema.into(), key.into()));
        } else {
            rows.records
                .insert((schema.into(), key.into()), value.clone());
        }
        ready(Ok(()))
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        let barrier = { self.0.lock().unwrap().block_read.take() };
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        let (result, callback) = {
            let mut rows = self.0.lock().unwrap();
            let result = if rows.fail_reads {
                Err(StoreFailure::Failed("planted read failure".into()))
            } else {
                Ok(rows.records.get(&(schema.into(), key.into())).cloned())
            };
            (result, rows.after_read.take())
        };
        if let Some(callback) = callback {
            callback();
        }
        ready(result)
    }
    fn record_scan<'a>(
        &'a self,
        _: &'a str,
        _: &'a [u8],
        _: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        unused()
    }
    fn add_usage_batch<'a>(
        &'a self,
        _: OpId,
        _: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        unused()
    }
    fn add_metering_batch<'a>(&'a self, _: OpId, _: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        unused()
    }
    fn upsert_plane_record<'a>(&'a self, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        unused()
    }
    fn get_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, Option<Vec<u8>>> {
        unused()
    }
    fn append_plane_record<'a>(&'a self, _: OpId, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        unused()
    }
    fn list_plane_records<'a>(
        &'a self,
        _: &'a str,
        _: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        unused()
    }
    fn delete_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, ()> {
        unused()
    }
    fn redeem_plane_token<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> StoreCall<'a, bool> {
        unused()
    }
    fn plane_token_live<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> StoreCall<'a, bool> {
        unused()
    }
}
