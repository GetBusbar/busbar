// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A COMMITTED WRITE NEVER READS AS A FAILURE (REVIEWER note 1, ARCHITECT ruling): a store that
//! commits a `reserve` or a `slice_release` and then answers the wrong number of grants or amounts
//! is FAULT through the store SDK, never FAILED ("nothing applied", which a caller may retry).

use std::sync::Arc;

use crate::both_ways::store_fixture::MemoryStore;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpResult, ReserveRefused, StoreSlots, Tail,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, MeteringRow, PlaneRecord, RecordStore, RecordStoreResult,
    UsageDelta, UsageLedger, VirtualKey,
};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, NoSink};
use crate::store_v3::LoadedStore;

/// The memory store, except that every committed `reserve` and `slice_release` answers one item
/// short.
struct Miscounts(MemoryStore);

impl RecordStore for Miscounts {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.0.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.0.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.0.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.0.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        self.0.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        self.0.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.0.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.0.list_metering(bucket)
    }
}

impl StoreSlots for Miscounts {
    const TAIL: Tail = MemoryStore::TAIL;

    fn open(settings: &[u8]) -> Result<Self, String> {
        <MemoryStore as StoreSlots>::open(settings).map(Self)
    }
    fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        self.0.add_usage_op(op, bucket, window_start, delta)
    }
    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        self.0.add_metering_op(op, delta)
    }
    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        self.0.append_audit_op(op, entry)
    }
    fn append_plane_record_op(&self, op: OpId, record: &PlaneRecord) -> OpResult<()> {
        self.0.append_plane_record_op(op, record)
    }
    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head> {
        self.0.append_batch(op, stream, records)
    }
    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        self.0.heads()
    }
    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        self.0.session_put(session, node, principal)
    }
    fn session_remove(&self, session: u64) -> Result<(), String> {
        self.0.session_remove(session)
    }
    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        self.0.sessions_for(principal)
    }
    fn record_put(&self, schema: &str, key: &[u8], value: &RecordBytes) -> Result<(), String> {
        StoreSlots::record_put(&self.0, schema, key, value)
    }
    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        StoreSlots::record_get(&self.0, schema, key)
    }
    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        StoreSlots::record_scan(&self.0, schema, prefix, limit)
    }
    fn reserve(
        &self,
        op: OpId,
        epoch: u64,
        cells: &[Cell<'_>],
    ) -> Result<Vec<Grant>, ReserveRefused> {
        let mut g = self.0.reserve(op, epoch, cells)?;
        g.pop();
        Ok(g)
    }
    fn slice_release(&self, op: OpId, epoch: u64, items: &[(u64, u64)]) -> OpResult<Vec<u64>> {
        let mut r = self.0.slice_release(op, epoch, items)?;
        r.pop();
        Ok(r)
    }
    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        self.0.add_usage_batch(op, cells)
    }
    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        self.0.add_metering_batch(op, deltas)
    }
    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        self.0.append_audit_batch(op, entries)
    }
    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        self.0.window_caps(op, caps)
    }
}

mod miscounts {
    busbar_contract::store_door!(super::Miscounts, "miscounts", "0", 64);
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x5108,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn open() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        miscounts::door,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
        },
    )
    .expect("the door loads");
    LoadedStore::open(p, d, b"{}", 0x5107).expect("it opens")
}

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

fn key(dimension: Dimension<'static>) -> CellKey<'static> {
    CellKey {
        bucket: "g",
        pool: None,
        dimension,
        window_start: 1_790_000_000_000,
    }
}

#[test]
fn a_committed_reserve_answered_with_the_wrong_grant_count_is_fault() {
    let s = open();
    let dims = [Dimension::Requests, Dimension::Class("input")];
    let caps: Vec<Cap<'_>> = dims
        .iter()
        .map(|d| Cap {
            key: key(*d),
            cap: 10,
            config_gen: 1,
        })
        .collect();
    let cells: Vec<Cell<'_>> = dims
        .iter()
        .map(|d| Cell {
            key: key(*d),
            amount: 1,
        })
        .collect();
    run(async {
        s.window_caps(mint(), &caps).await.expect("caps");
        let r = s.reserve(mint(), 0, &cells).await;
        assert!(
            matches!(r, Err(StoreFailure::Fault(_))),
            "a committed draw never reads as FAILED: {r:?}"
        );
    });
}

#[test]
fn a_committed_release_answered_with_the_wrong_count_is_fault() {
    let s = open();
    let caps = [Cap {
        key: key(Dimension::Requests),
        cap: 10,
        config_gen: 1,
    }];
    let cells = [Cell {
        key: key(Dimension::Requests),
        amount: 2,
    }];
    run(async {
        s.window_caps(mint(), &caps).await.expect("caps");
        // One cell: the miscount drops its only grant.
        assert!(matches!(
            s.reserve(mint(), 0, &cells).await,
            Err(StoreFailure::Fault(_))
        ));
        let r = s.slice_release(mint(), 0, &[(1, 1)]).await;
        assert!(
            matches!(r, Err(StoreFailure::Fault(_))),
            "a committed release never reads as FAILED: {r:?}"
        );
    });
}
