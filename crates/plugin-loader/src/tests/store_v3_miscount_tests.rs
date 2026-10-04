// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A COMMITTED WRITE NEVER READS AS A FAILURE (REVIEWER note 1, ARCHITECT ruling): a store that
//! commits a `reserve` or a `slice_release` and then answers the wrong number of grants or amounts
//! is FAULT through the store SDK, never FAILED ("nothing applied", which a caller may retry).

use std::sync::Arc;

use crate::both_ways::store_fixture::MemoryStore;
use crate::store_v3::wrap::{Hooks, Wrapped};
use busbar_contract::abi::sdk::store::{
    Cap, Cell, CellKey, Dimension, Grant, Op, OpResult, ReserveRefused, Step, StoreSlots,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

/// The memory store, except that every committed `reserve` and `slice_release` answers one item
/// short.
struct Miscounts;

impl Hooks for Miscounts {
    fn reserve<'c>(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        let mut g = Vec::new();
        let answer = <MemoryStore as StoreSlots>::reserve(inner, cx, op, epoch, cells, &mut g);
        if let Step::Ready(Ok(())) = answer {
            g.pop();
            grants.extend(g);
        }
        answer
    }
    fn slice_release(
        inner: &MemoryStore,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        let mut r = Vec::new();
        let answer =
            <MemoryStore as StoreSlots>::slice_release(inner, cx, op, epoch, items, &mut r);
        if let Step::Ready(Ok(())) = answer {
            r.pop();
            released.extend(r);
        }
        answer
    }
}

mod miscounts {
    busbar_contract::store_door!(super::Wrapped<super::Miscounts>, "miscounts", "0", 64);
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x5108,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// The handle's own allocator (another node than the test ops' [`mint`]).
fn bridge_mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x5107,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn open() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(miscounts::door).expect("the miscounting door states its Statement");
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: None,
        },
    )
    .expect("the door loads");
    LoadedStore::open(p, d, b"{}", bridge_mint).expect("it opens")
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
