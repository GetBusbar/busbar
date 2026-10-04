// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE `op_id` ALLOCATOR PER PROCESS, A FRESH ONE PER BOOT (ARCHITECT ruling on op_id identity): a
//! store handle mints its bridge writes' `op_id`s from the node's one allocator, never a counter of
//! its own. Over a DURABLE store (its dedupe log outlives every handle), a second handle, a reload
//! or a restart would otherwise re-mint an earlier write's id, and the store would answer the new
//! write as that one's replay and apply nothing.

use std::sync::Arc;

use crate::both_ways::store_fixture::MemoryStore;
use crate::store_v3::wrap::{Hooks, Wrapped};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{RecordStore, UsageDelta};
use busbar_contract::store_calls::{OpIdMint, StoreCalls};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

/// A DURABLE store stand-in: every instance opened on the same settings (the same "database") is
/// the SAME backing store, as every open of one database file is, whichever thread opens it. Its
/// dedupe log outlives any handle, as a durable one does.
struct Shared;

type Databases = std::collections::HashMap<Vec<u8>, Arc<MemoryStore>>;

static BACKING: std::sync::Mutex<Option<Databases>> = std::sync::Mutex::new(None);

impl Hooks for Shared {
    fn open(settings: &[u8], _: Option<Host>) -> Result<Arc<MemoryStore>, String> {
        let mut dbs = BACKING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(dbs
            .get_or_insert_with(Default::default)
            .entry(settings.to_vec())
            .or_insert_with(|| Arc::new(MemoryStore::new()))
            .clone())
    }
}

mod shared {
    busbar_contract::store_door!(super::Wrapped<super::Shared>, "shared", "0", 64);
}

/// One boot's allocator: its node half (the kernel draws it from the CSPRNG once per process) and
/// its one counter.
macro_rules! boot {
    ($name:ident, $node:expr) => {
        fn $name() -> OpId {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            OpId::from_parts(
                $node,
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
            )
        }
    };
}

/// The store on database `db`, minting from `mint`.
fn open(db: &str, mint: OpIdMint) -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_linked::<Store>(
        &LinkedRow::of(shared::door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: None,
        },
    )
    .expect("the door loads");
    let settings = format!("{{\"db\":\"{db}\"}}");
    LoadedStore::open(p, d, settings.as_bytes(), mint).expect("it opens")
}

fn one() -> UsageDelta {
    UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: Vec::new(),
    }
}

fn requests(s: &LoadedStore) -> i64 {
    RecordStore::get_usage(s, "k", 60).expect("usage").requests as i64
}

#[test]
fn two_handles_on_one_durable_store_both_land_their_writes() {
    boot!(this_boot, 0xb007_0001);
    let (a, b) = (
        open("two-handles", this_boot),
        open("two-handles", this_boot),
    );
    a.add_usage("k", 60, &one())
        .expect("the first handle's write");
    b.add_usage("k", 60, &one())
        .expect("the second handle's write");
    assert_eq!(
        requests(&b),
        2,
        "the second handle's write is not a replay of the first's"
    );
}

#[test]
fn a_write_after_a_restart_lands() {
    boot!(before, 0xb007_0002);
    boot!(after, 0xb007_0003);
    open("restart", before)
        .add_usage("k", 60, &one())
        .expect("the earlier boot's write");
    let restarted = open("restart", after);
    restarted
        .add_usage("k", 60, &one())
        .expect("the new boot's write");
    assert_eq!(
        requests(&restarted),
        2,
        "the new boot's counter 1 is a new id"
    );
}

#[test]
fn a_true_replay_is_deduped() {
    boot!(this_boot, 0xb007_0004);
    let s = open("replay", this_boot);
    let op = this_boot();
    let cells = [("k", 60u64, one())];
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(async {
            s.add_usage_batch(op, &cells).await.expect("the write");
            s.add_usage_batch(op, &cells).await.expect("its replay");
        });
    assert_eq!(requests(&s), 1, "the same op_id applies once");
}
