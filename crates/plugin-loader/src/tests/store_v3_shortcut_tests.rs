// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPILED-IN SHORTCUT'S RED ARM (TODO ABI-b4, store), host side. The store kind's ONE
//! conformance suite is the published script (`conformance/store.rs`), run in-tree over the
//! build's store, linked and dropped in (`conformance_store_runs_tests`). What stays here is the
//! one arm that is not a plugin's: the pre-table arrangement reached the compiled-in store through
//! its Rust type, a shortcut with no `op_id`, so a write the caller retried after losing the answer
//! applies twice; through the table the retry carries the same `op_id` and applies once. The
//! comparator must see the difference.

use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::records::{ModelTokensDelta, RecordStore, UsageDelta};
use busbar_contract::store_calls::StoreCalls;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

/// The shipped build's store: its compiled-in door, through the table.
fn compiled_in() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(crate::both_ways::store_fixture::door)
        .expect("the store states its Statement");
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: crate::dispatch::ConnTable::NoNeeds,
    };
    let p = load_linked::<Store>(&row, bind).expect("the door loads");
    LoadedStore::open(p, d, b"{}", mint).expect("it opens")
}

/// This test process's `op_id` allocator: one counter, as the kernel's `door::op_id` is.
fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x7e58,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

fn delta(requests: i64, input: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), input)].into_iter().collect(),
        }],
    }
}

/// THE RED ARM, KEPT: the table (either door) applies a replayed write once; the shortcut twice.
#[test]
fn the_compiled_in_shortcut_answers_a_replayed_write_differently() {
    let table = compiled_in();
    let cells = [("k", 60u64, delta(1, 5))];
    block(async {
        table
            .add_usage_batch(OpId::from_parts(2, 1), &cells)
            .await
            .expect("write");
        table
            .add_usage_batch(OpId::from_parts(2, 1), &cells)
            .await
            .expect("retry");
    });
    let through_table = format!(
        "{:?}",
        RecordStore::get_usage(&table, "k", 60).expect("read")
    );

    let shortcut = crate::both_ways::store_fixture::MemoryStore::new();
    shortcut.add_usage("k", 60, &cells[0].2).expect("write");
    shortcut.add_usage("k", 60, &cells[0].2).expect("retry");
    let through_shortcut = format!("{:?}", shortcut.get_usage("k", 60).expect("read"));

    assert_ne!(
        through_table, through_shortcut,
        "the comparator must catch a door that double-applies a replayed write"
    );
    assert!(through_table.contains("requests: 1"), "{through_table}");
    assert!(
        through_shortcut.contains("requests: 2"),
        "{through_shortcut}"
    );
}
