// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::store::OpId;
use busbar_contract::records::{ModelTokensDelta, RecordStore, UsageDelta};
use busbar_contract::store_calls::StoreCalls;

use crate::actual_store;

fn compiled_in() -> crate::store_v3::LoadedStore {
    actual_store::open()
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

    let shortcut = actual_store::open();
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
