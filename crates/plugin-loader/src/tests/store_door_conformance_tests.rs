// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[allow(unsafe_code)]
#[path = "actual_store.rs"]
mod actual_store;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{RecordStore, VirtualKey};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_dropped, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink};
use crate::store_v3::LoadedStore;
use std::sync::Arc;

const SCHEMA: &str = "both-ways";

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

fn dropped_store() -> LoadedStore {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let path = actual_store::path();
    let stated =
        crate::dispatch::rendering_of(actual_store::door).expect("actual SQLite statement");
    let plugin = load_dropped::<Store>(
        &path,
        &stated,
        Bind {
            instance: "actual-store-dropped".into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the actual SQLite image loads through the dropped ABI");
    LoadedStore::open(plugin, dispatcher, &actual_store::settings(), mint)
        .expect("the dropped actual SQLite database opens")
}

fn read(answer: Result<Option<RecordBytes>, StoreFailure>) -> String {
    format!(
        "{:?}",
        answer.map(|r| r.map(|r| String::from_utf8_lossy(r.as_slice()).into_owned()))
    )
}

fn script(s: &LoadedStore) -> Vec<String> {
    let r = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("a record");
    let mut t = Vec::new();
    block(async {
        t.push(format!(
            "put a = {:?}",
            s.record_put(SCHEMA, b"a", &r(b"one")).await
        ));
        t.push(format!(
            "get a = {}",
            read(StoreCalls::record_get(s, SCHEMA, b"a").await)
        ));
        t.push(format!(
            "get missing = {}",
            read(StoreCalls::record_get(s, SCHEMA, b"missing").await)
        ));
        t.push(format!(
            "put a again = {:?}",
            s.record_put(SCHEMA, b"a", &r(b"two")).await
        ));
        t.push(format!(
            "get a after = {}",
            read(StoreCalls::record_get(s, SCHEMA, b"a").await)
        ));
    });
    let key = VirtualKey {
        id: "key-1".into(),
        generation_hash: "h_key-1".into(),
        name: "key one".into(),
        enabled: true,
        created_at: 100,
        ..Default::default()
    };
    t.push(format!("put key = {:?}", RecordStore::put_key(s, &key)));
    t.push(format!("get key = {:?}", RecordStore::get_key(s, "key-1")));
    t.push(format!(
        "get no key = {:?}",
        RecordStore::get_key(s, "key-0")
    ));
    let cells = [(
        "k",
        60,
        busbar_contract::records::UsageDelta {
            requests: 4,
            billable_requests: 4,
            models: Vec::new(),
        },
    )];
    t.push(format!(
        "usage batch = {:?}",
        block(StoreCalls::add_usage_batch(
            s,
            OpId::from_parts(3, 1),
            &cells
        ))
    ));
    t.push(format!(
        "usage = {:?}",
        RecordStore::get_usage(s, "k", 60).map(|u| u.requests)
    ));
    t
}

#[test]
fn a_linked_and_a_dropped_in_store_answer_get_and_put_identically() {
    let linked = script(&actual_store::open());
    let dropped = script(&dropped_store());
    assert_eq!(
        linked, dropped,
        "the actual same Store image answers both origins alike"
    );

    assert!(linked[1].contains("one"), "{}", linked[1]);
    assert!(linked[2].ends_with("Ok(None)"), "{}", linked[2]);
    assert!(linked[4].contains("two"), "{}", linked[4]);
    assert!(linked[6].contains("key one"), "{}", linked[6]);
    assert!(linked[7].ends_with("Ok(None)"), "{}", linked[7]);
    assert!(linked[9].ends_with("Ok(4)"), "{}", linked[9]);
}

fn mint() -> busbar_contract::abi::store::OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    busbar_contract::abi::store::OpId::from_parts(
        0xd00c,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}
