// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[allow(unsafe_code)]
#[path = "actual_store.rs"]
mod actual_store;

use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::records::VirtualKey;
use busbar_contract::store_calls::{OpenedStore, StoreAxis, StoreDoor};

use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher, PluginLogConfig};
use crate::store_v3::DoorStoreAxis;

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0xa715,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn axis() -> DoorStoreAxis {
    let none = Default::default();
    DoorStoreAxis {
        dispatcher: Arc::new(Dispatcher::new(DispatchConfig::default())),
        logs: PluginLogConfig::from_words(None, None, &none, None, None)
            .expect("the plugins.logs defaults resolve"),
        conns: crate::dispatch::ConnTable::NoNeeds,
        mint,
    }
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

fn transcript(s: &OpenedStore) -> Vec<String> {
    let mut out = Vec::new();
    let key = VirtualKey {
        id: "vk-1".into(),
        name: "one".into(),
        enabled: true,
        created_at: 7,
        ..VirtualKey::default()
    };
    out.push(format!("put {:?}", s.records.put_key(&key)));
    out.push(format!(
        "get {:?}",
        s.records.get_key("vk-1").map(|k| k.map(|k| k.id))
    ));
    out.push(format!(
        "list {:?}",
        s.records
            .list_keys()
            .map(|v| v.into_iter().map(|k| k.id).collect::<Vec<_>>())
    ));
    out.push(format!(
        "miss {:?}",
        s.records.get_key("vk-none").map(|k| k.is_some())
    ));
    let calls = s.calls.as_ref().expect("a door store has v3 calls");
    let cells = [(
        "b",
        60,
        busbar_contract::records::UsageDelta {
            requests: 3,
            billable_requests: 3,
            models: Vec::new(),
        },
    )];
    out.push(format!(
        "usage batch {:?}",
        block(calls.add_usage_batch(OpId::from_parts(9, 1), &cells))
    ));
    out.push(format!(
        "usage {:?}",
        s.records.get_usage("b", 60).map(|u| u.requests)
    ));
    out
}

#[test]
fn boot_opens_the_build_store_through_its_door_linked_and_dropped_in_alike() {
    let axis = axis();
    let door = actual_store::door;
    let linked = axis
        .open(StoreDoor::Linked(door), "store", &actual_store::settings())
        .expect("the linked door opens");
    let linked = transcript(&linked);
    assert!(
        linked.iter().all(|l| !l.contains("Err")),
        "the linked store answered the script: {linked:#?}"
    );
    let path = actual_store::path();
    let dropped = axis
        .open(
            StoreDoor::Dropped {
                file: path.display().to_string(),
                bytes: Arc::new(std::fs::read(&path).expect("the example cdylib reads")),
                stated: rendering_of(door).expect("the store renders its Statement"),
            },
            "store-dropped",
            &actual_store::settings(),
        )
        .expect("the dropped-in door opens");
    assert_eq!(transcript(&dropped), linked, "the two doors answer alike");
}

#[test]
fn boot_is_handed_a_stores_door_and_a_row_with_none_is_refused() {
    use crate::{LinkedPlugin, PluginRegistry};
    let door = actual_store::door;
    let reg = PluginRegistry::empty()
        .link(vec![
            // A store row whose entry is not the store's own door states none to boot.
            LinkedPlugin::door_of_kind("store", "no-door", door),
            LinkedPlugin::store("with-door", door, true),
        ])
        .expect("the rows register");
    let Err(e) = reg.store_door("no-door") else {
        panic!("a store with no door was handed to boot");
    };
    assert_eq!(
        e,
        "plugin 'no-door' states no store door: rebuild the plugin against the 1.6.0 SDK"
    );
    let Ok(StoreDoor::Linked(d)) = reg.store_door("with-door") else {
        panic!("the row's door was not handed to boot");
    };
    assert_eq!(
        d as usize, door as busbar_contract::abi::mechanism::door::DoorFn as usize,
        "the row's own door"
    );
    let opened = axis()
        .open(StoreDoor::Linked(d), "with-door", &actual_store::settings())
        .expect("it opens through the axis");
    assert!(opened.records.list_keys().is_ok());
}
