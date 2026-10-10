// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE AXIS, BOTH WAYS (WIRE-STORE Q8/Q9; the boot store door): the store boot opens is
//! loaded through the ONE dispatcher and opened through the store v3 table, whichever door it came
//! in by. The build's store (its row reached by KIND) is opened through [`DoorStoreAxis`] LINKED
//! (its row's door, as the registry hands it) and DROPPED IN (the `store_v3_door` example
//! `cdylib`, admitted against the linked door's Statement), and both answer one script through
//! the 1.5.5 op set and the v3 calls, equal line for line.
//!
//! RED: the registry hands boot a store's DOOR, never its in-process open: a linked store row with
//! no door, and a store plugin that states none (a 1.5.5 JSON-contract plugin), are refused naming
//! the rebuild; a row with its door resolves to it.

use std::sync::Arc;

use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension};
use busbar_contract::abi::store::OpId;
use busbar_contract::records::VirtualKey;
use busbar_contract::store_calls::{OpenedStore, StoreAxis, StoreDoor};

use crate::dispatch::{rendering_of, DispatchConfig, Dispatcher, PluginLogConfig};
use crate::store_v3::DoorStoreAxis;

/// This test's `op_id` allocator: one counter, as the kernel's `door::op_id` is.
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

/// One script through both surfaces of an opened store: the 1.5.5 op set (a key written, read
/// back, listed, a miss) and the v3 calls (a cap, a reserve, a release).
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
    let k = CellKey {
        bucket: "b",
        pool: None,
        dimension: Dimension::Requests,
        window_start: 60,
    };
    let caps = [Cap {
        key: k,
        cap: 5,
        config_gen: 1,
    }];
    out.push(format!(
        "caps {:?}",
        block(calls.window_caps(OpId::from_parts(9, 1), &caps))
    ));
    let cells = [Cell { key: k, amount: 3 }];
    let grants = block(calls.reserve(OpId::from_parts(9, 2), 1, &cells));
    out.push(format!(
        "reserve {:?}",
        grants
            .as_ref()
            .map(|g| g.iter().map(|g| g.granted).collect::<Vec<_>>())
    ));
    if let Ok(g) = &grants {
        let items = [(g[0].slice_id, 2)];
        out.push(format!(
            "release {:?}",
            block(calls.slice_release(OpId::from_parts(9, 3), 1, &items))
        ));
    }
    out
}

#[test]
fn boot_opens_the_build_store_through_its_door_linked_and_dropped_in_alike() {
    let axis = axis();
    let door = crate::both_ways::store_fixture::door;
    let linked = axis
        .open(StoreDoor::Linked(door), "store", b"{}")
        .expect("the linked door opens");
    let linked = transcript(&linked);
    assert!(
        linked.iter().all(|l| !l.contains("Err")),
        "the linked store answered the script: {linked:#?}"
    );
    let path = crate::both_ways::example_cdylib("store_v3_door");
    let dropped = axis
        .open(
            StoreDoor::Dropped {
                file: path.display().to_string(),
                bytes: Arc::new(std::fs::read(&path).expect("the example cdylib reads")),
                stated: rendering_of(door).expect("the store renders its Statement"),
            },
            "store-dropped",
            b"{}",
        )
        .expect("the dropped-in door opens");
    assert_eq!(transcript(&dropped), linked, "the two doors answer alike");
}

#[test]
fn boot_is_handed_a_stores_door_and_a_row_with_none_is_refused() {
    use crate::{LinkedPlugin, PluginRegistry};
    let door = crate::both_ways::store_fixture::door;
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
        .open(StoreDoor::Linked(d), "with-door", b"{}")
        .expect("it opens through the axis");
    assert!(opened.records.list_keys().is_ok());
}
