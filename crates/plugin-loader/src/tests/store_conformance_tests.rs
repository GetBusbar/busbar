// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: store`, BOTH WAYS** (DECISIONS #2 rule (1), K5). The in-tree store example registered
//! through the LINKED door (its `rlib`'s `BUSBAR_COLD_ENTRY`) and the DROPPED-IN door (its `cdylib`,
//! signed into `plugins/`) resolves to the byte-identical registry row, and the store each door's
//! `open_store` opens answers one script byte-identically. See [`super::both_ways`].
//!
//! RED by planting the door bypass the axis replaces — linked rows handed to [`PluginRegistry::link`]
//! and never registered — which leaves the linked registry with no row for the name.

use super::both_ways::{both_doors, statement};
use busbar_api::{ScopeRef, Store, VirtualKey};

/// The script: put a key carrying a pool grant, read it back, list every key — the transcript is
/// what the host was handed, serialized as the engine would persist or serve it.
fn script(store: &dyn Store) -> String {
    let key = VirtualKey {
        id: "vk_both_ways".into(),
        generation_hash: "binding:vk_both_ways:1".into(),
        name: "both-ways".into(),
        allowed_scopes: Some(vec![ScopeRef::pool("fast")]),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    let put = store.put_key(&key).map_err(|e| e.to_string());
    let got = store.get_key(&key.id).map_err(|e| e.to_string());
    let listed = store.list_keys().map_err(|e| e.to_string());
    format!(
        "put={put:?}\nget={}\nlist={}",
        serde_json::to_string(&got.ok()).unwrap(),
        serde_json::to_string(&listed.ok()).unwrap()
    )
}

/// THE EXIT TEST: the store example linked and dropped in registers the same row and opens a store
/// that answers the same.
#[test]
fn a_linked_and_a_dropped_in_store_register_byte_identical_rows() {
    let manifest = statement(
        "store",
        "store-example",
        "example-store",
        busbar_plugin::cold::ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        &busbar_store_example_plugin::BUSBAR_COLD_ENTRY,
        "busbar_store_example_plugin",
        |registry| {
            registry
                .open_store("example-store", "{}")
                .expect("the store opens through its alias")
        },
        |opened| script(opened.as_ref()),
    ) else {
        eprintln!("skip: store example cdylib not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("vk_both_ways"),
        "the linked store ran the script: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}
