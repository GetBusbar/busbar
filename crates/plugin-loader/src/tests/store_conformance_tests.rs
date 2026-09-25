// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: store`, BOTH WAYS** (DECISIONS #2 rule (1)). The store kind's in-tree fixture
//! registered through the LINKED door (its `rlib`'s `BUSBAR_COLD_ENTRY`) and the DROPPED-IN door
//! (its `cdylib`, signed into `plugins/`) resolves to the byte-identical registry row, and the
//! store each door's `open_store` opens answers one script byte-identically. See
//! [`super::both_ways`].
//!
//! RED by planting the door bypass the axis replaces — linked rows handed to
//! [`PluginRegistry::link`] and never registered — which leaves the linked registry with no row for
//! the name.

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

/// THE EXIT TEST: the store fixture linked and dropped in registers the same row and opens a store
/// that answers the same.
#[test]
fn a_linked_and_a_dropped_in_store_register_byte_identical_rows() {
    let manifest = statement(
        "store",
        "store-fixture",
        "the-store",
        busbar_plugin::cold::ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        |registry| {
            registry
                .open_store("the-store", "{}")
                .expect("the store opens through its alias")
        },
        |opened| script(opened.as_ref()),
    ) else {
        eprintln!("skip: the store fixture's cdylib is not built");
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

/// THE LINKED DOOR ADMITS WHAT THE DROPPED-IN DOOR ADMITS. A linked row passes the structural gate a
/// signed manifest passes (every check but the artifact's integrity): a name the directory would
/// refuse, a kind the door does not serve and a payload schema this binary cannot speak are each
/// refused, naming the row; a well-formed built-in store row registers, opens through `open_store`
/// and carries its own ephemeral statement.
#[test]
fn the_linked_door_refuses_what_the_structural_gate_refuses() {
    use crate::{LinkedPlugin, PluginRegistry};
    fn ram(_: &str) -> Result<Box<dyn Store>, String> {
        Err("never opened".into())
    }
    let refused = |row: LinkedPlugin| match PluginRegistry::empty().link(vec![row]) {
        Ok(_) => panic!("the linked door admitted a row the structural gate refuses"),
        Err(e) => e,
    };
    let e = refused(LinkedPlugin::store("Not A Name", ram, false));
    assert!(e.contains("is not a valid plugin name"), "{e}");
    let mut wrong_kind = LinkedPlugin::store("a-plane", ram, false);
    wrong_kind.manifest.kind = "plane".into();
    wrong_kind.manifest.abi_version = 1;
    assert!(refused(wrong_kind).contains("is not linked through this door"));
    let mut future = LinkedPlugin::store("a-store", ram, false);
    future.manifest.abi_version = u32::MAX;
    assert!(refused(future).contains("is not supported for kind 'store'"));

    let reg = PluginRegistry::empty()
        .link(vec![LinkedPlugin::store("a-store", ram, true)])
        .expect("a well-formed row registers");
    let row = reg.resolve("a-store").expect("resolves by name");
    assert!(row.ephemeral && reg.loadable().is_empty() && reg.linked().len() == 1);
    let Err(e) = reg.open_store("a-store", "{}") else {
        panic!("open_store must call the row's own constructor");
    };
    assert_eq!(e, "never opened");
}
