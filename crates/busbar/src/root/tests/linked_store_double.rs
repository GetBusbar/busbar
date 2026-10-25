// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINKED STORE DOOR, PROVEN WHERE IT IS LINKED (R-FIX3). The kernel's test build takes no store
//! crate under any name (THE DESIGN Part 2 #2: the kernel reaches a store only through the store
//! kind's door): it links its in-crate double (`busbar_kernel::test_support::store_double`), and
//! its own tests run against that. These prove the double copies the real door the root links
//! (`crate::LINKED.stores`): the same Statement, and the same answers to one verb script, both
//! stores opened through their doors on the store axis exactly as boot opens the configured store.

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::rendering;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, UsageDelta, VirtualKey,
};
use busbar_contract::store_calls::{StoreAxis as _, StoreDoor};
use busbar_kernel::test_support::store_double;

fn read(door: DoorFn) -> rendering::Read {
    let stated = crate::root::loader::dispatch::rendering_of(door).expect("the door states");
    rendering::read(&stated).expect("the rendering reads")
}

/// The root's linked store row the double stands in for: the one under the double's key.
fn real_row() -> &'static busbar_kernel::preflight::LinkedStore {
    crate::LINKED
        .stores
        .iter()
        .find(|s| s.0 == store_double::STORE.0)
        .expect("the root links a store under the key the double answers")
}

/// `door`, opened through the store axis on a dispatcher of its own, as boot opens a store.
fn open(door: DoorFn, label: &str) -> Arc<dyn RecordStore> {
    let axis = crate::root::loader::store_v3::DoorStoreAxis {
        dispatcher: {
            let d = Arc::new(crate::root::loader::dispatch::Dispatcher::new(
                crate::root::loader::dispatch::DispatchConfig::default(),
            ));
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = d.lend_seal(busbar_kernel::seal::lend());
            d
        },
        logs: crate::root::boot::plugin_logs().clone(),
        // Neither store declares a need: each serves with no connection table.
        conns: crate::root::loader::dispatch::ConnTable::NoNeeds,
        mint: busbar_kernel::door::op_id,
    };
    axis.open(StoreDoor::Linked(door), label, b"{}")
        .expect("the store opens through its door")
        .records
}

fn plane(kind: &str, id: &str, parent: Option<&str>, seq: u64) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(str::to_string),
        seq,
        ts: 5,
        disposition: PlaneDisposition::Active,
        body: format!("{id}@{seq}").into_bytes(),
    }
}

/// One verb script, every answer written down: keys (the tombstone refusals), usage, the 1.5.5
/// audit rows (read), plane records (upsert, appended chain, parent listing), the
/// spent-token test-and-set, the live-token read and the denylist. No answer reads the wall clock.
fn transcript(s: &dyn RecordStore) -> Vec<String> {
    let mut t = Vec::new();
    let key = VirtualKey {
        id: "k1".into(),
        name: "one".into(),
        enabled: true,
        created_at: 10,
        ..Default::default()
    };
    t.push(format!("put_key {:?}", s.put_key(&key).map_err(|e| e.0)));
    t.push(format!(
        "put_key again {:?}",
        s.put_key(&key).map_err(|e| e.0)
    ));
    let got = s
        .get_key("k1")
        .map(|k| k.map(|k| (k.id, k.name, k.enabled, k.revision, k.deleted_at)));
    t.push(format!("get_key {:?}", got.map_err(|e| e.0)));
    let since = s.list_keys_since(0).map(|v| {
        v.into_iter()
            .map(|k| (k.id, k.revision))
            .collect::<Vec<_>>()
    });
    t.push(format!("list_keys_since {:?}", since.map_err(|e| e.0)));
    t.push(format!(
        "delete_key unknown {:?}",
        s.delete_key("nope").map_err(|e| e.0)
    ));
    // The tombstone: written (its instant is the wall clock's, so only its presence is read), and
    // never cleared by a live-shaped write.
    t.push(format!(
        "delete_key {:?}",
        s.delete_key("k1").map_err(|e| e.0)
    ));
    t.push(format!(
        "put_key over tombstone {:?}",
        s.put_key(&key).map_err(|e| e.0)
    ));
    let dead = s
        .get_key("k1")
        .map(|k| k.map(|k| (k.enabled, k.deleted_at.is_some(), k.revision)));
    t.push(format!("get_key tombstoned {:?}", dead.map_err(|e| e.0)));

    let delta = UsageDelta {
        requests: 2,
        billable_requests: 1,
        ..Default::default()
    };
    t.push(format!(
        "add_usage {:?}",
        s.add_usage("b", 60, &delta).map_err(|e| e.0)
    ));
    t.push(format!(
        "add_usage {:?}",
        s.add_usage("b", 60, &delta).map_err(|e| e.0)
    ));
    t.push(format!(
        "get_usage {:?}",
        s.get_usage("b", 60).map_err(|e| e.0)
    ));

    t.push(format!("list_audit {:?}", s.list_audit().map_err(|e| e.0)));

    let head = plane("probe", "t1", None, 0);
    t.push(format!(
        "upsert {:?}",
        s.upsert_plane_record(head.view()).map_err(|e| e.0)
    ));
    t.push(format!(
        "get {:?}",
        s.get_plane_record("probe", "t1").map_err(|e| e.0)
    ));
    for seq in [1, 2] {
        let step = plane("probe-step", "s", Some("t1"), seq);
        t.push(format!(
            "append {:?}",
            s.append_plane_record(step.view()).map_err(|e| e.0)
        ));
    }
    let chain = s.list_plane_records("probe-step", &PlaneSelector::Parent("t1".into()));
    t.push(format!("list by parent {:?}", chain.map_err(|e| e.0)));
    let parents = s.list_plane_record_parents("probe-step");
    t.push(format!("parents {:?}", parents.map_err(|e| e.0)));

    for _ in 0..2 {
        let spent = s.redeem_plane_token("probe", "tok", u64::MAX, 5);
        t.push(format!("redeem {:?}", spent.map_err(|e| e.0)));
    }
    let live = s.plane_token_live("probe", "t1", u64::MAX, 5);
    t.push(format!("live {:?}", live.map_err(|e| e.0)));
    let lapsed = s.plane_token_live("probe", "t1", 4, 5);
    t.push(format!("lapsed {:?}", lapsed.map_err(|e| e.0)));

    t.push(format!(
        "add_denylist {:?}",
        s.add_denylist("sub", "why").map_err(|e| e.0)
    ));
    t.push(format!(
        "list_denylist {:?}",
        s.list_denylist().map_err(|e| e.0)
    ));
    t
}

/// R-FIX3: THE KERNEL'S STORE DOUBLE STATES WHAT THE LINKED STORE DOOR STATES, so the kernel's tests,
/// which boot on the double and build every `GovState` over it, judge the store the binary ships.
/// Both Statements rendered: the same kind and ABI, `max_inflight`, flag marks, word marks, needs and
/// tail, and the same ephemeral flag on the linked row; the name is the double's own (the kernel names
/// no plugin, C1). Both opened through their doors on the store axis: the same answer to every verb
/// of one script, refusals byte for byte.
///
/// RED by flipping any copied rule in the double (e.g. `redeem_plane_token` answering `true` twice,
/// or `put_key` clearing a tombstone), or by stating a different tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kernel_store_double_states_what_the_linked_store_door_states() {
    let row = real_row();
    let (real, double) = (read(row.2), read(store_double::door));
    assert_ne!(
        double.name, real.name,
        "the double states its own name: the kernel names no plugin (C1)"
    );
    assert_eq!(double.name, store_double::NAME, "the Statement name");
    assert_eq!(
        store_double::STORE.3,
        store_double::NAME,
        "the canonical name"
    );
    assert_eq!(double.kind, real.kind);
    assert_eq!(double.kind_abi, real.kind_abi);
    assert_eq!(double.max_inflight, real.max_inflight, "max_inflight");
    assert_eq!(double.marks, real.marks, "the flag marks");
    assert_eq!(double.mark_words, real.mark_words, "every word mark");
    assert_eq!(double.needs, real.needs, "the needs");
    assert_eq!(double.kind_tail_size, real.kind_tail_size, "the tail");
    assert_eq!(store_double::STORE.1, row.1, "the ephemeral flag");

    let (real_door, double_door) = (row.2, store_double::door);
    let (want, got) = tokio::task::spawn_blocking(move || {
        let want = transcript(open(real_door, "linked-real").as_ref());
        let got = transcript(open(double_door, "linked-double").as_ref());
        (want, got)
    })
    .await
    .expect("the blocking scripts ran");
    assert_eq!(
        got, want,
        "the double answers the script as the linked store does"
    );
}
