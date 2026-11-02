// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::store::plane_view::{decode, KIND_DEMOTION};
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use std::path::PathBuf;
use std::sync::Arc;

fn durable_cfg(label: &str) -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-demotion-{}-{}-{}",
        std::process::id(),
        label,
        crate::door::op_id().counter()
    ));
    std::fs::create_dir_all(&dir).expect("create the actual SQLite database directory");
    let file = dir.join("demotions.sqlite3");
    let cfg = serde_json::json!({"db_path": file}).to_string();
    (file, cfg)
}

fn open_durable(settings: &str) -> Arc<LoadedStore> {
    let path = PathBuf::from(
        std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
            .expect("BUSBAR_TEST_SQLITE_CDYLIB names the actual built SQLite product"),
    );
    let stated = rendering_of_library(&path)
        .expect("read SQLite statement")
        .expect("SQLite exports a statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .expect("valid SQLite statement")
        .name;
    assert_eq!(
        module, "busbar-store-sqlite",
        "durability requires the actual SQLite product"
    );
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Store>(
        &path,
        &stated,
        Bind {
            instance: format!("demotion-{}", crate::door::op_id().counter()).into(),
            max_inflight_cap: 1024,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("load the actual SQLite store through its ABI");
    Arc::new(
        LoadedStore::open(plugin, dispatcher, settings.as_bytes(), crate::door::op_id)
            .expect("open the same actual SQLite database"),
    )
}
use crate::trust::demotion::{DemotionRecord, DemotionRow};
use busbar_contract::records::{PlaneSelector, RecordStore, RecordStoreResult};

trait DemotionStoreTestExt: RecordStore {
    fn list_demotions(&self) -> RecordStoreResult<Vec<DemotionRow>> {
        self.list_plane_records(KIND_DEMOTION, &PlaneSelector::All)?
            .iter()
            .map(|b| decode(b))
            .collect()
    }
}
impl<T: RecordStore + ?Sized> DemotionStoreTestExt for T {}

fn node(cfg: &str) -> DemotionRecord {
    let d = DemotionRecord::new();
    d.set_sink(crate::store::plane_view::PlaneStoreView::narrow(
        open_durable(cfg),
    ));
    d
}

#[test]
fn a_recorded_demotion_is_found_by_a_second_handle_on_the_same_store() {
    let (file, cfg) = durable_cfg("demotion-roundtrip");

    {
        let writer = node(&cfg);
        writer.record("fs", "quarantined", 1_700_000_000);
    }

    let rows = node(&cfg).list();
    assert_eq!(
        rows.len(),
        1,
        "ONE demotion for one demoted upstream. Zero here is the defect the record exists for — the \
         write returned `Ok(())` and the row is nowhere. The store at {} holds: {}",
        file.display(),
        format!("{:?}", std::fs::metadata(&file).map(|m| m.len()))
    );
    assert_eq!(rows[0].upstream, "fs");
    assert_eq!(
        rows[0].reason, "quarantined",
        "the operator-facing word is carried, or a restored demotion cannot say why it is there"
    );
    assert_eq!(
        rows[0].recorded_at, 1_700_000_000,
        "and when, which is what tells an operator whether this is the demotion they already know \
         about"
    );
}

#[test]
fn re_recording_the_same_server_replaces_the_row_rather_than_appending() {
    let (_file, cfg) = durable_cfg("demotion-upsert");
    {
        let writer = node(&cfg);
        writer.record("fs", "quarantined", 100);
        writer.record("fs", "quarantined", 200);
    }
    let rows = node(&cfg).list();
    assert_eq!(rows.len(), 1, "one server, one row: {rows:?}");
    assert_eq!(
        rows[0].recorded_at, 200,
        "and it is the LATEST observation, so the timestamp an operator reads is when the upstream \
         was last seen still drifting"
    );
}

#[test]
fn clearing_a_demotion_is_durable_so_a_worked_remedy_survives_the_next_restart() {
    let (_file, cfg) = durable_cfg("demotion-clear");
    {
        let writer = node(&cfg);
        writer.record("fs", "quarantined", 100);
        writer.record("git", "quarantined", 100);
    }
    {
        node(&cfg).clear("fs");
    }
    let rows = node(&cfg).list();
    assert_eq!(
        rows.len(),
        1,
        "clearing one server must not clear the others: {rows:?}"
    );
    assert_eq!(
        rows[0].upstream, "git",
        "the one that was cleared is gone and the one that was not is still demoted"
    );
}

#[test]
fn clearing_an_absent_record_is_a_no_op() {
    let (_file, cfg) = durable_cfg("demotion-clear-absent");
    let n = node(&cfg);
    n.clear("never-demoted");
    assert!(
        n.list().is_empty(),
        "an absent row cleared must leave an empty table, not create one"
    );
}

#[test]
fn only_a_drift_demotion_writes_and_only_an_agreeing_observation_clears() {
    use crate::trust::demotion::settle;
    use crate::trust::TrustState;

    let (_file, cfg) = durable_cfg("demotion-settle");
    let n = node(&cfg);

    settle(&n, "fs", TrustState::Quarantined);
    assert_eq!(n.list().len(), 1, "a drift demotion is recorded");

    for held in [
        TrustState::Error,
        TrustState::Suspended,
        TrustState::Pending,
    ] {
        settle(&n, "fs", held);
        assert_eq!(
            n.list().len(),
            1,
            "{held:?} must leave the row exactly as it is: it is not evidence that the upstream \
             stopped drifting, and an upstream that could clear its own demotion by going dark or \
             by being suspended would have the cheapest possible escape from one"
        );
    }

    settle(&n, "fs", TrustState::Approved);
    assert!(
        n.list().is_empty(),
        "and the operator's remedy landing — an observation that AGREES — is the one thing that \
         clears it"
    );

    for held in [
        TrustState::Error,
        TrustState::Suspended,
        TrustState::Pending,
    ] {
        settle(&n, "git", held);
    }
    assert!(
        n.list().is_empty(),
        "none of the non-drift states may create a record for a server that never had one"
    );
}

#[test]
fn with_no_durable_sink_a_demotion_is_recorded_nowhere() {
    let (_file, cfg) = durable_cfg("demotion-nosink");
    let sinkless = DemotionRecord::new();
    sinkless.record("fs", "quarantined", 100);
    assert!(
        sinkless.list().is_empty(),
        "a `DemotionRecord` with no store must report nothing, because it has nothing"
    );
    assert!(
        open_durable(&cfg)
            .list_demotions()
            .expect("list_demotions through the store")
            .is_empty(),
        "and nothing may have reached a store it was never given — a durability test that has \
         never seen a NON-durable deployment has proven nothing"
    );
}

#[test]
fn the_memory_store_keeps_demotions_only_for_the_life_of_the_process() {
    let d = DemotionRecord::new();
    d.set_sink(crate::store::plane_view::PlaneStoreView::narrow(
        crate::real_store::store(),
    ));
    d.record("fs", "quarantined", 100);
    assert_eq!(
        d.list().len(),
        1,
        "within the process the RAM default is a real store and reads the demotion back"
    );

    let restarted = DemotionRecord::new();
    restarted.set_sink(crate::store::plane_view::PlaneStoreView::narrow(
        crate::real_store::store(),
    ));
    assert!(
        restarted.list().is_empty(),
        "nothing the RAM default held survives the process — that is what `store: memory` means, \
         and why a deployment that needs a demotion to outlive a restart configures a backend"
    );
}
