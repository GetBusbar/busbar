// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::store::plane_view::{decode, KIND_DEMOTION};
use crate::test_support::durable_store::{durable_cfg, open_durable};
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
        std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
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
        std::sync::Arc::new(crate::governance::MemoryStore::new()),
    ));
    d.record("fs", "quarantined", 100);
    assert_eq!(
        d.list().len(),
        1,
        "within the process the RAM default is a real store and reads the demotion back"
    );

    let restarted = DemotionRecord::new();
    restarted.set_sink(crate::store::plane_view::PlaneStoreView::narrow(
        std::sync::Arc::new(crate::governance::MemoryStore::new()),
    ));
    assert!(
        restarted.list().is_empty(),
        "nothing the RAM default held survives the process — that is what `store: memory` means, \
         and why a deployment that needs a demotion to outlive a restart configures a backend"
    );
}
