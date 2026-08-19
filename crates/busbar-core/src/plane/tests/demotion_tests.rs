// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORD ITSELF, ACROSS THE REAL PLUGIN ABI — written by one handle, read by the next.
//!
//! `quarantine_boot_tests.rs` judges the property from OUTSIDE: a real `tools/call` against a real
//! upstream, refused after a restart. That is the case that matters and it is where the claim is
//! made. This file is the seam underneath it, and it exists for two things that an outside-in case
//! cannot reach without contorting:
//!
//! * **THE CLEAR.** An operator works the remedy, the sweep observes the upstream serving what was
//!   approved, and the row must go — otherwise the demotion outlives its own cause and the only way
//!   back is to edit a store by hand. A quarantine that cannot be lifted is not a stronger control,
//!   it is an outage.
//! * **THE ABI CROSSING, on its own.** Every method here is DEFAULTED on the trait to
//!   accept-and-keep-nothing, so each one has a silent-no-op shape available to it at three separate
//!   places — the trait, the wire enum, and `DynStore`. Exercising them through a `dlopen`ed cdylib
//!   with the handle dropped in between is the only arrangement in which "it was written" and "the
//!   call returned `Ok(())`" are different sentences.
//!
//! Everything below loads the genuine `busbar-store-example-plugin` cdylib through
//! `busbar_plugin_loader::load_store`, i.e. across the same C ABI a customer's postgres or sqlite
//! plugin is reached over.

use crate::plane::quarantine::PlaneQuarantine;
use crate::test_support::plugin_store::{durable_cfg, open_plugin};

/// A `PlaneQuarantine` with a freshly `dlopen`ed handle on `cfg`.
fn node(cfg: &str) -> PlaneQuarantine {
    let d = PlaneQuarantine::new();
    d.set_sink(crate::plane::store::PlaneStoreView::narrow(open_plugin(
        cfg,
    )));
    d
}

/// A DEMOTION SURVIVES THE HANDLE THAT WROTE IT. The whole claim, at its narrowest.
#[test]
fn a_recorded_demotion_is_found_by_a_second_dlopen_of_the_same_store() {
    let (file, cfg) = durable_cfg("demotion-roundtrip");

    // The writing handle is scoped so the library is unloaded before anything reads: a row still
    // reachable through the handle that wrote it says nothing about durability, because the fixture
    // could be holding it in a map it drops on close.
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
    assert_eq!(rows[0].server, "fs");
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

/// THE UPSERT. Two demotions of one server are one row, not a pile — the sweep re-records on every
/// tick a drifted upstream is still drifting, and a table that appended would grow without bound at
/// sweep rate for as long as an operator took to work the change.
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

/// THE CLEAR, AND IT IS NOT A LESSER CASE. The remedy has to be able to land, and it has to land
/// DURABLY — a clear that only took effect in the clearing process would re-quarantine the upstream
/// at the next restart, which is an operator fixing the same thing forever.
#[test]
fn clearing_a_demotion_is_durable_so_a_worked_remedy_survives_the_next_restart() {
    let (_file, cfg) = durable_cfg("demotion-clear");
    {
        let writer = node(&cfg);
        writer.record("fs", "quarantined", 100);
        writer.record("git", "quarantined", 100);
    }
    {
        // A DIFFERENT handle does the clearing, which is what a later process is.
        node(&cfg).clear("fs");
    }
    let rows = node(&cfg).list();
    assert_eq!(
        rows.len(),
        1,
        "clearing one server must not clear the others: {rows:?}"
    );
    assert_eq!(
        rows[0].server, "git",
        "the one that was cleared is gone and the one that was not is still demoted"
    );
}

/// CLEARING A SERVER THAT WAS NEVER DEMOTED IS A NO-OP, not an error. The sweep clears on EVERY
/// agreeing observation rather than tracking whether it had demoted — which is the arrangement that
/// cannot forget — so the overwhelmingly common call is this one.
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

/// THE SETTLE RULE, ARM BY ARM. Both things that take a live observation — the unattended sweep and
/// the operator's `connect` verb — go through this one function, so this is where the rule is pinned.
///
/// The two arms that must NOT write are the point of the case. `Error` is an upstream that could not
/// be reached: recording it would turn a network blip into a quarantine that survives restarts, and
/// clearing on it would let a demoted upstream buy its approval back by going dark. `Suspended` and
/// `Pending` do not serve for reasons that already live in config and have nothing to do with drift.
#[test]
fn only_a_drift_demotion_writes_and_only_an_agreeing_observation_clears() {
    use crate::plane::quarantine::settle;
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

    // And a state that does not serve never MINTS a row for a server that had none, or a
    // registration nobody had demoted would acquire a durable quarantine from an outage.
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

/// THE PERMANENT NEGATIVE. With NO sink attached — which is what `store: memory` is from here — a
/// demotion is recorded in this process and NOTHING is kept. Without this the cases above would pass
/// identically against an engine that wrote to somewhere nobody configured, and "durable" would be
/// an unfalsifiable word.
#[test]
fn with_no_durable_sink_a_demotion_is_recorded_nowhere() {
    let (_file, cfg) = durable_cfg("demotion-nosink");
    let sinkless = PlaneQuarantine::new();
    sinkless.record("fs", "quarantined", 100);
    assert!(
        sinkless.list().is_empty(),
        "a `PlaneQuarantine` with no store must report nothing, because it has nothing"
    );
    assert!(
        open_plugin(&cfg)
            .list_mcp_demotions()
            .expect("list_mcp_demotions over the ABI")
            .is_empty(),
        "and nothing may have reached a store it was never given — a durability test that has \
         never seen a NON-durable deployment has proven nothing"
    );
}

/// AND THE RAM DEFAULT REALLY IS RAM. `busbar-store-memory` implements none of these methods, so
/// attaching it is indistinguishable from attaching nothing — the documented `store: memory`
/// contract, asserted rather than assumed. It is also the exact shape of every already-signed store
/// plugin that predates these three methods.
#[test]
fn the_memory_store_keeps_no_demotions_which_is_the_documented_contract() {
    let d = PlaneQuarantine::new();
    d.set_sink(crate::plane::store::PlaneStoreView::narrow(
        std::sync::Arc::new(busbar_store_memory::MemoryStore::new()),
    ));
    d.record("fs", "quarantined", 100);
    assert!(
        d.list().is_empty(),
        "the RAM default accepts the write and keeps nothing, which is why the engine learns \
         durability by READING BACK and never from a write's return value"
    );
}
