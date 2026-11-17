// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STORE-LANE (ABI-MIN3-INTERFACE §14): An F_BLOCKING_FILE store on the lane: no worker blocked, ceilings, NEED
//! refused, readback after drop.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The halves the booted `plugin!` store fixture carries (`fixtures/min3_store.rs`: the lane image declares
//! F_BLOCKING_FILE, a 60 s commit ceiling, CEIL_OPEN 3,600 s and a scan ceiling above the lane range; the inline
//! image is the same store without the fact) run now as the sibling tests below; the whole arm stays ignored for
//! the pieces no harness reaches yet.

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::persistence::Decision;
use busbar_plugin_abi::fail::{CallError, FaultReason};
use busbar_plugin_loader::instance::OpenError;
use busbar_plugin_test::fake_needs::FakeNeeds;

use crate::min3_store::{booted, counts, initialization, inline, lane, read_one};

#[test]
#[ignore = "owner: W1-L3 (blocked: the rest of the arm needs what no harness reaches: the lane thread's watchdog word (busbar-plugin-abi host_side::watch exposes no read of another thread's word, only `scan`), the kernel readback that resolves a dropped commit (busbar-kernel persistence over a `StoreHandle`, not wired to a harness), and the 30 s `migrate` under CEIL_MIGRATE; the commit/no-worker-blocked/NEED/drop/clamp/inline halves run as the sibling tests)"]
fn a_blocking_store_runs_on_the_lane() {
    todo!("owner: W1-L3 (C-STORE-LANE)")
}

/// On a 2-worker multi-thread runtime, two lane commits that each sleep 2 s in their first poll complete OK
/// (the instance is not quarantined under its declared 60 s ceiling, with the watchdog running) while a no-op
/// task spawned meanwhile runs within 5 ms (neither worker is blocked); each commit ran off the polling thread.
#[test]
fn lane_commits_block_no_worker_and_pass_their_declared_ceiling() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a 2-worker runtime");
    let h = booted(lane::PLUGIN.plugin(), FakeNeeds::new());
    h.registry().start_watchdog();
    let id = "c-store-lane-commit";
    let config = format!(r#"{{"id":"{id}","commit_sleep_ms":2000}}"#);
    let spec = h.spec("lane", config.as_bytes());
    let store = rt
        .block_on(h.registry().open_store(
            &spec,
            &h.needs_arc(),
            &h.refs_arc(),
            Arc::new(|| Box::new(busbar_contract::plugin::TestKernelSeal)),
        ))
        .unwrap_or_else(|e| panic!("open failed: {e:?}"));
    let backend = Arc::clone(&store.backend);
    let polled_on = std::thread::current().id();
    rt.block_on(async move {
        let commit = |b: Arc<dyn busbar_contract::persistence::PersistenceBackend>| {
            tokio::spawn(async move {
                let (init, key) = initialization(&*b);
                b.commit(init, key)
                    .await
                    .map(|d| matches!(d, Decision::Applied(_)))
            })
        };
        let first = commit(Arc::clone(&backend));
        let second = commit(Arc::clone(&backend));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        tokio::spawn(async {}).await.expect("the no-op task ran");
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_millis(5),
            "a no-op task waited {waited:?}: a worker is blocked"
        );
        for done in [first, second] {
            assert_eq!(done.await.expect("the commit task"), Ok(true));
        }
        assert!(read_one(&*backend).await.is_ok(), "the instance is live");
    });
    let seen = counts(id);
    assert_eq!(seen.commits, 2);
    assert!(
        seen.commit_threads.iter().all(|t| *t != polled_on),
        "a lane commit runs on a lane thread"
    );
}

/// The same fixture without F_BLOCKING_FILE runs inline: its commit runs on the thread that polls it (no
/// `spawn_blocking`); the lane image's runs on another.
#[test]
fn the_same_store_without_the_fact_runs_inline() {
    let here = std::thread::current().id();
    for (plugin, id, inline_run) in [
        (inline::PLUGIN.plugin(), "c-store-lane-inline", true),
        (lane::PLUGIN.plugin(), "c-store-lane-off", false),
    ] {
        let h = booted(plugin, FakeNeeds::new());
        let config = format!(r#"{{"id":"{id}"}}"#);
        let store = h
            .open_store(id, config.as_bytes())
            .unwrap_or_else(|e| panic!("{id}: open failed: {e:?}"));
        let (init, key) = initialization(&*store.backend);
        assert!(matches!(
            h.block_on(store.backend.commit(init, key)),
            Ok(Decision::Applied(_))
        ));
        let threads = counts(id).commit_threads;
        assert_eq!(threads.len(), 1, "{id}");
        assert_eq!(threads[0] == here, inline_run, "{id}");
    }
}

/// Dropping the awaiting commit future before it completes leaves the lane job running to completion: the
/// fixture records the commit after the caller gave up.
#[test]
fn a_dropped_lane_commit_runs_to_completion() {
    let h = booted(lane::PLUGIN.plugin(), FakeNeeds::new());
    let id = "c-store-lane-drop";
    let config = format!(r#"{{"id":"{id}","commit_sleep_ms":500}}"#);
    let store = h
        .open_store("lane-drop", config.as_bytes())
        .unwrap_or_else(|e| panic!("open failed: {e:?}"));
    let (init, key) = initialization(&*store.backend);
    let gave_up = h.block_on(tokio::time::timeout(
        Duration::from_millis(50),
        store.backend.commit(init, key),
    ));
    assert!(gave_up.is_err(), "the commit was still running at 50 ms");
    assert_eq!(counts(id).commits, 0, "not recorded before its sleep ends");
    let deadline = Instant::now() + Duration::from_secs(10);
    while counts(id).commits == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(counts(id).commits, 1, "the detached job ran to completion");
}

/// A NEED from an F_BLOCKING_FILE store (its `open` resolving a SECRET) is FAULT `NeedNotAllowed`: the lane's
/// Need row is empty. The inline image makes the same SECRET and opens.
#[test]
fn a_need_from_a_lane_store_is_fault_need_not_allowed() {
    for (plugin, lane_store) in [
        (lane::PLUGIN.plugin(), true),
        (inline::PLUGIN.plugin(), false),
    ] {
        let mut needs = FakeNeeds::new();
        needs.secret("/secret", b"backend-password-1");
        let h = booted(plugin, needs);
        let opened = h.open_store("needs", br#"{"secret":"vault:db"}"#);
        match opened {
            Err(OpenError::Call(CallError::Fault(FaultReason::NeedNotAllowed(_))))
                if lane_store => {}
            Ok(_) if !lane_store => {}
            Err(e) => panic!("lane {lane_store}: {e:?}"),
            Ok(_) => panic!("a lane store's NEED was allowed"),
        }
    }
}

/// A D_CEILING above its range is clamped to the bound and logged once at `add`: the lane image's 500 s scan
/// ceiling becomes the lane column's 120 s.
#[test]
fn a_ceiling_above_the_lane_range_is_clamped_and_logged() {
    use busbar_plugin_abi::host_side::HOST;
    use busbar_plugin_loader::admit::admit_header;

    use busbar_plugin_loader::instance::{Ceilings, ImagesBuilder, SlotTable};

    use crate::min3_store::{Capture, LANE_SCAN_CLAMPED_US, LANE_SCAN_US};

    let capture = Capture::default();
    let _tap = capture.install();
    let slots = Arc::new(SlotTable::new());
    busbar_plugin_loader::instance::install_sinks(&slots);
    let mut images = ImagesBuilder::new(&HOST, slots, Ceilings::DEFAULT);
    let admitted = admit_header(lane::PLUGIN.plugin()).expect("the lane image admits");
    images.admit(admitted).expect("the lane image is described");
    let clamps = capture.with_message("plugin ceiling clamped into its range");
    assert_eq!(clamps.len(), 1, "one clamp, logged once");
    let scan_bit = busbar_plugin_abi::store::M_SCAN
        .trailing_zeros()
        .to_string();
    assert_eq!(clamps[0].field("entry"), Some(scan_bit.as_str()));
    assert_eq!(
        clamps[0].field("declared_us"),
        Some(LANE_SCAN_US.to_string().as_str())
    );
    assert_eq!(
        clamps[0].field("clamped_us"),
        Some(LANE_SCAN_CLAMPED_US.to_string().as_str())
    );
}
