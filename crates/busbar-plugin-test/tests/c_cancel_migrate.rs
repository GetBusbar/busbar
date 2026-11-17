// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-MIGRATE (ABI-MIN3-INTERFACE §14): Read as the open chain (WBS rule 12): the registry's boot future
//! dropped mid-open.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::Arc;
use std::time::Duration;

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_loader::instance::{OpenError, Registry};

use crate::min3_second::{self as fx, ParkNeeds};
use crate::min3_store as store;

/// The registry's step cap here: an `open` that NEEDs more often than this is cancelled `Steps`.
const MAX_STEPS: u32 = 4;

/// The cancelled store open of `id`: its held future dropped exactly once, no value built, so no Instance and no
/// `close`.
fn cancelled_once(id: &str) {
    let seen = store::counts(id);
    assert_eq!(
        seen.open_drops, 1,
        "{id}: exactly one cancel dropped the open future"
    );
    assert_eq!(seen.built, 0, "{id}: no instance was built");
    assert_eq!(seen.closes, 0, "{id}: no close was issued");
}

/// Round 31 reads the store's `migrate` chain as its `open` chain. The inline store fixture's `open` holds a
/// counted guard across a SECRET that never answers (`ParkNeeds::PARK`, its `/secret` handle), or NEEDs SECRET
/// of an answering handle for ever. The boot future (`Registry::open_store`) is cancelled (a) by the caller's
/// deadline on this thread, (b) by the registry's `max_steps`, and (c) by dropping it on a tokio worker: each
/// drops the plugin's future exactly once, inline on this thread for (a) and (b), builds no instance and issues
/// no close; the registry keeps serving and a plain store opens after.
#[test]
fn dropping_the_boot_future_mid_open_cancels_once() {
    let me = std::thread::current().id();
    let needs = Arc::new(ParkNeeds::default());
    let registry: &'static Registry = Box::leak(Box::new(fx::registry(
        Arc::clone(&needs),
        MAX_STEPS,
        &[store::inline::PLUGIN.plugin()],
    )));
    let module = "fixture-store-inline";
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");

    // (a) The caller's deadline.
    let spec = fx::spec(
        module,
        "migrate-deadline",
        br#"{"id":"migrate-deadline","secret":"the operator's reference","hold":true}"#,
    );
    let timed_out = rt.block_on(tokio::time::timeout(
        Duration::from_millis(200),
        registry.open_store(
            &spec,
            &needs,
            &busbar_plugin_test::suites::harness::no_refs(),
            Arc::new(|| Box::new(busbar_contract::plugin::TestKernelSeal)),
        ),
    ));
    assert!(timed_out.is_err(), "the parked open never finished");
    assert_eq!(needs.parked(), 1, "the open parked on its SECRET");
    cancelled_once("migrate-deadline");
    assert_eq!(
        store::counts("migrate-deadline").drop_threads,
        vec![me],
        "cancelled inline"
    );

    // (b) The step cap: SECRET of handle 2 answers DENIED at once, the open asks again until `max_steps`.
    let spec = fx::spec(
        module,
        "migrate-steps",
        br#"{"id":"migrate-steps","hold":true,"loop":2}"#,
    );
    match rt.block_on(registry.open_store(
        &spec,
        &needs,
        &busbar_plugin_test::suites::harness::no_refs(),
        Arc::new(|| Box::new(busbar_contract::plugin::TestKernelSeal)),
    )) {
        Err(OpenError::Call(CallError::Steps)) => {}
        Err(other) => panic!("the step cap ends the open: {other:?}"),
        Ok(_) => panic!("an open that NEEDs for ever opened"),
    }
    cancelled_once("migrate-steps");
    assert_eq!(
        store::counts("migrate-steps").drop_threads,
        vec![me],
        "cancelled inline"
    );

    // (c) The boot future dropped on a tokio worker.
    let workers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a multi-thread runtime");
    let before = needs.parked();
    let worker_needs = Arc::clone(&needs);
    let task = workers.spawn(async move {
        let needs = worker_needs;
        let spec = fx::spec(
            module,
            "migrate-dropped",
            br#"{"id":"migrate-dropped","secret":"the operator's reference","hold":true}"#,
        );
        registry
            .open_store(
                &spec,
                &needs,
                &busbar_plugin_test::suites::harness::no_refs(),
                Arc::new(|| Box::new(busbar_contract::plugin::TestKernelSeal)),
            )
            .await
            .map(drop)
    });
    crate::c_cancel_open::parked_past(&needs, before);
    task.abort();
    let joined = workers.block_on(task);
    assert!(
        matches!(&joined, Err(e) if e.is_cancelled()),
        "the boot future was dropped, not finished: {joined:?}"
    );
    cancelled_once("migrate-dropped");

    // The registry still serves: a plain store opens and builds.
    let spec = fx::spec(module, "migrate-after", br#"{"id":"migrate-after"}"#);
    let opened = rt
        .block_on(registry.open_store(
            &spec,
            &needs,
            &busbar_plugin_test::suites::harness::no_refs(),
            Arc::new(|| Box::new(busbar_contract::plugin::TestKernelSeal)),
        ))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(store::counts("migrate-after").built, 1);
    drop(opened);
}

#[test]
fn an_open_future_panicking_in_drop_faults_once_and_quarantines_nothing() {
    crate::c_panic_cancel::assert_open_cancel_fault();
}
