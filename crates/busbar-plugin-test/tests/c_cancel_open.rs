// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-OPEN (ABI-MIN3-INTERFACE §14): An `open` chain parked mid-NEED cancelled three ways (rounds 6, 8, 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_loader::instance::{OpenError, Registry};
use busbar_plugin_loader::ports::CallCx;

use crate::min3_second::{self as fx, ParkNeeds, PROBE};

/// The registry's step cap here: an `open` that NEEDs more often than this is cancelled `Steps`.
const MAX_STEPS: u32 = 4;

/// Waits (at most 10 s) until `needs` has parked one more SECRET than `before`.
pub(crate) fn parked_past(needs: &ParkNeeds, before: u32) {
    let until = Instant::now() + Duration::from_secs(10);
    while needs.parked() <= before {
        assert!(
            Instant::now() < until,
            "the open chain never parked on its SECRET"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The cancelled `open` of `tag`: its future was dropped exactly once, its plugin value never built, so no
/// Instance and no `close`.
pub(crate) fn cancelled_once(tag: &str) {
    assert_eq!(
        fx::count(tag, "open.future.drop"),
        1,
        "{tag}: exactly one cancel dropped the open future"
    );
    assert_eq!(fx::count(tag, "built"), 0, "{tag}: no instance was built");
    assert_eq!(fx::count(tag, "close"), 0, "{tag}: no close was issued");
}

/// The probe's `open` holds a counted guard across a SECRET that never answers (handle `ParkNeeds::PARK`), or
/// NEEDs SECRET of an answering handle for ever. Cancelled (a) by the caller's deadline (the open future dropped
/// by the timeout on the thread polling it), (b) by the registry's `max_steps` (the driver's `Err(Steps)`) and
/// (c) by dropping it on a tokio worker (the spawned open aborted while parked): each drops the plugin's future
/// exactly once, inline on the thread that drops or times out the chain for (a) and (b), builds no instance and
/// issues no close; the registry keeps serving.
#[test]
fn an_open_parked_mid_need_is_cancelled_three_ways_once_inline() {
    let me = std::thread::current().id();
    let needs = Arc::new(ParkNeeds::default());
    let registry: &'static Registry<ParkNeeds> = Box::leak(Box::new(fx::registry(
        Arc::clone(&needs),
        MAX_STEPS,
        &[fx::probe::PLUGIN.plugin()],
    )));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");

    // (a) The caller's deadline.
    let spec = fx::spec(
        PROBE,
        "cancel-deadline",
        br#"{"tag":"cancel-deadline","hold":true,"loop":1}"#,
    );
    let timed_out = rt.block_on(tokio::time::timeout(
        Duration::from_millis(200),
        registry.open_secret(&spec),
    ));
    assert!(timed_out.is_err(), "the parked open never finished");
    assert_eq!(needs.parked(), 1, "the open parked on its SECRET");
    cancelled_once("cancel-deadline");
    assert_eq!(
        fx::drop_threads("cancel-deadline"),
        vec![me],
        "cancelled inline"
    );

    // (b) The step cap: SECRET of handle 2 answers DENIED at once, the open asks again until `max_steps`.
    let spec = fx::spec(
        PROBE,
        "cancel-steps",
        br#"{"tag":"cancel-steps","hold":true,"loop":2}"#,
    );
    match rt.block_on(registry.open_secret(&spec)) {
        Err(OpenError::Call(CallError::Steps)) => {}
        Err(other) => panic!("the step cap ends the open: {other:?}"),
        Ok(_) => panic!("an open that NEEDs for ever opened"),
    }
    cancelled_once("cancel-steps");
    assert_eq!(
        fx::drop_threads("cancel-steps"),
        vec![me],
        "cancelled inline"
    );

    // (c) The open future dropped on a tokio worker.
    let workers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a multi-thread runtime");
    let before = needs.parked();
    let task = workers.spawn(async move {
        let spec = fx::spec(
            PROBE,
            "cancel-dropped",
            br#"{"tag":"cancel-dropped","hold":true,"loop":1}"#,
        );
        registry.open_secret(&spec).await.map(drop)
    });
    parked_past(&needs, before);
    task.abort();
    let joined = workers.block_on(task);
    assert!(
        matches!(&joined, Err(e) if e.is_cancelled()),
        "the open future was dropped, not finished: {joined:?}"
    );
    cancelled_once("cancel-dropped");

    // The registry still serves: a plain open builds and answers.
    let spec = fx::spec(PROBE, "cancel-after", br#"{"tag":"cancel-after"}"#);
    let port = rt
        .block_on(registry.open_secret(&spec))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let cx = CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: 1,
        stack: CallStack::default(),
    };
    let answer = rt.block_on(port.resolve(cx, br#"{"name":"db"}"#)).ok();
    assert_eq!(
        answer.map(|a| a.value.as_slice().to_vec()).as_deref(),
        Some(&b"db"[..])
    );
    assert_eq!(fx::count("cancel-after", "built"), 1);
}

#[test]
#[ignore = "owner: W1-H1; blocked (re-checked on dev 2026-11-16): needs a pool instrumented to record acquire and release in order (busbar-plugin-abi host_side/pool.rs exposes only the misses/drops counters), so 'held until cancel returned, then released zeroed, the slot lease last' is not observable from busbar-plugin-test; the cancel itself runs in an_open_parked_mid_need_is_cancelled_three_ways_once_inline"]
fn buffers_are_released_zeroed_after_cancel_returns_and_the_lease_last() {
    todo!("owner: W1-H1 (C-CANCEL-OPEN)")
}
