// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CANCEL-OPEN (ABI-MIN3-INTERFACE §14): An `open` chain parked mid-NEED cancelled three ways (rounds 6, 8, 10).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::host_side::pool::{observe_pool, PoolEvent};
use busbar_plugin_loader::instance::{OpenError, Registry};
use busbar_plugin_loader::ports::CallCx;

use crate::min3_second::{self as fx, ParkNeeds, Step, PROBE};

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

/// The registry the pool observer asks about the watched slot.
static WATCHED: OnceLock<&'static Registry<ParkNeeds>> = OnceLock::new();
/// The slot of the parked chain, once known (`u32::MAX` before).
static SLOT: AtomicU32 = AtomicU32::new(u32::MAX);

/// The pool observer: every block taken and returned, in the fixture's trace, each return with whether its bytes
/// were all zero and whether the watched slot was still leased (its record still in the slot table).
fn observe(event: PoolEvent<'_>) {
    match event {
        PoolEvent::Taken { block } => fx::step(Step::Taken(block)),
        PoolEvent::Released { block, bytes } => {
            let slot = SLOT.load(Ordering::SeqCst);
            let leased = WATCHED
                .get()
                .and_then(|registry| registry.scrub_of(slot))
                .is_some();
            fx::step(Step::Returned {
                block,
                zeroed: bytes.iter().all(|&b| b == 0),
                leased,
            });
        }
    }
}

/// Round 8: the boot future dropped on this thread while the probe's `open` is parked on a SECRET that never
/// answers, with the pool instrumented (`pool::observe_pool`). The chain's four blocks (`req`, both OutBufs and
/// `results`) stay out of the pool, so nothing can take them again, until the cancel has dropped the plugin's
/// future and returned (the driver's `Needs::release` runs only after `cancel` returns); then each comes back
/// once, all zero, while the slot is still leased; the lease goes last.
#[test]
fn buffers_are_released_zeroed_after_cancel_returns_and_the_lease_last() {
    observe_pool(observe);
    let me = std::thread::current().id();
    let needs = Arc::new(ParkNeeds::default());
    let registry: &'static Registry<ParkNeeds> = Box::leak(Box::new(fx::registry(
        Arc::clone(&needs),
        MAX_STEPS,
        &[fx::probe::PLUGIN.plugin()],
    )));
    assert!(WATCHED.set(registry).is_ok());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");

    let start = fx::trace().len();
    let spec = fx::spec(
        PROBE,
        "cancel-bufs",
        br#"{"tag":"cancel-bufs","hold":true,"loop":1}"#,
    );
    let mut boot = registry.open_secret(&spec);
    let polled = rt.block_on(tokio::time::timeout(Duration::from_millis(200), &mut boot));
    assert!(polled.is_err(), "the parked open never finished");
    let parked = fx::trace();
    let (at_park, slot) = parked
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(at, s)| match s {
            Step::Parked(slot) => Some((at, *slot)),
            _ => None,
        })
        .expect("the open chain parked on its SECRET");
    let mut held: Vec<usize> = Vec::new();
    for s in &parked[start..at_park] {
        match s {
            Step::Taken(block) => held.push(*block),
            Step::Returned { block, .. } => held.retain(|b| b != block),
            _ => {}
        }
    }
    assert_eq!(
        held.len(),
        4,
        "req, both OutBufs and results are out of the pool while the chain is parked: {held:x?}"
    );
    assert!(
        registry.scrub_of(slot).is_some(),
        "the chain's slot is leased while it is parked"
    );
    SLOT.store(slot, Ordering::SeqCst);

    drop(boot);
    let full = fx::trace();
    assert!(
        registry.scrub_of(slot).is_none(),
        "the slot lease was released by the drop"
    );
    let after = |at: usize| full.iter().enumerate().skip(at);
    let dropped = after(at_park)
        .find(|(_, s)| **s == Step::Dropped("cancel-bufs".to_owned()))
        .map(|(at, _)| at)
        .expect("the cancel dropped the plugin's open future");
    let released = after(at_park)
        .find(|(_, s)| **s == Step::NeedsReleased(slot))
        .map(|(at, _)| at)
        .expect("the driver released the chain's Needs");
    assert!(
        dropped < released,
        "the plugin's future dropped inside the cancel, before the release that follows its return"
    );
    for block in &held {
        let returns: Vec<(usize, bool, bool)> = after(at_park)
            .filter_map(|(at, s)| match s {
                Step::Returned {
                    block: b,
                    zeroed,
                    leased,
                } if b == block => Some((at, *zeroed, *leased)),
                _ => None,
            })
            .collect();
        assert_eq!(
            returns.len(),
            1,
            "block {block:#x} came back exactly once: {returns:?}"
        );
        let (at, zeroed, leased) = returns[0];
        assert!(
            at > released,
            "block {block:#x} came back only after the cancel had returned"
        );
        assert!(
            !after(at_park)
                .take_while(|(i, _)| *i < at)
                .any(|(_, s)| *s == Step::Taken(*block)),
            "block {block:#x} was not taken again before it came back"
        );
        assert!(zeroed, "block {block:#x} came back zeroed");
        assert!(
            leased,
            "the slot lease was still held when block {block:#x} came back"
        );
    }
    cancelled_once("cancel-bufs");
    assert_eq!(
        fx::drop_threads("cancel-bufs"),
        vec![me],
        "cancelled inline"
    );
}
