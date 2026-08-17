// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the permanent plugin-FFI worker pool.
//!
//! These pin the INVARIANT ("plugin code never runs on a caller's thread, and a thread that ran it
//! never exits") rather than the absence of a crash. The crash is a race — a green run of the real
//! thing proves nothing about it, which is exactly how this defect stayed open through 25 clean
//! reproduction attempts — so what is asserted here is the mechanical property that makes the race
//! unwinnable.

use super::on_plugin_thread;

/// SERIALISES THE TESTS THAT ASSERT WORKER *IDENTITY*, and it is not belt-and-braces.
///
/// `libtest` runs the tests in this file on parallel threads against ONE shared pool. Two of them
/// below assert that a specific worker is handed the next job, which is only true if no sibling
/// takes that idle worker in between. Nothing in the pool promises otherwise: handing an idle
/// worker to whoever asks first is the correct behaviour, so the flake was in the assertion, not
/// in the code under test.
///
/// Measured before this lock: `a_worker_is_reused_across_sequential_calls` failed roughly one run
/// in three under `cargo test -p busbar-plugin-loader --lib`, and passed 5 times out of 5 when run
/// alone. That is the signature of a test that needs exclusivity, and the reason it must be stated
/// here is that the obvious "fix" is to weaken the assertion to "some worker ran it", which would
/// delete the only check that the pool reuses threads at all.
///
/// The lock is deliberately NOT taken by `work_never_runs_on_the_callers_thread` or
/// `workers_are_named_for_what_they_are`: those hold under any scheduling, and serialising them
/// would hide a regression that only appears under contention.
static IDENTITY: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Poisoning is irrelevant here: the guard protects scheduling, not data, so a panicking sibling
/// leaves nothing inconsistent behind.
fn identity_lock() -> std::sync::MutexGuard<'static, ()> {
    IDENTITY.lock().unwrap_or_else(|p| p.into_inner())
}

/// The load-bearing one: work handed to this module runs on a DIFFERENT thread from the caller's.
///
/// If this regresses — if `on_plugin_thread` ever runs `f` inline as a "fast path" — then a libtest
/// worker, a Tokio blocking thread, or any caller that later retires picks up the plugin's
/// `pthread_key` TLS value again, and `__nptl_deallocate_tsd` calls a destructor inside an unmapped
/// image when that thread exits. The whole fix is this one fact.
#[test]
fn work_never_runs_on_the_callers_thread() {
    let caller = std::thread::current().id();
    let ran_on = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
    assert_ne!(
        ran_on, caller,
        "plugin code ran on the CALLER's thread. That thread now carries the plugin's TLS \
         destructor, and it will call into an unmapped image when it exits."
    );
}

/// The worker threads are the ones this module named, so a crash backtrace or a thread dump says
/// plainly whose threads these are.
#[test]
fn workers_are_named_for_what_they_are() {
    let name =
        on_plugin_thread(|| std::thread::current().name().map(str::to_string)).expect("no panic");
    assert_eq!(name.as_deref(), Some("busbar-plugin-ffi"));
}

/// A worker is REUSED rather than spawned per call — and, more importantly, the same thread can be
/// handed work again after it has already run some, which is what "never retires" buys.
#[test]
fn a_worker_is_reused_across_sequential_calls() {
    let _serial = identity_lock();
    let first = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
    let second = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
    assert_eq!(
        first, second,
        "a sequential second call should land on the idle worker the first one released"
    );
}

/// A panic in plugin code comes back as `Err` and does NOT kill the worker: the thread that ran it
/// must survive, because it is carrying that plugin's TLS. A worker that died on a panicking plugin
/// would reintroduce the exact crash on the panic path.
#[test]
fn a_panicking_job_is_caught_and_the_worker_survives() {
    let _serial = identity_lock();
    let before = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
    let err = on_plugin_thread(|| panic!("plugin blew up"));
    assert!(
        err.is_err(),
        "a panicking job must surface as Err, not unwind into the caller"
    );
    let after = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
    assert_eq!(
        before, after,
        "the worker that ran the panicking job must still be alive and reusable — if it exited, it \
         took a live plugin TLS destructor with it"
    );
}

/// Re-entrancy must not deadlock: plugin code that calls back through the loader takes a FRESH
/// worker rather than waiting on the one its own caller is occupying. A fixed-size pool would hang
/// here, and a hung gateway is not an improvement on a crashing one.
#[test]
fn a_nested_call_takes_a_second_worker_and_does_not_deadlock() {
    let (outer, inner) = on_plugin_thread(|| {
        let outer = std::thread::current().id();
        let inner = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
        (outer, inner)
    })
    .expect("no panic");
    assert_ne!(
        outer, inner,
        "a nested call must run on its own worker, not block on the busy one"
    );
}

/// Values move both ways across the rendezvous, including `!Send` ones — the soundness argument is
/// the caller blocking for the whole window, not the types.
#[test]
fn non_send_values_cross_the_rendezvous_in_both_directions() {
    let borrowed = String::from("borrowed by the closure, never moved");
    let ptr: *const u8 = borrowed.as_ptr();
    let expected_len = borrowed.len();
    let out = on_plugin_thread(move || {
        // A raw pointer is `!Send`; this is the shape every real ABI closure has.
        (ptr, borrowed.len())
    })
    .expect("no panic");
    assert_eq!(out.0, ptr);
    assert_eq!(out.1, expected_len);
}

/// Concurrent callers are served in parallel rather than serialized behind one worker — the pool
/// grows on demand, so making plugin calls thread-confined does not make them single-threaded.
#[test]
fn concurrent_callers_get_distinct_workers() {
    use std::sync::{Arc, Barrier};
    let n = 4;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let b = barrier.clone();
            std::thread::spawn(move || {
                on_plugin_thread(move || {
                    // Hold the worker until every sibling also holds one; with a pool that could not
                    // grow past a single worker this rendezvous would never complete.
                    b.wait();
                    std::thread::current().id()
                })
                .expect("no panic")
            })
        })
        .collect();
    let ids: std::collections::HashSet<_> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    assert_eq!(
        ids.len(),
        n,
        "each concurrent caller must get its own worker, not queue behind a shared one"
    );
}
