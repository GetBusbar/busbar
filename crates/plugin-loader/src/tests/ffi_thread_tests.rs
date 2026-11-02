// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Mutex;

use super::{on_plugin_thread, on_plugin_thread_in, Pool};

static IDENTITY: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn identity_lock() -> std::sync::MutexGuard<'static, ()> {
    IDENTITY.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn work_never_runs_on_the_callers_thread() {
    let _serial = identity_lock();
    let caller = std::thread::current().id();
    let ran_on = on_plugin_thread(|| std::thread::current().id()).expect("no panic");
    assert_ne!(
        ran_on, caller,
        "plugin code ran on the CALLER's thread. That thread now carries the plugin's TLS \
         destructor, and it will call into an unmapped image when it exits."
    );
}

#[test]
fn workers_are_named_for_what_they_are() {
    let _serial = identity_lock();
    let name =
        on_plugin_thread(|| std::thread::current().name().map(str::to_string)).expect("no panic");
    assert_eq!(name.as_deref(), Some("busbar-plugin-ffi"));
}

#[test]
fn a_worker_is_reused_across_sequential_calls() {
    static OWN: Mutex<Pool> = Mutex::new(Pool::empty());
    let _serial = identity_lock();
    let first = on_plugin_thread_in(&OWN, || std::thread::current().id()).expect("no panic");
    let second = on_plugin_thread_in(&OWN, || std::thread::current().id()).expect("no panic");
    assert_eq!(
        first, second,
        "a sequential second call should land on the idle worker the first one released"
    );
}

#[test]
fn a_panicking_job_is_caught_and_the_worker_survives() {
    static OWN: Mutex<Pool> = Mutex::new(Pool::empty());
    let _serial = identity_lock();
    let before = on_plugin_thread_in(&OWN, || std::thread::current().id()).expect("no panic");
    let err = on_plugin_thread_in(&OWN, || panic!("plugin blew up"));
    assert!(
        err.is_err(),
        "a panicking job must surface as Err, not unwind into the caller"
    );
    let after = on_plugin_thread_in(&OWN, || std::thread::current().id()).expect("no panic");
    assert_eq!(
        before, after,
        "the worker that ran the panicking job must still be alive and reusable — if it exited, it \
         took a live plugin TLS destructor with it"
    );
}

#[test]
fn a_nested_call_takes_a_second_worker_and_does_not_deadlock() {
    let _serial = identity_lock();
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

#[test]
fn non_send_values_cross_the_rendezvous_in_both_directions() {
    let _serial = identity_lock();
    let borrowed = String::from("borrowed by the closure, never moved");
    let ptr: *const u8 = borrowed.as_ptr();
    let expected_len = borrowed.len();
    let out = on_plugin_thread(move || (ptr, borrowed.len())).expect("no panic");
    assert_eq!(out.0, ptr);
    assert_eq!(out.1, expected_len);
}

#[test]
fn concurrent_callers_get_distinct_workers() {
    let _serial = identity_lock();
    use std::sync::{Arc, Barrier};
    let n = 4;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let b = barrier.clone();
            std::thread::spawn(move || {
                on_plugin_thread(move || {
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
