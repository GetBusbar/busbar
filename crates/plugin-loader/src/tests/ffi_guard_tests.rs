// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct unit tests for the worker-routing/panic-guard primitives at the top of `lib.rs`:
//! [`dlclose_on_worker`] and [`free_guarded`]. `validate_plugin_unloads_on_a_worker_not_the_callers_thread`
//! (in `lib_tests.rs`) already pins the end-to-end unload path, but it SKIPS whenever the in-tree
//! example store plugin cdylib isn't sitting next to the test binary — which is exactly the case
//! under an isolated single-package build (`cargo test --package busbar-plugin-loader`) — so under
//! that build, gutting `dlclose_on_worker` or `free_guarded` to a no-op changes nothing that test
//! observes. These cases exercise both functions directly, with no on-disk plugin fixture, so they
//! run, and hold, under every build of this crate.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A `Library` handle that needs no file on disk: `libloading`'s "this process" handle. `dlclose`ing
/// it is safe (it does not unmap the running program) and exercises exactly the same code path
/// [`dlclose_on_worker`] takes for a real plugin, without depending on any example-plugin cdylib
/// being built alongside this test binary.
#[cfg(unix)]
fn a_library_handle_to_this_process() -> Library {
    Library::from(libloading::os::unix::Library::this())
}

#[cfg(windows)]
fn a_library_handle_to_this_process() -> Library {
    Library::from(
        libloading::os::windows::Library::this()
            .expect("a handle to the running process's own module is always obtainable"),
    )
}

/// [`dlclose_on_worker`] must actually route the drop through [`ffi_thread::on_plugin_thread`] (that
/// is the whole point of the function — see its doc comment), which this crate makes observable via
/// the test-only [`UNLOADS_ON_WORKER`] counter. A mutant that replaces the function body with `()`
/// still compiles (the `Library` parameter is simply dropped, inline, on the caller's thread) but
/// never touches the counter — this test is what would go red for that mutant that the on-disk-cdylib
/// end-to-end test cannot see under an isolated single-package build.
#[test]
fn dlclose_on_worker_routes_the_unload_and_counts_it() {
    let before = UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    dlclose_on_worker(a_library_handle_to_this_process());
    let after = UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    assert_eq!(
        after,
        before + 1,
        "dlclose_on_worker must record exactly one routed unload on this thread"
    );
}

/// What [`free_guarded`]'s stub `busbar_free` saw, and how many times.
static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
static FREE_SAW: std::sync::Mutex<(usize, usize)> = std::sync::Mutex::new((0, 0));

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

unsafe extern "C-unwind" fn record_free(ptr: *mut u8, len: usize) {
    FREE_CALLS.fetch_add(1, Ordering::SeqCst);
    *FREE_SAW.lock().unwrap_or_else(|p| p.into_inner()) = (ptr as usize, len);
}

unsafe extern "C-unwind" fn panicking_free(_ptr: *mut u8, _len: usize) {
    FREE_CALLS.fetch_add(1, Ordering::SeqCst);
    panic!("a plugin busbar_free went wrong");
}

/// `free_guarded` on a non-null pointer must call the plugin's `free` fn with exactly the `(ptr,
/// len)` it was given. A mutant that replaces the body with `()` calls nothing at all.
#[test]
fn free_guarded_calls_the_plugin_free_fn_with_the_given_pointer_and_length() {
    let _serial = serial_guard();
    FREE_CALLS.store(0, Ordering::SeqCst);
    let mut byte = 5u8;
    let ptr = &mut byte as *mut u8;
    free_guarded(record_free, "acme-store-plugin", ptr, 3);
    assert_eq!(
        FREE_CALLS.load(Ordering::SeqCst),
        1,
        "free_guarded must call the plugin's free fn exactly once"
    );
    let (seen_ptr, seen_len) = *FREE_SAW.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        seen_ptr, ptr as usize,
        "free_guarded must pass through the exact pointer it was given"
    );
    assert_eq!(
        seen_len, 3,
        "free_guarded must pass through the exact length it was given"
    );
}

/// A null pointer means there is nothing to free — `free_guarded` must not call the plugin at all
/// (calling `free` on a buffer the plugin never allocated is its own bug).
#[test]
fn free_guarded_on_a_null_pointer_calls_nothing() {
    let _serial = serial_guard();
    FREE_CALLS.store(0, Ordering::SeqCst);
    free_guarded(record_free, "acme-store-plugin", std::ptr::null_mut(), 0);
    assert_eq!(
        FREE_CALLS.load(Ordering::SeqCst),
        0,
        "free_guarded must not call free on a null pointer"
    );
}

/// A plugin `free` that panics must not take this thread down with it — `free_guarded` swallows the
/// panic (the buffer leaks; that is strictly better than aborting the gateway).
#[test]
fn free_guarded_swallows_a_panicking_free_fn() {
    let _serial = serial_guard();
    FREE_CALLS.store(0, Ordering::SeqCst);
    let mut byte = 9u8;
    let ptr = &mut byte as *mut u8;
    // Must not panic/abort this test thread.
    free_guarded(panicking_free, "acme-store-plugin", ptr, 1);
    assert_eq!(
        FREE_CALLS.load(Ordering::SeqCst),
        1,
        "the panicking free fn must still have been attempted"
    );
}
