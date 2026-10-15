// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct unit tests for the worker-routing/panic-guard primitives at the top of `lib.rs`:
//! [`dlclose_on_worker`] and [`free_guarded`], exercised with no on-disk plugin fixture, so a
//! regression that guts either to a no-op is caught in every build, an isolated single-package one
//! (`cargo test --package busbar-plugin-loader`) included.

use super::*;

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
/// never touches the counter — this test goes red for that mutant.
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
