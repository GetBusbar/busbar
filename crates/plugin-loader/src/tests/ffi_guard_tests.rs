// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual image finalizers witness the thread on which the library is released. A counter in the
//! caller of `on_plugin_thread` cannot distinguish routing from an inline `drop(lib)`.
//!
//! GNU/Linux has an explicit finalizer section in the existing dropped fixture. On macOS, dyld keeps
//! images with TLV descriptors resident even without a TLS access, so this Rust fixture cannot
//! witness dlclose finalization there. Other targets need their own native finalizer witness;
//! a process-handle counter is not equivalent. musl's dlclose does not unload images either.

#![cfg(all(target_os = "linux", target_env = "gnu"))]

use super::*;
use crate::dispatch_tests::UnloadWitness;

#[test]
fn dlclose_on_worker_runs_this_images_finalizer_on_a_permanent_worker() {
    let caller = std::thread::current().id();
    let (witness, lib) = UnloadWitness::new();
    assert!(witness.is_pending(), "an open image has not been finalized");
    dlclose_on_worker(lib);
    let unloaded = witness.finished();
    assert_ne!(unloaded.thread, caller);
    assert!(
        unloaded.permanent,
        "the actual finalizer runs on an FFI worker"
    );

    // Positive control for the observer: releasing a second, independent image directly reports
    // THIS thread. Replacing the routed drop above with this inline drop must fail its assertions.
    let (inline, lib) = UnloadWitness::new();
    drop(lib);
    let unloaded = inline.finished();
    assert_eq!(unloaded.thread, caller);
    assert!(!unloaded.permanent);
}
