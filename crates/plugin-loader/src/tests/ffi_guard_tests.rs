// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

    let (inline, lib) = UnloadWitness::new();
    drop(lib);
    let unloaded = inline.finished();
    assert_eq!(unloaded.thread, caller);
    assert!(!unloaded.permanent);
}
