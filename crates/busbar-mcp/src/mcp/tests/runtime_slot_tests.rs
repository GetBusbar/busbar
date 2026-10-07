// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S RUNTIME SLOT HOLDS THE PLANE'S OWN RUNTIME, on every App, whenever it was built.
//!
//! The slot under `runtime_slot_key(<this plane's key>)` is this plane's state (BUSBAR-1.6.0.md §6),
//! and [`crate::mcp::runtime_of`] downcasts it with an `.expect`. App composition also keys the
//! FALLBACK plane's runtime, and it once derived that key and that runtime from two separate reads of
//! the plane registry. This test binary's registry grows while tests run (a test that links the
//! fallback plane registers it mid-suite), so an App built across that registration read "no fallback"
//! for the key — which then degraded to this plane's key — and "fallback" for the runtime, and the
//! fallback plane's runtime replaced this plane's under this plane's key. Any test then dying in
//! `runtime_of` was the symptom (merge-group run 37567965022, `roots_changed_tests`).
//!
//! The case below keeps several threads building Apps and registers the linked fallback plane while
//! they are mid-stream. It can fail only when composition keys one plane's runtime under another's.
//! It is a race probe: it exercises the window only in a process where the fallback plane was not
//! registered yet (run it alone to be sure), so a pass on one run says little, but it is the shape
//! that reproduced the defect before the fix.

use crate::mcp::connect::connect_support::mcp_cfg;
use crate::mcp::test_engine::*;
use crate::mcp::upstream::sampling_satisfy_tests::install_linked_planes;
use crate::testkit::TestAppMcpExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Threads building Apps while the fallback plane registers.
const BUILDERS: usize = 8;
/// Apps each builder builds; the registration lands once the builders are under way.
const BUILDS: usize = 32;

#[test]
fn an_app_built_while_a_fallback_plane_registers_keeps_this_planes_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime for the builders");
    // One App first, so this plane is registered BEFORE the fallback plane — the order the defect
    // needed (with the fallback plane first, `fallback_key()` never degraded to this plane's key).
    {
        let _entered = rt.enter();
        let app = test_app().mcp(&mcp_cfg()).build();
        let _ = crate::mcp::runtime_of(&engine_host(&app));
    }
    let built = Arc::new(AtomicUsize::new(0));
    let builders: Vec<_> = (0..BUILDERS)
        .map(|_| {
            let built = Arc::clone(&built);
            let runtime = rt.handle().clone();
            std::thread::spawn(move || {
                let _entered = runtime.enter();
                for _ in 0..BUILDS {
                    let app = test_app().mcp(&mcp_cfg()).build();
                    // The production accessor: panics if the slot holds anything but this plane's
                    // runtime.
                    let _ = crate::mcp::runtime_of(&engine_host(&app));
                    built.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    // Register while every builder is mid-stream, at whatever point of a build it happens to be.
    while built.load(Ordering::SeqCst) < BUILDERS {
        std::thread::yield_now();
    }
    // The test-linked planes (`[package.metadata.busbar] test-linked`) — the fallback plane among
    // them, linked as DATA so this source names no other plane.
    install_linked_planes();
    for builder in builders {
        builder
            .join()
            .expect("every App built across the registration carries this plane's own runtime");
    }
}
