// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CLOSE-PARKED (ABI-MIN3-INTERFACE §14): `close` with chains left parked in the slots: the plugin value drops
//! last (Miri in abi CI).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::atomic::Ordering;

use crate::bridge_fixture as fx;

/// Arm (a): a chain parks on a NEED holding a local whose `Drop` reads the plugin it borrows; the host's chain
/// handle is `mem::forget`-ten, so the chain is still in the slots at `close`. Closing drops the parked chain
/// while the plugin is alive, then the plugin. (Arm (b), an undecodable TOKEN, is the host driver's, W1-H1;
/// arm (c), an open session, needs a session kind and runs with `kind!`, W1-A4. busbar-ffi's own
/// `a_parked_chain_drops_before_its_plugin` runs the slot table's half under Miri.)
#[test]
fn close_with_parked_chains_drops_the_plugin_last() {
    let instance = fx::instance_with(b"park");
    let chain = fx::parked(&instance, b"park");
    core::mem::forget(chain);
    assert!(!fx::PARK_GONE.load(Ordering::SeqCst));
    drop(instance);
    assert!(fx::PARK_GONE.load(Ordering::SeqCst), "the plugin dropped");
    assert!(
        fx::PARK_SAW_ALIVE.load(Ordering::SeqCst),
        "the parked chain dropped first, with the plugin alive"
    );
}
