// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TLS-KEY (ABI-MIN3-INTERFACE §14): TLS destructors on exiting workers: no SIGSEGV, no `dlclose` of a loaded
//! image, re-admit reuses the image.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: the resident-image rule is implemented (plugin-loader admit.rs:392 and :588, Image::Loaded never unloaded; stage.rs:76 dlclose_on_worker only for pre-admission refusals), but the arm needs (1) a cdylib fixture whose first thread_local with destructor runs inside describe, open, close, a sync method and an async chain resume (no [[example]] cdylib exists for MIN-3; the only ones, store_fixture and transport_fixture, are the old ABI) and (2) a counting shim over the loader's dl calls, which the loader does not expose (no seam in plugin-loader/src). Belongs in the plugin-loader crate's tests, not reachable from plugin-test without adding both; not a core-connector piece, W1-C1A (OUTSTANDING row 2 harness work)"]
fn tls_destructors_on_exiting_workers_and_no_dlclose() {
    todo!("owner: W1-C1A (C-TLS-KEY)")
}
