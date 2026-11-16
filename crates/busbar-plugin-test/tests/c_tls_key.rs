// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TLS-KEY (ABI-MIN3-INTERFACE §14): TLS destructors on exiting workers: no SIGSEGV, no `dlclose` of a loaded
//! image, re-admit reuses the image.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A (blocked: needs a cdylib fixture arming a plugin TLS key on workers and a dlclose probe through the loader; no such fixture)"]
fn tls_destructors_on_exiting_workers_and_no_dlclose() {
    todo!("owner: W1-C1A (C-TLS-KEY)")
}
