// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PANIC-HOST (ABI-MIN3-INTERFACE §14 rounds 20, 24). A panicking sink installed by `set_log_sink`, through
//! the real path with no injection, is W1-H0's (merged). The injection arms run inside real entries of a fixture
//! (the `conformance` feature lands with its first caller, the `HOST` entries) and need A2's `HOST` and H1's
//! guard, so they are W1-H1's, not H0's (W1-H0 handoff, design hole 1); the audit row and metric are the registry
//! watchdog's (W1-L2); the round-24 arm goes through the ports and `RefusalMap` (W1-K8D).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::atomic::Ordering::Relaxed;

use busbar_plugin_abi::host::level;
use busbar_plugin_abi::host_side::host_vt::{set_log_sink, vt, HOST_FAULTS};

/// `HOST_FAULTS[HOST_PANIC]` (§10.7).
const HOST_PANIC: usize = 1;

fn panicking_sink(slot: Option<u32>, level: u32, error: u32, msg: &str) {
    panic!("C-PANIC-HOST: the sink panics on {slot:?} {level} {error} {msg}");
}

#[test]
fn a_panicking_log_sink_is_contained_and_counted_once() {
    set_log_sink(panicking_sink);
    let before = HOST_FAULTS[HOST_PANIC].load(Relaxed);
    vt::log(level::WARN, 0, "contained");
    assert_eq!(HOST_FAULTS[HOST_PANIC].load(Relaxed), before + 1);
}

#[test]
#[ignore = "blocked: needs the busbar-plugin-abi `conformance` injection feature (host_vt injection::fire) driven from inside a real fixture entry, and a spawned SIGABRT control process; no such fixture or dev-edge feature here (W1-H1)"]
fn every_host_fn_panicking_inside_a_real_entry_answers_its_fallback() {
    todo!("owner: W1-H1 (C-PANIC-HOST)")
}

#[test]
#[ignore = "blocked: needs the busbar-plugin-abi `conformance` injection feature (host_vt injection::fire) driven from inside a real fixture entry, and a spawned SIGABRT control process; no such fixture or dev-edge feature here (W1-H1)"]
fn the_uncontained_control_dies_with_sigabrt() {
    todo!("owner: W1-H1 (C-PANIC-HOST)")
}

#[test]
#[ignore = "blocked: the host_callback_panic audit row and metric are the registry watchdog (W1-L2), absent from this crate's reachable surface"]
fn one_host_callback_panic_row_and_metric_within_a_tick() {
    todo!("owner: W1-L2 (C-PANIC-HOST)")
}

#[test]
#[ignore = "owner: W1-K8D; blocked (re-checked on dev 2026-11-16): needs an auth fixture's verify through the MIN-3 auth port (plugin-loader adapters/auth.rs chain_req is todo!(), OUTSTANDING row 1) with busbar-plugin-abi's conformance crypto injection armed (no such dev edge here), and a store fixture through the store adapter (adapters/store.rs request todo!()); RefusalMap::from_port's 502 then runs beside the kernel's refusal map"]
fn a_crypto_panic_reaches_the_port_as_failed_unavailable() {
    todo!("owner: W1-K8D (C-PANIC-HOST)")
}
