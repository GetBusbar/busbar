// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-RMW (ABI-MIN3-INTERFACE §14): The counting configuration of `slots.rs`/`bridge.rs`/`scrub.rs` (rounds 8-17).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The slot-table share of the W1-A3 arm runs in busbar-ffi, where `slots.rs` lives: its atomics sit behind a
//! counting wrapper in that crate's test build only (`slots::counting`; a release build keeps the std atomics),
//! and the shims are driven through a plane and a transport fixture image there (GetBusbar/busbar#265):
//!
//! - `busbar_ffi::host::tests::session_methods_make_no_slot_rmw_and_open_and_end_one_cas_each`
//!   (crates/busbar-ffi/src/host.rs): 0 slot RMWs per plane `piece` and transport `ingest`/`emit`/`timer`;
//!   one free-list CAS per opener (`request`, `probe`, `begin`) and one per end (`end`, or the handle's drop).
//! - `busbar_ffi::host::tests::a_chain_makes_one_slot_cas_on_its_first_need_and_one_at_its_end` (round 10): 0
//!   chain-slot RMWs per never-NEED chain; exactly 1 insert CAS (first NEED) and 1 remove CAS (end or cancel)
//!   per chain that NEEDs, with 0 per resume lookup, for 1 and 4 NEEDs.
//! - `busbar_ffi::slots::tests::an_insert_and_a_remove_make_one_rmw_each_and_a_miss_none`: the table alone.
//!
//! The arm below stays ignored for what that share does not count (see its reason).

#[test]
#[ignore = "owner: W1-A3 (re-checked 2026-11-16; slot share runs in busbar-ffi, see the module doc, GetBusbar/busbar#265). Left: the opener's and end's second RMW, the session handle's Arc<Instance> increment and decrement (busbar-ffi src/host.rs `Session::inst`, a std Arc taken in `Instance::opened`), is under no counting configuration (busbar-ffi pins it only as strong_count +1/-1), and the machinery above busbar-ffi (busbar-plugin-abi src/kinds/plane.rs and kinds/transport.rs, the plugin-loader adapters) has no RMW counter for the 0 per piece/ingest/emit/timer/resume and exactly 2 per opener and end"]
fn zero_rmw_per_piece_ingest_and_resume_two_per_opener_and_end() {
    todo!("owner: W1-A3 (C-RMW)")
}

#[test]
#[ignore = "owner: W1-H1 (re-checked 2026-11-16: no counting configuration over the pool queues' CAS, busbar-plugin-abi src/host_side/pool.rs, nor over the Arc<Instance>/Arc<Image>/Arc<str> increments and decrements on the chain path; blocked also on the counting allocator, W1-U1, and the EC2 B-CHAIN run)"]
fn zero_refcount_and_four_pool_cas_per_never_need_chain() {
    todo!("owner: W1-H1 (C-RMW)")
}

#[test]
#[ignore = "owner: W1-H1 (re-checked 2026-11-16: no counting configuration over Scrub's snapshot read, the ArcSwap::load in busbar-plugin-abi src/host_side/scrub.rs, nor over the watchdog word after a thread's claim; blocked also on the counting allocator, W1-U1, and the EC2 bench)"]
fn two_rmw_per_scrubbed_text_and_none_per_clean_sync_answer() {
    todo!("owner: W1-H1 (C-RMW)")
}
