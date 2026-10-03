// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-contract's capability tests that have to MINT a token to run.
//!
//! Every token constructor (`Pass::mint`, `Grant::<C>::mint[_bound]`, `CallId::seal`,
//! `Origin::seal`, `SessionId::mint`, `IdempotencyKey::mint`, `UnitEnd::seal`) and the seal itself
//! (`KernelSeal::acquire_for_kernel`) are spelled only inside `crates/busbar-kernel/src`
//! (construction `token-sealed`, `token-sealed:kernel-seal`, `token-sealed:admit-token-mint`).
//! Their subject is the kernel's own capability behaviour, so they moved here, one file per source
//! file they came from; the contract's tests that need no token stayed in busbar-contract.

/// The runtime half of the proof (from `busbar-contract/src/caps/tests/mod.rs`).
mod the_runtime_half;

/// The renderings every one of these types hand-rolls, read back.
mod what_the_record_reads;

/// The posting's arithmetic at the edges.
mod the_posting_arithmetic;

/// Where a reported quantity came from, and the reports built on it.
mod what_the_usage_report_says;

/// A posting above its reservation carries the excess as its overdraft figure (item 318).
mod settle_carries_the_excess;

/// A sealed unit's bounded draft facts and leg replies (from
/// `busbar-contract/tests/bounded_limits.rs`).
mod bounded_limits;

/// Re-addressing a sealed destination down a transport stack (from
/// `busbar-contract/tests/destination_kinds.rs`).
mod destination_kinds;

/// The #74 zero-hot-path-cost witness. It reads this binary's counting `#[global_allocator]`, which
/// exists only off msvc.
#[cfg(not(target_env = "msvc"))]
mod capability_binding_zero_cost;
