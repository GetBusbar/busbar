// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL HOST SEAM — the trait a plane calls to reach the engine's host capabilities WITHOUT
//! naming a core type, and the lifecycle [`scope`] arena those capabilities register handles into.
//!
//! ## Why a trait object, not a `HostCtx`
//!
//! The HOT-lane ABI ([`busbar_plugin::hot`]) threads an opaque `HostCtx` (a `*mut c_void` aliasing a
//! stack `HostState` that borrows the live engine) through every host call. That pointer is `!Send`
//! and valid ONLY inside the synchronous frame that minted it — it MUST NOT be stored on a context
//! struct that crosses an `.await`. So the neutral seam a plane holds across async work CANNOT be "a
//! `HostCtx` on a ctx struct".
//!
//! [`EngineHost`] is that seam instead: an `Arc<dyn EngineHost>` a plane holds and calls typed, safe
//! methods on. Core implements it over its live `App`; each method mints the transient `HostCtx`
//! INTERNALLY, drives the relevant vtable slot SYNCHRONOUSLY, and returns an owned value — the raw
//! host pointer never escapes the call, so the trait object is freely `Send + Sync` and safe to carry
//! across `.await`. A core reach thereby becomes a Rust trait method with ZERO C-ABI impact.
//!
//! This seam begins with the CLOCK reaches; later stages append one method per remaining host reach
//! (gate-decide, govern-admit, breaker-admit, identity-admit, approval-redeem, …).

pub mod scope;

/// The neutral HOST seam a plane calls to reach the engine's host-owned capabilities.
///
/// A plane holds an `Arc<dyn EngineHost>` (minted core-side over the live engine) and calls these
/// typed methods rather than naming `busbar_core::plane_host::*_over(&App, …)`. Each method reaches
/// the SAME host vtable slot the in-core veneer drives, so the value is identical — this is a
/// same-dispatch relocation of the reach, not a new behaviour.
///
/// `Send + Sync` because a plane carries the handle across `.await` and between threads (e.g. into a
/// `spawn_blocking` breaker leg). That is sound precisely because no method exposes the `!Send`
/// `HostCtx`: each mints it internally, uses it synchronously, and drops it before returning.
pub trait EngineHost: Send + Sync {
    /// Read the host wall clock in whole SECONDS through the `clock_now` seam — the host-driven form
    /// of a plane's in-place seconds clock. Identical to `busbar_core::plane_host::clock_now_secs_over`.
    fn clock_now_secs(&self) -> u64;

    /// Read the host wall clock in MILLISECONDS through the `clock_now` seam — the host-driven form of
    /// a plane's in-place millis clock. Identical to `busbar_core::plane_host::clock_now_ms_over`.
    fn clock_now_ms(&self) -> u64;
}
