// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT INSTALL for the host-selection seam (loop unification, DECISIONS #28).
//!
//! The kernel-loop runners ([`run_gauntlet_via_kernel`] / [`open_gauntlet_via_kernel`]) live here in
//! the root (the only tier that sees both `busbar-kernel` and the plane engines). This module injects
//! them into the neutral per-capability-keyed registry in `busbar_kernel::plane_host` as
//! fn-pointers, mirroring `busbar_admin::install()`.
//!
//! LIVE, NOT DORMANT: [`install`] is called unconditionally at boot and FLIPS ALL FOUR planes (mcp,
//! a2a, llm-native, voice — each behind the default-on feature that pulls its crate), so every
//! `run_gauntlet[_session]` call for those planes dispatches into the kernel loop through this
//! registry. The substrate loop it replaced no longer exists; an unflipped plane runs
//! `run_gauntlet`'s inline verify-then-`drive` fallback.
//!
//! MONEY-NEUTRAL BY CONSTRUCTION, and MEASURED (item 125, 2026-09-24, pin 079a16efc): the
//! kernel-loop runner opens a ZERO hold and reports zero evidence (see `gauntlet_kernel.rs`), so
//! the plane's own metering inside `drive` stays the only money path. A build with the four flips
//! commented out recorded the two diverging C3 money cells
//! (`billing|key-usage|after-upstream-down`, `billing|rate-card|history-mid-window`) byte-identical
//! to the flipped build. The per-plane money authority for LLM is the separate `root-llm` feature,
//! not this seam.

use std::future::Future;
use std::pin::Pin;

use axum::response::Response;
use busbar_kernel::plane_host::{
    register_gauntlet_runner, register_session_runner, GauntletPlane, GauntletRequest,
};

use crate::root::gauntlet_kernel::{open_gauntlet_via_kernel, run_gauntlet_via_kernel};

/// The kernel-loop one-shot runner as a `busbar_kernel::plane_host::GauntletRunner` fn-pointer:
/// the async runner boxed into the erased future the neutral seam holds.
fn kernel_one_shot<'a>(
    req: GauntletRequest<'a>,
    plane: Box<dyn GauntletPlane + 'a>,
) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
    Box::pin(run_gauntlet_via_kernel(req, plane))
}

/// FLIP a one-shot plane (mcp, a2a, llm-native) onto the unified kernel loop, by capability key.
/// The per-plane cutover — call from [`install`] for that plane, gated on the fleet-box oracle (#29).
/// Until called for a key, that plane rides the substrate loop, byte-identical.
pub fn flip_one_shot_to_kernel(capability_key: &'static str) {
    register_gauntlet_runner(capability_key, kernel_one_shot);
}

/// FLIP a session plane (voice, duplex) onto the unified kernel loop's session admit, by capability
/// key. The per-plane cutover — call from [`install`] for that plane, gated on the fleet-box oracle.
pub fn flip_session_to_kernel(capability_key: &'static str) {
    register_session_runner(capability_key, open_gauntlet_via_kernel);
}

/// Install the kernel-backed runners into the host-selection seam. Called once by `main.rs` at boot,
/// AFTER the planes are registered (mirror of `busbar_admin::install()`).
///
/// W2.b — EVERY plane is FLIPPED onto the unified kernel loop (DECISIONS #28/#29). Each plane reports
/// its capability key and this registers the kernel-loop runner under it, so the SHIPPED serving path
/// for all four flows through `busbar_kernel::teller::run_unit[_async]` / `open_unit` — proven
/// byte-identical (the shadow-compare rider tests + the fleet-box oracle, #29). With every plane
/// flipped, the redundant substrate teller loop was DELETED: an unregistered plane now fails closed
/// in `run_gauntlet[_session]` rather than riding a second loop.
///
/// - MCP (W2.a) + A2A + LLM native are ONE-SHOT planes → [`flip_one_shot_to_kernel`].
/// - Voice/streaming is a SESSION plane (open-pass admit, no one-shot `drive`) → [`flip_session_to_kernel`].
///
/// Each flip is gated on the SAME `cfg` feature that pulls its plane crate, so a build that omits a
/// plane also omits its flip (and that plane's `GauntletPlane` never runs).
pub fn install() {
    #[cfg(feature = "plane-mcp")]
    flip_one_shot_to_kernel(busbar_mcp::PLANE_KEY);
    #[cfg(feature = "plane-a2a")]
    flip_one_shot_to_kernel(busbar_a2a::PLANE_KEY);
    // Routed through `PLANE_DECL.key` rather than a fresh `busbar_llm::PLANE_KEY` reach: `main.rs`
    // already names `busbar_llm::PLANE_DECL` to install the plane, and its `key` field IS the same
    // capability key (see `busbar_llm::PLANE_DECL`'s definition) — so this reads the seam the plane
    // already exposes instead of naming a second distinct `busbar_llm::` symbol.
    #[cfg(feature = "proto-llm")]
    flip_one_shot_to_kernel(busbar_llm::PLANE_DECL.key);
    #[cfg(feature = "plane-voice")]
    flip_session_to_kernel(busbar_voice::PLANE_KEY);
}
