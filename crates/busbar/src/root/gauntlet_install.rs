// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT INSTALL for the host-selection seam (loop unification, DECISIONS #28).
//!
//! The kernel-loop runners ([`run_gauntlet_via_kernel`] / [`open_gauntlet_via_kernel`]) live here in
//! the root (the only tier that sees both `busbar-kernel` and the plane engines). This module injects
//! them into the neutral per-capability-keyed registry in `busbar_substrate::plane_host` as
//! fn-pointers, mirroring `busbar_admin::install()`.
//!
//! DORMANT: [`install`] registers ZERO planes, so every gauntlet/session path stays on the substrate
//! loop, byte-identical to the shipped release. The per-plane FLIP onto the unified kernel loop is one
//! line — [`flip_one_shot_to_kernel`] or [`flip_session_to_kernel`] for that plane's capability key —
//! and each is gated on the fleet-box money oracle (#29).

use std::future::Future;
use std::pin::Pin;

use axum::response::Response;
use busbar_substrate::plane_host::{
    register_gauntlet_runner, register_session_runner, GauntletPlane, GauntletRequest,
};

use crate::root::gauntlet_kernel::{open_gauntlet_via_kernel, run_gauntlet_via_kernel};

/// The kernel-loop one-shot runner as a `busbar_substrate::plane_host::GauntletRunner` fn-pointer:
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
    #[cfg(feature = "proto-llm")]
    flip_one_shot_to_kernel(busbar_llm::PLANE_KEY);
    #[cfg(feature = "plane-voice")]
    flip_session_to_kernel(busbar_voice::PLANE_KEY);
}
