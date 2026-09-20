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
/// DORMANT by design: it registers NOTHING, so the seam stays UNSET and every plane rides the
/// substrate loop exactly as today. Each per-plane flip is one line added here — e.g.
/// `flip_one_shot_to_kernel("mcp");` or `flip_session_to_kernel("streaming");` — landed only once that
/// plane's money family is proven byte-green on the fleet-box oracle (#29).
pub fn install() {
    // Intentionally empty: zero planes flipped. The five onboards become oracle-gated one-liners here.
}
