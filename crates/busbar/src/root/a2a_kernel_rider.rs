// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-ONLY A2A KERNEL-LOOP RIDER — the second WITNESS on the generic bridge, after MCP.
//!
//! This module onboards the A2A invoke plane onto the unified kernel loop the SAME way MCP did:
//! as a THIN VERBATIM RIDER over the plane-neutral bridge
//! [`crate::root::gauntlet_kernel::run_gauntlet_via_kernel`]. [`run_a2a_via_kernel`] drives the SAME
//! A2A `GauntletPlane` — the crate-private `A2aInvokePlane` in `busbar-a2a`'s `receive.rs`, whose
//! `drive` is the whole of `invoke_inner` UNCHANGED — through `busbar_kernel::teller::run_unit_async`
//! instead of `busbar_kernel::plane_host::run_gauntlet`. A2A's metering stays inside
//! `A2aInvokePlane::drive`/`invoke_inner` and settles exactly where 1.5.5 does (the one flat
//! per-call `Queries` charge, `receive.rs:723-740`); the kernel exit opens an empty `ZeroHold`,
//! reports `Evidence::default` and binds no book, so it settles NOTHING and cannot double-count.
//!
//! THIS MODULE IS TEST-ONLY; THE FLIP IT REHEARSES IS LIVE. The shipped A2A call site is still
//! `busbar_kernel::plane_host::run_gauntlet` at `crates/busbar-a2a/src/a2a/receive.rs`, but
//! `gauntlet_install::install()` registers the kernel-loop runner under A2A's capability key at
//! boot, so that call ALREADY dispatches through `run_gauntlet_via_kernel` in production (item
//! 125). The money stays where it was because the bridge opens a `ZeroHold` and reports no
//! evidence; this rider's shadow proof is what shows the two paths byte-identical.
//!
//! WHY `#[cfg(test)]`. The rider is a re-point of an existing call, not a new production surface:
//! production already reaches the kernel bridge through `run_gauntlet`'s registered runner, so a
//! second production entry would be a second name for the same path. Compiling the rider (and its
//! shadow proof) test-only keeps zero ship surface AND zero dead code.
//!
//! PLANE-NEUTRALITY. The bridge names no plane: `run_gauntlet_via_kernel`, `GauntletPlane`,
//! `PlaneAnswer` and `PlaneInFlight` carry no `a2a` noun. This module is the ONLY place the A2A
//! rider names A2A, and it does so only to point the neutral bridge at the A2A plane.

use axum::response::Response;
use busbar_kernel::plane_host::{GauntletPlane, GauntletRequest};

use crate::root::gauntlet_kernel::run_gauntlet_via_kernel;

/// Run one A2A invoke request through the UNIFIED kernel loop and return the plane's response
/// verbatim — the test-only direct call of the bridge the shipped `run_gauntlet` call in
/// `busbar-a2a/src/a2a/receive.rs` already dispatches to through its registered runner.
///
/// A one-line delegation to the plane-neutral bridge: the A2A plane rides it with ZERO new bridge
/// code, exactly as the module header promises. Calling it and calling
/// `busbar_kernel::plane_host::run_gauntlet(req, plane)` with A2A's runner registered reach the same
/// bridge, which is what the shadow proof compares.
pub(crate) async fn run_a2a_via_kernel(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Response {
    run_gauntlet_via_kernel(req, plane).await
}

#[cfg(test)]
#[path = "tests/a2a_kernel_rider.rs"]
mod tests;
