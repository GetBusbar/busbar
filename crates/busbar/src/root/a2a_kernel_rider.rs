// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DORMANT A2A KERNEL-LOOP RIDER — the second WITNESS on the generic bridge, after MCP.
//!
//! This module onboards the A2A invoke plane onto the unified kernel loop the SAME way MCP did
//! (DECISIONS #28): as a THIN VERBATIM RIDER over the plane-neutral bridge
//! [`crate::root::gauntlet_kernel::run_gauntlet_via_kernel`]. [`run_a2a_via_kernel`] drives the SAME
//! A2A `GauntletPlane` — the crate-private `A2aInvokePlane` in `busbar-a2a`'s `receive.rs`, whose
//! `drive` is the whole of `invoke_inner` UNCHANGED — through `busbar_kernel::teller::run_unit_async`
//! instead of `busbar_substrate::plane_host::run_gauntlet`. A2A's metering stays inside
//! `A2aInvokePlane::drive`/`invoke_inner` and settles exactly where 1.5.5 does (the one flat
//! per-call `Queries` charge, `receive.rs:723-740`); the kernel exit opens an empty `ZeroHold`,
//! reports `Evidence::default` and binds no book, so it settles NOTHING and cannot double-count.
//!
//! DORMANT — DUAL-PATH, MONEY AUTHORITY NOT FLIPPED. The shipped A2A authority stays
//! `busbar_substrate::plane_host::run_gauntlet` at `crates/busbar-a2a/src/a2a/receive.rs:892`. This
//! rider is built and shadow-proven byte-identical here, but the one-line flip (re-point that call
//! to `run_a2a_via_kernel`) waits on the fleet-box money oracle (DECISIONS #29): `bin/oracle
//! record`+`replay` run DIRECTLY on a fleet box (docker present), scoped to the money families, vs
//! the 1.5.5 golden — NOT through `prove-remote.sh` (that wrapper is circular until core-deletion
//! lands). Per DECISIONS #29 the cutover is dual-write-then-flip-authority, not from-scratch byte
//! reproduction, because the loop==legacy switch-over golden is already green.
//!
//! WHY `#[cfg(test)]`. The rider is a re-point of an existing call, not a new production surface: the
//! only production entry to the kernel bridge stays the shipped substrate gauntlet until the flip.
//! Compiling the rider (and its shadow proof) test-only keeps zero ship surface AND zero dead-code
//! while the authority is dormant — the module is the flip's rehearsal, held one line away.
//!
//! PLANE-NEUTRALITY. The bridge names no plane: `run_gauntlet_via_kernel`, `GauntletPlane`,
//! `PlaneAnswer` and `PlaneInFlight` carry no `a2a` noun. This module is the ONLY place the A2A
//! rider names A2A, and it does so only to point the neutral bridge at the A2A plane.

use axum::response::Response;
use busbar_substrate::plane_host::{GauntletPlane, GauntletRequest};

use crate::root::gauntlet_kernel::run_gauntlet_via_kernel;

/// Run one A2A invoke request through the UNIFIED kernel loop and return the plane's response
/// verbatim — the dormant kernel-loop twin of the shipped `run_gauntlet` call at
/// `busbar-a2a/src/a2a/receive.rs:892`.
///
/// A one-line delegation to the plane-neutral bridge: the A2A plane rides it with ZERO new bridge
/// code, exactly as the module header promises. The flip is re-pointing `receive.rs:892` from
/// `busbar_substrate::plane_host::run_gauntlet(req, plane)` to this function — nothing else changes,
/// because A2A's `drive` (and its metering) is byte-identical on both loops.
pub(crate) async fn run_a2a_via_kernel(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Response {
    run_gauntlet_via_kernel(req, plane).await
}

#[cfg(test)]
#[path = "tests/a2a_kernel_rider.rs"]
mod tests;
